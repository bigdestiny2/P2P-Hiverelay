#!/usr/bin/env bash
#
# hiverelay-updater — pull-based self-update agent for one HiveRelay node.
#
# Run by a systemd timer (every ~15 min). Each box owns its own lifecycle:
# no inbound SSH, no orchestrator, works behind NAT. The flow:
#
#   1. Read this box's channel (/etc/hiverelay-updater.conf, default stable).
#   2. Fetch fleet/channels.json from the repo and resolve the target tag.
#   3. If already on the target -> no-op.
#   4. Otherwise: snapshot current SHA, fetch + checkout the target tag,
#      reinstall deps only if package-lock changed, restart the relay.
#   5. HEALTH-GATE: poll /health for running:true + target version (up to 120s).
#         green  -> done.
#         red    -> ROLL BACK to the snapshot, restart, re-verify, alert.
#
# Safety: single-flight (flock), refuses to run if the repo has uncommitted
# local changes (never clobbers a hand-edit), and a failed update always
# tries to leave the box on the version it started from.
#
# Usage:  hiverelay-updater [--dry-run]
set -euo pipefail

# systemd oneshot units don't export HOME; under `set -u` a bare $HOME
# reference below would abort the whole run. Default it (boxes run as root)
# so the script is robust whether launched by systemd or by hand.
: "${HOME:=/root}"

REPO_DIR="${HIVERELAY_REPO_DIR:-$HOME/hiverelay}"
CONF="${HIVERELAY_UPDATER_CONF:-/etc/hiverelay-updater.conf}"
CHANNELS_URL="${HIVERELAY_CHANNELS_URL:-https://raw.githubusercontent.com/bigdestiny2/P2P-Hiverelay/main/fleet/channels.json}"
SERVICE="${HIVERELAY_SERVICE:-hiverelay}"
# Where this agent is installed, for the post-update self-refresh. Resolved from
# $0 so a non-standard install path still refreshes itself; falls back to the
# canonical location when $0 is not a readable file (e.g. piped from stdin).
SELF_PATH="${HIVERELAY_UPDATER_PATH:-}"
if [ -z "$SELF_PATH" ]; then
  if [ -f "$0" ]; then SELF_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
  else SELF_PATH="/usr/local/bin/hiverelay-updater"; fi
fi
API="${HIVERELAY_API:-http://127.0.0.1:9100}"
ENV_FILE="${HIVERELAY_ENV_FILE:-/etc/hiverelay/hiverelay.env}"
HEALTH_TIMEOUT="${HIVERELAY_HEALTH_TIMEOUT:-120}"
LOCK="/run/hiverelay-updater.lock"

# ── supply-chain trust ─────────────────────────────────────────────
# The updater checks out a channel-named tag it resolves from a remote
# JSON file over the network. A repo/GitHub-account/CDN/CA MITM that can
# move that tag (or serve a forged one) would otherwise run arbitrary code
# as root on every box. We refuse to check out any tag that is not signed
# by a key in a locally provisioned allowed-signers file — fail closed.
#
# ALLOWED_SIGNERS is an OpenSSH allowed_signers file (the operator writes
# it once; see fleet/README.md "Signed releases"). We pin it as git's
# gpg.ssh.allowedSignersFile for the verify and force gpg.format=ssh, so
# verification never depends on whatever the box's git config happens to
# be. Set HIVERELAY_REQUIRE_SIGNED_TAGS=0 ONLY to break glass in an
# emergency where signing is broken and you accept the risk.
ALLOWED_SIGNERS="${HIVERELAY_ALLOWED_SIGNERS:-/etc/hiverelay/allowed-signers}"
REQUIRE_SIGNED_TAGS="${HIVERELAY_REQUIRE_SIGNED_TAGS:-1}"

DRY_RUN=0
VERIFY_ONLY=0
case "${1:-}" in
  --dry-run)     DRY_RUN=1 ;;
  # Verify-only: run just the tag-signature gate against a given tag and
  # exit 0 (trusted) / non-zero (untrusted). Used by the regression test
  # and handy for operators auditing a tag by hand. Does not touch the box.
  --verify-only) VERIFY_ONLY=1 ;;
esac

log() { echo "[updater $(date -u +%FT%TZ)] $*"; }
die() { log "ERR $*"; exit 1; }

# ── tag signature gate (fail closed) ───────────────────────────────
# Return 0 only if $1 is an existing tag whose signature verifies against a
# key in the operator-provisioned allowed-signers file. Any doubt -> non-zero.
# We invoke git with an explicit, self-contained trust config (SSH format +
# our allowed_signers path) so the result can't be softened by the box's
# ambient git config, and we require an actual "Good ... signature" line
# rather than trusting git's exit code alone.
verify_tag() {
  local tag="$1"
  local out

  if [ "$REQUIRE_SIGNED_TAGS" != "1" ]; then
    log "WARN HIVERELAY_REQUIRE_SIGNED_TAGS=$REQUIRE_SIGNED_TAGS — tag signature verification DISABLED (break-glass); NOT recommended"
    return 0
  fi

  if [ -z "$tag" ]; then
    log "verify_tag: no tag given"; return 1
  fi
  # Must be an annotated/signed tag object; lightweight tags can't be signed.
  if [ "$(git cat-file -t "refs/tags/$tag" 2>/dev/null)" != "tag" ]; then
    log "verify_tag: '$tag' is not an annotated (signable) tag — refusing"
    return 1
  fi
  if [ ! -r "$ALLOWED_SIGNERS" ]; then
    log "verify_tag: allowed-signers file '$ALLOWED_SIGNERS' missing/unreadable — refusing (provision it; see fleet/README.md)"
    return 1
  fi
  # SSH-signature path (default/documented). git prints the verification
  # result to stderr; capture both streams. A verified SSH signature yields
  # a "Good \"git\" signature" line; a GPG-signed tag yields
  # "Good signature". Accept either, but ONLY when git also exits 0.
  if out="$(git -c gpg.format=ssh \
                -c "gpg.ssh.allowedSignersFile=$ALLOWED_SIGNERS" \
                verify-tag --raw "$tag" 2>&1)"; then
    if printf '%s' "$out" | grep -Eq 'GOODSIG|TRUST_(FULLY|ULTIMATE)' \
       || printf '%s' "$out" | grep -qi 'Good.*signature'; then
      return 0
    fi
  fi
  log "verify_tag: signature check FAILED for '$tag' — refusing to check it out"
  printf '%s\n' "$out" | sed 's/^/[updater verify]   /' >&2 || true
  return 1
}

# ── verify-only mode ───────────────────────────────────────────────
# `hiverelay-updater --verify-only <tag>`: run only the signature gate in
# REPO_DIR and exit. No lock, no network, no box mutation — safe to run by
# hand and used by the regression test to prove the gate rejects an
# unsigned/untrusted tag.
if [ "$VERIFY_ONLY" = 1 ]; then
  VERIFY_TAG_ARG="${2:-}"
  [ -n "$VERIFY_TAG_ARG" ] || die "--verify-only requires a tag argument"
  cd "$REPO_DIR" || die "repo dir $REPO_DIR not found"
  if verify_tag "$VERIFY_TAG_ARG"; then
    log "verify-only: '$VERIFY_TAG_ARG' is TRUSTED"
    exit 0
  fi
  die "verify-only: '$VERIFY_TAG_ARG' is UNTRUSTED"
fi

# ── single-flight ──────────────────────────────────────────────────
# Lock under /run on Linux; fall back to /tmp where /run isn't writable
# (e.g. a dev box). If flock is unavailable, proceed rather than falsely
# reporting "in progress".
[ -w "$(dirname "$LOCK")" ] 2>/dev/null || LOCK="/tmp/hiverelay-updater.lock"
if command -v flock >/dev/null 2>&1; then
  exec 9>"$LOCK" 2>/dev/null || true
  flock -n 9 || { log "another run in progress; exiting"; exit 0; }
else
  log "WARN flock unavailable — proceeding without single-flight lock"
fi

# ── channel ────────────────────────────────────────────────────────
CHANNEL="stable"
if [ -r "$CONF" ]; then
  # Treat config as data, not shell. The installer writes CHANNEL=<name>;
  # sourcing this file would make a writable config path code-executable.
  CONF_CHANNEL="$(sed -n 's/^[[:space:]]*CHANNEL[[:space:]]*=[[:space:]]*//p' "$CONF" | head -n 1)"
  CONF_CHANNEL="${CONF_CHANNEL%\"}"
  CONF_CHANNEL="${CONF_CHANNEL#\"}"
  CONF_CHANNEL="${CONF_CHANNEL%\'}"
  CONF_CHANNEL="${CONF_CHANNEL#\'}"
  [ -n "$CONF_CHANNEL" ] && CHANNEL="$CONF_CHANNEL"
fi
if [[ ! "$CHANNEL" =~ ^[A-Za-z0-9._-]{1,32}$ ]]; then
  die "invalid channel '$CHANNEL' in $CONF"
fi

# ── resolve target tag ─────────────────────────────────────────────
JSON="$(curl -fsS --max-time 20 "$CHANNELS_URL")" || die "cannot fetch channels.json"
TARGET="$(printf '%s' "$JSON" | CHANNEL="$CHANNEL" python3 -c 'import os,sys,json; print(json.load(sys.stdin).get(os.environ["CHANNEL"], ""))')" \
  || die "cannot parse channels.json"
[ -n "$TARGET" ] || die "no target tag for channel '$CHANNEL'"
if [[ ! "$TARGET" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  die "invalid target tag '$TARGET' for channel '$CHANNEL'"
fi

cd "$REPO_DIR" || die "repo dir $REPO_DIR not found"

# refuse to touch a dirty tree (protects manual edits / stranded work)
if ! git diff --quiet || ! git diff --cached --quiet; then
  log "WARN repo has uncommitted changes; skipping auto-update"; exit 0
fi

CUR_VER="v$(grep -m1 '"version"' package.json | tr -dc '0-9.')"
CUR_SHA="$(git rev-parse HEAD)"

git fetch --tags --quiet origin || die "git fetch failed"
TARGET_SHA="$(git rev-parse -q --verify "refs/tags/$TARGET^{}")" || die "target tag $TARGET not found after fetch"

if [ "$CUR_SHA" = "$TARGET_SHA" ]; then
  log "channel=$CHANNEL up-to-date at $TARGET ($TARGET_SHA)"; exit 0
fi
log "channel=$CHANNEL current=$CUR_VER/$CUR_SHA target=$TARGET/$TARGET_SHA"
if [ "$DRY_RUN" = 1 ]; then log "dry-run: would update $CUR_SHA -> $TARGET_SHA"; exit 0; fi

# ── helpers ────────────────────────────────────────────────────────
apikey() {
  local key
  key="$(systemctl show "$SERVICE" -p Environment 2>/dev/null \
    | awk 'BEGIN{RS=" "} /^HIVERELAY_API_KEY=/{sub(/^HIVERELAY_API_KEY=/,""); print; exit}' || true)"
  if [ -z "$key" ] && [ -r "$ENV_FILE" ]; then
    key="$(awk -F= '/^[[:space:]]*HIVERELAY_API_KEY[[:space:]]*=/ { sub(/^[^=]*=/,""); sub(/^[[:space:]]*/,""); print; exit }' "$ENV_FILE" 2>/dev/null || true)"
  fi
  key="${key%\"}"
  key="${key#\"}"
  key="${key%\'}"
  key="${key#\'}"
  if [ -n "$key" ]; then printf '%s\n' "$key"; fi
  return 0
}

curl_with_optional_key() {
  local key="$1"
  shift
  if [ -z "$key" ]; then
    curl "$@" || return $?
    return 0
  fi
  if printf '%s' "$key" | LC_ALL=C grep -q '[[:cntrl:]]'; then
    return 2
  fi
  local header_file status
  header_file="$(mktemp)"
  chmod 600 "$header_file" 2>/dev/null || true
  printf 'Authorization: Bearer %s\n' "$key" > "$header_file"
  status=0
  curl -H "@$header_file" "$@" || status=$?
  rm -f "$header_file"
  return "$status"
}

healthy() {
  local expected_version="${1:-}"
  local key end body version
  key="$(apikey)"
  end=$((SECONDS + HEALTH_TIMEOUT))
  while [ $SECONDS -lt $end ]; do
    body="$(curl_with_optional_key "$key" -fsS --max-time 8 "$API/health" 2>/dev/null || true)"
    version="$(printf '%s' "$body" | sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
    if printf '%s' "$body" | grep -q '"running":true' &&
      { [ -z "$expected_version" ] || [ "$version" = "$expected_version" ]; }; then
      return 0
    fi
    sleep 5
  done
  return 1
}

deps_if_changed() { # $1=from-ref $2=to-ref
  if ! git diff --quiet "$1" "$2" -- package-lock.json 2>/dev/null; then
    log "package-lock changed -> reinstalling deps"
    npm ci --omit=dev --no-audit --no-fund 2>&1 | tail -2 \
      || npm install --omit=dev --no-audit --no-fund 2>&1 | tail -2
  fi
}

# Prove the runtime can actually boot BEFORE restarting the live service.
#
# `npm ci` succeeding does not mean the relay can start. On 2026-07-28
# utah-0.5gb installed cleanly and then crash-looped, because require-addon
# resolved the package root to "/" and looked for
# /prebuilds/linux-x64/sodium-native.node — the binary was present and correct
# inside node_modules. Same tag, same install; the difference was Node
# v22.22.2 vs v22.22.0 on the box that worked. `engines: >=20.0.0` admits both.
#
# Loading hyperswarm walks the exact chain that failed
# (hyperswarm -> hyperdht -> dht-rpc -> udx-native -> require-addon ->
# sodium-native), so this catches native-addon breakage of any origin — bad
# prebuild, wrong libc, Node ABI drift — without pinning a version we would
# then have to chase. Cheap: a require, no network, no listeners.
preflight_runtime() {
  node -e 'require("hyperswarm")' >/dev/null 2>&1
}

rollback_to_previous() {
  local reason="$1"
  log "FAIL $reason — ROLLING BACK to $CUR_VER ($CUR_SHA)"
  # --force is required, not optional. `npm ci` rewrites package-lock.json, so by
  # the time a dependency install has failed the tree is dirty and a plain
  # checkout refuses — which strands the box on the NEW tree with a half-built
  # node_modules, the exact opposite of what a rollback is for. Forcing is safe
  # here: the pre-update dirty-tree guard already refused to start on a dirty
  # tree, so anything dirty at this point was created by this run.
  if ! git checkout --quiet --force "$CUR_SHA"; then
    log "CRITICAL could not checkout previous SHA"
    exit 1
  fi
  if ! deps_if_changed "$TARGET_SHA" "$CUR_SHA"; then
    log "CRITICAL rollback dependency reinstall failed — manual attention needed on $(hostname)"
    exit 1
  fi
  systemctl restart "$SERVICE"
  if healthy "${CUR_VER#v}"; then
    log "rollback OK — back on $CUR_VER"
  else
    log "CRITICAL rollback unhealthy — manual attention needed on $(hostname)"
  fi
  exit 1
}

# ── update ─────────────────────────────────────────────────────────
# SUPPLY-CHAIN GATE (fail closed): never check out a tag we can't verify was
# signed by a trusted key. This runs AFTER fetch (so the tag object + its
# signature are local) and BEFORE checkout (so a forged/moved tag can never
# reach the working tree, deps install, or a service restart). A failure
# here leaves the box exactly where it was — no rollback needed.
verify_tag "$TARGET" || die "refusing to update: tag $TARGET is not signed by a trusted key (see fleet/README.md 'Signed releases')"

git checkout --quiet "$TARGET" || die "checkout $TARGET failed"
deps_if_changed "$CUR_SHA" "$TARGET_SHA" || rollback_to_previous "dependency install failed on $TARGET"
preflight_runtime || rollback_to_previous "runtime preflight failed on $TARGET (native addon or Node ABI)"

# SELF-UPDATE. The agent is the one component an update could never fix: it
# runs from /usr/local/bin and nothing here reinstalled it, so a bug in the
# update path could only be repaired by hand-visiting every box. That is
# exactly what happened with the missing --force on the rollback checkout —
# the fix shipped in the tag and reached no relay.
#
# Ordering matters. This runs AFTER verify_tag and AFTER the deps install, so
# the script being installed comes from a signature-verified tree that has
# already proven it can install. It runs BEFORE the service restart so a
# failed restart rolls back with the NEW agent's logic.
#
# The running shell is unaffected: bash has already read this file, and the
# replacement takes effect on the next tick. Install atomically (write a temp
# beside the target, then rename) so a crash mid-copy cannot leave a partial
# interpreter script at a path systemd will execute.
if [ -f "$REPO_DIR/fleet/updater.sh" ] && ! cmp -s "$REPO_DIR/fleet/updater.sh" "$SELF_PATH"; then
  if install -m 0755 "$REPO_DIR/fleet/updater.sh" "$SELF_PATH.next" 2>/dev/null &&
     bash -n "$SELF_PATH.next" 2>/dev/null &&
     mv -f "$SELF_PATH.next" "$SELF_PATH" 2>/dev/null; then
    log "agent self-updated from $TARGET — active next tick"
  else
    rm -f "$SELF_PATH.next" 2>/dev/null || true
    log "WARN agent self-update failed (non-fatal); continuing with the running agent"
  fi
fi

systemctl restart "$SERVICE"

if healthy "${TARGET#v}"; then
  log "OK updated $CUR_VER -> $TARGET — health green"
  # Pack loose objects accrued by fetch/checkout so repeated updates don't
  # grow .git. Plain gc only (NEVER --aggressive). Post-success ONLY —
  # never on the rollback path (it would lengthen recovery). Space-gated:
  # a repack needs transient ~2x scratch, so skip on a near-full box.
  # Foreground + timeout so gc can't wedge or race the next tick's
  # checkout, and its failure is non-fatal (must not change our exit).
  # Reachable history + all tags + the prior SHA are preserved (only
  # unreachable objects past gc.pruneExpire are dropped) — rollback-safe.
  FREE_KB=$(df -Pk "$REPO_DIR" 2>/dev/null | awk 'NR==2{print $4}')
  if [ "${FREE_KB:-0}" -gt 524288 ] && [ ! -f .git/gc.pid ]; then
    timeout 90 git gc --quiet --no-detach 2>&1 | tail -2 \
      || log "WARN git gc skipped/failed (non-fatal)"
  else
    log "skip gc: low disk (${FREE_KB:-?}KB free) or gc already running"
  fi
  exit 0
fi

# ── rollback ───────────────────────────────────────────────────────
rollback_to_previous "health not green on $TARGET ${TARGET#v} within ${HEALTH_TIMEOUT}s"
