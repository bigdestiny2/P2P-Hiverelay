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
API="${HIVERELAY_API:-http://127.0.0.1:9100}"
ENV_FILE="${HIVERELAY_ENV_FILE:-/etc/hiverelay/hiverelay.env}"
HEALTH_TIMEOUT="${HIVERELAY_HEALTH_TIMEOUT:-120}"
LOCK="/run/hiverelay-updater.lock"

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

log() { echo "[updater $(date -u +%FT%TZ)] $*"; }
die() { log "ERR $*"; exit 1; }

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

rollback_to_previous() {
  local reason="$1"
  log "FAIL $reason — ROLLING BACK to $CUR_VER ($CUR_SHA)"
  if ! git checkout --quiet "$CUR_SHA"; then
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
git checkout --quiet "$TARGET" || die "checkout $TARGET failed"
deps_if_changed "$CUR_SHA" "$TARGET_SHA" || rollback_to_previous "dependency install failed on $TARGET"
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
