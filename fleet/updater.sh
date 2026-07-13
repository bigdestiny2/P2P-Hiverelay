#!/usr/bin/env bash
#
# hiverelay-updater — pull-based self-update agent for one HiveRelay node.
#
# Run by a systemd timer (every ~15 min). Each box owns its own lifecycle:
# no inbound SSH, no orchestrator, works behind NAT. The flow:
#
#   1. Read this box's channel and canonical relay name from updater config.
#   2. Resolve fleet/channels.json only from an allowed-signer-verified,
#      monotonic control commit and persist the accepted control head.
#   3. Verify the target tag, then read its exact signed gateway manifest. Signed
#      cohort membership forces the gateway gate; mutable environment cannot.
#   4. If already on the target -> refresh required cohort evidence, then
#      no-op. Failure invalidates stale evidence and quarantines only app HTTPS.
#   5. Otherwise: snapshot current SHA, fetch + checkout the target tag,
#      reinstall deps only if package-lock changed, restart the relay.
#   6. HEALTH-GATE: poll /health for running:true + target version (up to 120s),
#      then run manifest-bound public HTTPS checks on signed cohort nodes.
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
unset GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_CONFIG GIT_CONFIG_COUNT
unset GIT_CONFIG_GLOBAL GIT_CONFIG_PARAMETERS GIT_CONFIG_SYSTEM GIT_DIR GIT_EXEC_PATH
unset GIT_INDEX_FILE GIT_NAMESPACE GIT_OBJECT_DIRECTORY GIT_PREFIX GIT_PROXY_COMMAND
unset GIT_QUARANTINE_PATH GIT_REPLACE_REF_BASE GIT_SHALLOW_FILE GIT_SSH GIT_SSH_COMMAND
unset GIT_SSL_CAINFO GIT_SSL_CAPATH GIT_SSL_NO_VERIFY GIT_WORK_TREE
export GIT_NO_REPLACE_OBJECTS=1
export GIT_GRAFT_FILE=/dev/null/hiverelay-disabled
export GIT_OPTIONAL_LOCKS=0
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0=core.hooksPath
export GIT_CONFIG_VALUE_0=/dev/null
export GIT_CONFIG_KEY_1=core.fsmonitor
export GIT_CONFIG_VALUE_1=false

REPO_DIR="${HIVERELAY_REPO_DIR:-$HOME/hiverelay}"
CONF="${HIVERELAY_UPDATER_CONF:-/etc/hiverelay-updater.conf}"
SERVICE="${HIVERELAY_SERVICE:-hiverelay}"
API="${HIVERELAY_API:-http://127.0.0.1:9100}"
ENV_FILE="${HIVERELAY_ENV_FILE:-/etc/hiverelay/hiverelay.env}"
GIT_BIN="${HIVERELAY_GIT_BIN:-/usr/bin/git}"
HEALTH_TIMEOUT="${HIVERELAY_HEALTH_TIMEOUT:-120}"
CONTROL_BRANCH="${HIVERELAY_CONTROL_BRANCH:-main}"
CONTROL_STATE="${HIVERELAY_CONTROL_STATE:-/var/lib/hiverelay-updater/control-channel.json}"
SIGNED_CHANNEL_RESOLVER="$REPO_DIR/scripts/resolve-signed-fleet-channel.mjs"
LOCK_DIR="/run/hiverelay-updater"

# Public HTTPS gateway node-local inputs. None of these selects whether the
# gate runs: only cohort membership in the verified target manifest does that.
# Cohort nodes require explicit config/nginx/evidence paths in the root-only
# updater EnvironmentFile; legacy/noncohort nodes never need them.
PUBLIC_GATEWAY_PROBE_CONFIG="${HIVERELAY_PUBLIC_GATEWAY_PROBE_CONFIG:-}"
PUBLIC_GATEWAY_PROBE_NGINX_CONFIG="${HIVERELAY_PUBLIC_GATEWAY_PROBE_NGINX_CONFIG:-}"
PUBLIC_GATEWAY_PROBE_NGINX_BINARY="${HIVERELAY_PUBLIC_GATEWAY_PROBE_NGINX_BINARY:-}"
PUBLIC_GATEWAY_PROBE_CA="${HIVERELAY_PUBLIC_GATEWAY_PROBE_CA:-}"
PUBLIC_GATEWAY_PROBE_EVIDENCE="${HIVERELAY_PUBLIC_GATEWAY_PROBE_EVIDENCE:-}"
PUBLIC_GATEWAY_OPS_CERTIFICATE="${HIVERELAY_PUBLIC_GATEWAY_OPS_CERTIFICATE:-}"
PUBLIC_GATEWAY_OPS_CERTIFICATE_KEY="${HIVERELAY_PUBLIC_GATEWAY_OPS_CERTIFICATE_KEY:-}"
PUBLIC_GATEWAY_OPS_CERTIFICATE_ROOT="${HIVERELAY_PUBLIC_GATEWAY_OPS_CERTIFICATE_ROOT:-}"
PUBLIC_GATEWAY_OPS_SS_BINARY="${HIVERELAY_PUBLIC_GATEWAY_OPS_SS_BINARY:-/usr/sbin/ss}"
PUBLIC_GATEWAY_OPS_EVIDENCE="${HIVERELAY_PUBLIC_GATEWAY_OPS_EVIDENCE:-}"
PUBLIC_GATEWAY_PROBE_PUBLIC_SUFFIX_READY="${HIVERELAY_PUBLIC_GATEWAY_PROBE_PUBLIC_SUFFIX_READY:-0}"
PUBLIC_GATEWAY_PROBE_TIMEOUT="${HIVERELAY_PUBLIC_GATEWAY_PROBE_TIMEOUT:-90}"
PUBLIC_GATEWAY_QUARANTINE_COMMAND="${HIVERELAY_PUBLIC_GATEWAY_QUARANTINE_COMMAND:-/usr/local/sbin/hiverelay-quarantine-public-gateway}"
PUBLIC_GATEWAY_QUARANTINE_BACKUP="${HIVERELAY_PUBLIC_GATEWAY_QUARANTINE_BACKUP:-}"
PUBLIC_GATEWAY_MANIFEST_PATH="fleet/public-hive-gateway-release.json"
PUBLIC_GATEWAY_CONTRACT_RESOLVER="$REPO_DIR/scripts/resolve-public-hive-gateway-node.mjs"

# Populated exclusively from the normalized manifest in TARGET_SHA.
PUBLIC_GATEWAY_REQUIRED=0
PUBLIC_GATEWAY_ADMISSION_PROFILE=""
PUBLIC_GATEWAY_EXPECTED_ORIGIN=""
PUBLIC_GATEWAY_EXPECTED_CONNECT_ADDRESS=""
PUBLIC_GATEWAY_EXPECTED_APP_KEY=""
PUBLIC_GATEWAY_EXPECTED_PATH=""
PUBLIC_GATEWAY_EXPECTED_SHA256=""
PUBLIC_GATEWAY_EXPECTED_DRIVE_VERSION=""
PUBLIC_GATEWAY_EXPECTED_PEER_FINGERPRINT256=""
PUBLIC_GATEWAY_EXPECTED_NGINX_SHA256=""
PUBLIC_GATEWAY_DEPLOYMENT_PROFILE="legacy"
PUBLIC_GATEWAY_OPERATOR_CONTRACT_SHA256="-"
PUBLIC_GATEWAY_OPS_REQUIRED=0
SOURCE_PUBLIC_GATEWAY_REQUIRED=0
SOURCE_PUBLIC_GATEWAY_OPERATOR_CONTRACT_SHA256="-"
PUBLIC_GATEWAY_RETIREMENT_REQUIRED=0
PUBLIC_GATEWAY_DISABLED_CONFIG_VERIFIER="$REPO_DIR/scripts/verify-public-hive-gateway-disabled-config.mjs"
PUBLIC_GATEWAY_QUARANTINE_VERIFIER="$REPO_DIR/scripts/verify-public-hive-gateway-quarantine.mjs"
PUBLIC_GATEWAY_QUARANTINE_CONTRACT_REF=""
PUBLIC_GATEWAY_QUARANTINE_CONTRACT_SHA256=""
PUBLIC_GATEWAY_QUARANTINE_AUTHORITY_DIR=""
PUBLIC_GATEWAY_QUARANTINE_HELPER_AUTHORITY=""
PUBLIC_GATEWAY_NGINX_BINARY_RECORD=""
PUBLIC_GATEWAY_SS_BINARY_RECORD=""

# ── supply-chain trust ─────────────────────────────────────────────
# The updater checks out a channel-named tag selected by signed Git control.
# A repo/Git-host-account/network compromise that can move a control ref or
# release tag would otherwise run arbitrary code as root on every box. We
# accept only monotonic control commits and release tags signed by keys in a
# locally provisioned allowed-signers file — fail closed.
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

stat_record() {
  stat -f '%u|%Lp|%l|%z|%d|%i|%m|%c' "$1" 2>/dev/null || \
    stat -c '%u|%a|%h|%s|%d|%i|%Y|%Z' "$1" 2>/dev/null
}

trusted_executable_parent_chain() {
  local filename="$1" label="$2" parent record uid mode rest mode_value
  # Walk the lexical path. Resolving dirname with `cd -P` first would erase an
  # attacker-controlled ancestor symlink and validate only its current target.
  parent="$(dirname "$filename")"
  while :; do
    [ -d "$parent" ] && [ ! -L "$parent" ] || { log "$label parent is unsafe: $parent"; return 1; }
    record="$(stat_record "$parent")" || { log "cannot inspect $label parent: $parent"; return 1; }
    IFS='|' read -r uid mode rest <<< "$record"
    [ "$uid" = "$EUID" ] || [ "$uid" = 0 ] || { log "$label parent has an untrusted owner: $parent"; return 1; }
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || { log "$label parent mode is malformed: $parent"; return 1; }
    mode_value=$((8#$mode))
    if (( (mode_value & 8#022) != 0 )); then
      # Root-owned sticky traversal roots such as /tmp do not let another
      # user replace this process's private child directory.
      if [ "$uid" != 0 ] || (( (mode_value & 8#1000) == 0 )); then
        log "$label parent is group/world writable: $parent"
        return 1
      fi
    fi
    [ "$parent" = / ] && break
    parent="$(dirname "$parent")"
  done
}

trusted_executable_canonical_path() {
  local filename="$1" label="$2" physical_parent leaf canonical
  physical_parent="$(cd -P "$(dirname "$filename")" 2>/dev/null && pwd -P)" || {
    log "$label parent cannot be resolved"
    return 1
  }
  leaf="$(basename "$filename")"
  if [ "$physical_parent" = / ]; then canonical="/$leaf"; else canonical="$physical_parent/$leaf"; fi
  [ "$filename" = "$canonical" ] || {
    log "$label path must be canonical and contain no symlink ancestors"
    return 1
  }
}

trusted_executable_record() {
  local filename="$1" label="$2" max_size="$3"
  local record final_record uid mode nlink size rest mode_value
  [[ "$filename" = /* ]] && [ "${#filename}" -le 4096 ] || { log "$label path is unsafe"; return 1; }
  trusted_executable_canonical_path "$filename" "$label" || return 1
  [ -x "$filename" ] && [ -f "$filename" ] && [ ! -L "$filename" ] || { log "$label is not a regular executable"; return 1; }
  trusted_executable_parent_chain "$filename" "$label" || return 1
  record="$(stat_record "$filename")" || { log "cannot inspect $label"; return 1; }
  IFS='|' read -r uid mode nlink size rest <<< "$record"
  [ "$uid" = "$EUID" ] || [ "$uid" = 0 ] || { log "$label has an untrusted owner"; return 1; }
  [ "$nlink" = 1 ] || { log "$label must have exactly one link"; return 1; }
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || { log "$label mode is malformed"; return 1; }
  mode_value=$((8#$mode))
  (( (mode_value & 8#111) != 0 )) && (( (mode_value & 8#022) == 0 )) || {
    log "$label must be executable and not group/world writable"
    return 1
  }
  [[ "$size" =~ ^[0-9]+$ ]] && [ "$size" -ge 1 ] && [ "$size" -le "$max_size" ] || {
    log "$label size is outside its trust bound"
    return 1
  }
  # Rewalk the lexical/canonical path and require an identical final stat so a
  # component swap during inspection cannot create a trusted record.
  trusted_executable_canonical_path "$filename" "$label" || return 1
  trusted_executable_parent_chain "$filename" "$label" || return 1
  [ -x "$filename" ] && [ -f "$filename" ] && [ ! -L "$filename" ] || {
    log "$label changed while establishing executable trust"
    return 1
  }
  final_record="$(stat_record "$filename")" || { log "cannot re-inspect $label"; return 1; }
  [ "$final_record" = "$record" ] || {
    log "$label identity changed while establishing executable trust"
    return 1
  }
  printf '%s\n' "$record"
}

trusted_executable_matches() {
  local filename="$1" label="$2" max_size="$3" expected="$4" current
  if ! current="$(trusted_executable_record "$filename" "$label" "$max_size")"; then
    [ -z "$current" ] || printf '%s\n' "$current"
    return 1
  fi
  if [ "$current" != "$expected" ]; then
    log "$label identity changed after its trusted snapshot"
    return 1
  fi
}

ensure_trusted_executable_snapshot() {
  local filename="$1" label="$2" max_size="$3" record_variable="$4" current expected
  expected="${!record_variable:-}"
  if [ -n "$expected" ]; then
    trusted_executable_matches "$filename" "$label" "$max_size" "$expected"
    return
  fi
  if ! current="$(trusted_executable_record "$filename" "$label" "$max_size")"; then
    [ -z "$current" ] || printf '%s\n' "$current"
    return 1
  fi
  printf -v "$record_variable" '%s' "$current"
}
[[ "$GIT_BIN" = /* ]] && [ -x "$GIT_BIN" ] && [ -f "$GIT_BIN" ] && [ ! -L "$GIT_BIN" ] || \
  die "trusted Git executable is unavailable at $GIT_BIN"
git() { "$GIT_BIN" "$@"; }

read_config_value() {
  local wanted="$1"
  awk -v wanted="$wanted" '
    /^[[:space:]]*($|#)/ { next }
    {
      line = $0
      key = line
      sub(/[[:space:]]*=.*/, "", key)
      sub(/^[[:space:]]*/, "", key)
      sub(/[[:space:]]*$/, "", key)
      if (key != wanted) next
      sub(/^[^=]*=[[:space:]]*/, "", line)
      values[++count] = line
    }
    END {
      if (count > 1) exit 2
      if (count == 0) exit 1
      print values[1]
    }
  ' "$CONF"
}

strip_config_quotes() {
  local value="$1"
  if [[ "$value" == \"*\" && "$value" == *\" ]]; then
    value="${value#\"}"
    value="${value%\"}"
  elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
    value="${value#\'}"
    value="${value%\'}"
  fi
  printf '%s\n' "$value"
}

verify_raw_tracked_tree() {
  local listing entry metadata file mode oid stage actual status
  listing="$(mktemp)" || return 1
  status=0
  if ! git ls-files --stage -z > "$listing"; then
    rm -f "$listing"
    return 1
  fi
  while IFS= read -r -d '' entry; do
    metadata="${entry%%$'\t'*}"
    file="${entry#*$'\t'}"
    read -r mode oid stage <<< "$metadata"
    case "$mode" in 100644|100755) ;; *) status=1; break ;; esac
    if [ "$stage" != "0" ] || [ ! -f "$file" ] || [ -L "$file" ]; then status=1; break; fi
    actual="$(git hash-object --no-filters -- "$file")" || { status=1; break; }
    if [ "$actual" != "$oid" ]; then status=1; break; fi
  done < "$listing"
  rm -f "$listing"
  return "$status"
}

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
                -c gpg.ssh.program=/usr/bin/ssh-keygen \
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
# Mutation-capable runs require one trusted advisory lock. Production uses a
# systemd-created root-only RuntimeDirectory and a fixed root-owned flock
# binary. A non-root developer run may use one UID-private sticky-/tmp child;
# root never falls back to /tmp and never runs unlocked.
if [ "$EUID" = 0 ]; then
  FLOCK_BIN=/usr/bin/flock
  trusted_executable_record "$FLOCK_BIN" 'production flock executable' 1048576 >/dev/null || \
    die "trusted production flock executable is unavailable"
else
  FLOCK_BIN="$(command -v flock 2>/dev/null || true)"
  [ -n "$FLOCK_BIN" ] && [[ "$FLOCK_BIN" = /* ]] || die "developer run requires an absolute flock executable"
  if ! FLOCK_RECORD="$(trusted_executable_record "$FLOCK_BIN" 'developer flock executable' 1048576)"; then
    [ -z "$FLOCK_RECORD" ] || printf '%s\n' "$FLOCK_RECORD"
    die "trusted developer flock executable is unavailable"
  fi
  LOCK_DIR="${TMPDIR:-/tmp}/hiverelay-updater-$EUID"
  if [ ! -e "$LOCK_DIR" ] && [ ! -L "$LOCK_DIR" ]; then
    mkdir -m 0700 "$LOCK_DIR" || die "could not create developer lock directory"
  fi
fi
[ -d "$LOCK_DIR" ] && [ ! -L "$LOCK_DIR" ] || die "updater lock directory is missing or unsafe"
LOCK_RECORD="$(stat_record "$LOCK_DIR")" || die "cannot inspect updater lock directory"
IFS='|' read -r LOCK_UID LOCK_MODE LOCK_NLINK LOCK_SIZE LOCK_REST <<< "$LOCK_RECORD"
[ "$LOCK_UID" = "$EUID" ] || die "updater lock directory must be owned by the effective user"
[[ "$LOCK_MODE" =~ ^[0-7]{3,4}$ ]] || die "updater lock directory mode is malformed"
LOCK_MODE_VALUE=$((8#$LOCK_MODE))
(( (LOCK_MODE_VALUE & 8#077) == 0 )) || die "updater lock directory must be owner-only"
trusted_executable_parent_chain "$LOCK_DIR/lock" 'updater lock directory' || \
  die "updater lock directory parent chain is unsafe"
exec 9< "$LOCK_DIR" || die "could not open updater lock directory"
"$FLOCK_BIN" -n 9 || { log "another run in progress; exiting"; exit 0; }
[ "$(stat_record "$LOCK_DIR")" = "$LOCK_RECORD" ] || die "updater lock directory changed during acquisition"

# ── channel ────────────────────────────────────────────────────────
[ -r "$CONF" ] || die "updater config $CONF is missing or unreadable; reinstall with an exact relay name"

# Treat config as data, never shell. A canonical RELAY_NAME is mandatory on
# every node so deleting probe environment cannot disguise a signed cohort node
# as a legacy relay.
if CONF_CHANNEL="$(read_config_value CHANNEL)"; then
  CHANNEL="$(strip_config_quotes "$CONF_CHANNEL")"
else
  status=$?
  [ "$status" -ne 2 ] || die "duplicate CHANNEL entries in $CONF"
  die "CHANNEL is required in $CONF; reinstall the updater with this node's assigned channel"
fi
if [[ ! "$CHANNEL" =~ ^[A-Za-z0-9._-]{1,32}$ ]]; then
  die "invalid channel '$CHANNEL' in $CONF"
fi

if CONF_RELAY_NAME="$(read_config_value RELAY_NAME)"; then
  RELAY_NAME="$(strip_config_quotes "$CONF_RELAY_NAME")"
else
  status=$?
  [ "$status" -ne 2 ] || die "duplicate RELAY_NAME entries in $CONF"
  die "RELAY_NAME is required in $CONF; reinstall the updater with this node's exact fleet identity"
fi
if [[ ! "$RELAY_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  die "invalid RELAY_NAME '$RELAY_NAME' in $CONF"
fi

cd "$REPO_DIR" || die "repo dir $REPO_DIR not found"

# Refuse dirty/untracked work and index flags that conceal tracked changes.
INDEX_FLAGS="$(git ls-files -v)" || die "cannot inspect tracked index flags"
if [ -n "$(git status --porcelain=v1 --untracked-files=all)" ] ||
   printf '%s\n' "$INDEX_FLAGS" | LC_ALL=C grep -qv '^H ' ||
   ! git diff --cached --quiet HEAD -- || ! verify_raw_tracked_tree; then
  log "WARN repo has uncommitted changes; skipping auto-update"; exit 0
fi

CUR_VER="v$(grep -m1 '"version"' package.json | tr -dc '0-9.')"
CUR_SHA="$(git rev-parse HEAD)"

# ── resolve signed, monotonic control state ───────────────────────
# The current signed checkout supplies the resolver code. It fetches the Git
# control branch, accepts channels.json only from the latest allowed-signer-
# verified commit that changed exactly that file, verifies the selected tag,
# and atomically records the accepted control commit before returning it.
[ -f "$SIGNED_CHANNEL_RESOLVER" ] && [ ! -L "$SIGNED_CHANNEL_RESOLVER" ] || \
  die "trusted signed fleet channel resolver is missing"
CONTROL_ARGS=(
  node "$SIGNED_CHANNEL_RESOLVER"
  --repo "$REPO_DIR"
  --remote origin
  --branch "$CONTROL_BRANCH"
  --channel "$CHANNEL"
  --allowed-signers "$ALLOWED_SIGNERS"
  --state "$CONTROL_STATE"
  --git-bin "$GIT_BIN"
  --installed-head "$CUR_SHA"
)
[ "$REQUIRE_SIGNED_TAGS" = 1 ] || CONTROL_ARGS+=(--allow-unsigned-release)
[ "$DRY_RUN" = 0 ] || CONTROL_ARGS+=(--dry-run)
CONTROL_RESOLUTION="$("${CONTROL_ARGS[@]}")" || \
  die "signed fleet channel control resolution failed"
[[ "$CONTROL_RESOLUTION" != *$'\n'* ]] || die "signed fleet channel resolver returned multiple records"
IFS=$'\t' read -r CONTROL_STATE_KIND TARGET TARGET_SHA CONTROL_COMMIT CONTROL_TIP CONTROL_EXTRA \
  <<< "$CONTROL_RESOLUTION"
[ "$CONTROL_STATE_KIND" = resolved ] && [ -z "$CONTROL_EXTRA" ] || \
  die "signed fleet channel resolver returned a malformed record"
if [[ ! "$TARGET" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] ||
  [[ ! "$TARGET_SHA" =~ ^([a-f0-9]{40}|[a-f0-9]{64})$ ]] ||
  [[ ! "$CONTROL_COMMIT" =~ ^([a-f0-9]{40}|[a-f0-9]{64})$ ]] ||
  [[ ! "$CONTROL_TIP" =~ ^([a-f0-9]{40}|[a-f0-9]{64})$ ]]; then
  die "signed fleet channel resolver returned invalid target or object IDs"
fi
LOCAL_TARGET_SHA="$(git rev-parse -q --verify "refs/tags/$TARGET^{}")" || \
  die "target tag $TARGET is missing after signed control resolution"
[ "$LOCAL_TARGET_SHA" = "$TARGET_SHA" ] || \
  die "target tag $TARGET changed after signed control resolution"

UP_TO_DATE=0
if [ "$CUR_SHA" = "$TARGET_SHA" ]; then
  UP_TO_DATE=1
else
  log "channel=$CHANNEL current=$CUR_VER/$CUR_SHA target=$TARGET/$TARGET_SHA"
fi

resolve_public_gateway_contract() {
  local manifest_entry manifest_tmp manifest_size contract status reason extra required contract_state

  PUBLIC_GATEWAY_REQUIRED=0
  if ! manifest_entry="$(git ls-tree --name-only "$TARGET_SHA" -- "$PUBLIC_GATEWAY_MANIFEST_PATH")"; then
    die "could not inspect exact target tree for public gateway policy"
  fi
  if [ -z "$manifest_entry" ]; then
    log "target $TARGET has no public gateway manifest; relay=$RELAY_NAME uses legacy health only"
    return 0
  fi
  [ "$manifest_entry" = "$PUBLIC_GATEWAY_MANIFEST_PATH" ] || \
    die "target public gateway manifest tree entry is ambiguous"
  [ -f "$PUBLIC_GATEWAY_CONTRACT_RESOLVER" ] && [ ! -L "$PUBLIC_GATEWAY_CONTRACT_RESOLVER" ] || \
    die "trusted public gateway contract resolver is missing"

  manifest_tmp="$(mktemp)" || die "could not allocate gateway manifest input"
  chmod 0600 "$manifest_tmp" 2>/dev/null || true
  if ! git show "$TARGET_SHA:$PUBLIC_GATEWAY_MANIFEST_PATH" > "$manifest_tmp"; then
    rm -f "$manifest_tmp"
    die "could not read public gateway manifest from exact target $TARGET_SHA"
  fi
  manifest_size="$(wc -c < "$manifest_tmp" | tr -d '[:space:]')"
  if ! [[ "$manifest_size" =~ ^[0-9]+$ ]] || [ "$manifest_size" -lt 1 ] || [ "$manifest_size" -gt 2097152 ]; then
    rm -f "$manifest_tmp"
    die "target public gateway manifest is empty or exceeds 2 MiB"
  fi

  local -a contract_args
  contract_args=(
    node "$PUBLIC_GATEWAY_CONTRACT_RESOLVER"
    --release-target "$TARGET"
    --relay "$RELAY_NAME"
    --channel "$CHANNEL"
    --require-public-t1
  )
  contract=""
  if contract="$("${contract_args[@]}" < "$manifest_tmp")"; then
    status=0
  else
    status=$?
  fi
  rm -f "$manifest_tmp"
  [ "$status" -eq 0 ] || die "target public gateway manifest is invalid for relay $RELAY_NAME"
  [[ "$contract" != *$'\n'* ]] || die "public gateway node contract returned multiple records"

  IFS=$'\t' read -r contract_state PUBLIC_GATEWAY_ADMISSION_PROFILE \
    PUBLIC_GATEWAY_EXPECTED_ORIGIN PUBLIC_GATEWAY_EXPECTED_CONNECT_ADDRESS \
    PUBLIC_GATEWAY_EXPECTED_APP_KEY PUBLIC_GATEWAY_EXPECTED_PATH \
    PUBLIC_GATEWAY_EXPECTED_SHA256 PUBLIC_GATEWAY_EXPECTED_DRIVE_VERSION \
    PUBLIC_GATEWAY_EXPECTED_PEER_FINGERPRINT256 PUBLIC_GATEWAY_EXPECTED_NGINX_SHA256 \
    PUBLIC_GATEWAY_DEPLOYMENT_PROFILE PUBLIC_GATEWAY_OPERATOR_CONTRACT_SHA256 extra <<< "$contract"

  case "$contract_state" in
    ordinary)
      reason="$PUBLIC_GATEWAY_ADMISSION_PROFILE"
      [ -n "$reason" ] && [ -z "$PUBLIC_GATEWAY_EXPECTED_ORIGIN" ] && [ -z "$extra" ] || \
        die "ordinary public gateway node contract is malformed"
      PUBLIC_GATEWAY_ADMISSION_PROFILE=""
      PUBLIC_GATEWAY_DEPLOYMENT_PROFILE="legacy"
      PUBLIC_GATEWAY_OPERATOR_CONTRACT_SHA256="-"
      log "target gateway posture=$reason; relay=$RELAY_NAME remains legacy health-only"
      ;;
    cohort)
      [ -z "$extra" ] || die "public gateway cohort contract has unsupported fields"
      for required in "$PUBLIC_GATEWAY_ADMISSION_PROFILE" "$PUBLIC_GATEWAY_EXPECTED_ORIGIN" \
        "$PUBLIC_GATEWAY_EXPECTED_CONNECT_ADDRESS" "$PUBLIC_GATEWAY_EXPECTED_APP_KEY" \
        "$PUBLIC_GATEWAY_EXPECTED_PATH" "$PUBLIC_GATEWAY_EXPECTED_SHA256" \
        "$PUBLIC_GATEWAY_EXPECTED_DRIVE_VERSION" "$PUBLIC_GATEWAY_EXPECTED_PEER_FINGERPRINT256" \
        "$PUBLIC_GATEWAY_EXPECTED_NGINX_SHA256"; do
        [ -n "$required" ] || die "public gateway cohort contract is incomplete"
      done
      case "$PUBLIC_GATEWAY_DEPLOYMENT_PROFILE" in
        legacy)
          die "enabled public gateway updater cohort must use public-t1-gateway"
          ;;
        public-t1-gateway)
          [[ "$PUBLIC_GATEWAY_OPERATOR_CONTRACT_SHA256" =~ ^[a-f0-9]{64}$ ]] || \
            die "public-t1-gateway cohort requires a canonical operator contract digest"
          PUBLIC_GATEWAY_OPS_REQUIRED=1
          PUBLIC_GATEWAY_QUARANTINE_CONTRACT_REF="$TARGET_SHA"
          PUBLIC_GATEWAY_QUARANTINE_CONTRACT_SHA256="$PUBLIC_GATEWAY_OPERATOR_CONTRACT_SHA256"
          ;;
        *) die "public gateway cohort deployment profile is unsupported" ;;
      esac
      PUBLIC_GATEWAY_REQUIRED=1
      log "signed public gateway cohort requires relay=$RELAY_NAME admission=$PUBLIC_GATEWAY_ADMISSION_PROFILE profile=$PUBLIC_GATEWAY_DEPLOYMENT_PROFILE"
      ;;
    *) die "unknown public gateway node contract state" ;;
  esac
}

resolve_source_public_gateway_contract() {
  local manifest_entry manifest_tmp manifest_size contract status extra state profile origin connect app_key path content version fingerprint nginx profile_kind digest
  SOURCE_PUBLIC_GATEWAY_REQUIRED=0
  [ "$UP_TO_DATE" = 0 ] || return 0
  manifest_entry="$(git ls-tree --name-only "$CUR_SHA" -- "$PUBLIC_GATEWAY_MANIFEST_PATH")" || \
    die "could not inspect exact current tree for public gateway policy"
  [ -n "$manifest_entry" ] || return 0
  [ "$manifest_entry" = "$PUBLIC_GATEWAY_MANIFEST_PATH" ] || die "current public gateway manifest tree entry is ambiguous"
  manifest_tmp="$(mktemp)" || die "could not allocate current gateway manifest input"
  chmod 0600 "$manifest_tmp" 2>/dev/null || true
  if ! git show "$CUR_SHA:$PUBLIC_GATEWAY_MANIFEST_PATH" > "$manifest_tmp"; then
    rm -f "$manifest_tmp"
    die "could not read public gateway manifest from exact current tree"
  fi
  manifest_size="$(wc -c < "$manifest_tmp" | tr -d '[:space:]')"
  if ! [[ "$manifest_size" =~ ^[0-9]+$ ]] || [ "$manifest_size" -lt 1 ] || [ "$manifest_size" -gt 2097152 ]; then
    rm -f "$manifest_tmp"
    die "current public gateway manifest is empty or exceeds 2 MiB"
  fi
  contract=""
  if contract="$(node "$PUBLIC_GATEWAY_CONTRACT_RESOLVER" \
      --release-target "$CUR_VER" --relay "$RELAY_NAME" --channel "$CHANNEL" --require-public-t1 < "$manifest_tmp")"; then
    status=0
  else
    status=$?
  fi
  rm -f "$manifest_tmp"
  [ "$status" -eq 0 ] || die "current public gateway manifest is invalid for relay $RELAY_NAME"
  [[ "$contract" != *$'\n'* ]] || die "current public gateway node contract returned multiple records"
  IFS=$'\t' read -r state profile origin connect app_key path content version fingerprint nginx profile_kind digest extra <<< "$contract"
  case "$state" in
    ordinary) return 0 ;;
    cohort)
      [ -z "$extra" ] && [ "$profile_kind" = public-t1-gateway ] && [[ "$digest" =~ ^[a-f0-9]{64}$ ]] || \
        die "current public gateway cohort contract is malformed"
      SOURCE_PUBLIC_GATEWAY_REQUIRED=1
      SOURCE_PUBLIC_GATEWAY_OPERATOR_CONTRACT_SHA256="$digest"
      if [ "$PUBLIC_GATEWAY_REQUIRED" = 0 ]; then
        PUBLIC_GATEWAY_QUARANTINE_CONTRACT_REF="$CUR_SHA"
        PUBLIC_GATEWAY_QUARANTINE_CONTRACT_SHA256="$digest"
      fi
      ;;
    *) die "unknown current public gateway node contract state" ;;
  esac
}

# The manifest is consulted only after the channel target is proven to be a
# trusted signed tag. This verification is required even on an up-to-date or
# noncohort tick so mutable channel metadata cannot select unsigned policy.
verify_tag "$TARGET" || die "refusing target release: tag $TARGET is not signed by a trusted key"
resolve_public_gateway_contract
resolve_source_public_gateway_contract
if [ "$SOURCE_PUBLIC_GATEWAY_REQUIRED" = 1 ] && [ "$PUBLIC_GATEWAY_REQUIRED" = 0 ]; then
  PUBLIC_GATEWAY_RETIREMENT_REQUIRED=1
fi

if [ "$DRY_RUN" = 1 ]; then
  if [ "$UP_TO_DATE" = 1 ]; then
    log "dry-run: already at $TARGET; gateway-required=$PUBLIC_GATEWAY_REQUIRED relay=$RELAY_NAME"
  else
    log "dry-run: would update $CUR_SHA -> $TARGET_SHA; gateway-required=$PUBLIC_GATEWAY_REQUIRED retirement-required=$PUBLIC_GATEWAY_RETIREMENT_REQUIRED relay=$RELAY_NAME"
  fi
  exit 0
fi

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

public_gateway_healthy() {
  local key path operator_contract release_manifest probe_status ops_status
  local -a probe_args verifier_args ops_args ops_verifier_args

  # Signed manifest cohort membership is the only opt-in. Stale/missing local
  # environment cannot switch this off; noncohort nodes remain untouched.
  [ "$PUBLIC_GATEWAY_REQUIRED" = 1 ] || return 0

  if [ ! -f "$REPO_DIR/scripts/preflight-public-hive-gateway.mjs" ]; then
    log "public gateway probe unavailable in target release"
    return 1
  fi
  if [ ! -f "$REPO_DIR/scripts/verify-public-hive-gateway-evidence.mjs" ]; then
    log "public gateway evidence verifier unavailable in target release"
    return 1
  fi
  if [ "$PUBLIC_GATEWAY_OPS_REQUIRED" = 1 ]; then
    [ -f "$REPO_DIR/scripts/preflight-public-hive-gateway-ops.mjs" ] || {
      log "public-t1-gateway operator preflight is unavailable in target release"
      return 1
    }
    [ -f "$REPO_DIR/scripts/verify-public-hive-gateway-ops-evidence.mjs" ] || {
      log "public-t1-gateway operator evidence verifier is unavailable in target release"
      return 1
    }
  fi
  if [ -z "$PUBLIC_GATEWAY_PROBE_CONFIG" ] || [ -z "$PUBLIC_GATEWAY_PROBE_NGINX_CONFIG" ] ||
    [ -z "$PUBLIC_GATEWAY_PROBE_NGINX_BINARY" ]; then
    log "signed public gateway cohort requires explicit config, nginx config, and nginx binary paths"
    return 1
  fi
  if [ "$PUBLIC_GATEWAY_PROBE_PUBLIC_SUFFIX_READY" != "0" ] &&
    [ "$PUBLIC_GATEWAY_PROBE_PUBLIC_SUFFIX_READY" != "1" ]; then
    log "public gateway public-suffix-ready flag must be 0 or 1"
    return 1
  fi
  if [[ "$PUBLIC_GATEWAY_PROBE_EVIDENCE" != /* ]]; then
    log "signed public gateway cohort requires an absolute HIVERELAY_PUBLIC_GATEWAY_PROBE_EVIDENCE path"
    return 1
  fi
  if [[ ! "$PUBLIC_GATEWAY_PROBE_TIMEOUT" =~ ^[1-9][0-9]{0,2}$ ]] ||
    [ "$PUBLIC_GATEWAY_PROBE_TIMEOUT" -gt 300 ]; then
    log "public gateway probe timeout must be an integer from 1 to 300 seconds"
    return 1
  fi
  for path in "$PUBLIC_GATEWAY_PROBE_CONFIG" "$PUBLIC_GATEWAY_PROBE_NGINX_CONFIG" \
    "$PUBLIC_GATEWAY_PROBE_NGINX_BINARY" "$PUBLIC_GATEWAY_PROBE_EVIDENCE" "$PUBLIC_GATEWAY_PROBE_CA"; do
    [ -z "$path" ] || [[ "$path" = /* ]] || {
      log "public gateway node-local paths must be absolute"
      return 1
    }
    if [ "${#path}" -gt 4096 ] || printf '%s' "$path" | LC_ALL=C grep -q '[[:cntrl:]]'; then
      log "public gateway node-local paths must be bounded and contain no control characters"
      return 1
    fi
  done
  if [ "$PUBLIC_GATEWAY_OPS_REQUIRED" = 1 ]; then
    for path in "$PUBLIC_GATEWAY_OPS_CERTIFICATE" "$PUBLIC_GATEWAY_OPS_CERTIFICATE_KEY" \
      "$PUBLIC_GATEWAY_OPS_CERTIFICATE_ROOT" "$PUBLIC_GATEWAY_OPS_SS_BINARY" "$PUBLIC_GATEWAY_OPS_EVIDENCE"; do
      [ -z "$path" ] || [[ "$path" = /* ]] || {
        log "public-t1-gateway operator paths must be absolute"
        return 1
      }
      if [ "${#path}" -gt 4096 ] || printf '%s' "$path" | LC_ALL=C grep -q '[[:cntrl:]]'; then
        log "public-t1-gateway operator paths must be bounded and contain no control characters"
        return 1
      fi
    done
    if [ -z "$PUBLIC_GATEWAY_OPS_CERTIFICATE" ] || [ -z "$PUBLIC_GATEWAY_OPS_CERTIFICATE_KEY" ] ||
      [ -z "$PUBLIC_GATEWAY_OPS_SS_BINARY" ] || [ -z "$PUBLIC_GATEWAY_OPS_EVIDENCE" ]; then
      log "public-t1-gateway cohort requires certificate, key, ss, and ops evidence paths"
      return 1
    fi
  fi

  ensure_trusted_executable_snapshot "$PUBLIC_GATEWAY_PROBE_NGINX_BINARY" \
    'gateway nginx binary' 268435456 PUBLIC_GATEWAY_NGINX_BINARY_RECORD || return 1
  if [ "$PUBLIC_GATEWAY_OPS_REQUIRED" = 1 ]; then
    ensure_trusted_executable_snapshot "$PUBLIC_GATEWAY_OPS_SS_BINARY" \
      'gateway ss binary' 67108864 PUBLIC_GATEWAY_SS_BINARY_RECORD || return 1
  fi

  key="$(apikey)"
  if [ -z "$key" ]; then
    log "public gateway probe requires the relay API key from the protected service environment"
    return 1
  fi

  probe_args=(
    node "$REPO_DIR/scripts/preflight-public-hive-gateway.mjs"
    --config "$PUBLIC_GATEWAY_PROBE_CONFIG"
    --mode fleet
    --nginx-config "$PUBLIC_GATEWAY_PROBE_NGINX_CONFIG"
    --nginx-binary "$PUBLIC_GATEWAY_PROBE_NGINX_BINARY"
    --probe-origin "$PUBLIC_GATEWAY_EXPECTED_ORIGIN"
    --connect-address "$PUBLIC_GATEWAY_EXPECTED_CONNECT_ADDRESS"
    --app-key "$PUBLIC_GATEWAY_EXPECTED_APP_KEY"
    --path "$PUBLIC_GATEWAY_EXPECTED_PATH"
    --release-target "$TARGET"
    --release-sha "$TARGET_SHA"
  )
  probe_args+=(--expected-sha256 "$PUBLIC_GATEWAY_EXPECTED_SHA256")
  [ -z "$PUBLIC_GATEWAY_PROBE_CA" ] || probe_args+=(--ca "$PUBLIC_GATEWAY_PROBE_CA")
  probe_args+=(--evidence "$PUBLIC_GATEWAY_PROBE_EVIDENCE")
  [ "$PUBLIC_GATEWAY_PROBE_PUBLIC_SUFFIX_READY" != "1" ] || probe_args+=(--public-suffix-ready)

  log "checking public HTTPS gateway content and isolation"
  # Shell assignment keeps the API key out of argv. The preflight uses only
  # its presence for the static security gate and never prints or persists it.
  probe_status=0
  HIVERELAY_API_KEY="$key" timeout "$PUBLIC_GATEWAY_PROBE_TIMEOUT" "${probe_args[@]}" || probe_status=$?
  trusted_executable_matches "$PUBLIC_GATEWAY_PROBE_NGINX_BINARY" \
    'gateway nginx binary' 268435456 "$PUBLIC_GATEWAY_NGINX_BINARY_RECORD" || return 1
  if [ "$probe_status" -ne 0 ]; then
    log "public gateway preflight failed for signed cohort relay $RELAY_NAME"
    return 1
  fi

  verifier_args=(
    node "$REPO_DIR/scripts/verify-public-hive-gateway-evidence.mjs"
    --evidence "$PUBLIC_GATEWAY_PROBE_EVIDENCE"
    --release-target "$TARGET"
    --release-sha "$TARGET_SHA"
    --require-mode fleet
    --require-admission-profile "$PUBLIC_GATEWAY_ADMISSION_PROFILE"
    --expected-origin "$PUBLIC_GATEWAY_EXPECTED_ORIGIN"
    --expected-connect-address "$PUBLIC_GATEWAY_EXPECTED_CONNECT_ADDRESS"
    --expected-app-key "$PUBLIC_GATEWAY_EXPECTED_APP_KEY"
    --expected-path "$PUBLIC_GATEWAY_EXPECTED_PATH"
    --expected-sha256 "$PUBLIC_GATEWAY_EXPECTED_SHA256"
    --expected-drive-version "$PUBLIC_GATEWAY_EXPECTED_DRIVE_VERSION"
    --expected-peer-fingerprint256 "$PUBLIC_GATEWAY_EXPECTED_PEER_FINGERPRINT256"
    --expected-nginx-sha256 "$PUBLIC_GATEWAY_EXPECTED_NGINX_SHA256"
  )
  log "verifying public gateway evidence against exact signed manifest bindings"
  if ! timeout "$PUBLIC_GATEWAY_PROBE_TIMEOUT" "${verifier_args[@]}" >/dev/null; then
    log "public gateway evidence does not match the signed cohort contract for $RELAY_NAME"
    return 1
  fi
  [ "$PUBLIC_GATEWAY_OPS_REQUIRED" = 1 ] || return 0

  trusted_executable_matches "$PUBLIC_GATEWAY_PROBE_NGINX_BINARY" \
    'gateway nginx binary' 268435456 "$PUBLIC_GATEWAY_NGINX_BINARY_RECORD" || return 1
  trusted_executable_matches "$PUBLIC_GATEWAY_OPS_SS_BINARY" \
    'gateway ss binary' 67108864 "$PUBLIC_GATEWAY_SS_BINARY_RECORD" || return 1

  operator_contract="$REPO_DIR/fleet/public-hive-gateway-operators/$RELAY_NAME.json"
  release_manifest="$REPO_DIR/$PUBLIC_GATEWAY_MANIFEST_PATH"
  [ -f "$operator_contract" ] && [ ! -L "$operator_contract" ] || {
    log "signed public-t1-gateway operator contract is missing or unsafe"
    return 1
  }
  ops_args=(
    node "$REPO_DIR/scripts/preflight-public-hive-gateway-ops.mjs"
    --mode fleet
    --contract "$operator_contract"
    --config "$PUBLIC_GATEWAY_PROBE_CONFIG"
    --gateway-evidence "$PUBLIC_GATEWAY_PROBE_EVIDENCE"
    --release-sha "$TARGET_SHA"
    --release-manifest "$release_manifest"
    --certificate "$PUBLIC_GATEWAY_OPS_CERTIFICATE"
    --certificate-key "$PUBLIC_GATEWAY_OPS_CERTIFICATE_KEY"
    --dns-live
    --ss-binary "$PUBLIC_GATEWAY_OPS_SS_BINARY"
    --evidence "$PUBLIC_GATEWAY_OPS_EVIDENCE"
  )
  [ -z "$PUBLIC_GATEWAY_OPS_CERTIFICATE_ROOT" ] || \
    ops_args+=(--certificate-root "$PUBLIC_GATEWAY_OPS_CERTIFICATE_ROOT")
  log "checking signed public-t1-gateway DNS, TLS, finite policy, and loopback sockets"
  ops_status=0
  timeout "$PUBLIC_GATEWAY_PROBE_TIMEOUT" "${ops_args[@]}" >/dev/null || ops_status=$?
  trusted_executable_matches "$PUBLIC_GATEWAY_PROBE_NGINX_BINARY" \
    'gateway nginx binary' 268435456 "$PUBLIC_GATEWAY_NGINX_BINARY_RECORD" || return 1
  trusted_executable_matches "$PUBLIC_GATEWAY_OPS_SS_BINARY" \
    'gateway ss binary' 67108864 "$PUBLIC_GATEWAY_SS_BINARY_RECORD" || return 1
  if [ "$ops_status" -ne 0 ]; then
    log "public-t1-gateway operator preflight failed for signed cohort relay $RELAY_NAME"
    return 1
  fi

  ops_verifier_args=(
    node "$REPO_DIR/scripts/verify-public-hive-gateway-ops-evidence.mjs"
    --evidence "$PUBLIC_GATEWAY_OPS_EVIDENCE"
    --contract "$operator_contract"
    --release-manifest "$release_manifest"
    --release-sha "$TARGET_SHA"
    --relay "$RELAY_NAME"
    --expected-contract-sha256 "$PUBLIC_GATEWAY_OPERATOR_CONTRACT_SHA256"
  )
  if ! timeout "$PUBLIC_GATEWAY_PROBE_TIMEOUT" "${ops_verifier_args[@]}" >/dev/null; then
    log "public-t1-gateway ops evidence does not match the signed operator contract for $RELAY_NAME"
    return 1
  fi
  trusted_executable_matches "$PUBLIC_GATEWAY_PROBE_NGINX_BINARY" \
    'gateway nginx binary' 268435456 "$PUBLIC_GATEWAY_NGINX_BINARY_RECORD" || return 1
  trusted_executable_matches "$PUBLIC_GATEWAY_OPS_SS_BINARY" \
    'gateway ss binary' 67108864 "$PUBLIC_GATEWAY_SS_BINARY_RECORD" || return 1
  return 0
}

invalidate_public_gateway_evidence() {
  local directory basename temp generated_at
  [[ "$PUBLIC_GATEWAY_PROBE_EVIDENCE" = /* ]] || return 1
  directory="$(dirname "$PUBLIC_GATEWAY_PROBE_EVIDENCE")"
  basename="$(basename "$PUBLIC_GATEWAY_PROBE_EVIDENCE")"
  [ -d "$directory" ] && [ ! -L "$directory" ] || return 1
  temp="$(mktemp "$directory/.${basename}.invalid.XXXXXX")" || return 1
  chmod 0600 "$temp" 2>/dev/null || { rm -f "$temp"; return 1; }
  generated_at="$(date -u +%FT%TZ)"
  if ! printf '{"schema":"hiverelay-public-gateway-evidence-invalid-v1","invalidatedAt":"%s","releaseTarget":"%s","releaseSha":"%s","relay":"%s"}\n' \
    "$generated_at" "$TARGET" "$TARGET_SHA" "$RELAY_NAME" > "$temp"; then
    rm -f "$temp"
    return 1
  fi
  sync -f "$temp" >/dev/null 2>&1 || { rm -f "$temp"; return 1; }
  if ! mv -f "$temp" "$PUBLIC_GATEWAY_PROBE_EVIDENCE"; then
    rm -f "$temp"
    return 1
  fi
  sync -f "$PUBLIC_GATEWAY_PROBE_EVIDENCE" >/dev/null 2>&1 || return 1
  sync -f "$directory" >/dev/null 2>&1 || return 1
  log "atomically invalidated stale public gateway evidence"
  return 0
}

invalidate_public_gateway_ops_evidence() {
  local directory basename temp generated_at
  [ "$PUBLIC_GATEWAY_OPS_REQUIRED" = 1 ] || return 0
  [[ "$PUBLIC_GATEWAY_OPS_EVIDENCE" = /* ]] || return 1
  directory="$(dirname "$PUBLIC_GATEWAY_OPS_EVIDENCE")"
  basename="$(basename "$PUBLIC_GATEWAY_OPS_EVIDENCE")"
  [ -d "$directory" ] && [ ! -L "$directory" ] || return 1
  temp="$(mktemp "$directory/.${basename}.invalid.XXXXXX")" || return 1
  chmod 0600 "$temp" 2>/dev/null || { rm -f "$temp"; return 1; }
  generated_at="$(date -u +%FT%TZ)"
  if ! printf '{"schema":"hiverelay-public-gateway-operator-readiness-invalid-v1","invalidatedAt":"%s","releaseTarget":"%s","releaseSha":"%s","relay":"%s","operatorContractSha256":"%s"}\n' \
    "$generated_at" "$TARGET" "$TARGET_SHA" "$RELAY_NAME" "$PUBLIC_GATEWAY_OPERATOR_CONTRACT_SHA256" > "$temp"; then
    rm -f "$temp"
    return 1
  fi
  sync -f "$temp" >/dev/null 2>&1 || { rm -f "$temp"; return 1; }
  if ! mv -f "$temp" "$PUBLIC_GATEWAY_OPS_EVIDENCE"; then
    rm -f "$temp"
    return 1
  fi
  sync -f "$PUBLIC_GATEWAY_OPS_EVIDENCE" >/dev/null 2>&1 || return 1
  sync -f "$directory" >/dev/null 2>&1 || return 1
  log "atomically invalidated stale public-t1-gateway ops evidence"
  return 0
}

verify_live_public_gateway_quarantine() {
  local contract_path contract_tmp contract_size quarantine_timeout
  [ -n "$PUBLIC_GATEWAY_QUARANTINE_CONTRACT_REF" ] &&
    [[ "$PUBLIC_GATEWAY_QUARANTINE_CONTRACT_SHA256" =~ ^[a-f0-9]{64}$ ]] || return 1
  [ -f "$PUBLIC_GATEWAY_QUARANTINE_VERIFIER" ] && [ ! -L "$PUBLIC_GATEWAY_QUARANTINE_VERIFIER" ] || return 1
  contract_path="fleet/public-hive-gateway-operators/$RELAY_NAME.json"
  [ "$(git ls-tree --name-only "$PUBLIC_GATEWAY_QUARANTINE_CONTRACT_REF" -- "$contract_path")" = "$contract_path" ] || return 1
  contract_tmp="$(mktemp)" || return 1
  chmod 0600 "$contract_tmp" 2>/dev/null || { rm -f "$contract_tmp"; return 1; }
  if ! git show "$PUBLIC_GATEWAY_QUARANTINE_CONTRACT_REF:$contract_path" > "$contract_tmp"; then
    rm -f "$contract_tmp"
    return 1
  fi
  contract_size="$(wc -c < "$contract_tmp" | tr -d '[:space:]')"
  if ! [[ "$contract_size" =~ ^[0-9]+$ ]] || [ "$contract_size" -lt 1 ] || [ "$contract_size" -gt 262144 ]; then
    rm -f "$contract_tmp"
    return 1
  fi
  local -a verify_args
  verify_args=(node "$PUBLIC_GATEWAY_QUARANTINE_VERIFIER"
    --contract "$contract_tmp"
    --expected-digest "$PUBLIC_GATEWAY_QUARANTINE_CONTRACT_SHA256"
    --nginx-binary "$PUBLIC_GATEWAY_PROBE_NGINX_BINARY")
  [ -z "$PUBLIC_GATEWAY_PROBE_CA" ] || verify_args+=(--ca "$PUBLIC_GATEWAY_PROBE_CA")
  quarantine_timeout="$PUBLIC_GATEWAY_PROBE_TIMEOUT"
  [[ "$quarantine_timeout" =~ ^[1-9][0-9]{0,2}$ ]] && [ "$quarantine_timeout" -le 300 ] || \
    quarantine_timeout=90
  local status=0
  timeout "$quarantine_timeout" "${verify_args[@]}" >/dev/null || status=$?
  rm -f "$contract_tmp"
  return "$status"
}

prepare_public_gateway_quarantine_authority() {
  local root relative destination entry size
  local -a closure=(
    fleet/quarantine-public-gateway.sh
    scripts/verify-public-hive-gateway-quarantine.mjs
    scripts/lib/public-hive-gateway-quarantine-authority.mjs
    scripts/lib/public-hive-gateway-release-manifest.mjs
    scripts/lib/public-hive-gateway-policy.mjs
  )
  if [ "$PUBLIC_GATEWAY_REQUIRED" != 1 ] && [ "$SOURCE_PUBLIC_GATEWAY_REQUIRED" != 1 ]; then
    return 0
  fi
  root="$(mktemp -d)" || return 1
  chmod 0700 "$root" 2>/dev/null || { rm -rf "$root"; return 1; }
  mkdir -m 0700 "$root/fleet" "$root/scripts" "$root/scripts/lib" || { rm -rf "$root"; return 1; }
  for relative in "${closure[@]}"; do
    entry="$(git ls-tree --name-only "$CUR_SHA" -- "$relative")" || { rm -rf "$root"; return 1; }
    [ "$entry" = "$relative" ] || { rm -rf "$root"; return 1; }
    destination="$root/$relative"
    git show "$CUR_SHA:$relative" > "$destination" || { rm -rf "$root"; return 1; }
    chmod 0400 "$destination" 2>/dev/null || { rm -rf "$root"; return 1; }
    size="$(wc -c < "$destination" | tr -d '[:space:]')"
    [[ "$size" =~ ^[0-9]+$ ]] && [ "$size" -ge 1 ] && [ "$size" -le 1048576 ] || {
      rm -rf "$root"
      return 1
    }
  done
  PUBLIC_GATEWAY_QUARANTINE_AUTHORITY_DIR="$root"
  PUBLIC_GATEWAY_QUARANTINE_HELPER_AUTHORITY="$root/fleet/quarantine-public-gateway.sh"
  PUBLIC_GATEWAY_QUARANTINE_VERIFIER="$root/scripts/verify-public-hive-gateway-quarantine.mjs"
  log "froze current-release public gateway quarantine verifier/helper authority at $CUR_SHA"
}

cleanup_public_gateway_quarantine_authority() {
  [ -z "$PUBLIC_GATEWAY_QUARANTINE_AUTHORITY_DIR" ] || \
    rm -rf "$PUBLIC_GATEWAY_QUARANTINE_AUTHORITY_DIR"
  PUBLIC_GATEWAY_QUARANTINE_HELPER_AUTHORITY=""
}

quarantine_public_gateway_edge() {
  local path quarantine_record nginx_record authority_record authority_final
  [ -n "$PUBLIC_GATEWAY_QUARANTINE_BACKUP" ] || \
    PUBLIC_GATEWAY_QUARANTINE_BACKUP="${PUBLIC_GATEWAY_PROBE_NGINX_CONFIG}.pre-quarantine"
  for path in "$PUBLIC_GATEWAY_QUARANTINE_COMMAND" "$PUBLIC_GATEWAY_PROBE_NGINX_CONFIG" \
    "$PUBLIC_GATEWAY_QUARANTINE_BACKUP" "$PUBLIC_GATEWAY_PROBE_NGINX_BINARY"; do
    [[ "$path" = /* ]] || { log "gateway quarantine requires absolute command/config paths"; return 1; }
    if [ "${#path}" -gt 4096 ] || printf '%s' "$path" | LC_ALL=C grep -q '[[:cntrl:]]'; then
      log "gateway quarantine paths must be bounded and contain no control characters"
      return 1
    fi
  done
  ensure_trusted_executable_snapshot "$PUBLIC_GATEWAY_PROBE_NGINX_BINARY" \
    'gateway nginx binary' 268435456 PUBLIC_GATEWAY_NGINX_BINARY_RECORD || return 1
  nginx_record="$PUBLIC_GATEWAY_NGINX_BINARY_RECORD"
  if ! quarantine_record="$(trusted_executable_record "$PUBLIC_GATEWAY_QUARANTINE_COMMAND" \
      'gateway quarantine command' 1048576)"; then
    [ -z "$quarantine_record" ] || printf '%s\n' "$quarantine_record"
    "$PUBLIC_GATEWAY_PROBE_NGINX_BINARY" -s stop >/dev/null 2>&1 || true
    return 1
  fi
  [ -n "$PUBLIC_GATEWAY_QUARANTINE_HELPER_AUTHORITY" ] && \
    [ -f "$PUBLIC_GATEWAY_QUARANTINE_HELPER_AUTHORITY" ] && \
    [ ! -L "$PUBLIC_GATEWAY_QUARANTINE_HELPER_AUTHORITY" ] || {
    log "current-release signed quarantine helper authority is unavailable"
    return 1
  }
  authority_record="$(stat_record "$PUBLIC_GATEWAY_QUARANTINE_HELPER_AUTHORITY")" || return 1
  if ! cmp -s -- "$PUBLIC_GATEWAY_QUARANTINE_COMMAND" "$PUBLIC_GATEWAY_QUARANTINE_HELPER_AUTHORITY"; then
    log "installed gateway quarantine command differs from the signed current-release helper bytes"
    "$PUBLIC_GATEWAY_PROBE_NGINX_BINARY" -s stop >/dev/null 2>&1 || true
    return 1
  fi
  authority_final="$(stat_record "$PUBLIC_GATEWAY_QUARANTINE_HELPER_AUTHORITY")" || return 1
  [ "$authority_final" = "$authority_record" ] || {
    log "signed current-release quarantine helper authority changed during comparison"
    return 1
  }
  trusted_executable_matches "$PUBLIC_GATEWAY_QUARANTINE_COMMAND" \
    'gateway quarantine command' 1048576 "$quarantine_record" || return 1
  trusted_executable_matches "$PUBLIC_GATEWAY_PROBE_NGINX_BINARY" \
    'gateway nginx binary' 268435456 "$nginx_record" || return 1
  if ! "$PUBLIC_GATEWAY_QUARANTINE_COMMAND" \
      "$PUBLIC_GATEWAY_PROBE_NGINX_CONFIG" \
      "$PUBLIC_GATEWAY_QUARANTINE_BACKUP" \
      "$PUBLIC_GATEWAY_PROBE_NGINX_BINARY"; then
    if trusted_executable_matches "$PUBLIC_GATEWAY_PROBE_NGINX_BINARY" \
        'gateway nginx binary' 268435456 "$nginx_record"; then
      "$PUBLIC_GATEWAY_PROBE_NGINX_BINARY" -s stop >/dev/null 2>&1 || true
    fi
    return 1
  fi
  trusted_executable_matches "$PUBLIC_GATEWAY_QUARANTINE_COMMAND" \
      'gateway quarantine command' 1048576 "$quarantine_record" &&
    trusted_executable_matches "$PUBLIC_GATEWAY_PROBE_NGINX_BINARY" \
      'gateway nginx binary' 268435456 "$nginx_record" || {
    log "CRITICAL quarantine helper or nginx binary changed during containment"
    return 1
  }
  verify_live_public_gateway_quarantine || {
    log "CRITICAL active nginx/app-address TLS 421 quarantine proof failed"
    if trusted_executable_matches "$PUBLIC_GATEWAY_PROBE_NGINX_BINARY" \
        'gateway nginx binary' 268435456 "$nginx_record"; then
      "$PUBLIC_GATEWAY_PROBE_NGINX_BINARY" -s stop >/dev/null 2>&1 || true
    fi
    return 1
  }
  trusted_executable_matches "$PUBLIC_GATEWAY_PROBE_NGINX_BINARY" \
    'gateway nginx binary' 268435456 "$nginx_record" || {
    log "CRITICAL nginx binary changed during quarantine verification"
    return 1
  }
}

contain_up_to_date_gateway_failure() {
  local failed=0
  invalidate_public_gateway_evidence || {
    log "CRITICAL could not invalidate stale public gateway evidence"
    failed=1
  }
  invalidate_public_gateway_ops_evidence || {
    log "CRITICAL could not invalidate stale public-t1-gateway ops evidence"
    failed=1
  }
  quarantine_public_gateway_edge || {
    log "CRITICAL could not quarantine public app HTTPS edge; management service was not stopped"
    failed=1
  }
  return "$failed"
}

verify_disabled_public_gateway_config() {
  [ -f "$PUBLIC_GATEWAY_DISABLED_CONFIG_VERIFIER" ] && [ ! -L "$PUBLIC_GATEWAY_DISABLED_CONFIG_VERIFIER" ] || {
    log "public gateway disabled-config verifier is missing from the trusted current release"
    return 1
  }
  [ -n "$PUBLIC_GATEWAY_PROBE_CONFIG" ] || {
    log "public gateway retirement requires the explicit operator config path"
    return 1
  }
  node "$PUBLIC_GATEWAY_DISABLED_CONFIG_VERIFIER" "$PUBLIC_GATEWAY_PROBE_CONFIG" >/dev/null
}

prepare_public_gateway_retirement() {
  local saved_ops="$PUBLIC_GATEWAY_OPS_REQUIRED" saved_digest="$PUBLIC_GATEWAY_OPERATOR_CONTRACT_SHA256" failed=0
  [ "$PUBLIC_GATEWAY_RETIREMENT_REQUIRED" = 1 ] || return 0
  PUBLIC_GATEWAY_OPS_REQUIRED=1
  PUBLIC_GATEWAY_OPERATOR_CONTRACT_SHA256="$SOURCE_PUBLIC_GATEWAY_OPERATOR_CONTRACT_SHA256"
  log "source public-t1 gateway is leaving its signed cohort; containing HTTPS before any checkout"
  quarantine_public_gateway_edge || { log "CRITICAL public gateway retirement containment failed"; failed=1; }
  invalidate_public_gateway_evidence || { log "CRITICAL public gateway retirement evidence invalidation failed"; failed=1; }
  invalidate_public_gateway_ops_evidence || { log "CRITICAL public gateway retirement ops evidence invalidation failed"; failed=1; }
  PUBLIC_GATEWAY_OPS_REQUIRED="$saved_ops"
  PUBLIC_GATEWAY_OPERATOR_CONTRACT_SHA256="$saved_digest"
  [ "$failed" = 0 ] || return 1
  verify_disabled_public_gateway_config || {
    log "public edge is contained, but operator config remains active; set an explicit disabled config and retry"
    return 1
  }
}

verify_public_gateway_retired() {
  [ "$PUBLIC_GATEWAY_RETIREMENT_REQUIRED" = 1 ] || return 0
  quarantine_public_gateway_edge && verify_disabled_public_gateway_config
}

deps_if_changed() { # $1=from-ref $2=to-ref
  if ! git diff --quiet "$1" "$2" -- package-lock.json 2>/dev/null; then
    log "package-lock changed -> reinstalling deps"
    npm ci --omit=dev --no-audit --no-fund 2>&1 | tail -2
  fi
}

rollback_to_previous() {
  local reason="$1"
  local containment_failed=0
  log "FAIL $reason — ROLLING BACK to $CUR_VER ($CUR_SHA)"
  if [ "$PUBLIC_GATEWAY_REQUIRED" = 1 ] &&
    [ "$PUBLIC_GATEWAY_DEPLOYMENT_PROFILE" = "public-t1-gateway" ]; then
    log "failed public-t1 transition: invalidating target evidence and quarantining public app HTTPS before management rollback"
    contain_up_to_date_gateway_failure || containment_failed=1
  fi
  if ! git checkout --quiet "$CUR_SHA"; then
    log "CRITICAL could not checkout previous SHA"
    exit 1
  fi
  if ! git diff --cached --quiet HEAD -- || ! verify_raw_tracked_tree; then
    log "CRITICAL previous checkout does not match its raw tracked blobs"
    exit 1
  fi
  if ! deps_if_changed "$TARGET_SHA" "$CUR_SHA"; then
    log "CRITICAL rollback dependency reinstall failed — manual attention needed on $(hostname)"
    exit 1
  fi
  if ! verify_raw_tracked_tree; then
    log "CRITICAL rollback dependency install changed tracked release bytes — manual attention needed on $(hostname)"
    exit 1
  fi
  if ! systemctl restart "$SERVICE"; then
    log "CRITICAL rollback checkout was restored but management service restart failed"
    exit 1
  fi
  if healthy "${CUR_VER#v}"; then
    if [ "$PUBLIC_GATEWAY_REQUIRED" = 1 ] &&
      [ "$PUBLIC_GATEWAY_DEPLOYMENT_PROFILE" = "public-t1-gateway" ]; then
      if [ "$containment_failed" = 0 ]; then
        log "management rollback OK — back on $CUR_VER; public edge remains quarantined pending refreshed previous-release manifest/config/nginx/DNS/TLS/SPKI/socket/content evidence"
      else
        log "CRITICAL management rollback recovered $CUR_VER but public edge containment was incomplete — operator action required"
      fi
    else
      log "rollback OK — back on $CUR_VER"
    fi
  else
    log "CRITICAL rollback unhealthy — manual attention needed on $(hostname)"
  fi
  exit 1
}

# An up-to-date signed cohort gateway still refreshes externally observed,
# release-bound evidence on every tick. There is no code checkout to roll back;
# a failure instead atomically poisons stale evidence and contains only the
# public-app nginx edge while leaving the management API/service running.
prepare_public_gateway_quarantine_authority || \
  die "could not freeze current-release public gateway quarantine verifier authority"
trap cleanup_public_gateway_quarantine_authority EXIT HUP INT TERM
if ! prepare_public_gateway_retirement; then
  die "public-t1 gateway retirement is contained but not eligible for checkout; operator action required"
fi

if [ "$UP_TO_DATE" = 1 ]; then
  if ! public_gateway_healthy; then
    if contain_up_to_date_gateway_failure; then
      die "public HTTPS gateway failed on up-to-date $TARGET; stale evidence invalidated and public edge quarantined; management API left running"
    fi
    die "public HTTPS gateway failed on up-to-date $TARGET; containment incomplete and operator action is required"
  fi
  log "channel=$CHANNEL up-to-date at $TARGET ($TARGET_SHA)"
  exit 0
fi

# ── update ─────────────────────────────────────────────────────────
# Tag trust and the exact target manifest were already verified above, before
# any target checkout or target-controlled process was launched.
if ! git checkout --quiet "$TARGET"; then
  log "FAIL checkout $TARGET failed; restoring exact prior SHA before any service mutation"
  if [ "$PUBLIC_GATEWAY_REQUIRED" = 1 ]; then
    contain_up_to_date_gateway_failure || log "CRITICAL public edge containment was incomplete after target checkout failure"
  fi
  git checkout --quiet "$CUR_SHA" || die "target checkout failed and prior SHA restoration also failed"
  git diff --cached --quiet HEAD -- && verify_raw_tracked_tree || \
    die "target checkout failed and restored prior checkout does not match raw tracked blobs"
  die "checkout $TARGET failed; prior SHA restored"
fi
git diff --cached --quiet HEAD -- && verify_raw_tracked_tree \
  || rollback_to_previous "target checkout does not match its raw tracked blobs"
deps_if_changed "$CUR_SHA" "$TARGET_SHA" || rollback_to_previous "dependency install failed on $TARGET"
verify_raw_tracked_tree || rollback_to_previous "dependency install changed tracked release bytes on $TARGET"
systemctl restart "$SERVICE" || rollback_to_previous "management service restart failed on $TARGET"

if healthy "${TARGET#v}"; then
  public_gateway_healthy || rollback_to_previous "public HTTPS gateway probe failed on $TARGET"
  verify_public_gateway_retired || rollback_to_previous "retired public HTTPS gateway containment/config proof failed on $TARGET"
  if [ "$PUBLIC_GATEWAY_RETIREMENT_REQUIRED" = 1 ]; then
    log "OK updated $CUR_VER -> $TARGET — public gateway retired green; edge remains TLS 421 contained"
  else
  log "OK updated $CUR_VER -> $TARGET — health green"
  fi
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
