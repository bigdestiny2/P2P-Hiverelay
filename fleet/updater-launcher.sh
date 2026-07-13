#!/bin/bash
#
# Stable root-installed launcher for the pull updater.
#
# The launcher is intentionally small. The full updater remains in the release
# checkout so a successful signed-tag checkout also updates the code used on
# the next timer tick. Before executing that code, this launcher proves that:
#
#   * fleet/updater.sh is the exact blob recorded at HEAD; and
#   * HEAD is the commit named by a trusted, signed, annotated release tag.
#
# This prevents a dirty checkout or an unsigned branch from replacing the
# root-executed updater merely because /usr/local/bin is a stable entry point.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
HOME=/root
export HOME
unset BASH_ENV ENV CDPATH GLOBIGNORE LD_PRELOAD LD_LIBRARY_PATH NODE_OPTIONS NODE_PATH \
  PYTHONPATH PYTHONHOME PYTHONSTARTUP SSH_ASKPASS SSH_AUTH_SOCK 2>/dev/null || true
set -euo pipefail

: "${HOME:=/root}"
unset GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_CONFIG GIT_CONFIG_COUNT
unset GIT_CONFIG_GLOBAL GIT_CONFIG_PARAMETERS GIT_CONFIG_SYSTEM GIT_DIR GIT_EXEC_PATH
unset GIT_INDEX_FILE GIT_NAMESPACE GIT_OBJECT_DIRECTORY GIT_PREFIX GIT_PROXY_COMMAND
unset GIT_QUARANTINE_PATH GIT_REPLACE_REF_BASE GIT_SHALLOW_FILE GIT_SSH GIT_SSH_COMMAND
unset GIT_SSL_CAINFO GIT_SSL_CAPATH GIT_SSL_NO_VERIFY GIT_WORK_TREE
export GIT_NO_REPLACE_OBJECTS=1
export GIT_GRAFT_FILE=/dev/null/hiverelay-disabled
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0=core.hooksPath
export GIT_CONFIG_VALUE_0=/dev/null
export GIT_CONFIG_KEY_1=core.fsmonitor
export GIT_CONFIG_VALUE_1=false

CONF="${HIVERELAY_UPDATER_CONF:-/etc/hiverelay-updater.conf}"
ALLOWED_SIGNERS="${HIVERELAY_ALLOWED_SIGNERS:-/etc/hiverelay/allowed-signers}"
UPDATER_ENV_TRUST_FILE="${HIVERELAY_UPDATER_ENV_TRUST_FILE:-/etc/hiverelay/hiverelay-updater.env}"

log() { echo "[updater-launcher $(date -u +%FT%TZ)] $*"; }
die() { log "ERR $*" >&2; exit 1; }

stat_record() {
  stat -f '%u|%Lp|%l|%z|%d|%i|%m|%c' "$1" 2>/dev/null || \
    stat -c '%u|%a|%h|%s|%d|%i|%Y|%Z' "$1" 2>/dev/null
}

safe_parent() {
  local path="$1" label="$2" parent record uid mode rest mode_value
  # Preserve the lexical chain so an intermediate symlink cannot disappear
  # into an otherwise trusted physical target before it is inspected.
  parent="$(dirname "$path")"
  while :; do
    [ -d "$parent" ] && [ ! -L "$parent" ] || die "$label parent is not a regular directory: $parent"
    record="$(stat_record "$parent")" || die "cannot inspect $label parent: $parent"
    IFS='|' read -r uid mode rest <<< "$record"
    [ "$uid" = "$EUID" ] || [ "$uid" = 0 ] || die "$label parent must be owned by root or the effective user: $parent"
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || die "$label parent mode is malformed: $parent"
    mode_value=$((8#$mode))
    if (( (mode_value & 8#022) != 0 )); then
      [ "$uid" = 0 ] && (( (mode_value & 8#1000) != 0 )) || \
        die "$label parent must not be group/world writable: $parent"
    fi
    [ "$parent" = / ] && break
    parent="$(dirname "$parent")"
  done
}

require_physical_canonical_path() {
  local path="$1" label="$2" physical_parent leaf canonical
  physical_parent="$(cd -P "$(dirname "$path")" 2>/dev/null && pwd -P)" || \
    die "$label parent cannot be resolved"
  leaf="$(basename "$path")"
  if [ "$physical_parent" = / ]; then canonical="/$leaf"; else canonical="$physical_parent/$leaf"; fi
  [ "$path" = "$canonical" ] || \
    die "$label path must be canonical and contain no symlink ancestors"
}

canonical_absolute_path() {
  local value="$1"
  [ -z "$value" ] && return 0
  [[ "$value" = /* ]] && [ "${#value}" -le 4096 ] || return 1
  [[ "$value" != *'//' ]] && [[ "$value" != *'/./'* ]] && [[ "$value" != *'/../'* ]] &&
    [[ "$value" != */. ]] && [[ "$value" != */.. ]] &&
    ! printf '%s' "$value" | LC_ALL=C grep -q '[[:cntrl:]]'
}

validate_updater_env_value() {
  local key="$1" value="$2" port
  case "$key" in
    HIVERELAY_SERVICE)
      [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9_.@-]{0,126}([.]service)?$ ]] || return 1
      ;;
    HIVERELAY_API)
      if [[ "$value" =~ ^http://(127[.]0[.]0[.]1|localhost):([0-9]{1,5})$ ]]; then
        port="${BASH_REMATCH[2]}"
      elif [[ "$value" =~ ^http://\[::1\]:([0-9]{1,5})$ ]]; then
        port="${BASH_REMATCH[1]}"
      else
        return 1
      fi
      [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || return 1
      ;;
    HIVERELAY_CONTROL_BRANCH)
      [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$ ]] &&
        [[ "$value" != -* ]] && [[ "$value" != *..* ]] || return 1
      ;;
    HIVERELAY_HEALTH_TIMEOUT|HIVERELAY_PUBLIC_GATEWAY_PROBE_TIMEOUT)
      [[ "$value" =~ ^[1-9][0-9]{0,2}$ ]] && [ "$value" -le 300 ] || return 1
      ;;
    HIVERELAY_REQUIRE_SIGNED_TAGS|HIVERELAY_PUBLIC_GATEWAY_PROBE_PUBLIC_SUFFIX_READY)
      [ "$value" = 0 ] || [ "$value" = 1 ] || return 1
      ;;
    HIVERELAY_CONTROL_STATE|HIVERELAY_ENV_FILE|HIVERELAY_PUBLIC_GATEWAY_PROBE_CONFIG|\
    HIVERELAY_PUBLIC_GATEWAY_PROBE_NGINX_CONFIG|HIVERELAY_PUBLIC_GATEWAY_PROBE_NGINX_BINARY|\
    HIVERELAY_PUBLIC_GATEWAY_PROBE_CA|HIVERELAY_PUBLIC_GATEWAY_PROBE_EVIDENCE|\
    HIVERELAY_PUBLIC_GATEWAY_OPS_CERTIFICATE|HIVERELAY_PUBLIC_GATEWAY_OPS_CERTIFICATE_KEY|\
    HIVERELAY_PUBLIC_GATEWAY_OPS_CERTIFICATE_ROOT|HIVERELAY_PUBLIC_GATEWAY_OPS_SS_BINARY|\
    HIVERELAY_PUBLIC_GATEWAY_OPS_EVIDENCE|HIVERELAY_PUBLIC_GATEWAY_QUARANTINE_COMMAND|\
    HIVERELAY_PUBLIC_GATEWAY_QUARANTINE_BACKUP)
      canonical_absolute_path "$value" || return 1
      ;;
  esac
}

trusted_file_record() {
  local path="$1" label="$2" exact_mode="${3:-}" max_size="${4:-0}"
  local owner_policy="${5:-euid}"
  local min_size="${6:-1}"
  local require_single_link="${7:-1}"
  local record uid mode nlink size rest mode_value
  [[ "$path" = /* ]] || die "$label path must be absolute"
  [ "${#path}" -le 4096 ] || die "$label path is too long"
  require_physical_canonical_path "$path" "$label"
  [ -f "$path" ] && [ ! -L "$path" ] || die "$label must be a regular non-symlink file"
  safe_parent "$path" "$label"
  record="$(stat_record "$path")" || die "cannot inspect $label"
  IFS='|' read -r uid mode nlink size rest <<< "$record"
  if [ "$owner_policy" = root-ok ]; then
    [ "$uid" = "$EUID" ] || [ "$uid" = 0 ] || die "$label must be owned by root or the effective user"
  else
    [ "$uid" = "$EUID" ] || die "$label must be owned by the effective user"
  fi
  [ "$require_single_link" = 0 ] || [ "$nlink" = 1 ] || die "$label must have exactly one link"
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || die "$label mode is malformed"
  mode_value=$((8#$mode))
  (( (mode_value & 8#022) == 0 )) || die "$label must not be group/world writable"
  [ -z "$exact_mode" ] || [ "$mode" = "$exact_mode" ] || die "$label must have mode $exact_mode"
  if [ "$max_size" -gt 0 ]; then
    [[ "$size" =~ ^[0-9]+$ ]] && [ "$size" -ge "$min_size" ] && [ "$size" -le "$max_size" ] || \
      die "$label size must be from $min_size to $max_size bytes"
  fi
  printf '%s\n' "$record"
}

trusted_directory() {
  local path="$1" label="$2" record uid mode rest mode_value
  [[ "$path" = /* ]] || die "$label path must be absolute"
  require_physical_canonical_path "$path" "$label"
  [ -d "$path" ] && [ ! -L "$path" ] || die "$label must be a regular directory"
  safe_parent "$path" "$label"
  record="$(stat_record "$path")" || die "cannot inspect $label"
  IFS='|' read -r uid mode rest <<< "$record"
  [ "$uid" = "$EUID" ] || [ "$uid" = 0 ] || die "$label must be owned by root or the effective user"
  mode_value=$((8#$mode))
  (( (mode_value & 8#022) == 0 )) || die "$label must not be group/world writable"
}

sha256_file() {
  if [ -x /usr/bin/shasum ]; then /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'
  elif [ -x /usr/bin/sha256sum ]; then /usr/bin/sha256sum "$1" | /usr/bin/awk '{print $1}'
  else die 'trusted SHA-256 utility is unavailable'
  fi
}

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

strip_optional_quotes() {
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

trusted_file_record "$CONF" 'updater config' '' 262144 >/dev/null
UPDATER_ENV_RECORD="$(trusted_file_record "$UPDATER_ENV_TRUST_FILE" 'updater EnvironmentFile' 600 262144 euid 0)"
UPDATER_ENV_SHA256="$(sha256_file "$UPDATER_ENV_TRUST_FILE")"

UPDATER_ENV_KEYS_SEEN=$'\n'
while IFS= read -r env_line || [ -n "$env_line" ]; do
  [[ "$env_line" =~ ^[[:space:]]*($|#) ]] && continue
  [[ "$env_line" == *=* ]] || die 'updater EnvironmentFile contains a malformed line'
  env_key="${env_line%%=*}"
  env_value="${env_line#*=}"
  env_key="$(printf '%s' "$env_key" | awk '{$1=$1; print}')"
  env_value="$(printf '%s' "$env_value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [[ "$env_key" =~ ^HIVERELAY_[A-Z0-9_]+$ ]] || die 'updater EnvironmentFile contains an invalid key'
  case "$UPDATER_ENV_KEYS_SEEN" in
    *$'\n'"$env_key"$'\n'*) die "updater EnvironmentFile repeats $env_key" ;;
  esac
  case "$env_key" in
    HIVERELAY_SERVICE|HIVERELAY_API|\
    HIVERELAY_CONTROL_BRANCH|HIVERELAY_CONTROL_STATE|HIVERELAY_ENV_FILE|HIVERELAY_HEALTH_TIMEOUT|\
    HIVERELAY_REQUIRE_SIGNED_TAGS|HIVERELAY_PUBLIC_GATEWAY_PROBE_CONFIG|\
    HIVERELAY_PUBLIC_GATEWAY_PROBE_NGINX_CONFIG|HIVERELAY_PUBLIC_GATEWAY_PROBE_NGINX_BINARY|\
    HIVERELAY_PUBLIC_GATEWAY_PROBE_CA|HIVERELAY_PUBLIC_GATEWAY_PROBE_EVIDENCE|\
    HIVERELAY_PUBLIC_GATEWAY_OPS_CERTIFICATE|HIVERELAY_PUBLIC_GATEWAY_OPS_CERTIFICATE_KEY|\
    HIVERELAY_PUBLIC_GATEWAY_OPS_CERTIFICATE_ROOT|HIVERELAY_PUBLIC_GATEWAY_OPS_SS_BINARY|\
    HIVERELAY_PUBLIC_GATEWAY_OPS_EVIDENCE|HIVERELAY_PUBLIC_GATEWAY_PROBE_PUBLIC_SUFFIX_READY|\
    HIVERELAY_PUBLIC_GATEWAY_PROBE_TIMEOUT|HIVERELAY_PUBLIC_GATEWAY_QUARANTINE_COMMAND|\
    HIVERELAY_PUBLIC_GATEWAY_QUARANTINE_BACKUP) ;;
    *) die "updater EnvironmentFile key $env_key is not allowed" ;;
  esac
  if [ "${#env_value}" -gt 4096 ] || printf '%s' "$env_value" | LC_ALL=C grep -q '[[:cntrl:]]'; then
    die "updater EnvironmentFile value for $env_key is unsafe"
  fi
  env_value="$(strip_optional_quotes "$env_value")"
  validate_updater_env_value "$env_key" "$env_value" || \
    die "updater EnvironmentFile value for $env_key is not canonical or in range"
  UPDATER_ENV_KEYS_SEEN="${UPDATER_ENV_KEYS_SEEN}${env_key}"$'\n'
  export "$env_key=$env_value"
done < "$UPDATER_ENV_TRUST_FILE"
[ "$(trusted_file_record "$UPDATER_ENV_TRUST_FILE" 'updater EnvironmentFile' 600 262144 euid 0)" = "$UPDATER_ENV_RECORD" ] || \
  die 'updater EnvironmentFile metadata changed while parsing'
[ "$(sha256_file "$UPDATER_ENV_TRUST_FILE")" = "$UPDATER_ENV_SHA256" ] || \
  die 'updater EnvironmentFile content changed while parsing'

REPO_DIR="${HIVERELAY_REPO_DIR:-}"
if [ -z "$REPO_DIR" ]; then
  configured_repo=""
  if configured_repo="$(read_config_value REPO_DIR)"; then
    REPO_DIR="$(strip_optional_quotes "$configured_repo")"
  else
    status=$?
    [ "$status" -ne 2 ] || die "$CONF contains duplicate REPO_DIR entries"
  fi
fi
REPO_DIR="${REPO_DIR:-$HOME/hiverelay}"

[[ "$REPO_DIR" = /* ]] || die "repository path must be absolute"
[ "${#REPO_DIR}" -le 4096 ] || die "repository path is too long"
if printf '%s' "$REPO_DIR" | LC_ALL=C grep -q '[[:space:][:cntrl:]]'; then
  die "repository path must not contain whitespace or control characters"
fi
if printf '%s' "$ALLOWED_SIGNERS" | LC_ALL=C grep -q '[[:cntrl:]]'; then
  die "allowed-signers path contains control characters"
fi
[[ "$ALLOWED_SIGNERS" = /* ]] || die "allowed-signers path must be absolute"

UPDATER="$REPO_DIR/fleet/updater.sh"
[ -d "$REPO_DIR/.git" ] || [ -f "$REPO_DIR/.git" ] || die "repository not found at $REPO_DIR"
trusted_directory "$REPO_DIR" 'repository'
[ -f "$UPDATER" ] && [ ! -L "$UPDATER" ] || die "trusted updater must be a regular non-symlink file"
UPDATER_RECORD="$(trusted_file_record "$UPDATER" 'trusted updater' '' 1048576 root-ok)"
ALLOWED_SIGNERS_RECORD="$(trusted_file_record "$ALLOWED_SIGNERS" 'allowed-signers file' '' 262144)"
ALLOWED_SIGNERS_SHA256="$(sha256_file "$ALLOWED_SIGNERS")"
ALLOWED_SIGNERS_SNAPSHOT="$(mktemp /tmp/hiverelay-allowed-signers.XXXXXX)" || die 'cannot allocate allowed-signers snapshot'
cleanup_snapshot() { rm -f "$ALLOWED_SIGNERS_SNAPSHOT"; }
trap cleanup_snapshot EXIT HUP INT TERM
/bin/cat "$ALLOWED_SIGNERS" > "$ALLOWED_SIGNERS_SNAPSHOT"
chmod 0400 "$ALLOWED_SIGNERS_SNAPSHOT"
[ "$(sha256_file "$ALLOWED_SIGNERS_SNAPSHOT")" = "$ALLOWED_SIGNERS_SHA256" ] || die 'allowed-signers changed while snapshotting'

GIT_BIN="${HIVERELAY_GIT_BIN:-/usr/bin/git}"
[[ "$GIT_BIN" = /* ]] && [ -x "$GIT_BIN" ] && [ -f "$GIT_BIN" ] && [ ! -L "$GIT_BIN" ] || \
  die "trusted Git executable is unavailable at $GIT_BIN"
trusted_file_record "$GIT_BIN" 'trusted Git executable' '' 268435456 root-ok 1 0 >/dev/null

HEAD_SHA="$($GIT_BIN -C "$REPO_DIR" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" || \
  die "cannot resolve repository HEAD"
[[ "$HEAD_SHA" =~ ^[0-9a-fA-F]{40,64}$ ]] || die "repository HEAD is malformed"

EXPECTED_UPDATER_BLOB="$($GIT_BIN -C "$REPO_DIR" rev-parse --verify 'HEAD:fleet/updater.sh' 2>/dev/null)" || \
  die "HEAD does not contain fleet/updater.sh"
ACTUAL_UPDATER_BLOB="$($GIT_BIN -C "$REPO_DIR" hash-object --no-filters "$UPDATER" 2>/dev/null)" || \
  die "cannot hash fleet/updater.sh"
[ "$ACTUAL_UPDATER_BLOB" = "$EXPECTED_UPDATER_BLOB" ] || \
  die "fleet/updater.sh differs from the signed checkout"

TRUSTED_TAG=""
while IFS= read -r tag; do
  [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || continue
  [ "$($GIT_BIN -C "$REPO_DIR" cat-file -t "refs/tags/$tag" 2>/dev/null || true)" = tag ] || continue
  tag_commit="$($GIT_BIN -C "$REPO_DIR" rev-parse --verify "refs/tags/$tag^{commit}" 2>/dev/null || true)"
  [ "$tag_commit" = "$HEAD_SHA" ] || continue

  verify_output=""
  if verify_output="$($GIT_BIN -C "$REPO_DIR" \
      -c gpg.format=ssh \
      -c "gpg.ssh.allowedSignersFile=$ALLOWED_SIGNERS_SNAPSHOT" \
      -c gpg.ssh.program=/usr/bin/ssh-keygen \
      verify-tag --raw "$tag" 2>&1)" &&
      { printf '%s' "$verify_output" | grep -Eq 'GOODSIG|TRUST_(FULLY|ULTIMATE)' ||
        printf '%s' "$verify_output" | grep -qi 'Good.*signature'; }; then
    TRUSTED_TAG="$tag"
    break
  fi
done < <($GIT_BIN -C "$REPO_DIR" tag --points-at "$HEAD_SHA")

[ "$(trusted_file_record "$ALLOWED_SIGNERS" 'allowed-signers file' '' 262144)" = "$ALLOWED_SIGNERS_RECORD" ] || \
  die 'allowed-signers metadata changed during release verification'
[ "$(sha256_file "$ALLOWED_SIGNERS")" = "$ALLOWED_SIGNERS_SHA256" ] || \
  die 'allowed-signers content changed during release verification'

[ -n "$TRUSTED_TAG" ] || die "HEAD $HEAD_SHA is not an allowed-signer-verified release tag"
[ "$(trusted_file_record "$UPDATER" 'trusted updater' '' 1048576 root-ok)" = "$UPDATER_RECORD" ] || \
  die 'trusted updater metadata changed during release verification'
FINAL_UPDATER_BLOB="$($GIT_BIN -C "$REPO_DIR" hash-object --no-filters "$UPDATER" 2>/dev/null)" || \
  die "cannot re-hash fleet/updater.sh"
[ "$FINAL_UPDATER_BLOB" = "$EXPECTED_UPDATER_BLOB" ] || \
  die "fleet/updater.sh changed during release verification"

export HIVERELAY_REPO_DIR="$REPO_DIR"
log "executing updater from trusted $TRUSTED_TAG ($HEAD_SHA)"
cleanup_snapshot
trap - EXIT HUP INT TERM
exec /bin/bash --noprofile --norc "$UPDATER" "$@"
