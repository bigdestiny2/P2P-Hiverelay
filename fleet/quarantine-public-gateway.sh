#!/bin/bash
# Replace only the public-app nginx fragment with a TLS default reject server.
# The separate exact management/API virtual host remains loaded and reachable.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset BASH_ENV ENV CDPATH GLOBIGNORE LD_PRELOAD LD_LIBRARY_PATH NODE_OPTIONS NODE_PATH \
  PYTHONPATH PYTHONHOME PYTHONSTARTUP GIT_DIR GIT_WORK_TREE 2>/dev/null || true
set -euo pipefail

ACTIVE_CONFIG="${1:-}"
BACKUP_CONFIG="${2:-}"
NGINX_BINARY="${3:-}"
MARKER='# hiverelay-public-gateway-quarantine-v1'
FAIL_CLOSED_READY=0
FAIL_CLOSED_ATTEMPTED=0
CONTAINMENT_COMPLETE=0
TEMP_CONFIG=''
NGINX_RECORD=''
DIRECTORY_RECORD=''

attempt_fail_closed_stop() {
  if [ "$FAIL_CLOSED_READY" = 1 ] && [ "$FAIL_CLOSED_ATTEMPTED" = 0 ]; then
    FAIL_CLOSED_ATTEMPTED=1
    if trusted_executable_matches "$NGINX_BINARY" 'nginx binary' 268435456 "$NGINX_RECORD"; then
      "$NGINX_BINARY" -s stop >/dev/null 2>&1 || true
    else
      echo 'public gateway quarantine: nginx identity changed; refusing to execute untrusted stop bytes' >&2
    fi
  fi
}

cleanup_temp_config() {
  if [ -n "$TEMP_CONFIG" ]; then
    rm -f "$TEMP_CONFIG" >/dev/null 2>&1 || true
  fi
}

on_exit() {
  local status="$1"
  trap - EXIT HUP INT TERM
  cleanup_temp_config
  if [ "$status" -ne 0 ] && [ "$FAIL_CLOSED_READY" = 1 ] && \
    [ "$CONTAINMENT_COMPLETE" = 0 ]; then
    attempt_fail_closed_stop
  fi
  return "$status"
}

on_signal() {
  local signal="$1"
  local status="$2"
  echo "public gateway quarantine: received $signal before TLS 421 containment was proven" >&2
  exit "$status"
}

trap 'on_exit $?' EXIT
trap 'on_signal HUP 129' HUP
trap 'on_signal INT 130' INT
trap 'on_signal TERM 143' TERM

die() {
  local reason="$*"
  if [ "$FAIL_CLOSED_READY" = 1 ]; then
    attempt_fail_closed_stop
    reason="$reason; nginx stop attempted because TLS 421 containment was not proven"
  fi
  echo "public gateway quarantine: $reason" >&2
  exit 1
}

safe_absolute_path() {
  local value="$1"
  [[ "$value" = /* ]] || return 1
  [ "${#value}" -le 4096 ] || return 1
  ! printf '%s' "$value" | LC_ALL=C grep -q '[[:cntrl:]]'
}

stat_record() {
  stat -f '%u|%Lp|%l|%z|%d|%i|%m|%c' "$1" 2>/dev/null || \
    stat -c '%u|%a|%h|%s|%d|%i|%Y|%Z' "$1" 2>/dev/null
}

trusted_parent_chain() {
  local filename="$1" label="$2" parent record uid mode rest mode_value
  parent="$(dirname "$filename")"
  while :; do
    [ -d "$parent" ] && [ ! -L "$parent" ] || {
      echo "public gateway quarantine: $label parent is unsafe: $parent" >&2
      return 1
    }
    record="$(stat_record "$parent")" || return 1
    IFS='|' read -r uid mode rest <<< "$record"
    [ "$uid" = "$EUID" ] || [ "$uid" = 0 ] || {
      echo "public gateway quarantine: $label parent has an untrusted owner: $parent" >&2
      return 1
    }
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    mode_value=$((8#$mode))
    if (( (mode_value & 8#022) != 0 )); then
      if [ "$uid" != 0 ] || (( (mode_value & 8#1000) == 0 )); then
        echo "public gateway quarantine: $label parent is group/world writable: $parent" >&2
        return 1
      fi
    fi
    [ "$parent" = / ] && break
    parent="$(dirname "$parent")"
  done
}

require_canonical_path() {
  local filename="$1" label="$2" physical_parent leaf canonical
  physical_parent="$(cd -P "$(dirname "$filename")" 2>/dev/null && pwd -P)" || return 1
  leaf="$(basename "$filename")"
  if [ "$physical_parent" = / ]; then canonical="/$leaf"; else canonical="$physical_parent/$leaf"; fi
  [ "$filename" = "$canonical" ] || {
    echo "public gateway quarantine: $label path must be canonical and contain no symlink ancestors" >&2
    return 1
  }
}

trusted_directory_record() {
  local directory="$1" label="$2" record final_record uid mode rest mode_value
  require_canonical_path "$directory" "$label" || return 1
  [ -d "$directory" ] && [ ! -L "$directory" ] || return 1
  trusted_parent_chain "$directory/entry" "$label" || return 1
  record="$(stat_record "$directory")" || return 1
  IFS='|' read -r uid mode rest <<< "$record"
  [ "$uid" = "$EUID" ] || [ "$uid" = 0 ] || return 1
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
  mode_value=$((8#$mode))
  (( (mode_value & 8#022) == 0 )) || {
    echo "public gateway quarantine: $label is group/world writable" >&2
    return 1
  }
  require_canonical_path "$directory" "$label" || return 1
  trusted_parent_chain "$directory/entry" "$label" || return 1
  final_record="$(stat_record "$directory")" || return 1
  [ "$final_record" = "$record" ] || return 1
  printf '%s\n' "$record"
}

trusted_regular_record() {
  local filename="$1" label="$2" max_size="$3" link_policy="$4"
  local record final_record uid mode nlink size rest mode_value
  require_canonical_path "$filename" "$label" || return 1
  [ -f "$filename" ] && [ ! -L "$filename" ] || return 1
  trusted_parent_chain "$filename" "$label" || return 1
  record="$(stat_record "$filename")" || return 1
  IFS='|' read -r uid mode nlink size rest <<< "$record"
  [ "$uid" = "$EUID" ] || [ "$uid" = 0 ] || return 1
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
  mode_value=$((8#$mode))
  (( (mode_value & 8#022) == 0 )) || return 1
  case "$link_policy" in
    1) [ "$nlink" = 1 ] || return 1 ;;
    2) [ "$nlink" = 2 ] || return 1 ;;
    1-or-2) [ "$nlink" = 1 ] || [ "$nlink" = 2 ] || return 1 ;;
    *) return 1 ;;
  esac
  [[ "$size" =~ ^[0-9]+$ ]] && [ "$size" -ge 1 ] && [ "$size" -le "$max_size" ] || return 1
  require_canonical_path "$filename" "$label" || return 1
  trusted_parent_chain "$filename" "$label" || return 1
  final_record="$(stat_record "$filename")" || return 1
  [ "$final_record" = "$record" ] || return 1
  printf '%s\n' "$record"
}

trusted_executable_record() {
  local filename="$1" label="$2" max_size="$3" record mode mode_value
  record="$(trusted_regular_record "$filename" "$label" "$max_size" 1)" || return 1
  IFS='|' read -r _ mode _ <<< "$record"
  mode_value=$((8#$mode))
  (( (mode_value & 8#111) != 0 )) || return 1
  printf '%s\n' "$record"
}

trusted_executable_matches() {
  local filename="$1" label="$2" max_size="$3" expected="$4" current
  current="$(trusted_executable_record "$filename" "$label" "$max_size")" || return 1
  [ "$current" = "$expected" ] || {
    echo "public gateway quarantine: $label identity changed" >&2
    return 1
  }
}

trusted_regular_matches() {
  local filename="$1" label="$2" max_size="$3" link_policy="$4" expected="$5" current
  current="$(trusted_regular_record "$filename" "$label" "$max_size" "$link_policy")" || return 1
  [ "$current" = "$expected" ] || {
    echo "public gateway quarantine: $label identity changed" >&2
    return 1
  }
}

run_trusted_nginx() {
  local status=0
  trusted_executable_matches "$NGINX_BINARY" 'nginx binary' 268435456 "$NGINX_RECORD" || return 125
  "$NGINX_BINARY" "$@" || status=$?
  trusted_executable_matches "$NGINX_BINARY" 'nginx binary' 268435456 "$NGINX_RECORD" || return 125
  return "$status"
}

safe_absolute_path "$ACTIVE_CONFIG" || die 'active config must be a bounded absolute path'
safe_absolute_path "$BACKUP_CONFIG" || die 'backup config must be a bounded absolute path'
safe_absolute_path "$NGINX_BINARY" || die 'nginx binary must be a bounded absolute path'
[ "$ACTIVE_CONFIG" != "$BACKUP_CONFIG" ] || die 'active and backup config paths must differ'
[ "$(dirname "$ACTIVE_CONFIG")" = "$(dirname "$BACKUP_CONFIG")" ] || \
  die 'active and backup configs must share one directory for atomic containment'
DIRECTORY="$(dirname "$ACTIVE_CONFIG")"
DIRECTORY_RECORD="$(trusted_directory_record "$DIRECTORY" 'config directory')" || \
  die 'config directory must be canonical, owner-trusted, and non-writable'
require_canonical_path "$ACTIVE_CONFIG" 'active config' || die 'active config path is not canonical'
require_canonical_path "$BACKUP_CONFIG" 'backup config' || die 'backup config path is not canonical'
NGINX_RECORD="$(trusted_executable_record "$NGINX_BINARY" 'nginx binary' 268435456)" || \
  die 'nginx binary must be canonical, owner-trusted, single-link, and non-writable'
FAIL_CLOSED_READY=1

sync_path() { sync -f "$1" >/dev/null 2>&1 || die "could not durably sync quarantine phase path $1"; }

directory_unchanged() {
  local current
  current="$(trusted_directory_record "$DIRECTORY" 'config directory')" || return 1
  [ "$current" = "$DIRECTORY_RECORD" ]
}

refresh_directory_record() {
  DIRECTORY_RECORD="$(trusted_directory_record "$DIRECTORY" 'config directory')"
}

fail_closed_stop() {
  local reason="$1"
  die "$reason; quarantine file retained to prevent public leakage"
}

ACTIVE_RECORD="$(trusted_regular_record "$ACTIVE_CONFIG" 'active config' 1048576 1-or-2)" || \
  die 'active public gateway config must be canonical, owner-trusted, non-writable, and have one or two links'
ALREADY_QUARANTINED=0
if grep -qxF "$MARKER" "$ACTIVE_CONFIG"; then ALREADY_QUARANTINED=1; fi
trusted_regular_matches "$ACTIVE_CONFIG" 'active config' 1048576 1-or-2 "$ACTIVE_RECORD" || \
  die 'active config changed while detecting quarantine state'

if [ "$ALREADY_QUARANTINED" = 1 ]; then
  BACKUP_RECORD="$(trusted_regular_record "$BACKUP_CONFIG" 'recovery backup' 1048576 1)" || \
    die 'edge is quarantined but its recovery backup is missing or unsafe'
  directory_unchanged || die 'config directory changed before quarantine validation'
  trusted_regular_matches "$ACTIVE_CONFIG" 'active quarantine config' 1048576 1 "$ACTIVE_RECORD" || \
    die 'active quarantine config changed before validation'
  if ! run_trusted_nginx -t; then
    fail_closed_stop 'installed quarantine nginx validation failed'
  fi
  trusted_regular_matches "$ACTIVE_CONFIG" 'active quarantine config' 1048576 1 "$ACTIVE_RECORD" || \
    fail_closed_stop 'active quarantine config changed during validation'
  trusted_regular_matches "$BACKUP_CONFIG" 'recovery backup' 1048576 1 "$BACKUP_RECORD" || \
    fail_closed_stop 'recovery backup changed during validation'
  if ! run_trusted_nginx -s reload; then
    fail_closed_stop 'installed quarantine nginx reload failed'
  fi
  trusted_regular_matches "$ACTIVE_CONFIG" 'active quarantine config' 1048576 1 "$ACTIVE_RECORD" || \
    fail_closed_stop 'active quarantine config changed during reload'
  trusted_regular_matches "$BACKUP_CONFIG" 'recovery backup' 1048576 1 "$BACKUP_RECORD" || \
    fail_closed_stop 'recovery backup changed during reload'
  CONTAINMENT_COMPLETE=1
  echo "public gateway quarantine: existing TLS 421 containment validated and reloaded"
  exit 0
fi

RESUME_AFTER_LINK=0
if [ -e "$BACKUP_CONFIG" ] || [ -L "$BACKUP_CONFIG" ]; then
  BACKUP_RECORD="$(trusted_regular_record "$BACKUP_CONFIG" 'existing quarantine backup' 1048576 1-or-2)" || \
    die 'existing quarantine backup is unsafe'
  IFS='|' read -r _ _ ACTIVE_NLINK _ <<< "$ACTIVE_RECORD"
  IFS='|' read -r _ _ BACKUP_NLINK _ <<< "$BACKUP_RECORD"
  if [ "$ACTIVE_CONFIG" -ef "$BACKUP_CONFIG" ] && [ "$ACTIVE_NLINK" = 2 ] && \
      [ "$BACKUP_NLINK" = 2 ] && [ "$ACTIVE_RECORD" = "$BACKUP_RECORD" ]; then
    RESUME_AFTER_LINK=1
  else
    AMBIGUOUS_BACKUP="${BACKUP_CONFIG}.ambiguous.$(date -u +%Y%m%dT%H%M%SZ).$$"
    require_canonical_path "$AMBIGUOUS_BACKUP" 'ambiguous recovery evidence' || \
      fail_closed_stop 'ambiguous recovery evidence path is unsafe'
    directory_unchanged || fail_closed_stop 'config directory changed before preserving ambiguous recovery evidence'
    trusted_regular_matches "$ACTIVE_CONFIG" 'active config' 1048576 1-or-2 "$ACTIVE_RECORD" || \
      fail_closed_stop 'active config changed before preserving ambiguous recovery evidence'
    trusted_regular_matches "$BACKUP_CONFIG" 'existing quarantine backup' 1048576 1-or-2 "$BACKUP_RECORD" || \
      fail_closed_stop 'existing recovery backup changed before preservation'
    mv "$BACKUP_CONFIG" "$AMBIGUOUS_BACKUP" || fail_closed_stop 'could not preserve ambiguous quarantine recovery evidence'
    refresh_directory_record || fail_closed_stop 'config directory became unsafe while preserving recovery evidence'
    trusted_regular_matches "$ACTIVE_CONFIG" 'active config' 1048576 1-or-2 "$ACTIVE_RECORD" || \
      fail_closed_stop 'active config changed while preserving recovery evidence'
    trusted_regular_record "$AMBIGUOUS_BACKUP" 'ambiguous recovery evidence' 1048576 1-or-2 >/dev/null || \
      fail_closed_stop 'preserved ambiguous recovery evidence is unsafe'
    sync_path "$AMBIGUOUS_BACKUP"
    sync_path "$DIRECTORY"
    echo "public gateway quarantine: preserved ambiguous recovery evidence at $AMBIGUOUS_BACKUP" >&2
  fi
else
  IFS='|' read -r _ _ ACTIVE_NLINK _ <<< "$ACTIVE_RECORD"
  [ "$ACTIVE_NLINK" = 1 ] || \
    die 'active public gateway config must have exactly one link before quarantine'
fi

read_unique_directive() {
  local directive="$1"
  awk -v wanted="$directive" '
    {
      line = $0
      sub(/^[[:space:]]*/, "", line)
      if (index(line, wanted " ") != 1 && index(line, wanted "\t") != 1) next
      sub("^" wanted "[[:space:]]+", "", line)
      sub(/[[:space:]]*;[[:space:]]*$/, "", line)
      seen[line] = 1
    }
    END {
      for (value in seen) { count++; selected = value }
      if (count != 1) exit 1
      print selected
    }
  ' "$ACTIVE_CONFIG"
}

CERTIFICATE="$(read_unique_directive ssl_certificate)" || \
  die 'active gateway config must contain one unique ssl_certificate path'
CERTIFICATE_KEY="$(read_unique_directive ssl_certificate_key)" || \
  die 'active gateway config must contain one unique ssl_certificate_key path'
trusted_regular_matches "$ACTIVE_CONFIG" 'active config' 1048576 1-or-2 "$ACTIVE_RECORD" || \
  die 'active config changed while deriving TLS identity'
for tls_path in "$CERTIFICATE" "$CERTIFICATE_KEY"; do
  safe_absolute_path "$tls_path" || die 'TLS paths in the active config must be bounded absolute paths'
  [[ "$tls_path" =~ ^/[A-Za-z0-9._/+:-]+$ ]] || die 'TLS paths in the active config contain unsafe characters'
done

directory_unchanged || die 'config directory changed before temporary quarantine creation'
TEMP_CONFIG="$(mktemp "$DIRECTORY/.hiverelay-public-gateway-quarantine.XXXXXX")" || \
  die 'could not create temporary quarantine config'
chmod 0644 "$TEMP_CONFIG" || die 'could not set temporary quarantine config permissions'
printf '%s\n' "$MARKER" > "$TEMP_CONFIG" || die 'could not initialize temporary quarantine config'
cat >> "$TEMP_CONFIG" <<EOF || die 'could not write temporary quarantine config'
server {
  listen 443 ssl default_server;
  listen [::]:443 ssl default_server;
  server_name _;

  ssl_certificate $CERTIFICATE;
  ssl_certificate_key $CERTIFICATE_KEY;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_session_tickets off;

  gzip off;
  gunzip off;
  access_log off;
  error_log stderr crit;
  return 421;
}
EOF
TEMP_RECORD="$(trusted_regular_record "$TEMP_CONFIG" 'temporary quarantine config' 1048576 1)" || \
  die 'temporary quarantine config is unsafe'
refresh_directory_record || die 'config directory became unsafe after temporary quarantine creation'
trusted_regular_matches "$ACTIVE_CONFIG" 'active config' 1048576 1-or-2 "$ACTIVE_RECORD" || \
  die 'active config changed before recovery link creation'

# A same-directory hard link preserves the exact recovery bytes without a
# window where the active path disappears. The following rename atomically
# replaces only the public-app fragment.
if [ "$RESUME_AFTER_LINK" = 0 ]; then
  [ ! -e "$BACKUP_CONFIG" ] && [ ! -L "$BACKUP_CONFIG" ] || \
    die 'recovery backup appeared before link creation'
  ln "$ACTIVE_CONFIG" "$BACKUP_CONFIG" || die 'could not create quarantine recovery backup'
  ACTIVE_RECORD="$(trusted_regular_record "$ACTIVE_CONFIG" 'linked active config' 1048576 2)" || \
    fail_closed_stop 'active config is unsafe after recovery link creation'
  BACKUP_RECORD="$(trusted_regular_record "$BACKUP_CONFIG" 'linked recovery backup' 1048576 2)" || \
    fail_closed_stop 'recovery backup is unsafe after link creation'
  [ "$ACTIVE_RECORD" = "$BACKUP_RECORD" ] && [ "$ACTIVE_CONFIG" -ef "$BACKUP_CONFIG" ] || \
    fail_closed_stop 'recovery link does not preserve the exact active inode'
  refresh_directory_record || fail_closed_stop 'config directory became unsafe after recovery link creation'
  sync_path "$BACKUP_CONFIG"
  sync_path "$DIRECTORY"
else
  trusted_regular_matches "$ACTIVE_CONFIG" 'linked active config' 1048576 2 "$ACTIVE_RECORD" || \
    fail_closed_stop 'resumed active config changed before atomic containment'
  trusted_regular_matches "$BACKUP_CONFIG" 'linked recovery backup' 1048576 2 "$BACKUP_RECORD" || \
    fail_closed_stop 'resumed backup changed before atomic containment'
fi
trusted_regular_matches "$TEMP_CONFIG" 'temporary quarantine config' 1048576 1 "$TEMP_RECORD" || \
  fail_closed_stop 'temporary quarantine config changed before atomic containment'
if ! mv -f "$TEMP_CONFIG" "$ACTIVE_CONFIG"; then
  if [ "$RESUME_AFTER_LINK" = 0 ]; then rm -f "$BACKUP_CONFIG"; fi
  die 'could not atomically install quarantine config'
fi
TEMP_CONFIG=''
refresh_directory_record || fail_closed_stop 'config directory became unsafe after atomic containment'
ACTIVE_RECORD="$(trusted_regular_record "$ACTIVE_CONFIG" 'installed quarantine config' 1048576 1)" || \
  fail_closed_stop 'installed quarantine config is unsafe'
BACKUP_RECORD="$(trusted_regular_record "$BACKUP_CONFIG" 'recovery backup' 1048576 1)" || \
  fail_closed_stop 'recovery backup is unsafe after atomic containment'
grep -qxF "$MARKER" "$ACTIVE_CONFIG" || fail_closed_stop 'installed quarantine marker is missing'
trusted_regular_matches "$ACTIVE_CONFIG" 'installed quarantine config' 1048576 1 "$ACTIVE_RECORD" || \
  fail_closed_stop 'installed quarantine config changed while checking its marker'
sync_path "$ACTIVE_CONFIG"
sync_path "$DIRECTORY"

if ! run_trusted_nginx -t; then
  fail_closed_stop 'quarantine nginx validation failed'
fi
trusted_regular_matches "$ACTIVE_CONFIG" 'installed quarantine config' 1048576 1 "$ACTIVE_RECORD" || \
  fail_closed_stop 'installed quarantine config changed during validation'
trusted_regular_matches "$BACKUP_CONFIG" 'recovery backup' 1048576 1 "$BACKUP_RECORD" || \
  fail_closed_stop 'recovery backup changed during validation'
if ! run_trusted_nginx -s reload; then
  fail_closed_stop 'quarantine nginx reload failed'
fi
trusted_regular_matches "$ACTIVE_CONFIG" 'installed quarantine config' 1048576 1 "$ACTIVE_RECORD" || \
  fail_closed_stop 'installed quarantine config changed during reload'
trusted_regular_matches "$BACKUP_CONFIG" 'recovery backup' 1048576 1 "$BACKUP_RECORD" || \
  fail_closed_stop 'recovery backup changed during reload'

CONTAINMENT_COMPLETE=1
cleanup_temp_config
trap - EXIT HUP INT TERM
echo "public gateway quarantine: public app edge replaced with TLS 421 reject; management vhost left intact"
