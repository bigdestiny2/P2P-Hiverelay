#!/usr/bin/env bash
# Read-only fleet health from the workstation, using local inventory when present.
# SSH queries localhost /health; the API key stays on the remote host.
# accept-new accepts first-use keys, but changed keys remain blocked and reported.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
RELAYS=""
SHOW_HELP=0
usage() {
  printf 'Usage: bash fleet/fleet-status.sh [--inventory FILE] [--help]\n'
  printf 'Default inventory: fleet/relays.local.json when present, otherwise fleet/relays.json.\n'
  printf 'Retired and other hosts are listed separately and never probed.\n'
}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --inventory)
      [ "$#" -ge 2 ] && [ -n "$2" ] && [[ "$2" != --* ]] || { echo '--inventory requires a file' >&2; exit 2; }
      [ -z "$RELAYS" ] || { echo '--inventory may only be specified once' >&2; exit 2; }
      RELAYS="$2"; shift 2 ;;
    --inventory=*)
      [ -z "$RELAYS" ] || { echo '--inventory may only be specified once' >&2; exit 2; }
      RELAYS="${1#*=}"
      [ -n "$RELAYS" ] || { echo '--inventory requires a file' >&2; exit 2; }
      shift ;;
    --help|-h) SHOW_HELP=1; shift ;;
    *) echo 'Unknown argument; use --help' >&2; exit 2 ;;
  esac
done
if [ "$SHOW_HELP" -eq 1 ]; then usage; exit 0; fi
if [ -z "$RELAYS" ]; then
  if [ -e "$HERE/relays.local.json" ] || [ -L "$HERE/relays.local.json" ]; then
    RELAYS="$HERE/relays.local.json"
  else
    RELAYS="$HERE/relays.json"
  fi
fi
[ -f "$RELAYS" ] && [ -r "$RELAYS" ] || { echo 'Inventory file is missing or unreadable' >&2; exit 2; }
umask 077
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

clean_field() {
  local value="${1:-?}"
  value="$(printf '%s' "$value" | LC_ALL=C tr -c '[:print:]' '?' | tr '|' '?' | cut -c1-80)"
  [ -n "$value" ] && printf '%s' "$value" || printf '?'
}

valid_host() {
  local value="$1"
  [ -n "$value" ] &&
    [ "${#value}" -le 253 ] &&
    [[ "$value" != -* ]] &&
    [[ "$value" != *@* ]] &&
    # POSIX bracket expressions don't escape ] with a backslash, so a literal ]
    # must be first and a literal - must be last, or the class closes early and
    # rejects every host (plain IPs included). Chars: ] [ - . _ : and alnum.
    [[ "$value" =~ ^[]A-Za-z0-9._:[-]+$ ]]
}

valid_channel() {
  [[ "$1" =~ ^[A-Za-z0-9._-]{1,32}$ ]]
}

valid_key_path() {
  local value="${1:-}"
  [ -z "$value" ] && return 0
  [ "${#value}" -le 1024 ] &&
    ! printf '%s' "$value" | LC_ALL=C grep -q '[[:cntrl:]]'
}

# Validate the whole file before any network I/O. Do not hide parser failures in
# process substitution, or interpolate inventory data into shell/Python programs.
if ! python3 - "$RELAYS" "$WORK" <<'INVENTORY_EOF'
import json, pathlib, sys

def field(row, key, default="", limit=1024):
    value = row.get(key, default)
    if value is None:
        value = default
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 or ord(c) == 127 or c == "|" for c in value):
        raise ValueError("invalid " + key + " field")
    return value

try:
    data = json.loads(pathlib.Path(sys.argv[1]).read_text())
    if not isinstance(data, dict) or not isinstance(data.get("relays"), list):
        raise ValueError("relays must be an array")
    active, excluded, names = [], {}, set()
    for group in ("relays", "retiredRelays", "otherRelays", "otherHosts"):
        rows = data.get(group, [])
        if not isinstance(rows, list):
            raise ValueError(group + " must be an array")
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError(group + " entries must be objects")
            name = field(row, "name", limit=80)
            if not name:
                raise ValueError("name is required")
            retired = group == "retiredRelays" or field(row, "role") == "retired" or field(row, "status") == "retired" or bool(row.get("retiredAt"))
            if retired or group != "relays":
                kind = "retired" if retired else "other"
                reason = field(row, "retirementReason") or field(row, "reason") or field(row, "disposition") or "excluded from active fleet"
                excluded[name] = (name, reason, kind)
                continue
            if name in names:
                raise ValueError("duplicate active relay name")
            names.add(name)
            host = field(row, "tailnet") or field(row, "publicIp")
            key = field(row, "sshKey")
            if key == "default":
                key = ""
            active.append((name, host, key, field(row, "channel", "stable", 32)))
    root = pathlib.Path(sys.argv[2])
    (root / "active").write_text("".join("|".join(r) + "\n" for r in active if r[0] not in excluded))
    (root / "excluded").write_text("".join("|".join(r) + "\n" for r in excluded.values()))
except (OSError, ValueError, TypeError):
    # Never echo untrusted inventory content or a private path in diagnostics.
    print("Invalid inventory: expected relay objects with bounded, delimiter-free string fields", file=sys.stderr)
    sys.exit(2)
INVENTORY_EOF
then
  exit 2
fi
while IFS='|' read -r name host keyspec channel; do
  valid_host "$host" || { echo 'Invalid inventory: BADHOST (use a host/IP without user or options)' >&2; exit 2; }
  valid_channel "$channel" || { echo 'Invalid inventory: BADCHAN (use a simple channel name)' >&2; exit 2; }
  valid_key_path "$keyspec" || { echo 'Invalid inventory: BADKEY (invalid identity file path)' >&2; exit 2; }
done < "$WORK/active"

CH="$(curl -fsS --max-time 15 https://raw.githubusercontent.com/bigdestiny2/P2P-Hiverelay/main/fleet/channels.json 2>/dev/null || cat "$HERE/channels.json")"

# Keep raw SSH stderr private. It can contain paths, key details or server text.
ssh_failure() {
  if LC_ALL=C grep -Eiq 'REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed|host key has changed|Offending .* key' "$WORK/ssh-error"; then
    printf 'SSH-HOST-TRUST: verify host fingerprint and known_hosts'
  elif LC_ALL=C grep -Eiq 'no such identity|identity file .*not accessible|Load key .*No such file|UNPROTECTED PRIVATE KEY FILE|bad permissions|Load key .*invalid format|sign_and_send_pubkey: signing failed' "$WORK/ssh-error"; then
    printf 'SSH-KEY: check identity file, permissions and agent'
  elif LC_ALL=C grep -Eiq 'Permission denied|Authentication failed|Too many authentication failures|no supported authentication methods' "$WORK/ssh-error"; then
    printf 'SSH-AUTH: check root key authorization and agent'
  elif LC_ALL=C grep -Eiq 'timed out|timeout' "$WORK/ssh-error"; then
    printf 'SSH-TIMEOUT: check reachability, firewall and tailnet'
  elif LC_ALL=C grep -Eiq 'Could not resolve hostname|Name or service not known|No route to host|Network is unreachable|Connection refused|Connection reset|Connection closed' "$WORK/ssh-error"; then
    printf 'SSH-NETWORK: check address, route and sshd'
  else
    printf 'SSH-ERROR: SSH or remote probe failed (exit %s)' "$1"
  fi
}

# Remote probe, delivered verbatim over stdin (bash -s) — no quote escaping.
read -r -d '' REMOTE <<'REMOTE_EOF' || true
V="$(python3 -c 'import json, re, sys
v = json.load(open(sys.argv[1])).get("version", "")
if not isinstance(v, str) or not re.fullmatch(r"v?[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", v):
    raise ValueError("invalid version")
print(v if v.startswith("v") else "v" + v)' "$HOME/hiverelay/package.json" 2>/dev/null || printf '?')"
read_api_key() {
  local key
  key="$(systemctl show hiverelay -p Environment 2>/dev/null | awk 'BEGIN{RS=" "} /^HIVERELAY_API_KEY=/{sub(/^HIVERELAY_API_KEY=/,""); print; exit}' || true)"
  if [ -z "$key" ] && [ -r /etc/hiverelay/hiverelay.env ]; then
    key="$(awk -F= '/^[[:space:]]*HIVERELAY_API_KEY[[:space:]]*=/ { sub(/^[^=]*=/,""); sub(/^[[:space:]]*/,""); print; exit }' /etc/hiverelay/hiverelay.env 2>/dev/null || true)"
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
K="$(read_api_key)"
H=$(curl_with_optional_key "$K" -fsS --max-time 10 --max-filesize 65536 http://127.0.0.1:9100/health 2>/dev/null) || H=""
if [ -z "$H" ]; then
  R="HEALTH-UNAVAILABLE ? ?"
else
  R=$(printf '%s' "$H" | python3 -c 'import sys,json
d=json.load(sys.stdin)
r=d.get("running")
if type(r) is not bool: raise ValueError("missing running state")
def count(k):
    n=d.get(k)
    return n if type(n) is int and n >= 0 else "?"
print("RUNNING" if r else "STOPPED", count("seededApps"), count("connections"))' 2>/dev/null || echo "HEALTH-INVALID ? ?")
fi
D=$(df -h / | awk 'NR==2{print $5}')
echo "$V|$R|$D"
REMOTE_EOF

printf 'Inventory: %s\n' "$(clean_field "$(basename "$RELAYS")")"
printf '%-15s %-24s %-10s %-19s %-6s %-6s %-6s %s\n' RELAY VERSION SSH HEALTH APPS CONNS DISK TARGET

while IFS='|' read -r name host keyspec channel; do
  safe_name="$(clean_field "$name")"
  target="$(printf '%s' "$CH" | CHANNEL="$channel" python3 -c 'import os,sys,json;print(json.load(sys.stdin).get(os.environ["CHANNEL"], ""))' 2>/dev/null || echo '?')"
  safe_target="$(clean_field "$target")"
  keyarg=()
  if [ -n "$keyspec" ]; then
    case "$keyspec" in '~/'*) keyspec="$HOME/${keyspec:2}" ;; esac
    if [ ! -f "$keyspec" ] || [ ! -r "$keyspec" ]; then
      printf '%-15s %-24s %-10s %-19s %-6s %-6s %-6s %s\n' "$safe_name" - KEY-MISSING unobserved - - - "$safe_target"
      printf '  KEY-MISSING: configure a readable SSH identity file for this relay.\n'
      continue
    fi
    keyarg=(-i "$keyspec")
  fi
  # Empty-array expansion also works under macOS Bash 3.2 with set -u.
  ssh_status=0
  out="$(ssh ${keyarg[@]+"${keyarg[@]}"} -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o ServerAliveInterval=10 -o ServerAliveCountMax=1 -o BatchMode=yes "root@$host" bash -s <<<"$REMOTE" 2>"$WORK/ssh-error")" || ssh_status=$?
  if [ "$ssh_status" -ne 0 ]; then
    printf '%-15s %-24s %-10s %-19s %-6s %-6s %-6s %s\n' "$safe_name" - FAILED unobserved - - - "$safe_target"
    printf '  %s\n' "$(ssh_failure "$ssh_status")"
    continue
  fi
  out="$(printf '%s\n' "$out" | tail -n 1)"
  IFS='|' read -r ver rest disk <<<"$out"
  [[ "${ver:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]] || ver='?'
  read -r health apps conns <<<"${rest:-PROBE-INVALID ? ?}"
  case "$health" in RUNNING|STOPPED|HEALTH-UNAVAILABLE|HEALTH-INVALID) ;; *) health=PROBE-INVALID; apps='?'; conns='?' ;; esac
  [[ "${apps:-}" =~ ^[0-9]+$ ]] || apps='?'
  [[ "${conns:-}" =~ ^[0-9]+$ ]] || conns='?'
  # Flag disk pressure before a full disk wedges the relay.
  disk_display="${disk:-?}"
  if [[ "$disk_display" =~ ^[0-9]{1,3}%$ ]]; then
    disk_pct="${disk_display%%%}"
    if [ "$disk_pct" -ge 90 ]; then disk_display="${disk}!!"
    elif [ "$disk_pct" -ge 75 ]; then disk_display="${disk}!"; fi
  else
    disk_display='?'
  fi
  printf '%-15s %-24s %-10s %-19s %-6s %-6s %-6s %s\n' \
    "$safe_name" "$(clean_field "${ver:-?}")" OK "$(clean_field "$health")" \
    "$(clean_field "${apps:-?}")" "$(clean_field "${conns:-?}")" \
    "$(clean_field "$disk_display")" "$safe_target"
done < "$WORK/active"

if [ -s "$WORK/excluded" ]; then
  printf '\nExcluded inventory (not probed or active rollout targets):\n'
  while IFS='|' read -r name reason kind; do
    printf '  %-15s %-8s %s\n' "$(clean_field "$name")" "$kind" "$(clean_field "$reason")"
  done < "$WORK/excluded"
fi
printf '\nSSH failures leave service health unobserved; HEALTH-UNAVAILABLE/INVALID require checking localhost /health and its API key.\n'
printf 'TARGET is an informational channel hint, not signed rollout or readiness evidence.\n'
printf 'DISK flags: %s = >=75%% (set/verify maxStorageBytes), %s = >=90%% (act now — a full disk wedges the relay).\n' '!' '!!'
