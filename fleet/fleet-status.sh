#!/usr/bin/env bash
#
# fleet-status.sh — one-shot health table for the raw fleet, run from your
# workstation. Reads fleet/relays.json, reaches each box (tailnet name if
# enrolled, else publicIp + its sshKey), shells in, and asks the relay's
# localhost /health on the box (the API stays bound to 127.0.0.1 — we never
# expose it; we shell in and query locally).
#
#   bash fleet/fleet-status.sh
#   HIVERELAY_FLEET_INCLUDE=utah,bern bash fleet/fleet-status.sh
#
# HIVERELAY_FLEET_INCLUDE and HIVERELAY_FLEET_EXCLUDE are comma-separated
# relay-name lists. They are applied before any SSH connection is opened, so an
# operator can prove a maintenance scan cannot touch an independently owned or
# held lane.
#
# StrictHostKeyChecking=accept-new is deliberate so a rotated host key never
# masquerades as "server down" (the 2026-06-16 bern false alarm).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# The committed inventory always carries sshKey="default" — real key paths are
# operator-specific and never land in the repo. Point HIVERELAY_FLEET_INVENTORY
# at a private copy (e.g. fleet/relays.local.json, gitignored) to supply them.
RELAYS="${HIVERELAY_FLEET_INVENTORY:-$HERE/relays.json}"
[ -f "$RELAYS" ] || { echo "fleet inventory not found: $RELAYS"; exit 1; }
INCLUDE="${HIVERELAY_FLEET_INCLUDE:-}"
EXCLUDE="${HIVERELAY_FLEET_EXCLUDE:-}"

CH="$(curl -fsS --max-time 15 https://raw.githubusercontent.com/bigdestiny2/P2P-Hiverelay/main/fleet/channels.json 2>/dev/null || cat "$HERE/channels.json")"

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

valid_name_list() {
  local value="${1:-}"
  [ -z "$value" ] || [[ "$value" =~ ^[A-Za-z0-9._-]+(,[A-Za-z0-9._-]+)*$ ]]
}

valid_name_list "$INCLUDE" || { echo "invalid HIVERELAY_FLEET_INCLUDE relay list" >&2; exit 1; }
valid_name_list "$EXCLUDE" || { echo "invalid HIVERELAY_FLEET_EXCLUDE relay list" >&2; exit 1; }

# Remote probe, delivered verbatim over stdin (bash -s) — no quote escaping.
read -r -d '' REMOTE <<'REMOTE_EOF' || true
V="v$(node -p 'require(process.env.HOME + "/hiverelay/package.json").version' 2>/dev/null || printf '?')"
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
H=$(curl_with_optional_key "$K" -fsS --max-time 10 http://127.0.0.1:9100/health 2>/dev/null || true)
S=$(curl_with_optional_key "$K" -fsS --max-time 10 http://127.0.0.1:9100/status 2>/dev/null || true)
R=$(HEALTH="$H" STATUS="$S" python3 -c 'import os,json;h=json.loads(os.environ["HEALTH"]);s=json.loads(os.environ["STATUS"]);print(h.get("running"),s.get("seededApps","?"),s.get("connections","?"))' 2>/dev/null || echo "? ? ?")
D=$(df -h / | awk 'NR==2{print $5}')
U_ENABLED="$(systemctl is-enabled hiverelay-updater.timer 2>/dev/null || true)"
[ -n "$U_ENABLED" ] || U_ENABLED=missing
U_ACTIVE="$(systemctl is-active hiverelay-updater.timer 2>/dev/null || true)"
[ -n "$U_ACTIVE" ] || U_ACTIVE=inactive
C=$(awk -F= '/^[[:space:]]*CHANNEL[[:space:]]*=/ { sub(/^[^=]*=/,""); sub(/^[[:space:]]*/,""); sub(/[[:space:]]*$/,""); print; exit }' /etc/hiverelay-updater.conf 2>/dev/null || true)
[ -n "$C" ] || C=?
P=$(awk -F= '/^[[:space:]]*PINNED_TAG[[:space:]]*=/ { sub(/^[^=]*=/,""); sub(/^[[:space:]]*/,""); sub(/[[:space:]]*$/,""); print; exit }' /etc/hiverelay-updater.conf 2>/dev/null || true)
[ -z "$P" ] || C="$C@$P"
echo "$V|$R|$D|$U_ENABLED/$U_ACTIVE|$C"
REMOTE_EOF

printf '%-12s %-14s %-8s %-6s %-6s %-6s %-14s %-10s %s\n' RELAY VERSION RUNNING APPS CONNS DISK UPDATER CONFIGURED ASSIGNED
printf '%-12s %-14s %-8s %-6s %-6s %-6s %-14s %-10s %s\n' ───── ─────── ─────── ──── ───── ──── ─────── ────────── ────────

while IFS='|' read -r name host keyspec channel; do
  safe_name="$(clean_field "$name")"
  safe_channel="$(clean_field "$channel")"
  if ! valid_host "$host"; then
    printf '%-12s %-14s %-8s %-6s %-6s %-6s %-14s %-10s %s\n' "$safe_name" BADHOST - - - - - - "$safe_channel"
    continue
  fi
  if ! valid_channel "$channel"; then
    printf '%-12s %-14s %-8s %-6s %-6s %-6s %-14s %-10s %s\n' "$safe_name" BADCHAN - - - - - - "$safe_channel"
    continue
  fi
  if ! valid_key_path "$keyspec"; then
    printf '%-12s %-14s %-8s %-6s %-6s %-6s %-14s %-10s %s\n' "$safe_name" BADKEY - - - - - - "$safe_channel"
    continue
  fi
  keyarg=(); [ -n "$keyspec" ] && keyarg=(-i "${keyspec/#\~/$HOME}")
  target="$(printf '%s' "$CH" | CHANNEL="$channel" python3 -c 'import os,sys,json;print(json.load(sys.stdin).get(os.environ["CHANNEL"], ""))' 2>/dev/null || echo '?')"
  safe_target="$(clean_field "$target")"
  # ${keyarg[@]+...} so an empty keyarg (default-key boxes) doesn't trip `set -u`
  # on bash <4.4 (macOS ships 3.2) with "unbound variable".
  out="$(ssh ${keyarg[@]+"${keyarg[@]}"} -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes "root@$host" bash -s <<<"$REMOTE" 2>/dev/null || true)"
  if [ -z "$out" ]; then
    printf '%-12s %-14s %-8s %-6s %-6s %-6s %-14s %-10s %s\n' "$safe_name" UNREACH - - - - - - "$safe_target"
    continue
  fi
  out="$(printf '%s\n' "$out" | tail -n 1)"
  IFS='|' read -r ver rest disk updater configured <<<"$out"
  read -r run apps conns <<<"${rest:-? ? ?}"
  # Flag disk pressure so a filling box is caught BEFORE it wedges (a full disk
  # hangs the relay → public 502). ! at >=75%, !! at >=90%.
  disk_pct="$(printf '%s' "$disk" | tr -dc '0-9')"
  disk_display="${disk:-?}"
  if [ -n "$disk_pct" ]; then
    if [ "$disk_pct" -ge 90 ] 2>/dev/null; then disk_display="${disk}!!"
    elif [ "$disk_pct" -ge 75 ] 2>/dev/null; then disk_display="${disk}!"; fi
  fi
  printf '%-12s %-14s %-8s %-6s %-6s %-6s %-14s %-10s %s\n' \
    "$safe_name" \
    "$(clean_field "${ver:-?}")" \
    "$(clean_field "${run:-?}")" \
    "$(clean_field "${apps:-?}")" \
    "$(clean_field "${conns:-?}")" \
    "$(clean_field "${disk_display}")" \
    "$(clean_field "${updater:-?}")" \
    "$(clean_field "${configured:-?}")" \
    "$safe_target"
done < <(INCLUDE="$INCLUDE" EXCLUDE="$EXCLUDE" python3 -c '
import json,os,sys
include = set(filter(None, os.environ.get("INCLUDE", "").split(",")))
exclude = set(filter(None, os.environ.get("EXCLUDE", "").split(",")))
for r in json.load(open(sys.argv[1]))["relays"]:
    if include and r["name"] not in include:
        continue
    if r["name"] in exclude:
        continue
    host = r["tailnet"] or r["publicIp"]
    key  = "" if r.get("sshKey") in (None,"default") else r["sshKey"]
    print("{}|{}|{}|{}".format(r["name"], host, key, r.get("channel", "stable")))
' "$RELAYS")

printf '\nDISK flags: %s = >=75%% (set/verify maxStorageBytes), %s = >=90%% (act now — a full disk wedges the relay).\n' '!' '!!'
