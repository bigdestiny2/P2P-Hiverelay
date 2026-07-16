#!/usr/bin/env bash
#
# fleet-status.sh — one-shot health table for the raw fleet, run from your
# workstation. Reads fleet/relays.json, reaches each box (tailnet name if
# enrolled, else publicIp + its sshKey), shells in, and asks the relay's
# localhost /health on the box (the API stays bound to 127.0.0.1 — we never
# expose it; we shell in and query locally).
#
#   bash fleet/fleet-status.sh
#
# StrictHostKeyChecking=accept-new is deliberate so a rotated host key never
# masquerades as "server down" (the 2026-06-16 bern false alarm).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
RELAYS="$HERE/relays.json"
[ -f "$RELAYS" ] || { echo "relays.json not found"; exit 1; }

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

# Remote probe, delivered verbatim over stdin (bash -s) — no quote escaping.
read -r -d '' REMOTE <<'REMOTE_EOF' || true
V="v$(grep -m1 '"version"' "$HOME/hiverelay/package.json" | tr -dc '0-9.')"
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
R=$(printf '%s' "$H" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("running"),d.get("seededApps","?"),d.get("connections","?"))' 2>/dev/null || echo "? ? ?")
D=$(df -h / | awk 'NR==2{print $5}')
echo "$V|$R|$D"
REMOTE_EOF

printf '%-11s %-9s %-8s %-6s %-6s %-6s %s\n' RELAY VERSION RUNNING APPS CONNS DISK TARGET
printf '%-11s %-9s %-8s %-6s %-6s %-6s %s\n' ───── ─────── ─────── ──── ───── ──── ──────

while IFS='|' read -r name host keyspec channel; do
  safe_name="$(clean_field "$name")"
  safe_channel="$(clean_field "$channel")"
  if ! valid_host "$host"; then
    printf '%-9s %-9s %-8s %-6s %-6s %-6s %s\n' "$safe_name" BADHOST - - - - "$safe_channel"
    continue
  fi
  if ! valid_channel "$channel"; then
    printf '%-9s %-9s %-8s %-6s %-6s %-6s %s\n' "$safe_name" BADCHAN - - - - "$safe_channel"
    continue
  fi
  if ! valid_key_path "$keyspec"; then
    printf '%-9s %-9s %-8s %-6s %-6s %-6s %s\n' "$safe_name" BADKEY - - - - "$safe_channel"
    continue
  fi
  keyarg=(); [ -n "$keyspec" ] && keyarg=(-i "${keyspec/#\~/$HOME}")
  target="$(printf '%s' "$CH" | CHANNEL="$channel" python3 -c 'import os,sys,json;print(json.load(sys.stdin).get(os.environ["CHANNEL"], ""))' 2>/dev/null || echo '?')"
  safe_target="$(clean_field "$target")"
  # ${keyarg[@]+...} so an empty keyarg (default-key boxes) doesn't trip `set -u`
  # on bash <4.4 (macOS ships 3.2) with "unbound variable".
  out="$(ssh ${keyarg[@]+"${keyarg[@]}"} -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes "root@$host" bash -s <<<"$REMOTE" 2>/dev/null || true)"
  if [ -z "$out" ]; then
    printf '%-9s %-9s %-8s %-6s %-6s %-6s %s\n' "$safe_name" UNREACH - - - - "$safe_target"
    continue
  fi
  out="$(printf '%s\n' "$out" | tail -n 1)"
  IFS='|' read -r ver rest disk <<<"$out"
  read -r run apps conns <<<"${rest:-? ? ?}"
  printf '%-9s %-9s %-8s %-6s %-6s %-6s %s\n' \
    "$safe_name" \
    "$(clean_field "${ver:-?}")" \
    "$(clean_field "${run:-?}")" \
    "$(clean_field "${apps:-?}")" \
    "$(clean_field "${conns:-?}")" \
    "$(clean_field "${disk:-?}")" \
    "$safe_target"
done < <(python3 -c '
import json,sys
for r in json.load(open(sys.argv[1]))["relays"]:
    host = r["tailnet"] or r["publicIp"]
    key  = "" if r.get("sshKey") in (None,"default") else r["sshKey"]
    print("{}|{}|{}|{}".format(r["name"], host, key, r.get("channel", "stable")))
' "$RELAYS")
