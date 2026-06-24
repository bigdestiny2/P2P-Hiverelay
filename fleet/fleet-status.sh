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

# Remote probe, delivered verbatim over stdin (bash -s) — no quote escaping.
read -r -d '' REMOTE <<'REMOTE_EOF' || true
V="v$(grep -m1 '"version"' "$HOME/hiverelay/package.json" | tr -dc '0-9.')"
K=$(systemctl show hiverelay -p Environment 2>/dev/null | grep -o 'HIVERELAY_API_KEY=[^ ]*' | cut -d= -f2)
if [ -n "$K" ]; then H=$(curl -fsS --max-time 10 -H "Authorization: Bearer $K" http://127.0.0.1:9100/health 2>/dev/null)
else H=$(curl -fsS --max-time 10 http://127.0.0.1:9100/health 2>/dev/null); fi
R=$(printf '%s' "$H" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("running"),d.get("seededApps","?"),d.get("connections","?"))' 2>/dev/null || echo "? ? ?")
D=$(df -h / | awk 'NR==2{print $5}')
echo "$V|$R|$D"
REMOTE_EOF

printf '%-11s %-9s %-8s %-6s %-6s %-6s %s\n' RELAY VERSION RUNNING APPS CONNS DISK TARGET
printf '%-11s %-9s %-8s %-6s %-6s %-6s %s\n' ───── ─────── ─────── ──── ───── ──── ──────

while IFS='|' read -r name host keyspec channel; do
  ssh_args=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes)
  [ -n "$keyspec" ] && ssh_args=(-i "${keyspec/#\~/$HOME}" "${ssh_args[@]}")
  target="$(printf '%s' "$CH" | python3 -c "import sys,json;print(json.load(sys.stdin).get('$channel',''))" 2>/dev/null || echo '?')"
  out="$(ssh "${ssh_args[@]}" "root@$host" bash -s <<<"$REMOTE" 2>/dev/null || true)"
  if [ -z "$out" ]; then
    printf '%-11s %-9s %-8s %-6s %-6s %-6s %s\n' "$name" UNREACH - - - - "$target"
    continue
  fi
  IFS='|' read -r ver rest disk <<<"$out"
  read -r run apps conns <<<"${rest:-? ? ?}"
  printf '%-11s %-9s %-8s %-6s %-6s %-6s %s\n' "$name" "${ver:-?}" "${run:-?}" "${apps:-?}" "${conns:-?}" "${disk:-?}" "$target"
done < <(python3 -c '
import json,sys
for r in json.load(open(sys.argv[1]))["relays"]:
    host = r["tailnet"] or r["publicIp"]
    key  = "" if r.get("sshKey") in (None,"default") else r["sshKey"]
    print("{}|{}|{}|{}".format(r["name"], host, key, r.get("channel", "stable")))
' "$RELAYS")
