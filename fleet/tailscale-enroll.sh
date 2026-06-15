#!/usr/bin/env bash
#
# tailscale-enroll.sh — put THIS box on the tailnet so the fleet has a
# stable, identity-based management plane (no SSH host-key / key-distribution
# drift — the exact failure mode that made bern look "lost" on 2026-06-16).
#
# Run on the relay host (as root):
#   sudo bash fleet/tailscale-enroll.sh
#
# Auth is intentionally interactive: this script will NOT take an auth key
# on the command line and will NOT store one. Either:
#   (a) run it and follow the printed `tailscale up` login URL, or
#   (b) export TS_AUTHKEY yourself in the shell first (ephemeral key you
#       generated in the Tailscale admin console) — it is read from the
#       environment only, never written to disk by this script.
set -euo pipefail

if ! command -v tailscale >/dev/null 2>&1; then
  echo "Installing tailscale…"
  curl -fsSL https://tailscale.com/install.sh | sh
fi

HOSTNAME_TAG="$(hostname | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g')"
echo "Bringing ${HOSTNAME_TAG} onto the tailnet…"

# SSH over the tailnet (identity-based) so break-glass never depends on
# local known_hosts again. --accept-dns=false keeps the box's resolver.
if [ -n "${TS_AUTHKEY:-}" ]; then
  tailscale up --ssh --hostname "$HOSTNAME_TAG" --accept-dns=false --authkey "$TS_AUTHKEY"
else
  echo "No TS_AUTHKEY in env — starting interactive login. Open the URL it prints:"
  tailscale up --ssh --hostname "$HOSTNAME_TAG" --accept-dns=false
fi

echo
echo "Enrolled. Tailnet name:"
tailscale status --self --json 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print('  ', d['Self']['DNSName'].rstrip('.'))" 2>/dev/null \
  || tailscale ip -4
echo "Add that name to fleet/relays.json (the box's \"tailnet\" field)."
