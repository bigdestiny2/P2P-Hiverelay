#!/usr/bin/env bash
#
# install-updater.sh — install the hiverelay-updater agent on THIS box.
# Run on the relay host (as root). Idempotent.
#
#   curl -fsSL .../fleet/install-updater.sh | bash -s -- <channel>
# or, from a checked-out repo on the box:
#   sudo bash fleet/install-updater.sh stable
#
# <channel> must match a key in fleet/channels.json (stable | canary).
set -euo pipefail

CHANNEL="${1:-stable}"
REPO_DIR="${HIVERELAY_REPO_DIR:-$HOME/hiverelay}"
SRC="$REPO_DIR/fleet"

if [[ ! "$CHANNEL" =~ ^[A-Za-z0-9._-]{1,32}$ ]]; then
  echo "Invalid channel '$CHANNEL' — use a key from fleet/channels.json (for example stable or canary)" >&2
  exit 1
fi

[ -d "$SRC" ] || { echo "fleet/ not found in $REPO_DIR — clone/pull the repo first"; exit 1; }

echo "Installing hiverelay-updater (channel=$CHANNEL)…"

install -m 0755 "$SRC/updater.sh" /usr/local/bin/hiverelay-updater
install -m 0644 "$SRC/hiverelay-updater.service" /etc/systemd/system/hiverelay-updater.service
install -m 0644 "$SRC/hiverelay-updater.timer"   /etc/systemd/system/hiverelay-updater.timer

printf 'CHANNEL=%s\n' "$CHANNEL" > /etc/hiverelay-updater.conf
chmod 0644 /etc/hiverelay-updater.conf

systemctl daemon-reload
systemctl enable --now hiverelay-updater.timer

# Supply-chain gate (audit HR-DIS-003): the updater refuses to check out a tag
# that is not signed by a trusted key. Warn loudly if the allowed-signers file
# is not yet provisioned — until it exists, updates correctly FAIL CLOSED.
# See docs/SUPPLY-CHAIN.md § "Signed release tags".
ALLOWED_SIGNERS="${HIVERELAY_ALLOWED_SIGNERS:-/etc/hiverelay/allowed-signers}"
if [ ! -r "$ALLOWED_SIGNERS" ]; then
  echo "WARN allowed-signers file '$ALLOWED_SIGNERS' not found — signed-tag" >&2
  echo "     verification will FAIL CLOSED (no updates) until you install it." >&2
fi

# Also bound the log footprint so updates can't bloat the disk (idempotent,
# does not restart the relay). Safe no-op if already hardened.
if [ -f "$SRC/harden-box.sh" ]; then
  echo "Applying log-footprint hardening…"
  bash "$SRC/harden-box.sh" || echo "WARN harden-box.sh failed (non-fatal)"
fi

echo "Installed. Channel=$CHANNEL. Timer:"
systemctl status hiverelay-updater.timer --no-pager | sed -n '1,4p' || true
echo
echo "Dry-run the agent now (no changes):"
echo "  hiverelay-updater --dry-run"
