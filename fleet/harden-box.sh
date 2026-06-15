#!/usr/bin/env bash
#
# harden-box.sh — bound the log footprint on a relay box so version
# updates (and the relay's own status chatter) can't bloat the disk.
# Idempotent; safe to re-run. Does NOT restart the relay — only journald.
#
#   sudo bash fleet/harden-box.sh
#
# What it sets (sizes verified for the smallest fleet box, 19-24G, by an
# adversarial review on 2026-06-16):
#   - journald SystemMaxUse=200M (~1% of disk), SystemKeepFree=1G so
#     journald yields disk to the corestore on a near-full box before it
#     becomes the problem, SystemMaxFileSize=50M (≥4 segments so a vacuum
#     never drops the whole journal at once). No MaxRetentionSec — let
#     SystemMaxUse be the only bound (time caps throw away free history).
#   - logrotate for /var/log/hiverelay.log (the deployed unit's stdout
#     sink): copytruncate (relay holds the fd open), maxsize 20M, 7 days.
#
# NOT addressed here (needs a source change + version bump, tracked
# separately): the 5s `process.stdout.write` status line that drives the
# volume. Capping bounds the disk; the TTY-gated structured-log fix in
# packages/core/cli/index.js quiets the source. Until that ships, the
# cap + rotation are the guarantee.
set -euo pipefail

echo "Bounding journald…"
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/10-hiverelay-cap.conf <<'EOF'
[Journal]
SystemMaxUse=200M
SystemKeepFree=1G
SystemMaxFileSize=50M
EOF
systemctl restart systemd-journald
journalctl --vacuum-size=200M >/dev/null 2>&1 || true

echo "Installing logrotate for /var/log/hiverelay.log…"
cat > /etc/logrotate.d/hiverelay <<'EOF'
/var/log/hiverelay.log {
  daily
  rotate 7
  maxsize 20M
  missingok
  notifempty
  compress
  delaycompress
  copytruncate
}
EOF

echo "Done. journald now: $(journalctl --disk-usage 2>/dev/null | grep -oE '[0-9.]+[MG]' | tail -1); relay: $(systemctl is-active hiverelay 2>/dev/null)"
