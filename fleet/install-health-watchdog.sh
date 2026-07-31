#!/usr/bin/env bash
# install-health-watchdog.sh — install local health restart timer on a relay box.
# Run as root on the box, or via: ssh root@box 'bash -s' < fleet/install-health-watchdog.sh
set -euo pipefail

SCRIPT_SRC="${1:-}"
if [ -n "$SCRIPT_SRC" ] && [ -f "$SCRIPT_SRC" ]; then
  install -m 0755 "$SCRIPT_SRC" /usr/local/bin/hiverelay-health-watchdog.sh
else
  # Embedded install when piped over SSH without file args
  cat > /usr/local/bin/hiverelay-health-watchdog.sh <<'WATCH'
#!/usr/bin/env bash
# health-watchdog.sh — local systemd timer target.
# If HiveRelay is "active" but /health fails repeatedly, force-kill and restart.
# Covers event-loop hangs (LISTEN on :9100, no response) that systemd cannot see.
#
# State: /run/hiverelay-health-watchdog.failcount
# Env (optional drop-in):
#   HIVERELAY_HEALTH_URL      default http://127.0.0.1:9100/health
#   HIVERELAY_HEALTH_TIMEOUT  curl max-time seconds (default 5)
#   HIVERELAY_HEALTH_FAILS    consecutive failures before restart (default 2)
set -uo pipefail

URL="${HIVERELAY_HEALTH_URL:-http://127.0.0.1:9100/health}"
TIMEOUT="${HIVERELAY_HEALTH_TIMEOUT:-5}"
NEED_FAILS="${HIVERELAY_HEALTH_FAILS:-2}"
STATE_FILE="${HIVERELAY_HEALTH_STATE:-/run/hiverelay-health-watchdog.failcount}"
UNIT="${HIVERELAY_UNIT:-hiverelay}"
LOG_TAG="hiverelay-health-watchdog"

log() { logger -t "$LOG_TAG" -- "$*"; echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*"; }

active=$(systemctl is-active "$UNIT" 2>/dev/null || echo inactive)
if [ "$active" != "active" ] && [ "$active" != "activating" ]; then
  # Unit not expected to answer health; clear streak
  echo 0 >"$STATE_FILE" 2>/dev/null || true
  exit 0
fi

# Skip while still starting (boot grace)
MainPID=$(systemctl show "$UNIT" -p MainPID --value 2>/dev/null || echo 0)
if [ -n "$MainPID" ] && [ "$MainPID" != "0" ] && [ -r "/proc/$MainPID" ]; then
  # seconds of process life
  start_ticks=$(awk '{print $22}' /proc/"$MainPID"/stat 2>/dev/null || echo 0)
  hz=$(getconf CLK_TCK 2>/dev/null || echo 100)
  uptime_s=$(awk '{print int($1)}' /proc/uptime)
  start_s=$(( start_ticks / hz ))
  # approximate process age from boot - starttime is jiffies since boot
  age=$(( uptime_s - start_s ))
  if [ "$age" -ge 0 ] && [ "$age" -lt 90 ]; then
    log "grace period age=${age}s pid=$MainPID — skip"
    exit 0
  fi
fi

# NOTE: deliberately not `curl -f`. -f discards the response body on a non-2xx
# status, and the relay answers 503 with {"ok":false,"reason":"disk-critical"}
# as a DELIBERATE drain signal (PRODUCTION.md:433-436). Without the body this
# watchdog cannot tell "draining on purpose" from "event-loop hung", so it
# counted the drain as a failure and SIGKILLed — and since a restart frees no
# disk, the box then looped every ~4 minutes forever.
body=$(curl -sS --max-time "$TIMEOUT" "$URL" 2>/dev/null || true)
if echo "$body" | grep -q '"ok"[[:space:]]*:[[:space:]]*true'; then
  echo 0 >"$STATE_FILE"
  exit 0
fi

# This watchdog exists for ONE failure mode: an event-loop hang that systemd
# cannot see, where the unit is active and :9100 is listening but /health never
# answers. A structured JSON answer — whatever it says — proves the loop is
# turning, so it is by definition not the thing we are here to kill.
#
# Deliberate not-ok states (disk-critical drain, storage-fail-closed) are
# reported precisely so an operator can act. SIGKILLing them destroys the signal
# and fixes nothing: a restart frees no disk and does not clear a fail-closed
# storage authority. Treat any reasoned reply as "responsive" and stand down.
if echo "$body" | grep -q '"reason"[[:space:]]*:'; then
  reason=$(echo "$body" | sed -n 's/.*"reason"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  log "relay responsive but not ok (reason=${reason:-unknown}) — reporting, not a hang; not restarting"
  echo 0 >"$STATE_FILE"
  exit 0
fi

fails=0
if [ -f "$STATE_FILE" ]; then
  fails=$(cat "$STATE_FILE" 2>/dev/null || echo 0)
fi
fails=$((fails + 1))
echo "$fails" >"$STATE_FILE"
log "health FAIL $fails/$NEED_FAILS body=${body:0:80}"

if [ "$fails" -lt "$NEED_FAILS" ]; then
  exit 0
fi

log "forcing restart of $UNIT after $fails consecutive health failures"
# Force-kill hung event loops (SIGTERM often does nothing when loop is stuck)
systemctl kill -s SIGKILL "$UNIT" 2>/dev/null || true
sleep 1
fuser -k -9 9100/tcp 2>/dev/null || true
sleep 1
systemctl reset-failed "$UNIT" 2>/dev/null || true
systemctl start "$UNIT" 2>/dev/null || systemctl restart "$UNIT" 2>/dev/null || true
echo 0 >"$STATE_FILE"
log "restart issued"
exit 0
WATCH
  chmod 0755 /usr/local/bin/hiverelay-health-watchdog.sh
fi

cat > /etc/systemd/system/hiverelay-health-watchdog.service <<'EOF'
[Unit]
Description=HiveRelay health watchdog (one-shot probe)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/hiverelay-health-watchdog.sh
Nice=10
TimeoutStartSec=30
EOF

cat > /etc/systemd/system/hiverelay-health-watchdog.timer <<'EOF'
[Unit]
Description=HiveRelay health watchdog every 2 minutes
Requires=hiverelay-health-watchdog.service

[Timer]
OnBootSec=3min
OnUnitActiveSec=2min
AccuracySec=30s
Persistent=true
Unit=hiverelay-health-watchdog.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now hiverelay-health-watchdog.timer
systemctl start hiverelay-health-watchdog.service || true
echo "installed hiverelay-health-watchdog.timer"
systemctl list-timers --all | grep hiverelay-health || true
