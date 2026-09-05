#!/usr/bin/env bash
# HiveRelay RC9 watchdog: bounded evidence capture and signed pidfd restart.
# There are deliberately no environment-controlled policy, unit, path, URL,
# threshold, command, or signal inputs in this process.
set -euo pipefail
umask 077

export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LANG=C
export LC_ALL=C

readonly UNIT=hiverelay.service
readonly HEALTH_URL=http://127.0.0.1:9100/health
readonly RUNTIME_DIR=/run/hiverelay-watchdog
readonly LOCK_FILE=${RUNTIME_DIR}/watchdog.lock
readonly POLICY_HELPER=/usr/local/libexec/hiverelay-health-watchdog-policy.mjs
readonly SIGNAL_HELPER=/usr/local/libexec/hiverelay-health-watchdog-pidfd
readonly NODE=/usr/bin/node
readonly SYSTEMCTL=/usr/bin/systemctl
readonly CURL=/usr/bin/curl
readonly FLOCK=/usr/bin/flock
readonly LOGGER=/usr/bin/logger
readonly LOG_TAG=hiverelay-health-watchdog

log () {
  "$LOGGER" -t "$LOG_TAG" -- "$*" 2>/dev/null || true
  printf '%s\n' "$*"
}

clear_streak () {
  "$NODE" "$POLICY_HELPER" clear >/dev/null
}

if [ "$(id -u)" != 0 ]; then
  log 'refusing watchdog execution without uid 0'
  exit 77
fi

for directory in "$RUNTIME_DIR" /etc/hiverelay/watchdog /var/lib/hiverelay-watchdog /var/log/hiverelay-watchdog/diagnostics; do
  if [ -L "$directory" ]; then
    log "watchdog directory must not be a symlink: $directory"
    exit 78
  fi
  metadata=$(stat -Lc '%u:%g:%a:%F' -- "$directory" 2>/dev/null || true)
  if [ "$metadata" != '0:0:700:directory' ]; then
    log "watchdog directory authority mismatch: $directory"
    exit 78
  fi
done

exec 9>"$LOCK_FILE"
if ! "$FLOCK" -n 9; then
  log 'watchdog invocation already owns the fixed lock; skipping'
  exit 0
fi

active=$("$SYSTEMCTL" is-active "$UNIT" 2>/dev/null || true)
if [ "$active" != active ]; then
  clear_streak
  log "unit is not exactly active (state=${active:-unknown}); failure streak reset"
  exit 0
fi

main_pid=$("$SYSTEMCTL" show "$UNIT" --property=MainPID --value --no-pager 2>/dev/null || true)
if ! [[ "$main_pid" =~ ^[1-9][0-9]*$ ]]; then
  clear_streak
  log 'active unit has no exact MainPID; failure streak reset'
  exit 0
fi

if ! snapshot=$("$NODE" "$POLICY_HELPER" snapshot "$main_pid" 2>/dev/null); then
  clear_streak
  log 'could not bind the active unit to a complete process tuple; failure streak reset'
  exit 0
fi
IFS=$'\t' read -r proc_starttime executable_sha256 cgroup_sha256 age_seconds extra <<<"$snapshot"
if [ -n "${extra:-}" ] || ! [[ "$proc_starttime" =~ ^[1-9][0-9]*$ ]] ||
   ! [[ "$executable_sha256" =~ ^[0-9a-f]{64}$ ]] ||
   ! [[ "$cgroup_sha256" =~ ^[0-9a-f]{64}$ ]] ||
   ! [[ "$age_seconds" =~ ^-?[0-9]+$ ]]; then
  clear_streak
  log 'process tuple helper returned a noncanonical snapshot; failure streak reset'
  exit 0
fi
if [ "$age_seconds" -lt 90 ]; then
  clear_streak
  log "startup grace applies (age=${age_seconds}s); failure streak reset"
  exit 0
fi

health_body=$(mktemp "$RUNTIME_DIR/health-body.XXXXXXXX")
chmod 0600 "$health_body"
cleanup () { rm -f -- "$health_body"; }
trap cleanup EXIT HUP INT TERM

set +e
health_status=$(
  ulimit -f 128
  "$CURL" --silent --show-error --http1.1 --connect-timeout 5 --max-time 5 --max-filesize 65536 \
    --output "$health_body" --write-out '%{http_code}' -- "$HEALTH_URL" 2>/dev/null
)
curl_exit=$?
set -e
if ! [[ "$health_status" =~ ^[0-9]{3}$ ]]; then health_status=000; fi

if ! outcome=$("$NODE" "$POLICY_HELPER" classify "$health_body" "$health_status" "$curl_exit" 2>/dev/null); then
  log 'health result could not be classified inside fixed bounds; no signal'
  exit 1
fi
case "$outcome" in
  healthy|responsive-not-restartable|eligible-empty|eligible-timeout) ;;
  *)
    log 'health classifier returned an unknown outcome; no signal'
    exit 1
    ;;
esac

if ! record=$("$NODE" "$POLICY_HELPER" record "$outcome" "$UNIT" "$main_pid" \
  "$proc_starttime" "$executable_sha256" 2>/dev/null); then
  log 'failure-state authority or persistence failed; no signal'
  exit 1
fi

if [ "$outcome" = healthy ]; then
  log 'healthy response observed; failure streak reset'
  exit 0
fi
if [ "$outcome" = responsive-not-restartable ]; then
  if ! responsive_diagnostic=$("$NODE" "$POLICY_HELPER" diagnose "$UNIT" "$main_pid" \
    "$proc_starttime" "$executable_sha256" "$cgroup_sha256" "$health_status" "$health_body" 2>/dev/null); then
    log "nonempty response observed (status=$health_status); restart forbidden; bounded diagnostic capture failed"
    exit 1
  fi
  IFS=$'\t' read -r diagnostic_decision responsive_sha responsive_path extra <<<"$responsive_diagnostic"
  if [ "$diagnostic_decision" != diagnostic ] || [ -n "${extra:-}" ] ||
     ! [[ "$responsive_sha" =~ ^[0-9a-f]{64}$ ]] ||
     ! [[ "$responsive_path" =~ ^/var/log/hiverelay-watchdog/diagnostics/watchdog-[0-9]{13}-[0-9a-f]{64}\.json$ ]]; then
    log "nonempty response observed (status=$health_status); restart forbidden; diagnostic result was noncanonical"
    exit 1
  fi
  log "nonempty response observed (status=$health_status); alert only, restart forbidden, diagnostic_sha256=$responsive_sha"
  exit 0
fi
if [ "$record" != eligible ]; then
  log "first eligible empty transport outcome recorded ($outcome); awaiting a distinct invocation"
  exit 0
fi

set +e
authorization=$("$NODE" "$POLICY_HELPER" authorize "$UNIT" "$main_pid" "$proc_starttime" \
  "$executable_sha256" "$cgroup_sha256" "$health_status" "$health_body" 2>/dev/null)
authorization_exit=$?
set -e
if [ "$authorization_exit" -ne 0 ]; then
  log 'restart predicate reached but signed policy, state, sequence, or diagnostic gate denied signaling'
  exit 0
fi

IFS=$'\t' read -r decision term_grace_ms kill_allowed policy_sha256 diagnostic_sha256 diagnostic_path extra <<<"$authorization"
if [ "$decision" != authorized ] || [ -n "${extra:-}" ] ||
   ! [[ "$term_grace_ms" =~ ^[0-9]+$ ]] || [ "$term_grace_ms" -lt 5000 ] || [ "$term_grace_ms" -gt 120000 ] ||
   ! [[ "$kill_allowed" =~ ^[01]$ ]] || ! [[ "$policy_sha256" =~ ^[0-9a-f]{64}$ ]] ||
   ! [[ "$diagnostic_sha256" =~ ^[0-9a-f]{64}$ ]] ||
   ! [[ "$diagnostic_path" =~ ^/var/log/hiverelay-watchdog/diagnostics/watchdog-[0-9]{13}-[0-9a-f]{64}\.json$ ]]; then
  log 'authorization helper returned a noncanonical decision; consumed sequence is not retried and no signal is sent'
  exit 1
fi

log "signed restart authorized policy_sha256=$policy_sha256 diagnostic_sha256=$diagnostic_sha256"
set +e
"$SIGNAL_HELPER" \
  --unit "$UNIT" \
  --pid "$main_pid" \
  --starttime "$proc_starttime" \
  --executable-sha256 "$executable_sha256" \
  --cgroup-sha256 "$cgroup_sha256" \
  --term-grace-ms "$term_grace_ms" \
  --kill-allowed "$kill_allowed"
signal_exit=$?
set -e
if [ "$signal_exit" -ne 0 ]; then
  log "pidfd signal gate declined or failed (exit=$signal_exit); policy sequence remains consumed"
  exit 1
fi

log 'pidfd-bound restart signal sequence completed; systemd owns any subsequent service restart'
exit 0
