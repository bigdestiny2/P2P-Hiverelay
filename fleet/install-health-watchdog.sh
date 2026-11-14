#!/usr/bin/env bash
# Install the RC9 signed pidfd watchdog from an exact local release checkout.
# Piped/embedded installation is intentionally unsupported: the shell, Node
# policy helper, C pidfd helper, service and timer must be one tracked set.
set -euo pipefail
umask 077

export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LANG=C
export LC_ALL=C

readonly UNIT=hiverelay.service
readonly WATCHDOG_UNIT=hiverelay-health-watchdog.service
readonly TIMER=hiverelay-health-watchdog.timer
readonly BIN_DIR=/usr/local/bin
readonly LIBEXEC_DIR=/usr/local/libexec
readonly SYSTEMD_DIR=/etc/systemd/system
readonly CONFIG_DIR=/etc/hiverelay/watchdog
readonly STATE_DIR=/var/lib/hiverelay-watchdog
readonly RUNTIME_DIR=/run/hiverelay-watchdog
readonly LOG_DIR=/var/log/hiverelay-watchdog
readonly DIAGNOSTIC_DIR=${LOG_DIR}/diagnostics

die () { printf 'watchdog install: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die 'root is required'
[ -x /usr/bin/node ] || die '/usr/bin/node is required'
[ -x /usr/bin/curl ] || die '/usr/bin/curl is required'
[ -x /usr/bin/systemctl ] || die '/usr/bin/systemctl is required'
[ -x /usr/bin/cc ] || [ -x /usr/bin/gcc ] || die 'a system C compiler is required'

node_major=$(/usr/bin/node -p 'Number(process.versions.node.split(".")[0])')
[[ "$node_major" =~ ^[0-9]+$ ]] && [ "$node_major" -ge 20 ] || die 'Node.js >=20 is required'
active=$(/usr/bin/systemctl is-active "$UNIT" 2>/dev/null || true)
[ "$active" = active ] || die "$UNIT must be exactly active for the non-restart installation proof"
before_pid=$(/usr/bin/systemctl show "$UNIT" --property=MainPID --value --no-pager)
before_restarts=$(/usr/bin/systemctl show "$UNIT" --property=NRestarts --value --no-pager)
[[ "$before_pid" =~ ^[1-9][0-9]*$ ]] || die "$UNIT has no exact MainPID"
[[ "$before_restarts" =~ ^[0-9]+$ ]] || die "$UNIT has no exact NRestarts counter"

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
for name in health-watchdog.sh health-watchdog-policy.mjs health-watchdog-helper.c \
  hiverelay-health-watchdog.service hiverelay-health-watchdog.timer; do
  [ -f "$script_dir/$name" ] && [ ! -L "$script_dir/$name" ] ||
    die "tracked companion is missing or a symlink: $name"
done

/bin/bash -n "$script_dir/health-watchdog.sh"
/usr/bin/node --check "$script_dir/health-watchdog-policy.mjs"

for directory in "$CONFIG_DIR" "$STATE_DIR" "$RUNTIME_DIR" "$LOG_DIR" "$DIAGNOSTIC_DIR"; do
  [ ! -L "$directory" ] || die "refusing symlink directory: $directory"
  /usr/bin/install -d -o root -g root -m 0700 -- "$directory"
  metadata=$(stat -Lc '%u:%g:%a:%F' -- "$directory")
  [ "$metadata" = '0:0:700:directory' ] || die "directory authority mismatch: $directory"
done
/usr/bin/install -d -o root -g root -m 0755 -- "$LIBEXEC_DIR"

build_dir=$(mktemp -d /var/tmp/hiverelay-watchdog-build.XXXXXXXX)
cleanup () { rm -rf -- "$build_dir"; }
trap cleanup EXIT HUP INT TERM
compiler=/usr/bin/cc
[ -x "$compiler" ] || compiler=/usr/bin/gcc
"$compiler" -std=c11 -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
  -Wall -Wextra -Werror -Wformat=2 \
  -o "$build_dir/hiverelay-health-watchdog-pidfd" "$script_dir/health-watchdog-helper.c"

/usr/bin/install -o root -g root -m 0755 -- "$script_dir/health-watchdog.sh" \
  "$BIN_DIR/hiverelay-health-watchdog.sh"
/usr/bin/install -o root -g root -m 0755 -- "$script_dir/health-watchdog-policy.mjs" \
  "$LIBEXEC_DIR/hiverelay-health-watchdog-policy.mjs"
/usr/bin/install -o root -g root -m 0755 -- "$build_dir/hiverelay-health-watchdog-pidfd" \
  "$LIBEXEC_DIR/hiverelay-health-watchdog-pidfd"
/usr/bin/install -o root -g root -m 0644 -- "$script_dir/hiverelay-health-watchdog.service" \
  "$SYSTEMD_DIR/hiverelay-health-watchdog.service"
/usr/bin/install -o root -g root -m 0644 -- "$script_dir/hiverelay-health-watchdog.timer" \
  "$SYSTEMD_DIR/hiverelay-health-watchdog.timer"

sequence_file=$STATE_DIR/highest-restart-policy-sequence-v1.json
if [ ! -e "$sequence_file" ]; then
  sequence_temp=$(mktemp "$STATE_DIR/.highest-restart-policy-sequence-v1.XXXXXXXX")
  printf '%s' '{"consumedAt":0,"kind":"HiveRelayWatchdogConsumedSequenceV1","policySha256":"0000000000000000000000000000000000000000000000000000000000000000","sequence":0,"version":1}' >"$sequence_temp"
  chown root:root "$sequence_temp"
  chmod 0600 "$sequence_temp"
  sync -f "$sequence_temp"
  if ! ln -- "$sequence_temp" "$sequence_file"; then
    rm -f -- "$sequence_temp"
    die 'consumed-sequence initialization raced or failed'
  fi
  rm -f -- "$sequence_temp"
  sync -f "$STATE_DIR"
fi

for installed in \
  "$BIN_DIR/hiverelay-health-watchdog.sh:0:0:755" \
  "$LIBEXEC_DIR/hiverelay-health-watchdog-policy.mjs:0:0:755" \
  "$LIBEXEC_DIR/hiverelay-health-watchdog-pidfd:0:0:755" \
  "$SYSTEMD_DIR/hiverelay-health-watchdog.service:0:0:644" \
  "$SYSTEMD_DIR/hiverelay-health-watchdog.timer:0:0:644" \
  "$sequence_file:0:0:600"; do
  path=${installed%%:*}
  expected=${installed#*:}
  metadata=$(stat -Lc '%u:%g:%a' -- "$path")
  [ "$metadata" = "$expected" ] || die "installed authority mismatch: $path"
done

cmp -s -- "$script_dir/health-watchdog.sh" "$BIN_DIR/hiverelay-health-watchdog.sh" ||
  die 'installed shell differs from tracked release bytes'
cmp -s -- "$script_dir/health-watchdog-policy.mjs" "$LIBEXEC_DIR/hiverelay-health-watchdog-policy.mjs" ||
  die 'installed policy helper differs from tracked release bytes'

if [ -x /usr/bin/systemd-analyze ]; then
  /usr/bin/systemd-analyze verify \
    "$SYSTEMD_DIR/hiverelay-health-watchdog.service" \
    "$SYSTEMD_DIR/hiverelay-health-watchdog.timer"
fi
/usr/bin/systemctl daemon-reload
/usr/bin/systemctl enable --now "$TIMER"
/usr/bin/systemctl start "$WATCHDOG_UNIT"

after_pid=$(/usr/bin/systemctl show "$UNIT" --property=MainPID --value --no-pager)
after_restarts=$(/usr/bin/systemctl show "$UNIT" --property=NRestarts --value --no-pager)
result=$(/usr/bin/systemctl show "$WATCHDOG_UNIT" --property=Result --value --no-pager)
[ "$result" = success ] || die 'watchdog oneshot was not green'
[ "$after_pid" = "$before_pid" ] || die 'green watchdog proof detected a relay PID change'
[ "$after_restarts" = "$before_restarts" ] || die 'green watchdog proof detected a hidden restart'

shell_sha=$(/usr/bin/sha256sum -- "$BIN_DIR/hiverelay-health-watchdog.sh")
shell_sha=${shell_sha%% *}
policy_sha=$(/usr/bin/sha256sum -- "$LIBEXEC_DIR/hiverelay-health-watchdog-policy.mjs")
policy_sha=${policy_sha%% *}
printf 'installed %s; green oneshot kept pid=%s restarts=%s shell_sha256=%s policy_sha256=%s\n' \
  "$TIMER" "$after_pid" "$after_restarts" "$shell_sha" "$policy_sha"
