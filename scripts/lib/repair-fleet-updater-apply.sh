#!/usr/bin/env bash
set -euo pipefail

candidate="$1"
expected_hash="$2"
channel="$3"
pin="$4"
repo="${HIVERELAY_REPO_DIR:-/root/hiverelay}"
conf="${HIVERELAY_UPDATER_CONF:-/etc/hiverelay-updater.conf}"
updater="/usr/local/bin/hiverelay-updater"
allowed="${HIVERELAY_ALLOWED_SIGNERS:-/etc/hiverelay/allowed-signers}"
backup="/run/hiverelay-updater.repair.$$"
config_backup="/run/hiverelay-updater.conf.repair.$$"
config_existed=0
success=0
timer_enabled="$(systemctl is-enabled hiverelay-updater.timer 2>/dev/null || true)"
timer_active="$(systemctl is-active hiverelay-updater.timer 2>/dev/null || true)"

cleanup() {
  status="${1:-1}"
  trap - EXIT HUP INT TERM
  if [ "$success" != 1 ]; then
    if [ -f "$backup" ]; then install -m 0755 "$backup" "$updater"; fi
    if [ "$config_existed" = 1 ] && [ -f "$config_backup" ]; then
      install -m 0644 "$config_backup" "$conf"
    elif [ "$config_existed" = 0 ]; then
      rm -f "$conf"
    fi
    if [ "$timer_enabled" = enabled ]; then
      systemctl enable hiverelay-updater.timer >/dev/null 2>&1 || true
      if [ "$timer_active" = active ]; then
        systemctl start hiverelay-updater.timer >/dev/null 2>&1 || true
      else
        systemctl stop hiverelay-updater.timer >/dev/null 2>&1 || true
      fi
    else
      systemctl disable --now hiverelay-updater.timer >/dev/null 2>&1 || true
    fi
  fi
  rm -f "$candidate" "$backup" "$config_backup" "${conf}.next" "${updater}.next"
  exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

[ "$(id -u)" = 0 ] || { echo 'repair requires root' >&2; exit 1; }
[[ "$channel" =~ ^[A-Za-z0-9._-]{1,32}$ ]] || { echo 'invalid channel' >&2; exit 1; }
[[ "$pin" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { echo 'invalid pin' >&2; exit 1; }
[ -f "$candidate" ] || { echo 'candidate updater missing' >&2; exit 1; }
[ "$(sha256sum "$candidate" | awk '{print $1}')" = "$expected_hash" ] || { echo 'candidate updater checksum mismatch' >&2; exit 1; }
bash -n "$candidate"

cd "$repo"
[ -z "$(git status --porcelain=v1 --untracked-files=normal)" ] || { echo 'relay repo is dirty' >&2; exit 1; }
git fetch --tags --quiet origin
HIVERELAY_REPO_DIR="$repo" HIVERELAY_ALLOWED_SIGNERS="$allowed" \
  bash "$candidate" --verify-only "$pin"
target_sha="$(git rev-parse -q --verify "refs/tags/$pin^{}")"
current_sha="$(git rev-parse HEAD)"
[ "$current_sha" = "$target_sha" ] || {
  echo 'pin is not the currently installed commit; refusing application mutation' >&2
  exit 1
}
version="v$(node -p 'require(process.argv[1]).version' "$repo/package.json")"
[ "$version" = "$pin" ] || { echo 'runtime package version does not match pin' >&2; exit 1; }

health_body="$(curl -fsS --max-time 8 http://127.0.0.1:9100/health)"
HEALTH="$health_body" EXPECTED="${pin#v}" python3 -c \
  'import json,os; h=json.loads(os.environ["HEALTH"]); assert h.get("running") is True and h.get("version") == os.environ["EXPECTED"]'

systemctl stop hiverelay-updater.timer >/dev/null 2>&1 || true
[ "$(systemctl is-active hiverelay-updater.service 2>/dev/null || true)" != active ] || {
  echo 'updater service is already active; retry after it exits' >&2
  exit 1
}
if [ -f "$updater" ]; then cp -p "$updater" "$backup"; fi
if [ -f "$conf" ]; then cp -p "$conf" "$config_backup"; config_existed=1; fi
install -m 0755 "$candidate" "${updater}.next"
mv -f "${updater}.next" "$updater"
printf 'CHANNEL=%s\nPINNED_TAG=%s\n' "$channel" "$pin" > "${conf}.next"
chmod 0644 "${conf}.next"
mv -f "${conf}.next" "$conf"

HIVERELAY_REPO_DIR="$repo" HIVERELAY_UPDATER_CONF="$conf" \
  HIVERELAY_ALLOWED_SIGNERS="$allowed" "$updater" --dry-run
systemctl enable --now hiverelay-updater.timer >/dev/null
[ "$(systemctl is-enabled hiverelay-updater.timer)" = enabled ]
[ "$(systemctl is-active hiverelay-updater.timer)" = active ]

[ "$(git rev-parse HEAD)" = "$current_sha" ] || {
  echo 'application commit changed during no-op repair' >&2
  exit 1
}
health_body="$(curl -fsS --max-time 8 http://127.0.0.1:9100/health)"
HEALTH="$health_body" EXPECTED="${pin#v}" python3 -c \
  'import json,os; h=json.loads(os.environ["HEALTH"]); assert h.get("running") is True and h.get("version") == os.environ["EXPECTED"]'

success=1
printf 'HIVERELAY_REPAIR_OK|%s|%s|enabled|active\n' "$version" "$pin"
