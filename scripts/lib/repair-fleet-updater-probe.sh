#!/usr/bin/env bash
set -euo pipefail

repo="${HIVERELAY_REPO_DIR:-/root/hiverelay}"
conf="${HIVERELAY_UPDATER_CONF:-/etc/hiverelay-updater.conf}"
allowed="${HIVERELAY_ALLOWED_SIGNERS:-/etc/hiverelay/allowed-signers}"
requested_pin="${1:-}"
[[ "$requested_pin" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || {
  echo 'invalid requested pin' >&2
  exit 1
}

version="v$(node -p 'require(process.argv[1]).version' "$repo/package.json" 2>/dev/null || printf '?')"
health="$(curl -fsS --max-time 8 http://127.0.0.1:9100/health 2>/dev/null || true)"
health_fields="$(HEALTH="$health" python3 -c 'import json,os; h=json.loads(os.environ["HEALTH"]); print("{}|{}".format(str(h.get("running", "?")).lower(), h.get("version", "?")))' 2>/dev/null || printf '?|?')"
IFS='|' read -r running health_version <<< "$health_fields"
enabled="$(systemctl is-enabled hiverelay-updater.timer 2>/dev/null || true)"
active="$(systemctl is-active hiverelay-updater.timer 2>/dev/null || true)"
channel="$(awk -F= '/^[[:space:]]*CHANNEL[[:space:]]*=/ {sub(/^[^=]*=/,"");sub(/^[[:space:]]*/,"");sub(/[[:space:]]*$/,"");print;exit}' "$conf" 2>/dev/null || true)"
pin="$(awk -F= '/^[[:space:]]*PINNED_TAG[[:space:]]*=/ {sub(/^[^=]*=/,"");sub(/^[[:space:]]*/,"");sub(/[[:space:]]*$/,"");print;exit}' "$conf" 2>/dev/null || true)"

tag_verified=false
head_matches=false
repo_clean=false
cd "$repo"
[ -z "$(git status --porcelain=v1 --untracked-files=normal 2>/dev/null || printf '?')" ] && repo_clean=true
target_sha="$(git rev-parse -q --verify "refs/tags/$requested_pin^{}" 2>/dev/null || true)"
current_sha="$(git rev-parse HEAD 2>/dev/null || true)"
if [ -n "$target_sha" ] && [ "$target_sha" = "$current_sha" ]; then head_matches=true; fi
if [ -n "$target_sha" ] && [ -r "$allowed" ] &&
  [ "$(git cat-file -t "refs/tags/$requested_pin" 2>/dev/null || true)" = tag ]; then
  if verify_output="$(git -c gpg.format=ssh -c "gpg.ssh.allowedSignersFile=$allowed" \
    verify-tag --raw "$requested_pin" 2>&1)"; then
    if printf '%s' "$verify_output" | grep -Eq 'GOODSIG|TRUST_(FULLY|ULTIMATE)' ||
      printf '%s' "$verify_output" | grep -qi 'Good.*signature'; then
      tag_verified=true
    fi
  fi
fi

ready=false
if [ "$tag_verified" = true ] && [ "$head_matches" = true ] &&
  [ "$repo_clean" = true ] &&
  [ "$version" = "$requested_pin" ] && [ "$running" = true ] &&
  [ "$health_version" = "${requested_pin#v}" ]; then
  ready=true
fi

printf 'HIVERELAY_REPAIR_PROBE|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
  "${version:-?}" "${running:-?}" "${enabled:-missing}" \
  "${active:-inactive}" "${channel:-?}" "${pin:--}" \
  "${tag_verified}" "${head_matches}" "${health_version:-?}" \
  "${repo_clean}" "${ready}"
