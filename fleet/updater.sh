#!/usr/bin/env bash
#
# hiverelay-updater — pull-based self-update agent for one HiveRelay node.
#
# Run by a systemd timer (every ~15 min). Each box owns its own lifecycle:
# no inbound SSH, no orchestrator, works behind NAT. The flow:
#
#   1. Read this box's channel (/etc/hiverelay-updater.conf, default stable).
#   2. Fetch fleet/channels.json from the repo and resolve the target tag.
#   3. If already on the target -> no-op.
#   4. Otherwise: snapshot current SHA, fetch + checkout the target tag,
#      reinstall deps only if package-lock changed, restart the relay.
#   5. HEALTH-GATE: poll /health for running:true (up to 120s).
#         green  -> done.
#         red    -> ROLL BACK to the snapshot, restart, re-verify, alert.
#
# Safety: single-flight (flock), refuses to run if the repo has uncommitted
# local changes (never clobbers a hand-edit), and a failed update always
# tries to leave the box on the version it started from.
#
# Usage:  hiverelay-updater [--dry-run]
set -euo pipefail

# systemd oneshot units don't export HOME; under `set -u` a bare $HOME
# reference below would abort the whole run. Default it (boxes run as root)
# so the script is robust whether launched by systemd or by hand.
: "${HOME:=/root}"

REPO_DIR="${HIVERELAY_REPO_DIR:-$HOME/hiverelay}"
CONF="${HIVERELAY_UPDATER_CONF:-/etc/hiverelay-updater.conf}"
CHANNELS_URL="${HIVERELAY_CHANNELS_URL:-https://raw.githubusercontent.com/bigdestiny2/P2P-Hiverelay/main/fleet/channels.json}"
SERVICE="${HIVERELAY_SERVICE:-hiverelay}"
API="${HIVERELAY_API:-http://127.0.0.1:9100}"
HEALTH_TIMEOUT="${HIVERELAY_HEALTH_TIMEOUT:-120}"
LOCK="/run/hiverelay-updater.lock"

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

log() { echo "[updater $(date -u +%FT%TZ)] $*"; }
die() { log "ERR $*"; exit 1; }

# ── single-flight ──────────────────────────────────────────────────
# Lock under /run on Linux; fall back to /tmp where /run isn't writable
# (e.g. a dev box). If flock is unavailable, proceed rather than falsely
# reporting "in progress".
[ -w "$(dirname "$LOCK")" ] 2>/dev/null || LOCK="/tmp/hiverelay-updater.lock"
if command -v flock >/dev/null 2>&1; then
  exec 9>"$LOCK" 2>/dev/null || true
  flock -n 9 || { log "another run in progress; exiting"; exit 0; }
else
  log "WARN flock unavailable — proceeding without single-flight lock"
fi

# ── channel ────────────────────────────────────────────────────────
CHANNEL="stable"
# shellcheck disable=SC1090
[ -f "$CONF" ] && . "$CONF"

# ── resolve target tag ─────────────────────────────────────────────
JSON="$(curl -fsS --max-time 20 "$CHANNELS_URL")" || die "cannot fetch channels.json"
TARGET="$(printf '%s' "$JSON" | python3 -c "import sys,json; print(json.load(sys.stdin).get('$CHANNEL',''))")" \
  || die "cannot parse channels.json"
[ -n "$TARGET" ] || die "no target tag for channel '$CHANNEL'"

cd "$REPO_DIR" || die "repo dir $REPO_DIR not found"

# refuse to touch a dirty tree (protects manual edits / stranded work)
if ! git diff --quiet || ! git diff --cached --quiet; then
  log "WARN repo has uncommitted changes; skipping auto-update"; exit 0
fi

CUR_VER="v$(grep -m1 '"version"' package.json | tr -dc '0-9.')"
CUR_SHA="$(git rev-parse HEAD)"

if [ "$TARGET" = "$CUR_VER" ]; then
  log "channel=$CHANNEL up-to-date at $CUR_VER"; exit 0
fi
log "channel=$CHANNEL current=$CUR_VER target=$TARGET (from $CUR_SHA)"
if [ "$DRY_RUN" = 1 ]; then log "dry-run: would update $CUR_VER -> $TARGET"; exit 0; fi

# ── helpers ────────────────────────────────────────────────────────
apikey() { systemctl show "$SERVICE" -p Environment 2>/dev/null | grep -o 'HIVERELAY_API_KEY=[^ ]*' | cut -d= -f2; }

healthy() {
  local key hdr end
  key="$(apikey)"
  hdr=(); [ -n "$key" ] && hdr=(-H "Authorization: Bearer $key")
  end=$((SECONDS + HEALTH_TIMEOUT))
  while [ $SECONDS -lt $end ]; do
    if curl -fsS --max-time 8 "${hdr[@]}" "$API/health" 2>/dev/null | grep -q '"running":true'; then
      return 0
    fi
    sleep 5
  done
  return 1
}

deps_if_changed() { # $1=from-ref $2=to-ref
  if ! git diff --quiet "$1" "$2" -- package-lock.json 2>/dev/null; then
    log "package-lock changed -> reinstalling deps"
    npm ci --omit=dev --no-audit --no-fund 2>&1 | tail -2 \
      || npm install --omit=dev --no-audit --no-fund 2>&1 | tail -2
  fi
}

# ── update ─────────────────────────────────────────────────────────
git fetch --tags --quiet origin || die "git fetch failed"
git rev-parse -q --verify "refs/tags/$TARGET" >/dev/null || die "target tag $TARGET not found after fetch"
git checkout --quiet "$TARGET" || die "checkout $TARGET failed"
deps_if_changed "$CUR_SHA" "$TARGET"
systemctl restart "$SERVICE"

if healthy; then
  log "OK updated $CUR_VER -> $TARGET — health green"
  # Pack loose objects accrued by fetch/checkout so repeated updates don't
  # grow .git. Plain gc only (NEVER --aggressive). Post-success ONLY —
  # never on the rollback path (it would lengthen recovery). Space-gated:
  # a repack needs transient ~2x scratch, so skip on a near-full box.
  # Foreground + timeout so gc can't wedge or race the next tick's
  # checkout, and its failure is non-fatal (must not change our exit).
  # Reachable history + all tags + the prior SHA are preserved (only
  # unreachable objects past gc.pruneExpire are dropped) — rollback-safe.
  FREE_KB=$(df -Pk "$REPO_DIR" 2>/dev/null | awk 'NR==2{print $4}')
  if [ "${FREE_KB:-0}" -gt 524288 ] && [ ! -f .git/gc.pid ]; then
    timeout 90 git gc --quiet --no-detach 2>&1 | tail -2 \
      || log "WARN git gc skipped/failed (non-fatal)"
  else
    log "skip gc: low disk (${FREE_KB:-?}KB free) or gc already running"
  fi
  exit 0
fi

# ── rollback ───────────────────────────────────────────────────────
log "FAIL health not green on $TARGET within ${HEALTH_TIMEOUT}s — ROLLING BACK to $CUR_VER ($CUR_SHA)"
git checkout --quiet "$CUR_SHA" || log "CRITICAL could not checkout previous SHA"
deps_if_changed "$TARGET" "$CUR_SHA"
systemctl restart "$SERVICE"
if healthy; then
  log "rollback OK — back on $CUR_VER"
else
  log "CRITICAL rollback unhealthy — manual attention needed on $(hostname)"
fi
exit 1
