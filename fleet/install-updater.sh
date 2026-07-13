#!/bin/bash
#
# install-updater.sh — install the hiverelay-updater agent on THIS box.
# Run on the relay host (as root). Idempotent.
#
#   curl -fsSL .../fleet/install-updater.sh | bash -s -- <channel> <relay-name>
# or, from a checked-out repo on the box:
#   sudo bash fleet/install-updater.sh stable sing-1
#
# <relay-name> must exactly match this node's fleet/relays.json identity. It is
# required so a signed gateway cohort cannot be bypassed by deleting probe env.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset BASH_ENV ENV CDPATH GLOBIGNORE LD_PRELOAD LD_LIBRARY_PATH NODE_OPTIONS NODE_PATH \
  PYTHONPATH PYTHONHOME PYTHONSTARTUP SSH_ASKPASS SSH_AUTH_SOCK 2>/dev/null || true
set -euo pipefail

stat_record() {
  stat -f '%u|%Lp|%l|%z' "$1" 2>/dev/null || stat -c '%u|%a|%h|%s' "$1" 2>/dev/null
}

unsafe_name() {
  local path="$1"
  printf '%s.unsafe.%s.%s\n' "$path" "$(date -u +%Y%m%dT%H%M%SZ)" "$$"
}

safe_owned_directory() {
  local record uid mode rest mode_value
  [ -d "$1" ] && [ ! -L "$1" ] || return 1
  record="$(stat_record "$1")" || return 1
  IFS='|' read -r uid mode rest <<< "$record"
  [ "$uid" = "$EUID" ] || return 1
  mode_value=$((8#$mode))
  (( (mode_value & 8#022) == 0 ))
}

CHANNEL="${1:-stable}"
RELAY_NAME="${2:-${HIVERELAY_RELAY_NAME:-}}"
REPO_DIR="${HIVERELAY_REPO_DIR:-$HOME/hiverelay}"
SRC="$REPO_DIR/fleet"
DESTDIR="${DESTDIR:-}"

case "$REPO_DIR" in
  /*) ;;
  *) echo "HIVERELAY_REPO_DIR must be an absolute path" >&2; exit 1 ;;
esac
if [ "${#REPO_DIR}" -gt 4096 ] || printf '%s' "$REPO_DIR" | LC_ALL=C grep -q '[[:space:][:cntrl:]]'; then
  echo "HIVERELAY_REPO_DIR must be bounded and contain no whitespace or control characters" >&2
  exit 1
fi
if [ -n "$DESTDIR" ] && [[ "$DESTDIR" != /* ]]; then
  echo "DESTDIR must be empty or an absolute path" >&2
  exit 1
fi

if [[ ! "$CHANNEL" =~ ^[A-Za-z0-9._-]{1,32}$ ]]; then
  echo "Invalid channel '$CHANNEL' — use a key from fleet/channels.json (for example stable or canary)" >&2
  exit 1
fi
if [[ ! "$RELAY_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  echo "Invalid or missing relay name '$RELAY_NAME' — use the exact fleet/relays.json name" >&2
  exit 1
fi

[ -d "$SRC" ] || { echo "fleet/ not found in $REPO_DIR — clone/pull the repo first"; exit 1; }
[ -f "$SRC/updater-launcher.sh" ] || { echo "updater launcher not found in $SRC"; exit 1; }
[ -f "$SRC/quarantine-public-gateway.sh" ] || { echo "gateway quarantine helper not found in $SRC"; exit 1; }
[ -f "$SRC/relays.json" ] || { echo "fleet relay inventory not found in $SRC"; exit 1; }

# Catch typos and channel/identity drift before persisting the node identity.
# Values cross the language boundary only through the environment, never code.
if ! HIVERELAY_INSTALL_RELAY_NAME="$RELAY_NAME" HIVERELAY_INSTALL_CHANNEL="$CHANNEL" \
  python3 -c '
import json, os, sys
with open(sys.argv[1], encoding="utf-8") as source:
    document = json.load(source)
rows = document.get("relays", []) if isinstance(document, dict) else []
wanted = os.environ["HIVERELAY_INSTALL_RELAY_NAME"]
matches = [row for row in rows if isinstance(row, dict) and row.get("name") == wanted]
valid = len(matches) == 1 and matches[0].get("channel") == os.environ["HIVERELAY_INSTALL_CHANNEL"]
sys.exit(0 if valid else 1)
' \
  "$SRC/relays.json"; then
  echo "Relay '$RELAY_NAME' is not uniquely assigned to channel '$CHANNEL' in fleet/relays.json" >&2
  exit 1
fi

echo "Installing hiverelay-updater (channel=$CHANNEL)…"

BIN_DIR="$DESTDIR/usr/local/bin"
SBIN_DIR="$DESTDIR/usr/local/sbin"
SYSTEMD_DIR="$DESTDIR/etc/systemd/system"
CONF="$DESTDIR/etc/hiverelay-updater.conf"
ENV_DIR="$DESTDIR/etc/hiverelay"
ENV_FILE="$ENV_DIR/hiverelay-updater.env"

install -d -m 0755 "$BIN_DIR" "$SBIN_DIR" "$SYSTEMD_DIR"
if [ -e "$ENV_DIR" ] || [ -L "$ENV_DIR" ]; then
  if ! safe_owned_directory "$ENV_DIR"; then
    ENV_DIR_UNSAFE="$(unsafe_name "$ENV_DIR")"
    mv "$ENV_DIR" "$ENV_DIR_UNSAFE" || { echo "Could not quarantine unsafe updater environment directory: $ENV_DIR" >&2; exit 1; }
    echo "WARN quarantined unsafe updater environment directory at $ENV_DIR_UNSAFE" >&2
  fi
fi
install -d -m 0700 "$ENV_DIR"
chmod 0700 "$ENV_DIR"

# The environment file is required by the unit. Preserve operator-provisioned
# gateway probe settings across every idempotent reinstall; only enforce its
# root-only permissions. Refuse symlinks/non-regular files before touching it.
ENV_PRESERVE=0
if [ -e "$ENV_FILE" ] || [ -L "$ENV_FILE" ]; then
  if [ -f "$ENV_FILE" ] && [ ! -L "$ENV_FILE" ]; then
    ENV_RECORD="$(stat_record "$ENV_FILE")" || ENV_RECORD=''
    IFS='|' read -r ENV_UID ENV_MODE ENV_NLINK ENV_SIZE <<< "$ENV_RECORD"
    if [ "$ENV_UID" = "$EUID" ] && [ "$ENV_MODE" = 600 ] && [ "$ENV_NLINK" = 1 ] &&
      [[ "$ENV_SIZE" =~ ^[0-9]+$ ]] && [ "$ENV_SIZE" -le 262144 ]; then ENV_PRESERVE=1; fi
  fi
  if [ "$ENV_PRESERVE" = 0 ]; then
    ENV_UNSAFE="$(unsafe_name "$ENV_FILE")"
    mv "$ENV_FILE" "$ENV_UNSAFE" || { echo "Could not quarantine unsafe updater environment path: $ENV_FILE" >&2; exit 1; }
    echo "WARN quarantined unsafe updater environment path at $ENV_UNSAFE" >&2
  fi
fi
ENV_TMP="$(mktemp "$ENV_DIR/.hiverelay-updater.env.XXXXXX")"
trap 'rm -f "$ENV_TMP"' EXIT HUP INT TERM
chmod 0600 "$ENV_TMP"
if [ "$ENV_PRESERVE" = 1 ]; then /bin/cat "$ENV_FILE" > "$ENV_TMP"; fi
mv -f "$ENV_TMP" "$ENV_FILE"
trap - EXIT HUP INT TERM

# This file is parsed as data by both launcher and updater. Persisting the
# absolute repo path lets a generic launcher support non-default installations
# without embedding mutable paths in /usr/local/bin.
CONF_TMP="$(mktemp "$CONF.tmp.XXXXXX")"
trap 'rm -f "$CONF_TMP"' EXIT HUP INT TERM
printf 'CHANNEL=%s\nRELAY_NAME=%s\nREPO_DIR=%s\n' "$CHANNEL" "$RELAY_NAME" "$REPO_DIR" > "$CONF_TMP"
chmod 0644 "$CONF_TMP"
mv -f "$CONF_TMP" "$CONF"
trap - EXIT HUP INT TERM

# Install only the small trust-checking launcher. The updater implementation
# stays in the signed checkout and therefore advances on the next timer tick
# after a successful signed release update. Install executable/unit artifacts
# only after all persistent input paths above have passed validation.
install -m 0755 "$SRC/updater-launcher.sh" "$BIN_DIR/hiverelay-updater"
install -m 0755 "$SRC/quarantine-public-gateway.sh" "$SBIN_DIR/hiverelay-quarantine-public-gateway"
install -m 0644 "$SRC/hiverelay-updater.service" "$SYSTEMD_DIR/hiverelay-updater.service"
install -m 0644 "$SRC/hiverelay-updater.timer"   "$SYSTEMD_DIR/hiverelay-updater.timer"

if [ -z "$DESTDIR" ]; then
  systemctl daemon-reload
  systemctl enable --now hiverelay-updater.timer
else
  echo "DESTDIR install: skipped systemctl and host hardening"
fi

# Supply-chain gate (audit HR-DIS-003): the updater refuses to check out a tag
# that is not signed by a trusted key. Warn loudly if the allowed-signers file
# is not yet provisioned — until it exists, updates correctly FAIL CLOSED.
# See docs/SUPPLY-CHAIN.md § "Signed release tags".
ALLOWED_SIGNERS="${HIVERELAY_ALLOWED_SIGNERS:-$DESTDIR/etc/hiverelay/allowed-signers}"
if [ ! -r "$ALLOWED_SIGNERS" ]; then
  echo "WARN allowed-signers file '$ALLOWED_SIGNERS' not found — signed-tag" >&2
  echo "     verification will FAIL CLOSED (no updates) until you install it." >&2
fi

# Also bound the log footprint so updates can't bloat the disk (idempotent,
# does not restart the relay). Safe no-op if already hardened.
if [ -z "$DESTDIR" ] && [ -f "$SRC/harden-box.sh" ]; then
  echo "Applying log-footprint hardening…"
  bash "$SRC/harden-box.sh" || echo "WARN harden-box.sh failed (non-fatal)"
fi

echo "Installed. Channel=$CHANNEL. Relay=$RELAY_NAME. Environment=$ENV_FILE"
if [ -z "$DESTDIR" ]; then
  echo "Timer:"
  systemctl status hiverelay-updater.timer --no-pager | sed -n '1,4p' || true
fi
echo
echo "Verify through the same systemd environment used by timer ticks:"
echo "  systemctl start hiverelay-updater.service"
