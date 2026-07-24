#!/usr/bin/env bash
# Rollback for the HiveRelay Blind public-test sidecar (1.0.0-rc.1.public-test.1).
# Stops/removes ONLY the sidecar Edge listener + daemon + volume-init containers
# of the public-test compose project. Retains all volumes (roots), images and
# the rest of the fleet. Idempotent. See README.md in this directory.
set -euo pipefail

PROJECT="hiverelay-blind-public-test"
REMOVE_IMAGES=0
T1_PATH=""
EDGE_IMAGE="hiverelay/blind-edge@sha256:7b0ae890bf806bb0382529aeac4d20618333922b847809f730a8e0fafe48fb2b"
DAEMON_IMAGE="hiverelay/blind-daemon@sha256:d9c343d9846dc3d76dff4033499276f7f526f9a0a7e338dc24e778b1da96e716"
T1_SHA256="bfcc12664be108cdb13b1ca83f088a87fdcb03efa598377aca1c1d34a0f36064"

while [ $# -gt 0 ]; do
  case "$1" in
    --project-name) PROJECT="$2"; shift 2 ;;
    --remove-images) REMOVE_IMAGES=1; shift ;;
    --verify-t1) T1_PATH="$2"; shift 2 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
COMPOSE_FILE="${ROOT}/docker-compose.blind-public-test.yml"
[ -f "${COMPOSE_FILE}" ] || { echo "missing ${COMPOSE_FILE}" >&2; exit 1; }

compose() { docker compose -p "${PROJECT}" -f "${COMPOSE_FILE}" "$@"; }

echo "== rollback: stopping sidecar listener + containers (project ${PROJECT})"
# Edge first: closes the public TCP 443 listener before anything else moves.
compose stop blind-edge blind-daemon blind-volume-init

echo "== rollback: removing the three sidecar containers (volumes retained)"
compose rm -f blind-edge blind-daemon blind-volume-init

echo "== rollback: verifying retained roots"
for vol in "${PROJECT}_blind-runtime" "${PROJECT}_blind-data"; do
  if docker volume inspect "${vol}" >/dev/null 2>&1; then
    echo "  retained volume: ${vol}"
  else
    echo "  note: volume ${vol} not present (never created or already removed)"
  fi
done

echo "== rollback: remaining containers for project ${PROJECT} (expect none)"
remaining="$(docker ps -a --filter "label=com.docker.compose.project=${PROJECT}" --format '{{.Names}}')"
if [ -n "${remaining}" ]; then
  echo "  ERROR: containers remain: ${remaining}" >&2
  exit 1
fi
echo "  none"

if [ "${REMOVE_IMAGES}" = "1" ]; then
  echo "== rollback: removing digest-pinned test images (optional)"
  docker image rm "${EDGE_IMAGE}" "${DAEMON_IMAGE}" || true
fi

if [ -n "${T1_PATH}" ]; then
  echo "== rollback: verifying T1 remains byte-identical and disabled"
  actual="$(shasum -a 256 "${T1_PATH}" | awk '{print $1}')"
  [ "${actual}" = "${T1_SHA256}" ] || { echo "  ERROR: T1 hash changed: ${actual}" >&2; exit 1; }
  grep -q '"enabled": false' "${T1_PATH}" || { echo "  ERROR: T1 enabled flag is not false" >&2; exit 1; }
  echo "  T1 unchanged and disabled"
fi

echo "== rollback complete: sidecar stopped, roots retained, fleet untouched"
