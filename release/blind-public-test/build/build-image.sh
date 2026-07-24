#!/usr/bin/env bash
# HiveRelay vNext public-test split image builds.
# Builds one multi-arch (linux/amd64+linux/arm64) OCI archive for one Blind
# component from the exact accepted source tree, with mode=max provenance and
# rewritten timestamps for reproducible platform manifests.
#
# Usage: build-image.sh <edge|daemon> <round> [--no-cache]
#   round 1|2  — output archive/log are suffixed with the round; round 2 is the
#                reproducibility check and MUST be run with --no-cache.
set -euo pipefail

COMPONENT="${1:?edge|daemon}"
ROUND="${2:?round number}"
NOCACHE="${3:-}"

RELEASE_VERSION="1.0.0-rc.1.public-test.1"
SOURCE_REVISION="ba710dc682a2cd0fa8a5bcc8a332e5a568eeb9ff"
SOURCE_TREE="edfe1e64754c84a9e852a8ef177b573e739f7136"
# git show -s --format=%ct ba710dc682a2cd0fa8a5bcc8a332e5a568eeb9ff
SOURCE_DATE_EPOCH="1784917371"
IMAGE_NAME="hiverelay/blind-${COMPONENT}"

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT_DIR="${ROOT}/release/blind-public-test/oci-archives"
LOG_DIR="${ROOT}/release/blind-public-test/build/logs"
mkdir -p "${OUT_DIR}" "${LOG_DIR}"

OUT="${OUT_DIR}/${IMAGE_NAME#hiverelay/}-${RELEASE_VERSION}-build${ROUND}.oci.tar"
LOG="${LOG_DIR}/${COMPONENT}-build${ROUND}.log"

cd "${ROOT}"
# Exact pinned inputs (duplicated in the Dockerfiles as ARG defaults):
#   toolchain  node:22-bookworm@sha256:5647be709086c696ff32edaaf1c70cd26d1da6ab2b39c32f3c7b4c4a31957e37
#   runtime    node:22-bookworm-slim@sha256:53ada149d435c38b14476cb57e4a7da73c15595aba79bd6971b547ceb6d018bf
docker buildx build \
  --file "Dockerfile.blind-${COMPONENT}" \
  --platform linux/amd64,linux/arm64 \
  --build-arg "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" \
  --build-arg "HIVERELAY_BLIND_BUNDLE_ID=${RELEASE_VERSION}" \
  --build-arg "HIVERELAY_BLIND_BUILD_ID=${RELEASE_VERSION}" \
  --build-arg "HIVERELAY_BLIND_SOURCE_REVISION=${SOURCE_REVISION}" \
  --build-arg "HIVERELAY_BLIND_SOURCE_TREE=${SOURCE_TREE}" \
  --provenance mode=max \
  --tag "${IMAGE_NAME}:${RELEASE_VERSION}" \
  ${NOCACHE} \
  --output "type=oci,rewrite-timestamp=true,dest=${OUT}" \
  --progress=plain \
  . 2>&1 | tee "${LOG}"

echo "wrote ${OUT}"
