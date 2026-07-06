#!/usr/bin/env bash
#
# verify-image-signature.sh — fail-closed cosign verification hook for the
# published HiveRelay container image (audit HR-DIS-001).
#
# Verifies that <image-ref> carries a valid cosign keyless (OIDC) signature
# produced by THIS repository's publish workflow. Exits 0 only on a good
# signature from the expected identity + issuer; non-zero otherwise.
#
# Usage:
#   scripts/verify-image-signature.sh ghcr.io/bigdestiny2/p2p-hiverelay@sha256:<digest>
#   scripts/verify-image-signature.sh ghcr.io/bigdestiny2/p2p-hiverelay:0.24.0@sha256:<digest>
#
# Env overrides (defaults match this repo):
#   COSIGN_IDENTITY_REGEXP  allowed --certificate-identity-regexp
#   COSIGN_OIDC_ISSUER      allowed --certificate-oidc-issuer
set -euo pipefail

IMAGE_REF="${1:-}"
if [ -z "$IMAGE_REF" ]; then
  echo "usage: $0 <image-ref>@sha256:<digest>" >&2
  exit 2
fi

# Signing by digest binds the signature to exact bytes; a tag-only ref is not
# verifiable in a meaningful way. Require the digest to be present.
if ! printf '%s' "$IMAGE_REF" | grep -Eq '@sha256:[a-f0-9]{64}$'; then
  echo "verify-image-signature: '$IMAGE_REF' is not digest-pinned (need @sha256:<64 hex>)" >&2
  exit 2
fi

if ! command -v cosign >/dev/null 2>&1; then
  echo "verify-image-signature: cosign not installed — cannot verify (fail closed)" >&2
  echo "  install: https://docs.sigstore.dev/system_config/installation/" >&2
  exit 3
fi

IDENTITY_REGEXP="${COSIGN_IDENTITY_REGEXP:-https://github.com/bigdestiny2/P2P-Hiverelay/\.github/workflows/.+@refs/(heads|tags)/.+}"
OIDC_ISSUER="${COSIGN_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

echo "verify-image-signature: verifying $IMAGE_REF"
if cosign verify \
    --certificate-identity-regexp "$IDENTITY_REGEXP" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    "$IMAGE_REF" >/dev/null; then
  echo "verify-image-signature: OK — signature valid (identity=$IDENTITY_REGEXP)"
  exit 0
fi

echo "verify-image-signature: FAILED — no valid signature from the expected identity/issuer" >&2
exit 1
