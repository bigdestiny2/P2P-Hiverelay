# Hiverelay Release Image Manifest Evidence - 2026-06-24

## Scope

This Level 1/2 release-evidence slice focuses only on the release image-manifest
proof family. It does not claim Docker boot, Umbrel package smoke, StartOS
package verification, fleet rollout, or real Umbrel runtime review.

## Result

The exact `0.20.0` release image reference verified in this loop is:

```text
ghcr.io/bigdestiny2/p2p-hiverelay:0.20.0@sha256:0b8857cda2d0e399031a135a0c5f9c8a2ec6fa77cf64ed1c59aba58351c9eae1
```

The registry returned an OCI image index with required Linux `amd64` and Linux
`arm64` platform manifests. GHCR also returned two OCI attestation sidecar
manifests with `unknown/unknown` platform labels; those are not runnable
platform images and must not be treated as duplicate platform rows.

## Code Change

`scripts/check-release-image-manifest.mjs` now skips manifest entries annotated
with:

```text
vnd.docker.reference.type=attestation-manifest
```

before duplicate-platform checks. It still requires `linux/amd64` and
`linux/arm64`, still rejects malformed platform digests, and still rejects
duplicate runnable platform labels.

`test/unit/release-image-manifest-check.test.js` now includes the GHCR-shaped
case: two runnable platform manifests plus two attestation sidecars.

## Validation

Focused unit slice:

```sh
./node_modules/.bin/brittle test/unit/release-image-manifest-check.test.js
```

Result: pass, 5/5 tests and 21/21 assertions.

Live GHCR evidence command:

```sh
npm run release:check-image-manifest -- \
  --image ghcr.io/bigdestiny2/p2p-hiverelay:0.20.0@sha256:0b8857cda2d0e399031a135a0c5f9c8a2ec6fa77cf64ed1c59aba58351c9eae1 \
  --out /private/tmp/hiverelay-0.20.0-manifest-evidence.json
```

Result: pass; evidence written to
`/private/tmp/hiverelay-0.20.0-manifest-evidence.json`.

The evidence file reports:

- `status: "verified"`
- `image.tag: "0.20.0"`
- `image.digest: "sha256:0b8857cda2d0e399031a135a0c5f9c8a2ec6fa77cf64ed1c59aba58351c9eae1"`
- required platforms: `linux/amd64`, `linux/arm64`
- platform digests:
  - `linux/amd64`: `sha256:a40599ee0e8e97fa8f4c23c50a8b2fe267bf1fb430d41327199737dd4399d104`
  - `linux/arm64`: `sha256:7f9c5c62b8a9dc427b9e0735e6153bd8ca065bf30b95bcb0d5233babfbafab40`
- `manifestCount: 4`, because the OCI index includes two platform manifests
  plus two attestation manifests.

## Residual Risk

- This proof checks registry manifest shape and platform coverage. It does not
  boot the Docker image.
- `release-image-manifest-evidence.json` in `/private/tmp` is a local proof
  artifact, not a release asset.
- Full release readiness still needs image smoke, Umbrel package smoke, StartOS
  package/registry evidence, fleet rollout, and real Umbrel runtime review.
