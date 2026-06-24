# Hiverelay Release Image Smoke - 2026-06-24

## Scope

This Level 1/2 slice attempted the exact digest-pinned Docker image smoke for
the published `0.20.0` image:

```text
ghcr.io/bigdestiny2/p2p-hiverelay:0.20.0@sha256:0b8857cda2d0e399031a135a0c5f9c8a2ec6fa77cf64ed1c59aba58351c9eae1
```

The smoke command was:

```sh
npm run release:smoke-image -- \
  ghcr.io/bigdestiny2/p2p-hiverelay:0.20.0@sha256:0b8857cda2d0e399031a135a0c5f9c8a2ec6fa77cf64ed1c59aba58351c9eae1 \
  --evidence /private/tmp/hiverelay-0.20.0-image-smoke-evidence.json \
  --timeout-ms 180000
```

## Result

The image starts and reaches the dashboard smoke path, but the full smoke is
red. The current published image rejects the normal in-band dashboard WebSocket
with:

```text
dashboard WebSocket open failed: Unexpected server response: 403
```

No `/private/tmp/hiverelay-0.20.0-image-smoke-evidence.json` file was written,
because the smoke script only writes public evidence after all checks pass.

## Root Cause

The release image uses the default restricted `corsOrigins: []` API setting.
Browser dashboard WebSockets send an `Origin` header, but the old WebSocket
feed rejected every origin unless `corsOrigins` was `*` or explicitly listed.
That means a same-origin browser dashboard socket could be rejected even though
the dashboard itself loaded and carried a valid in-band management token.

## Source Fix

The source tree now fixes the dashboard WebSocket CORS rule:

- `packages/core/core/relay-node/ws-feed.js` allows same-origin dashboard
  WebSockets by comparing the request `Origin` host with the request `Host`
  while still rejecting cross-origin sockets unless explicitly allowlisted.
- `scripts/smoke-release-image.mjs` and `scripts/smoke-umbrel-package.mjs` now
  send a browser-like same-origin `Origin` header for dashboard WebSocket
  checks.
- Both smoke scripts accept any HTTP 4xx response as a valid query-token
  rejection, then separately prove normal in-band authentication works.

## Validation

Focused local validation after the source fix:

```sh
./node_modules/.bin/brittle --timeout 120000 \
  test/unit/ws-feed-payload.test.js \
  test/unit/release-smoke-evidence-writer.test.js
```

Result: pass, 17/17 tests and 121/121 assertions.

Also passed:

```sh
node --check packages/core/core/relay-node/ws-feed.js
node --check scripts/smoke-release-image.mjs
node --check scripts/smoke-umbrel-package.mjs
```

## Rebuilt Local Image Smoke

A follow-up Level 1/2 loop rebuilt the Docker image from the fixed local source
tree and reran the image smoke against that local artifact:

```sh
docker build -t p2p-hiverelay:local-smoke-20260624 .
```

Local image metadata after the build:

```text
image id: sha256:10f0966b853a4d6d46748d9833bf12f1cfcdefec091cd4646ca84243da96e4f7
platform: linux/arm64
size bytes: 274620496
```

The smoke command was:

```sh
npm run release:smoke-image -- \
  p2p-hiverelay:local-smoke-20260624 \
  --timeout-ms 180000
```

Result:

```text
release image smoke passed: p2p-hiverelay:local-smoke-20260624
```

This proves the same-origin dashboard WebSocket fix works inside a rebuilt
container. It is not public release evidence because the local image tag is not
a digest-pinned GHCR reference, and the smoke script only writes public evidence
for `ghcr.io/...:<semver>@sha256:<digest>` refs.

## Residual Risk

- The published `0.20.0` image remains smoke-red; it predates the same-origin
  dashboard WebSocket fix. The rebuilt local image is green.
- `docs/RELEASE_IMAGE_PUBLICATION_GATE_2026-06-24.md` records the next
  publication boundary: Docker is locally available, the fixed local image is
  present, full stable release secrets are missing in this session, and GHCR
  read-only manifest inspection stalled.
- A new public GHCR image digest must be built and pushed from the fixed source,
  then
  `npm run release:check-image-manifest` and `npm run release:smoke-image` must
  be rerun against that new digest.
- This loop did not run Umbrel package smoke, StartOS package verification,
  fleet rollout, or real Umbrel runtime review.
