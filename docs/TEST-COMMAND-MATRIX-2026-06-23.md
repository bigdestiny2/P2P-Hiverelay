# Hiverelay Test Command Matrix

Generated: 2026-06-23
Loop candidate: `hiverelay-test-matrix`
Autonomy level: Level 1 test/documentation artifact
Source root: `/Users/localllm/Projects/pear-ecosystem/00-core/hiverelay`

## Executive Status

Hiverelay has a broad test and release-proof surface. Future agent loops should
avoid treating `npm test` as the only signal: the repo has fast unit slices,
targeted boundary slices, release-evidence verifiers, Umbrel package checks,
fleet rollout checks, Docker/GHCR image checks, StartOS packaging, and true
external review gates.

The current best local pattern is:

1. Use focused `./node_modules/.bin/brittle ...` slices while changing a
   boundary.
2. Run `npm run lint` and `npm run audit:workspace` for broad local hygiene.
3. Use release/Umbrel/fleet verifier commands only when their required sidecar
   evidence files already exist.
4. Keep Docker, GHCR, StartOS, raw-fleet SSH, real Umbrel device review, and
   upstream store review as environment-dependent gates.

The Hiverelay worktree already contains many unrelated modified and untracked
files. This note is intentionally additive and does not try to normalize or
claim ownership of those changes.

## Root Scripts

Run from `/Users/localllm/Projects/pear-ecosystem/00-core/hiverelay`.

| Command | Scope | When to use | Known exclusions |
|---|---|---|---|
| `npm run lint` | StandardJS over the workspace | Always after source edits | Does not prove runtime, network, image, or release evidence |
| `npm run audit:workspace` | Workspace/release-surface alignment audit | After docs/package/release-surface edits | Depends on current repo metadata; not a network proof |
| `npm run test:unit` | All unit tests under `test/unit/**/*.test.js` with 120s timeout | Broad local regression sweep | Can be large; use focused slices while iterating |
| `npm run test:integration` | Integration tests under `test/integration/**/*.test.js` | P2P/network/federation behavior changes | May require socket permissions and can be slower/flakier than unit slices |
| `npm test` | All `test/**/*.test.js` through Brittle | Final broad local smoke when time permits | Broad, may include integration/network-heavy tests |
| `npm run test:bare` | Bare runtime test entrypoint | Bare/Pear runtime compatibility checks | Requires `brittle-bare`/Bare runtime availability |
| `npm run release:prepare` | Sync release surfaces for a version/channel | Release prep only | Mutates release metadata; do not run casually in audit loops |
| `npm run release:check-distribution-env` | Stable-release credential/env preflight | Before distribution release workflows | Full releases require external credentials/secrets |
| `npm run release:write-evidence` | Write release evidence sidecar | Release workflow/evidence capture | Requires real proof inputs; do not fabricate |
| `npm run release:verify-evidence` | Verify `release-evidence.json` and linked sidecars | After evidence exists or in bundle verification | Fails until required sidecars/artifacts exist |
| `npm run release:verify-handoff-evidence` | Verify reviewer handoff bundle/sidecars; add `--require-umbrel-runtime-review` for final review-ready Umbrel handoff | After official handoff assets exist | Requires release/handoff evidence bundle; strict Umbrel mode also requires real runtime review evidence |
| `npm run release:verify-review-ready-handoff` | Verify final Umbrel reviewer handoff with real runtime-review evidence required | After real Umbrel runtime-review evidence exists | Requires release/handoff evidence bundle plus `umbrel-runtime-review-evidence.json` |
| `npm run release:check-image-manifest` | Verify pinned GHCR digest is multi-arch image index | After GHCR digest exists | Requires exact image reference/digest and registry access |
| `npm run release:smoke-image` | Smoke the published Docker image | Docker image proof | Requires Docker and the exact image reference |
| `npm run fleet:check-rollout` | Verify live relay fleet convergence | Release/fleet promotion proof | Requires raw fleet access, SSH/env, and live relays |
| `npm run umbrel:check-gallery` | Validate Umbrel gallery asset shape | Umbrel package docs/assets | Does not prove real Umbrel install/runtime |
| `npm run umbrel:export-official` | Export official Umbrel package shape | Preparing upstream Umbrel PR | Mutates target checkout; needs correct target repo |
| `npm run umbrel:write-runtime-review` | Write public-safe manual Umbrel runtime evidence | After real Umbrel UI review | Requires real device/reviewer facts; rejects local/secrets |
| `npm run umbrel:verify-runtime-review` | Verify runtime-review evidence sidecar | After review sidecar exists | Does not create the real review proof |
| `npm run umbrel:smoke-package` | Docker smoke of Umbrel app package | Package-level Umbrel contract | Requires Docker; not a real Umbrel device review |
| `HIVERELAY_IMAGE_DIGEST=sha256:<digest> npm run startos:verify` | `cd startos && make verify IMAGE_DIGEST="$HIVERELAY_IMAGE_DIGEST"` | StartOS release package verification | Requires Docker, `start-sdk`, image tarballs/package artifacts, and a public multi-arch digest |
| `npm run startos:verify:local` | `cd startos && make verify ALLOW_TAG_ONLY_IMAGE=1` | Local StartOS package mechanics check | Explicitly allows tag-only image use; not release evidence |

## High-Value Focused Brittle Slices

Use these direct commands instead of full-suite runs while iterating. Add or
remove files based on the touched boundary.

### API and HTTP Boundary

```sh
./node_modules/.bin/brittle --timeout 120000 \
  test/unit/api-auth.test.js \
  test/unit/api-ui-token.test.js \
  test/unit/api-trustproxy-auth.test.js \
  test/unit/api-body.test.js \
  test/unit/api-validation.test.js \
  test/unit/capability-endpoints.test.js \
  test/unit/gateway-server.test.js
```

Covers management API auth, UI token handling, `trustProxy` behavior, bounded
JSON body reads, query/config validation, capability endpoints, and gateway
HTTP surfaces. It does not prove live reverse-proxy deployment, Umbrel app-proxy,
or external browser/device behavior.

### Security, Quorum, Fork, and Policy Boundary

```sh
./node_modules/.bin/brittle --timeout 120000 \
  test/unit/capability-endpoints.test.js \
  test/unit/api-auth.test.js \
  test/unit/api-ui-token.test.js \
  test/unit/api-trustproxy-auth.test.js \
  test/unit/protocol-security.test.js \
  test/unit/swarm-firewall.test.js \
  test/unit/policy-guard.test.js \
  test/unit/verifier.test.js \
  test/unit/quorum-selector.test.js \
  test/unit/client-quorum-fork-integration.test.js \
  test/unit/fork-detector.test.js
```

This is the current security-boundary slice used by the 2026-06-23 security
alignment note. It covers auth, service protocol restrictions, swarm firewall,
relay exposure policy, verifier behavior, quorum diversity, client fork
evidence, and fork detection.

### Release Evidence Verifiers

```sh
./node_modules/.bin/brittle --timeout 120000 \
  test/unit/release-evidence.test.js \
  test/unit/release-evidence-verify.test.js \
  test/unit/release-handoff-evidence-verify.test.js \
  test/unit/release-image-manifest-check.test.js \
  test/unit/release-smoke-evidence-writer.test.js
```

Covers sidecar schema, hash agreement, release/handoff evidence verification,
post-release handoff sidecar timestamp ordering, image manifest proof parsing,
OCI attestation-sidecar handling, and smoke-evidence writing. It does not prove
the actual GHCR image, Docker boot, StartOS upload, Umbrel PR, or fleet rollout.

### Umbrel Package and Runtime Evidence

```sh
./node_modules/.bin/brittle --timeout 120000 \
  test/unit/umbrel-gallery-check.test.js \
  test/unit/umbrel-runtime-review-evidence.test.js \
  test/unit/umbrel-runtime-review-verify.test.js \
  test/unit/official-umbrel-export.test.js \
  test/unit/official-umbrel-pr-evidence.test.js \
  test/unit/umbrel-ui-controls.test.js
```

Covers gallery safety, public-safe runtime review evidence writing/verification,
official package export, PR evidence shape, optional runtime-review handoff
time-ordering, and dashboard UI control behavior. It does not replace real
Umbrel install/start/dashboard/setup/reinstall review.

### Fleet, StartOS, and Distribution Metadata

```sh
./node_modules/.bin/brittle --timeout 120000 \
  test/unit/fleet-rollout-check.test.js \
  test/unit/fleet-shell-safety.test.js \
  test/unit/startos-registry-evidence.test.js \
  test/unit/release-distribution-env.test.js \
  test/unit/release-image-manifest-check.test.js
```

Covers local parsers and validators for fleet rollout sidecars, fleet shell
safety, StartOS registry evidence, distribution env preflight, and image-manifest
proof. It does not contact the real fleet, registry, or GHCR unless the
corresponding script is run with real configuration.

### Protocol Encoding and P2P Plumbing

```sh
./node_modules/.bin/brittle --timeout 120000 \
  test/unit/protocol-json-encoding.test.js \
  test/unit/seed-protocol-encoding.test.js \
  test/unit/forward-relay-encoding.test.js \
  test/unit/circuit-relay-encoding.test.js \
  test/unit/circuit-relay-bridge.test.js \
  test/unit/anchor-channel.test.js \
  test/unit/custody-channel.test.js \
  test/unit/publish-channel.test.js
```

Covers bounded encoding/decoding and channel-level protocol behavior. It does
not prove live DHT, cross-relay, or browser/WebSocket operation.

## Integration And Environment-Heavy Gates

| Command | Use for | Requirements / cautions |
|---|---|---|
| `npm run test:integration` | Client, federation, gateway, DHT relay WebSocket, blind custody, pairing, restart persistence, reliability | Needs socket permissions; may be slower than unit slices |
| `npm run test:bare` | Bare runtime entrypoint compatibility | Needs Bare/brittle-bare runtime available |
| `npm run release:check-image-manifest -- --image <ref>@sha256:<digest> --out release-image-manifest-evidence.json` | Prove pushed GHCR image digest is multi-arch; OCI attestation sidecars are tolerated but not counted as runnable platforms | Needs network/registry access and exact digest |
| `npm run release:smoke-image -- <ref>@sha256:<digest> --evidence release-image-smoke-evidence.json` | Smoke exact Docker image | Needs Docker and image pull access; current published `0.20.0` image is red on dashboard WebSocket HTTP 403, while a rebuilt local image from the fixed source passes. Public evidence still needs a new GHCR digest |
| `npm run umbrel:smoke-package` | Smoke in-repo Umbrel package with Docker | Needs Docker; still not a real Umbrel device UI review |
| `npm run umbrel:write-runtime-review ...` | Capture manual real Umbrel lifecycle evidence | Needs real Umbrel install/review facts; must not include secrets/local URLs |
| `npm run fleet:check-rollout` | Prove raw fleet convergence | Needs configured live fleet access and selected channel facts |
| `HIVERELAY_IMAGE_DIGEST=sha256:<digest> npm run startos:verify` | Verify release StartOS `.s9pk` package | Needs Docker, `start-sdk`, package image artifacts, and a public multi-arch digest |
| `npm run startos:verify:local` | Verify local StartOS mechanics only | Explicitly tag-only; not release evidence |

For final Umbrel App Store reviewer handoff, run
`npm run release:verify-review-ready-handoff -- --bundle-dir <dir>` after
`umbrel-runtime-review-evidence.json` has been produced from a real Umbrel
device review. The automated release workflow intentionally stops at draft PR
plus pending-review evidence.

## Known Exclusions

- A green local unit slice does not prove official Umbrel marketplace review,
  StartOS registry publication, live raw fleet convergence, or GHCR image
  availability.
- Release sidecar verifiers only prove evidence that exists; they do not create
  the external facts.
- Docker image and Umbrel package smoke checks are not real Umbrel device review.
- `startos:verify` depends on local StartOS packaging tooling and image
  artifacts.
- `release:prepare` and export/write commands can mutate release surfaces or
  evidence files; use them only in explicit release/evidence loops.
- The repo currently has many modified and untracked files. Treat unrelated
  worktree state as pre-existing unless the active loop explicitly owns it.

## Validation In This Loop

Recent local validation:

```sh
./node_modules/.bin/brittle --timeout 120000 \
  test/unit/api-validation.test.js \
  test/unit/api-body.test.js \
  test/unit/release-evidence-verify.test.js
```

and `git diff --check`.

The 2026-06-24 release-image smoke loops also ran:

```sh
./node_modules/.bin/brittle --timeout 120000 \
  test/unit/ws-feed-payload.test.js \
  test/unit/release-smoke-evidence-writer.test.js

docker build -t p2p-hiverelay:local-smoke-20260624 .

npm run release:smoke-image -- \
  p2p-hiverelay:local-smoke-20260624 \
  --timeout-ms 180000
```

Result: focused WebSocket/smoke tests passed, local Docker build passed, and
the rebuilt local image smoke passed. Digest-pinned GHCR evidence remains
pending until a fixed public image is pushed.

## Recommended Next Level 1/2 Step

Run a Hiverelay release-evidence cleanup loop:

- Choose one evidence family: release sidecars, Umbrel runtime review,
  StartOS registry, or live fleet rollout.
- Run the corresponding focused unit slice first.
- Then run the real evidence writer/checker only if the required environment
  exists.
- Promote the resulting evidence file or a source-backed gap note, refresh the
  brain, and score again.

## Source Evidence

- `/Users/localllm/Projects/pear-ecosystem/00-core/hiverelay/package.json`
- `/Users/localllm/Projects/pear-ecosystem/00-core/hiverelay/packages/core/package.json`
- `/Users/localllm/Projects/pear-ecosystem/00-core/hiverelay/packages/client/package.json`
- `/Users/localllm/Projects/pear-ecosystem/00-core/hiverelay/packages/verifier/package.json`
- `/Users/localllm/Projects/pear-ecosystem/00-core/hiverelay/startos/Makefile`
- `/Users/localllm/Projects/pear-ecosystem/00-core/hiverelay/docs/CURRENT_STATUS_AUDIT_2026-06-23.md`
- `/Users/localllm/Projects/pear-ecosystem/00-core/hiverelay/docs/SECURITY-BOUNDARY-ALIGNMENT-2026-06-23.md`
- `/Users/localllm/Projects/pear-ecosystem/00-core/hiverelay/docs/AUDIT-ROADMAP.md`
- `/Users/localllm/Projects/pear-ecosystem/00-core/hiverelay/docs/RELEASE_AUTOMATION.md`
