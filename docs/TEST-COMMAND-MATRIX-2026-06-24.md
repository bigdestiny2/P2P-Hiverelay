# Hiverelay Test Command Matrix - 2026-06-24

## Scope

Current Level 1 command matrix for the Hiverelay / Blindspark monorepo.

Source root:

`/Users/localllm/Projects/pear-ecosystem/00-core/hiverelay`

This matrix updates the 2026-06-23 matrix with the current release-proof state
and the focused validation executed for the 2026-06-24 status audit.

## Local Command Results

| Command | Result | Notes |
| --- | --- | --- |
| `git status --short \| wc -l` | Informational | Returned `305`; the repo has a broad pre-existing dirty worktree. |
| `npm run audit:workspace` | Pass with warning | Workspace alignment passed. Warning: official Umbrel package still needs its real `getumbrel/umbrel-apps` PR URL. |
| `node --check scripts/audit-workspace-alignment.mjs` | Pass | Audit script parses cleanly. |
| `node --check scripts/check-release-image-manifest.mjs` | Pass | Image-manifest checker parses cleanly. |
| `node --check scripts/smoke-release-image.mjs` | Pass | Release image smoke script parses cleanly. |
| `./node_modules/.bin/brittle --timeout 120000 test/unit/api-seed-publish.test.js test/unit/api-catalog-read.test.js test/unit/release-evidence-verify.test.js` | Pass | `60/60` tests and `268/268` assertions. Covers seed publish validation, catalog read shaping, and release evidence verification. |
| `./node_modules/.bin/brittle --timeout 120000 test/unit/fleet-rollout-check.test.js test/unit/release-evidence-verify.test.js test/unit/release-handoff-evidence-verify.test.js` | Pass | `143/143` tests and `636/636` assertions. Covers loopback-only fleet rollout probe API evidence at writer, release verifier, and final handoff verifier boundaries. |
| `./node_modules/.bin/brittle --timeout 120000 test/unit/official-umbrel-pr-evidence.test.js test/unit/startos-registry-evidence.test.js test/unit/umbrel-runtime-review-verify.test.js test/unit/release-handoff-evidence-verify.test.js` | Pass | `120/120` tests and `543/543` assertions. Covers official Umbrel, StartOS registry, runtime-review, and final handoff sidecar verification, including StartOS linked image-sidecar kind checks. |

## Primary Root Scripts

| Command | Scope | Use When | Current Caveat |
| --- | --- | --- | --- |
| `npm run audit:workspace` | Workspace/readme/release-surface alignment | After docs, package, dashboard, API, release-surface changes | Currently passes with Umbrel PR URL warning. |
| `npm run lint` | StandardJS over source | After source edits | Pass in the final review loop. |
| `npm run test:unit` | All unit tests | Broad local regression | Pass in the final review loop; exit `0`, final visible TAP `ok 2183`. |
| `./node_modules/.bin/brittle test/integration/**/*.test.js` | Integration/network/P2P tests | Federation, DHT, gateway, custody, restart paths | Pass outside sandbox for UDX/network sockets; exit `0`, final visible TAP `ok 82`. |
| `npm test` | Full Brittle test sweep | Final broad local smoke | Not a substitute for external release proofs. |
| `npm run release:check-image-manifest` | GHCR digest platform proof | After a public digest exists | Published `0.20.0` digest has manifest proof. A new fixed digest is still needed. |
| `npm run release:smoke-image` | Docker image runtime proof | Against exact image ref/digest | Published `0.20.0` digest is smoke-red; freshly rebuilt `p2p-hiverelay:local-current-20260624` is green. |
| `npm run release:check-distribution-env -- --channel both --prerelease false` | Stable release credential preflight | Before a full release train or official workflow dispatch | Red in this local session: fleet, Umbrel, official PR, StartOS key, and registry secrets are absent. |
| `docker buildx imagetools inspect ghcr.io/bigdestiny2/p2p-hiverelay:0.20.0` | Read-only GHCR registry probe | Before relying on local registry access | Stalled in this session and was killed after about 90 seconds. Retry from the release environment. |
| `npm run umbrel:smoke-package` | Umbrel package Docker smoke | Before Umbrel handoff | Published digest is red on stale dashboard busy-state guards; `npm run umbrel:smoke-package -- --image-ref p2p-hiverelay:local-current-20260624 --timeout-ms 120000` passes against the current source image. |
| `npm run release:verify-review-ready-handoff` | Final Umbrel handoff verifier | After real runtime-review evidence exists | Requires real Umbrel device sidecar. |
| `npm run fleet:check-rollout` | Live fleet convergence | Stable/canary rollout proof | Requires live relay access and selected channel; probe API bases must be loopback because checks run on each relay over SSH. |
| `HIVERELAY_IMAGE_DIGEST=sha256:<digest> npm run startos:verify` | StartOS package verification | StartOS release packaging | Requires a fresh public multi-arch digest; release packaging now fails without one. |
| `npm run startos:verify:local` | StartOS package mechanics check | Local-only packaging smoke | Explicitly allows the tag-only image path with `ALLOW_TAG_ONLY_IMAGE=1`; not release evidence. |

## Focused Slices

### Seed, Catalog, And Release Evidence Boundary

```sh
./node_modules/.bin/brittle --timeout 120000 \
  test/unit/api-seed-publish.test.js \
  test/unit/api-catalog-read.test.js \
  test/unit/release-evidence-verify.test.js
```

Current result: pass, `60/60` tests and `268/268` assertions.

Use this when touching:

- `packages/core/core/relay-node/api-seed-publish.js`
- `packages/core/core/relay-node/api-catalog-read.js`
- release evidence verifier paths
- catalog publication or Hiverelay Spec seeding contracts

### Release Image Proof Boundary

```sh
./node_modules/.bin/brittle --timeout 120000 \
  test/unit/release-image-manifest-check.test.js \
  test/unit/release-smoke-evidence-writer.test.js \
  test/unit/ws-feed-payload.test.js
```

Use this before rerunning a public GHCR digest proof. It proves local parser and
smoke-writer behavior, not the external image itself.

### Umbrel Review Boundary

```sh
./node_modules/.bin/brittle --timeout 120000 \
  test/unit/umbrel-gallery-check.test.js \
  test/unit/umbrel-runtime-review-evidence.test.js \
  test/unit/umbrel-runtime-review-verify.test.js \
  test/unit/official-umbrel-export.test.js \
  test/unit/official-umbrel-pr-evidence.test.js \
  test/unit/umbrel-ui-controls.test.js
```

Use before writing or verifying real Umbrel review evidence. It does not create
the real device review proof.

### Store Handoff Evidence Boundary

```sh
./node_modules/.bin/brittle --timeout 120000 \
  test/unit/official-umbrel-pr-evidence.test.js \
  test/unit/startos-registry-evidence.test.js \
  test/unit/umbrel-runtime-review-verify.test.js \
  test/unit/release-handoff-evidence-verify.test.js
```

Current result: pass, `120/120` tests and `543/543` assertions.

Use before touching official Umbrel PR handoff, StartOS registry evidence,
runtime-review evidence, or final store handoff verification. This compact
local slice now proves that StartOS registry evidence rejects linked release
image sidecars whose JSON `kind` does not match the expected image-manifest or
image-smoke sidecar identity.

### Fleet, StartOS, And Release Evidence Proof Boundary

```sh
./node_modules/.bin/brittle --timeout 120000 \
  test/unit/fleet-rollout-check.test.js \
  test/unit/release-evidence-verify.test.js \
  test/unit/release-handoff-evidence-verify.test.js \
  test/unit/fleet-shell-safety.test.js \
  test/unit/startos-registry-evidence.test.js \
  test/unit/release-distribution-env.test.js
```

Use before touching live rollout, StartOS registry publication, or distribution
preflight logic. The first three tests are the compact local release/fleet
evidence verifier slice; current result for that compact slice is pass with
`143/143` tests and `636/636` assertions, including rejection of non-loopback
fleet rollout `probes.api` values. It does not contact live relays or
registries by itself.

## External Gates

These cannot be proven by local tests alone:

- New digest-pinned GHCR image built from the fixed source.
- Public `release-image-smoke-evidence.json` for that digest.
- Official Umbrel PR URL/state/head and real-device runtime review sidecar.
- StartOS registry publication evidence.
- Live raw fleet rollout evidence.

## Recommended Next Validation Path

For the next Hiverelay proof loop, prefer this order:

1. Run the relevant focused unit slice.
2. Run `npm run audit:workspace`.
3. Only then run the external evidence command if its environment exists.
4. Record the sidecar or a source-backed gap note.
5. Recompile the brain and rescore the ecosystem queue.

When external credentials or registry access are absent, stay in local-only
mode:

1. Pick a release-evidence verifier/writer slice, a small RelayNode/API helper
   extraction, or a command-matrix refresh.
2. Prove the slice with targeted unit tests and `npm run audit:workspace`.
3. Do not promote local test results into public release claims.
4. Record the remaining external gate explicitly and rescore.
