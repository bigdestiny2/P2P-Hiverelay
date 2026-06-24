# Hiverelay Current Status Audit - 2026-06-24

## Scope

Level 1 source-backed status audit for the Hiverelay / Blindspark monorepo.

Captured at: `2026-06-24T18:21:52+0400`

Source root:

`/Users/localllm/Projects/pear-ecosystem/00-core/hiverelay`

This note is a current decision surface for agent loops. It does not replace the
longer historical audit trail in `docs/CURRENT_STATUS_AUDIT_2026-06-23.md` or
`docs/AUDIT-ROADMAP.md`; it summarizes the present release and proof boundary.

## Bottom Line

Hiverelay is in late hardening and external-proof collection, not early product
architecture. The source tree is aligned around `v0.20.0`, has broad API,
protocol, release-evidence, Umbrel, fleet, and StartOS automation, and passes
the workspace alignment audit, lint, dependency audit, full unit suite, full
integration suite, and real Bare runtime smoke locally in this loop.

The main remaining gaps are not ordinary code TODOs:

- A fixed public GHCR digest is still needed because the published `0.20.0`
  image smoke is red on dashboard WebSocket in-band auth.
- Official Umbrel App Store proof still needs a real upstream
  `getumbrel/umbrel-apps` PR URL/state/head and real-device runtime-review
  evidence.
- StartOS registry/marketplace proof still needs real registry publication
  evidence.
- Raw fleet convergence still needs authoritative `fleet-rollout-evidence.json`
  from live relays or the release workflow.

The repo has a large pre-existing dirty worktree: `git status --short | wc -l`
returned `305` changed paths during this audit. Treat unrelated changes as
pre-existing unless a loop explicitly owns them.

## Current Implemented Surfaces

- Root package is `p2p-hiverelay-monorepo@0.20.0` with workspaces for
  `packages/core`, `packages/services`, `packages/client`, and
  `packages/verifier`.
- Root README presents Hiverelay as Core3 blind relay infrastructure packaged as
  Blindspark for Umbrel and StartOS, with publication boundaries separated from
  source readiness.
- Root README now includes a high-fidelity Mermaid `Relay System Graph`
  covering clients/operators, Hyperswarm/Hypercore/HTTP/WebSocket ingress,
  Core3 kernel services, Protomux channels, schemas/evidence contracts,
  release/store/fleet distribution, and runtime guardrails.
- API decomposition is substantially advanced: auth, request parsing, response
  shaping, catalog reads, seed publishing, unseed, status, peers, registry,
  reputation, gateway stats, service/router discovery, dashboard routes,
  operator telemetry, subsidy, alerts, custody, federation, and many management
  routes have dedicated helpers and focused tests. Authenticated service
  management snapshots now also bound and sanitize provider stats, device
  list rows, federation remote-catalog rows, detailed custody diagnostics,
  operator telemetry snapshots, HTTP overview relay/seeder/reputation/Tor
  summaries, public health disk summaries, public Node/Bare anchor aggregates, public Node/Bare catalog pagination,
  sanitized public catalog metadata/federation snapshots, legacy catalog type-route bounds, public Prometheus metrics redaction, dashboard WebSocket relay/seeder/AutoHeal/
  custody/transport/payment/reputation/network updates, metrics history snapshots, public Hyperdrive gateway JSON error responses, standalone gateway seed responses, data-plane gateway JSON responses, public Poker HTTP/WS adapter response/body/error hygiene, Umbrel AI model add duplicate-write/inline-status hardening, and Umbrel setup wizard action-lock/status hardening before the appliance UI renders
  service/device/federation/custody/telemetry metadata.
- Protocol and P2P boundary hardening is broad: JSON Protomux framing, seed
  protocol, forward/circuit relay encoding, proof responses, signed directory,
  service protocol subscription bounds, generic service RPC error redaction,
  AI/QVAC management provider-error redaction, quorum/fork detection, and
  AutoHeal capacity behavior are documented in the audit roadmap and covered by
  focused tests.
- Release automation is present for release prep, distribution preflight,
  image-manifest proof, Docker image smoke, Umbrel package smoke, official
  Umbrel PR evidence, StartOS package/registry evidence, fleet rollout, and
  final handoff verification. `prepare-release` and the distribution preflight
  default normal full releases to `both` fleet channels and prereleases to
  `none`, so stable releases do not silently stop at canary unless explicitly
  overridden. Evidence writers and release/handoff verifiers
  stream present `.s9pk` hashing rather than loading whole StartOS packages
  into memory. StartOS registry publication evidence now also hash-checks the
  release image manifest and image smoke sidecars from workflow-recorded paths
  and SHA-256 values before writing public registry evidence, and it now also
  requires those linked sidecars to carry the expected `kind` values before
  emitting StartOS registry proof. The final release certificate writer parses
  public JSON sidecars through the public-safety scanner and stream-hashes them
  before writing `release-evidence.json`, so unsafe, malformed, stale, or
  oversized evidence fails at the source.
  Release-image and Umbrel-package smoke now also prove the packaged
  Blindspark dashboard/setup UI-hardening contracts: wallet, service, restart,
  AI-model, and setup-wizard busy/status/action-lock markers are checked in the
  smoke writers and enforced again by release evidence verification and final
  release-handoff verification.
  Real Umbrel runtime-review evidence now must carry the upstream
  `getumbrel/umbrel-apps` PR URL in the writer, standalone verifier, and final
  release-handoff verifier, binding manual device review to the reviewer
  handoff it unblocks. The same manual runtime-review artifact now also
  requires real-device checks for setup action locks, wallet busy state, service
  action state, restart pending state, and AI model add duplicate-submit
  prevention.
  Stable-release preflight rejects malformed GitHub tokens and private-key
  credentials, including whitespace-padded or newline-injected secrets, before
  checkout, SSH, `gh`, GitHub env writes, or StartOS publish steps. It also
  rejects an official Umbrel fork setting that points at the upstream
  `getumbrel/umbrel-apps` repository, rejects unsafe explicit fleet rollout
  timeout variables before live SSH rollout checks, and release/handoff
  verifiers reject both upstream-owned official Umbrel PR head evidence and
  fleet rollout sidecars
  whose recorded probe timing is too short, too long, missing, or malformed to
  prove live convergence. The fleet rollout writer now enforces that same
  timing window before writing `verified` public rollout evidence, so unsafe
  manual one-shot probes fail before a sidecar can be attached to release
  evidence. The same rollout checker now also parses timing inputs as exact
  positive decimal integers only, rejecting whitespace, control characters,
  fractions, and exponent notation before SSH probing without reflecting the
  malformed value back to stderr. Fleet rollout API probe bases are now
  loopback-only at the writer and verifier boundary: `fleet:check-rollout`
  rejects non-loopback `--api` values before SSH probing or writing public
  evidence, and release/handoff verifiers reject non-loopback `probes.api`
  values before accepting fleet convergence. Official Umbrel PR handoff evidence writing
  now also validates raw workflow and PR metadata without trim-normalizing
  environment values, so whitespace-padded PR URLs, run ids, server URLs, head
  refs, or run attempts cannot be silently cleaned before public evidence is
  written. StartOS registry evidence writing now applies the same raw metadata
  rule to workflow, registry, package, hash, and linked image-evidence
  environment values before writing public registry sidecars. The central
  release certificate writer now also rejects whitespace-normalized workflow,
  release, image, surface, and sidecar metadata before writing
  `release-evidence.json`. Release and handoff verification now also require
  boolean prerelease flags and reject prerelease certificates that contain live
  fleet, Umbrel PR/community-store, or StartOS registry promotion facts.
- Umbrel package surfaces are first-submission shaped: app proxy, persistent
  `/data`, digest-pinned image, review-mode default, setup, add-wallet,
  management UI, packaged UI-hardening smoke proof, gallery validation,
  runtime-review writer, and runtime-review verifier. The submission plan and
  checklist now distinguish digest-pin shape from runtime-ready image proof:
  the current package is structurally pinned, but it must not be submitted until
  a fixed public GHCR digest passes manifest and release-image smoke evidence.
- StartOS packaging surfaces exist with digest-required `startos:verify`, a
  local-only `startos:verify:local`, a StartOS manifest, package build/verify
  path, and registry evidence writer/verifier.
- Fleet rollout tooling exists for channel metadata, updater install, health
  gates, rollback, SSH-safe probes, and release evidence linkage.
- Federation JSON polling now avoids a Node-only static `https` import in the
  Bare module graph. HTTPS catalog/proof pulls use native `globalThis.fetch`
  when available, while the Bare-safe mapped `http` module remains the fallback
  for plain HTTP. `npm run test:bare` now adds the bundled Bare binary path.

## Validation In This Loop

Passed:

- `npm audit`
  - Result: pass; `found 0 vulnerabilities`.
- `npm run lint`
  - Result: pass.
- `npm run test:unit`
  - Result: pass; exit `0`, final visible TAP test `ok 2183`.
- `./node_modules/.bin/brittle test/integration/**/*.test.js`
  - Result: pass outside sandbox for UDX/network sockets; exit `0`, final
    visible TAP test `ok 82`.
- `npm run test:bare`
  - Result: pass under real Bare runtime; `5/5` tests and `17/17` assertions.
- `npm run audit:workspace`
  - Result: pass with one warning:
    `Umbrel official package still needs its real getumbrel/umbrel-apps PR URL in submission`.
- `docker build -t p2p-hiverelay:local-current-20260624 .`
  - Result: pass; fresh current-worktree local image built with manifest list
    `sha256:160bdeec62731c0be6946ebb618b4a76afa164d577370a9883a841ea154d885e`.
- `npm run release:smoke-image -- p2p-hiverelay:local-current-20260624 --timeout-ms 120000`
  - Result: pass against the freshly built current-worktree image.
- `npm run umbrel:smoke-package -- --image-ref p2p-hiverelay:local-current-20260624 --timeout-ms 120000`
  - Result: pass against the freshly built current-worktree image; this covers
    setup, wallet save/persistence, service selection, dashboard WebSocket, and
    Umbrel-style restart persistence.
- `npm run startos:verify:local`
  - Result: pass once Docker Desktop was started; note this explicitly allows
    the tag-only local mechanics path. Release packaging now requires
    `HIVERELAY_IMAGE_DIGEST=sha256:<multi-arch-digest> npm run startos:verify`.
- `node scripts/check-release-distribution-env.mjs --prerelease false --github-env /tmp/hiverelay-release-env-full`
  - Result: expected local block. The full-release default enters the live
    distribution path and fails only on absent local credentials:
    `FLEET_SSH_PRIVATE_KEY`, `UMBREL_STORE_TOKEN`,
    `UMBREL_OFFICIAL_PR_TOKEN`, `UMBREL_OFFICIAL_FORK`,
    `STARTOS_DEVELOPER_KEY_PEM`, and `STARTOS_REGISTRY_URL`.
- `node scripts/check-release-distribution-env.mjs --prerelease true --github-env /tmp/hiverelay-release-env-pre`
  - Result: pass; prerelease distribution credential preflight skipped.
- `./node_modules/.bin/brittle --timeout 120000 test/unit/prepare-release.test.js`
  - Result: pass; includes proof that implicit full releases bump both
    `canary` and `stable`.
- `./node_modules/.bin/brittle --timeout 120000 test/unit/federation-hardening.test.js`
  - Result: pass; `18/18` tests and `55/55` assertions.
- `npx standard packages/core/core/federation.js scripts/audit-workspace-alignment.mjs test/bare/index.js`
  - Result: pass.
- `node --check scripts/audit-workspace-alignment.mjs`
  - Result: pass.
- `node --check scripts/check-release-image-manifest.mjs`
  - Result: pass.
- `node --check scripts/smoke-release-image.mjs`
  - Result: pass.
- `node --check scripts/smoke-umbrel-package.mjs`
  - Result: pass.
- `node --check scripts/write-umbrel-runtime-review-evidence.mjs`
  - Result: pass.
- `node --check scripts/verify-umbrel-runtime-review-evidence.mjs`
  - Result: pass.
- `node --check scripts/verify-release-evidence.mjs`
  - Result: pass.
- `node --check scripts/verify-release-handoff-evidence.mjs`
  - Result: pass.
- `node --check test/unit/release-evidence-verify.test.js`
  - Result: pass.
- `node --check test/unit/release-handoff-evidence-verify.test.js`
  - Result: pass.
- `node --check test/unit/release-smoke-evidence-writer.test.js`
  - Result: pass.
- `node --check test/unit/umbrel-runtime-review-evidence.test.js`
  - Result: pass.
- `node --check test/unit/umbrel-runtime-review-verify.test.js`
  - Result: pass.
- `node --check test/unit/fleet-rollout-check.test.js`
  - Result: pass.
- `npx standard scripts/smoke-release-image.mjs scripts/smoke-umbrel-package.mjs scripts/verify-release-evidence.mjs test/unit/release-evidence-verify.test.js test/unit/release-smoke-evidence-writer.test.js scripts/audit-workspace-alignment.mjs`
  - Result: pass.
- `npx standard scripts/verify-release-handoff-evidence.mjs test/unit/release-handoff-evidence-verify.test.js scripts/audit-workspace-alignment.mjs`
  - Result: pass.
- `npx standard scripts/write-umbrel-runtime-review-evidence.mjs scripts/verify-umbrel-runtime-review-evidence.mjs scripts/verify-release-handoff-evidence.mjs test/unit/umbrel-runtime-review-evidence.test.js test/unit/umbrel-runtime-review-verify.test.js test/unit/release-handoff-evidence-verify.test.js scripts/audit-workspace-alignment.mjs`
  - Result: pass.
- `npx standard scripts/check-fleet-rollout.mjs scripts/verify-release-evidence.mjs scripts/verify-release-handoff-evidence.mjs test/unit/fleet-rollout-check.test.js test/unit/release-evidence-verify.test.js test/unit/release-handoff-evidence-verify.test.js`
  - Result: pass.
- `npx standard scripts/write-startos-registry-evidence.mjs test/unit/startos-registry-evidence.test.js`
  - Result: pass.
- `./node_modules/.bin/brittle --timeout 120000 test/unit/fleet-rollout-check.test.js test/unit/release-evidence-verify.test.js test/unit/release-handoff-evidence-verify.test.js`
  - Result: pass; `143/143` tests and `636/636` assertions.
- `./node_modules/.bin/brittle --timeout 120000 test/unit/official-umbrel-pr-evidence.test.js test/unit/startos-registry-evidence.test.js test/unit/umbrel-runtime-review-verify.test.js test/unit/release-handoff-evidence-verify.test.js`
  - Result: pass; `120/120` tests and `543/543` assertions.
- `./node_modules/.bin/brittle --timeout 120000 test/unit/startos-registry-evidence.test.js`
  - Result: pass; `23/23` tests and `93/93` assertions.
- `./node_modules/.bin/brittle --timeout 120000 test/unit/release-smoke-evidence-writer.test.js test/unit/release-evidence-verify.test.js`
  - Result: pass; `61/61` tests and `326/326` assertions.
- `./node_modules/.bin/brittle --timeout 120000 test/unit/umbrel-runtime-review-evidence.test.js test/unit/umbrel-runtime-review-verify.test.js test/unit/release-handoff-evidence-verify.test.js`
  - Result: pass; `87/87` tests and `365/365` assertions.
- `git diff --check -- scripts/smoke-release-image.mjs scripts/smoke-umbrel-package.mjs scripts/verify-release-evidence.mjs test/unit/release-evidence-verify.test.js test/unit/release-smoke-evidence-writer.test.js scripts/audit-workspace-alignment.mjs README.md docs/AUDIT-ROADMAP.md docs/CURRENT_STATUS_AUDIT_2026-06-24.md`
  - Result: pass.
- `./node_modules/.bin/brittle --timeout 120000 test/unit/api-seed-publish.test.js test/unit/api-catalog-read.test.js test/unit/release-evidence-verify.test.js`
  - Result: pass; `60/60` tests and `268/268` assertions.
- `./node_modules/.bin/brittle --timeout 120000 test/unit/startos-registry-evidence.test.js`
  - Result: pass; `21/21` tests and `70/70` assertions.
- `./node_modules/.bin/brittle --timeout 120000 test/unit/release-evidence.test.js`
  - Result: pass; `31/31` tests and `175/175` assertions.
- `./node_modules/.bin/brittle --timeout 120000 test/unit/hyper-gateway-hardening.test.js test/unit/gateway-standalone-server.test.js test/unit/api-gateway-stats.test.js`
  - Result: pass; `13/13` tests and `63/63` assertions.
- `./node_modules/.bin/brittle --timeout 120000 test/unit/gateway-standalone-server.test.js`
  - Result: pass; `4/4` tests and `26/26` assertions.
- `./node_modules/.bin/brittle --timeout 120000 test/unit/gateway-server.test.js`
  - Result: pass; `4/4` tests and `35/35` assertions.
- `./node_modules/.bin/brittle --timeout 120000 test/unit/poker-ws-adapter.test.js test/unit/poker-http-adapter.test.js test/unit/api-service-config.test.js`
  - Result: pass; `52/52` tests and `376/376` assertions.
- `npx standard packages/services/builtin/poker/ws-adapter.js test/unit/poker-ws-adapter.test.js packages/services/builtin/poker/http-adapter.js test/unit/poker-http-adapter.test.js scripts/audit-workspace-alignment.mjs`
  - Result: pass.
- `./node_modules/.bin/brittle --timeout 120000 test/unit/protocol-security.test.js test/unit/client-service.test.js test/unit/services.test.js`
  - Result: pass; `79/79` tests and `278/278` assertions.
- `npx standard packages/core/core/services/protocol.js test/unit/protocol-security.test.js scripts/audit-workspace-alignment.mjs`
  - Result: pass.
- `./node_modules/.bin/brittle --timeout 120000 test/unit/api-ai-models.test.js test/unit/api-qvac-models.test.js test/unit/services.test.js`
  - Result: pass; `59/59` tests and `214/214` assertions.
- `npx standard packages/core/core/relay-node/api.js packages/core/core/relay-node/api-ai-models.js test/unit/api-ai-models.test.js test/unit/api-qvac-models.test.js scripts/audit-workspace-alignment.mjs`
  - Result: pass.
- `./node_modules/.bin/brittle --timeout 120000 test/unit/umbrel-ui-controls.test.js`
  - Result: pass; `21/21` tests and `195/195` assertions.
- `./node_modules/.bin/brittle --timeout 120000 test/unit/dashboard-wizard-ui.test.js test/unit/umbrel-ui-controls.test.js`
  - Result: pass; `27/27` tests and `255/255` assertions.
- `npx standard packages/core/gateway/hyper-gateway.js test/unit/hyper-gateway-hardening.test.js scripts/audit-workspace-alignment.mjs`
  - Result: pass.

Attempted and still red:

- `npm run umbrel:smoke-package`
  - Result: fails against the package-pinned public GHCR digest
    `ghcr.io/bigdestiny2/p2p-hiverelay:0.20.0@sha256:0b8857cda2d0e399031a135a0c5f9c8a2ec6fa77cf64ed1c59aba58351c9eae1`
    because the published image is stale and lacks the dashboard wallet/service
    busy-state guards now present in source.
- Live fleet rollout.
- Real Umbrel runtime review.

## Release Evidence State

Current release evidence docs added before this loop:

- `docs/RELEASE_IMAGE_MANIFEST_EVIDENCE_2026-06-24.md`
  - The published `0.20.0` GHCR digest resolves to a multi-arch image index with
    runnable `linux/amd64` and `linux/arm64` platform manifests.
  - OCI attestation sidecars are correctly ignored for runnable-platform
    duplicate checks.
- `docs/RELEASE_IMAGE_SMOKE_2026-06-24.md`
  - The published `0.20.0` digest-pinned image is smoke-red because dashboard
    WebSocket in-band auth receives HTTP 403 and the Umbrel package smoke now
    also proves the same published digest is stale on dashboard wallet/service
    busy-state markers.
  - The source tree contains the same-origin WebSocket fix and the current
    wallet/service busy-state UI hardening.
  - A rebuilt local image `p2p-hiverelay:local-current-20260624` passed both
    `npm run release:smoke-image` and `npm run umbrel:smoke-package -- --image-ref`.
  - Public release evidence still requires a new GHCR digest built from the
    fixed source, followed by image-manifest proof and image smoke against that
    digest.
- `docs/RELEASE_IMAGE_PUBLICATION_GATE_2026-06-24.md`
  - An earlier pass recorded Docker locally available outside the Codex sandbox
    and a fixed local image present with id
    `sha256:10f0966b853a4d6d46748d9833bf12f1cfcdefec091cd4646ca84243da96e4f7`.
    This continuation restarted Docker Desktop and replaced the stale local
    proof with `p2p-hiverelay:local-current-20260624`.
  - Stable release distribution preflight is externally gated in this session:
    fleet, Umbrel, official PR, StartOS key, and registry secrets are absent.
  - Read-only GHCR manifest inspection stalled for this session, so registry
    access/connectivity is unproven locally.
  - The safe next move is the official `release-surfaces.yml` workflow or an
    explicitly approved manual multi-arch GHCR push.

## Current Open Proof Gaps

These remain open because they require external runtime or review state:

- Fixed public GHCR digest:
  - Build/push a new public image from the fixed source.
  - Run `npm run release:check-image-manifest -- --image <ref>@sha256:<digest> --out release-image-manifest-evidence.json`.
  - Run `npm run release:smoke-image -- <ref>@sha256:<digest> --evidence release-image-smoke-evidence.json`.
- Official Umbrel App Store:
  - Capture the real upstream PR URL/state/head.
  - Capture real-device `umbrel-runtime-review-evidence.json`.
  - Verify with `npm run release:verify-review-ready-handoff`.
- StartOS:
  - Build/verify package artifacts in the intended release environment.
  - Publish to the configured registry.
  - Capture `startos-registry-evidence.json` with package URL/id/hash agreement.
- Raw fleet:
  - Run `npm run fleet:check-rollout` against live relays and selected channel.
  - Capture `fleet-rollout-evidence.json` proving target commit, package
    version, `/health.version`, health state, inventory digest, and relay names.

## Current Engineering Gaps

The source tree is much closer to standard than the original audit state, but
the following remain worth tracking:

- `RelayNode` and the management API are still large, even with many extracted
  helpers. Continue shrinking branch clusters only when a focused helper and
  direct tests can preserve behavior.
- Release evidence needs a full public green path after the dashboard WebSocket
  fix lands in a new digest-pinned GHCR image.
- Store/review evidence must stay separate from source claims; docs should not
  imply official marketplace availability before the external sidecars exist.
- The dirty worktree is broad enough that future loops should inspect touched
  paths carefully and avoid reverting unrelated changes.

## Recommended External Proof Edges

1. `hiverelay-publish-fixed-ghcr-image-and-rerun-release-smoke`
   - Highest proof upgrade, but externally gated: run the official
     `release-surfaces.yml` workflow or explicitly approved manual GHCR push,
     then capture digest-pinned manifest and smoke evidence.
2. `hiverelay-official-umbrel-pr-url-and-runtime-review-evidence`
   - Moves Blindspark from source-ready package to reviewer-ready handoff.
3. `hiverelay-startos-registry-publication-evidence`
   - Converts StartOS package automation into registry proof.
4. `hiverelay-live-fleet-rollout-evidence`
   - Proves raw relay fleet convergence rather than only local tooling.

## Recommended Local-Only Edges

Use these when GHCR, Umbrel, StartOS, or fleet credentials are absent:

1. `hiverelay-release-evidence-local-verifier-slice`
   - Run and, if needed, harden the local release-evidence verifier/writer unit
     slices without publishing new external facts. Keep sidecar claims honest:
     local tests can prove schema, chronology, public-safety, and hash checks,
     not registry availability.
2. `hiverelay-relaynode-api-extraction-slice`
   - Pick one remaining large `RelayNode` or management API branch cluster,
     extract a focused helper only if behavior-preserving tests can be added or
     reused in the same slice.
3. `hiverelay-local-command-matrix-refresh`
   - Refresh `docs/TEST-COMMAND-MATRIX-2026-06-24.md` after any local source
     change so future agents know the focused validation path before reaching
     for full `npm test`.
4. `hiverelay-todo-triage-refresh`
   - Rerun the maintained-source marker scan only if new TODO/FIXME markers
     appear; `docs/TODO-TRIAGE-2026-06-24.md` currently classifies that surface
     as non-actionable.

## Source Evidence

- `package.json`
- `README.md`
- `docs/AUDIT-ROADMAP.md`
- `docs/CURRENT_STATUS_AUDIT_2026-06-23.md`
- `docs/TEST-COMMAND-MATRIX-2026-06-23.md`
- `docs/TEST-COMMAND-MATRIX-2026-06-24.md`
- `docs/SHIP-HANDOFF-2026-06-24.md`
- `docs/RELEASE_IMAGE_MANIFEST_EVIDENCE_2026-06-24.md`
- `docs/RELEASE_IMAGE_SMOKE_2026-06-24.md`
- `umbrel-app/OFFICIAL-SUBMISSION-PLAN.md`
- `umbrel-app/SUBMISSION-CHECKLIST.md`
