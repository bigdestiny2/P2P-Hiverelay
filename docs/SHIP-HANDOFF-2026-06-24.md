# HiveRelay Ship Handoff - 2026-06-24

This is the current ship boundary after the final local review pass.

## Local State

- Branch: `main`
- HEAD inspected: `872674d feat(fleet): bound log footprint + git gc so updates don't bloat boxes (#56)`
- Worktree size: 300+ changed/untracked paths. Do not push the entire dirty
  tree blindly; choose a scoped release branch/commit set.
- Docker Desktop was started during this pass and Docker-backed local smokes
  are now runnable.
- `umbrel-app/data/.gitkeep` is intentional official-package content, not
  generated runtime data. The Umbrel export/checklist expects the package shape
  to include `umbrel-app.yml`, `docker-compose.yml`, and `data/.gitkeep`.
- `docs/HIVERELAY-ARCHITECTURE-GRAPH.md` is the new graph-first relay
  architecture/spec map linked from the README.

## Green Local Gates

- `npm audit`
- `npm run lint`
- `npm run audit:workspace`
  - Warning only: official Umbrel package still needs the real
    `getumbrel/umbrel-apps` PR URL.
  - Includes the architecture graph guard: the README must link
    `docs/HIVERELAY-ARCHITECTURE-GRAPH.md` plus the static SVG asset, and the
    graph doc/SVG must keep the relay, protocol, API, security, use-case, and
    release/fleet surfaces.
  - Includes the Umbrel UI guard for non-refreshing setup/add-wallet controls,
    service save/restart busy state, and accessible wallet/service status
    feedback.
- `npm run test:unit`
  - Exit `0`, final visible TAP `ok 2184`.
- `./node_modules/.bin/brittle test/integration/**/*.test.js`
  - Exit `0`, final visible TAP `ok 82`; run outside sandbox for UDX sockets.
- `npm run test:bare`
  - Real Bare runtime, `5/5` tests and `17/17` assertions.
- `docker build -t p2p-hiverelay:local-current-20260624 .`
  - Fresh current-worktree image built.
- `npm run release:smoke-image -- p2p-hiverelay:local-current-20260624 --timeout-ms 120000`
  - Passed.
- `npm run umbrel:smoke-package -- --image-ref p2p-hiverelay:local-current-20260624 --timeout-ms 120000`
  - Passed.
- `npm run startos:verify:local`
  - Passed; this verifies local StartOS packaging mechanics with the
    explicitly opt-in tag-only path. Release packaging now requires
    `HIVERELAY_IMAGE_DIGEST=sha256:<multi-arch-digest> npm run startos:verify`.
- `git diff --check`
  - Passed across the dirty worktree after the final local review pass.
- `./node_modules/.bin/brittle --timeout 120000 test/unit/prepare-release.test.js`
  - Passed, `7/7` tests and `21/21` assertions. This proves prereleases
    default to no fleet promotion and full releases default to `channel=both`.
- `./node_modules/.bin/brittle --timeout 120000 test/unit/release-distribution-env.test.js`
  - Passed, `18/18` tests and `156/156` assertions. This now asserts the
    distribution preflight writes `HIVERELAY_RELEASE_EFFECTIVE_CHANNEL=both`
    for an implicit full release and `none` for an implicit prerelease.
- `./node_modules/.bin/brittle --timeout 120000 test/unit/umbrel-ui-controls.test.js`
  - Passed, `22/22` tests and `206/206` assertions. This covers the
    non-refreshing setup/add-wallet controls, service save/restart busy state,
    duplicate-write guards, and accessible wallet/service status feedback.
- `npx standard scripts/audit-workspace-alignment.mjs`
  - Passed after adding the graph-doc drift guard.
- `xmllint --noout docs/assets/hiverelay-core3-architecture.svg`
  - Passed.
- `rsvg-convert -w 2000 -o /tmp/hiverelay-core3-architecture-rsvg.png docs/assets/hiverelay-core3-architecture.svg`
  - Passed; the rendered PNG was visually inspected for full-frame layout,
    readable labels, and no obvious text overlap.

## Still Red Or External

- `npm run umbrel:smoke-package` without `--image-ref` is red because the
  package-pinned public image
  `ghcr.io/bigdestiny2/p2p-hiverelay:0.20.0@sha256:0b8857cda2d0e399031a135a0c5f9c8a2ec6fa77cf64ed1c59aba58351c9eae1`
  is stale and lacks the current dashboard wallet/service busy-state guards.
- Full-release distribution preflight correctly defaults into live promotion
  and blocks locally on missing credentials:
  `FLEET_SSH_PRIVATE_KEY`, `UMBREL_STORE_TOKEN`,
  `UMBREL_OFFICIAL_PR_TOKEN`, `UMBREL_OFFICIAL_FORK`,
  `STARTOS_DEVELOPER_KEY_PEM`, and `STARTOS_REGISTRY_URL`.
- Public GHCR proof still needs a new digest built from the fixed source.
- Digest-pinned StartOS release verification still needs the new public digest.
- Official Umbrel proof still needs the real upstream PR plus real-device
  runtime review evidence.
- StartOS registry proof still needs real registry publication evidence.
- Raw fleet proof still needs authoritative `fleet-rollout-evidence.json`.

## Release Path

1. Create a scoped release branch from this dirty worktree rather than pushing
   all local changes directly from `main`.
2. Use the official `release-surfaces.yml` workflow, or an explicitly approved
   manual multi-arch GHCR push, to publish a new image digest from the fixed
   source.
3. Run image manifest proof and image smoke against the exact new digest.
4. Run Umbrel package smoke against the same exact digest and update package
   metadata only after it is green.
5. Run StartOS verify/package/registry publication from the release environment.
6. Run fleet rollout and capture evidence for both `canary` and `stable` unless
   an explicit override says otherwise.
7. Attach the Umbrel official PR/runtime-review, StartOS registry, fleet, image,
   and smoke sidecars to final `release-evidence.json`.
