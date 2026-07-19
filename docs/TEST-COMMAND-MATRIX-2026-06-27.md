# Hiverelay Test Command Matrix - 2026-06-27

## Scope

Current local verification matrix for the HiveRelay / Blindspark monorepo after
the 0.20.2 ecosystem-consumer alignment, release-default review, architecture
graph refresh, release-secret-template hardening, and Umbrel package-smoke
evidence hardening for app-proxy writes plus setup dashboard-link behavior.
It also records the final standalone fleet rollout checker default alignment:
manual rollout proof now defaults to both canary and stable unless explicitly
overridden. The local security/readiness sweep was re-run on 2026-06-28 after
the app manifests were staged to npm `latest` defaults and the npm package
dry-run proof was promoted into a first-class release gate. It was extended on
2026-07-01 with the read-only release-blocker closure board that aggregates the
external proof gaps without publishing, setting secrets, or mutating fleet or
store state. It now also records the PearBrowser/HiveRelay alignment closure
and the executable RelayKernel gateway compatibility matrix.

Source root:

`~/pear-ecosystem/00-core/hiverelay`

This matrix supersedes the 2026-06-24 matrix for the current local ship loop.
It records only local evidence. Live fleet promotion, official Umbrel review,
and StartOS registry publication still require external sidecars from the
release environment.

## Local Command Results

| Command | Result | Notes |
| --- | --- | --- |
| `npm test` | Pass | Re-run on 2026-06-28. Full Brittle sweep exited `0`. Includes unit, integration, pairing, custody, AutoHeal, bare smoke, API, release, and protocol slices. |
| `npm run lint` | Pass | StandardJS source lint passed after release-template and ecosystem-audit updates. |
| `npm run audit:workspace` | Pass with official Umbrel PR warning | Re-run on 2026-07-01 after the seed protocol handshake alias hardening, PearBrowser desktop/mobile/site alignment, npm-registry lock warning cleanup, RelayKernel gateway matrix, and release-promise scope gate. The seed protocol, PearBrowser dependency/defaults, relay HTTP/HTTPS, pearbrowser.com metadata, RelayKernel gateway-compatibility, and public release-promise rows pass; the only remaining warning is the expected official Umbrel App Store PR URL row. |
| `npm run audit:relaykernel-gateway` | Pass | New executable compatibility matrix for the RelayKernel extraction path. Verifies `/.well-known/hiverelay.json`, `/catalog.json`, and `/v1/hyper/:driveKey/*path` against the concrete Node API, Bare HTTP, and dedicated data-plane gateway handlers. |
| `npm run audit:release-promise` | Pass | New public promise-scope check. Verifies `prepare-release` default notes and the official Umbrel PR body template stay scoped to Core Availability / Blindspark instead of overbroad AI, poker, custody, payment, ZK, arbitration, or service-marketplace claims. |
| `npm run audit:owned-diff` | Pass | New development worktree hygiene check. The current dirty audit branch is reviewable because every changed or untracked HiveRelay path maps to a named audit-owned slice; this does not replace the clean-worktree requirement in `release:check-blockers`. |
| `npm run ecosystem:prepare-latest -- --check` | Pass with warnings | No consumer package or lockfile changes are needed, so the app manifests/source markers are already staged for npm `latest`. In the sandboxed local run, registry proof timed out and emitted prepare-mode warnings; the live `release:check-npm-latest` row below confirms the strict post-publish gate is still blocked by the stale `p2p-hiveservices` npm `latest` tag. |
| `npm run ecosystem:check-workspace -- --required --workspace-root ../..` | Pass | Full sibling ecosystem workspace is present from the Hiverelay checkout root: 8/8 current app consumers found, including PearBrowser desktop, PearPaste, Pear POS, Pear Tickets, p2pbuilders, Opengit relay, anonGPT native, and `hiverelay-test`. |
| `npm run ecosystem:sync:local -- --check` | Expected fail in release-default state | Current app manifests are staged to npm `latest`, so local mode reports 25 would-change entries back to file links plus stale PearBrowser lock metadata. Use this only when intentionally switching a development checkout back to local file links. |
| `npm run audit:ecosystem-consumers:local` | Expected fail in release-default state | Current app manifests are staged to npm `latest`, so the local-mode audit rejects the `latest` specs and local-source markers. This proves the release-default state is not silently drifting back to file links. |
| `HIVERELAY_NPM_LATEST_JSON='{"p2p-hiverelay":"0.9.2","p2p-hiverelay-client":"0.9.2","p2p-hiverelay-verifier":"0.9.2","p2p-hiveservices":"0.9.2"}' npm run ecosystem:sync -- --check` | Expected fail | Published-app defaults are blocked because npm `latest` still resolves to `0.9.2` for the four-package HiveRelay line, which would downgrade PearBrowser, PearPaste, anonGPT, and other tracked consumers from the local `0.20.2` line. |
| `npm run release:check-npm-latest -- --json` | Expected fail until final npm dist-tag promotion | Live registry check on 2026-07-01 shows `p2p-hiverelay`, `p2p-hiverelay-client`, and `p2p-hiverelay-verifier` now have `latest=0.20.2`, but `p2p-hiveservices` still has `latest=0.9.2`; downstream app lockfiles and live consumer promotion must wait until all four packages resolve to `0.20.2`. Once the registry gate is green, rerun with `-- --out npm-latest-evidence.json`; the command refuses to write the sidecar unless all four package `latest` tags are verified. |
| `npm run release:check-npm-packages` | Pass | First-class dry-run pack gate passed with an isolated npm cache. All four publishable packages include `README.md` and `LICENSE`, report `unsafe=none` for obvious path leaks, and pack as: `p2p-hiverelay` 169 entries / 486923 bytes, `p2p-hiverelay-client` 7 entries / 79104 bytes, `p2p-hiveservices` 30 entries / 98441 bytes, `p2p-hiverelay-verifier` 5 entries / 11330 bytes. |
| `npm run audit:public-artifacts` | Pass | Public docs and GitHub workflow files are scanned for scanner-sensitive token-prefix, bearer-header, and private-key delimiter examples. |
| `npm run umbrel:export-official -- --target /private/tmp/hiverelay-official-umbrel-check/blindspark --allow-placeholder --check` | Pass | Official Umbrel export is in sync when written to the required `blindspark/` package directory name. |
| `npm run release:check-official-umbrel-pr` | Expected fail until PR opened | Current official manifest still has `submission: https://github.com/getumbrel/umbrel-apps/pull/PENDING`; reviewer handoff must stamp the real upstream PR URL before this gate passes. |
| `npm run release:check-github-setup -- --repo bigdestiny2/P2P-Hiverelay` | Superseded external blocker | Issue #120 now records that required repository secret names are visible; the remaining blocker is masked value shape for `UMBREL_STORE_TOKEN`, `UMBREL_OFFICIAL_PR_TOKEN`, `UMBREL_OFFICIAL_FORK`, and `STARTOS_REGISTRY_URL`. Use the targeted `--issue-120-repair` flow, rerun the presence check, then rerun the side-effect-free `release-distribution-preflight.yml`. |
| `npm run release:check-distribution-env -- --channel both --prerelease false` | Blocked locally | This shell does not contain the required live-release values: fleet SSH key, Umbrel community token, official Umbrel PR token/fork, npm automation token, StartOS developer key, and StartOS registry URL. Validate a generated env file and rerun the GitHub Actions preflight before tagging. |
| `npm run release:check-blockers -- --json --skip-git --bundle-dir /private/tmp/hiverelay-empty-release-bundle --out /private/tmp/hiverelay-release-blockers-report.json` | Expected fail until external proof exists | New read-only closure board exits non-zero, writes a public-safe diagnostic report when requested, and reports the exact missing env, `npm-latest-evidence.json`, GHCR, Umbrel, StartOS, fleet, and final handoff evidence rows instead of treating scattered gate status as release readiness. Printed and written reports redact token-looking values across paths, details, and command strings. Missing sidecar rows prefer artifact-producing commands where available, including release, smoke, official Umbrel PR, runtime-review, StartOS registry, and fleet rollout evidence writers. The bundle directory itself must be a regular directory, not a symlink; downloaded evidence candidates must also be regular files, and JSON sidecars must be non-empty, parse as objects, and be at most 2 MiB. Symlinked bundle roots, symlinked sidecars, empty, malformed, array-valued, or oversized bundle entries remain blockers. `--skip-git` is only used here so the empty-bundle smoke stays hermetic; real release closure must include the clean-worktree row. |
| `gh workflow run release-distribution-preflight.yml --repo bigdestiny2/P2P-Hiverelay --ref main -f channel=both -f prerelease=false` then `gh run view 28293455583 --repo bigdestiny2/P2P-Hiverelay --json databaseId,status,conclusion,headSha,headBranch,createdAt,url` | Expected fail | Current full-release preflight is tied to `main@94580c6` and fails only on four external release values: malformed Umbrel store token, official PR token/fork, and malformed StartOS registry URL. |
| `cd startos && make digest` | Blocked externally | `ghcr.io/bigdestiny2/p2p-hiverelay:0.20.2` does not resolve yet, so the current StartOS `.s9pk` verify path cannot prove the package until the release image is published. |
| `npm run docs:update-ship-handoff -- --date 2026-06-26 --ref 94580c6c228be4291229b008ffa787278385d6bf --branch main --test-run 28293344980 --docker-run 28293344978 --preflight-run 28293455583 --preflight-url https://github.com/bigdestiny2/P2P-Hiverelay/actions/runs/28293455583 --preflight-head 94580c6c228be4291229b008ffa787278385d6bf --preflight-branch main --preflight-created-at 2026-06-27T15:27:01Z --preflight-state completed/failure --superseded-preflight-success 28238930607 --superseded-preflight-success-head 1ffffe6 --check` | Pass | Generated ship handoff is in sync with the guarded npm-latest consumer commit and now records the ecosystem parity gate, source-marker coverage, the four current issue #120 masked-value blockers, and StartOS GHCR image/digest blocker. |
| `node --test test/unit/ecosystem-consumers.test.js` | Pass | `29/29` tests and `157/157` assertions. The unit fixture explicitly keeps PearBrowser desktop, PearPaste, Pear POS, Pear Tickets, p2pbuilders, Opengit's optional bridge, anonGPT native, and `hiverelay-test` in the current-consumer inventory, rejects PearPaste recovery/spec doc regressions back to the old `0.9.x` client guidance, proves stale app package, lock, and versioned source-marker defaults can be synced forward, makes npm-latest the default app path, blocks npm-latest app defaults when npm would downgrade from `0.20.2`, and verifies `ecosystem:prepare-latest -- --check` can prove staged `latest` defaults without writing app files. |
| `npm audit` | Pass | Re-run on 2026-06-28. npm reported `found 0 vulnerabilities` for the HiveRelay workspace, including dev dependencies. |
| `git diff --check` | Pass | No whitespace errors in the current HiveRelay diff. |
| `./node_modules/.bin/brittle --timeout 120000 test/unit/relaykernel-gateway-compat.test.js test/unit/relaykernel-profile.test.js test/unit/profile-vector-verifier.test.js` | Pass | `16/16` tests and `100/100` assertions. Covers the executable RelayKernel gateway compatibility matrix, checked-in Node/Bare/data-plane route handler binding, route-term drift rejection, stable RelayKernel profile vector, the portable `relaykernel-http-route-matrix-v1-blindspark-compat` fixture, the app-module boundary vector that keeps QVAC/poker/custody/services outside the RelayKernel profile, table-backed supported-vector inventory, duplicate/missing supported-vector inventory rejection, focused one-vector debug verification, and the profile-vector CLI (`21/21` vectors). |
| `./node_modules/.bin/brittle --timeout 120000 test/unit/seed-protocol-encoding.test.js` | Pass | `11/11` tests and `86/86` assertions. Covers bounded seed request/accept/deny/unseed encodings, malformed/truncated/invalid-state decode behavior, relay/client decoded-error handling, canonical `MAX_PROTOCOL_HANDSHAKE_BYTES` / `parseProtocolHandshake` exports, compatibility aliases, and handshake rejection before pending request replay. |
| `./node_modules/.bin/brittle test/unit/umbrel-ui-controls.test.js` | Pass | `24/24` tests and `253/253` assertions. Covers setup/wallet no-navigation writes, app-proxy wallet/seed/lease writes, app-proxy-safe wizard dashboard fallback links, bounded hidden-tab lease polling, service-card manager UX, restart convergence, AI model busy state, DOM-only rendering, no inline appliance/setup styles, no inline `onerror`, and no production `innerHTML =` dashboard writes. |
| `./node_modules/.bin/brittle test/unit/fleet-rollout-check.test.js` | Pass | `18/18` tests and `133/133` assertions. Covers rollout evidence schema, SSH/probe hardening, stale channel target rejection, package/runtime version convergence, secret redaction, and the no-flag default selecting both canary and stable relays. |
| `./node_modules/.bin/brittle --timeout 120000 test/unit/release-blockers-check.test.js test/unit/npm-latest-check.test.js` | Pass | Covers the closure-board package script, missing-evidence blocker reporting, public output redaction, offline npm-latest fixtures, reusable `npm-latest-evidence.json` sidecar validation, stale sidecar rejection, symlinked bundle-root rejection before sidecars are trusted, local candidate env-file proof, incomplete fixture rejection without falling through to live npm lookup, and npm-latest sidecar write refusal when tags are stale. |
| `./node_modules/.bin/brittle test/unit/umbrel-ui-controls.test.js test/unit/release-smoke-evidence-writer.test.js test/unit/release-evidence-verify.test.js test/unit/release-handoff-evidence-verify.test.js` | Pass | `157/157` tests and `924/924` assertions. Covers Umbrel no-navigation UI controls plus release-image and Umbrel-package smoke sidecars requiring app-proxy-safe seed/lease writes, bounded lease polling, dashboard static-markup safety, setup dashboard-link app-path rewriting, and final release/handoff verifier rejection of stale proof fields. |
| `./node_modules/.bin/brittle test/unit/public-artifact-secret-scan.test.js test/unit/ship-handoff-update.test.js test/unit/release-secret-template.test.js test/unit/release-distribution-env.test.js test/unit/github-release-secrets-apply.test.js test/unit/github-release-setup.test.js` | Pass | `42/42` tests and `312/312` assertions. Covers public-artifact secret-pattern scanning, generated ship handoff, safe release-secret template creation, local distribution-env validation, GitHub secret application shape, exact post-apply setup/preflight command output, and repo secret-name setup checks. |

## Ecosystem Consumer Boundary

`npm run ecosystem:prepare-latest` is the pre-publish staging path for known
direct app consumers: it writes manifests and source markers to npm `latest`
without fabricating package-lock registry metadata. `npm run ecosystem:sync`
is the post-publish npm-latest gate; it refuses to refresh lockfiles until all
four HiveRelay packages resolve through npm `latest` to `0.20.2`. The no-write
strict form is `npm run ecosystem:sync -- --check`; the no-write prepared-state
check is `npm run ecosystem:prepare-latest -- --check`. From this Hiverelay
checkout, the full sibling workspace guard is `npm run ecosystem:check-workspace
-- --required --workspace-root ../..`. `npm run
ecosystem:sync:local -- --check` and `npm run audit:ecosystem-consumers:local`
remain development-only file-link guards and are expected to fail while the
workspace is intentionally staged for release-default npm `latest`. The active
direct consumers are:

- PearBrowser desktop
- PearPaste
- Pear POS
- Pear Tickets
- p2pbuilders
- Opengit's optional Hiverelay bridge
- anonGPT native
- `hiverelay-test`

The sync check updates known package defaults and versioned source markers when
run without `--check`; in strict npm-latest mode it refreshes lockfiles only
after registry proof is green. The audit scans `package.json` files plus the
nearest lockfiles, rejects stale split-package metadata, rejects stale
monorepo-root Hiverelay entries, and fails on any new unclassified
`p2p-hiverelay*` dependency. It also checks current PearPaste recovery/spec docs
for the npm `latest` package guidance and rejects the old `^0.9.2` /
publish-blocker text.

`00-core/hr-acct`, `00-core/hr-fleet`, and `00-core/hr-release` are not active
app consumer roots, but they are no longer allowed to drift silently: the same
audit now checks their root, core, client, services, verifier manifests and
root lockfiles for `0.20.2`, plus the client/services `p2p-hiverelay`
dependency range of `^0.20.2`.

## Consumer App Smoke Results

These app-level checks were run after the package-parity audit so the current
consumer set is covered by both metadata and runtime/import smoke:

| Consumer | Command | Result |
| --- | --- | --- |
| PearBrowser desktop | `npm test` | Pass: `559/559` Node tests. |
| PearPaste | `npm run test:unit` | Pass: `48/48` unit tests and `260/260` assertions. |
| Pear POS | `npm test` | Pass: `22` Vitest files and `381/381` tests. |
| Pear Tickets | `npm test` | Pass: `5` Vitest files and `17/17` tests. |
| p2pbuilders | `npm test` | Pass: all chained checks, including `m12-hiverelay-client-migration.js`. |
| anonGPT native | `npm run check` and `npm test` | Pass: syntax check plus `129/129` Node tests. |
| `hiverelay-test` | `npm run smoke` | Pass: offline import, constructor, options, status, and destroy smoke. |
| Opengit optional bridge | package inspection plus `npm run audit:ecosystem-consumers` | Pass: no package-local test script; dependency pin is covered by the ecosystem audit. |

## Release Distribution Boundary

The release workflow default has been rechecked:

- Full releases with no explicit channel resolve to `both`.
- Standalone `fleet:check-rollout` also defaults to `both`, so manual rollout
  proof no longer shrinks to canary-only unless explicitly overridden.
- Prereleases with no explicit channel resolve to `none`.
- Manual `release-surfaces.yml` dispatch offers `canary`, `stable`, `both`, and
  `none`, with `both` as the default.
- `release-surfaces.yml` explicitly runs `npm run audit:public-artifacts` and
  `node --test test/unit/ecosystem-consumers.test.js` before image publish so
  release logs show both the public-artifact secret-pattern guard and the
  ecosystem consumer inventory guard. The full sibling-checkout
  `npm run ecosystem:prepare-latest -- --check` path is the safe no-write
  pre-publish staging gate for npm `latest` app defaults; local file-link audit
  mode is development-only.
- `release-distribution-preflight.yml` is the side-effect-free check to run
  before retrying a live release.

Stable release secrets now have a safer local repair loop:

```sh
npm run release:write-secret-template -- \
  --out /private/tmp/hiverelay-release-secrets.env

npm run release:check-distribution-env -- \
  --env-file /private/tmp/hiverelay-release-secrets.env \
  --channel both \
  --prerelease false

npm run release:apply-github-secrets -- \
  --repo bigdestiny2/P2P-Hiverelay \
  --env-file /private/tmp/hiverelay-release-secrets.env \
  --dry-run
```

The generated file is placeholder-only, owner-readable/writable, outside the
repo by default, and guarded against repo-path writes, symlink writes, and
accidental overwrites. The dry-run and apply helper output now print the exact
`release:check-github-setup` and `release-distribution-preflight.yml` commands
to run next.

## External Gates

These are still not proven by local tests:

- Corrected GitHub-hosted full-release values and a fresh passing
  `release-distribution-preflight.yml` run.
- New digest-pinned GHCR image built from the final source; the current
  `ghcr.io/bigdestiny2/p2p-hiverelay:0.20.2` tag must exist before
  `make digest`, `npm run startos:verify:local`, or release
  `HIVERELAY_IMAGE_DIGEST=... npm run startos:verify` can pass.
- Public `release-image-manifest-evidence.json` and
  `release-image-smoke-evidence.json` for that digest.
- `fleet-rollout-evidence.json` proving canary/stable live fleet convergence.
- Official Umbrel PR evidence and real-device Umbrel runtime review evidence.
- `startos-registry-evidence.json` proving StartOS registry publication.

## Current Blockers

The latest recorded side-effect-free distribution preflight is run `28293455583`
at `main@94580c6`, created `2026-06-27T15:27:01Z`, and it failed because
GitHub-hosted release values are malformed:

This was rechecked with `gh run list` / `gh run view` on 2026-06-27; no newer
passing `release-distribution-preflight.yml` run exists at the time of this
matrix update.

- `UMBREL_STORE_TOKEN`
- `UMBREL_OFFICIAL_PR_TOKEN`
- `UMBREL_OFFICIAL_FORK`
- `STARTOS_REGISTRY_URL`

The repo-side repair tooling is ready. Do not cut a full live release until the
values are rotated and a fresh full-release preflight passes with
`channel=both` and `prerelease=false`.

Separately, the StartOS source is ready for a digest-pinned package build, but
`cd startos && make digest` currently fails because
`ghcr.io/bigdestiny2/p2p-hiverelay:0.20.2` is not published. Publish the final
multi-arch GHCR image first, then run `make digest` and
`HIVERELAY_IMAGE_DIGEST=sha256:<digest> npm run startos:verify` before treating
StartOS as release-proven.
