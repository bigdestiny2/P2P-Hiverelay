# Hiverelay Test Command Matrix - 2026-06-27

## Scope

Current local verification matrix for the HiveRelay / Blindspark monorepo after
the 0.20.2 ecosystem-consumer alignment, release-default review, architecture
graph refresh, release-secret-template hardening, and Umbrel package-smoke
evidence hardening for app-proxy writes plus setup dashboard-link behavior.
It also records the final standalone fleet rollout checker default alignment:
manual rollout proof now defaults to both canary and stable unless explicitly
overridden.

Source root:

`/Users/localllm/Projects/pear-ecosystem/00-core/hiverelay`

This matrix supersedes the 2026-06-24 matrix for the current local ship loop.
It records only local evidence. Live fleet promotion, official Umbrel review,
and StartOS registry publication still require external sidecars from the
release environment.

## Local Command Results

| Command | Result | Notes |
| --- | --- | --- |
| `npm test` | Pass | Full Brittle sweep exited `0`. Includes unit, integration, pairing, custody, AutoHeal, bare smoke, API, release, and protocol slices. |
| `npm run lint` | Pass | StandardJS source lint passed after release-template and ecosystem-audit updates. |
| `npm run audit:workspace` | Pass with warning | Workspace alignment passed. Expected warning remains: official Umbrel package still needs its real `getumbrel/umbrel-apps` PR URL. |
| `npm run ecosystem:sync -- --check` | Pass | Known direct app consumers already resolve to the latest local Hiverelay workspace package links, linked lockfile metadata, and versioned source markers. |
| `npm run audit:ecosystem-consumers` | Pass | Active direct consumers resolve to the local Hiverelay `0.20.2` line; lockfile metadata and source markers are checked for drift. |
| `npm run audit:public-artifacts` | Pass | Public docs and GitHub workflow files are scanned for scanner-sensitive token-prefix, bearer-header, and private-key delimiter examples. |
| `npm run umbrel:export-official -- --target /private/tmp/hiverelay-official-umbrel-check/blindspark --allow-placeholder --check` | Pass | Official Umbrel export is in sync when written to the required `blindspark/` package directory name. |
| `npm run release:check-github-setup -- --repo bigdestiny2/P2P-Hiverelay` | Pass | Required GitHub release secret names are present (`6/6`); this confirms setup shape only because GitHub Secrets values are intentionally not readable. |
| `npm run release:check-distribution-env -- --channel both --prerelease false` | Blocked locally | This shell does not contain the required live-release values: fleet SSH key, Umbrel community token, official Umbrel PR token/fork, StartOS developer key, and StartOS registry URL. Validate a generated env file and rerun the GitHub Actions preflight before tagging. |
| `cd startos && make digest` | Blocked externally | `ghcr.io/bigdestiny2/p2p-hiverelay:0.20.2` does not resolve yet, so the current StartOS `.s9pk` verify path cannot prove the package until the release image is published. |
| `npm run docs:update-ship-handoff -- --date 2026-06-26 --ref 5934dbc522f891c193017f550a95d4edfa0fafa6 --branch main --pr 141 --test-run 28292603571 --docker-run 28292603573 --preflight-run 28292692235 --preflight-url https://github.com/bigdestiny2/P2P-Hiverelay/actions/runs/28292692235 --preflight-head 5934dbc522f891c193017f550a95d4edfa0fafa6 --preflight-branch main --preflight-created-at 2026-06-27T14:55:58Z --preflight-state completed/failure --superseded-preflight-success 28238930607 --superseded-preflight-success-head 1ffffe6 --check` | Pass | Generated ship handoff is in sync with merged PR #141 and now records the ecosystem parity gate, fresh current-main preflight blocker, and StartOS GHCR image/digest blocker. |
| `node --test test/unit/ecosystem-consumers.test.js` | Pass | `13/13` tests and `64/64` assertions. The unit fixture explicitly keeps PearBrowser desktop, PearPaste, Pear POS, Pear Tickets, p2pbuilders, Opengit's optional bridge, anonGPT native, and `hiverelay-test` in the current-consumer inventory, rejects PearPaste recovery/spec doc regressions back to the old `0.9.x` client guidance, and proves stale app package, lock, and versioned source-marker defaults can be synced forward. |
| `npm audit --audit-level=high` | Pass | npm reported `found 0 vulnerabilities` for the HiveRelay workspace. |
| `git diff --check` | Pass | No whitespace errors in the current HiveRelay diff. |
| `./node_modules/.bin/brittle test/unit/umbrel-ui-controls.test.js` | Pass | `24/24` tests and `253/253` assertions. Covers setup/wallet no-navigation writes, app-proxy wallet/seed/lease writes, app-proxy-safe wizard dashboard fallback links, bounded hidden-tab lease polling, service-card manager UX, restart convergence, AI model busy state, DOM-only rendering, no inline appliance/setup styles, no inline `onerror`, and no production `innerHTML =` dashboard writes. |
| `./node_modules/.bin/brittle test/unit/fleet-rollout-check.test.js` | Pass | `18/18` tests and `133/133` assertions. Covers rollout evidence schema, SSH/probe hardening, stale channel target rejection, package/runtime version convergence, secret redaction, and the no-flag default selecting both canary and stable relays. |
| `./node_modules/.bin/brittle test/unit/umbrel-ui-controls.test.js test/unit/release-smoke-evidence-writer.test.js test/unit/release-evidence-verify.test.js test/unit/release-handoff-evidence-verify.test.js` | Pass | `157/157` tests and `924/924` assertions. Covers Umbrel no-navigation UI controls plus release-image and Umbrel-package smoke sidecars requiring app-proxy-safe seed/lease writes, bounded lease polling, dashboard static-markup safety, setup dashboard-link app-path rewriting, and final release/handoff verifier rejection of stale proof fields. |
| `./node_modules/.bin/brittle test/unit/public-artifact-secret-scan.test.js test/unit/ship-handoff-update.test.js test/unit/release-secret-template.test.js test/unit/release-distribution-env.test.js test/unit/github-release-secrets-apply.test.js test/unit/github-release-setup.test.js` | Pass | `42/42` tests and `312/312` assertions. Covers public-artifact secret-pattern scanning, generated ship handoff, safe release-secret template creation, local distribution-env validation, GitHub secret application shape, exact post-apply setup/preflight command output, and repo secret-name setup checks. |

## Ecosystem Consumer Boundary

`npm run ecosystem:sync -- --check` is the no-write default-version gate for the
known direct app consumers, and `npm run audit:ecosystem-consumers` is the
package-parity inventory gate for the workspace outside the HiveRelay source
tree. They treat these as active direct consumers that should default to the
newest local Hiverelay line:

- PearBrowser desktop
- PearPaste
- Pear POS
- Pear Tickets
- p2pbuilders
- Opengit's optional Hiverelay bridge
- anonGPT native
- `hiverelay-test`

The sync check updates known package defaults, linked lock metadata, and
versioned source markers when run without `--check`. The audit scans
`package.json` files plus the nearest lockfiles, rejects stale split-package
metadata, rejects stale monorepo-root Hiverelay entries, and fails on any new
unclassified `p2p-hiverelay*` dependency. It also checks current PearPaste
recovery/spec docs for the local `0.20.2` workspace package guidance and
rejects the old `^0.9.2` / publish-blocker text.

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
  `npm run audit:ecosystem-consumers` remains a local workspace parity gate.
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

The latest recorded side-effect-free distribution preflight is run `28292692235`
at `main@5934dbc`, created `2026-06-27T14:55:58Z`, and it failed because
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
