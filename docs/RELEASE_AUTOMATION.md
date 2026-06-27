# Release Automation

HiveRelay release surfaces are synchronized by `scripts/prepare-release.mjs`
and the `Release surfaces` GitHub Actions workflow.

The workflow is serialized with GitHub Actions `concurrency` group
`release-surfaces` and `cancel-in-progress: false`. Published releases, pushed
`v*` tags, and manual promotions queue instead of racing pushes to `main`, GHCR
tags, release assets, or the Umbrel community-store checkout.

Runs that make it past checkout also write `release-evidence.json`. It is
uploaded as a workflow artifact even when a later gate fails, so the artifact
shows which gates passed, failed, or were still pending. Successful runs also
attach the same file to the GitHub Release, tying together the tag SHA,
metadata commit SHA, GHCR digest, StartOS `.s9pk` SHA-256, smoke gates, checked
fleet rollout channel, `fleet/relays.json` inventory digest and expected relay
names, per-relay package-version/runtime convergence,
`release-image-manifest-evidence.json` SHA-256,
`release-image-smoke-evidence.json` SHA-256,
`umbrel-package-smoke-evidence.json` SHA-256, `fleet-rollout-evidence.json`
SHA-256, Umbrel store/PR status plus exact Umbrel Git refs, and StartOS
release/registry status plus the registry URL, package URL, and package id. A successful
full-release run must record completed fleet rollout for the requested channel,
official Umbrel draft PR URL/head SHA plus the GitHub-reported `OPEN` state,
draft flag, `master` base, head owner, head branch, and head OID,
community-store commit, and StartOS registry URL/package URL/package id/publish statuses;
otherwise evidence generation fails the job instead of attaching an incomplete
green release certificate. The release certificate writer validates raw
workflow, release, image, surface, and sidecar metadata without trimming
whitespace before writing public release evidence, so padded run ids, tag SHAs,
URLs, digests, or evidence paths fail instead of being silently cleaned.
Successful full releases attach `release-evidence.json`, both smoke sidecars,
`release-image-manifest-evidence.json`, and `fleet-rollout-evidence.json`;
prereleases attach release evidence plus the image-manifest and smoke sidecars
because they do not promote the fleet. The release and handoff verifiers require
the prerelease flag to be a real boolean and reject prerelease certificates that
carry fleet rollout, official Umbrel PR, community-store, StartOS registry,
registry package, or registry-evidence facts. Before upload, the
workflow runs `npm run release:verify-evidence` to hash-check the StartOS
artifact and prove the release evidence matches the image-manifest, smoke, and
fleet sidecars, including the authoritative fleet inventory digest and selected
relay names. The image-manifest sidecar proves the pinned GHCR digest is an
OCI/Docker image index containing `linux/amd64` and `linux/arm64` manifests.
The normal verifier path rejects non-success workflow evidence; failed-run
artifacts are diagnostic only and require the explicit
`--allow-failed-diagnostic` flag for local inspection.
After upload, it downloads the release assets back from GitHub Release into a
temporary bundle and runs the same verifier with `--bundle-dir`, proving the
published assets round-trip. After the post-publication Umbrel and StartOS
handoff sidecars are uploaded, the workflow downloads
`release-image-smoke-evidence.json`, `umbrel-package-smoke-evidence.json`,
`fleet-rollout-evidence.json`,
`official-umbrel-pr-evidence.json`, `startos-registry-evidence.json`,
`release-image-manifest-evidence.json`, `release-evidence.json`, and
`blindspark.s9pk` back from the GitHub Release and runs
`npm run release:verify-handoff-evidence -- --bundle-dir`, proving the reviewer
handoff and registry publication assets agree with the final release
certificate, image-platform proof, smoke proof, live-fleet rollout proof, and
package hash.

Pre-releases are isolated by default. A tag such as `vX.Y.Z-beta.1` or a
GitHub Release marked pre-release builds and pushes only its explicit image tag,
uploads the StartOS test package to that GitHub Release, and uses
`channel=none`. It does not update `latest`, fleet channels, Umbrel metadata,
or the community store. The workflow rejects prereleases if a channel other
than `none` is requested. `release:prepare` follows the same rule locally:
pre-release versions default to `channel=none` and reject explicit fleet/app
store channel promotion. They also skip the community Umbrel store by default
and reject an explicit pre-release `--umbrel-store` target. They do not move
sibling ecosystem app defaults.

Full releases are distribution-complete by default. Before any public GitHub
Release is looked up, created, reused, or written to, the workflow requires the
masked repository values needed to publish the npm packages, verify the raw
fleet, push the Umbrel community store, open or update the official Umbrel draft
PR, and publish the StartOS registry package to pass the same full-release
preflight as
`release-distribution-preflight.yml`. Missing or malformed credentials fail the
run and record `distributionPreflight: failed` in release evidence.

## Repository Secret Setup

Configure the release secrets before cutting a full release. Use stdin or local
environment variables so secret values do not appear in shell history. The
workflow reads these values as repository secrets, including
`UMBREL_OFFICIAL_FORK` even though it is a fork slug rather than a token and
`STARTOS_REGISTRY_URL` even though it is a public HTTPS URL. That keeps all
release-distribution values masked in GitHub Actions logs. The
`release:write-secret-template` and `release:apply-github-secrets` script names
are historical; they validate and apply the whole masked release-value set.
Before setting or rotating GitHub Secrets, generate a local candidate template,
replace the placeholders, then validate the exact candidate values with the
same distribution checker used by the release workflow. Keep the candidate file
outside the repo and delete it after the secrets are set.

```sh
npm run release:write-secret-template -- \
  --out /private/tmp/hiverelay-release-secrets.env

$EDITOR /private/tmp/hiverelay-release-secrets.env

npm run release:check-distribution-env -- \
  --env-file /private/tmp/hiverelay-release-secrets.env \
  --channel both \
  --prerelease false
```

The generated template is written with owner-only permissions and refuses to
overwrite an existing file unless `--force` is passed. The final edited file
should have this shape:

```sh
FLEET_SSH_PRIVATE_KEY<<FLEET_KEY
PASTE_THE_FULL_FLEET_PRIVATE_KEY_BLOCK_HERE
FLEET_KEY
UMBREL_STORE_TOKEN=PASTE_COMMUNITY_STORE_GITHUB_TOKEN_HERE
UMBREL_OFFICIAL_PR_TOKEN=PASTE_OFFICIAL_PR_GITHUB_TOKEN_HERE
UMBREL_OFFICIAL_FORK=owner/umbrel-apps
NPM_TOKEN=PASTE_NPM_AUTOMATION_TOKEN_HERE
STARTOS_DEVELOPER_KEY_PEM<<STARTOS_KEY
PASTE_THE_FULL_STARTOS_DEVELOPER_PRIVATE_KEY_BLOCK_HERE
STARTOS_KEY
STARTOS_REGISTRY_URL=https://registry.example.tld
FLEET_ROLLOUT_TIMEOUT_MS=1800000
```

The edited private-key values must include their normal begin/end delimiter
lines in the local file; the documentation intentionally avoids spelling those
delimiters or token prefixes out so public docs stay friendly to secret
scanners.

The local `--env-file` parser accepts simple `NAME=value` entries and
`NAME<<DELIM` heredocs for multiline private keys. It performs shape checks
only; it does not contact the fleet, Umbrel, StartOS, or GitHub, and it does
not print secret values. Candidate-file validation is hermetic: ambient shell
secrets do not satisfy missing file entries. When this check fails, its stderr
prints a safe repair path with the template command, the candidate-env
validation command, the `release:apply-github-secrets` command, and the
side-effect-free `release-distribution-preflight.yml` rerun. The repair block never includes
the candidate secret values. After the candidate file passes, apply the exact
same file to GitHub Secrets. Run the helper once with `--dry-run` so the
operator can confirm the target repository and names without changing GitHub
state.

```sh
repo=bigdestiny2/P2P-Hiverelay

npm run release:apply-github-secrets -- \
  --repo "$repo" \
  --env-file /private/tmp/hiverelay-release-secrets.env \
  --dry-run

npm run release:apply-github-secrets -- \
  --repo "$repo" \
  --env-file /private/tmp/hiverelay-release-secrets.env
```

The helper validates the candidate file again before any write, sends masked
release values to `gh secret set` through stdin, stores
`FLEET_ROLLOUT_TIMEOUT_MS` as an optional repository variable when present, and
does not print the candidate values. Both dry-run and apply output print the exact
`release:check-github-setup` and `gh workflow run
release-distribution-preflight.yml` commands to run next.

Expected shapes:

| Name | Shape |
| --- | --- |
| `FLEET_SSH_PRIVATE_KEY` | PEM/OpenSSH private key block without surrounding whitespace |
| `UMBREL_STORE_TOKEN` | GitHub token with push access to `bigdestiny2/blindspark-umbrel-store` |
| `UMBREL_OFFICIAL_PR_TOKEN` | GitHub token able to push the official-package fork and open/update `getumbrel/umbrel-apps` PRs |
| `UMBREL_OFFICIAL_FORK` | Fork slug such as `owner/umbrel-apps`; it must not be `getumbrel/umbrel-apps` |
| `NPM_TOKEN` | npm automation token able to publish `p2p-hiverelay`, `p2p-hiverelay-client`, `p2p-hiverelay-verifier`, and `p2p-hiveservices` |
| `STARTOS_DEVELOPER_KEY_PEM` | StartOS developer private key block without surrounding whitespace |
| `STARTOS_REGISTRY_URL` | Public HTTPS registry base URL without credentials, query string, or fragment |
| `FLEET_ROLLOUT_TIMEOUT_MS` | Optional integer from 600000 to 14400000 milliseconds |

After configuration, confirm the names are visible:

```sh
npm run release:check-github-setup
```

This check reads the repository secret and variable names through `gh`; it does
not print secret values. It fails if any required release secret is missing, if
a required secret name was accidentally configured as a public repository
variable, or if the optional `FLEET_ROLLOUT_TIMEOUT_MS` variable is malformed.
GitHub does not expose repository secret values through the API, so a green
local setup check is a presence/placement audit, not proof that the stored
values are valid or that a release is live.

After setting or rotating release secrets, run the side-effect-free masked-value
preflight in GitHub Actions:

```sh
gh workflow run release-distribution-preflight.yml \
  --repo "$repo" \
  -f channel=both \
  -f prerelease=false

run_id="$(gh run list \
  --repo "$repo" \
  --workflow release-distribution-preflight.yml \
  --limit 1 \
  --json databaseId \
  --jq '.[0].databaseId')"

gh run watch "$run_id" --repo "$repo" --exit-status
```

That workflow runs `release:check-distribution-env` against the actual masked
repository secrets without building images, updating fleet channels, opening
Umbrel PRs, or publishing to StartOS. A full release is considered live only
after `release-surfaces.yml` succeeds and attaches `release-evidence.json` plus
the required sidecars to the GitHub Release.

The same masked-value check also gates `release-surfaces.yml` before public
GitHub Release continuation. For tag-push and manual runs, the workflow now
verifies the full-release distribution values before it even checks whether the
GitHub Release exists or creates one. For an already-tagged release such as a
rerun after a failed attempt, a bad value shape stops the run before release
assets are uploaded or clobbered and before fleet, Umbrel, or StartOS work
continues. After correcting the repository secrets, run
`release-distribution-preflight.yml` for `channel=both` and
`prerelease=false`; only then rerun the already-tagged `release-surfaces.yml`
workflow.

Never reuse an existing release tag for newly merged code. Prepare and tag a
fresh version, then let `release-surfaces.yml` build the digest, update
metadata, roll the selected fleet channels, and attach evidence. A full release
with no channel override defaults to `both`; a prerelease defaults to `none`.

`release-surfaces.yml` is the only workflow that publishes release image tags.
The older `docker-publish.yml` workflow is snapshot-only: pushes to `main`
publish `latest` and `main-<sha>` for canary testing, but `vX.Y.Z` tags are
reserved for the release workflow so the GHCR digest, fleet channels, Umbrel
metadata, and StartOS package move together.

## What Updates Automatically

When a GitHub Release is published, a `v*` tag is pushed, or the workflow is
manually dispatched, the workflow:

1. Validates the release version/channel, verifies the release tag is already
   contained in `main`, and runs the stable-release distribution credential
   preflight.
2. Creates or reuses the public GitHub Release object only after the
   distribution preflight passes for tag-push/manual runs so later asset
   uploads and download verification target the same release.
3. Installs dependencies and runs `npm audit`, `npm run lint`,
   `npm run audit:workspace`, `npm run audit:public-artifacts`,
   `node --test test/unit/ecosystem-consumers.test.js`, and
   `npm run test:unit`. The public-artifact audit keeps release docs and
   workflows free of scanner-sensitive secret examples, while the explicit
   ecosystem inventory guard keeps the release log tied to the PearBrowser,
   PearPaste, anonGPT, and other direct consumer default-pinning contract before
   any image is published.
4. Builds and pushes the multi-arch GHCR image from the tagged source:
   `ghcr.io/bigdestiny2/p2p-hiverelay:<version>`. Full releases also update
   `latest`; prereleases do not.
5. Resolves the pushed multi-arch `sha256:` digest.
6. Verifies the exact pushed image reference (`<version>@sha256:...`) is a
   multi-platform OCI/Docker image index with `linux/amd64` and `linux/arm64`
   manifests, tolerating OCI attestation sidecars without counting them as
   runnable platform duplicates, then writes
   `release-image-manifest-evidence.json`.

Before cutting a release from a full sibling workspace, also run
`npm run ecosystem:sync -- --check` and `npm run audit:ecosystem-consumers` from
the Hiverelay repo. The sync check proves PearBrowser, PearPaste, anonGPT, and
the other direct consumers already default to the latest local Hiverelay package
links, linked lockfile metadata, and versioned source markers. Full
`release:prepare` runs now attempt the same ecosystem sync automatically when
the sibling workspace is present; HiveRelay-only CI checkouts record a skip note
instead. The audit proves there are no new unclassified `p2p-hiverelay*` app
pins.
7. Boots the exact pushed image reference (`<version>@sha256:...`) in Docker,
   waits for `/health`, verifies the Blindspark appliance dashboard and setup
   page, proves the home-server `HIVERELAY_ACCEPT_MODE=review` default,
   proves dashboard WebSocket URL-token rejection plus in-band auth, and checks
   the authenticated service-management and usage telemetry APIs.
8. Returns to `main`, then runs `npm run release:prepare -- vX.Y.Z --channel both
   --image-digest sha256:...`.
9. Boots the synchronized `umbrel-app/docker-compose.yml` package with the
   release image override, verifies the dashboard/setup pages, review-mode
   default, authenticated wallet save flow, service catalog, service-selection
   save flow, dashboard WebSocket in-band auth, usage telemetry, and data
   persistence across restart.
10. Configures a StartOS developer key, builds `startos/blindspark.s9pk` from
   the resolved GHCR digest, and verifies it with `start-sdk verify`. Full
   releases require `STARTOS_DEVELOPER_KEY_PEM`; prereleases may still use an
   ephemeral key for a sideload-only test artifact.
11. Publishes `p2p-hiverelay`, `p2p-hiverelay-client`,
   `p2p-hiverelay-verifier`, and `p2p-hiveservices` to npm, or leaves an
   already-published immutable tarball in place, then verifies every `latest`
   dist-tag equals the release semver. This runs after image, Umbrel, and
   StartOS package smoke/verify gates but before the release asset upload,
   fleet promotion, Umbrel store updates, and StartOS registry publication.
   This is the gate that lets PearBrowser, PearPaste, anonGPT, and other app consumers safely move from local workspace links to the published release line.
   After this gate is green, run `npm run ecosystem:sync:latest` from a
   full sibling workspace to switch tracked app manifests to npm `latest` and
   refresh lockfiles from real registry metadata. Before this gate is green,
   `ecosystem:sync:latest` intentionally refuses to edit app defaults.
12. Uploads the verified `.s9pk` to the GitHub Release as a sideloadable
   StartOS package.
13. Commits the synchronized release surfaces back to `main`:
   workspace package versions, `package-lock.json`, README status, fleet
   channel, Umbrel metadata, and StartOS metadata.
14. Waits for the raw systemd relays on the promoted channel to converge on
    the release tag SHA, checked-out package version, and `/health`
    `running:true` with the release version.
15. Publishes the verified `.s9pk` to the configured StartOS registry with
    `start-sdk publish` and writes `startos-registry-evidence.json`.
16. Exports the official Umbrel package shape and opens or updates a draft PR
    against `getumbrel/umbrel-apps`.
17. Writes and uploads `release-evidence.json` plus public-safe image-manifest
    and smoke sidecars as durable proof of the image digest, StartOS package
    hash, checked gates, rollout channel, and every external release surface
    that was published, verified, or skipped.

The raw systemd fleet updates live because every relay box polls
`fleet/channels.json` from `main`. Full published releases default to
`channel=both`, so canary and stable relays advance in the same verified
release run. The standalone distribution preflight uses the same full-release
default when `HIVERELAY_RELEASE_CHANNEL` is unset, and uses `channel=none` for
prerelease checks. The preflight writes
`HIVERELAY_RELEASE_EFFECTIVE_CHANNEL` into the GitHub environment after the
channel has passed the allowlist, so workflow logs and later steps can show the
actual fleet target chosen by defaulting or override. Prereleases with
`channel=canary`, `channel=stable`, or `channel=both` are rejected before
release evidence can be written. For staged or manual promotions, dispatch the
workflow with `channel=canary`, `channel=stable`, `channel=both`, or
`channel=none`, or set `HIVERELAY_RELEASE_CHANNEL` for the release workflow
environment.

Full releases require `FLEET_SSH_PRIVATE_KEY`. After `fleet/channels.json` is
committed to `main`, the workflow SSHes to every relay on the promoted channel,
checks that the repo `HEAD` equals the release tag commit, and requires the
local relay health endpoint to report `running:true` plus the release version.
The rollout sidecar records the `fleet/channels.json` SHA-256 plus the selected
channel targets, and the release verifiers reject sidecars whose channel config
does not point canary, stable, or both at the promoted tag. Set repository
variable `FLEET_ROLLOUT_TIMEOUT_MS` to tune the default 30 minute wait. The
fleet rollout writer also refuses to mint a `verified` sidecar unless the
recorded `timeoutMs`, `intervalMs`, and `sshTimeoutMs` values are inside the
same proof window accepted by the release and handoff verifiers. The rollout
checker accepts those timing values only as plain positive decimal integers,
rejecting whitespace, control characters, fractions, and exponent notation
before SSH probing or public evidence writing.

## Umbrel Stores

The in-repo Umbrel package (`umbrel-app/`) is always updated with the new
image tag and digest.

The community Umbrel store checkout is updated automatically. Full releases
require repository secret `UMBREL_STORE_TOKEN` with push access to
`bigdestiny2/blindspark-umbrel-store`; prereleases skip the external store.

After metadata sync, the workflow runs `npm run umbrel:smoke-package` against
the newly pinned package. This is a Docker lifecycle smoke for the Umbrel
contract: app-proxy compose shape, no broad host access, dashboard/setup page,
management token, review-mode default, add-wallet API, service catalog,
service-selection API, dashboard WebSocket in-band auth, usage telemetry, and
persistence through a restart of the same `/data` bind mount.

When the community-store checkout is present, the workflow runs that repo's
own `npm run validate` gate after release metadata sync and before pushing.
That catches version/image-pin drift, broken listed gallery references,
symlinked gallery directories or assets, oversized gallery assets, wrongly
sized gallery images, public docs regressions, and stale jsDelivr asset anchors
while still permitting the documented first-submission `gallery: []` handoff.

Official Umbrel marketplace publication is still controlled by Umbrel review.
Use the synchronized `umbrel-app/` metadata as the source for the marketplace
PR against `getumbrel/umbrel-apps`.

The official package is kept in first-submission shape:

- `manifestVersion: 1.1`
- `gallery: []` and `releaseNotes: ""`
- no `icon:` field in the manifest
- `docker-compose.yml` uses `app_proxy`, a tag+digest-pinned multi-arch image,
  `${APP_DATA_DIR}/data:/data`, no raw host `ports:`, no host networking, no
  privileged mode, and no Docker socket mount
- `data/.gitkeep` exists for the bind-mount source directory
- `HIVERELAY_ACCEPT_MODE=review` is set so new seed requests queue for operator
  approval until the owner switches modes
- `HIVERELAY_MAX_STORAGE=10GB` is set as a conservative first-boot home-server
  cap; saved operator config wins on later restarts, and direct CLI/VPS
  operators can keep the core 50 GB default or pass `--max-storage`

Before opening the official PR, copy only `umbrel-app.yml`,
`docker-compose.yml`, and `data/.gitkeep` into `blindspark/` in a fork of
`getumbrel/umbrel-apps`. After the PR exists, replace
`submission: https://github.com/getumbrel/umbrel-apps/pull/PENDING` with the
real PR URL. The package validator accepts only that exact upstream PR URL
shape or the documented `PENDING` placeholder, and it requires empty
`releaseNotes` while the placeholder is still present. Runtime Umbrel testing
is still required before review: install or update through Umbrel, open
through `app_proxy`, confirm the review-mode default, complete setup/add-wallet,
observe setup/wallet/service/AI action-state feedback, restart, and confirm
identity/data persistence.

After that real-device review passes, write a public-safe manual evidence
sidecar:

```sh
npm run umbrel:write-runtime-review -- \
  --out umbrel-runtime-review-evidence.json \
  --release v0.16.3 \
  --device "<public device label>" \
  --umbrel-version <version> \
  --tested-by <public reviewer> \
  --public-key-before <hex> \
  --public-key-after <hex> \
  --checks installedThroughUmbrel,dashboardProxyLoads,liveFeedInBandAuth,noWebSocketUrlTokens,wizardCompletes,setupActionLockObserved,addWalletPersists,walletBusyStateObserved,managementActionsPersist,serviceActionStateObserved,serviceRestartPendingObserved,aiModelAddStateObserved,reviewModeDefault,dataWritableUid999,reinstallPreservesPublicKey
```

Then verify the sidecar before attaching or citing it:

```sh
npm run umbrel:verify-runtime-review -- \
  --evidence umbrel-runtime-review-evidence.json \
  --release v0.16.3
```

The writer rejects local URLs, LAN IPs, APP_SEED, bearer tokens, API keys, and
non-upstream PR URLs, and stores only a SHA-256 of the relay public key. The
verifier rejects missing, duplicate, failed, or unknown manual checks, raw public
key fields, release/PR drift, local details, and secret-looking strings. This
artifact is intentionally separate from the automated Docker smoke sidecar; it
is the proof surface for the real Umbrel UI lifecycle review. If
`umbrel-runtime-review-evidence.json` is present in a downloaded release handoff
bundle, `npm run release:verify-handoff-evidence -- --bundle-dir <dir>` also
validates it against the release version and upstream PR URL. Automated draft PR
creation still passes without that sidecar because the real-device review
happens later.

For the final review-ready Umbrel handoff, make that manual proof mandatory:

```sh
npm run release:verify-review-ready-handoff -- --bundle-dir <dir>
```

That stricter mode fails until `umbrel-runtime-review-evidence.json` is present
and passes the real-device setup/add-wallet/service-management lifecycle plus
setup/wallet/service/restart/AI action-state checks. It is a convenience alias for
`release:verify-handoff-evidence -- --require-umbrel-runtime-review`.

The helper command for a local official-store checkout is:

```sh
npm run umbrel:export-official -- \
  --target ../umbrel-apps/blindspark \
  --allow-placeholder
```

After opening the PR, stamp the real submission URL:

```sh
npm run umbrel:export-official -- \
  --target ../umbrel-apps/blindspark \
  --submission-url https://github.com/getumbrel/umbrel-apps/pull/<number>
```

The release workflow does this automatically as a draft PR for full releases.
After stamping the real PR URL, it runs the exporter in `--check` mode so the
`draft-pr-ready` evidence status cannot be recorded while the official
`blindspark/` package is stale or contains extra files. It also queries the PR
through `gh pr view` and requires the upstream PR to be `OPEN`, still marked as
draft, based on `master`, and pointed at the generated release branch before it
records release evidence. The official PR sidecar also records
`runtimeReview.status: pending-real-device-review` plus the expected
`umbrel-runtime-review-evidence.json` filename and
`npm run umbrel:verify-runtime-review` verifier command. This is intentional:
the automated release can open the draft PR and prove package smoke, but it must
not claim the human Umbrel UI lifecycle review has happened until the separate
runtime review artifact is generated and verified. That artifact must be bound
to the same upstream `getumbrel/umbrel-apps` PR URL, stores hashes of the relay
public key before and after reinstall, and the verifier requires those hashes
to match, so reviewers can see reinstall identity persistence without
publishing the raw relay key.
Configure:

- `UMBREL_OFFICIAL_PR_TOKEN` — a GitHub token that can push to the fork and open
  PRs against `getumbrel/umbrel-apps`.
- `UMBREL_OFFICIAL_FORK` — the fork repository, for example
  `bigdestiny2/umbrel-apps`. This must be a fork, not the upstream
  `getumbrel/umbrel-apps` repository.

The PR is created as a draft because the official store still expects runtime
Umbrel lifecycle review before submission. After release evidence is uploaded
and downloaded back for bundle verification, the workflow refreshes the draft
PR body with deterministic links to `release-evidence.json`,
`release-image-manifest-evidence.json`, `release-image-smoke-evidence.json`,
`umbrel-package-smoke-evidence.json`, `fleet-rollout-evidence.json`,
`blindspark.s9pk`,
`startos-registry-evidence.json`, and the release workflow run, so reviewer
handoff starts with live generated install/update, image-platform, raw-fleet,
and StartOS proof already attached. The body also names the dashboard WebSocket
URL-token rejection and in-band auth checks covered by the smoke sidecars, so
live-feed security is visible to reviewers instead of hidden in JSON. It then writes,
uploads, downloads, and byte-compares
`official-umbrel-pr-evidence.json` so the PR handoff itself has a public-safe
release asset. The handoff writer reuses the GitHub-reported PR state, draft
flag, base branch, head owner, head branch, and head OID recorded in the
release evidence, and validates those raw metadata values without trimming
whitespace before writing public evidence. The upstream PR URL must point to
`getumbrel/umbrel-apps`, but the head owner in release and handoff evidence
must be the configured fork owner, not `getumbrel`.

The automated `release:verify-handoff-evidence` gate checks that handoff sidecar
against the published release evidence, smoke sidecars, fleet rollout sidecar,
image-manifest sidecar/link, fleet rollout link, StartOS package link, StartOS
registry package link, StartOS registry evidence link, workflow URL, exact
upstream `getumbrel/umbrel-apps` PR URL, `OPEN`/draft state, `master` base
branch, and release head owner/branch/OID before the run finishes. The separate
review-ready invocation adds `--require-umbrel-runtime-review` so final Umbrel
handoff cannot pass with only the pending-review marker; use
`npm run release:verify-review-ready-handoff -- --bundle-dir <dir>` for that
final reviewer handoff.

## StartOS

`startos/manifest.yaml` and the StartOS README status line are synchronized on
every release. `startos/Makefile` derives its default `VERSION` from the root
`package.json`, while still allowing local `make VERSION=...` overrides. Full
releases require
`STARTOS_DEVELOPER_KEY_PEM`; prereleases may run `start-sdk init` to create an
ephemeral CI key for sideload-only artifacts. The StartOS entrypoint mirrors
the appliance posture used by Umbrel: review-mode first boot, simple dashboard,
and `HIVERELAY_MAX_STORAGE=10GB` as a conservative first-boot cap that yields
to saved operator config on later restarts. CI then runs the digest-pinned
package build:

```sh
HIVERELAY_IMAGE_DIGEST=sha256:<multi-arch-digest> npm run startos:verify
```

For non-release local mechanics checks only, `npm run startos:verify:local`
sets `ALLOW_TAG_ONLY_IMAGE=1` explicitly. Release packaging fails without
`IMAGE_DIGEST`.

The verified `startos/blindspark.s9pk` is uploaded to the GitHub Release, so
StartOS users can sideload the newest release directly. Full-release registry
publication requires:

- `STARTOS_DEVELOPER_KEY_PEM` — the PEM contents for
  `~/.embassy/developer.key.pem`.
- `STARTOS_REGISTRY_URL` — the registry location passed to
  `start-sdk publish <location> startos/blindspark.s9pk`.

Without those secrets, a full release fails the distribution preflight instead
of silently producing a sideload-only release. Prereleases can still build,
verify, and upload a sideload-only artifact.

After `start-sdk publish` succeeds, the workflow writes
`startos-registry-evidence.json` with the registry URL, derived public package
URL, package id, `.s9pk` SHA-256, release asset URL, release image manifest
evidence URL, release image smoke evidence URL, and workflow run URL. The
writer validates raw workflow, registry, package, hash, and linked evidence
metadata without trimming whitespace before writing public registry evidence.
`release-evidence.json` records that sidecar path and SHA-256, and the first
`release:verify-evidence` pass checks the sidecar hash plus its package,
registry, release, image-proof links, and workflow fields before any release
evidence is uploaded.
After the main release evidence assets have been uploaded and downloaded back
for bundle verification, it uploads the StartOS registry evidence file to the
GitHub Release, downloads it back, byte-compares it, and includes it in the
final `release:verify-handoff-evidence` check before continuing.

For local release reproduction after GHCR publish, pass the same digest CI
captured:

```sh
cd startos
make verify IMAGE_DIGEST=sha256:<multi-arch-digest>
```

## Local Use

Prepare a release locally after the GHCR image exists:

```sh
npm run release:prepare -- v0.16.4 \
  --channel both \
  --image-digest sha256:<multi-arch-digest>
```

Check for drift without writing:

```sh
npm run release:prepare -- v0.16.4 \
  --channel both \
  --image-digest sha256:<multi-arch-digest> \
  --check
```

Use `--channel canary`, `--channel stable`, or `--channel none` only for an
explicit staged/manual promotion that should differ from the published
full-release default. Pre-release tags default to `--channel none` and cannot
be prepared with a fleet/app-store promotion channel.

Smoke a pushed image locally when Docker can pull it:

```sh
npm run release:smoke-image -- \
  ghcr.io/bigdestiny2/p2p-hiverelay:0.16.4@sha256:<multi-arch-digest>
```

Verify the pushed image digest still exposes the required release platforms:

```sh
npm run release:check-image-manifest -- \
  --image ghcr.io/bigdestiny2/p2p-hiverelay:0.16.4@sha256:<multi-arch-digest> \
  --out release-image-manifest-evidence.json
```

Smoke the Umbrel package lifecycle after `release:prepare` has updated
`umbrel-app/docker-compose.yml`:

```sh
npm run umbrel:smoke-package -- \
  --image-ref ghcr.io/bigdestiny2/p2p-hiverelay:0.16.4@sha256:<multi-arch-digest>
```

Check raw fleet convergence from a workstation with SSH access:

```sh
npm run fleet:check-rollout -- \
  --target v0.16.4 \
  --channel both \
  --ssh-key ~/.ssh/cloudzy_hiverelay \
  --evidence fleet-rollout-evidence.json
```

The resulting `fleet-rollout-evidence.json` records only public-safe rollout
facts: target tag/SHA/version, channel, health/runtime convergence, the
remote package version, `fleet/relays.json` SHA-256, selected relay names,
and `channelConfig` proof for `fleet/channels.json`. It intentionally omits
relay hosts, SSH keys, and API keys. The release verifiers compare that
inventory digest, relay-name list, channel-config digest and targets,
package-version matches, runtime-version matches, and health state against the
checked-out release, so an incomplete sidecar or stale channel pointer cannot
stand in for full canary/stable convergence.

The workflow refuses to publish a release tag that is not an ancestor of
`main`. That keeps the built image reproducible from the GitHub release while
still letting later stable promotions commit channel metadata on top of the
current main branch.

Inspect a completed release evidence bundle:

```sh
mkdir -p startos
gh release download v0.16.4 --pattern '*evidence.json'
gh release download v0.16.4 --pattern 'blindspark.s9pk' --dir startos
npm run release:verify-evidence -- \
  --bundle-dir .
```

Inspect the post-release handoff evidence for a full release:

```sh
mkdir -p startos
gh release download v0.16.4 --pattern 'release-evidence.json'
gh release download v0.16.4 --pattern 'release-image-manifest-evidence.json'
gh release download v0.16.4 --pattern 'release-image-smoke-evidence.json'
gh release download v0.16.4 --pattern 'umbrel-package-smoke-evidence.json'
gh release download v0.16.4 --pattern 'official-umbrel-pr-evidence.json'
gh release download v0.16.4 --pattern 'startos-registry-evidence.json'
gh release download v0.16.4 --pattern 'blindspark.s9pk' --dir startos
npm run release:verify-handoff-evidence -- \
  --bundle-dir .
```

After `umbrel-runtime-review-evidence.json` is attached, run the stricter final
Umbrel reviewer handoff check:

```sh
npm run release:verify-review-ready-handoff -- --bundle-dir .
```
