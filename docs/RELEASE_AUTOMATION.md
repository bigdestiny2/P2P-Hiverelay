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
Public release notes and the official Umbrel PR body are intentionally scoped
to Core Availability / Blindspark. `npm run audit:release-promise` checks those
public handoff surfaces, and `prepare-release` rejects custom release notes
that recast the release as an AI, poker, custody, payment, ZK, arbitration, or
service-marketplace product.
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

Pre-releases are isolated by default, with ONE deliberate exception: the
community Umbrel store. A tag such as `vX.Y.Z-beta.1` or a GitHub Release marked
pre-release builds and pushes only its explicit image tag, uploads the StartOS
test package to that GitHub Release, and uses `channel=none`. It does not update
`latest`, fleet channels, official Umbrel fork metadata, or npm `latest`. The
workflow rejects prereleases if a channel other than `none` is requested.

The community Umbrel store (`bigdestiny2/blindspark-umbrel-store`) now
auto-syncs on EVERY release — prereleases included — whenever the
`UMBREL_STORE_TOKEN` repository secret is set, so it never lags the fleet. The
checkout, validate, and commit/push steps are gated on `UMBREL_STORE_TOKEN`
alone (no `is_prerelease` condition). The built multi-arch image digest still
flows into the store's `hiverelay-blindspark/docker-compose.yml` `@sha256` pin
on every sync. `release:prepare` mirrors this locally: a full release syncs the
store by default, and a prerelease syncs it when an explicit `--umbrel-store`
target is passed (the workflow passes it whenever the store checkout is
present). `--no-umbrel-store` always wins. Prereleases still do not move sibling
ecosystem app defaults or promote a fleet/app-store channel.

Full releases are distribution-complete by default. Before any public GitHub
Release is looked up, created, reused, or written to, the workflow requires the
masked repository values needed to publish the npm packages, verify the raw
fleet, push the Umbrel community store, open or update the official Umbrel draft
PR, and publish the StartOS registry package to pass the same full-release
preflight as
`release-distribution-preflight.yml`. Missing or malformed credentials fail the
run and record `distributionPreflight: failed` in release evidence.

## Maintenance-Release Lane

A patch cut from an older released tag (for example `v0.24.4` on
`release/v0.24.4` after `main` had moved on to the next train) is a
maintenance release: its tag is not an ancestor of `main`. The workflow's
Verify release ref gate rejects such tags on a normal run.

To release one, dispatch the workflow with the explicit `maintenance_branch`
input set to the branch carrying the tag (for example `release/v0.24.4`).
A maintenance release is never implicit — the branch comes only from the
dispatch input. The gate then accepts the tag only when:

- the tag is contained in the declared maintenance branch, and
- the branch forks from an already-released tag (everything before the fork
  point has already shipped).

If `maintenance_branch` is set but the tag is an ancestor of `main`, the run
fails: use a normal release. All evidence gates run unchanged; the only other
difference is that the release-surface sync commit pushes to the maintenance
branch instead of `main`, because pushing a maintenance tree to `main` would
rewind it to the older release line. `v0.24.4` (the release that promoted npm
`latest` off `0.20.2`) shipped through this lane.

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

For the historical `v0.20.2` issue #120 repair (resolved before the
0.24.x/0.26.0 trains), the last issue comment said the
repository secret names are present and only four masked values still have bad
shape: `UMBREL_STORE_TOKEN`, `UMBREL_OFFICIAL_PR_TOKEN`,
`UMBREL_OFFICIAL_FORK`, and `STARTOS_REGISTRY_URL`. Use the targeted mode so
the operator does not have to re-enter already-valid fleet, npm, ecosystem, or
StartOS private-key values:

```sh
npm run release:write-secret-template -- \
  --issue-120-repair \
  --out /private/tmp/hiverelay-release-secrets.env

$EDITOR /private/tmp/hiverelay-release-secrets.env

npm run release:check-distribution-env -- \
  --issue-120-repair \
  --env-file /private/tmp/hiverelay-release-secrets.env

npm run release:apply-github-secrets -- \
  --issue-120-repair \
  --repo bigdestiny2/P2P-Hiverelay \
  --env-file /private/tmp/hiverelay-release-secrets.env \
  --dry-run

npm run release:apply-github-secrets -- \
  --issue-120-repair \
  --repo bigdestiny2/P2P-Hiverelay \
  --env-file /private/tmp/hiverelay-release-secrets.env
```

In targeted mode the helper writes exactly those four repository Secrets. It
still refuses malformed GitHub tokens, still rejects `getumbrel/umbrel-apps`,
and still requires a public HTTPS StartOS registry URL. It canonicalizes
`UMBREL_OFFICIAL_FORK` to `owner/umbrel-apps` and
`STARTOS_REGISTRY_URL` to a trimmed public HTTPS base URL before writing.

The generated template is written with owner-only permissions and refuses to
overwrite an existing file unless `--force` is passed. The final edited file
should have this shape:

```sh
FLEET_SSH_PRIVATE_KEY<<FLEET_KEY
PASTE_THE_FULL_FLEET_PRIVATE_KEY_BLOCK_HERE
FLEET_KEY
UMBREL_STORE_TOKEN=PASTE_COMMUNITY_STORE_GITHUB_TOKEN_HERE
UMBREL_OFFICIAL_PR_TOKEN=PASTE_OFFICIAL_PR_GITHUB_TOKEN_HERE
ECOSYSTEM_CONSUMER_TOKEN=PASTE_ECOSYSTEM_APP_REPO_GITHUB_TOKEN_HERE
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
does not print the candidate values. `UMBREL_OFFICIAL_FORK` and
`STARTOS_REGISTRY_URL` are canonicalized before writing so copied GitHub fork
URLs or harmless trailing slashes do not cause another repair loop. Both
dry-run and apply output print the exact
`release:check-github-setup` and `gh workflow run
release-distribution-preflight.yml` commands to run next.

Expected shapes:

| Name | Shape |
| --- | --- |
| `FLEET_SSH_PRIVATE_KEY` | PEM/OpenSSH private key block without surrounding whitespace |
| `UMBREL_STORE_TOKEN` | GitHub token with push access to `bigdestiny2/blindspark-umbrel-store` |
| `UMBREL_OFFICIAL_PR_TOKEN` | GitHub token able to push the official-package fork and open/update `getumbrel/umbrel-apps` PRs |
| `ECOSYSTEM_CONSUMER_TOKEN` | GitHub token with push access to release-managed app consumer repos: PearBrowser desktop, PearPaste, p2pbuilders, Opengit, and anonGPT |
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
values are valid or that a release is live. When this setup check fails, it
prints the same safe repair path: generate `/private/tmp/hiverelay-release-secrets.env`,
validate it locally, apply the values through stdin, rerun the setup check, and
then rerun the side-effect-free masked-value preflight.

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

Before rerunning a public full release, or before calling a completed release
ready, use the read-only closure board. It does not publish, upload, set
secrets, update fleet metadata, or open PRs. It does authenticate read-only to
GitHub because stable/GA closure must live-bind the current Release and exact
Actions run/artifact; set `GH_TOKEN` with `actions:read` and `contents:read`.
It does not contact npm unless `--check-npm-live` is passed explicitly. With `--npm-latest-json`, the npm
proof is taken from a trusted offline fixture and the checker refuses incomplete
fixtures instead of falling through to a live lookup. Once the live registry
gate is green, write `npm-latest-evidence.json` beside the other downloaded
release assets:

```sh
npm run release:check-npm-latest -- \
  --expected-version 0.20.2 \
  --out npm-latest-evidence.json
```

The npm-latest command refuses to write that sidecar unless every package
`latest` tag is verified at the expected release version.

```sh
export GH_TOKEN=<read-only-github-token>
npm run release:check-blockers -- \
  --bundle-dir /path/to/downloaded-release-assets \
  --env-file /private/tmp/hiverelay-release-secrets.env \
  --npm-latest-json /private/tmp/hiverelay-npm-latest.json \
  --out release-blockers-report.json
```

The command aggregates the DMC-style public-release blockers into one
machine-readable board: clean worktree, side-effect-free distribution env,
npm `latest` via `npm-latest-evidence.json`, release evidence, GHCR image
manifest and image smoke, Umbrel package smoke, official Umbrel PR, real Umbrel
runtime review, StartOS registry publication, StartOS package artifact, fleet
rollout, and the strict review-ready handoff verifier. It exits non-zero until
every blocker has a present evidence file and the existing release/handoff
verifiers pass, including live closure verification. A coherent offline
`release-closure-evidence.json` bundle remains diagnostic only and cannot make
the board ready. The optional `--out release-blockers-report.json` file is a
public-safe diagnostic report of the current board, not a release proof; it can
be attached to handoff notes while blockers are still open. The printed and
written reports redact token-looking values across top-level paths, row details,
and command strings before they leave the process. Missing sidecar rows
prefer artifact-producing commands where the repo has one; for example, the
official Umbrel PR row points at
`npm run release:write-official-umbrel-pr-evidence -- --out official-umbrel-pr-evidence.json`,
image and Umbrel smoke rows use their `--evidence` writers, and fleet rollout
uses `--evidence fleet-rollout-evidence.json`. The final release and handoff
rows remain verifier commands because they validate the already-collected
bundle. `npm run release:check-official-umbrel-pr` remains the local
manifest/submission URL gate before the official PR sidecar can be written.
When checking a downloaded bundle, evidence entries must be regular files; the
closure board rejects symlinked or non-regular evidence candidates instead of
marking those rows present. JSON evidence sidecars must also be non-empty and
2 MiB or smaller, matching the public-safe evidence writer limit, and must
parse as JSON objects before the row can be marked present.

For development loops that intentionally carry a dirty audit branch, run
`npm run audit:owned-diff` before cutting a release branch. That command does
not satisfy the `worktree.clean` release blocker; it only proves every changed
or untracked path is mapped to a named audit-owned slice so the release branch
can be committed, reviewed, or split deliberately.

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
3. Installs dependencies and runs the blocking release gate: `npm audit`,
   `npm run lint`, `npm run audit:public-artifacts`,
   `npm run release:check-npm-packages`,
   `node --test test/unit/ecosystem-consumers.test.js`, and
   `npm run test:unit`. A real failure in any of these still fails the release.
   `npm run audit:workspace` runs SEPARATELY as an ADVISORY step
   (`continue-on-error`): it checks StartOS/Umbrel/docs version alignment and
   cross-repo drift — release hygiene, not code correctness or security — so it
   emits a `::warning::` annotation on drift but never aborts the image build or
   the community-store sync. Fix flagged alignment drift before the next stable.
   The public-artifact audit stays BLOCKING because it is a real secrets-leak
   scanner (GitHub tokens, private keys, Bearer tokens in README/docs/.github),
   not an alignment check. The public-artifact audit keeps release docs and
   workflows free of scanner-sensitive secret examples, the npm package dry-run
   gate proves the four publishable tarballs include README/license metadata
   without obvious unsafe paths, and the explicit ecosystem inventory guard
   keeps the release log tied to the PearBrowser, PearPaste, anonGPT, and other
   direct consumer default-pinning contract before any image is published.
4. For full releases, verifies the full sibling app workspace is present before
   any image or npm side effects, so app defaults cannot be silently skipped
   when PearBrowser, PearPaste, anonGPT, or another current consumer checkout is
   missing.
5. Publishes `p2p-hiverelay`, `p2p-hiverelay-client`,
   `p2p-hiverelay-verifier`, and `p2p-hiveservices` to npm from the tagged
   source, or leaves an already-published immutable tarball in place, then
   verifies every `latest` dist-tag equals the release semver through
   `npm run release:check-npm-latest`. This is the gate that lets PearBrowser,
   PearPaste, anonGPT, and other app consumers safely move from local workspace
   links to the published release line.
   A tagged **prerelease** publishes the same four packages under the `next`
   dist-tag and leaves `latest` untouched; only a stable tag moves `latest`.
   Branch candidates publish nothing. The evidence record carries the matching
   `published-next`/`current-next` status.
   npm package visibility and dist-tag readback are eventually consistent, so
   the workflow uses bounded exponential backoff for both phases. Every registry
   read and dist-tag mutation used by that gate, including the pre-publish
   existence probe, also has a 30-second timeout and is killed if it hangs. The
   release fails closed unless the registry returns the exact release version
   before any container or appliance work begins.
   The helper only runs `npm view` and `npm dist-tag add`; neither invokes
   package lifecycle scripts, so its direct-child kill cannot orphan a package
   script. The containing GitHub Actions step has a 120-minute outer timeout,
   which also bounds `npm publish`, its lifecycle scripts, and the complete
   four-package retry budget.
   This step runs **before** every container and appliance surface on purpose. It
   used to sit after the image smoke, which meant a Docker, StartOS, or Umbrel
   failure skipped npm entirely — that is how `0.24.2` built and signed a release
   image but never reached the registry.
   `npm run release:check-npm-packages` has already dry-run packed the same
   four workspaces before this publish step, so README/license metadata and
   unsafe-path checks fail before npm side effects.
   Operators can check the live registry gate without publishing by running
   `npm run release:check-npm-latest`; it fails until all four package `latest`
   dist-tags equal the monorepo release version, emits JSON with `-- --json`,
   and writes `npm-latest-evidence.json` with `-- --out` only when the proof is
   verified.
6. Builds and pushes the multi-arch GHCR image from the tagged source:
   `ghcr.io/bigdestiny2/p2p-hiverelay:<version>`. Full releases also update
   `latest`; prereleases do not.
7. Resolves the pushed multi-arch `sha256:` digest.
8. Verifies the exact pushed image reference (`<version>@sha256:...`) is a
   multi-platform OCI/Docker image index with `linux/amd64` and `linux/arm64`
   manifests, tolerating OCI attestation sidecars without counting them as
   runnable platform duplicates, then writes
   `release-image-manifest-evidence.json`.

Before cutting a release from a full sibling workspace, run
`npm run ecosystem:sync:local -- --check` and
`npm run audit:ecosystem-consumers:local` from the Hiverelay repo. That local
check proves PearBrowser, PearPaste, anonGPT, and the other direct consumers can
still follow the current checkout's package links, linked lockfile metadata, and
versioned source markers before npm publish. Full `release:prepare` runs default
to npm `latest` mode after the release workflow has promoted the npm packages.
For the pushable app repos only, `npm run ecosystem:sync:release -- --check`
and `npm run audit:ecosystem-consumers:release` run the same published-default
contract with `--consumer-scope release`.
The stable workflow checks out the release-managed app consumer repos
(`pearbrowser-desktop`, `pearpaste`, `p2pbuilders`, `Opengit`, and `anongpt`),
runs `npm run ecosystem:check-workspace -- --required --workspace-root .. --consumer-scope release`
before Docker or npm publication, then passes `--ecosystem-workspace-root ..`
and `--ecosystem-consumer-scope release` to release prep. After npm `latest` is
verified, it commits and pushes those app repo manifest, lockfile, and source
marker updates with `npm run ecosystem:commit-consumers`. Local-only POS,
Tickets, and test consumers remain covered by the local `all` scope audits but
do not block the remote customer release workflow. Stable release prep still
fails if the selected sibling app workspace is missing; use
`--no-ecosystem-consumers` only for sparse local checks or intentional
release-candidate skips. The audit proves there are no new unclassified
`p2p-hiverelay*` app pins.
9. Boots the exact pushed image reference (`<version>@sha256:...`) in Docker,
   waits for `/health`, verifies the Blindspark appliance dashboard and setup
   page, proves the home-server `HIVERELAY_ACCEPT_MODE=review` default,
   proves dashboard WebSocket URL-token rejection plus in-band auth, and checks
   the authenticated service-management and usage telemetry APIs.
10. Returns to `main`, then runs `npm run release:prepare -- vX.Y.Z --channel both
   --image-digest sha256:... --ecosystem-workspace-root .. --ecosystem-consumer-scope release --ecosystem-dependency-mode npm-latest`.
   In a full sibling workspace this switches tracked app manifests to npm
   `latest` and refreshes lockfiles from real registry metadata; before the npm
   gate is green, the default `ecosystem:sync` intentionally refuses to edit app
   defaults. To stage app defaults before the registry catches up, run
   `npm run ecosystem:prepare-latest`; it writes app manifests/source markers to
   `latest` and deliberately leaves lockfiles for the strict post-publish sync.
11. Commits and pushes changed release-managed app consumer repos with
   `ECOSYSTEM_CONSUMER_TOKEN`, so PearBrowser, PearPaste, p2pbuilders, Opengit,
   and anonGPT pull the newest Hiverelay npm line by default.
12. Boots the synchronized `umbrel-app/docker-compose.yml` package with the
   release image override, verifies the dashboard/setup pages, review-mode
   default, authenticated wallet save flow, service catalog, service-selection
   save flow, dashboard WebSocket in-band auth, usage telemetry, and data
   persistence across restart.
13. Configures a StartOS developer key, builds `startos/blindspark.s9pk` from
   the resolved GHCR digest, and verifies it with `start-sdk verify`. Full
   releases require `STARTOS_DEVELOPER_KEY_PEM`; prereleases may still use an
   ephemeral key for a sideload-only test artifact.
14. Uploads the verified `.s9pk` to the GitHub Release as a sideloadable
   StartOS package.
15. Commits the synchronized release surfaces back to `main`:
   workspace package versions, `package-lock.json`, README status, fleet
   channel, Umbrel metadata, and StartOS metadata.
16. Waits for the raw systemd relays on the promoted channel to converge on
    the release tag SHA, checked-out package version, and `/health`
    `running:true` with the release version.
17. Publishes the verified `.s9pk` to the configured StartOS registry with
    `start-sdk publish` and writes `startos-registry-evidence.json`.
18. Exports the official Umbrel package shape and opens or updates a draft PR
    against `getumbrel/umbrel-apps`.
19. Writes and uploads `release-evidence.json` plus public-safe image-manifest
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

The community Umbrel store checkout is updated automatically on EVERY release —
prereleases included — whenever repository secret `UMBREL_STORE_TOKEN` (push
access to `bigdestiny2/blindspark-umbrel-store`) is set, so the community store
never lags the fleet. The checkout, validate, and commit/push steps gate on
`UMBREL_STORE_TOKEN` alone; there is no `is_prerelease` condition on the
community store. Each sync bumps the store `package.json`/`umbrel-app.yml`
version and re-pins the `hiverelay-blindspark/docker-compose.yml` image to the
built multi-arch `@sha256` digest. Only the OFFICIAL Umbrel fork PR to
getumbrel/umbrel-apps and the npm `latest` publish remain non-prerelease-gated.
If `UMBREL_STORE_TOKEN` is unset, the store sync is skipped for that run.

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
  --release v0.20.2 \
  --device "<public device label>" \
  --umbrel-version <version> \
  --tested-by <public reviewer> \
  --public-key-before <hex> \
  --public-key-after <hex> \
  --checks installedThroughUmbrel,dashboardProxyLoads,liveFeedInBandAuth,noWebSocketUrlTokens,wizardCompletes,setupActionLockObserved,addWalletPersists,dynamicPayoutControlsObserved,walletBusyStateObserved,managementActionsPersist,serviceActionStateObserved,serviceRestartPendingObserved,aiModelAddStateObserved,reviewModeDefault,dataWritableUid999,reinstallPreservesPublicKey
```

Then verify the sidecar before attaching or citing it:

```sh
npm run umbrel:verify-runtime-review -- \
  --evidence umbrel-runtime-review-evidence.json \
  --release v0.20.2
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
setup/wallet/dynamic-payout/service/restart/AI action-state checks. It is a convenience alias for
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
records release evidence. For local handoff readiness, run
`npm run release:check-official-umbrel-pr`; it fails while
`umbrel-app/umbrel-app.yml` still has the `PENDING` submission URL and passes
only after a real `getumbrel/umbrel-apps` PR URL is stamped. The official PR
sidecar also records
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

### StartOS 0.4 package handoff

The TypeScript-SDK package in `startos-0.4/` remains isolated from the legacy
package above. It is not triggered directly by release publication. A separate
`dispatch-startos-04` job, with `needs: sync` and job-scoped `actions: write`,
dispatches it only after the source `sync` job succeeds. The dispatch uses the
exact release tag as both workflow ref and input and passes that
`release-surfaces` run id as runtime authority. The parent then waits, with a
bounded timeout, for the exact child run to succeed. A separate least-privilege
closure job then downloads the exact child's immutable Actions artifact,
independently inspects its package, compares it to current Release bytes, and
publishes the final closure certificate before the overall workflow can pass.

Before any signing key or package build, the downstream workflow verifies the
exact tag checkout, release evidence/tag-SHA agreement, the multi-arch image
digest and child digests, and the amd64/arm64 child config
`org.opencontainers.image.revision` labels. Release builds set
`REQUIRE_RELEASE_IMAGE_DIGEST=1`, and the packed manifest must contain the
same tag-plus-digest ref. Structured manifest inspection also requires the
exact authored StartOS id/version, its sole runtime-image key, and the expected
architecture set; unrelated text cannot satisfy the image-ref check.

An equivalent source-workflow rerun reuses the existing evidence-bound image
index from an earlier completed pre-handoff checkpoint and recreates only the
mutable tag alias. It does not rebuild a timestamp-bearing provenance index
under the same semver tag. This keeps the immutable StartOS package and sidecar
bound to one canonical multi-arch digest while still permitting recovery when
a prior parent run failed after that checkpoint.

The retry pointer is a single immutable, digest-bearing Actions artifact
uploaded immediately after local verification; mutable GitHub Release assets
are never reuse authority. The retry gate selects the exact non-expired REST
artifact for the tag/SHA, authenticates its numeric id, source run, archive
URL, size, ZIP SHA-256, and exact two-file inventory, then requires the embedded
run id/attempt to match. Before any retag or new signature, it verifies that
run id and URL name `.github/workflows/release-surfaces.yml` (with display name
`Release surfaces`) at the exact tag ref and tag SHA, that its event is `push`,
`release`, or `workflow_dispatch`, and that
exactly one `sync` job reached `completed` with every enumerated pre-handoff
checkpoint step successful. It then verifies the existing index signature against the exact
`release-surfaces.yml@refs/tags/<tag>` GitHub OIDC identity and issuer, and
live-inspects the evidence-bound amd64/arm64 child digests for the exact OS,
architecture, and `org.opencontainers.image.revision` source SHA. The `sync`
job or parent run may have failed after that durable checkpoint; terminal job
or whole-run success is deliberately not the reuse authority because it would
prevent safe recovery from a later transient failure.

The secret-bearing child does not run Start9's setup composite: that composite
calls mutable nested actions and downloads a live CLI before local
authentication. Required actions are pinned to full reviewed commit SHAs. The
workflow instead downloads the exact `start-cli 1.1.0` Linux asset from its
fixed release URL into a private temporary directory and verifies SHA-256
`70eff67b6e9a936acd8aaaf787b783819252ecedaa5c74d462e3b15ed4dd843a`
before `chmod`, PATH exposure, first execution, or developer-key exposure. The
lockfile-verified `npm ci` also completes before developer-key exposure. The
deterministic `startos-0.4-release-evidence.json` sidecar binds the tag SHA,
image ref/digest, per-platform child digests/revisions, pinned action/CLI/SDK
identities, package SHA-256, exact inspected manifest identity, and package
commitment. It excludes timestamps and mutable parent-run material, so an
equivalent retry remains verifiable. `start-cli 1.1.0` does not expose a signer
fingerprint through `s9pk inspect`; the sidecar records that limitation instead
of making an unproved signer claim.

The toolchain section is explicitly a declared source/workflow build contract
plus the current inspection runtime, not an assertion that a package embeds
verifiable original-build provenance. The `.s9pk` format/CLI exposes no such
provenance. The artifact proof is therefore its bytes, commitment, structured
manifest, and the exact successful child's immutable Actions artifact, while
the SDK/action/CLI pins describe the tag's required build contract.

Both `blindspark-startos-0.4.s9pk` and its sidecar are an immutable release
pair. Every child run installs the locked source dependencies and builds the
package again from the exact tag and authenticated toolchain. Existing Release
assets are compare-only: they can never be copied into a new trusted Actions
artifact. Reruns accept only one non-empty `uploaded` record of each name with
a valid GitHub SHA-256 digest, and the newly built bytes must match those
records exactly; they never delete or `--clobber` either asset. A package
without its sidecar, a sidecar without its package, duplicate names, a
zero-byte/`starter` record, or a source rebuild mismatch fails closed for
audited manual recovery. The child Actions artifact is populated only from the
fresh local build after that comparison.

`release-evidence.json` is a **pre-handoff checkpoint** certificate, not a
terminal `sync`-job or overall workflow-success claim. For a tag release it records
`checkpoint-passed-pending-sync-completion-and-startos-0.4-closure` and points to
`release-closure-evidence.json`. The child queries the exact recorded parent
run attempt and requires its `sync` job to be terminal and successful. Image
reuse queries that same exact attempt but requires the enumerated image-sign,
manifest, smoke, evidence-write, and local-verification steps to be successful,
while the independently authenticated artifact proves its own completed upload;
a later transient `sync` failure therefore
does not wedge the immutable image authority. Only after the exact child succeeds does the parent download
that child's non-expired, digest-bearing Actions artifact by numeric REST id,
authenticate the downloaded ZIP size and SHA-256 against that same REST record,
authenticate `start-cli`, independently inspect the `.s9pk` commitment and
structured manifest, and prove the artifact package/sidecar are byte-identical
to the current GitHub Release pair. It then publishes and verifies
`release-closure-evidence.json`, re-downloads the entire closure bundle, and
runs the live GitHub verifier. That verifier re-fetches every current Release
asset by numeric REST id and digest, authenticates the exact child run attempt,
downloads the exact non-expired artifact id, checks its REST ZIP size/digest
and inventory, requires the current GitHub tag to resolve to the recorded source
commit, and requires its bytes to equal the Release pair. After those checks it
re-fetches the Release and required asset inventory and requires every
id/state/size/digest/URL to remain unchanged, re-resolves the tag, and re-fetches
the exact Actions artifact record to reject deletion or expiry during the check.
The Release `draft`/`prerelease` state must exactly match the checkpoint evidence;
the stable blocker additionally supplies `--expected-prerelease false`, so a
prerelease certificate cannot clear GA. These terminal checks close the
download-window replacement race. Offline JSON
inspection is explicitly non-authoritative and cannot clear stable/GA. The
blocker board therefore requires `GH_TOKEN` and this live verifier. Each live
API/download/unzip subprocess is capped at 60 seconds, and the closure job has
an explicit 20-minute bound.

The public evidence upload itself remains a non-atomic multi-asset GitHub
Release update: `gh release upload --clobber` may replace only a subset before
failing. That public surface is therefore never the image-reuse pointer. The
prior immutable Actions artifact lets a retry restore and republish the same
source-bound digest and evidence. The artifact uses the repository's explicit
90-day retention boundary. If it has expired or been deleted after public
release state exists, the workflow fails closed for audited
recovery instead of rebuilding a different index beneath immutable packages.

The workflow is intentionally non-atomic: GHCR, npm, the legacy StartOS
package/registry, the StartOS 0.4 package/evidence Release pair, fleet channels,
and Umbrel/ecosystem metadata can already have changed before a downstream
closure failure. A failed closure therefore
leaves the parent red and blocks stable/GA completion; it does not claim that
earlier external writes were rolled back. The legacy `blindspark.s9pk` asset
contract remains unchanged.

Because GitHub loads a dispatched workflow and its scripts from `--ref`, these
controls can run only for a release tag that already contains them. They do not
retrofit the existing `v0.26.0-rc.3` tag; the first eligible release is the next
new tag cut from a commit containing this workflow. Moving an existing tag is
not an accepted recovery path. Manual runs must also load the workflow from the
exact tag, for example `gh workflow run release-surfaces.yml --ref vX.Y.Z -f
version=vX.Y.Z ...`; a branch-loaded dispatch fails before release writes.

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
  --ssh-key ~/.ssh/hiverelay_fleet \
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
