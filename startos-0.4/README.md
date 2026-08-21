# Blindspark — StartOS 0.4 package

The **StartOS 0.4** (TypeScript-SDK) build of Blindspark, the HiveRelay blind
relay appliance. This is the port of the legacy `../startos/` package (which
targets the **0.3.5.x** YAML-manifest format) to the 0.4 `@start9labs/start-sdk`
toolchain and the new signed `.s9pk` format.

The two packages are **separate distribution channels** and coexist during the
transition: keep shipping `../startos/blindspark.s9pk` to 0.3.x devices, and
the `blindspark-startos-0.4.s9pk` GitHub Release asset to 0.4 devices. The
different release filenames are intentional: the package formats are not
interchangeable.

## What it does (unchanged from 0.3.x)

- Runs the **same** published multi-arch image the Umbrel app and 0.3 package
  pin. Release packages use the immutable
  `ghcr.io/bigdestiny2/p2p-hiverelay:<version>@sha256:<digest>` ref; the plain
  semver tag remains only as the local authoring/mechanics default.
- Persists a 32-byte seed at `/data/.app-seed` (first boot generates, later
  boots reuse) → stable dashboard token + relay identity across reinstalls.
- Serves the single-page appliance dashboard on `9100`, fronted by StartOS
  over Tor/LAN.
- Safe defaults: `HIVERELAY_ACCEPT_MODE=review`, `HIVERELAY_MAX_STORAGE=10GB`.
- Backs up the `/data` volume; a restore brings the node back as itself.

## What changed for 0.4

| 0.3.5.x (`../startos/`) | 0.4 (this package) |
|---|---|
| `manifest.yaml` | `startos/manifest/index.ts` (`setupManifest`) |
| `docker-images:` dir of per-arch tarballs, `Dockerfile.retag`, buildx export | `images.blindspark.source.dockerTag` — start-cli pulls the registry image directly, **no rebuild/retag** |
| `docker_entrypoint.sh` baked into the image | inline `sh -c` seed-gen + `exec node …` in `startos/main.ts` (`exec.command` + `exec.env`) |
| `interfaces:` with `tor-config`/`lan-config` | `sdk.setupInterfaces` → `MultiHost.bindPort(9100)` + `createInterface({type:'ui'})` |
| `compat` + duplicity backup | `sdk.setupBackups(() => sdk.Backups.ofVolumes('main'))` |
| `start-sdk pack` | `npm run build` (ncc) → `start-cli s9pk pack` (via SDK `s9pk.mk`) |

## Build

Prerequisites: **Node.js**, **Docker** (to pull the image per arch), and
**`start-cli`** (StartOS 0.4 CLI — install the `.deb`, or `cargo install` from
`Start9Labs/start-os`; it carries its own `1.x` version line).

```sh
npm ci            # installs @start9labs/start-sdk 2.0.1 (brings in s9pk.mk)
make              # tsc check → ncc bundle → pack one universal .s9pk
```

`make` produces the predictable
local file `blindspark.s9pk` (multi-arch). The release workflow verifies it and
renames the uploaded 0.4 asset to `blindspark-startos-0.4.s9pk`, preserving the
legacy 0.3.x release asset name `blindspark.s9pk`. Verify / inspect a local build
with:

```sh
start-cli s9pk inspect blindspark.s9pk commitment
start-cli s9pk inspect blindspark.s9pk manifest
```

Sideload for testing: upload the `.s9pk` from your StartOS UI
(**System → Sideload Service**), or `start-cli` against your server.

Release packaging is deliberately stricter. It succeeds only with the digest
from the successful `release-surfaces` run:

```sh
make universal \
  REQUIRE_RELEASE_IMAGE_DIGEST=1 \
  IMAGE_DIGEST=sha256:<multi-arch-digest>
```

The Makefile exports the resulting tag-plus-digest ref to the TypeScript
manifest. CI then inspects the packed manifest and rejects a package that does
not contain that exact ref.

## Releasing a new version

Bump **both** in lockstep with the HiveRelay monorepo version:

1. `startos/manifest/index.ts` → `images.blindspark.source.dockerTag` image tag.
2. `startos/versions/current.ts` → `version` (`MAJOR.MINOR.PATCH:BUILD`) and
   add a prior entry to `startos/versions/index.ts`'s `other: []` if migrating
   from an earlier **0.4** build.

Do not run this release package from a release-published event directly.
`release-surfaces.yml` has a separate `dispatch-startos-04` job with
`needs: sync`; only that least-privilege job can dispatch this workflow. It
passes the exact successful source run id and uses the release tag itself as
the workflow ref. A deliberate manual retry must do the same:

```sh
gh workflow run release-startos-0.4.yml \
  --ref vX.Y.Z \
  --raw-field tag=vX.Y.Z \
  --raw-field release_surfaces_run_id=<successful-release-surfaces-run-id>
```

Before any developer key or build step, the workflow resolves
`refs/tags/vX.Y.Z`, checks out that exact tag, proves
`HEAD == refs/tags/vX.Y.Z^{commit}`, verifies exactly one `sync` job in the
source release run completed successfully, and binds its
release/image-manifest evidence to the tag SHA. The parent run may still be in
progress because it waits for this child; requiring the whole parent to finish
would deadlock. The child also inspects the amd64 and arm64 image configs and requires each
`org.opencontainers.image.revision` label to equal the tag commit.

The secret-bearing job does not execute Start9's setup composite, because that
composite calls mutable nested actions and downloads a live CLI before local
authentication. Required checkout/artifact actions are pinned to full reviewed
commit SHAs. CI downloads the exact `start-cli 1.1.0` Linux asset from its fixed
release URL and requires SHA-256
`70eff67b6e9a936acd8aaaf787b783819252ecedaa5c74d462e3b15ed4dd843a`
before chmod, PATH exposure, first execution, or developer-key exposure. The
lockfile-verified `npm ci` also completes before key exposure. The package lock
pins `@start9labs/start-sdk` to `2.0.1`; the manifest, lock root,
resolved tarball, and integrity must all agree. These identities are recorded
in the sidecar as the source/workflow build contract and current inspection
runtime: the package format does not embed enough information to prove its
original build toolchain.

Published 0.4 assets are an immutable package/evidence pair. A retry accepts
them only as compare-only state. Every child still installs the locked source
dependencies and builds from the exact tag with the authenticated toolchain;
public Release bytes are never copied into a trusted Actions artifact. Exactly
one non-empty `uploaded` record of each name must have a valid GitHub SHA-256
digest and match the new source-built bytes. Package-only or sidecar-only
recovery, duplicate names, zero-byte/`starter` records, and rebuild drift fail
closed for audited manual recovery; the workflow never deletes or clobbers an
existing 0.4 asset. The child then uploads only its fresh local package and
sidecar to the run/attempt-named, digest-bearing Actions artifact.

Equivalent source reruns reuse the prior completed release checkpoint's canonical image
digest instead of rebuilding a potentially different provenance-bearing index.
The pointer is a single immutable, digest-bearing Actions artifact uploaded
after local evidence verification; the non-atomic public Release evidence
update is never trusted as that pointer. CI authenticates the artifact's exact
REST id/source/size/ZIP digest/inventory, binds its embedded prior Actions run
attempt to the exact release-surfaces workflow path/tag/SHA/event, and requires the enumerated image/evidence
checkpoint steps to have succeeded. The artifact's verified REST record and
ZIP bytes prove the upload itself without depending on the action's terminal
client-side conclusion. This permits recovery from a later
transient `sync` failure or partial public evidence replacement. CI then verifies the
keyless signature against the exact release-workflow tag identity, hashes the
live raw index and binds its exact amd64/arm64 descriptor digests, then checks
both child configs for the source revision. Any semantic mismatch fails closed.
The authority artifact has an explicit 90-day retention boundary. If it has
expired or been deleted after public release state exists, CI requires audited
recovery rather than silently rebuilding a different index beneath an
immutable package.

The parent dispatcher waits up to its bounded timeout for the exact child run.
It passes the exact parent run attempt and numeric id of a separate,
run/attempt-named image-authority artifact. Before exporting image environment,
the child authenticates that artifact's parent path/event/tag/SHA/checkpoints,
REST record and exact two-file ZIP. Public checkpoint JSON is compare-only. It
then verifies the exact-tag keyless signature, raw-index hash and amd64/arm64
membership, plus both child revision labels before any package key or build.
Its final closure job installs the same hash-authenticated CLI, downloads the
exact image-authority and immutable child Actions artifacts by numeric REST id,
authenticates both ZIPs' size/SHA-256, independently inspects the `.s9pk`
commitment and structured manifest, and proves the artifact bytes match the
current GitHub Release package/sidecar pair. It then publishes
`release-closure-evidence.json`, re-downloads the complete published bundle,
and runs live GitHub closure verification. That mode re-fetches current Release
assets by exact REST id/digest, authenticates the exact parent and child run
attempts/workflow paths (including an exact-tag qualifier when the API supplies
one), downloads both exact artifact ids, verifies their REST
ZIP size/digest/inventory, resolves the current tag to the recorded source
commit, and compares their files with the Release checkpoint/pair. A final
inventory re-fetch requires
the Release id, exact draft/prerelease policy, and each required asset
id/state/size/digest/URL to remain unchanged after verification; it also
revalidates both exact artifact records, terminal-success parent run, and tag
commit. The in-parent check permits that same parent to be in progress; later
stable checks require it to have completed successfully. The stable blocker passes
`--expected-prerelease false`, so prerelease proof cannot clear GA. Offline JSON-only
verification is explicitly non-authoritative and cannot clear stable/GA. The earlier
`release-evidence.json` describes
only a pre-handoff checkpoint, not terminal `sync` success, and explicitly remains
`checkpoint-passed-pending-sync-completion-and-startos-0.4-closure`; stable/GA blocker checks require the
final closure certificate, so the release cannot be reported complete while
the child is missing or failed.

Release publication is non-atomic. GHCR, npm, the legacy StartOS path, the
StartOS 0.4 package/evidence Release pair, fleet channels, and Umbrel/ecosystem
metadata may already have changed before a closure failure. Such a failure
leaves the parent red and blocks stable/GA closure; it
does not roll back or claim success for those earlier external writes.

The workflow must already exist in the tag used as `--ref`. These controls
cannot be used to retrofit `v0.26.0-rc.3`, whose tag predates them; use the next
new release tag containing this implementation rather than moving an existing
tag. Manual parent dispatches must likewise use that exact tag as `--ref`; a
branch-loaded dispatch is rejected before release writes.

`start-cli 1.1.0` exposes the package root sighash/max-size commitment, but no
signer identity or public-key fingerprint through `s9pk inspect`. The sidecar
therefore binds the exact inspected commitment output and artifact SHA-256 and
records the signer-identity limitation explicitly; it does not claim a signer
fingerprint or embedded original-build provenance that the pinned CLI cannot
prove.

## Self-updating (roadmap)

Today, appliance relays are updated by reinstalling/upgrading the package
through the StartOS registry (StartOS 0.4's signed-`.s9pk` + partial-download
mechanism), the same operator-driven path as 0.3.x. The HiveRelay roadmap is to
add **Pear-runtime OTA self-update** (`upgrade: pear://…`) so a relay pulls
signed updates over pure P2P without a full package reinstall — gated behind the
Corestore-6→7 storage-engine migration it depends on. Until then, StartOS
registry upgrades remain the update channel for this package.
