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

The Start9 setup action is pinned to reviewed commit
`21507e89e717a303cb1064ac4c853d28b96d323b`. Because that action installs the
newest matching CLI asset rather than accepting a version/checksum input, CI
immediately requires `start-cli 1.1.0` and SHA-256
`70eff67b6e9a936acd8aaaf787b783819252ecedaa5c74d462e3b15ed4dd843a`
before the signing key is configured. The package lock pins
`@start9labs/start-sdk` to `2.0.1`; all three toolchain identities are recorded
in the release sidecar. They are labelled as the source/workflow build contract
and current inspection runtime: the package format does not embed enough
information to prove the original build toolchain of a recovered package.

Published 0.4 assets are immutable. A retry accepts an existing package only
after structured inspection proves its exact service id, authored package
version/build, sole runtime image ref and architecture set, and after its
commitment, package SHA-256, and deterministic
`startos-0.4-release-evidence.json` sidecar match. If the package exists but
the sidecar is missing, CI inspects the existing package and writes the missing
sidecar without rebuilding or replacing package bytes. Equivalent source
reruns reuse the prior successful sync job's canonical image digest instead of
rebuilding a potentially different provenance-bearing index. Any semantic mismatch,
or an orphaned sidecar without its package, fails closed.

The parent dispatcher waits up to its bounded timeout for the exact child run
and then downloads and verifies the source evidence, image-manifest evidence,
0.4 package, and 0.4 sidecar. A release-surfaces run therefore cannot report
success while the StartOS 0.4 closure is missing or failed.

The workflow must already exist in the tag used as `--ref`. These controls
cannot be used to retrofit `v0.26.0-rc.3`, whose tag predates them; use the next
new release tag containing this implementation rather than moving an existing
tag.

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
