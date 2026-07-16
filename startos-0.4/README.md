# Blindspark — StartOS 0.4 package

The **StartOS 0.4** (TypeScript-SDK) build of Blindspark, the HiveRelay blind
relay appliance. This is the port of the legacy `../startos/` package (which
targets the **0.3.5.x** YAML-manifest format) to the 0.4 `@start9labs/start-sdk`
toolchain and the new signed `.s9pk` format.

The two packages are **separate distribution channels** and coexist during the
transition: keep shipping `../startos/blindspark.s9pk` to 0.3.x devices, and
this one to 0.4 devices.

## What it does (unchanged from 0.3.x)

- Runs the **same** published multi-arch image the Umbrel app and 0.3 package
  pin: `ghcr.io/bigdestiny2/p2p-hiverelay:<version>`.
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
npm ci            # installs @start9labs/start-sdk 2.0.5 (brings in s9pk.mk)
make              # tsc check → ncc bundle → pack one x86_64 + aarch64 s9pk
```

`make` produces `blindspark.s9pk` (multi-arch). Verify / inspect with:

```sh
start-cli s9pk verify blindspark.s9pk
start-cli s9pk inspect blindspark.s9pk
```

Sideload for testing: upload the `.s9pk` from your StartOS UI
(**System → Sideload Service**), or `start-cli` against your server.

## Releasing a new version

Bump **both** in lockstep with the HiveRelay monorepo version:

1. `startos/manifest/index.ts` → `images.blindspark.source.dockerTag` image tag.
2. `startos/versions/current.ts` → `version` (`MAJOR.MINOR.PATCH:BUILD`) and
   add a prior entry to `startos/versions/index.ts`'s `other: []` if migrating
   from an earlier **0.4** build.

## Self-updating (roadmap)

Today, appliance relays are updated by reinstalling/upgrading the package
through the StartOS registry (StartOS 0.4's signed-`.s9pk` + partial-download
mechanism), the same operator-driven path as 0.3.x. The HiveRelay roadmap is to
add **Pear-runtime OTA self-update** (`upgrade: pear://…`) so a relay pulls
signed updates over pure P2P without a full package reinstall — gated behind the
Corestore-6→7 storage-engine migration it depends on. Until then, StartOS
registry upgrades remain the update channel for this package.
