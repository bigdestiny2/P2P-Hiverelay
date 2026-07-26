# Blindspark for StartOS

A **blind relay** for the Pear / Holepunch peer-to-peer app ecosystem,
packaged for [StartOS](https://start9.com) (Start9). Blindspark seeds
end-to-end-encrypted Hyperdrives — content it can verify and serve but
**cannot read** — so P2P apps stay reachable while their authors and
users are offline.

- **Repo:** https://github.com/bigdestiny2/P2P-Hiverelay
- **Releases (.s9pk downloads):** https://github.com/bigdestiny2/P2P-Hiverelay/releases
- **License:** Apache-2.0 · no account, no telemetry, no payment

---

## Install on StartOS

### Option A — Sideload (works today)

1. Download `blindspark.s9pk` from the
   [latest release](https://github.com/bigdestiny2/P2P-Hiverelay/releases/latest).
2. In your StartOS dashboard, go to **System → Sideload Service** and
   drop the `.s9pk` file in.
3. Open **Services → Blindspark → Start**.

The package is multi-arch — the same `.s9pk` installs on both x86_64 and
aarch64 (ARM) devices; StartOS picks the right image automatically.

### Option B — Custom registry

If you host the package in a registry, users add it once via
**Marketplace → Change → Add custom registry** and then install/update
Blindspark like any other service. See
[Managing Service Registries](https://docs.start9.com/0.3.5.x/user-manual/alt-registries).

### First run

1. Open the **Blindspark Dashboard** from the service's UI button.
2. A short wizard names your relay and lets you choose how it accepts
   seed requests (review each one, or auto-accept).
3. That's it — the one-page dashboard shows your relay's name and public
   key, live status, connected peers, how many apps it keeps alive, and
   real on-disk storage usage.

Your relay identity and dashboard token derive from a seed stored on the
service's data volume, so the node comes back as itself across reinstalls
and a backup/restore round-trip. Fresh installs start in review mode and
use a conservative 10 GB storage cap; saved operator config wins on later
restarts.

---

## How the package fits together

| Piece | Role |
|---|---|
| `manifest.yaml` | StartOS package manifest (0.3.5.x schema) |
| `docker_entrypoint.sh` | Persists a seed on `/data` (StartOS has no `APP_SEED`), exports env, starts the relay |
| `check-web.sh` | Health check — dashboard reachable |
| `instructions.md` | Shown to users inside StartOS |
| `Makefile` | buildx per-arch tar → `start-sdk pack` → `blindspark.s9pk` |

The dashboard works behind StartOS's Tor/LAN proxy via the same
`HIVERELAY_UI_EXPOSE_TOKEN` mechanism built for Umbrel: the relay embeds
a seed-derived bearer token in served HTML, so no localhost assumption is
needed. The seed lives at `/data/.app-seed`. The entrypoint also sets
`HIVERELAY_UI_SIMPLE` so StartOS serves the single-page appliance
dashboard (no operator-only tabs, no Docs/GitHub), plus
`HIVERELAY_ACCEPT_MODE=review` and `HIVERELAY_MAX_STORAGE=10GB` as
first-boot home-server defaults.

---

## Build from source

```bash
cd startos
make digest                                      # print the published multi-arch manifest digest for the current VERSION
make IMAGE_DIGEST=sha256:<multi-arch-digest>    # buildx per-arch image tars, render icon, start-sdk pack
make verify IMAGE_DIGEST=sha256:<multi-arch-digest>
```

Requirements: `docker` (with `buildx`), `start-sdk`, `rsvg-convert` (or
render `icon.png` manually from `../umbrel-app/icon.svg`, 256×256).

**Pinning the image (`IMAGE_DIGEST`):** the retag `FROM` is pinned to the
`:$(VERSION)` tag's **multi-arch manifest (OCI image-index) digest** — NOT a
per-arch layer/blob digest. Get the right one with `make digest` (it runs
`docker buildx imagetools inspect` and prints the top-level `Digest:`). Do
**not** grab the first `sha256:` out of a CI log — that's usually a blob, and
the `FROM` then fails to resolve (`not found`). `make` runs `check-digest`
before building: it fails fast if the pinned `IMAGE_DIGEST` doesn't match the
tag's manifest — catching both a wrong digest and a **stale** one left over
from a previous `VERSION` (which would otherwise silently build the wrong
image). To skip the pin for a local mechanics check only, build with
`make ALLOW_TAG_ONLY_IMAGE=1 IMAGE_DIGEST=`. That path still pulls the
published `ghcr.io/bigdestiny2/p2p-hiverelay:$(VERSION)` tag, so it fails
until the current release image exists and is not release evidence.

**Multi-arch:** `docker-images` is a directory (`image/`) of per-arch
tarballs — `x86_64.tar` and `aarch64.tar`. `make` builds each with
`docker buildx ... --output type=docker` (a legacy docker-archive with
`manifest.json`, which the 0.3.5.x reader requires — plain `docker save`
fails under Docker's containerd image store). At pack time `start-sdk`
writes a `multiarch.cbor` index (default `aarch64`); on install the
device extracts the tar for its CPU.

The build reuses the published multi-arch GHCR image
(`ghcr.io/bigdestiny2/p2p-hiverelay`, the same one the Umbrel app pins)
rather than rebuilding. On each release, `npm run release:prepare` keeps the
root package version, `manifest.yaml`, Umbrel image pin, fleet metadata, and
store metadata aligned. Set `IMAGE_DIGEST` to the published top-level manifest
digest when building the StartOS package; `check-digest` keeps that pin honest
at build time.

### Building start-sdk itself (macOS, verified 2026-06-11)

There is no prebuilt macOS binary; compile from the official repo
(the 0.3.5.x SDK is the `startbox` binary behind an argv0 symlink):

```bash
git clone --depth 1 --branch v0.3.5.1 --recurse-submodules \
  https://github.com/Start9Labs/start-os.git /tmp/start-os
cd /tmp/start-os
mkdir -p web/dist/static && touch web/dist/static/.keep   # build stubs the
git rev-parse HEAD > GIT_HASH.txt                          # Makefile normally makes
rustup toolchain install 1.78.0   # newer rustc breaks the pinned `time` crate
cd core/startos
cargo +1.78.0 install --path . --bin startbox \
  --no-default-features --features cli,sdk --locked
ln -sf ~/.cargo/bin/startbox ~/.cargo/bin/start-sdk
start-sdk init   # generates ~/.embassy/developer.key.pem (signing key)
```

---

## Distributing it

Three paths, smallest to widest reach:

1. **Sideload** — host `blindspark.s9pk` on a GitHub Release and have
   people sideload it (Option A above). Best for testing and early users.
2. **Your own registry** — host the `.s9pk` yourself (even on a Start9
   server over Tor), or run a full registry
   ([Start9Labs/registry](https://github.com/start9labs/registry)) and
   publish with `start-sdk publish <registry> blindspark.s9pk`. Users add
   your registry URL.
3. **Official Start9 marketplace / Community Registry** — email
   **submissions@start9.com** with a link to this public repo. Start9
   snapshots it, reviews code + security, builds from these `make`
   scripts, and tests on their hardware (including a low-resource Pi)
   before publishing to the Community Beta Registry, then production on
   request. See the
   [submission docs](https://docs.start9.com/0.3.5.x/developer-docs/submission).

## Before submitting to the Start9 registry

- [ ] `make verify IMAGE_DIGEST=sha256:<multi-arch-digest>` passes against the
      published release image. Current `v0.20.2` verification is blocked until
      `ghcr.io/bigdestiny2/p2p-hiverelay:0.20.2` resolves.
- [ ] Sideload `blindspark.s9pk` on a real StartOS device: wizard
      completes, dashboard authenticates over Tor and LAN, identity
      survives a reinstall, backup/restore round-trips.
- [ ] Health check goes green after first sync.
- [ ] Screenshots for the registry listing.
- [ ] Submit per the docs above.

## Status

Package source targets multi-arch image tarballs (x86_64 + aarch64),
v0.25.0-rc.3, one-page dashboard via `HIVERELAY_UI_SIMPLE`, review-mode first boot,
and a first-boot-only 10 GB storage cap. Current `v0.20.2` package verification
is externally gated on the published GHCR image/tag and digest; once that image
exists, `make verify IMAGE_DIGEST=sha256:<multi-arch-digest>` is the release
gate. Not yet device-tested on real StartOS hardware; the checklist above is
the remaining work. The runtime mechanisms it relies on (token auth behind a
proxy, seed persistence, `/data` home) are the same ones verified end-to-end for
the Umbrel package.
