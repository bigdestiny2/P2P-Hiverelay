# Blindspark — StartOS package

StartOS (Start9) packaging for **Blindspark by HiveRelay**, mirroring
the [Umbrel package](../umbrel-app/): same multi-arch GHCR image, same
`/data` volume layout, same proxy-UI auth mechanism.

## How the pieces fit

| Piece | Role |
|---|---|
| `manifest.yaml` | StartOS package manifest (0.3.5.x schema) |
| `docker_entrypoint.sh` | Persists a seed on `/data` (StartOS has no `APP_SEED`), exports env, starts the relay |
| `check-web.sh` | Health check — dashboard reachable |
| `instructions.md` | Shown to users inside StartOS |
| `Makefile` | buildx per-arch tar → `start-sdk pack` → `blindspark.s9pk` |

The dashboard works behind StartOS's Tor/LAN proxy via the same
`HIVERELAY_UI_EXPOSE_TOKEN` mechanism built for Umbrel (v0.12.0): the
relay embeds a seed-derived bearer token in served HTML, so no
localhost assumption is needed. The seed lives at `/data/.app-seed` —
identity and token survive reinstalls with the data volume.

## Building

```bash
cd startos
make          # buildx per-arch image tars, render icon, start-sdk pack
make verify   # start-sdk verify s9pk blindspark.s9pk
```

Requirements: `docker` (with `buildx`), `start-sdk`, `rsvg-convert` (or
render `icon.png` manually from `../umbrel-app/icon.svg`, 256×256).

**Multi-arch:** `docker-images` is a directory (`image/`) of per-arch
tarballs — `x86_64.tar` and `aarch64.tar`. `make` builds each with
`docker buildx ... --output type=docker` (a legacy docker-archive with
`manifest.json`, which the 0.3.5.x reader requires — plain `docker save`
fails under Docker's containerd image store). At pack time `start-sdk`
writes a `multiarch.cbor` index (default `aarch64`); on install the
device extracts the tar for its CPU.

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

Note: `make` builds both architectures (x86_64 + aarch64) into the
`image/` directory, so the one packed s9pk installs on both.

## Before submitting to the Start9 registry

- [ ] Validate `manifest.yaml` against the current start-os schema
      (`start-sdk verify`) — field names here target 0.3.5.x and may
      need updates as StartOS evolves.
- [ ] `make verify` passes.
- [ ] Sideload `blindspark.s9pk` on a real StartOS device: wizard
      completes, dashboard authenticates over Tor and LAN, identity
      survives a reinstall, backup/restore round-trips.
- [ ] Health check goes green after first sync.
- [ ] Screenshots for the registry listing.
- [ ] Submit per https://docs.start9.com/ packaging guide
      (community registry PR or marketplace submission).

## Status

**Packs + verifies** with `start-sdk` 0.3.5.1 (multi-arch image, v0.16.3,
one-page dashboard via `HIVERELAY_UI_SIMPLE`). Not yet device-tested on
real StartOS hardware — the remaining checklist above (sideload, Tor/LAN
auth, reinstall identity, backup/restore) still needs a physical device.
The runtime mechanisms it relies on (token auth behind a proxy, seed
persistence, `/data` home) are the same ones verified end-to-end for the
Umbrel package.
