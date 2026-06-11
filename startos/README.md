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
| `Makefile` | pull image → `start-sdk pack` → `blindspark.s9pk` |

The dashboard works behind StartOS's Tor/LAN proxy via the same
`HIVERELAY_UI_EXPOSE_TOKEN` mechanism built for Umbrel (v0.12.0): the
relay embeds a seed-derived bearer token in served HTML, so no
localhost assumption is needed. The seed lives at `/data/.app-seed` —
identity and token survive reinstalls with the data volume.

## Building

```bash
cd startos
make          # pulls ghcr image, renders icon, start-sdk pack
make verify   # start-sdk verify s9pk blindspark.s9pk
```

Requirements: `docker`, `start-sdk`, `rsvg-convert` (or render
`icon.png` manually from `../umbrel-app/icon.svg`, 256×256).

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

Scaffold — **not yet packed or device-tested**. The runtime mechanisms
it relies on (token auth behind a proxy, seed persistence, `/data`
home) are the same ones verified end-to-end for the Umbrel package in a
container simulation on 2026-06-11.
