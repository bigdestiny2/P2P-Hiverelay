# Blindspark by HiveRelay — Umbrel App Store package

> **Version boundary:** the stable HiveRelay baseline is `v0.24.3`; this
> directory on `main` also receives candidate appliance work. Use the
> [stable guide](../docs/STABLE-0.24.3.md) and its immutable container digest
> when stable behavior is required. A manifest version on `main` is not by
> itself a stable store publication.

This directory packages [HiveRelay](https://github.com/bigdestiny2/p2p-hiverelay)
as an Umbrel app: **Blindspark**, a blind relay for the Pear / Holepunch
peer-to-peer ecosystem. It seeds encrypted Hyperdrives the relay can verify
and serve but cannot read, keeping P2P apps reachable and powering blind
social recovery.

There is **no Lightning / earning component** — it is a blind availability
node, full stop.

## What's in here

| File | Purpose |
|------|---------|
| `umbrel-app.yml` | App Store manifest (id, category, description, gallery). |
| `docker-compose.yml` | Service definition Umbrel runs. Wraps the published multi-arch image. |
| `data/.gitkeep` | Empty app-data bind mount source for the official package. |
| `icon.svg` | App icon kept here for handoff; official store assets are committed by Umbrel. |
| `gallery/` | Screenshot shot list for handoff; official gallery assets are committed by Umbrel. |
| `SUBMISSION-CHECKLIST.md` | Pre-submission gate for the `getumbrel/umbrel-apps` PR. |

## How auth works behind Umbrel's proxy

The relay's management API (dashboard + first-run wizard) is normally
localhost-only. Behind Umbrel's `app_proxy` the request arrives from the
proxy's address, not localhost, so that check can't apply.

This package sets `HIVERELAY_UI_EXPOSE_TOKEN=true`. In that mode the relay
derives a stable management token from Umbrel's `$APP_SEED`, embeds it in
the dashboard/wizard HTML it serves, and the bundled UI sends it back as
`Authorization: Bearer`. The security boundary is Umbrel's authenticated
app proxy plus the fact that the relay's port is **never published to the
host/LAN** — only the proxy can reach it. See
`packages/core/config/default.js` → `ui.exposeToken` for the full contract.

The package also sets `HIVERELAY_ACCEPT_MODE=review` and
`HIVERELAY_MAX_STORAGE=10GB` for first boot, plus the operator-declared
`HIVERELAY_CAPACITY_PROFILE=edge-community` planning profile. That keeps
home-server installs operator-reviewed and capped conservatively, while any
saved operator config wins on later restarts. PC/VPS operators can keep the core
50 GB default or pass `--max-storage` directly.

`HIVERELAY_MAX_STORAGE` bounds **managed** capacity. The declared profile then
narrows new adoption to its durable share, so the stock package holds at most
**3.5 GB of durable payload** inside its 10 GB managed cap; the remainder is
budgeted for the cache, repair, and service pools. Raise `HIVERELAY_MAX_STORAGE`
if you want a larger durable budget, and read
`capacity.enforcement.effectiveCapBytes` from `/status` to see the limit that
actually binds. The profile still does **not** claim separate physical
enforcement for each planned pool — only the durable ceiling is enforced. See
`docs/BOUNDED-CAPACITY-HARDWARE-ROADMAP.md`.

The ordinary Umbrel package is the **edge/community** profile, not a service
farm. Its Services layer and all packaged utility-service flags start disabled,
so installing Blindspark does not silently add persistent outbox, notification,
shard-store, proof, VRF, or witness workloads alongside relay storage. An owner
can explicitly select services in the dashboard and restart after checking the
box's available storage and memory. That saved selection is an operator choice;
it is not part of the package default.

## Run it on your own Umbrel today (before the App Store listing)

You don't have to wait for the store. On the box:

```bash
# 1. Pull the stable v0.24.3 image by immutable multi-arch digest.
docker pull ghcr.io/bigdestiny2/p2p-hiverelay:0.24.3@sha256:cb104aa65d7e8f57766ea7d60d64dbb6b081a0b9fc5b318c0fa75cb22c0d31c8

# 2. Install as a local/community app via umbreld, or run the compose
#    directly with APP_DATA_DIR + APP_SEED set. Preserve the digest pin;
#    candidate or floating tags are not the stable artifact.
```

The first-run wizard is at the app's dashboard once it's running.

## Submitting to the Umbrel App Store

Work `SUBMISSION-CHECKLIST.md` top to bottom. The short version:

1. Capture real gallery screenshots and keep the icon ready for reviewer handoff.
2. Keep the image tag and sha256 digest pin in `docker-compose.yml` aligned with
   the release you are submitting.
3. Fork `getumbrel/umbrel-apps`, drop this directory in as `blindspark/`,
   including only `umbrel-app.yml`, `docker-compose.yml`, and
   `data/.gitkeep`. Open the PR and record its URL in `umbrel-app.yml`
   (`submission:`).

The `.github/workflows/umbrel-app-validate.yml` workflow checks the
manifest and compose on every change here. It permits the documented
first-submission `gallery: []` handoff, and once gallery filenames are listed it
requires safe numbered PNG/JPEG filenames, existing files, and 1440x900
dimensions so broken or wrongly sized screenshots do not reach the upstream PR.
