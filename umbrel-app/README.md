# Blindspark by HiveRelay — Umbrel App Store package

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
| `icon.svg` | App icon — **placeholder**, replace before submission. |
| `gallery/` | Screenshots for the store listing — **placeholders**, replace before submission. |
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

## Run it on your own Umbrel today (before the App Store listing)

You don't have to wait for the store. On the box:

```bash
# 1. Pull the published image (multi-arch; works on Pi/arm64 and x86/amd64)
docker pull ghcr.io/bigdestiny2/p2p-hiverelay:0.12.0

# 2. Install as a local/community app via umbreld, or run the compose
#    directly with APP_DATA_DIR + APP_SEED set. The bare :0.12.0 tag is
#    fine for a personal install (the sha256 digest pin is only an App
#    Store review requirement).
```

The first-run wizard is at the app's dashboard once it's running.

## Submitting to the Umbrel App Store

Work `SUBMISSION-CHECKLIST.md` top to bottom. The short version:

1. Replace `icon.svg` and the `gallery/` screenshots with real assets.
2. Pin the image by sha256 digest in `docker-compose.yml` (instructions
   are inline on the `image:` line).
3. Fork `getumbrel/umbrel-apps`, drop this directory in as `blindspark/`,
   open the PR, and record its URL in `umbrel-app.yml` (`submission:`).

The `.github/workflows/umbrel-app-validate.yml` workflow checks the
manifest, compose, and asset presence on every change here, so breakage
is caught before it reaches the upstream PR.
