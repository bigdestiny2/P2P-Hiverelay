# PearBrowser Marketplace Demo

This fixture is the smallest browser-facing HiveRelay app in the monorepo.
It exists to prove the relay can publish a Hyperdrive, expose it through the
HTTP gateway, list it in the public catalog, and hand the same app off to the
Pear browser projects.

## What it exercises

- `scripts/pearbrowser-marketplace-demo.js` for the end-to-end local demo flow
- `GET /catalog.json` for public catalog visibility
- `GET /v1/hyper/<driveKey>/index.html` for gateway-served first paint
- `GET /.well-known/hiverelay.json` for capability discovery

## Run it locally

From the HiveRelay repo root:

```bash
npm run demo:pearbrowser
```

For a one-shot validation pass that tears itself down after publishing:

```bash
npm run demo:pearbrowser:once
```

The script starts a local HyperDHT testnet, boots a HiveRelay node against it,
publishes this fixture, waits for catalog + gateway readiness, and prints the
URLs you can open in PearBrowser or `pearbrowser-desktop`.

## Files in this fixture

- `index.html` is the landing page served from the relay gateway
- `app.js` checks whether the relay catalog can see this app
- `manifest.json` provides the browser-consumable metadata row

Keep this fixture small and stable. It is a smoke-test surface for the browser
contracts, not a feature demo or a design playground.
