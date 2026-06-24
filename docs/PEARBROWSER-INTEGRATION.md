# HiveRelay and Pear Browser Projects

This document describes the current contracts between HiveRelay and the two
browser anchors in this workspace:

- [`../../../01-browser/PearBrowser`](../../../01-browser/PearBrowser)
- [`../../../01-browser/pearbrowser-desktop`](../../../01-browser/pearbrowser-desktop)

It intentionally focuses on the surfaces that need to stay stable even while
package versions drift.

## The contract browsers expect from HiveRelay

### 1. Public catalog

Browsers need a browsable index. Today that means:

- `GET /catalog.json`
- optional `catalogBeeKey` in that response for a signed Hyperbee catalog

Current behavior in this repo:

- the gateway route paginates into `items`
- older consumers may still expect `apps`
- mobile code already tolerates both shapes

If a relay has no usable catalog, app-store UX falls back to raw drive keys and
manual workflows.

### 2. Public content gateway

Browsers need a fast path for first load:

- `GET /v1/hyper/:key/*path`

That is what turns "wait for the DHT and a peer" into "open the app/site now,
keep P2P syncing in the background."

### 3. Capability advertisement

Browsers and tooling need machine-readable relay metadata:

- `GET /.well-known/hiverelay.json`

This is the stable place to advertise:

- relay pubkey
- runtime (`node` or `bare`)
- version
- supported transports
- feature flags
- region/operator-facing limits

### 4. Publish and seed entry points

At minimum the browser ecosystem needs:

- `POST /seed` for authenticated pinning
- publisher-signed `POST /api/v1/seed` where that flow is used

Desktop tooling already uses `p2p-hiverelay-client` directly for this.

### 5. Liveness and diagnostics

- `GET /health`
- `GET /status`

These are the low-friction checks every browser-side tool and operator script
ends up using first.

## What each browser currently does

### PearBrowser mobile

The mobile browser treats HiveRelay as:

- an HTTP app-store source
- a fast-start gateway for `hyper://` and app content
- a relay configuration target the user can swap at runtime

Relevant implementation seams:

- `backend/relay-client.js`
- `backend/catalog-manager.js`
- `backend/index.js`

The mobile app can also prefer a signed catalog bee when the relay advertises a
`catalogBeeKey` in `/catalog.json`.

### PearBrowser desktop

The desktop browser does the same HTTP/gateway work, but it also has ecosystem
publishing scripts that already depend on HiveRelay:

- `scripts/publish-and-pin.js`
- `scripts/pin-self-on-hiverelay.js`
- `scripts/publish-catalog-bee.js`
- `scripts/check-relays.js`

The most important desktop-specific contract is the signed Hyperbee catalog:

- the browser can consume a `hyperbee://` catalog directly
- the relay can advertise that catalog through `catalogBeeKey`
- `scripts/publish-catalog-bee.js` already emits the exact signed `\x00meta`
  format the browser expects

## Content requirements for browser-friendly drives

For a drive to feel native inside the browsers, it should provide:

1. `manifest.json` at the root
2. a valid entry file such as `/index.html`
3. relative asset loading that survives gateway paths
4. enough metadata for catalog display

Recommended `manifest.json` fields:

```json
{
  "name": "My App",
  "version": "1.0.0",
  "description": "Short one-line description",
  "author": "your-name",
  "entry": "/index.html",
  "categories": ["utilities"]
}
```

Without this, relay catalogs degrade and browser discovery gets worse fast.

## Signed catalog bees versus plain HTTP catalogs

There are now two useful catalog layers:

### Plain HTTP catalog

- easiest interoperability path
- served from `/catalog.json`
- ideal for app-store bootstrap and non-P2P consumers

### Signed Hyperbee catalog

- better long-term Pear-native format
- relay advertises the bee with `catalogBeeKey`
- browser replicates and verifies the catalog instead of trusting a raw HTTP
  JSON payload

The two should coexist. The HTTP catalog remains the bootstrap/discovery path;
the signed bee is the stronger in-network catalog once the client can replicate
it.

## Local workspace flows

### Publish an app/site and make it browser-visible

Use HiveRelay-side publishing helpers:

- [`../scripts/publish-app.js`](../scripts/publish-app.js)
- [`./PUBLISHING.md`](./PUBLISHING.md)

Then verify:

```bash
curl http://127.0.0.1:9100/catalog.json
curl http://127.0.0.1:9100/v1/hyper/<driveKey>/index.html
curl http://127.0.0.1:9100/.well-known/hiverelay.json
```

### Publish a browser-consumable catalog bee

From desktop:

```bash
node scripts/publish-catalog-bee.js <catalog.json> --storage <dir> --serve
```

That gives you a stable `hyperbee://` catalog plus relay pinning.

## Risks to keep in mind

### Version skew

This workspace is not pinned to one HiveRelay version line:

- `hiverelay` is `0.16.3`
- `pearbrowser-desktop` still depends on `^0.8.12`

That means compatibility work should bias toward:

- wire-level HTTP contracts
- capability-doc verification
- signed catalog formats
- focused browser smoke tests

### Catalog shape drift

Catalog responses have evolved. Keep consumers tolerant:

- `items` versus `apps`
- presence or absence of `catalogBeeKey`
- relay-managed pagination

### Service assumptions

Browser projects should not assume every relay runs the same service set. Relay
services are optional and runtime-dependent.

## Recommended shared smoke test

Every ecosystem project that wants browser visibility should prove these five
steps locally:

1. Publish a drive with `manifest.json`.
2. Seed it on a local or reachable relay.
3. Confirm it appears in `GET /catalog.json`.
4. Confirm `GET /v1/hyper/<driveKey>/index.html` serves.
5. Open it from PearBrowser or pearbrowser-desktop without hand-editing code.

That smoke test is the right place to standardize next across the workspace.
