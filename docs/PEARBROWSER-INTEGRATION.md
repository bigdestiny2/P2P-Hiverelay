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
- optional `indexRoom` when a relay exposes the schema-sheets index sidecar

Current behavior in this repo:

- the gateway route paginates into `items`
- older consumers may still expect `apps`
- mobile code already tolerates `apps`, `items`, and `entries`
- desktop code can additionally consume `indexRoom` through its
  `IndexRoomClient`

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
- fallback `GET /api/capabilities`

This is the stable place to advertise:

- relay pubkey
- runtime (`node` or `bare`)
- version
- supported transports
- feature flags
- region/operator-facing limits
- `gatewayUrl`, `onionGatewayUrl`, and `indexRoom` when available

Capability documents remain additive at `schemaVersion: 1`; browsers must
ignore unknown fields and verify signatures over the full canonical payload
when a signature is present.

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
- a signed `catalogBeeKey` source when the catalog advertises one
- an HTTPS-capable relay transport path for the default public relay URLs

Relevant implementation seams:

- `backend/relay-client.js`
- `backend/catalog-manager.js`
- `backend/index.js`

The mobile app can also prefer a signed catalog bee when the relay advertises a
`catalogBeeKey` in `/catalog.json`.

Current 2026-07-07 status: mobile now declares `bare-https` directly and its
relay client uses scheme-aware HTTP/HTTPS transport, so default
`https://relay-*.p2phiverelay.xyz` gateway URLs do not fall back to plain HTTP
or the wrong default port. Mobile still does not mirror the desktop
relay-directory stack. It lacks the desktop `capability-verify.cjs`, DHT
relay-record bootstrap, and `indexRoom` consumer. It should keep working
against plain `/catalog.json` and `/v1/hyper`, but it will not benefit from
signed capability verification or DHT-resolved gateway/index metadata until
those pieces are ported.

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

Desktop also has the stronger relay-discovery stack:

- signed capability-doc verification in `backend/capability-verify.cjs`
- signed DHT relay-record resolution in `backend/relay-record.js`
- index-room catalog hydration in `backend/index-room-client.js`
- `p2p-hiverelay-client` calls for publishing, seeding, durability waits, and
  release proof scripts

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

## Current 0.25.0-rc.9 ecosystem alignment

The Hiverelay workspace packages are now `0.25.0-rc.9`. Pear Browser desktop is the
main bundled consumer. The desktop alignment pass moved the following surfaces
to the newest Hiverelay line:

1. `scripts/check-hiverelay-layout.mjs` now expects `0.25.0-rc.9`.
2. `package-lock.json` resolves `p2p-hiverelay`, `p2p-hiverelay-client`, and
   `p2p-hiverelay-verifier` to `0.25.0-rc.9`.
3. `.github/workflows/desktop-ci.yml` checks out
   `bigdestiny2/P2P-Hiverelay@v0.25.0-rc.9` and guards `0.25.0-rc.9`.
4. Desktop README, release-readiness docs, and the release-packaging test now
   name the local `0.25.0-rc.9` workspace packages.
5. Desktop local install state has been refreshed so `npm ls` resolves the
   three `p2p-hiverelay*` packages to the `0.25.0-rc.9` workspace links.
6. Desktop and mobile relay clients now use explicit HTTP/HTTPS transport
   selection for public relay gateway fetches. This HTTPS relay transport path
   is backed by `bare-https`, which is declared directly in both browser
   package manifests.
7. `pearbrowser.com` release metadata has been re-synced from the desktop
   README (`v0.5.0`, production length `33841`) so public copy no longer
   advertises the older pinned browser length.

The mobile tree is not a direct `p2p-hiverelay*` package consumer. Its update is
separate: keep the HTTP/HTTPS gateway path working, then port the desktop
capability verification, DHT relay-record bootstrap, and `indexRoom` consumer
when mobile wants parity with the `0.20.x` signed discovery model.

Public ecosystem copy should also be refreshed in the same pass:

- `hyper-fetch` live-smoke evidence that names relay `v0.20.0` should be
  refreshed after a real public relay advertises `v0.25.0-rc.7`.

### Non-bundled direct consumers

The main bundle is PearBrowser desktop. Other direct package consumers exist,
but they are not all release-critical for the browser:

- `02-apps/pear-pos`, `02-apps/pear-tickets`, and
  `04-experiments/hiverelay-test` already point at the local Hiverelay
  workspace packages.
- `02-apps/pearpaste` now points at the local Hiverelay `0.25.0-rc.9` core/client
  workspace packages for encrypted availability, custody, and relay pinning.
- `03-sites/pearbrowser-publishers/src/p2pbuilders` now points at the local
  Hiverelay `0.25.0-rc.9` workspace packages and imports the split
  `p2p-hiverelay-client` SDK.
- `04-experiments/Opengit/packages/opengit-relay` now points its optional
  `--use-hiverelay` bridge at the local Hiverelay `0.25.0-rc.9` workspace packages
  and dynamically imports the split ESM client.
- `04-experiments/anongpt-native` now points at the local Hiverelay `0.25.0-rc.9`
  core workspace package for customer relay/onion AI transport and directory
  discovery.
- `00-core/hr-acct` and `00-core/hr-fleet` are snapshot/worktree-style relay
  copies that are intentionally not the current source of truth.

Those app consumers now default to the current local Hiverelay line. PearBrowser
desktop remains the main bundled browser consumer, but PearPaste and anonGPT are
live customer-facing relay consumers and should block whole-ecosystem package
parity claims if they drift.

`npm run ecosystem:sync` updates those known app consumers to the current local
Hiverelay workspace package links, refreshes linked lockfile metadata, and
rewrites versioned source markers such as the bundled HiveRelay catalog entry.
Run it with `-- --check` when you want a no-write release gate.

`npm run audit:ecosystem-consumers` keeps this inventory honest. It scans the
workspace package manifests and lockfiles, treats PearBrowser desktop as the
release-critical bundled consumer, treats PearPaste, pear-pos, pear-tickets,
p2pbuilders, Opengit's optional relay bridge, anonGPT, and `hiverelay-test` as
current workspace consumers, ignores snapshot relay worktrees, and fails on any
new unclassified `p2p-hiverelay*` dependency. It also rejects stale lockfile
metadata such as old monorepo-root HiveRelay entries or split-package ranges
that do not match the current Hiverelay version. Source-level migration markers
render from the current Hiverelay package version, so the PearBrowser catalog
and live-customer app notes move with the release line.
The per-app source/import migration notes live in
[`ECOSYSTEM-UPGRADE-0.20.2.md`](./ECOSYSTEM-UPGRADE-0.20.2.md).

## Risks to keep in mind

### Version skew

This workspace is not pinned to one HiveRelay version line at all times. On
2026-07-07 the authoritative Hiverelay package line is:

- `p2p-hiverelay` `0.25.0-rc.9`
- `p2p-hiverelay-client` `0.25.0-rc.9`
- `p2p-hiverelay-verifier` `0.25.0-rc.9`

That means compatibility work should bias toward:

- wire-level HTTP contracts
- capability-doc verification
- signed catalog formats
- focused browser smoke tests

Package-version parity still matters for the bundled desktop release: if the
desktop lockfile or CI checkout remains on `0.20.0`, local tests are not proving
the newest bundled Hiverelay client.

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
