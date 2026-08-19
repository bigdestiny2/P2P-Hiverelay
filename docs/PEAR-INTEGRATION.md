# HiveRelay for Pear and Bare Apps

This guide replaces the older pre-split notes. It is scoped to the current
workspace:

- [`../`](../) for HiveRelay itself
- [`../../../01-browser/PearBrowser`](../../../01-browser/PearBrowser) for the mobile browser
- [`../../../01-browser/pearbrowser-desktop`](../../../01-browser/pearbrowser-desktop) for the desktop browser

The main distinction is simple:

- **Your app** runs the `p2p-hiverelay-client` SDK inside Pear/Bare.
- **The relay** runs as a Node service or as the Bare-native relay app.
- **Browsers** consume the relay's HTTP and capability surfaces for fast-load,
  catalog, and publish flows.

## What is current

- `HiveRelayClient` is the client entry point for Pear/Bare apps.
- The relay advertises capabilities at `/.well-known/hiverelay.json`.
- Public browser-facing content comes from `GET /catalog.json` and
  `GET /v1/hyper/:key/*path`.
- Authenticated publisher/operator writes use `POST /seed`.
- Publisher-signed seed requests also exist at `POST /api/v1/seed`.
- The services layer is optional. In this tree the built-in examples under
  `packages/services/builtin/` are `poker` and `vrf`; do not assume the older
  identity/storage/compute examples are present everywhere.

## Quick start inside a Pear app

```js
import Corestore from 'corestore'
import Hyperswarm from 'hyperswarm'
import { HiveRelayClient } from 'p2p-hiverelay-client'

const store = new Corestore(Pear.config.storage)
await store.ready()

const swarm = new Hyperswarm()
const client = new HiveRelayClient({ store, swarm })
await client.start()
```

Why this shape matters:

- Pear apps should use `Pear.config.storage`, not an ad hoc filesystem path.
- Passing your own `swarm` lets the rest of the app share DHT state cleanly.
- `await client.start()` is required before publish/open/seed/custody calls.

If you are writing a plain Node script instead of a Pear app, the simple path
form still works:

```js
const client = new HiveRelayClient('./my-storage')
await client.start()
```

## Publish flow for Pear apps

The practical path is:

1. Build a Hyperdrive.
2. Include a root `manifest.json`.
3. Publish with `HiveRelayClient.publish(...)` or
   [`../scripts/publish-app.js`](../scripts/publish-app.js).
4. Seed the resulting drive on one or more relays.
5. Verify that the drive is reachable through both P2P and relay HTTP.

Minimal publish example:

```js
const drive = await client.publish([
  {
    path: '/index.html',
    content: '<!doctype html><h1>Hello from Pear</h1>'
  },
  {
    path: '/manifest.json',
    content: JSON.stringify({
      name: 'Hello Pear',
      version: '1.0.0',
      description: 'Minimal Pear app',
      author: 'you',
      entry: '/index.html',
      categories: ['utilities']
    }, null, 2)
  }
])

await client.seed(drive.key, { replicas: 3 })
```

### Manifest expectations

For browser and catalog consumers, the useful minimum is:

```json
{
  "name": "My App",
  "version": "1.0.0",
  "description": "What the app does",
  "author": "your-name",
  "entry": "/index.html",
  "categories": ["utilities"]
}
```

Without a manifest, browsers can still fetch the drive by key, but catalog UIs
have poor metadata and often fall back to generic labels.

## Relay contracts Pear apps should rely on

### Capability discovery

Fetch and verify the relay's capability document before treating a relay as
trusted infrastructure:

```js
const doc = await client.fetchCapabilities('https://relay.example.com')
console.log(doc.pubkey, doc.version, doc.features)
```

Use this for:

- relay identity pinning
- transport selection
- feature discovery such as `capability-doc`, `seed-revocability`,
  `auto-heal`, `publish-channel-v1`, or `dht-relay-ws`

Do not hardcode service availability from old docs.

### Public browser-facing surfaces

- `GET /catalog.json`
  - public catalog snapshot
  - may include a `catalogBeeKey` for a signed Hyperbee catalog
- `GET /v1/hyper/:key/*path`
  - HTTP gateway for seeded Hyperdrive content
- `GET /health`
  - load balancer/liveness probe
- `GET /status`
  - unauthenticated status summary
- `POST /seed`
  - authenticated operator/publisher seed write

## Service RPC guidance

The older "all relays expose identity/storage/compute" story is no longer a
safe assumption.

Treat services as optional and relay-specific:

1. Read the capability doc.
2. Check the operator's service manifest.
3. Only then call `client.callService(...)`.

That keeps Pear apps from coupling themselves to services that exist only on a
subset of Node relays or on older branches.

## Pear-native relay versus Node relay

See [`PEAR-DEPLOYMENT.md`](./PEAR-DEPLOYMENT.md)
for the full matrix. The short version:

- **Bare relay** is the always-on data plane: DHT peering, seeding, circuit
  relay, read-only HTTP surfaces.
- **Node relay** is the full operator/control plane: management APIs,
  auth-gated publish flows, optional services, extra transports.

If your app depends on the browser-facing HTTP gateway or catalog, either relay
runtime is fine as long as those public routes are enabled.

## How this plugs into the browser anchors

### PearBrowser mobile

[`PearBrowser`](../../../01-browser/PearBrowser)
uses HiveRelay for:

- relay-backed app discovery via `/catalog.json`
- fast first paint via `/v1/hyper/:key/*path`
- relay configuration and health checks
- optional signed Hyperbee catalogs when `catalogBeeKey` is advertised

Mobile is currently an HTTP/catalog consumer rather than a direct
`p2p-hiverelay*` package consumer. It should keep tolerating plain
`/catalog.json` gateway relays, but parity with the newest desktop integration
requires porting signed capability-doc verification, DHT relay-record
bootstrap, and `indexRoom` hydration.

### PearBrowser desktop

[`pearbrowser-desktop`](../../../01-browser/pearbrowser-desktop)
adds stronger catalog tooling:

- `scripts/publish-catalog-bee.js` publishes a signed Hyperbee catalog
- browser clients can prefer a signed bee when the relay advertises
  `catalogBeeKey`
- desktop release/publish scripts already use `p2p-hiverelay-client`
- desktop bootstraps signed DHT relay records and optional index rooms

## Compatibility note for this workspace

There can be active version skew across the ecosystem. As of 2026-08-18, the
published stable npm line is `0.24.4` (`latest` for `p2p-hiverelay`,
`p2p-hiverelay-client`, `p2p-hiveservices`, and `p2p-hiverelay-verifier`),
and the workspace on `main` is versioned for the `0.26.0-rc.3`
release-candidate train:

- `p2p-hiverelay` — stable `0.24.4`, rc `0.26.0-rc.3`
- `p2p-hiverelay-client` — stable `0.24.4`, rc `0.26.0-rc.3`
- `p2p-hiverelay-verifier` — stable `0.24.4`, rc `0.26.0-rc.3`

PearBrowser desktop is the bundled consumer that must be kept in lockstep:
`scripts/check-hiverelay-layout.mjs`, `package-lock.json`, and desktop CI must
all point at the same Hiverelay package line before local tests prove the new
client. Both PearBrowser desktop and mobile now declare `bare-https` and use
scheme-aware HTTP/HTTPS relay transport so public `https://relay-*.p2phiverelay.xyz`
gateway URLs do not silently run through the wrong transport path. Prefer
documenting and testing stable wire contracts
(`/.well-known/hiverelay.json`, `/api/capabilities`, `/catalog.json`,
`/v1/hyper/...`, signed catalog bees, signed DHT relay records, and `indexRoom`)
instead of relying on package-version parity alone.

p2pbuilders now points at the current Hiverelay workspace packages (published stable line `0.24.4`) and
uses the split `p2p-hiverelay-client` SDK, with a local migration guard that
rejects the removed `p2p-hiverelay/client` subpath. Opengit's optional
`--use-hiverelay` bridge also points at the current core/client packages (stable line `0.24.4`)
and dynamically imports the split ESM client while preserving the native relay
default. PearPaste and anonGPT now also point at the current Hiverelay
workspace packages (stable line `0.24.4`) by default, because they are live customer-facing relay
consumers. The main PearBrowser bundle is still the release-critical bundled
consumer, but whole-ecosystem package-parity claims require these
non-bundled direct consumers to stay on the same Hiverelay line too.
See [`ECOSYSTEM-UPGRADE-0.20.2.md`](./ECOSYSTEM-UPGRADE-0.20.2.md) for the
per-app import/API migration notes.

Run `npm run ecosystem:sync` from this repo to update the known app consumers to
the current local Hiverelay workspace package links and refresh their linked
lockfile metadata plus versioned source markers such as bundled catalog entries.
Run `npm run ecosystem:sync -- --check` when you want the same contract as a
no-write release gate.

Run `npm run audit:ecosystem-consumers` to verify that consumer inventory. The
command fails if a new unclassified `p2p-hiverelay*` dependency appears or if
one of the current customer app pins drifts away from the local Hiverelay
workspace line before the docs and upgrade plan are updated.

## Practical validation checklist

For any Pear/Bare app you want browsers to consume:

1. `await client.publish(...)` succeeds.
2. `await client.seed(...)` gets at least one acceptance.
3. `curl http://127.0.0.1:9100/catalog.json` shows the drive with usable
   metadata.
4. `curl http://127.0.0.1:9100/v1/hyper/<driveKey>/index.html` returns HTML.
5. The app loads in PearBrowser or pearbrowser-desktop without a manual key
   paste fallback.

If you need relay-side pin diagnostics, also read
[`PUBLISHING.md`](./PUBLISHING.md).
