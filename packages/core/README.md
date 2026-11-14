# p2p-hiverelay

Core HiveRelay runtime: a blind always-on relay for Hypercore and Hyperdrive
applications. It can seed apps, expose browser-friendly gateway routes, run the
operator dashboard/API, provide circuit/forward relay transports, and serve as
the kernel underneath Blindspark appliance packages.

## Install

```sh
npm install p2p-hiverelay
```

```js
import { RelayNode } from 'p2p-hiverelay'

const relay = new RelayNode({
  storagePath: './hiverelay-storage',
  apiKey: process.env.HIVERELAY_API_KEY
})

await relay.start()
```

The package is ESM-only and requires Node 20 or newer.

## CLI

```sh
npx p2p-hiverelay start --storage ./hiverelay-storage
```

The CLI also exposes setup, federation, catalog, QVAC, and management helpers.
Run `npx p2p-hiverelay --help` for the available commands.

`testnet` is development tooling for a HiveRelay source workspace. From a
checkout, run `npm ci`, then `node packages/core/cli/index.js testnet`.
Use `--no-client` to start only the local DHT and relay nodes. Published
packages do not include the testnet dependencies or sibling client source;
the installed CLI reports this requirement before starting testnet resources.

## Main Surfaces

- `p2p-hiverelay` exports the core relay runtime.
- `p2p-hiverelay/gateway` exposes the Hyperdrive HTTP gateway.
- `p2p-hiverelay/core/*` subpaths expose protocol helpers used by split SDKs,
  services, and verifiers.

Use `p2p-hiverelay-client` for application SDK workflows and
`p2p-hiveservices` for optional service providers.

## License

Apache-2.0
