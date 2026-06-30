# p2p-hiveservices

Optional service providers for HiveRelay. These run above the Core relay
transport and expose application-layer capabilities such as identity,
schemas, storage proofs, VRF, arbitration, AI model dispatch, and the poker
SignedLog substrate.

## Install

```sh
npm install p2p-hiveservices
```

```js
import { createBuiltInServices } from 'p2p-hiveservices'

const services = createBuiltInServices({
  enabled: ['identity', 'storage-proof']
})
```

The package is ESM-only and requires Node 20 or newer.

## Built-In Providers

- `identity`
- `storage`
- `storage-proof`
- `schema`
- `sla`
- `vrf`
- `arbitration`
- `zk`
- `ai`
- `poker`

Providers are designed to be enabled explicitly by relay operators. Service
RPCs and pub/sub ride on the authenticated HiveRelay service protocol; clients
should use `p2p-hiverelay-client` for `callService()` and
`subscribeService()`.

## License

Apache-2.0
