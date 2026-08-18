# p2p-hiveservices

Optional service providers for HiveRelay. These run above the Core relay
transport and expose application-layer capabilities such as identity,
schemas, storage proofs, VRF, arbitration, AI model dispatch, encrypted wake
notifications, signed outbox logs, and the poker SignedLog substrate.

## Install

```sh
npm install p2p-hiveservices
```

The package exports the individual service classes:

```js
import { IdentityService, StorageProofService } from 'p2p-hiveservices'
```

A relay operator normally never constructs these directly. Install
`p2p-hiveservices` next to `p2p-hiverelay` and list builtin shortnames in the
relay's `config.plugins` (or select them in the dashboard Services tab); the
Core plugin loader resolves each shortname to its class from this package:

```json
{
  "plugins": ["identity", "storage-proof"]
}
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
- `notify`
- `outboxlog`

Providers are designed to be enabled explicitly by relay operators. Service
RPCs and pub/sub ride on the authenticated HiveRelay service protocol; clients
should use `p2p-hiverelay-client` for `callService()` and
`subscribeService()`.

`notify` persists signed provider bindings, device registrations,
capabilities, revocations, watches, replay/dedupe guards, quota buckets, and
redacted delivery events to `<relay-storage>/notify-service-state.json` when a
Node relay supplies `config.storage`. Tests and custom deployments can inject
`createMemoryNotifyPersistence()` or `createJsonFileNotifyPersistence(path)`.

`outboxlog` persists signed opaque rows, invite keys, and per-outbox heads to
`<relay-storage>/outboxlog-state.json` when a Node relay supplies
`config.storage`. Tests and custom deployments can inject
`createMemoryOutboxPersistence()` or `createJsonFileOutboxPersistence(path)`.
It is namespace-driven rather than Peerit-specific: operators can declare
`outboxlog.namespaces` such as `peerit`, `poked`, or `privchat`, each with
`blind` posture and caps for outboxes, entries per outbox, and value bytes.
The relay verifies the signed `_ns` envelope, enforces registered namespaces
and hot-path caps, and still treats record bodies as opaque app-owned data.
Blind namespaces must use the versioned sealed-body contract exposed by
`createOutboxBlindSealedBody()`: the relay accepts `body.sealed` ciphertext
envelopes and rejects naked ciphertext objects, obvious plaintext/data-key
fields, or malformed seal versions. Key exchange and encryption remain
client-owned. Apps that want the stock symmetric helper can use
`createOutboxBlindSealKey()`, `sealOutboxBlindPayload()`, and
`openOutboxBlindPayload()`; the helper uses XChaCha20-Poly1305, supports
additional authenticated data, and never gives the relay decryption material.
Apps can wrap the symmetric seal key to X25519 recipient keys with
`createOutboxBlindRecipientKeyPair()`, `wrapOutboxBlindSealKey()`, and
`openOutboxBlindSealKeyEnvelope()`. The resulting key envelope can travel as
app-owned record metadata; recipient discovery, trust, rotation, and group
membership remain app protocol choices. Apps can also use
`createOutboxBlindSealAAD()` to bind ciphertext to a canonical app-owned
namespace/appId/type/id/keyId tuple, so a private record can reject opens under
the wrong app namespace, writer, record id, type, or key epoch without giving
the relay any decryption authority. Recipient directory entries can use
`createOutboxBlindRecipientDirectoryEntry()` and
`verifyOutboxBlindRecipientDirectoryEntry()` to publish and check a canonical
recipient-id/public-key/keyId fingerprint in app-owned records. This is only
record-shape integrity: apps still decide which directory publishers, recipient
entries, rotations, and groups are trusted. When a recipient key rotates,
`verifyOutboxBlindRecipientDirectoryRotation()` checks that the new entry keeps
the same namespace/appId/recipient id, names the previous `keyId` through
`replacesKeyId`, changes both `keyId` and public key, and still has a valid
fingerprint. Apps that maintain explicit directory-publisher trust roots can
use `verifyOutboxBlindRecipientDirectoryRecord()` to verify that a signed
recipient directory record came from an app-supplied trusted publisher, passes
the existing OutboxLog signature verifier, and carries a canonical recipient
entry. The relay still does not decide which publishers or groups are trusted.

## License

Apache-2.0
