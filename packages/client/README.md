# p2p-hiverelay-client

Client SDK for [HiveRelay](https://github.com/bigdestiny2/p2p-hiverelay) — a
network of blind peer (relay) nodes that discover each other, replicate your
Hyperdrives, and seed your content so it stays available even when your app is
offline. Your users never see the relay infrastructure: they get a simple
`publish` / `open` / `get` API.

- **ESM only** (`"type": "module"`), Node ≥ 20.
- **Bare-safe** — runs in [Pear](https://docs.pears.com/) / Bare apps. The only
  native deps are `sodium-universal`, `b4a`, and (`@noble`) for the PVSS module.
- **Apache-2.0**.

## Install

```sh
npm install p2p-hiverelay-client
```

```js
import { HiveRelayClient } from 'p2p-hiverelay-client'
```

Subpath modules (all Bare-safe, usable standalone):

```js
import { keygen, split, reconstruct } from 'p2p-hiverelay-client/secret-sharing.js'
import { createCustodyIntent } from 'p2p-hiverelay-client/custody.js'
import { attachPairing } from 'p2p-hiverelay-client/pairing.js'
```

## Quickstart

```js
import { HiveRelayClient } from 'p2p-hiverelay-client'

// Simple mode: pass a storage path; the client creates its own
// Corestore + Hyperswarm and discovers relays automatically.
const client = new HiveRelayClient('./my-app-storage')
await client.start()

// Publish content to a Hyperdrive and ask relays to seed it.
const drive = await client.publish([
  { path: '/index.html', content: '<h1>Hello</h1>' }
])
const key = drive.key.toString('hex')
console.log('Share this key:', key)

// On another device (or after a restart): open by key and read files.
await client.open(key)
const html = await client.get(key, '/index.html')
console.log(html.toString()) // <h1>Hello</h1>

await client.destroy()
```

### Constructor

```js
// Simple: storage path string. Owns its swarm + store.
new HiveRelayClient('./storage')

// Advanced: bring your own swarm / store / keyPair.
new HiveRelayClient({ swarm, store, keyPair, autoDiscover, maxRelays })
```

Always call `await client.start()` before using the content or custody APIs,
and `await client.destroy()` when done.

### Content API

| Method | Returns | Notes |
| --- | --- | --- |
| `await client.publish(files \| dirPath, opts)` | `Hyperdrive` | `files` is `[{ path, content }]`, or a directory path. `opts`: `appId`, `key`, `seed`, `replicas`, `timeout`. |
| `await client.open(key, opts)` | `Hyperdrive` | Replicate + open a drive by 64-hex key. |
| `await client.get(driveKey, path)` | `Buffer` | Read one file from an opened drive. |
| `await client.put(driveKey, path, content)` | — | Write to a drive you own. |
| `await client.list(driveKey, dir)` | `string[]` | List entries under a directory. |
| `await client.seed(appKey, opts)` | — | Ask relays to seed an existing drive. |

`seed()` keeps the legacy v2 signature preimage by default for mixed-version
relay fleets. For upgraded relay testing, pass `seedSignatureDomain: 'v3'` to
sign the preferred `hiverelay.seed-request.v3` domain-separated preimage.
Upgraded relays advertise `seed-signature-domain-v3` in their signed capability
document.

Publisher-signed `/api/v1/seed` and `hiverelay-publish` submissions can also
use the replay-hardened `hiverelay.seed-request.replay-v1` profile by signing
`issuedAt` plus a 16-byte `requestNonce`. Relays advertising
`seed-request-replay-v1` reject stale replay-profile submissions and duplicate
nonces for the same publisher.

### Capability Documents

`fetchCapabilities(relayUrl, opts)` reads `/.well-known/hiverelay.json`, verifies
the document signature when present, and emits `capability-doc-stale` when
`attestedAt` is older than `opts.maxAgeMs` (default: 24h). For strict relay
selection, pass `requireFreshCapabilityDoc: true`; signed but stale or
future-skewed documents are rejected instead of only warned.

## Service RPC

Relays expose named services over a P2P service channel. `callService` is the
request/response primitive; `subscribeService` is its streaming counterpart.

| Method | Returns | Notes |
| --- | --- | --- |
| `await client.callService(service, method, params?, opts?)` | service result | RPC to a relay service. `opts`: `relay` (pubkey hex; defaults to best service relay), `timeout` (ms, default `30000`). Throws `NO_RELAY` / `NO_SERVICE_CHANNEL` / `SERVICE_TIMEOUT`. |
| `client.subscribeService(service, event, onEvent, opts?)` | unsubscribe `fn` | Live service events. Topic is `<service>/<event>`, matched exactly (lowercase hex keys). `opts.relay` selects the relay. |

```js
const result = await client.callService('identity', 'whoami')

const off = client.subscribeService('arbitration', 'resolved', (data) => {
  console.log('resolved:', data)
})
off() // unsubscribe
```

`subscribeService` sends one `MSG_SUBSCRIBE` for the first local listener on a
`(relay, topic)` pair and `MSG_UNSUBSCRIBE` when the last detaches; pass hex keys
(e.g. a poker `tableKey`) in **lowercase**, or the subscription is silently dead.
`onEvent` must be a function; the topic string must be ≤ 256 chars.

### Trustless seed verification

Two methods let you confirm a relay genuinely holds and serves an app
(Hyperdrive), with no trust in its self-reported catalog.

| Method | Returns | Notes |
| --- | --- | --- |
| `await client.verifySeeded(driveKey, opts)` | verdict object | Replication-based check. `opts.relay` (pubkey hex, **required**), `opts.timeout` (ms, default `30000`). |
| `await client.proveSeeded(driveKey, opts)` | proof report | Tier-2 signed proof-of-retrievability sampling. Prefers `POST /api/proof/retrievability` when capabilities advertise it, otherwise falls back to legacy `storage-proof.prove`. `opts.relay` (pubkey hex, **required**), `opts.relayUrl` (optional HTTP capability/proof URL), `opts.proofTransport` (`auto`, `http`, or `service`), `opts.proofSignatureProfile` (`retrievability-proof-v1` opt-in, legacy omitted by default), `opts.samples` (default `3`, clamped to `1..16`), `opts.timeout` (ms, default `30000`). |

### Accounting receipts

`fetchAccountingReceipt(relayUrl, { apiKey, refresh, expectedPubkey })` reads
`GET /api/accounting/receipt`, verifies the receipt signature locally, and
optionally rejects receipts whose relay pubkey does not match `expectedPubkey`.
Set `refresh: false` to ask the relay not to force a fresh disk scan.

```js
const r = await client.fetchAccountingReceipt('https://relay.example', {
  apiKey,
  expectedPubkey: relayPubkeyHex
})

console.log(r.verified, r.receipt.diskBytes)
```

#### `verifySeeded(driveKey, { relay, timeout })`

Opens the drive, confirms the relay is a live peer advertising the full length,
and downloads **both** cores (metadata + blobs) to completion. Hypercore verifies
every block against the drive key's signed Merkle root on arrival, so a relay
cannot fake content it does not hold.

```js
const v = await client.verifySeeded(driveKey, { relay: relayPubkeyHex })
// { complete, relayIsPeer, relayHasFullLength, contentVerified,
//   metaLength, blobsLength, relayRemoteLength, driveKey, relay }
if (v.complete) console.log('relay is serving the full app')
```

Returns:

```js
{
  complete,            // relayHasFullLength && contentVerified
  relayIsPeer,         // relay is a live peer on the drive's core
  relayHasFullLength,  // relay's advertised remoteLength covers the meta head
  contentVerified,     // both cores downloaded + Merkle-verified
  metaLength,          // metadata core length
  blobsLength,         // blobs core length
  relayRemoteLength,   // relay's advertised metadata length
  driveKey,            // 64-hex
  relay                // relay pubkey hex
}
```

**Caveat:** replication rides the shared swarm, so `contentVerified` proves the
content is genuine and served, and `relayHasFullLength` is the relay's own
advertised state — it is **not** a per-block, relay-attributable,
third-party-portable proof. For that, use `proveSeeded`.

#### `proveSeeded(driveKey, { relay, samples })`

Opens the drive to learn the metadata head, samples up to 16 random block indices,
prefers the relay's `POST /api/proof/retrievability` route when a cached or
fetched capability doc advertises `retrievability-proof-http`, falls back to the
`storage-proof.prove` service per sample, and verifies each **signed** proof
against an isolated temp-Corestore verifier (length pinned to the head). Each
proof is signed by the relay over a fresh nonce, so a passing result is
per-block, relay-attributable, and non-replayable.
Set `proofSignatureProfile: 'retrievability-proof-v1'` to request the
RelayKernel domain-separated signature preimage when the relay advertises
`retrievability-proof-domain-v1`; omit it for legacy-compatible proof bytes.

```js
const r = await client.proveSeeded(driveKey, { relay: relayPubkeyHex, samples: 5 })
// r.ok === true only if EVERY sampled block verified at the current head
```

Returns:

```js
{
  ok,          // true iff every sample verified (and total > 0)
  proofKind,   // "proof-of-retrievability"
  proofLimit,  // challenge-response proof; not proof-of-replication
  proofTransport, // "http" or "service"
  driveKey,    // 64-hex
  relay,       // relay pubkey hex
  head,        // metadata head length proofs were pinned to
  passed,      // number of samples that verified
  total,       // number of samples taken
  samples      // [{ index, transport, valid, proofKind, signatureProfile, reason }]
}
```

The relay must either advertise `retrievability-proof-http` in its capability doc
or run the opt-in `storage-proof` service (default OFF). This is a
challenge-response proof-of-*retrievability*, not sealed proof-of-replication: a
relay could fetch a block on demand rather than store it; random sampling plus
the latency bound make that expensive, not cryptographically precluded. v1
proves the drive **metadata** core.

## Blind custody for a secret (PVSS)

`splitForCustody` / `reconstructFromCustody` place a **secret key** into *blind*
custody on the relay fleet using Publicly Verifiable Secret Sharing
(Schoenmakers PVSS over secp256k1).

The invariant: **a relay can publicly verify the encrypted share it holds, but
can never open it** — it never sees the secret, never runs the split, and never
reconstructs. You split the key to a set of **guardians** (secp256k1 recipient
keypairs); each relay custodies one guardian-encrypted share. Any **t** of the
**n** guardians can later recover the key; fewer than t — and any number of
relays — cannot.

This is how an app hands off a content-encryption key: encrypt your data with
the dealer key, publish the *ciphertext* to a drive, and blind-custody the key.
Recover it on another device with a guardian quorum.

### Split

```js
import { HiveRelayClient } from 'p2p-hiverelay-client'
import { keygen } from 'p2p-hiverelay-client/secret-sharing.js'

const client = new HiveRelayClient('./dealer-storage')
await client.start()

// 1. n guardian keypairs (secp256k1). Distribute the SECRET keys to your
//    guardians out-of-band; keep only their PUBLIC keys here.
const guardians = [await keygen(), await keygen(), await keygen()]

// 2. The relays that will custody the shares — one per guardian.
//    relays[i] is assigned share i+1. `pubkey` is the relay's ed25519 identity.
const relays = [
  { url: 'http://relay-a.example:9100', pubkey: '<relay-a-pubkey-hex>' },
  { url: 'http://relay-b.example:9100', pubkey: '<relay-b-pubkey-hex>' },
  { url: 'http://relay-c.example:9100', pubkey: '<relay-c-pubkey-hex>' }
]

// 3. The content drive whose encryption key this custody protects.
const drive = await client.publish([{ path: '/note.enc', content: ciphertext }])
const appKey = drive.key.toString('hex')

// 4. Split + custody. Omit `secret` to have a fresh dealer key generated.
//    The custody POST endpoints (intent / seed / commit) are AUTHENTICATED —
//    pass the relay's API key via opts.apiKey (per-relay Bearer key).
const custody = await client.splitForCustody({
  guardians: guardians.map(g => g.publicKey),
  threshold: 2, // any 2 of 3 guardians can recover
  relays,
  appKey,
  opts: {
    apiKey,            // required: Bearer key the relays accept for custody writes
    retainMs: 365 * 24 * 60 * 60 * 1000, // how long relays hold the share
    pollTimeoutMs: 90_000                // how long to wait for verified receipts
  }
})

console.log('dealer key:', custody.key) // 64-hex — DEALER-PRIVATE, never published
console.log('intentId:', custody.intentId)
console.log('share bundle:', custody.shareBundleKey)
```

`splitForCustody` returns:

```js
{
  intentId,       // custody intent id (look up status on any relay)
  commitmentRoot, // PVSS commitment root, bound into the signed intent
  shareBundleKey, // hypercore key of the published PUBLIC share bundle
  key,            // dealer-PRIVATE encryption key — NEVER leaves the client
  secretPoint,    // the secret as an EC point (dealer-private)
  intent,         // signed v2 custody intent
  commit,         // signed quorum commit
  receipts        // the verified, anchored relay receipts
}
```

It PVSS-splits the secret to the guardians, publishes the **public** share
bundle (commitments + *encrypted* shares — no secret material) over the P2P
data plane, signs a v2 custody intent that names the bundle and assigns one
share-index per relay, hands the intent to each relay, waits for a
**share-verified** receipt from every relay, then signs and publishes the quorum
commit. `requiredReplicas` equals `n` (every relay must anchor); the
reconstruction threshold `t` is the separate `shareThreshold` field.

### Options (`opts`)

| Field | Default | Notes |
| --- | --- | --- |
| `apiKey` | — | **Bearer key for the custody writes.** The intent / seed / commit endpoints are authenticated; without it they 401. Per-relay. |
| `secret` | random | 64-hex scalar to split. Omit for a fresh dealer key. |
| `retainMs` | 30 days | How long relays retain the share before expiry. |
| `deadlineMs` | 10 min | Receipt-collection window. |
| `pollTimeoutMs` | 60_000 | How long to wait for every relay's verified receipt before `CUSTODY_QUORUM_TIMEOUT`. |
| `pollIntervalMs` | 1000 | Status poll interval. |
| `blindContentId` / `ciphertextRoot` / `contentVersion` | derived | Bind the custody to a specific encrypted payload (see below). |

### Authentication & finding relays

Custody **writes** need an API key the relay accepts (`opts.apiKey`); custody
**reads** (status, share bundle) and `reconstructFromCustody` are
**permissionless** — recovery needs only guardian keys + the public bundle, no
relay auth. Requires relays on **v0.9.1+**.

Each relay entry is `{ url, pubkey }`. Get both from the relay's public
capability doc:

```js
const doc = await (await fetch(url + '/.well-known/hiverelay.json')).json()
const relay = { url, pubkey: doc.pubkey }   // doc.version must be >= 0.9.1
```

### Recovering an arbitrary secret (encrypt-then-custody)

**Important:** `custody.key` is a *fresh 32-byte dealer key* — it is **not** your
secret bytes. To make an existing secret (a seed, a mnemonic, a master key)
recoverable, **encrypt your secret with the dealer key and custody the dealer
key.** Then recovery = reconstruct the dealer key → decrypt your secret.

```js
import sodium from 'sodium-universal'
import b4a from 'b4a'

// SETUP — custody a fresh dealer key, encrypt your real secret under it.
const custody = await client.splitForCustody({ guardians, threshold: 2, relays, appKey, opts: { apiKey } })
const dealerKey = b4a.from(custody.key, 'hex')                 // 32 bytes
const nonce = b4a.alloc(sodium.crypto_secretbox_NONCEBYTES); sodium.randombytes_buf(nonce)
const box = b4a.alloc(mySecret.length + sodium.crypto_secretbox_MACBYTES)
sodium.crypto_secretbox_easy(box, mySecret, nonce, dealerKey) // mySecret = e.g. rootSeed
// Store { nonce, box } anywhere (it's ciphertext) — e.g. a blind drive — and keep
// the RECOVERY COORDINATES so a future device can find the custody:
const coordinates = { intentId: custody.intentId, shareBundleKey: custody.shareBundleKey, threshold: 2, relays }

// RECOVER — gather t guardian SECRET keys (no relay API key needed).
const out = await client.reconstructFromCustody({
  ...coordinates,
  guardianSecretKeys: [g1.secretKey, g3.secretKey]
})
const recoveredKey = b4a.from(out.key, 'hex')
const mySecretBack = b4a.alloc(box.length - sodium.crypto_secretbox_MACBYTES)
sodium.crypto_secretbox_open_easy(mySecretBack, box, nonce, recoveredKey)
// mySecretBack === mySecret
```

The **recovery coordinates** (`intentId`, `shareBundleKey`, `threshold`,
relays) are *not secret* — they're useless without `t` guardian keys. Hand them
to each guardian alongside their share, or keep them on a short "recovery card."
That's the bootstrap a fresh device needs to find the custody.

### Reconstruct

On any device that can gather **t** guardian **secret** keys:

```js
const recovered = await client.reconstructFromCustody({
  intentId: custody.intentId,
  guardianSecretKeys: [guardians[0].secretKey, guardians[2].secretKey], // any t
  relays // used to resolve shareBundleKey + threshold from the signed intent
})

recovered.key === custody.key // true — the dealer key is back
```

You may pass `shareBundleKey` and `threshold` explicitly to skip the relay
round-trip. Each guardian decrypts only its own share (matched by recovering its
recipient pubkey from the key); `reconstruct()` re-verifies every decryption's
DLEQ proof, so a forged or merely-*encrypted* share is rejected — the relays'
encrypted shares alone can never reconstruct the key.

## License

Apache-2.0
