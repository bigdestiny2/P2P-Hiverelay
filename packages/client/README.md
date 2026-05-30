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
const custody = await client.splitForCustody({
  guardians: guardians.map(g => g.publicKey),
  threshold: 2, // any 2 of 3 guardians can recover
  relays,
  appKey
})

console.log('dealer key:', custody.key) // encrypt your content with THIS — never published
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
