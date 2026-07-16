# Blind-shard dealer contract

The exact wire contract for an **app-side node dealer** that disperses a secret
k-of-n across a set of HiveRelay `shard-store` relays and reconstructs it at a
reader's edge — the "public plaintext, blind custody" path (encrypt content with
a random key, store the ciphertext, disperse the **key** as blind shards so no
single operator, and no `k-1` colluding operators, can produce the plaintext).

This document is the reference for integrators (e.g. porting a dealer into
another app) so a `buildPin` / publish-intent implementation matches the relay's
verifier **byte-for-byte** and never produces an orphan-intent rejection.

Anchored to (v0.24.0 line):

| Piece | Path |
| --- | --- |
| Reference dealer | [`scripts/blind-dispersal-live.mjs`](../scripts/blind-dispersal-live.mjs) |
| Dispersal plan/codec | [`packages/client/blind-shards.js`](../packages/client/blind-shards.js) (`planDispersal`, `recoverSecret`, `shardAddressOf`) |
| HTTP transport | [`packages/client/shard-transport.js`](../packages/client/shard-transport.js) (`createHttpShardPut`, `createHttpShardFetch`) |
| v2 intent signer | [`packages/core/core/custody-signing.js`](../packages/core/core/custody-signing.js) (`createCustodyIntent`) |
| Pin signer + canonical body | [`packages/services/builtin/shard-store/shard-pin.js`](../packages/services/builtin/shard-store/shard-pin.js) (`signShardPin`, `shardPinSignable`) |
| Address normalizer | `packages/services/builtin/shard-store/index.js` (`normalizeShardAddress`) |
| Orphan-intent resolver | `packages/core/core/relay-node/index.js` → `_resolveShardCustodyAssignment` |

## Wire flow

```
planDispersal(n,k)  →  createCustodyIntent(v2)  →  POST /api/custody/intent (each relay)
                    →  PUT /api/v1/shard (custody pin, each relay)  →  recoverSecret (any k)
```

The intent is published **before** any PUT: each relay authorizes a shard PUT
only against a custody intent it has already indexed. `planDispersal` splits and
encodes every share's content address **without storing anything**, so the whole
roster (relay → shareIndex → `shard:<hash>`) is known and signed into the intent
before shards go out.

## 1. Publish the intent — `POST /api/custody/intent`

- Header: `Authorization: Bearer <relay admin apiKey>`
- Body: the JSON of the signed intent from step 2.
- The relay ingests it into its seeding registry; `getCustodyIntent(intentId)`
  must return it **before** any PUT.

If a relay has not indexed the intent named by a pin, its resolver returns
`null` and the PUT is rejected (`UNAUTHORIZED_PIN`) — this is the orphan-intent
case. A **payment** pin (`custodyIntentId: null`) can never satisfy the custody
resolver; use a custody pin bound to a published intent.

## 2. The v2 custody intent — `createCustodyIntent(fields, publisherKeyPair)`

`version: 2` is **required** — v1 rejects the PVSS share fields as "unknown
field" (the surface is opt-in per version, [`custody-signing.js` `allowedFieldsFor`](../packages/core/core/custody-signing.js)).

Base signable fields (subset you set) + the v2 `custody-intent` share allowlist
(`shareScheme`, `shareThreshold`, `commitmentRoot`, `shareBundleKey`,
`shareAssignments`, `shareManifest`):

```js
createCustodyIntent({
  version: 2,                        // REQUIRED — unlocks the share-field allowlist
  blindContentId: '<64hex>',
  ciphertextRoot: plan.commitmentRoot,   // '<64hex>'
  contentVersion: 1,
  requiredReplicas: n,
  candidateRelays: relays.map(r => r.pubkey),   // optional; ['<relayPubkeyHex>', ...]
  // --- v2 share fields ---
  shareScheme:    'pvss-secp256k1-v1',
  shareThreshold: k,
  commitmentRoot: plan.commitmentRoot,          // '<64hex>' — Feldman commitment root
  shareBundleKey: '<64hex>',
  shareAssignments: plan.shares.map(s => ({
    relayPubkey: relays[s.shareIndex - 1].pubkey.toLowerCase(),   // relay -> shareIndex
    shareIndex:  s.shareIndex
  })),
  shareManifest: plan.shares.map(s => ({
    shareIndex:      s.shareIndex,               // shareIndex -> shard
    shard:           s.shard,                    // 'shard:<64hex>'
    shareCommitment: s.shareCommitment
  }))
}, publisherKeyPair)
```

Notes:
- `publisherPubkey` is derived from `publisherKeyPair` — **do not pass it.**
- `intentId` (if not supplied) is `blake2b` of
  `{type:'custody-intent-id-v1', blindContentId, ciphertextRoot, contentVersion, publisherPubkey, timestamp}`.
- Useful defaults already applied: `custodyMode:'blind'`, `contentType:'shard-set'`,
  `deadline: now+10m`, `retainUntil: now+30d`.
- **Client-signer parity (task #115 — resolved):** the Bare-safe client signer
  (`packages/client/custody.js`) now carries all six v2 custody-intent fields,
  including `shareManifest` (#162), so a browser/Bare dealer can author a
  manifest-bearing intent today — the same as a **node** dealer using the core
  signer above. `shareManifest` stays optional: when absent it is omitted from
  the signed payload, byte-identical to a manifest-less v2 intent.

## 3. The custody pin — `signShardPin(pin, publisherKeyPair)`

Domain `hiverelay.shard-pin.v1`. The signable is
`DOMAIN + '\0' + stableStringify(pinBody)` with **sorted keys**, where `pinBody`
is *exactly* these seven fields (nothing else is signed):

```js
signShardPin({
  reason:          'custody',
  hash:            normalizeShardAddress(shard),  // bare 64-hex; strips 'shard:' — verifier enforces ^[0-9a-f]{64}$
  pinner:          '<publisherPubkeyHex>',        // defaults to publisherKeyPair.publicKey
  custodyIntentId: intent.intentId,               // NON-null for reason:'custody'
  shareIndex:      s.shareIndex,                  // integer for reason:'custody'
  retainUntil:     <ms epoch>,
  nonce:           '<fresh hex>'
}, publisherKeyPair)
```

`verifyShardPin` fails **before** the resolver runs if, for `reason:'custody'`,
`custodyIntentId` is falsy or `shareIndex` is not an integer.

## 4. The relay's acceptance rule (`_resolveShardCustodyAssignment`)

For each PUT the relay runs `resolveCustodyAssignment(pin.custodyIntentId, thisRelayPubkey)`:

```js
intent = seedingRegistry.getCustodyIntent(pin.custodyIntentId)   // null → orphan → REJECT
assignment = intent.shareAssignments.find(a => a.relayPubkey === thisRelayPubkey)  // not assigned → REJECT
share      = intent.shareManifest.find(m => m.shareIndex === assignment.shareIndex)
// PUT accepted only if:
//   pin.shareIndex === assignment.shareIndex
//   AND pin.hash === normalizeShardAddress(share.shard)
```

So a relay can only pin the **one** share it was assigned; the roster is signed
into the intent.

## The `buildPin` seam

If your dealer exposes a `buildPin(shardId, bytes, ctx)` injection, `ctx` should
carry the per-relay `{ custodyIntentId, shareIndex, retainUntil }` resolved from
the roster + plan:

```js
buildPin (shardId, bytes, ctx) {
  return signShardPin({
    reason:          'custody',
    hash:            normalizeShardAddress(shardId),
    custodyIntentId: ctx.custodyIntentId,   // the published intent's id — NOT null
    shareIndex:      ctx.shareIndex,         // this relay's assigned index
    retainUntil:     ctx.retainUntil,
    nonce:           freshNonce()
  }, this.publisherKeyPair)
}
```

This is the same shape as a payment pin; the only additions are `custodyIntentId`
+ `shareIndex`, fronted by the publish-intent step.

## Reference dealer

See [`scripts/blind-dispersal-live.mjs`](../scripts/blind-dispersal-live.mjs)
for the full `plan → publish intent → PUT each shard → reconstruct` flow against
a real relay set from an operator-supplied config
(`{ threshold, secret?, publisherSeed?, relays:[{ baseUrl, pubkey, apiKey }] }`,
in share-index order). It is the fleet-run form of
`test/integration/blind-dispersal-fleet-e2e.test.js`, which proves the same
flow against four in-process `RelayNode` instances (real seeding registry, real
production resolver, no stub).

`planDispersal` returns
`{ key, secretPoint, threshold, count, commitmentRoot, shares:[{ shareIndex, bytes, shard, shareCommitment }] }`.
`recoverSecret` binds each fetched share to the manifest's `shareCommitment`
before use ([`blind-shards.js:241`](../packages/client/blind-shards.js)), so a
forged-but-self-consistent share is rejected — **integrity rests on an authentic
manifest** (the signed intent you published).

## Prerequisites & honest scope

- **Relays must run a build that mounts `/api/v1/shard`** — the v0.24.0 line
  (the mount, `#154`; the custody-authorized PUT + live proof, `#159`). A relay
  on an older tag 404s the surface.
- Enable the service: `shard-store` in the relay's `plugins`, `enableServices:true`.
  PUT authorization defaults to `custody` (`config.shardStore.putAuth`).
- **Same operator ≠ the security property.** Dispersing across relays a single
  entity controls proves the **mechanism** live; it does **not** provide the
  guarantee that no single operator can reconstruct — that needs **independent**
  operators. Build to a shard roster (`[{ baseUrl, pubkey }]`) so flipping a
  same-operator cohort to independent operators is a config change, not code.
