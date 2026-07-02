# Blind Shard Store — `shard:<hash>` content-addressed blob surface

Status: **draft v0.1.0** — implementation-ready. Author: review pass 2026-07-02.
Target: `p2p-hiveservices` builtin service `shard-store`, wired into
`p2p-hiverelay` like `notify` / `outboxlog` / `storage-proof`.

---

## 1. Summary

A **content-addressed blind blob store**: a caller `PUT`s already-encrypted
bytes and gets back `shard:<hash>` where `hash = blake2b-256(ciphertext)`;
`GET shard:<hash>` returns those exact bytes. The address *is* the integrity
proof — the caller re-hashes what it receives and trusts the relay for nothing.
The relay only ever sees, hashes, stores, and serves opaque ciphertext.

The primitive exists to give **Atomic Blind Custody** a place to put its
erasure-coded / PVSS shares as *independently placeable, independently
verifiable* units — replacing today's single `shareBundleKey` hypercore bundle
with per-share content-addressed blobs. It is also usable stand-alone as a
generic blind CAS (e.g. chunk stores, sealed attachments).

### Goals

- G1. `PUT` / `GET` / `HEAD` / `DELETE` of opaque blobs keyed by content hash.
- G2. Content-address integrity: a served blob is self-verifying; a tampered
  or wrong-hash blob is rejected at `PUT` and detectable at `GET`.
- G3. Blindness: the relay never introspects or decrypts a blob, and does not
  leak *which* blobs it holds to unauthorized probers.
- G4. Anti-abuse: `PUT` cannot be a free disk-fill DoS. Every stored byte is
  authorized (custody pin **or** payment/quota) and accounted.
- G5. Custody integration: bind `shareIndex → shard:<hash>` so a
  `custody-receipt` can attest a specific share, and extend proof-of-storage
  to challenge a `shard:<hash>`.
- G6. Placement/recovery: shards replicate across operator-/region-diverse
  relays; a client can fetch k-of-n by hash and reconstruct.
- G7. Retention/eviction: retention windows, tombstones, ref-counting, and
  over-replication shedding — reusing StorageAccounting/eviction.

### Non-goals

- N1. **No plaintext, no encryption at the relay.** Callers seal bytes before
  `PUT`. The relay is content-agnostic. (Sealing helper lives client-side,
  reusing `outboxlog/blind-seal.js`.)
- N2. **Not proof-of-replication.** Possession proofs are challenge-response
  proof-of-retrievability, same honest limitation as `storage-proof`.
- N3. **No global content index.** The relay does not advertise a browsable
  list of all held hashes (that would defeat G3). Discovery is via custody
  manifests + DHT announce on the hash topic.

---

## 2. Concepts & addressing

| Term | Definition |
|---|---|
| **shard** | An opaque ciphertext blob, ≤ `maxShardBytes`. |
| **shard hash** | `blake2b-256(ciphertext)`, lowercase hex (64 chars). The canonical id. |
| **`shard:<hash>`** | The address string. `shard:` prefix + 64-hex. |
| **shard record** | Relay-side metadata for a stored shard (below). Never includes plaintext. |
| **manifest** | Signed map `shareIndex → shard:<hash>` published by a custody intent. |
| **pin** | An authorization that makes a shard eligible to be stored + retained. |

Hash algorithm: **BLAKE2b-256** via `sodium.crypto_generichash` (32-byte
output) — the same hash the proof layer already uses
(`proof-of-storage.js:storageProofSignable`). Hex is lowercased and validated
against `/^[0-9a-f]{64}$/`. The `shard:` prefix is required on the wire to
namespace against Hypercore keys (which are also 64-hex).

Large blobs are chunked by the storage engine (§4) but a shard's hash is over
its **whole ciphertext**, so content-addressing is chunk-transparent.

---

## 3. Architecture

New builtin service `shard-store` (`packages/services/builtin/shard-store/`),
a `ServiceProvider` registered in `plugin-loader.js:BUILTIN_MAP` exactly like
`storage-proof`. It composes three parts:

```
ShardStoreService (ServiceProvider)
├── ShardEngine        content-addressed store: hash → bytes (hyperblobs + index)
├── ShardPinRegistry   authorization + ref-counting + retention (who pinned what, until when)
└── ShardProofProvider signed possession proofs (extends proof-of-storage.js)
```

- **Storage engine** = a `hyperblobs` instance over a dedicated Hypercore
  (`shard-blobs` core) for the bytes, plus a **Hyperbee index**
  `blake2b(ciphertext) → { blobId, byteLength, refs, retainUntil, addedAt }`.
  hyperblobs addresses by `{blockOffset,byteOffset,...}` id, *not* by content
  hash, so the Hyperbee is what makes it content-addressed. The backing
  Hypercore gives replication + the Merkle tree the possession proof uses.
- **Pin registry** = a small signed/append store (mirror `outboxlog`'s
  journal+snapshot pattern, §12) recording each pin: `{ hash, pinner,
  reason: 'custody'|'payment', custodyIntentId?, retainUntil, sig }`. A shard
  is retained while it has ≥1 live pin; GC reclaims when refs hit 0 past grace.
- **Proof provider** = reuses the `proof-of-storage.js` signable/domain pattern
  and the `retrievability-proof.js` guard (NOT_SEEDED-indistinguishable,
  phantom-core DoS guard, per-caller token buckets).

Wiring: `RelayNode` constructs it via the plugin loader (opt-in
`config.plugins` includes `shard-store`), passes `{ node, store, config }` to
`start()`. Like the notify↔outboxlog composition (relay-node/index.js), the
relay attaches the **custody manifest source** so the pin registry can honor
custody-intent pins.

---

## 4. Data model & on-disk layout

**Shard record** (Hyperbee value, JSON):

```jsonc
{
  "hash": "<64-hex>",            // blake2b256(ciphertext) — also the key
  "blobId": { "blockOffset": 12, "byteOffset": 34567, "blockLength": 3, "byteLength": 65536 },
  "byteLength": 65536,           // ciphertext length
  "refs": 2,                     // live pin count
  "retainUntil": 1788000000000,  // max(pin.retainUntil) ; ms
  "addedAt": 1782900000000,
  "sealMeta": null               // OPTIONAL opaque caller hint (e.g. AEAD scheme id); never secret
}
```

**On disk** under `<storage>/shard-store/`:
- `blobs/` — the `shard-blobs` Hypercore (hyperblobs data + Merkle tree).
- `index/` — the Hyperbee (`hash → record`).
- `pins.jsonl` + `pins-state.json` — pin journal + checkpoint (journal-first,
  §12; identical layering to the outboxlog #144/#146 fix).

**Limits** (config, §14, with defaults):
`maxShardBytes = 4 MiB`, `maxTotalBytes` (inherits relay storage budget via
StorageAccounting), `maxShardsPerPinner`, `maxPins`.

---

## 5. Wire protocol

Two transports, one core. Primary is the **P2P service RPC** (blind
Pear/Bare clients reach it like `storage-proof`); the **HTTP bridge** mirrors
it for browser/ops (token-gated, like the outboxlog HTTP adapter).

### 5.1 Service RPC (capabilities)

`manifest().capabilities = ['put', 'get', 'has', 'unpin', 'prove']`

| Method | Params | Returns |
|---|---|---|
| `put` | `{ ciphertext: <bytes/base64>, claimedHash?, pin: {...}, sealMeta? }` | `{ ok, shard: "shard:<hash>", byteLength, deduped }` |
| `get` | `{ hash, nonce? }` | `{ ok, ciphertext, byteLength }` (nonce ⇒ also returns a possession proof) |
| `has` | `{ hash }` | `{ ok, present, byteLength }` — **auth-gated** (§7) |
| `unpin` | `{ hash, pinRef, sig }` | `{ ok, refs }` |
| `prove` | `{ hash, nonce }` | signed possession attestation (§10) |

### 5.2 HTTP bridge

```
POST   /api/v1/shard              body=ciphertext, headers: X-Shard-Pin, X-Pear-Token  → 201 {shard,byteLength,deduped}
GET    /api/v1/shard/<hash>       → 200 octet-stream (+ optional X-Shard-Proof header when ?nonce=)
HEAD   /api/v1/shard/<hash>       → 200 (Content-Length) | 404  (auth-gated, constant-shape)
DELETE /api/v1/shard/<hash>       body={pinRef,sig}  → 200 {refs}
POST   /api/v1/shard/<hash>/prove body={nonce}  → 200 {proof}
```

Route resolution mirrors `resolveSeedCoreRoute` / `resolveRetrievabilityProofRoute`.
Body size hard-capped at `maxShardBytes`; streamed to the engine, never fully
buffered beyond the cap.

---

## 6. Content-address integrity

- **On `PUT`:** stream bytes → `crypto_generichash` running hash; on close,
  compare to `claimedHash` if provided (reject `HASH_MISMATCH` 400 if differ);
  store under the computed hash. **Idempotent:** if the hash already exists,
  bump refs, return `deduped: true`, store nothing new.
- **On `GET`:** the caller re-hashes the returned bytes and compares to the
  requested hash. The relay MAY also attach a possession proof (§10). A relay
  that returns wrong bytes is caught by the caller's re-hash — no trust needed.
- Hash is over **ciphertext**, so integrity holds without the relay reading
  plaintext.

---

## 7. Blindness & privacy

- **Never introspect.** The engine only hashes/stores/serves bytes. `sealMeta`
  is an opaque caller string (bounded), stored verbatim, never parsed.
- **Existence-probe posture (the important one).** A naive `GET → 404` lets
  anyone enumerate which shards a relay holds — a metadata leak about who is
  custodying what. Adopt the `retrievability-proof` stance:
  `NOT_HELD` is **indistinguishable** from `held-but-unauthorized`.
  Concretely: `has`/`HEAD`/`GET` for a hash the caller isn't authorized to
  read return the *same* shape/timing as "not held". Read authorization =
  the caller proves (a) knowledge of the hash **and** (b) a read capability:
  either they hold a pin on it, or they present a custody membership proof
  (a signature chaining to the custody intent that names the hash), or the
  operator runs the store in `openRead` mode (explicitly non-blind, opt-in).
  Default: **hash-knowledge is the read capability** for GET (you can't ask
  for bytes you can't name), but `has`/enumeration requires the stronger cap.
- No global list endpoint. No metrics that reveal individual hashes.

---

## 8. `PUT` authorization — the load-bearing decision

Content-addressed `PUT` is inherently open (anyone with bytes can store them),
so unauthorized `PUT` is a disk-fill DoS. Every stored byte MUST be authorized
by exactly one of:

**A. Custody pin (recommended default).** The `PUT` carries a `pin` that
references a *valid signed `custody-intent`* whose manifest binds this exact
`shard:<hash>` to a `shareIndex` assigned to this relay
(`shareAssignments[relayPubkey].shareIndex`). The store accepts the byte only
if the hash appears in a live custody manifest it is assigned. This ties the
store tightly to custody, needs no payment rail, and makes the byte-budget
self-limiting (bounded by accepted custody intents).

**B. Payment / quota.** For stand-alone CAS use, gate `PUT` behind the
existing subsidy/payment surface (`api-subsidy.js`) and a per-pinner abuse
bucket (reuse notify's `consumeBucket` + configurable limits). A paid/quota'd
pin sets `reason: 'payment'` and counts against the pinner's budget.

**C. Capability token.** An operator-issued bearer (like the outboxlog token)
for trusted first-party apps.

The pin object:

```jsonc
{
  "reason": "custody" | "payment" | "token",
  "custodyIntentId": "<hex>",     // required when reason=custody
  "shareIndex": 3,                // required when reason=custody
  "pinner": "<pubkey hex>",       // who is responsible / billable
  "retainUntil": 1788000000000,
  "nonce": "<hex16>",
  "sig": "<128-hex>"              // pinner signs the pin body (domain-separated)
}
```

**Recommendation:** ship **A** (custody pin) as the default and only mode for
v1; add **B/C** behind config flags. This is the single upstream decision that
unblocks the rest — it makes the store a custody component first, generic CAS
second.

---

## 9. Custody integration

The custody v2 layer (`custody-signing.js`) already models shares:
`custody-intent` carries `shareScheme`, `shareThreshold`, `commitmentRoot`,
`shareBundleKey`, `shareAssignments` (relay→shareIndex); `custody-receipt`
carries `shareIndex`, `shareCommitment`, `shareVerified`. The shard store
replaces the single `shareBundleKey` bundle with **per-share content-addressed
blobs**:

1. **Manifest binding.** Extend the intent with a `shareManifest`:
   `[{ shareIndex, shard: "shard:<hash>", shareCommitment }]`, and make
   `commitmentRoot = merkleRoot(sorted shareCommitments)` (already the field).
   Add `shard` (the content hash) alongside each `shareCommitment` so a
   relay's "I hold share 3" is verifiable as "I hold the blob whose hash the
   signed manifest binds to index 3". `shareManifest` is an allowed field on
   `custody-intent`; validation (custody-signing.js:473+) additionally checks
   `manifest[shareIndex].shard` is present and well-formed.
2. **Publisher flow.** Publisher seals each share, `PUT`s it (reason=custody,
   its own intent), collects the returned hashes into `shareManifest`, signs
   the intent. Each assigned relay then `PUT`s (dedupes) / pins its share and,
   on `shareVerified`, signs the `custody-receipt`.
3. **`shareVerified`.** A relay sets `shareVerified: true` only after it holds
   the blob AND the blob's hash matches the manifest binding for its assigned
   `shareIndex` (content-address check) AND the public share commitment
   verifies (existing PVSS check — no secret key).
4. **Recovery.** A recovering client reads the (published) intent → gets the
   `shareManifest` → fetches ≥ `shareThreshold` shards by hash via `GET` from
   whichever assigned relays answer → reconstructs. Discovery: DHT announce on
   `topic = blake2b('shard' || hash)` so holders are findable without a
   central index (§11).
5. **State-machine roles** map onto proofs (§10): `custody-proof` (observer
   possession during retention), `custody-non-serving-proof` (relay signs it
   no longer serves the hash post-expiry) both use the shard possession proof.

---

## 10. Proof-of-possession for shards

Two modes, both reusing `proof-of-storage.js` conventions
(domain-separated, relay-swarm-key signed, nonce-guarded, verifiable against
the hash alone — relay trusted for nothing).

**Mode R — retrieval proof (strongest, default).** `GET {hash, nonce}` returns
the bytes **plus** a Hypercore Merkle proof that the blob's blocks hash into
the `shard-blobs` core, plus a signature over
`DOMAIN || shard-hash || nonce || blake2b(block)`. Because the address *is*
the content hash, the verifier re-hashes the returned bytes → integrity is
self-proving even without the signature; the signature adds relay attribution
+ replay resistance. This is the analog of `retrievabilityProofSignable`.

**Mode A — signed possession attestation (no bytes transferred).** `prove
{hash, nonce}` returns a signature over
`SHARD_PROOF_DOMAIN || shard-hash || nonce || blake2b(nonce || firstBlock)`
where `firstBlock` is the blob's first storage block. This lets an observer /
witness get a relay-signed, replay-guarded attestation *without* pulling the
whole share — feeding `custody-proof` / `custody-non-serving-proof`. It is a
weaker guarantee than Mode R (proves possession of the first block + a signed
claim), and MUST be documented as such (same honesty bar as
`RETRIEVABILITY_PROOF_LIMITATION`).

New constants (mirror proof-of-storage.js):
`SHARD_PROOF_DOMAIN = 'hiverelay.shard-possession.v1'`,
`SHARD_PROOF_KIND = 'proof-of-shard-possession'`,
`SHARD_PROOF_SIGNATURE_PROFILE = 'shard-possession-v1'`.

Relay-side guard (copy `retrievability-proof.js`): serve a proof **only** for a
hash the store actually holds *and* the caller is authorized to read (§7);
otherwise `NOT_HELD` — indistinguishable from unauthorized. Per-caller token
buckets throttle proof spam (phantom-hash DoS guard: never touch the engine
for an unheld hash beyond a constant-time index miss).

Verifier (`packages/verifier` + client): `verifyShardProof(proof, {hash,
nonce, relayPubkey})` → checks domain, nonce match, signature, and (Mode R)
that the returned bytes hash to `hash`.

---

## 11. Placement, replication, recovery

- **Blob-core replication.** The `shard-blobs` Hypercore replicates over the
  existing swarm like any seeded core; an assigned relay joins the custody's
  topic and pulls the shares it is assigned. Because shards are content-hashed,
  a relay can hold a *sparse* subset (only its assigned indices) — it does not
  need the whole bundle. (This is the win over `shareBundleKey`.)
- **Discovery.** Each holder announces on `topic = blake2b('shard' || hash)`.
  A recovering client / AutoHeal looks up the topic to find current holders.
  Announce is presence-only (holder pubkey), never the plaintext.
- **AutoHeal / re-replication.** Extend the existing AutoHeal scheduler
  (referenced in ATOMIC-BLIND-CUSTODY.md) to treat a `shard:<hash>` as a
  first-class placeable unit with a target replica count = the share's
  assignment count. On a holder drop (missed possession proof), re-assign the
  share to a diversity-satisfying replacement and have it `PUT`/pull the blob.
- **Diversity.** Reuse the operator/region fairshare cap
  (`ceil(target / minOperators)` per operator) so a share set is spread across
  diverse operators — the shard policies (`shards-10of16-diverse`, witness
  variants) depend on this.

---

## 12. Retention, eviction, GC

- **Ref-counted retention.** A shard lives while `refs ≥ 1`. `retainUntil =
  max(live pins.retainUntil)`. A pin expires at its `retainUntil`; when the
  last pin expires, the shard enters a grace window then is GC'd (blob freed
  from the core via hyperblobs `clear`, index row deleted).
- **Tombstones.** On custody expiry, the relay can emit a
  `custody-non-serving-proof` (Mode A signed over the hash) and drop the shard
  — the tombstone is the signed record that it *stopped* serving.
- **Eviction integration.** Register shard bytes with `StorageAccounting`
  (`storage-accounting.js`) so they count in the honest disk total and the
  adoption/over-replication guard. Over-replication shed: if a share has more
  than its target replicas and this relay is not diversity-critical, it may
  shed (drop pin + blob) — reusing the eviction floor-gate logic.
- **Persistence durability.** The pin journal is journal-first (append per pin)
  + periodic snapshot checkpoint, with signature re-verification on load and
  drop-unverifiable-rows — identical to the outboxlog #144/#146 model, so a
  tampered `pins.jsonl` can't forge retention.

---

## 13. Accounting, metrics, dashboard

- StorageAccounting counts `shard-store/blobs` bytes as part of the measured
  disk total.
- Metrics (Prometheus, `metrics.js`): `hiverelay_shards_held` (gauge),
  `hiverelay_shard_bytes` (gauge), `hiverelay_shard_put_total` /
  `_get_total` / `_proof_total` (counters), `hiverelay_shard_proof_pass_ratio`.
  **No per-hash labels** (privacy).
- Dashboard: a small card on the custody/services page — shards held, bytes,
  proof pass rate, pins near expiry.

---

## 14. Config

```jsonc
"shardStore": {
  "enabled": false,                 // opt-in via config.plugins too
  "maxShardBytes": 4194304,         // 4 MiB
  "maxTotalBytes": null,            // null ⇒ inherit relay storage budget
  "maxShardsPerPinner": 100000,
  "maxPins": 1000000,
  "retentionGraceMs": 86400000,     // 24h after last pin expiry
  "putAuth": "custody",             // "custody" | "payment" | "token" | ["custody","payment"]
  "openRead": false,                // true ⇒ non-blind GET (explicit opt-out of §7)
  "persistFlushMs": 250,            // debounced snapshot (like notify)
  "proofBuckets": { "perHour": 600, "burst": 60 },
  "putBuckets":   { "perHour": 6000, "burst": 200 }
}
```

---

## 15. Threat model

| Threat | Mitigation |
|---|---|
| Disk-fill DoS via open PUT | §8 authorization (custody pin / payment / token); per-pinner quota; byte budget |
| Relay serves wrong/garbage bytes | Content-address: caller re-hashes GET → detects; retrieval proof (§10) |
| Relay forges "I hold it" | Possession proof over content hash + nonce; Mode A limited (documented) |
| Enumerate what a relay custodies | §7 NOT_HELD-indistinguishable; no list endpoint; no per-hash metrics |
| Tampered on-disk pins forge retention | Journal signature re-verify on load, drop unverifiable (§12) |
| Phantom-hash proof spam | Per-caller token buckets; constant-time index miss for unheld hashes |
| Recover plaintext from shards | Client seals before PUT; relay never has keys; k-of-n diversity (custody sim) |
| Replay a recorded proof | Fresh 32-byte challenge nonce in the signable |
| Correlate share holders | DHT announce is presence-only; diverse placement |

---

## 16. API reference (error codes)

`OK` shapes in §5. Errors (HTTP status / RPC `code`):

| Code | HTTP | When |
|---|---|---|
| `HASH_MISMATCH` | 400 | PUT bytes don't hash to `claimedHash` |
| `TOO_LARGE` | 413 | blob > `maxShardBytes` |
| `UNAUTHORIZED_PIN` | 403 | pin doesn't reference a valid custody assignment / lacks payment/token |
| `QUOTA_EXHAUSTED` | 429 | pinner over quota / bucket empty |
| `NOT_HELD` | 404 | not held **or** unauthorized read (indistinguishable) |
| `BAD_SIGNATURE` | 400 | pin/unpin/proof-request signature invalid |
| `STORAGE_FULL` | 507 | relay byte budget exhausted |
| `SERVICE_UNAVAILABLE` | 503 | engine not started |

---

## 17. Test plan

- **Engine:** put→get round-trip; dedup (same bytes → same hash, refs++);
  HASH_MISMATCH; TOO_LARGE; chunked blob (> 1 hypercore block) hashes whole.
- **Content-address integrity:** GET of a hash whose bytes were externally
  mutated on disk is caught by re-hash; corrupted index row rejected on load.
- **Blindness/privacy:** unauthorized `has`/`GET` returns NOT_HELD identical to
  truly-absent (shape + timing within tolerance); no plaintext in any response.
- **Auth:** custody-pin PUT accepted only when hash ∈ signed manifest for the
  assigned index; unassigned relay rejected `UNAUTHORIZED_PIN`; payment/quota
  path with zero limit → `QUOTA_EXHAUSTED`.
- **Custody integration:** intent with `shareManifest` validates; receipt
  `shareVerified` requires held+hash-match; commit needs distinct-index quorum;
  recovery fetches k-of-n by hash and reconstructs (simulation vector).
- **Proofs:** Mode R proof verifies against hash+relay key; wrong nonce
  rejected; recorded proof not replayable; Mode A attestation verifies +
  documented-limitation asserted; phantom-hash spam throttled.
- **Retention/GC:** last-pin expiry → grace → GC frees blob + index; tombstone
  emitted; over-replication shed respects diversity floor; StorageAccounting
  reflects shard bytes.
- **Durability:** pin journal-first + checkpoint; crash-without-flush restore
  replays tail; hand-edited `pins.jsonl` drops unverifiable rows.
- **Bench:** put/get p50/p99, proof p99, RSS per 10k shards — a
  `scripts/bench-shard-store.mjs` mirroring the outboxlog bench, with release
  budgets.

---

## 18. Phased build plan

**M1 — Engine + surface (MVP CAS).** `ShardEngine` (hyperblobs + Hyperbee
index), `put/get/has/unpin`, content-address integrity, size caps, HTTP + RPC,
debounced persistence, StorageAccounting hook, per-caller quota. Tests + bench.
*Acceptance:* blind put/get/dedup works; unauthorized PUT rejected; bytes
counted; privacy posture enforced.

**M2 — Pins + custody binding.** `ShardPinRegistry` (journal-first + checkpoint,
sig re-verify), custody-pin auth (mode A of §8), `shareManifest` field on
`custody-intent` + validation, `shareVerified` gate. Tests incl. recovery
vector. *Acceptance:* a custody intent can bind shares to hashes; only assigned
relays pin; receipt attests correctly.

**M3 — Proofs.** `ShardProofProvider`, `SHARD_PROOF_DOMAIN`, Mode R + Mode A,
`verifyShardProof` in verifier + client SDK, relay guard + buckets. Tests.
*Acceptance:* possession provable/verifiable against hash alone; limitations
documented; spam throttled.

**M4 — Placement/recovery/retention.** DHT announce on hash topic, AutoHeal
shard unit + diversity cap, over-replication shed, tombstones, GC. Tests +
simulation. *Acceptance:* a dropped holder is re-healed diversely; expiry
GCs + tombstones; k-of-n recovery end-to-end.

**M5 — Ops.** Metrics, dashboard card, config surface, docs, release. Ship as
a `shard-store` builtin service (opt-in), likely v0.22.0.

---

## 19. Open decisions (need a call before M1)

1. **PUT auth default** — custody-pin-only for v1 (recommended), or also
   payment/token from day one? (Determines coupling + the pin schema surface.)
2. **Read capability** — is hash-knowledge sufficient for `GET` (default), or
   require a custody-membership proof for reads too (stricter blindness)?
3. **Engine** — hyperblobs+Hyperbee (recommended, gets replication + Merkle
   proofs free) vs. a flat on-disk CAS (simpler, but then proofs need a
   separate Merkle scheme and no free replication).
4. **Manifest home** — extend `custody-intent` with `shareManifest`
   (recommended, keeps it signed + in the state machine) vs. a side document
   referenced by `shareBundleKey`.
5. **Chunk size / max shard** — 4 MiB default OK, or align to the erasure-code
   shard size the custody encoder emits?
