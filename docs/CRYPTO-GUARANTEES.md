# Cryptographic guarantees

What a HiveRelay operator can and cannot do, in terms of math rather than
trust. If you're an operator weighing what you're signing up for, or an app
developer choosing relays, this is the document to point at.

## TL;DR

A relay's trust surface depends on the content mode.

- For **public/non-blind apps**, a relay may store readable public Hypercore
  blocks and catalog metadata. Do not use public mode for data that must remain
  confidential from the operator.
- For **blind-mode apps and atomic custody payloads**, the relay stores
  ciphertext and does not receive the decryption key. The operator can still
  see network metadata such as peer pubkeys and timing.

Across those modes, the relay cannot:

- Forge an app or its updates (publisher signature required, verified by every reader)
- Pass proof-of-relay/storage-proof challenges without the challenged bytes and
  matching cryptographic proof material
- Decrypt a blind-mode app or custody payload even if it stores the ciphertext
  forever (the encryption key is never sent to relays)

This isn't a promise from the relay operator. It's enforced by the protocol;
a malicious operator who tried to violate any of the above would either fail
the cryptographic check or simply not produce the result. Apps and clients
verify, they don't trust.

## What's encrypted

### 1. The wire (Noise / hypercore-protocol)

Every Hyperswarm connection — peer-to-peer or peer-to-relay — is wrapped in
a Noise XK handshake (`hypercore-protocol`) before any application data
flows. The handshake provides:

| Property | Means |
|---|---|
| Confidentiality | A passive observer (including the relay forwarding the bytes) sees ciphertext only — random-looking bytes |
| Integrity | An active attacker can't tamper with bytes in flight without breaking the MAC; receiver detects and tears down the connection |
| Forward secrecy | If the long-term keys leak later, past sessions remain unreadable (ephemeral keys are discarded after handshake) |
| Mutual authentication | Both sides prove possession of their static keys; the connection is identity-pinned |

This applies to the Hypercore *replication* protocol and to every Protomux
sub-channel layered on top (seed-request, circuit-relay, proof-of-relay,
service-RPC, app-catalog). Passive observers and relays that only forward
opaque circuit traffic see Noise frames. A relay that is the replication
endpoint decrypts its own transport session and may store the resulting public
blocks unless the app content is encrypted before replication.

Wire encryption protects data in transit from passive observers and from relays
that are merely forwarding opaque circuit traffic. A relay that intentionally
seeds a public/non-blind app also stores the app's public blocks, so wire
encryption is not a confidentiality guarantee against that relay's local disk.
Use blind mode or application-level encryption when the relay operator must not
read content.

**Source:** [hypercore-protocol README](https://github.com/holepunchto/hypercore-protocol),
[Noise Protocol Framework spec](http://www.noiseprotocol.org/noise.html).

### 2. App content (Hypercore)

Hypercores are Merkle-tree-backed append-only logs. Each block is signed
by the publisher's keypair. Readers verify the signature against the
public key (the appKey) before accepting the block. A relay that stored
forged blocks would simply fail signature verification on the reader side
— forged content cannot enter the chain.

| Layer | Crypto |
|---|---|
| Block authenticity | Ed25519 signature over the Merkle root by the publisher key |
| Position integrity | Every block references the previous Merkle root — blocks cannot be reordered or omitted without detection |
| Write authority | Only the holder of the publisher private key can append |

**Implication for relays:** a relay cannot inject content into an app's feed.
For non-blind/public apps, it may be able to read the public blocks it stores;
for blind-mode apps, it stores ciphertext. In both cases, the worst integrity
failure it can cause is refusal or selective service, which readers route
around by querying other peers.

### 3. Blind-mode apps

For apps that publish in blind mode (`client.publish(content, { encryptionKey })`),
content is encrypted with a 32-byte symmetric key *before* it enters the
Hypercore. The relay stores the encrypted blocks as opaque bytes and has
no way to decrypt them.

| What relays see | What they don't |
|---|---|
| Encrypted block ciphertext | Plaintext content |
| The appKey (Hypercore public key) | The encryption key (never transmitted to relays) |
| Block sizes and rough write timing | Block contents |
| Peer connection metadata (which pubkeys connected) | Reader identity beyond pubkey |

The encryption key is shared peer-to-peer (out of band, or through the app
itself once a reader authenticates). The relay never holds it.

**Concrete guarantee:** even an operator with full filesystem access to
their own relay storage holds nothing more than encrypted blocks they can't
decrypt. The HTTP gateway returns 403 for blind apps to enforce this at the
application layer too — there's no "view in browser" path that would
require decryption.

### 4. Identity & seed requests

Seed requests carry a signature from the app's publisher key over
`(appKey || 'seed' || timestamp || maxStorageBytes)`. Relays verify the
signature before honoring the request. This means:

- Anyone can ask a relay to seed an app, but only the app's publisher
  can authenticate the request as "I'm the one publishing this"
- Replay protection: timestamps must be within a 5-minute window of
  the relay's clock, and signatures are cached for dedup
- An unsigned seed request can still be accepted (depending on
  acceptMode), but it carries no publisher attestation — the operator is
  trusting the network's reputation system to surface bad actors

Unseed requests (the kill switch) require the same publisher signature.
A relay won't drop content on a third party's say-so.

## What proof-of-relay actually proves

A relay can be challenged to produce a Merkle proof for a specific block of
content it claims to be serving. The challenger picks a random block, the
relay returns the block + its inclusion proof, the challenger verifies
against the publisher's signed Merkle root.

What this proves:
- The relay actually has the bytes (otherwise it can't produce the proof)
- The bytes are the correct ones (otherwise the inclusion proof fails)

What this does *not* prove:
- That the relay will serve the bytes to a different peer at request time
  (it can selectively answer)
- That the relay holds the bytes *in memory* — it could fetch on demand
  from another peer and proxy

That's why proof-of-relay is paired with **bandwidth receipts** (signed proofs
of bytes actually transferred to a counterparty) and, where enabled, sampled
`storage-proof` service challenges for a richer "this relay is serving" signal.
See `core/protocol/proof-of-relay.js`,
`core/protocol/bandwidth-receipt.js`, and
`services/builtin/storage-proof-service.js`.

## Trustless seed verification

How a client confirms that a *specific* relay genuinely holds and serves an
app — without trusting the relay's self-reported catalog. There are two
tiers, layered, each anchoring its trust in the drive key's signed Merkle
root rather than in the relay's word.

### Tier 1 — replication check (`client.verifySeeded`)

```js
const v = await client.verifySeeded(driveKey, { relay: relayPubkeyHex })
//   { complete, relayIsPeer, relayHasFullLength, contentVerified,
//     metaLength, blobsLength, relayRemoteLength }
```

The client opens the drive, confirms the relay is a live peer advertising the
full length, and downloads **both** of the drive's Hypercores (metadata +
blobs) to completion. Hypercore verifies every block against the drive key's
signed Merkle root *on arrival* — a forged or substituted block fails
verification, so the relay cannot fake content it isn't the author of.

| Field | Means |
|---|---|
| `contentVerified` | The genuine, complete content downloaded and verified against the drive key |
| `relayIsPeer` | The relay is a live peer of the drive |
| `relayHasFullLength` | The relay *advertises* the full metadata length |
| `complete` | `relayHasFullLength && contentVerified` |

**What this does *not* prove.** Replication rides the shared swarm, so
`contentVerified` proves the content is genuine and served *by the swarm*,
and `relayHasFullLength` is the relay's own advertised state. It is **not** a
per-block, relay-attributable, third-party-portable proof. For that, Tier 2.

### Tier 2 — signed proof-of-retrievability (`client.proveSeeded`)

```js
const r = await client.proveSeeded(driveKey, { relay: relayPubkeyHex, samples: 5 })
//   { ok, driveKey, relay, head, passed, total,
//     samples: [{ index, valid, reason }, …] }
//   r.ok === true only if EVERY sampled block verified at the current head
```

The client opens the drive (learning the metadata head), samples up to 16
random block indices, and for each one challenges the relay with a fresh
32-byte nonce over the existing service RPC (`storage-proof.prove`). Each
signed proof is verified against an isolated, key-only verifier core. Two
independent checks, neither trusting the relay:

| Check | Crypto |
|---|---|
| Content | A real Hypercore block proof; the key-only verifier confirms the block hashes into the drive key's **signed Merkle root** — forged content is rejected |
| Attribution + freshness | The relay signs `coreKey \|\| u32le(index) \|\| nonce \|\| blake2b(block)` with its swarm identity key — the proof is attributable to *this* relay and bound to *this* nonce, so a recorded proof can't be replayed |
| Length pin | The proof's author-signed `upgrade.length` is checked against the current head (`minLength`), rejecting a relay stuck on an old, shorter signed version |

Relay-side, `buildStorageProof` reads **local storage only** — it throws
`BLOCK_NOT_LOCAL` / `BLOCK_OUT_OF_RANGE` rather than fetch-on-demand to answer
a challenge.

**Honest limitation.** This is a challenge-response **proof-of-retrievability**,
not a sealed **proof-of-replication**. A relay could in principle fetch a
block on demand rather than store it. Random-index sampling across the full
core plus a latency bound make that expensive and detectable — but it is *not*
cryptographically precluded. Sealed PoRep is out of scope. (v1 proves the
drive's **metadata** core; blobs-core proofs are a follow-up.)

**Privacy gate (blind drives).** The relay-side service is opt-in and **off
by default** (Node: `config.plugins` / Services tab; Bare/appliance:
`config.services` or `HIVERELAY_STORAGE_PROOF=1`). Critically, a blind or
privacy-redacted drive returns `NOT_SEEDED` — **indistinguishable** from a key
the relay genuinely doesn't hold. A signed proof is cryptographic,
relay-attributable evidence of possession; serving it for a blind drive would
turn `prove()` into a possession oracle that defeats the catalog's deliberate
redaction (see "Blind-mode apps" above). The service also carries a
sybil-resistant global proof-work rate cap and a phantom-core DoS guard
(it only proves keys already in the relay's app registry — never `store.get`
on a caller-supplied key).

## Threat model — what a malicious operator can do

| Attack | What happens |
|---|---|
| Read app contents (non-blind) | Possible — the operator stores plaintext blocks. **Use blind mode if you don't want this.** |
| Read app contents (blind mode) | **Impossible** — they only have ciphertext, no key |
| Inject forged content into an app | **Impossible** — Ed25519 signature verification on every block |
| Modify blocks they're storing | Detectable — Merkle root mismatch |
| Refuse to serve content | Possible — but other relays / peers will serve it (this is why replication-factor matters) |
| Lie about serving in proof-of-relay | **Impossible** — they have to produce real Merkle proofs against real bytes |
| Fake holding a seeded app under proof-of-retrievability | **Cannot forge content** — signed block proofs must hash into the drive key's signed root; can't fake attribution either (relay signature over a fresh nonce). Can only fetch-on-demand instead of storing (PoR limit) |
| Surveil who connects | Possible — they see counterparty pubkeys (this is the network-metadata threat). Mitigations: Tor transport, ephemeral keys per session |
| Censor specific apps from their catalog | Possible — that's the whole *point* of accept-modes. The operator chooses what they carry. Other relays may still carry it. |

## Threat model — what a malicious *client* can do

| Attack | Impact |
|---|---|
| Submit floods of seed requests | Mitigated by accept-modes (Review queues, Closed rejects) and per-relay rate limits |
| Try to push forged content under someone else's appKey | Fails — signature check |
| Try to use a relay as an open DDoS amplifier via DHT-relay-WS | Mitigated by `maxConnections` per transport plus API and endpoint rate limits; transport-specific abuse controls still remain an operational tuning surface |
| Try to read another app's blind content | Fails — they don't have the encryption key |

## How this compares to running on a centralized cloud

| Property | HiveRelay (blind mode) | Cloud (S3 / Lambda / Vercel) |
|---|---|---|
| Operator can read your data | No | Yes (or service role can) |
| Operator can subpoena your data | Only ciphertext available | Yes, plaintext |
| Operator can be coerced to forge content | No (signature) | Yes (vendor controls signing keys) |
| Operator visibility into who reads | Pubkeys only, can be ephemeral | IP addresses, often tied to identity |
| Single point of failure | No (multiple replicas) | Vendor outage |
| Compliance/data-residency claims | Operator chooses what to store | Vendor SLA |

This isn't an argument that HiveRelay is unconditionally better — there are
plenty of apps where vendor-managed makes more sense. It's an argument that
the *trust surface is genuinely smaller* for apps that fit the model.

## What we're explicitly *not* claiming

- **Anonymity.** A relay sees the pubkey of every peer that connects. That's a
  network-metadata leak. If you need anonymity, layer Tor (`transports/tor/`)
  or use ephemeral keypairs per session.
- **Censorship resistance against state actors.** A nation-state can
  fingerprint and block Hyperswarm DHT traffic. We provide the tools (Tor,
  blind mode, federation) but don't claim impunity against well-funded
  adversaries.
- **Long-term unbreakable encryption.** Curve25519 / Ed25519 / ChaCha20-Poly1305
  are state-of-the-art today. They could conceivably be broken in 30 years
  by quantum computers. Nothing in HiveRelay specifically addresses
  post-quantum, and that's an honest limitation.

## Source pointers

- `packages/core/core/protocol/seed-request.js` — signature scheme
- `packages/core/core/protocol/proof-of-relay.js` — challenge/response math
- `packages/core/core/protocol/bandwidth-receipt.js` — signed transfer proofs
- `packages/core/core/protocol/proof-of-storage.js` — Tier-2 signed proof-of-retrievability (legacy `storage-proof` route, build/verify)
- `packages/services/builtin/storage-proof-service.js` — Tier-2 relay service (`storage-proof.prove`, privacy gate, rate caps)
- `packages/client/index.js` — `client.verifySeeded` (Tier 1) and `client.proveSeeded` (Tier 2)
- `packages/services/identity/attestation.js` — Schnorr attestations for dev-key → app-key bindings
- [hypercore docs](https://docs.holepunch.to/) — upstream cryptography
- [Noise Protocol XK pattern](http://www.noiseprotocol.org/noise.html#interactive-handshake-patterns) — wire encryption
