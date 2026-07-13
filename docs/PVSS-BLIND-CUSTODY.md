# PVSS Blind Key Custody

*Publicly verifiable threshold custody of secrets, on top of HiveRelay's blind
custody plane. Shipped in v0.9.0; made end-to-end in v0.9.1–v0.9.2.*

Atomic Blind Custody (see [ATOMIC-BLIND-CUSTODY.md](./ATOMIC-BLIND-CUSTODY.md))
lets relays hold encrypted **content** they can't read and prove they stopped
serving it. PVSS blind custody extends that guarantee to the **keys
themselves**: a relay holds an opaque, guardian-encrypted *share* of a secret,
publicly verifies that share is well-formed **without ever decrypting it**, and
any *t-of-n* guardians later reconstruct the secret entirely client-side.

No party can reconstruct alone — not the relay (it never has a guardian key),
and not any single guardian (it has one share of `t`). This is the primitive
behind social recovery, team break-glass, and inheritance for serverless / Pear
apps, with always-on, auditable availability.

---

## The scheme

`pvss-secp256k1-v1` — Schoenmakers Publicly Verifiable Secret Sharing over
secp256k1:

- **Secret.** A scalar `s`; the dealer-private outputs are the secret point
  `S = s·G` and a derived `key` (a hash of `S`). Only the dealer ever sees
  these.
- **Feldman commitments.** The dealer commits to its sharing polynomial as
  `C_j = a_j·G`. `commitmentRoot` is a hash over the commitment vector and is
  named in the signed intent; the full vector travels in the public share
  bundle.
- **Encrypted shares.** Share `i` is encrypted to guardian `i`'s public key as
  `Y_i`. Only the holder of guardian `i`'s secret key can recover the
  plaintext share `S_i`.
- **Per-share DLEQ proofs.** Each encrypted share carries a non-interactive
  proof that `Y_i` encrypts the *correct* share for that commitment — checkable
  by anyone, with no secret. This is what lets a relay verify a share it cannot
  read.
- **Reconstruction.** Any `t` guardians decrypt their shares and Lagrange-
  interpolate **in the exponent** to recover `S` (and thus `key`).
  `reconstruct()` re-checks each decryption's DLEQ, so a forged or merely-
  re-encrypted share is rejected at recovery.

Two disjoint key sets are involved:

| Set | Curve / type | Role |
|---|---|---|
| **Guardians** | secp256k1 (`keygen()` → `{ publicKey, secretKey }`) | Can decrypt a share and reconstruct. The recovery quorum. |
| **Relays** | ed25519 (Hyperswarm identity) | Custody + publicly verify shares + sign receipts. **Never** decrypt. |

`shareThreshold` (t) is the **reconstruction** threshold. The intent's
`requiredReplicas` equals the relay/share count **n** — it is the commit floor
and the upper bound on `shareIndex`. Relay `relays[i]` is assigned
`shareIndex = i + 1`.

---

## Data path (what travels where)

Custody splits cleanly into a control plane and a data plane:

- **Control plane (HTTP custody channel, publisher-authed).** The signed v2
  custody intent and commit. The intent names `shareScheme`, `shareThreshold`,
  `commitmentRoot`, `shareBundleKey`, and the `shareAssignments`
  (relayPubkey → shareIndex). Tiny; no bulk data.
- **Data plane (P2P replication).** The **public** share bundle
  (`commitments[]` + `encryptedShares[]` + per-share DLEQ proofs) is written to
  a sibling Hypercore — `shareBundleKey` — that custodying relays replicate.
  Public material only; no secret, so blindness is preserved end-to-end.

The dealer's `key` / `secretPoint` are returned to the caller and **must never
be published**.

---

## Client API

Both methods are on `HiveRelayClient`. Crypto (`p2p-hiverelay-client/secret-sharing.js`)
and signing (`p2p-hiverelay-client/custody.js`) are Bare-safe and self-contained
— they do not depend on the relay package, so they run in Pear/Bare.

### `splitForCustody({ secret?, guardians, threshold, relays, appKey, opts })`

1. PVSS-split the secret to the guardians' recipient pubkeys.
2. Write the public share bundle to a fresh sibling Hypercore and serve it.
3. Author + sign the v2 custody intent (`addressKey = appKey`,
   `requiredReplicas = relays.length`, `shareThreshold = threshold`,
   `shareBundleKey`, `shareAssignments`).
4. Publish the intent to each relay (HTTP, Bearer-authed).
5. **Seed for custody** — POST `/seed` per relay with the `custodyIntentId`.
   This is what drives the relay to replicate + verify its assigned share and
   anchor a receipt. *(Added in v0.9.1; without it no receipt is ever
   produced.)* `opts.maxStorage` is required as a positive safe-integer byte
   bound and is forwarded unchanged to every relay seed. Missing, zero, or
   unsafe bounds fail before the bundle or intent is published.
6. Poll until every relay returns a **share-verified, anchored** receipt.
7. Sign + publish the quorum commit.

Returns `{ intentId, commitmentRoot, shareBundleKey, key, secretPoint, intent,
commit, receipts }`. `key` + `secretPoint` are dealer-private.

### `reconstructFromCustody({ intentId, guardianSecretKeys, relays?, shareBundleKey?, threshold? })`

Resolves `shareBundleKey` (from a relay's signed intent if not passed), reads
the public bundle, decrypts only the shares belonging to the supplied guardian
keys, and Lagrange-reconstructs. Returns `{ key, secretPoint, shares }`.

```js
import { HiveRelayClient } from 'p2p-hiverelay-client'
import { keygen } from 'p2p-hiverelay-client/secret-sharing.js'

const g1 = await keygen(); const g2 = await keygen(); const g3 = await keygen()

const res = await app.splitForCustody({
  guardians: [g1.publicKey, g2.publicKey, g3.publicKey],
  threshold: 2,
  relays: [r1, r2, r3],          // { url, pubkey }
  appKey,
  opts: { apiKey, maxStorage: 512 * 1024 * 1024 }
})

const out = await app.reconstructFromCustody({
  intentId: res.intentId,
  guardianSecretKeys: [g1.secretKey, g3.secretKey],   // any 2 of 3
  shareBundleKey: res.shareBundleKey,
  threshold: 2
})
// out.key === res.key
```

---

## Relay-side verification (what makes it *blind* and *publicly verifiable*)

A PVSS receipt is produced only inside the relay's `seedApp` path
(`_recordCustodyReceipt`). The relay:

1. Fetches the signed intent by `custodyIntentId` (it must already be
   published) to learn its `shareIndex`, `shareScheme`, and `shareBundleKey`.
2. Replicates the public share bundle from the data plane.
3. Runs `verifyShareBundleForRelay` — checks its assigned encrypted share
   against the published commitments via the share's DLEQ proof. **No secret
   key, no decryption.**
4. On success, anchors a v2 receipt with `shareVerified: true`. **Fail-closed:**
   an unavailable or malformed share yields *no* receipt, so that relay is not
   counted toward the reconstruction quorum. The content drive it replicates
   stays served regardless — share custody is an added layer.

The publicly-verifiable property: anyone (not just the dealer) can confirm from
the public bundle + commitments that every committed receipt corresponds to a
correctly-encrypted share — so a relay cannot fake custody of a share it
doesn't hold, and cannot substitute a share without detection.

---

## Threat model (summary)

- **Honest-but-curious relay.** Holds `Y_i` (encrypted) + commitments; cannot
  derive `S_i` without guardian `i`'s secret key. Learns nothing about `s`.
- **Malicious relay.** Cannot anchor a valid receipt for a share it doesn't
  hold or a share it tampered with — the DLEQ check fails, so it is excluded
  from quorum. Cannot reconstruct (no guardian key).
- **Up to `t-1` colluding guardians.** Hold `< t` shares; cannot reconstruct.
- **Forged share at recovery.** `reconstruct()` re-verifies each decryption's
  DLEQ; an encrypted-but-undecrypted or substituted share is rejected.
- **Dealer.** Is trusted to generate the secret and not publish `key` /
  `secretPoint`. PVSS protects against everyone *after* the split, not against
  a dishonest dealer at split time.

---

## Status

- **v0.9.0** — scheme, v2 signing, relay-side verification.
- **v0.9.1** — end-to-end over the wire: `splitForCustody` triggers the custody
  seed; public custody status surfaces `receipts[]`; already-seeded re-pin
  anchors a receipt. Validated by an in-process split→receipt→commit→reconstruct
  test against a live relay.
- **v0.9.2** — the custody expiry sweep attests for shares whose entry was
  seeded over the seed-request channel (recovers the linkage by `addressKey`)
  and self-generates the attestation nonce.

Live: the foundation fleet (5 relays) runs v0.9.2; a real `splitForCustody` →
`reconstructFromCustody` round-trip has been verified against a production
relay over the public DHT.
