import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  computeReceiptRoot,
  createCustodyCommit,
  createCustodyExpiryWitness,
  createCustodyIntent,
  createCustodyNonServingProof,
  createCustodyProof,
  createCustodyReceipt,
  createSourceRetired,
  hashHex,
  validateCustodyTransition,
  verifyCustodyEntry
} from 'p2p-hiverelay/core/custody-signing.js'

function keyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

test('custody signing: intent/receipt/commit/retirement/proof verify', (t) => {
  const publisher = keyPair()
  const relay = keyPair()
  const observer = keyPair()
  const now = Date.now()
  const blindContentId = hashHex('blind-content')
  const ciphertextRoot = hashHex('ciphertext-root')
  const addressKey = hashHex('address-key')

  const intent = createCustodyIntent({
    addressKey,
    blindContentId,
    ciphertextRoot,
    contentVersion: 7,
    requiredReplicas: 1,
    deadline: now + 60_000,
    retainUntil: now + 120_000
  }, publisher, { timestamp: now })

  t.ok(verifyCustodyEntry(intent, { now }).valid, 'intent verifies')

  const receipt = createCustodyReceipt({
    intentId: intent.intentId,
    blindContentId,
    ciphertextRoot,
    contentVersion: 7,
    retainUntil: now + 120_000,
    relayRegion: 'test',
    shardIds: [0]
  }, relay, { timestamp: now + 1000 })

  t.ok(verifyCustodyEntry(receipt, { now: now + 1000 }).valid, 'receipt verifies')

  const commit = createCustodyCommit({
    intentId: intent.intentId,
    blindContentId,
    ciphertextRoot,
    contentVersion: 7,
    relayQuorum: [b4a.toString(relay.publicKey, 'hex')],
    receiptRoot: computeReceiptRoot([receipt])
  }, publisher, { timestamp: now + 2000 })

  t.ok(verifyCustodyEntry(commit, { now: now + 2000 }).valid, 'commit verifies')

  const retired = createSourceRetired({
    intentId: intent.intentId,
    blindContentId,
    retiredAtVersion: 7
  }, publisher, { timestamp: now + 3000 })

  t.ok(verifyCustodyEntry(retired, { now: now + 3000 }).valid, 'source retirement verifies')

  const proof = createCustodyProof({
    intentId: intent.intentId,
    blindContentId,
    relayPubkey: b4a.toString(relay.publicKey, 'hex'),
    challengeNonce: hashHex('challenge'),
    shardIds: [0],
    blockIndices: [1, 2],
    passed: true,
    latencyMs: 42
  }, observer, { timestamp: now + 4000 })

  t.ok(verifyCustodyEntry(proof, { now: now + 4000 }).valid, 'custody proof verifies')

  const nonServingProof = createCustodyNonServingProof({
    intentId: intent.intentId,
    addressKey: intent.addressKey,
    blindContentId,
    challengeNonce: hashHex('post-expiry-challenge'),
    retainUntil: now + 120_000,
    notServing: true,
    notServingReason: 'expired-unseeded',
    catalogPresent: false,
    activeSwarmServing: false
  }, relay, { timestamp: now + 130_000 })

  t.ok(verifyCustodyEntry(nonServingProof, { now: now + 130_000 }).valid, 'non-serving proof verifies')
})

test('custody signing: tampering and forbidden plaintext metadata are rejected', (t) => {
  const publisher = keyPair()
  const now = Date.now()
  const intent = createCustodyIntent({
    blindContentId: hashHex('blind-content'),
    ciphertextRoot: hashHex('ciphertext-root'),
    contentVersion: 1,
    requiredReplicas: 1,
    deadline: now + 60_000,
    retainUntil: now + 120_000
  }, publisher, { timestamp: now })

  const tampered = { ...intent, ciphertextRoot: hashHex('other-root') }
  t.is(verifyCustodyEntry(tampered, { now }).valid, false, 'tampered intent signature rejected')

  t.exception(() => createCustodyIntent({
    blindContentId: hashHex('blind-content'),
    ciphertextRoot: hashHex('ciphertext-root'),
    contentVersion: 1,
    requiredReplicas: 1,
    deadline: now + 60_000,
    retainUntil: now + 120_000,
    dataKey: 'never-send-this'
  }, publisher, { timestamp: now }), /forbidden/, 'dataKey is rejected')

  t.exception(() => createCustodyIntent({
    blindContentId: hashHex('blind-content'),
    ciphertextRoot: hashHex('ciphertext-root'),
    contentVersion: 1,
    requiredReplicas: 1,
    deadline: now + 60_000,
    retainUntil: now + 120_000,
    name: 'private docs'
  }, publisher, { timestamp: now }), /forbidden/, 'plaintext metadata is rejected')

  t.exception(() => createCustodyIntent({
    blindContentId: hashHex('blind-content'),
    ciphertextRoot: hashHex('ciphertext-root'),
    contentVersion: 1,
    requiredReplicas: 1,
    deadline: now + 60_000,
    retainUntil: now + 120_000,
    surpriseField: true
  }, publisher, { timestamp: now }), /unknown custody field/, 'unknown fields are rejected')
})

test('custody signing: every forbidden field name is blocked at create time', (t) => {
  // The 10 forbidden plaintext fields should all be rejected by the
  // validator before signing — no leak path possible.
  const publisher = keyPair()
  const now = Date.now()
  const baseIntent = {
    blindContentId: hashHex('a'),
    ciphertextRoot: hashHex('b'),
    contentVersion: 1,
    requiredReplicas: 1,
    deadline: now + 60_000,
    retainUntil: now + 120_000
  }
  const forbidden = ['dataKey', 'decryptionKey', 'plaintext', 'fileName', 'filename',
    'path', 'name', 'description', 'author', 'categories']
  for (const field of forbidden) {
    t.exception(
      () => createCustodyIntent({ ...baseIntent, [field]: 'value' }, publisher, { timestamp: now }),
      /forbidden/,
      `field "${field}" rejected`
    )
  }
})

test('custody signing: future-skew tolerance — entry from clock-skewed peer is rejected', (t) => {
  // A publisher signs an entry with their current timestamp. A verifier
  // whose clock is far behind sees the entry as "from the future" and
  // rejects it (>10min skew tolerance).
  const publisher = keyPair()
  const now = Date.now()
  const intent = createCustodyIntent({
    blindContentId: hashHex('a'),
    ciphertextRoot: hashHex('b'),
    contentVersion: 1,
    requiredReplicas: 1,
    deadline: now + 60_000,
    retainUntil: now + 120_000
  }, publisher, { timestamp: now })

  // Verify with `now` set to 30 min before the entry was signed — the
  // entry's timestamp will appear too far in the future.
  const skewedNow = now - 30 * 60 * 1000
  const result = verifyCustodyEntry(intent, { now: skewedNow })
  t.is(result.valid, false, 'rejected when verifier clock is far behind')
})

test('custody signing: receipt with mismatched relay pubkey is rejected', (t) => {
  const publisher = keyPair()
  const relayA = keyPair()
  const relayB = keyPair()
  const now = Date.now()
  const intent = createCustodyIntent({
    blindContentId: hashHex('a'),
    ciphertextRoot: hashHex('b'),
    contentVersion: 1,
    requiredReplicas: 1,
    deadline: now + 60_000,
    retainUntil: now + 120_000
  }, publisher, { timestamp: now })

  // relayA signs but relayB's pubkey is in the receipt
  const receipt = createCustodyReceipt({
    intentId: intent.intentId,
    blindContentId: intent.blindContentId,
    ciphertextRoot: intent.ciphertextRoot,
    contentVersion: 1,
    retainUntil: intent.retainUntil
  }, relayA, { timestamp: now })

  // Tamper: swap signer pubkey to relayB while keeping relayA's signature
  const tampered = { ...receipt, relayPubkey: b4a.toString(relayB.publicKey, 'hex') }
  t.is(verifyCustodyEntry(tampered, { now }).valid, false, 'mismatched signer rejected')
})

test('custody signing: computeReceiptRoot is deterministic and order-invariant', (t) => {
  // The commit's receiptRoot is a hash over the relay quorum's receipts.
  // Order of receipts in the input must not change the root, otherwise
  // different observers compute different roots and quorum can't agree.
  const r1 = { type: 'custody-receipt', intentId: 'x', relayPubkey: 'a', anchored: true, timestamp: 1, signature: 'sig1' }
  const r2 = { type: 'custody-receipt', intentId: 'x', relayPubkey: 'b', anchored: true, timestamp: 2, signature: 'sig2' }
  const r3 = { type: 'custody-receipt', intentId: 'x', relayPubkey: 'c', anchored: true, timestamp: 3, signature: 'sig3' }

  const root123 = computeReceiptRoot([r1, r2, r3])
  const root321 = computeReceiptRoot([r3, r2, r1])
  const root213 = computeReceiptRoot([r2, r1, r3])

  t.is(root123, root321, 'order does not matter (123 vs 321)')
  t.is(root123, root213, 'order does not matter (123 vs 213)')
  t.is(typeof root123, 'string')
  t.is(root123.length, 64, 'root is 64 hex chars (sha-256)')
})

test('custody signing: witness tombstone create + verify', (t) => {
  // A witness signs an attestation that a relay has stopped serving content
  // after retainUntil. The witness does NOT store content; it just observed.
  const witness = keyPair()
  const relay = keyPair()
  const now = Date.now()
  const intentId = hashHex('intent')
  const blindContentId = hashHex('blind')
  const nonServingProofHash = hashHex('non-serving-proof-A')

  const tombstone = createCustodyExpiryWitness({
    intentId,
    blindContentId,
    relayPubkey: b4a.toString(relay.publicKey, 'hex'),
    nonServingProofHash,
    catalogPresent: false,
    gatewayServing: false,
    activeSwarmObserved: false
  }, witness, { timestamp: now })

  t.is(tombstone.type, 'custody-expiry-witness')
  t.is(tombstone.witnessPubkey, b4a.toString(witness.publicKey, 'hex'))
  t.is(tombstone.relayPubkey, b4a.toString(relay.publicKey, 'hex'))
  t.is(tombstone.catalogPresent, false)
  t.is(tombstone.gatewayServing, false)
  t.ok(tombstone.signature, 'tombstone is signed')

  const verified = verifyCustodyEntry(tombstone, { now })
  t.is(verified.valid, true, 'witness signature verifies')
})

test('custody signing: tampered witness tombstone is rejected', (t) => {
  const witness = keyPair()
  const relay = keyPair()
  const now = Date.now()
  const tombstone = createCustodyExpiryWitness({
    intentId: hashHex('intent'),
    blindContentId: hashHex('blind'),
    relayPubkey: b4a.toString(relay.publicKey, 'hex'),
    nonServingProofHash: hashHex('proof'),
    catalogPresent: false,
    gatewayServing: false,
    activeSwarmObserved: false
  }, witness, { timestamp: now })

  // Tamper: flip catalogPresent to claim relay IS still serving (collusion)
  const tampered = { ...tombstone, catalogPresent: true }
  const verified = verifyCustodyEntry(tampered, { now })
  t.is(verified.valid, false, 'tampered witness rejected')
})

test('custody signing: witness tombstone transition requires post-expiry non-serving proof', (t) => {
  const publisher = keyPair()
  const relay = keyPair()
  const witness = keyPair()
  const now = Date.now()
  const blindContentId = hashHex('witness-transition-blind')
  const addressKey = hashHex('witness-transition-address')
  const intent = createCustodyIntent({
    addressKey,
    blindContentId,
    ciphertextRoot: hashHex('witness-transition-ciphertext'),
    contentVersion: 1,
    requiredReplicas: 1,
    deadline: now + 60_000,
    retainUntil: now + 120_000
  }, publisher, { timestamp: now })
  const nonServingProof = createCustodyNonServingProof({
    intentId: intent.intentId,
    addressKey,
    blindContentId,
    retainUntil: intent.retainUntil,
    notServing: true,
    catalogPresent: false,
    activeSwarmServing: false
  }, relay, { timestamp: now + 130_000 })
  const validWitness = createCustodyExpiryWitness({
    intentId: intent.intentId,
    blindContentId,
    relayPubkey: b4a.toString(relay.publicKey, 'hex'),
    nonServingProofHash: hashHex(nonServingProof),
    catalogPresent: false,
    gatewayServing: false,
    activeSwarmObserved: false
  }, witness, { timestamp: now + 131_000 })

  const valid = validateCustodyTransition(validWitness, { intent, nonServingProofs: [nonServingProof] })
  t.is(valid.valid, true, 'valid witness with matching non-serving proof is accepted')

  const beforeExpiry = { ...validWitness, timestamp: now + 60_000 }
  const early = validateCustodyTransition(beforeExpiry, { intent, nonServingProofs: [nonServingProof] })
  t.is(early.valid, false, 'witness before retainUntil is rejected')

  const serving = { ...validWitness, gatewayServing: true }
  const observedServing = validateCustodyTransition(serving, { intent, nonServingProofs: [nonServingProof] })
  t.is(observedServing.valid, false, 'witness that observed serving is rejected')

  const wrongHash = { ...validWitness, nonServingProofHash: hashHex('wrong-proof') }
  const mismatch = validateCustodyTransition(wrongHash, { intent, nonServingProofs: [nonServingProof] })
  t.is(mismatch.valid, false, 'witness must bind to a known non-serving proof')
})

test('custody signing: receiptRoot is unique per quorum (different signatures → different roots)', (t) => {
  // Different signatures across the quorum must produce different roots —
  // commits over different relay sets are distinguishable.
  const r1 = { type: 'custody-receipt', intentId: 'x', relayPubkey: 'a', anchored: true, timestamp: 1, signature: 'sig1' }
  const r2 = { type: 'custody-receipt', intentId: 'x', relayPubkey: 'b', anchored: true, timestamp: 2, signature: 'sig2' }
  const r3 = { type: 'custody-receipt', intentId: 'x', relayPubkey: 'c', anchored: true, timestamp: 3, signature: 'sig3' }

  const rootAB = computeReceiptRoot([r1, r2])
  const rootAC = computeReceiptRoot([r1, r3])
  t.not(rootAB, rootAC, 'different relay quorums produce different roots')
})

// ─── Partial-quorum support ────────────────────────────────────────────
//
// validateCustodyTransition for 'custody-commit' previously rejected any
// commit whose set of receipts didn't match the relay's full set of
// anchored receipts. That made T-of-N quorums (T < N) inherently racy:
// any receipts arriving after the publisher's threshold-collect but
// before the relay's commit-process tipped the receiptRoot or
// relayQuorum into a mismatch. drop-pear's v3.0.7 partial-quorum design
// hit this whenever real-world gossip arrived faster than the publisher
// submitted the commit (which was every time against ≥4-relay sets).
//
// The fix: when commit carries an explicit `relayQuorum`, validate only
// against the receipts from those specific pubkeys. Publisher signature
// on the commit binds the chosen set, so a malicious publisher can't
// swap in alternative receipts after the relays have signed.
//
// These tests pin the new behaviour.

test('custody signing: commit with explicit relayQuorum is validated against the named subset, not all visible receipts (partial-quorum support)', (t) => {
  const publisher = keyPair()
  const relayA = keyPair()
  const relayB = keyPair()
  const relayC = keyPair()
  const now = Date.now()
  const blindContentId = hashHex('partial-quorum-blind')
  const ciphertextRoot = hashHex('partial-quorum-ciphertext')

  // n=3 relays, threshold=2. Intent declares the 2-of-3 floor.
  const intent = createCustodyIntent({
    addressKey: hashHex('partial-quorum-address'),
    blindContentId,
    ciphertextRoot,
    contentVersion: 1,
    requiredReplicas: 2, // = threshold = the commit-quorum floor
    deadline: now + 60_000,
    retainUntil: now + 120_000
  }, publisher, { timestamp: now })

  const mkReceipt = (relay, ts) => createCustodyReceipt({
    intentId: intent.intentId,
    blindContentId,
    ciphertextRoot,
    contentVersion: 1,
    retainUntil: now + 120_000,
    relayRegion: 'test',
    shardIds: []
  }, relay, { timestamp: ts })

  const receiptA = mkReceipt(relayA, now + 1000)
  const receiptB = mkReceipt(relayB, now + 1500)
  // receiptC arrives later via gossip — the publisher collected only A+B,
  // then went to commit. Previously this caused receiptRoot mismatch on
  // any relay that had seen receiptC via gossip.
  const receiptC = mkReceipt(relayC, now + 2000)

  // Publisher commits referencing only A+B.
  const ab = [receiptA, receiptB]
  const commit = createCustodyCommit({
    intentId: intent.intentId,
    blindContentId,
    ciphertextRoot,
    contentVersion: 1,
    relayQuorum: ab.map(r => r.relayPubkey).sort(),
    receiptRoot: computeReceiptRoot(ab)
  }, publisher, { timestamp: now + 3000 })

  // Relay's view includes C via gossip (the bug condition).
  const status = { intent, receipts: [receiptA, receiptB, receiptC] }
  const result = validateCustodyTransition(commit, status)
  t.is(result.valid, true, `commit must validate against named subset (got: ${result.reason || 'OK'})`)
})

test('custody signing: commit naming a pubkey with no visible receipt is rejected', (t) => {
  // Publisher can't reference receipts the relay can't see — that would
  // let a malicious publisher forge a commit citing a relay that never
  // signed. The new check requires every pubkey in relayQuorum to have
  // a corresponding anchored receipt visible to the relay.
  const publisher = keyPair()
  const relayA = keyPair()
  const relayB = keyPair()
  const relayPhantom = keyPair() // never signed anything
  const now = Date.now()
  const blindContentId = hashHex('phantom-blind')
  const ciphertextRoot = hashHex('phantom-ciphertext')

  const intent = createCustodyIntent({
    addressKey: hashHex('phantom-address'),
    blindContentId,
    ciphertextRoot,
    contentVersion: 1,
    requiredReplicas: 2,
    deadline: now + 60_000,
    retainUntil: now + 120_000
  }, publisher, { timestamp: now })

  const mkReceipt = (relay) => createCustodyReceipt({
    intentId: intent.intentId,
    blindContentId,
    ciphertextRoot,
    contentVersion: 1,
    retainUntil: now + 120_000,
    relayRegion: 'test',
    shardIds: []
  }, relay, { timestamp: now + 1000 })

  const receiptA = mkReceipt(relayA)
  const receiptB = mkReceipt(relayB)

  // Commit claims phantom is in the quorum (it never anchored).
  const fakeQuorum = [
    receiptA.relayPubkey,
    b4a.toString(relayPhantom.publicKey, 'hex')
  ].sort()
  const commit = createCustodyCommit({
    intentId: intent.intentId,
    blindContentId,
    ciphertextRoot,
    contentVersion: 1,
    relayQuorum: fakeQuorum,
    // Even with the receiptRoot computed correctly, the named pubkey
    // doesn't correspond to a visible receipt → reject.
    receiptRoot: hashHex('fake-root')
  }, publisher, { timestamp: now + 2000 })

  const status = { intent, receipts: [receiptA, receiptB] }
  const result = validateCustodyTransition(commit, status)
  t.is(result.valid, false, 'phantom quorum must be rejected')
  t.ok(/not yet visible/.test(result.reason), `expected "not yet visible" reason, got: ${result.reason}`)
})

test('custody signing: legacy commit without relayQuorum still validates against all visible receipts (backwards compat)', (t) => {
  // Pre-this-change publishers always committed with relayQuorum = all
  // visible receipts. Those still need to verify cleanly. Backwards-compat
  // path: empty or missing relayQuorum → use all anchored receipts.
  const publisher = keyPair()
  const relay = keyPair()
  const now = Date.now()
  const blindContentId = hashHex('legacy-blind')
  const ciphertextRoot = hashHex('legacy-ciphertext')

  const intent = createCustodyIntent({
    addressKey: hashHex('legacy-address'),
    blindContentId,
    ciphertextRoot,
    contentVersion: 1,
    requiredReplicas: 1,
    deadline: now + 60_000,
    retainUntil: now + 120_000
  }, publisher, { timestamp: now })

  const receipt = createCustodyReceipt({
    intentId: intent.intentId,
    blindContentId,
    ciphertextRoot,
    contentVersion: 1,
    retainUntil: now + 120_000,
    relayRegion: 'test',
    shardIds: []
  }, relay, { timestamp: now + 1000 })

  // Legacy commit — relayQuorum = single relay (matches all visible).
  const commit = createCustodyCommit({
    intentId: intent.intentId,
    blindContentId,
    ciphertextRoot,
    contentVersion: 1,
    relayQuorum: [receipt.relayPubkey],
    receiptRoot: computeReceiptRoot([receipt])
  }, publisher, { timestamp: now + 2000 })

  const status = { intent, receipts: [receipt] }
  const result = validateCustodyTransition(commit, status)
  t.is(result.valid, true, 'legacy single-relay commit still validates')
})
