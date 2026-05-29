// custody-claim-path-witness: v0.8.27 regression tests for the claim-path
// erasure witness.
//
// Background. The custody expiry sweep historically only attested the
// UNCLAIMED-expiry path: content that sat untouched until its retainUntil
// window lapsed. validateCustodyTransition enforced that floor by rejecting
// any non-serving-proof / expiry-witness timestamped before retainUntil.
//
// That left a gap: a *claimed* drop — where the publisher has signed a
// source-retired entry ("I deleted the source; the handoff is complete",
// which itself requires a custody commit, so the recipient/quorum already
// holds the content) — produced no third-party-provable destruction until
// the (often weeks-long) retain window elapsed. That is the exact piece
// dmc flagged as missing for "provable to a third party."
//
// v0.8.27 relaxes the retainUntil floor on the claim path: once a validated
// source-retirement exists, a relay may attest non-serving (and peers may
// witness) immediately. These tests pin both the pure-function relaxation
// and the registry-append integration.

import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { SeedingRegistry } from 'p2p-hiverelay/core/registry/index.js'
import {
  createCustodyNonServingProof,
  createCustodyExpiryWitness,
  createCustodyIntent,
  validateCustodyTransition,
  hashHex
} from 'p2p-hiverelay/core/custody-signing.js'

function keyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

function registryFixture () {
  const registry = new SeedingRegistry(null, null)
  const blocks = []
  registry.localLog = {
    async append (block) {
      blocks.push(JSON.parse(b4a.toString(block)))
    }
  }
  return { registry, blocks }
}

test('claim-path: non-serving-proof before retainUntil is rejected without retirement, accepted with it', (t) => {
  const publisher = keyPair()
  const relay = keyPair()
  const now = Date.now()
  const blindContentId = hashHex('claim-nsp-blind')
  const addressKey = hashHex('claim-nsp-address')

  const intent = createCustodyIntent({
    addressKey,
    blindContentId,
    ciphertextRoot: hashHex('claim-nsp-ciphertext'),
    contentVersion: 1,
    requiredReplicas: 1,
    deadline: now + 60_000,
    retainUntil: now + 120_000
  }, publisher, { timestamp: now })

  // Proof timestamped well BEFORE retainUntil — the claim-path scenario.
  const nonServing = createCustodyNonServingProof({
    intentId: intent.intentId,
    addressKey,
    blindContentId,
    retainUntil: intent.retainUntil,
    notServing: true,
    notServingReason: 'source-retired',
    catalogPresent: false,
    activeSwarmServing: false
  }, relay, { timestamp: now + 2_000 })

  const withoutRetirement = validateCustodyTransition(nonServing, { intent })
  t.is(withoutRetirement.valid, false, 'rejected before retainUntil with no retirement')
  t.ok(/before retainUntil/.test(withoutRetirement.reason), 'reason cites retainUntil floor')

  // A truthy sourceRetired in the status context discharges the floor.
  const withRetirement = validateCustodyTransition(nonServing, {
    intent,
    sourceRetired: { type: 'source-retired', intentId: intent.intentId }
  })
  t.is(withRetirement.valid, true, 'accepted before retainUntil once source is retired')

  // The getCustodyStatus() field name (`sourceRetirement`) is honored too.
  const withRetirementAlias = validateCustodyTransition(nonServing, {
    intent,
    sourceRetirement: { type: 'source-retired', intentId: intent.intentId }
  })
  t.is(withRetirementAlias.valid, true, 'sourceRetirement alias also discharges the floor')
})

test('claim-path: expiry-witness before retainUntil follows the same retirement rule', (t) => {
  const publisher = keyPair()
  const relay = keyPair()
  const witness = keyPair()
  const now = Date.now()
  const blindContentId = hashHex('claim-witness-blind')
  const addressKey = hashHex('claim-witness-address')

  const intent = createCustodyIntent({
    addressKey,
    blindContentId,
    ciphertextRoot: hashHex('claim-witness-ciphertext'),
    contentVersion: 1,
    requiredReplicas: 1,
    deadline: now + 60_000,
    retainUntil: now + 120_000
  }, publisher, { timestamp: now })

  const nonServing = createCustodyNonServingProof({
    intentId: intent.intentId,
    addressKey,
    blindContentId,
    retainUntil: intent.retainUntil,
    notServing: true,
    notServingReason: 'source-retired',
    catalogPresent: false,
    activeSwarmServing: false
  }, relay, { timestamp: now + 2_000 })

  const tombstone = createCustodyExpiryWitness({
    intentId: intent.intentId,
    blindContentId,
    relayPubkey: b4a.toString(relay.publicKey, 'hex'),
    nonServingProofHash: hashHex(nonServing),
    catalogPresent: false,
    gatewayServing: false,
    activeSwarmObserved: false
  }, witness, { timestamp: now + 3_000 })

  const ctx = { intent, nonServingProofs: [nonServing] }
  const early = validateCustodyTransition(tombstone, ctx)
  t.is(early.valid, false, 'witness before retainUntil rejected with no retirement')
  t.ok(/before retainUntil/.test(early.reason), 'reason cites retainUntil floor')

  const retired = validateCustodyTransition(tombstone, { ...ctx, sourceRetired: { type: 'source-retired' } })
  t.is(retired.valid, true, 'witness before retainUntil accepted once source is retired')
})

test('claim-path integration: registry rejects a pre-retainUntil non-serving-proof until the source is retired', async (t) => {
  const { registry } = registryFixture()
  const publisher = keyPair()
  const relayA = keyPair()
  const relayB = keyPair()
  const now = Date.now()
  const blindContentId = hashHex('claim-int-blind')
  const ciphertextRoot = hashHex('claim-int-ciphertext')
  const addressKey = hashHex('claim-int-address')

  const intent = await registry.publishCustodyIntent({
    addressKey,
    blindContentId,
    ciphertextRoot,
    contentVersion: 1,
    requiredReplicas: 2,
    deadline: now + 60_000,
    retainUntil: now + 120_000
  }, publisher)

  await registry.recordCustodyReceipt({
    intentId: intent.intentId, blindContentId, ciphertextRoot, contentVersion: 1, retainUntil: intent.retainUntil
  }, relayA)
  await registry.recordCustodyReceipt({
    intentId: intent.intentId, blindContentId, ciphertextRoot, contentVersion: 1, retainUntil: intent.retainUntil
  }, relayB)
  await registry.publishCustodyCommit({ intentId: intent.intentId }, publisher)

  const mkProof = (ts) => createCustodyNonServingProof({
    intentId: intent.intentId,
    addressKey,
    blindContentId,
    retainUntil: intent.retainUntil,
    notServing: true,
    notServingReason: 'source-retired',
    catalogPresent: false,
    activeSwarmServing: false
  }, relayA, { timestamp: ts })

  // Committed but NOT yet source-retired → the retainUntil floor still holds.
  await t.exception(
    registry.recordCustodyNonServingProof(mkProof(now + 2_000)),
    /INVALID_CUSTODY_TRANSITION/,
    'pre-retainUntil proof rejected while source is not retired'
  )

  // Publisher retires the source — the claim is complete.
  await registry.publishSourceRetired({ intentId: intent.intentId }, publisher)
  t.is(registry.getCustodyStatus(intent.intentId).sourceRetired, true, 'source retired')

  // Now the same early-timestamped proof is accepted.
  await registry.recordCustodyNonServingProof(mkProof(now + 3_000))
  const status = registry.getCustodyStatus(intent.intentId)
  t.is(status.nonServingProofCount, 1, 'claim-path non-serving-proof indexed before retainUntil')
  t.alike(status.nonServingRelays, [b4a.toString(relayA.publicKey, 'hex')], 'attesting relay reported')
})

test('claim-path integration: a peer witness counts as valid before retainUntil once retired', async (t) => {
  const { registry } = registryFixture()
  const publisher = keyPair()
  const relay = keyPair()
  const witness = keyPair()
  const now = Date.now()
  const blindContentId = hashHex('claim-wint-blind')
  const ciphertextRoot = hashHex('claim-wint-ciphertext')
  const addressKey = hashHex('claim-wint-address')

  const intent = await registry.publishCustodyIntent({
    addressKey,
    blindContentId,
    ciphertextRoot,
    contentVersion: 1,
    requiredReplicas: 1,
    deadline: now + 60_000,
    retainUntil: now + 120_000
  }, publisher)
  await registry.recordCustodyReceipt({
    intentId: intent.intentId, blindContentId, ciphertextRoot, contentVersion: 1, retainUntil: intent.retainUntil
  }, relay)
  await registry.publishCustodyCommit({ intentId: intent.intentId }, publisher)
  await registry.publishSourceRetired({ intentId: intent.intentId }, publisher)

  const nonServing = await registry.recordCustodyNonServingProof(createCustodyNonServingProof({
    intentId: intent.intentId,
    addressKey,
    blindContentId,
    retainUntil: intent.retainUntil,
    notServing: true,
    notServingReason: 'source-retired',
    catalogPresent: false,
    activeSwarmServing: false
  }, relay, { timestamp: now + 2_000 }))

  // Witness timestamped before retainUntil — valid because the source is retired.
  const tombstone = await registry.recordCustodyExpiryWitness({
    intentId: intent.intentId,
    timestamp: now + 3_000,
    relayPubkey: b4a.toString(relay.publicKey, 'hex'),
    nonServingProofHash: hashHex(nonServing),
    catalogPresent: false,
    gatewayServing: false,
    activeSwarmObserved: false
  }, witness)

  const status = registry.getCustodyStatus(intent.intentId)
  t.ok(tombstone.signature, 'claim-path witness signed')
  t.is(status.expiryWitnessCount, 1, 'raw witness indexed')
  t.is(status.validExpiryWitnessCount, 1, 'claim-path witness counts as valid before retainUntil')
})
