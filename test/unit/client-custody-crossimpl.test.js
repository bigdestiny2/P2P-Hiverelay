// Cross-implementation agreement: CLIENT signer ↔ CORE verifier.
//
// The publisher-side custody signer lives in the client SDK
// (packages/client/custody.js); the relay-side verifier lives in core
// (packages/core/core/custody-signing.js). They are independently-versioned
// wire peers that never share code — the client pins a frozen
// p2p-hiverelay@0.7.2 that predates custody-signing.js, so it carries its own
// self-contained copy. A shared import would be false comfort; the real
// interop contract is that the two agree byte-for-byte on the SIGNED PAYLOAD.
//
// These tests pin that contract: an entry signed by the client must verify and
// validate unchanged in core, the signatures must be identical given identical
// inputs, and tampering is caught. The v2 case specifically pins the nested
// shareAssignments key order — custodySignablePayload stringifies those objects
// positionally (JSON.stringify, not stableStringify), so a key-order drift
// between the two impls would silently break v2 interop.

import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { keygen, split } from 'p2p-hiverelay-client/secret-sharing.js'
import {
  createCustodyIntent as clientIntent,
  createCustodyCommit as clientCommit,
  createSourceRetired as clientRetired,
  hashHex as clientHashHex,
  summarizeCustodyStatus as clientSummary
} from 'p2p-hiverelay-client/custody.js'
import {
  createCustodyIntent as coreIntent,
  createCustodyReceipt as coreReceipt,
  computeReceiptRoot,
  verifyCustodyEntry,
  validateCustodyTransition,
  hashHex,
  summarizeCustodyStatus as coreSummary
} from 'p2p-hiverelay/core/custody-signing.js'
import { shareCommitmentAt } from 'p2p-hiverelay/core/pvss.js'

// Custody entries are signed with sodium ed25519 keys.
function keyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

async function shareholders (n) {
  const keys = []
  for (let i = 0; i < n; i++) keys.push(await keygen())
  return keys
}

// relays[i] custodies share i+1 — the dealer's split-to-relay assignment.
function assignmentsFor (relays) {
  return relays.map((r, i) => ({ relayPubkey: b4a.toString(r.publicKey, 'hex'), shareIndex: i + 1 }))
}

test('cross-impl: client + core hashHex agree', (t) => {
  t.is(clientHashHex('hiverelay-cross-impl'), hashHex('hiverelay-cross-impl'), 'identical BLAKE2b digest')
})

test('cross-impl: expiry witness quorum summaries agree and require publisher-selected policy', (t) => {
  const now = Date.now()
  const publisher = keyPair()
  const relay = keyPair()
  const witnessA = keyPair()
  const witnessB = keyPair()
  const witnessC = keyPair()
  const outsider = keyPair()
  const relayPubkey = b4a.toString(relay.publicKey, 'hex')
  const publisherPubkey = b4a.toString(publisher.publicKey, 'hex')
  const intent = {
    intentId: hashHex('witness-policy-intent'),
    custodyMode: 'blind',
    blindContentId: hashHex('witness-policy-blind'),
    requiredReplicas: 1,
    retainUntil: now
  }
  const proof = {
    intentId: intent.intentId,
    blindContentId: intent.blindContentId,
    relayPubkey,
    retainUntil: intent.retainUntil,
    timestamp: now + 1,
    notServing: true,
    catalogPresent: false,
    activeSwarmServing: false
  }
  const witnessEntry = (kp, overrides = {}) => ({
    type: 'custody-expiry-witness',
    intentId: intent.intentId,
    blindContentId: intent.blindContentId,
    relayPubkey,
    witnessPubkey: b4a.toString(kp.publicKey, 'hex'),
    timestamp: now + 2,
    nonServingProofHash: hashHex(proof),
    catalogPresent: false,
    gatewayServing: false,
    activeSwarmObserved: false,
    ...overrides
  })
  const policy = {
    kind: 'hivemesh-witness-quorum-policy',
    version: 1,
    intentId: intent.intentId,
    subjectRelayPubkey: relayPubkey,
    publisherPubkey,
    selectedBy: 'publisher',
    witnessCount: 3,
    requiredWitnesses: 2,
    minOperators: 2,
    minRegions: 2,
    witnesses: [
      { witnessPubkey: b4a.toString(witnessA.publicKey, 'hex'), operator: 'op-a', region: 'us-east' },
      { witnessPubkey: b4a.toString(witnessB.publicKey, 'hex'), operator: 'op-b', region: 'eu-west' },
      { witnessPubkey: b4a.toString(witnessC.publicKey, 'hex'), operator: 'op-c', region: 'ap-south' }
    ]
  }
  const entries = [
    witnessEntry(witnessA),
    witnessEntry(witnessB),
    witnessEntry(witnessB),
    witnessEntry(outsider),
    witnessEntry(witnessC, { gatewayServing: true })
  ]

  const client = clientSummary(intent, [], null, null, [], [proof], entries, policy)
  const core = coreSummary(intent, [], null, null, [], [proof], entries, policy)
  t.alike(client, core, 'client and core summary agree')
  t.is(client.expiryWitnessCount, 5)
  t.is(client.validExpiryWitnessCount, 4, 'active-serving witness is excluded before quorum evaluation')
  t.is(client.expiryWitnessQuorum.valid, true)
  t.is(client.expiryWitnessQuorum.count, 2)
  t.is(client.expiryWitnessQuorum.required, 2)
  t.alike(client.expiryWitnessQuorum.accepted, [
    b4a.toString(witnessA.publicKey, 'hex'),
    b4a.toString(witnessB.publicKey, 'hex')
  ])
  t.ok(client.expiryWitnessQuorum.rejected.find(row => row.reason === 'duplicate witness'))
  t.ok(client.expiryWitnessQuorum.rejected.find(row => row.reason === 'witness not publisher-selected'))

  const invalidPolicy = { ...policy, selectedBy: 'relay' }
  const invalid = coreSummary(intent, [], null, null, [], [proof], entries, invalidPolicy)
  t.absent(invalid.expiryWitnessQuorum.valid)
  t.is(invalid.expiryWitnessQuorum.reason, 'invalid-policy')
  t.ok(invalid.expiryWitnessQuorum.errors.includes('witness set must be publisher-selected'))
})

test('cross-impl: a client-signed v1 intent is byte-identical to core and verifies in core', (t) => {
  const now = Date.now()
  const publisher = keyPair()
  const fields = {
    blindContentId: hashHex('xi-blind'),
    ciphertextRoot: hashHex('xi-cipher'),
    contentVersion: 1,
    requiredReplicas: 3,
    deadline: now + 60_000,
    retainUntil: now + 120_000
  }
  const ci = clientIntent({ ...fields }, publisher, { timestamp: now })
  const ki = coreIntent({ ...fields }, publisher, { timestamp: now })
  t.is(ci.version, 1, 'defaults to v1')
  t.is(ci.signature, ki.signature, 'client + core sign the v1 intent identically')
  t.alike(ci, ki, 'normalized entries are identical')
  t.ok(verifyCustodyEntry(ci, { now }).valid, 'core verifies the client-signed v1 intent')
})

test('cross-impl: a client-signed v2 PVSS intent is byte-identical to core, verifies, and binds a core receipt', async (t) => {
  const now = Date.now()
  const n = 3
  const threshold = 2
  const keys = await shareholders(n)
  const res = await split({ threshold, shareholders: keys.map(k => k.publicKey) })
  const publisher = keyPair()
  const relays = Array.from({ length: n }, () => keyPair())
  const fields = {
    version: 2,
    blindContentId: hashHex('xv2-blind'),
    ciphertextRoot: hashHex('xv2-cipher'),
    contentVersion: 1,
    requiredReplicas: n,
    deadline: now + 60_000,
    retainUntil: now + 120_000,
    shareScheme: 'pvss-secp256k1-v1',
    shareThreshold: threshold,
    commitmentRoot: res.public.commitmentRoot,
    shareBundleKey: hashHex('xv2-bundle'),
    shareAssignments: assignmentsFor(relays)
  }
  const ci = clientIntent({ ...fields }, publisher, { timestamp: now })
  const ki = coreIntent({ ...fields }, publisher, { timestamp: now })
  // THE keystone assertion: identical signatures prove the two impls serialize
  // the nested shareAssignments objects in the same key order. A divergence
  // here silently breaks v2 interop, and no other test would catch it.
  t.is(ci.signature, ki.signature, 'client + core sign the v2 intent identically (nested key order pinned)')
  t.alike(ci.shareAssignments, ki.shareAssignments, 'shareAssignments normalize identically')
  t.ok(verifyCustodyEntry(ci, { now }).valid, 'core verifies the client-signed v2 intent')

  // A core (relay) receipt for the client-signed intent binds via the
  // transition check — relays[0] is assigned shareIndex 1.
  const receipt = coreReceipt({
    version: 2,
    intentId: ci.intentId,
    blindContentId: ci.blindContentId,
    ciphertextRoot: ci.ciphertextRoot,
    contentVersion: ci.contentVersion,
    retainUntil: ci.retainUntil,
    relayRegion: 'xi',
    shardIds: [0],
    shareScheme: 'pvss-secp256k1-v1',
    commitmentRoot: ci.commitmentRoot,
    shareIndex: 1,
    shareCommitment: shareCommitmentAt(res.public.commitments, 1),
    shareVerified: true
  }, relays[0], { timestamp: now + 1000 })
  t.ok(verifyCustodyEntry(receipt, { now: now + 1000 }).valid, 'core relay receipt verifies')
  t.ok(validateCustodyTransition(receipt, { intent: ci }).valid, 'core receipt binds to the client-signed v2 intent')
})

test('cross-impl: a client-signed custody-commit verifies and validates against core receipts', async (t) => {
  const now = Date.now()
  const n = 3
  const threshold = 2
  const keys = await shareholders(n)
  const res = await split({ threshold, shareholders: keys.map(k => k.publicKey) })
  const publisher = keyPair()
  const relays = Array.from({ length: n }, () => keyPair())
  const intent = clientIntent({
    version: 2,
    blindContentId: hashHex('xc-blind'),
    ciphertextRoot: hashHex('xc-cipher'),
    contentVersion: 1,
    requiredReplicas: n,
    deadline: now + 60_000,
    retainUntil: now + 120_000,
    shareScheme: 'pvss-secp256k1-v1',
    shareThreshold: threshold,
    commitmentRoot: res.public.commitmentRoot,
    shareBundleKey: hashHex('xc-bundle'),
    shareAssignments: assignmentsFor(relays)
  }, publisher, { timestamp: now })

  const receipts = relays.map((relay, i) => coreReceipt({
    version: 2,
    intentId: intent.intentId,
    blindContentId: intent.blindContentId,
    ciphertextRoot: intent.ciphertextRoot,
    contentVersion: intent.contentVersion,
    retainUntil: intent.retainUntil,
    relayRegion: 'xi',
    shardIds: [i],
    shareScheme: 'pvss-secp256k1-v1',
    commitmentRoot: intent.commitmentRoot,
    shareIndex: i + 1,
    shareCommitment: shareCommitmentAt(res.public.commitments, i + 1),
    shareVerified: true
  }, relay, { timestamp: now + 1000 }))

  for (const r of receipts) {
    t.ok(validateCustodyTransition(r, { intent }).valid, `receipt #${r.shareIndex} binds to the client intent`)
  }

  const commit = clientCommit({
    intentId: intent.intentId,
    blindContentId: intent.blindContentId,
    ciphertextRoot: intent.ciphertextRoot,
    contentVersion: intent.contentVersion,
    relayQuorum: receipts.map(r => r.relayPubkey).sort(),
    receiptRoot: computeReceiptRoot(receipts)
  }, publisher, { timestamp: now + 2000 })

  t.ok(verifyCustodyEntry(commit, { now: now + 2000 }).valid, 'core verifies the client-signed commit')
  t.ok(validateCustodyTransition(commit, { intent, receipts }).valid, 'client commit validates against the core receipts')
})

test('cross-impl: core rejects a tampered client-signed intent', (t) => {
  const now = Date.now()
  const publisher = keyPair()
  const intent = clientIntent({
    blindContentId: hashHex('xt-blind'),
    ciphertextRoot: hashHex('xt-cipher'),
    contentVersion: 1,
    requiredReplicas: 3,
    deadline: now + 60_000,
    retainUntil: now + 120_000
  }, publisher, { timestamp: now })

  t.ok(verifyCustodyEntry(intent, { now }).valid, 'pristine client intent verifies')
  t.is(verifyCustodyEntry({ ...intent, requiredReplicas: 99 }, { now }).valid, false, 'mutated field breaks the signature')
})

test('cross-impl: custody allowlist rejects top-level and nested smuggling fields', (t) => {
  const now = Date.now()
  const publisher = keyPair()
  const relays = Array.from({ length: 3 }, () => keyPair())
  const fields = {
    version: 2,
    blindContentId: hashHex('allowlist-blind'),
    ciphertextRoot: hashHex('allowlist-cipher'),
    contentVersion: 1,
    requiredReplicas: 3,
    deadline: now + 60_000,
    retainUntil: now + 120_000,
    shareScheme: 'pvss-secp256k1-v1',
    shareThreshold: 2,
    commitmentRoot: hashHex('allowlist-commitment'),
    shareBundleKey: hashHex('allowlist-bundle'),
    shareAssignments: assignmentsFor(relays)
  }
  const intent = clientIntent({ ...fields }, publisher, { timestamp: now })

  const topLevel = verifyCustodyEntry({ ...intent, caption: 'plaintext should not ride along' }, { now })
  t.absent(topLevel.valid, 'unknown top-level field rejected')
  t.is(topLevel.reason, 'unknown custody field: caption')

  const topLevelSecret = verifyCustodyEntry({ ...intent, dataKey: 'plaintext should not ride along' }, { now })
  t.absent(topLevelSecret.valid, 'secret-looking top-level field rejected by allowlist')
  t.is(topLevelSecret.reason, 'unknown custody field: dataKey')

  const nestedIntent = {
    ...intent,
    shareAssignments: intent.shareAssignments.map((assignment, index) => index === 0
      ? { ...assignment, caption: 'plaintext should not ride along' }
      : assignment)
  }
  const nested = verifyCustodyEntry(nestedIntent, { now })
  t.absent(nested.valid, 'unknown nested assignment field rejected')
  t.is(nested.reason, 'unknown shareAssignment field: caption')

  t.exception(
    () => coreIntent({
      ...fields,
      shareAssignments: [{ ...fields.shareAssignments[0], caption: 'plaintext' }, ...fields.shareAssignments.slice(1)]
    }, publisher, { timestamp: now }),
    /unknown shareAssignment field: caption/,
    'core signer refuses to create a smuggled assignment'
  )
  t.exception(
    () => coreIntent({ ...fields, dataKey: 'plaintext' }, publisher, { timestamp: now }),
    /unknown custody field: dataKey/,
    'core signer refuses secret-looking top-level fields via the allowlist'
  )
  t.exception(
    () => clientIntent({
      ...fields,
      shareAssignments: [{ ...fields.shareAssignments[0], caption: 'plaintext' }, ...fields.shareAssignments.slice(1)]
    }, publisher, { timestamp: now }),
    /unknown shareAssignment field: caption/,
    'client signer refuses to create a smuggled assignment'
  )
  t.exception(
    () => clientIntent({ ...fields, dataKey: 'plaintext' }, publisher, { timestamp: now }),
    /unknown custody field: dataKey/,
    'client signer refuses secret-looking top-level fields via the allowlist'
  )
})

test('cross-impl: a client-signed source-retired verifies in core', (t) => {
  const now = Date.now()
  const publisher = keyPair()
  const retired = clientRetired({
    intentId: hashHex('xr-intent'),
    blindContentId: hashHex('xr-blind'),
    retiredAtVersion: 1
  }, publisher, { timestamp: now })
  const res = verifyCustodyEntry(retired, { now })
  t.ok(res.valid, 'core verifies the client-signed source-retired')
  t.is(res.entry.publisherPubkey, b4a.toString(publisher.publicKey, 'hex'), 'publisher pubkey echoed')
})
