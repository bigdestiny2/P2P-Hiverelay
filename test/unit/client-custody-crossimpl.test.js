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
  hashHex as clientHashHex
} from 'p2p-hiverelay-client/custody.js'
import {
  createCustodyIntent as coreIntent,
  createCustodyReceipt as coreReceipt,
  computeReceiptRoot,
  verifyCustodyEntry,
  validateCustodyTransition,
  hashHex
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
