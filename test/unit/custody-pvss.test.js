// PVSS custody — Phase 2. Two concerns in one file:
//
//   1. CROSS-IMPLEMENTATION AGREEMENT. The relay's verify-only path lives in
//      core (packages/core/core/pvss.js); the dealer/shareholder prover lives
//      in the client SDK (packages/client/secret-sharing.js). They are
//      independently versioned deployables that meet over the wire, so a
//      shared import would be false comfort. These tests pin that the LIVE
//      core verifier accepts exactly what the client prover produces, and
//      rejects tampering — byte-for-byte transcript agreement is the real
//      interop contract.
//
//   2. CUSTODY-LOG WIRE FORMAT (version 2). The signed custody log gains
//      optional PVSS fields (intent: shareScheme/shareThreshold/commitmentRoot;
//      receipt: shareScheme/commitmentRoot/shareIndex/shareCommitment/
//      shareVerified). Version-gated so v1 entries stay byte-identical. Plus
//      FORBIDDEN_KEYS hardening against cleartext share material.

import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { keygen, split, decryptShare } from 'p2p-hiverelay-client/secret-sharing.js'
import {
  commitmentRootOf,
  shareCommitmentAt,
  verifyEncryptedShare,
  verifyDecryptedShare
} from 'p2p-hiverelay/core/pvss.js'
import {
  createCustodyIntent,
  createCustodyReceipt,
  createCustodyCommit,
  computeReceiptRoot,
  validateCustodyTransition,
  summarizeCustodyStatus,
  verifyCustodyEntry,
  hashHex
} from 'p2p-hiverelay/core/custody-signing.js'

async function shareholders (n) {
  const keys = []
  for (let i = 0; i < n; i++) keys.push(await keygen())
  return keys
}

// Custody entries are signed with sodium ed25519 keys (distinct from the
// secp256k1 PVSS shareholder keys keygen() produces).
function keyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

// Map relay pubkeys to share indices 1..n for an intent's shareAssignments
// (relays[i] custodies share i+1) — mirrors the dealer's split, where index
// i+1's encrypted share is delivered to the relay this names.
function assignmentsFor (relays) {
  return relays.map((r, i) => ({ relayPubkey: b4a.toString(r.publicKey, 'hex'), shareIndex: i + 1 }))
}

// Build a realistic PVSS custody scenario: a real client split plus a v2
// custody-intent pinning the resulting commitmentRoot/threshold, the share
// bundle key, and the relay→index assignment map. Returns the n custodying
// relay keypairs (relays[i] is assigned shareIndex i+1).
async function pvssScenario ({ n, threshold, now }) {
  const keys = await shareholders(n)
  const res = await split({ threshold, shareholders: keys.map(k => k.publicKey) })
  const publisher = keyPair()
  const relays = Array.from({ length: n }, () => keyPair())
  const blindContentId = hashHex('pvss-blind-' + n + '-' + threshold + '-' + now)
  const ciphertextRoot = hashHex('pvss-cipher-' + n + '-' + threshold + '-' + now)
  const shareBundleKey = hashHex('pvss-bundle-' + n + '-' + threshold + '-' + now)
  const intent = createCustodyIntent({
    version: 2,
    blindContentId,
    ciphertextRoot,
    contentVersion: 1,
    requiredReplicas: n,
    deadline: now + 60_000,
    retainUntil: now + 120_000,
    shareScheme: 'pvss-secp256k1-v1',
    shareThreshold: threshold,
    commitmentRoot: res.public.commitmentRoot,
    shareBundleKey,
    shareAssignments: assignmentsFor(relays)
  }, publisher, { timestamp: now })
  return { keys, res, publisher, relays, blindContentId, ciphertextRoot, shareBundleKey, intent }
}

// A v2 custody-receipt for `shareIndex`, echoing the intent's PVSS binding and
// pinning the per-index commitment point. `overrides` tampers individual
// fields for the negative cases.
function pvssReceipt (intent, relay, shareIndex, commitments, now, overrides = {}) {
  return createCustodyReceipt({
    version: 2,
    intentId: intent.intentId,
    blindContentId: intent.blindContentId,
    ciphertextRoot: intent.ciphertextRoot,
    contentVersion: intent.contentVersion,
    retainUntil: intent.retainUntil,
    relayRegion: 'test',
    shardIds: [Math.max(0, shareIndex - 1)],
    shareScheme: 'pvss-secp256k1-v1',
    commitmentRoot: intent.commitmentRoot,
    shareIndex,
    shareCommitment: shareCommitmentAt(commitments, shareIndex),
    shareVerified: true,
    ...overrides
  }, relay, { timestamp: now + 1000 })
}

// ─── 1. Cross-implementation agreement (core verifier ↔ service prover) ───

test('cross-impl: core commitmentRootOf reproduces the service-published root', async (t) => {
  const keys = await shareholders(4)
  const res = await split({ threshold: 2, shareholders: keys.map(k => k.publicKey) })
  t.is(
    commitmentRootOf(res.public.commitments),
    res.public.commitmentRoot,
    'independent core hash matches the dealer-published commitmentRoot'
  )
})

test('cross-impl: core verifyEncryptedShare accepts every honest share', async (t) => {
  const keys = await shareholders(5)
  const res = await split({ threshold: 3, shareholders: keys.map(k => k.publicKey) })
  for (const share of res.public.encryptedShares) {
    t.ok(
      verifyEncryptedShare(res.public.commitments, share),
      `core verifies honest share #${share.index} (no secret key)`
    )
  }
})

test('cross-impl: core shareCommitmentAt is a stable per-index point a relay can pin', async (t) => {
  const keys = await shareholders(3)
  const res = await split({ threshold: 2, shareholders: keys.map(k => k.publicKey) })
  for (const share of res.public.encryptedShares) {
    const sc = shareCommitmentAt(res.public.commitments, share.index)
    t.ok(/^0[23][0-9a-f]{64}$/.test(sc), `index ${share.index} → compressed point`)
    t.is(shareCommitmentAt(res.public.commitments, share.index), sc, 'deterministic')
  }
})

test('cross-impl: a tampered encrypted share or proof is rejected by the core verifier', async (t) => {
  const keys = await shareholders(3)
  const res = await split({ threshold: 2, shareholders: keys.map(k => k.publicKey) })

  const swapped = { ...res.public.encryptedShares[0], encryptedShare: (await keygen()).publicKey }
  t.is(verifyEncryptedShare(res.public.commitments, swapped), false, 'swapped share value rejected')

  const badProof = { ...res.public.encryptedShares[1], proof: { ...res.public.encryptedShares[1].proof, s: 'f'.repeat(64) } }
  t.is(verifyEncryptedShare(res.public.commitments, badProof), false, 'tampered DLEQ response rejected')

  const wrongIndex = { ...res.public.encryptedShares[2], index: 99 }
  t.is(verifyEncryptedShare(res.public.commitments, wrongIndex), false, 'wrong index breaks the commitment recompute')
})

test('cross-impl: core verifyDecryptedShare agrees with the service on honest + forged shares', async (t) => {
  const keys = await shareholders(3)
  const res = await split({ threshold: 2, shareholders: keys.map(k => k.publicKey) })
  const enc = res.public.encryptedShares.find(s => s.index === 1)
  const dec = await decryptShare({ encryptedShare: enc, secretKey: keys[0].secretKey })

  t.is(verifyDecryptedShare(dec), true, 'honest decrypted share verifies in core')

  const forged = { ...dec, share: (await keygen()).publicKey }
  t.is(verifyDecryptedShare(forged), false, 'forged decrypted share rejected in core')
})

// ─── 2. Custody-log wire format (version 2) ───

test('custody v2: a PVSS custody intent + receipt sign, verify, and bind end-to-end', async (t) => {
  const now = Date.now()
  const n = 5
  const threshold = 3
  const keys = await shareholders(n)
  const res = await split({ threshold, shareholders: keys.map(k => k.publicKey) })
  const publisher = keyPair()
  const relays = Array.from({ length: n }, () => keyPair())
  const relay = relays[0] // assigned shareIndex 1 by assignmentsFor below
  const blindContentId = hashHex('pvss-blind-content')
  const ciphertextRoot = hashHex('pvss-ciphertext-root')

  const intent = createCustodyIntent({
    version: 2,
    blindContentId,
    ciphertextRoot,
    contentVersion: 1,
    requiredReplicas: n,
    deadline: now + 60_000,
    retainUntil: now + 120_000,
    shareScheme: 'pvss-secp256k1-v1',
    shareThreshold: threshold,
    commitmentRoot: res.public.commitmentRoot,
    shareBundleKey: hashHex('pvss-bundle-content'),
    shareAssignments: assignmentsFor(relays)
  }, publisher, { timestamp: now })

  t.ok(verifyCustodyEntry(intent, { now }).valid, 'v2 intent signature verifies')
  t.is(intent.version, 2, 'intent carries version 2')
  t.is(intent.commitmentRoot, res.public.commitmentRoot, 'intent pins the published commitmentRoot')

  // The relay publicly verifies the encrypted share it will custody (#1)
  // BEFORE attesting shareVerified — exactly the relay-side flow, no secret.
  const share = res.public.encryptedShares.find(s => s.index === 1)
  t.ok(verifyEncryptedShare(res.public.commitments, share), 'relay verifies encrypted share #1 with no secret key')

  const receipt = createCustodyReceipt({
    version: 2,
    intentId: intent.intentId,
    blindContentId,
    ciphertextRoot,
    contentVersion: 1,
    retainUntil: now + 120_000,
    relayRegion: 'test',
    shardIds: [0],
    shareScheme: 'pvss-secp256k1-v1',
    commitmentRoot: res.public.commitmentRoot,
    shareIndex: 1,
    shareCommitment: shareCommitmentAt(res.public.commitments, 1),
    shareVerified: true
  }, relay, { timestamp: now + 1000 })

  t.ok(verifyCustodyEntry(receipt, { now: now + 1000 }).valid, 'v2 receipt signature verifies')
  t.is(receipt.shareCommitment, shareCommitmentAt(res.public.commitments, 1), 'receipt pins the per-index commitment point')
  t.ok(validateCustodyTransition(receipt, { intent }).valid, 'receipt binds to its PVSS intent')
})

test('custody v2: version-gating keeps the v1 surface closed to PVSS fields', (t) => {
  const now = Date.now()
  const publisher = keyPair()
  const base = {
    blindContentId: hashHex('gate-blind'),
    ciphertextRoot: hashHex('gate-cipher'),
    contentVersion: 1,
    requiredReplicas: 3,
    deadline: now + 60_000,
    retainUntil: now + 120_000
  }

  // v1 (default) intent with no PVSS fields verifies — unchanged behavior.
  const v1 = createCustodyIntent({ ...base }, publisher, { timestamp: now })
  t.ok(verifyCustodyEntry(v1, { now }).valid, 'plain v1 intent verifies')
  t.is(v1.version, 1, 'defaults to version 1')
  t.is(v1.shareScheme, undefined, 'no PVSS fields leak into v1')

  // A v1 intent carrying a PVSS field is rejected as an unknown field.
  t.exception(
    () => createCustodyIntent({ ...base, shareScheme: 'pvss-secp256k1-v1' }, publisher, { timestamp: now }),
    /unknown custody field: shareScheme/,
    'v1 intent rejects shareScheme'
  )

  // version 2 is only defined for intent + receipt; other types reject it.
  t.exception(
    () => createCustodyCommit({
      version: 2,
      intentId: v1.intentId,
      blindContentId: base.blindContentId,
      ciphertextRoot: base.ciphertextRoot,
      contentVersion: 1,
      relayQuorum: [],
      receiptRoot: hashHex('rr')
    }, publisher, { timestamp: now }),
    /version 2 unsupported for custody-commit/,
    'version 2 rejected for commit type'
  )

  // An unsupported version number is rejected outright.
  t.exception(
    () => createCustodyIntent({ ...base, version: 3 }, publisher, { timestamp: now }),
    /unsupported custody version/,
    'version 3 rejected'
  )
})

test('custody v2: cleartext PVSS share material is forbidden in any custody entry', (t) => {
  const now = Date.now()
  const publisher = keyPair()
  const base = {
    version: 2,
    blindContentId: hashHex('forbid-blind'),
    ciphertextRoot: hashHex('forbid-cipher'),
    contentVersion: 1,
    requiredReplicas: 3,
    deadline: now + 60_000,
    retainUntil: now + 120_000,
    shareScheme: 'pvss-secp256k1-v1',
    shareThreshold: 2,
    commitmentRoot: hashHex('forbid-root')
  }
  // A top-level PVSS secret field is rejected by the positive allowlist (which
  // names the offending field) before signing — the same primary gate the base
  // custody fields use (see custody-signing.test.js and custody-signing.js:
  // rejectUnknownFields runs before the recursive forbidden scan). These field
  // names are never in any allowlist, so they can never reach a signed entry.
  for (const secretField of ['share', 'shareScalar', 'decryptedShare', 'secret', 'secretPoint', 'coefficient', 'coefficients', 'polynomial']) {
    t.exception(
      () => createCustodyIntent({ ...base, [secretField]: 'deadbeef' }, publisher, { timestamp: now }),
      new RegExp('unknown custody field: ' + secretField),
      `top-level ${secretField} rejected by the allowlist`
    )
  }
  // Nested PVSS secret material riding inside an otherwise-allowed container is
  // caught by the recursive forbidden-secret scan (the backstop for allowlisted
  // containers).
  t.exception(
    () => createCustodyIntent({ ...base, candidateRelays: [{ share: 'nested-secret' }] }, publisher, { timestamp: now }),
    /forbidden/,
    'nested PVSS secret is rejected by the recursive scan'
  )
})

test('custody v2: receipt↔intent PVSS binding is enforced by validateCustodyTransition', async (t) => {
  const now = Date.now()
  const { res, intent, relays } = await pvssScenario({ n: 3, threshold: 2, now })
  const relay = relays[0] // assigned shareIndex 1 by the scenario
  const commitments = res.public.commitments

  t.ok(validateCustodyTransition(pvssReceipt(intent, relay, 1, commitments, now), { intent }).valid, 'matching receipt valid')

  t.is(
    validateCustodyTransition(pvssReceipt(intent, relay, 1, commitments, now, { commitmentRoot: hashHex('other-root') }), { intent }).reason,
    'commitmentRoot mismatch',
    'wrong commitmentRoot rejected'
  )

  // shareScheme is constrained to one known value at normalize time, so a
  // mismatching scheme can only arrive on an adversarial (un-normalized) entry
  // over the wire — the transition check must still catch it.
  const good = pvssReceipt(intent, relay, 1, commitments, now)
  t.is(
    validateCustodyTransition({ ...good, shareScheme: 'pvss-secp256k1-v2' }, { intent }).reason,
    'shareScheme mismatch',
    'mismatched shareScheme rejected'
  )

  t.is(
    validateCustodyTransition(pvssReceipt(intent, relay, 99, commitments, now), { intent }).reason,
    'shareIndex out of range',
    'shareIndex beyond requiredReplicas rejected'
  )

  t.is(
    validateCustodyTransition({ ...good, shareVerified: false }, { intent }).reason,
    'shareVerified must be true',
    'unverified share rejected'
  )
})

test('custody v2: intent shareBundleKey + shareAssignments are validated at signing time', async (t) => {
  const now = Date.now()
  const keys = await shareholders(3)
  const res = await split({ threshold: 2, shareholders: keys.map(k => k.publicKey) })
  const publisher = keyPair()
  const relays = Array.from({ length: 3 }, () => keyPair())
  const hex = (r) => b4a.toString(r.publicKey, 'hex')
  const base = {
    version: 2,
    blindContentId: hashHex('assign-blind'),
    ciphertextRoot: hashHex('assign-cipher'),
    contentVersion: 1,
    requiredReplicas: 3,
    deadline: now + 60_000,
    retainUntil: now + 120_000,
    shareScheme: 'pvss-secp256k1-v1',
    shareThreshold: 2,
    commitmentRoot: res.public.commitmentRoot,
    shareBundleKey: hashHex('assign-bundle')
  }
  const mk = (overrides) => createCustodyIntent({ ...base, ...overrides }, publisher, { timestamp: now })

  // Happy path signs + verifies, and the map is sorted ascending by shareIndex
  // (fed in reverse to prove the sort actually runs).
  const ok = mk({ shareAssignments: assignmentsFor(relays).slice().reverse() })
  t.ok(verifyCustodyEntry(ok, { now }).valid, 'valid v2 intent signs + verifies')
  t.alike(ok.shareAssignments.map(a => a.shareIndex), [1, 2, 3], 'assignments sorted ascending by shareIndex')

  // shareBundleKey is required for a v2 intent.
  const noBundle = { ...base, shareAssignments: assignmentsFor(relays) }
  delete noBundle.shareBundleKey
  t.exception(() => createCustodyIntent(noBundle, publisher, { timestamp: now }), /shareBundleKey must be 64 hex/, 'shareBundleKey required')

  t.exception(() => mk({ shareAssignments: [] }), /shareAssignments must be a non-empty array/, 'empty assignments rejected')
  t.exception(
    () => mk({ shareAssignments: [{ relayPubkey: hex(relays[0]), shareIndex: 4 }, { relayPubkey: hex(relays[1]), shareIndex: 2 }] }),
    /shareIndex exceeds requiredReplicas/,
    'index beyond requiredReplicas rejected'
  )
  t.exception(
    () => mk({ shareAssignments: [{ relayPubkey: hex(relays[0]), shareIndex: 1 }, { relayPubkey: hex(relays[1]), shareIndex: 1 }] }),
    /duplicate shareIndex/,
    'duplicate index rejected'
  )
  t.exception(
    () => mk({ shareAssignments: [{ relayPubkey: hex(relays[0]), shareIndex: 1 }, { relayPubkey: hex(relays[0]), shareIndex: 2 }] }),
    /duplicate relayPubkey/,
    'duplicate relay rejected'
  )
  t.exception(
    () => mk({ shareAssignments: [{ relayPubkey: hex(relays[0]), shareIndex: 1 }] }),
    /shareAssignments fewer than shareThreshold/,
    'fewer assignments than threshold rejected'
  )
})

test('custody v2: a receipt from an unassigned relay (or wrong index) is rejected', async (t) => {
  const now = Date.now()
  const { res, intent, relays } = await pvssScenario({ n: 3, threshold: 2, now })
  const commitments = res.public.commitments

  // relays[1] is assigned shareIndex 2; a receipt for that index binds.
  t.ok(validateCustodyTransition(pvssReceipt(intent, relays[1], 2, commitments, now), { intent }).valid, 'assigned relay at its index binds')

  // relays[1] claiming index 3 (assigned to relays[2]) is rejected.
  t.is(
    validateCustodyTransition(pvssReceipt(intent, relays[1], 3, commitments, now), { intent }).reason,
    'shareIndex does not match assignment',
    'assigned relay cannot claim a different index'
  )

  // A relay absent from the assignment map is rejected outright.
  const stranger = keyPair()
  t.is(
    validateCustodyTransition(pvssReceipt(intent, stranger, 1, commitments, now), { intent }).reason,
    'relay not in shareAssignments',
    'unassigned relay rejected'
  )
})

test('custody v2: a PVSS receipt cannot bind to a non-PVSS (v1) intent', async (t) => {
  const now = Date.now()
  const { res } = await pvssScenario({ n: 3, threshold: 2, now })
  const publisher = keyPair()
  const blindContentId = hashHex('v1-intent-blind')
  const ciphertextRoot = hashHex('v1-intent-cipher')
  const v1Intent = createCustodyIntent({
    blindContentId,
    ciphertextRoot,
    contentVersion: 1,
    requiredReplicas: 3,
    deadline: now + 60_000,
    retainUntil: now + 120_000
  }, publisher, { timestamp: now })
  t.is(v1Intent.version, 1, 'control intent is v1 (no PVSS)')

  const relay = keyPair()
  const receipt = createCustodyReceipt({
    version: 2,
    intentId: v1Intent.intentId,
    blindContentId,
    ciphertextRoot,
    contentVersion: 1,
    retainUntil: now + 120_000,
    relayRegion: 'test',
    shardIds: [0],
    shareScheme: 'pvss-secp256k1-v1',
    commitmentRoot: res.public.commitmentRoot,
    shareIndex: 1,
    shareCommitment: shareCommitmentAt(res.public.commitments, 1),
    shareVerified: true
  }, relay, { timestamp: now + 1000 })

  t.is(
    validateCustodyTransition(receipt, { intent: v1Intent }).reason,
    'share custody declared for non-PVSS intent',
    'PVSS receipt against a non-PVSS intent rejected'
  )
})

test('custody v2: custody-commit requires distinct PVSS share indices across the quorum', async (t) => {
  const now = Date.now()
  const { res, publisher, intent } = await pvssScenario({ n: 2, threshold: 2, now })
  const relayA = keyPair()
  const relayB = keyPair()
  const commitments = res.public.commitments

  const buildCommit = (receipts) => createCustodyCommit({
    intentId: intent.intentId,
    blindContentId: intent.blindContentId,
    ciphertextRoot: intent.ciphertextRoot,
    contentVersion: intent.contentVersion,
    relayQuorum: receipts.map(r => r.relayPubkey).sort(),
    receiptRoot: computeReceiptRoot(receipts)
  }, publisher, { timestamp: now + 2000 })

  // Two receipts colliding on shareIndex = 1 cannot reconstruct the secret.
  const dup = [
    pvssReceipt(intent, relayA, 1, commitments, now),
    pvssReceipt(intent, relayB, 1, commitments, now)
  ]
  t.is(
    validateCustodyTransition(buildCommit(dup), { intent, receipts: dup }).reason,
    'duplicate shareIndex in quorum',
    'colliding share indices rejected'
  )

  // Distinct indices 1 and 2 reconstruct → commit valid.
  const ok = [
    pvssReceipt(intent, relayA, 1, commitments, now),
    pvssReceipt(intent, relayB, 2, commitments, now)
  ]
  t.ok(validateCustodyTransition(buildCommit(ok), { intent, receipts: ok }).valid, 'distinct indices commit valid')
})

test('custody v2: summarizeCustodyStatus surfaces a PVSS block only for PVSS intents', async (t) => {
  const now = Date.now()
  const { res, intent } = await pvssScenario({ n: 3, threshold: 2, now })
  const relayA = keyPair()
  const relayB = keyPair()
  const commitments = res.public.commitments
  const receipts = [
    pvssReceipt(intent, relayA, 2, commitments, now),
    pvssReceipt(intent, relayB, 1, commitments, now)
  ]
  const summary = summarizeCustodyStatus(intent, receipts)
  t.ok(summary.pvss, 'pvss block present')
  t.is(summary.pvss.shareScheme, 'pvss-secp256k1-v1', 'scheme surfaced')
  t.is(summary.pvss.shareThreshold, 2, 'threshold surfaced')
  t.is(summary.pvss.commitmentRoot, res.public.commitmentRoot, 'root surfaced')
  t.alike(summary.pvss.shareIndices, [1, 2], 'share indices deduped + sorted')

  // Non-PVSS intent → no pvss block (byte-identical to pre-change summaries).
  const publisher = keyPair()
  const v1Intent = createCustodyIntent({
    blindContentId: hashHex('sum-v1-blind'),
    ciphertextRoot: hashHex('sum-v1-cipher'),
    contentVersion: 1,
    requiredReplicas: 1,
    deadline: now + 60_000,
    retainUntil: now + 120_000
  }, publisher, { timestamp: now })
  t.is(summarizeCustodyStatus(v1Intent, []).pvss, undefined, 'no pvss block for v1 intent')
})
