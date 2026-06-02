#!/usr/bin/env node

/**
 * test-arbitration-poker-schemas.js
 *
 * Validates poker dispute schemas added to ArbitrationService:
 *
 *   1. Relay-level disputes still submit + are unaffected.
 *   2. Each poker/* type accepts well-formed evidence.
 *   3. Each poker/* type rejects malformed evidence with a specific reason.
 *   4. submit() rejects poker disputes that omit appEvidence entirely.
 *   5. Oversized appEvidence is rejected.
 *   6. evidence() returns 'inconclusive' when no verifier is registered.
 *   7. evidence() returns the verifier's verdict when one is registered,
 *      normalising booleans and bad-shape returns into 'inconclusive'.
 *   8. setAppEvidenceVerifier guards on type + function shape.
 */

import { ArbitrationService, POKER_DISPUTE_TYPES, RELAY_DISPUTE_TYPES } from '../packages/services/builtin/arbitration-service.js'

let passed = 0
let failed = 0

function assert (condition, label) {
  if (condition) {
    console.log(`  PASS  ${label}`)
    passed++
  } else {
    console.log(`  FAIL  ${label}`)
    failed++
  }
}

async function shouldThrow (label, fn, includes) {
  let threw = false
  let msg = null
  try { await fn() } catch (err) { threw = true; msg = err.message }
  if (!threw) {
    assert(false, label + ' (no throw)')
    return
  }
  if (includes && (!msg || !msg.includes(includes))) {
    assert(false, label + ' (wrong message: ' + msg + ')')
    return
  }
  assert(true, label + ' (' + msg + ')')
}

const TABLE_KEY = 'a'.repeat(64)
const RESPONDENT = 'b'.repeat(64)
const CLAIMANT = 'c'.repeat(64)

function newSvc () {
  const svc = new ArbitrationService()
  // Bypass start() — we don't need the relay node hooks for schema testing.
  // Just give the service a no-op router.pubsub so submit doesn't crash.
  svc.node = { router: { pubsub: { publish () {} } } }
  return svc
}

// ── 1. Relay dispute types unchanged ────────────────────────────────────────
async function testRelayDisputesUnchanged () {
  console.log('\n── 1. Relay-level disputes still submit ──')
  for (const type of RELAY_DISPUTE_TYPES) {
    const svc = newSvc()
    const d = await svc.submit({
      type,
      respondent: RESPONDENT,
      claimant: CLAIMANT,
      receipts: [],
      penalty: 100
    }, { caller: 'local' })
    assert(d && d.type === type, `${type}: submits, no appEvidence required`)
    assert(d.evidence.appEvidence === null, `${type}: appEvidence is null`)
  }
}

// ── 2. Poker disputes accept well-formed evidence ───────────────────────────
async function testPokerWellFormed () {
  console.log('\n── 2. Poker disputes accept well-formed evidence ──')
  const goodEvidence = {
    'poker/missing-share': {
      tableKey: TABLE_KEY,
      handId: 'hand-42',
      cardIndex: 17,
      deadline: 1700000000000,
      logProof: { tick: 12 }
    },
    'poker/invalid-share': {
      tableKey: TABLE_KEY,
      handId: 'hand-42',
      cardIndex: 17,
      ciphertext: 'ab'.repeat(32),
      share: 'cd'.repeat(32),
      witness: { challenge: 'aa', response: 'bb' }
    },
    'poker/refused-reveal': {
      tableKey: TABLE_KEY,
      handId: 'hand-42',
      showdownDeadline: 1700000000000,
      potCommitProof: { tick: 30 },
      logProof: { tick: 34 }
    }
  }
  for (const type of POKER_DISPUTE_TYPES) {
    const svc = newSvc()
    const d = await svc.submit({
      type,
      respondent: RESPONDENT,
      claimant: CLAIMANT,
      appEvidence: goodEvidence[type],
      penalty: 100
    }, { caller: 'local' })
    assert(d.evidence.appEvidence !== null, `${type}: appEvidence carried`)
    assert(d.evidence.appEvidence.tableKey === TABLE_KEY, `${type}: tableKey carried`)
  }
}

// ── 3. Malformed evidence rejected with specific reasons ───────────────────
async function testPokerMalformed () {
  console.log('\n── 3. Malformed poker evidence rejected ──')
  const svc = newSvc()
  await shouldThrow('missing-share bad tableKey', () => svc.submit({
    type: 'poker/missing-share',
    respondent: RESPONDENT,
    claimant: CLAIMANT,
    appEvidence: { tableKey: 'not-hex', handId: 'h', cardIndex: 0, deadline: 1, logProof: {} }
  }, { caller: 'local' }), 'tableKey')

  await shouldThrow('invalid-share bad cardIndex (>=52)', () => svc.submit({
    type: 'poker/invalid-share',
    respondent: RESPONDENT,
    claimant: CLAIMANT,
    appEvidence: {
      tableKey: TABLE_KEY, handId: 'h', cardIndex: 99,
      ciphertext: 'ab', share: 'cd', witness: {}
    }
  }, { caller: 'local' }), 'cardIndex')

  await shouldThrow('invalid-share oversized ciphertext', () => svc.submit({
    type: 'poker/invalid-share',
    respondent: RESPONDENT,
    claimant: CLAIMANT,
    appEvidence: {
      tableKey: TABLE_KEY, handId: 'h', cardIndex: 1,
      ciphertext: 'aa'.repeat(5000), // 5000 bytes > 2048 cap
      share: 'cd', witness: {}
    }
  }, { caller: 'local' }), 'ciphertext')

  await shouldThrow('refused-reveal missing potCommitProof', () => svc.submit({
    type: 'poker/refused-reveal',
    respondent: RESPONDENT,
    claimant: CLAIMANT,
    appEvidence: {
      tableKey: TABLE_KEY, handId: 'h',
      showdownDeadline: 1, logProof: {}
    }
  }, { caller: 'local' }), 'potCommitProof')
}

// ── 4. Poker dispute without appEvidence rejected ───────────────────────────
async function testPokerRequiresAppEvidence () {
  console.log('\n── 4. Poker dispute without appEvidence ──')
  const svc = newSvc()
  await shouldThrow('missing-share: no appEvidence at all', () => svc.submit({
    type: 'poker/missing-share',
    respondent: RESPONDENT,
    claimant: CLAIMANT
  }, { caller: 'local' }), 'MISSING_APP_EVIDENCE')
}

// ── 5. Oversized appEvidence rejected ───────────────────────────────────────
async function testOversized () {
  console.log('\n── 5. Oversized appEvidence ──')
  const svc = newSvc()
  // Build an oversized witness blob (>64 KB serialized).
  const huge = { junk: 'x'.repeat(100000) }
  await shouldThrow('oversized', () => svc.submit({
    type: 'poker/invalid-share',
    respondent: RESPONDENT,
    claimant: CLAIMANT,
    appEvidence: {
      tableKey: TABLE_KEY, handId: 'h', cardIndex: 1,
      ciphertext: 'ab', share: 'cd', witness: huge
    }
  }, { caller: 'local' }), 'oversized')
}

// ── 6. evidence() returns 'inconclusive' when no verifier ───────────────────
async function testEvidenceNoVerifier () {
  console.log('\n── 6. evidence() with no verifier registered ──')
  const svc = newSvc()
  const d = await svc.submit({
    type: 'poker/missing-share',
    respondent: RESPONDENT,
    claimant: CLAIMANT,
    appEvidence: {
      tableKey: TABLE_KEY, handId: 'h', cardIndex: 0, deadline: 1, logProof: {}
    }
  }, { caller: 'local' })
  const e = await svc.evidence({ id: d.id })
  assert(e.appEvidence && e.appEvidence.verdict === 'inconclusive', 'verdict inconclusive')
  assert(e.appEvidence.reason === 'no-verifier-registered', 'reason: no-verifier-registered')
}

// ── 7. evidence() uses registered verifier; normalises return ───────────────
async function testEvidenceWithVerifier () {
  console.log('\n── 7. evidence() with verifier ──')
  // Boolean return.
  let svc = newSvc()
  svc.setAppEvidenceVerifier('poker/missing-share', () => true)
  let d = await svc.submit({
    type: 'poker/missing-share',
    respondent: RESPONDENT,
    claimant: CLAIMANT,
    appEvidence: { tableKey: TABLE_KEY, handId: 'h', cardIndex: 0, deadline: 1, logProof: {} }
  }, { caller: 'local' })
  let e = await svc.evidence({ id: d.id })
  assert(e.appEvidence.verdict === 'claim-supported', 'boolean true → claim-supported')

  svc = newSvc()
  svc.setAppEvidenceVerifier('poker/missing-share', () => false)
  d = await svc.submit({
    type: 'poker/missing-share',
    respondent: RESPONDENT,
    claimant: CLAIMANT,
    appEvidence: { tableKey: TABLE_KEY, handId: 'h', cardIndex: 0, deadline: 1, logProof: {} }
  }, { caller: 'local' })
  e = await svc.evidence({ id: d.id })
  assert(e.appEvidence.verdict === 'claim-refuted', 'boolean false → claim-refuted')

  // Throwing verifier becomes inconclusive (not a crash).
  svc = newSvc()
  svc.setAppEvidenceVerifier('poker/missing-share', () => { throw new Error('boom') })
  d = await svc.submit({
    type: 'poker/missing-share',
    respondent: RESPONDENT,
    claimant: CLAIMANT,
    appEvidence: { tableKey: TABLE_KEY, handId: 'h', cardIndex: 0, deadline: 1, logProof: {} }
  }, { caller: 'local' })
  e = await svc.evidence({ id: d.id })
  assert(e.appEvidence.verdict === 'inconclusive', 'throwing verifier → inconclusive')
  assert(e.appEvidence.reason.startsWith('verifier-threw:'), 'reason mentions verifier threw')

  // Bad-shape verifier return becomes inconclusive.
  svc = newSvc()
  svc.setAppEvidenceVerifier('poker/missing-share', () => ({ verdict: 'lol-no' }))
  d = await svc.submit({
    type: 'poker/missing-share',
    respondent: RESPONDENT,
    claimant: CLAIMANT,
    appEvidence: { tableKey: TABLE_KEY, handId: 'h', cardIndex: 0, deadline: 1, logProof: {} }
  }, { caller: 'local' })
  e = await svc.evidence({ id: d.id })
  assert(e.appEvidence.verdict === 'inconclusive', 'bad-verdict return → inconclusive')
}

// ── 8. setAppEvidenceVerifier guards ────────────────────────────────────────
async function testSetVerifierGuards () {
  console.log('\n── 8. setAppEvidenceVerifier guards ──')
  const svc = newSvc()
  let threw = false
  try { svc.setAppEvidenceVerifier('not-an-app-type', () => true) }
  catch { threw = true }
  assert(threw, 'rejects unknown app type')

  threw = false
  try { svc.setAppEvidenceVerifier('poker/missing-share', 'not-a-fn') }
  catch { threw = true }
  assert(threw, 'rejects non-function')
}

async function main () {
  await testRelayDisputesUnchanged()
  await testPokerWellFormed()
  await testPokerMalformed()
  await testPokerRequiresAppEvidence()
  await testOversized()
  await testEvidenceNoVerifier()
  await testEvidenceWithVerifier()
  await testSetVerifierGuards()
  console.log(`\n── done: ${passed} passed, ${failed} failed ──`)
  process.exit(failed === 0 ? 0 : 1)
}

main().catch((err) => {
  console.error('fatal:', err)
  process.exit(2)
})
