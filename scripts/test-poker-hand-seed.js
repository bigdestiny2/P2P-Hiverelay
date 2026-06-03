#!/usr/bin/env node

/**
 * test-poker-hand-seed.js
 *
 * The poker relay is card-blind, so its only randomness contribution is a
 * verifiable per-hand seed. This exercises that helper end-to-end against the
 * real VRFService:
 *
 *   - handSeedAlpha is canonical: deterministic, depends on BOTH tableKey and
 *     handId, validates inputs
 *   - prove(alpha) → verifyHandSeed accepts; tampered pi / beta / handId /
 *     pubkey are all rejected; malformed inputs never throw
 *   - handDeckOrder is a deterministic permutation; different hands differ
 *   - combineBetas XORs multiple seats' betas into a seed no single seat
 *     controls, and each contribution stays independently verifiable
 */

import { VRFService } from '../packages/services/builtin/vrf-service.js'
import {
  handSeedAlpha, verifyHandSeed, handDeckOrder, combineBetas, HAND_SEED_DOMAIN
} from '../packages/services/builtin/poker/hand-seed.js'

let passed = 0
let failed = 0
function assert (cond, label) {
  if (cond) { console.log(`  PASS  ${label}`); passed++ } else { console.log(`  FAIL  ${label}`); failed++ }
}
function throws (fn, label) {
  try { fn(); assert(false, label + ' (expected throw)') } catch { assert(true, label) }
}

const TABLE = 'ab'.repeat(32) // 64-hex table pubkey
const TABLE2 = 'cd'.repeat(32)

async function main () {
  // ── 1. canonical alpha ───────────────────────────────────────────────────────
  console.log('── handSeedAlpha ──')
  const a1 = handSeedAlpha(TABLE, 'hand-1')
  assert(/^[0-9a-f]{64}$/.test(a1), 'alpha is 32-byte hex')
  assert(handSeedAlpha(TABLE, 'hand-1') === a1, 'alpha is deterministic')
  assert(handSeedAlpha(TABLE, 'hand-2') !== a1, 'alpha depends on handId')
  assert(handSeedAlpha(TABLE2, 'hand-1') !== a1, 'alpha depends on tableKey')
  assert(handSeedAlpha(TABLE, 7) === handSeedAlpha(TABLE, '7'), 'numeric handId coerces to its string form')
  assert(typeof HAND_SEED_DOMAIN === 'string' && HAND_SEED_DOMAIN.length > 0, 'domain constant is exported')
  throws(() => handSeedAlpha('xyz', 'hand-1'), 'rejects a non-64-hex tableKey')
  throws(() => handSeedAlpha(TABLE, ''), 'rejects an empty handId')
  throws(() => handSeedAlpha(TABLE, 'x'.repeat(200)), 'rejects an over-long handId')
  throws(() => handSeedAlpha(TABLE, {}), 'rejects a non-string/number handId')

  // ── 2. prove + verify a hand seed (single relay) ─────────────────────────────
  console.log('\n── prove / verifyHandSeed ──')
  const svc = new VRFService({ seed: '11'.repeat(32) })
  await svc.start({ node: null })
  const vrfPubkey = (await svc.pubkey()).pubkey

  const alpha = handSeedAlpha(TABLE, 'hand-42')
  const out = await svc.prove({ alpha })
  assert(out.alpha === alpha, 'service proves exactly the canonical alpha')

  const ok = verifyHandSeed({ vrfPubkey, tableKey: TABLE, handId: 'hand-42', pi: out.pi, beta: out.beta })
  assert(ok.valid === true && ok.beta === out.beta, 'verifyHandSeed accepts an honest seed and returns beta')
  assert(ok.alpha === alpha, 'verifyHandSeed recomputes the same alpha')

  // verify without supplying beta still validates the proof
  assert(verifyHandSeed({ vrfPubkey, tableKey: TABLE, handId: 'hand-42', pi: out.pi }).valid === true, 'verify works without an expected beta')

  // negatives — all return {valid:false}, none throw
  const tamperedPi = out.pi.slice(0, -2) + (out.pi.endsWith('00') ? '01' : '00')
  assert(verifyHandSeed({ vrfPubkey, tableKey: TABLE, handId: 'hand-42', pi: tamperedPi }).valid === false, 'rejects a tampered proof')
  assert(verifyHandSeed({ vrfPubkey, tableKey: TABLE, handId: 'hand-43', pi: out.pi }).valid === false, 'rejects a proof bound to a different handId')
  assert(verifyHandSeed({ vrfPubkey, tableKey: TABLE2, handId: 'hand-42', pi: out.pi }).valid === false, 'rejects a proof bound to a different table')
  const betaMismatch = verifyHandSeed({ vrfPubkey, tableKey: TABLE, handId: 'hand-42', pi: out.pi, beta: 'ff'.repeat(64) })
  assert(betaMismatch.valid === false && betaMismatch.reason === 'beta-mismatch', 'rejects a beta that does not match the proof')
  const wrongKey = (new VRFService({ seed: '22'.repeat(32) }))
  await wrongKey.start({ node: null })
  const wrongPubkey = (await wrongKey.pubkey()).pubkey
  assert(verifyHandSeed({ vrfPubkey: wrongPubkey, tableKey: TABLE, handId: 'hand-42', pi: out.pi }).valid === false, 'rejects a proof under the wrong VRF key')
  assert(verifyHandSeed({ vrfPubkey, tableKey: TABLE, handId: 'hand-42', pi: 'zzzz' }).valid === false, 'malformed pi returns invalid (no throw)')

  // ── 3. handDeckOrder ─────────────────────────────────────────────────────────
  console.log('\n── handDeckOrder ──')
  const order = handDeckOrder(out.beta)
  assert(order.length === 52, 'deck order has 52 cards')
  assert(new Set(order).size === 52 && Math.min(...order) === 0 && Math.max(...order) === 51, 'deck order is a permutation of 0..51')
  assert(JSON.stringify(handDeckOrder(out.beta)) === JSON.stringify(order), 'deck order is deterministic for a beta')
  const out2 = await svc.prove({ alpha: handSeedAlpha(TABLE, 'hand-43') })
  assert(JSON.stringify(handDeckOrder(out2.beta)) !== JSON.stringify(order), 'a different hand yields a different deck order')
  assert(handDeckOrder(out.beta, 6).length === 6, 'deckSize is configurable')
  throws(() => handDeckOrder(out.beta, 0), 'rejects a non-positive deckSize')

  // ── 4. combineBetas (no single seat controls the seed) ───────────────────────
  console.log('\n── combineBetas ──')
  // three seats each prove the SAME alpha under their own key
  const seats = []
  for (const s of ['11', '22', '33']) {
    const seat = new VRFService({ seed: s.repeat(32) })
    await seat.start({ node: null })
    const pub = (await seat.pubkey()).pubkey
    const proof = await seat.prove({ alpha })
    // each seat's contribution is independently verifiable
    assert(verifyHandSeed({ vrfPubkey: pub, tableKey: TABLE, handId: 'hand-42', pi: proof.pi, beta: proof.beta }).valid === true, `seat ${s} contribution verifies`)
    seats.push(proof.beta)
  }
  const combined = combineBetas(seats)
  assert(/^[0-9a-f]{128}$/.test(combined), 'combined seed is a 64-byte hex value')
  assert(combineBetas(seats) === combined, 'combine is deterministic')
  // order-independent (XOR commutes) and changing any contribution changes it
  assert(combineBetas([seats[2], seats[0], seats[1]]) === combined, 'combine is order-independent')
  assert(combineBetas([seats[0], seats[1]]) !== combined, 'dropping a contribution changes the seed')
  assert(combineBetas([seats[0]]) === seats[0], 'a single contribution combines to itself')
  // combined seed drives a deck order just like a single beta
  assert(handDeckOrder(combined).length === 52, 'combined seed produces a valid deck order')
  throws(() => combineBetas([]), 'combine rejects an empty array')
  throws(() => combineBetas(['ab']), 'combine rejects a wrong-length beta')

  console.log(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed === 0 ? 0 : 1)
}

main().catch(err => { console.error(err); process.exit(1) })
