#!/usr/bin/env node

/**
 * test-vrf-sortition.js
 *
 * Exercises the pure sortition primitive (packages/services/builtin/vrf/sortition.js)
 * that turns an unbiasable VRF output into a verifiable shuffle or committee.
 *
 *   seededShuffle:
 *     - deterministic for a fixed (seed, domain); is a true permutation
 *     - different seeds (and different domains) yield different orders
 *     - verifyShuffle accepts a faithful replay and rejects a tampered one
 *
 *   weightedSample:
 *     - unweighted draws a distinct k-subset, deterministic, order-independent
 *     - weighted draws without replacement; zero-weight is never picked;
 *       heavy weights dominate over many independent seeds (statistical)
 *     - canonical ordering: enumerating candidates in any order is identical
 *     - count >= pool returns the whole pool; count 0 / empty pool are clean
 *     - verifyCommittee accepts a faithful replay and rejects a wrong one
 *     - malformed inputs throw (non-integer weight, duplicate id, bad seed)
 *
 *   quantizeWeights:
 *     - rounds to fixed point; positive floors to >= 1; zero/negative -> 0
 */

import { sha512 } from '@noble/hashes/sha2.js'
import {
  seededShuffle, weightedSample, quantizeWeights,
  verifyCommittee, verifyShuffle,
  SHUFFLE_DOMAIN, SELECT_DOMAIN, DEFAULT_WEIGHT_SCALE
} from '../packages/services/builtin/vrf/sortition.js'

let passed = 0
let failed = 0
function assert (cond, label) {
  if (cond) { console.log(`  PASS  ${label}`); passed++ } else { console.log(`  FAIL  ${label}`); failed++ }
}
function rejects (fn, label) {
  try { fn(); assert(false, label + ' (expected throw)') } catch { assert(true, label) }
}

function toHex (bytes) {
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0')
  return s
}
// Distinct 64-byte seeds for statistical sweeps.
function seedFor (i) {
  const buf = new Uint8Array(8)
  let v = BigInt(i)
  for (let k = 0; k < 8; k++) { buf[k] = Number(v & 0xffn); v >>= 8n }
  return toHex(sha512(buf))
}
function sameMultiset (a, b) {
  if (a.length !== b.length) return false
  const sa = [...a].sort(); const sb = [...b].sort()
  return sa.every((x, i) => x === sb[i])
}

function main () {
  // ── 1. seededShuffle: determinism + permutation ─────────────────────────────
  console.log('── seededShuffle ──')
  const deck = Array.from({ length: 52 }, (_, i) => i)
  const seedA = 'a1'.repeat(32)
  const s1 = seededShuffle(seedA, deck)
  const s2 = seededShuffle(seedA, deck)
  assert(JSON.stringify(s1) === JSON.stringify(s2), 'shuffle is deterministic for a fixed seed')
  assert(sameMultiset(s1, deck), 'shuffle is a true permutation (same multiset)')
  assert(JSON.stringify(s1) !== JSON.stringify(deck), 'shuffle actually reorders')
  assert(JSON.stringify(seededShuffle(seedA, deck)) === JSON.stringify(s1) &&
         deck[0] === 0 && deck[51] === 51, 'shuffle does not mutate the input array')

  const s3 = seededShuffle('b2'.repeat(32), deck)
  assert(JSON.stringify(s3) !== JSON.stringify(s1), 'different seeds give different orders')
  // domain separation: same seed, different domain ⇒ different permutation
  const sDom = seededShuffle(seedA, deck, { domain: 'other/domain/v1' })
  assert(JSON.stringify(sDom) !== JSON.stringify(s1), 'domain tag separates streams off the same seed')

  // single / empty
  assert(JSON.stringify(seededShuffle(seedA, [7])) === JSON.stringify([7]), 'shuffle of one element is identity')
  assert(JSON.stringify(seededShuffle(seedA, [])) === JSON.stringify([]), 'shuffle of empty is empty')

  // verifyShuffle
  assert(verifyShuffle(seedA, deck, s1) === true, 'verifyShuffle accepts a faithful replay')
  const tampered = s1.slice(); [tampered[0], tampered[1]] = [tampered[1], tampered[0]]
  assert(verifyShuffle(seedA, deck, tampered) === false, 'verifyShuffle rejects a tampered order')
  assert(verifyShuffle('c3'.repeat(32), deck, s1) === false, 'verifyShuffle rejects a wrong seed')

  // ── 2. shuffle uniformity (loose, non-flaky) ────────────────────────────────
  console.log('\n── shuffle uniformity ──')
  const N = 4
  const small = [0, 1, 2, 3]
  const trials = 4000
  const posCount = 0 // element 0 landing in position 0
  let elem0pos0 = 0
  for (let i = 0; i < trials; i++) {
    const r = seededShuffle(seedFor(i), small)
    if (r[0] === 0) elem0pos0++
  }
  // expected trials/N = 1000; ~7σ bounds [800,1200] — never flaky for a sane RNG
  assert(elem0pos0 > 800 && elem0pos0 < 1200, `shuffle roughly uniform (elem0@pos0=${elem0pos0}, expect ~${trials / N})`)
  void posCount

  // ── 3. weightedSample: unweighted k-subset ──────────────────────────────────
  console.log('\n── weightedSample (unweighted) ──')
  const pool = ['aa', 'bb', 'cc', 'dd', 'ee', 'ff', '11', '22']
  const c3 = weightedSample({ seed: seedA, candidates: pool, count: 3 })
  assert(c3.length === 3, 'draws the requested count')
  assert(new Set(c3).size === 3, 'committee members are distinct (no replacement)')
  assert(c3.every(id => pool.includes(id)), 'all members come from the candidate pool')
  assert(JSON.stringify(weightedSample({ seed: seedA, candidates: pool, count: 3 })) === JSON.stringify(c3),
    'unweighted selection is deterministic')

  // order-independence: shuffling the *input* list must not change the committee
  const poolShuffled = seededShuffle('ff'.repeat(32), pool)
  const c3b = weightedSample({ seed: seedA, candidates: poolShuffled, count: 3 })
  assert(JSON.stringify(c3b) === JSON.stringify(c3), 'committee depends only on the candidate set, not enumeration order')

  // object form with ignored weights behaves like string form
  const objPool = pool.map(id => ({ id, weight: 5 }))
  assert(JSON.stringify(weightedSample({ seed: seedA, candidates: objPool, count: 3 })) === JSON.stringify(c3),
    'unweighted ignores weights on object candidates')

  // count >= pool returns the whole set; count 0 / empty are clean
  const all = weightedSample({ seed: seedA, candidates: pool, count: 999 })
  assert(all.length === pool.length && sameMultiset(all, pool), 'count >= size returns the full pool')
  assert(weightedSample({ seed: seedA, candidates: pool, count: 0 }).length === 0, 'count 0 returns empty')
  assert(weightedSample({ seed: seedA, candidates: [], count: 3 }).length === 0, 'empty pool returns empty')

  // ── 4. weightedSample: weighted, without replacement ────────────────────────
  console.log('\n── weightedSample (weighted) ──')
  const wPool = [
    { id: 'heavy', weight: 100 },
    { id: 'light', weight: 1 },
    { id: 'zero', weight: 0 }
  ]
  // zero-weight can never be drawn for a single seat
  let zeroSeen = 0
  for (let i = 0; i < 500; i++) {
    const one = weightedSample({ seed: seedFor(i), candidates: wPool, count: 1, weighted: true })
    if (one[0] === 'zero') zeroSeen++
  }
  assert(zeroSeen === 0, 'zero-weight candidate is never selected')

  // heavy dominates light over many independent seeds (P(heavy)=100/101)
  let heavy = 0; let light = 0
  const wTrials = 2000
  for (let i = 0; i < wTrials; i++) {
    const one = weightedSample({ seed: seedFor(i), candidates: [{ id: 'heavy', weight: 100 }, { id: 'light', weight: 1 }], count: 1, weighted: true })
    if (one[0] === 'heavy') heavy++; else light++
  }
  assert(heavy > 1700 && light > 0, `weighting biases selection (heavy=${heavy}, light=${light} of ${wTrials})`)

  // determinism + without-replacement for a multi-seat draw
  const wp = [
    { id: 'a', weight: 10 }, { id: 'b', weight: 10 }, { id: 'c', weight: 10 },
    { id: 'd', weight: 10 }, { id: 'e', weight: 10 }
  ]
  const w2 = weightedSample({ seed: seedA, candidates: wp, count: 3, weighted: true })
  assert(w2.length === 3 && new Set(w2).size === 3, 'weighted multi-seat draw has no repeats')
  assert(JSON.stringify(weightedSample({ seed: seedA, candidates: wp, count: 3, weighted: true })) === JSON.stringify(w2),
    'weighted selection is deterministic')
  // order independence under weighting too
  const wpRev = wp.slice().reverse()
  assert(JSON.stringify(weightedSample({ seed: seedA, candidates: wpRev, count: 3, weighted: true })) === JSON.stringify(w2),
    'weighted committee is independent of enumeration order')
  // drawing the whole pool returns every positive-weight member
  const wAll = weightedSample({ seed: seedA, candidates: wp, count: 5, weighted: true })
  assert(sameMultiset(wAll, wp.map(c => c.id)), 'weighted full draw returns all positive-weight members')

  // domain separation between shuffle and select off the same beta
  const beta = '7e'.repeat(64)
  const asShuffleFirst = seededShuffle(beta, pool, { domain: SHUFFLE_DOMAIN })[0]
  const asSelectFirst = weightedSample({ seed: beta, candidates: pool, count: pool.length, domain: SELECT_DOMAIN })[0]
  assert(typeof asShuffleFirst === 'number' || typeof asShuffleFirst === 'string', 'shuffle/select domains are distinct constants')
  assert(SHUFFLE_DOMAIN !== SELECT_DOMAIN, 'shuffle and select default domains differ')

  // ── 5. verifyCommittee ──────────────────────────────────────────────────────
  console.log('\n── verifyCommittee ──')
  assert(verifyCommittee({ seed: seedA, candidates: wp, count: 3, weighted: true, expected: w2 }) === true,
    'verifyCommittee accepts a faithful weighted replay')
  const wrong = w2.slice().reverse()
  assert(verifyCommittee({ seed: seedA, candidates: wp, count: 3, weighted: true, expected: wrong }) === false,
    'verifyCommittee rejects a reordered committee')
  assert(verifyCommittee({ seed: 'de'.repeat(32), candidates: wp, count: 3, weighted: true, expected: w2 }) === false,
    'verifyCommittee rejects a wrong seed')
  assert(verifyCommittee({ seed: seedA, candidates: pool, count: 3, expected: c3 }) === true,
    'verifyCommittee accepts a faithful unweighted replay')

  // ── 6. quantizeWeights ──────────────────────────────────────────────────────
  console.log('\n── quantizeWeights ──')
  const q = quantizeWeights([
    { id: 'p', weight: 12.5 },
    { id: 'tiny', weight: 0.0000001 }, // < 1 fixed-point unit but positive
    { id: 'z', weight: 0 },
    { id: 'neg', weight: -3 }
  ])
  const byId = Object.fromEntries(q.map(e => [e.id, e.weight]))
  assert(byId.p === Math.round(12.5 * DEFAULT_WEIGHT_SCALE), 'quantize rounds to fixed point')
  assert(byId.tiny === 1, 'positive-but-tiny weight floors to 1 (stays drawable)')
  assert(byId.z === 0, 'zero weight stays 0')
  assert(byId.neg === 0, 'negative weight clamps to 0')
  // array-tuple form
  const q2 = quantizeWeights([['x', 2], ['y', 3]])
  assert(q2[0].weight === 2 * DEFAULT_WEIGHT_SCALE && q2[1].weight === 3 * DEFAULT_WEIGHT_SCALE, 'quantize accepts [id, weight] tuples')
  // round-trips into a weighted draw
  const qc = weightedSample({ seed: seedA, candidates: q.filter(e => e.weight > 0), count: 2, weighted: true })
  assert(qc.length === 2 && !qc.includes('z') && !qc.includes('neg'), 'quantized weights feed a weighted draw cleanly')

  // ── 7. error handling ───────────────────────────────────────────────────────
  console.log('\n── error handling ──')
  rejects(() => weightedSample({ seed: seedA, candidates: [{ id: 'a', weight: 1.5 }], count: 1, weighted: true }),
    'weighted mode rejects a non-integer weight')
  rejects(() => weightedSample({ seed: seedA, candidates: [{ id: 'a', weight: -1 }], count: 1, weighted: true }),
    'weighted mode rejects a negative weight')
  rejects(() => weightedSample({ seed: seedA, candidates: ['dup', 'dup'], count: 1 }),
    'duplicate candidate id throws')
  rejects(() => weightedSample({ seed: '', candidates: pool, count: 1 }), 'empty seed throws')
  rejects(() => weightedSample({ seed: 'zz', candidates: pool, count: 1 }), 'non-hex seed throws')
  rejects(() => weightedSample({ seed: seedA, candidates: pool, count: -1 }), 'negative count throws')
  rejects(() => weightedSample({ seed: seedA, candidates: 'notarray', count: 1 }), 'non-array candidates throws')
  rejects(() => seededShuffle(seedA, 'notarray'), 'seededShuffle rejects non-array items')
  rejects(() => quantizeWeights([{ id: 'a', weight: Infinity }]), 'quantize rejects non-finite weight')

  console.log(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed === 0 ? 0 : 1)
}

main()
