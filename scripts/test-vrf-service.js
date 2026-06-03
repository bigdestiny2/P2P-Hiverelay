#!/usr/bin/env node

/**
 * test-vrf-service.js
 *
 * Exercises the VRFService provider and the chained randomness beacon end to
 * end (the RFC-vector byte-exactness gate lives in test-vrf-vectors.js):
 *
 *   Service:
 *     - deterministic key derivation from a node keypair (domain-separated,
 *       and distinct from the node's identity pubkey)
 *     - prove → verify round-trip; beta consistency
 *     - verify rejects tampered proof / wrong pubkey / wrong alpha
 *     - proof-to-hash matches; malformed inputs are rejected cleanly
 *     - alpha length cap enforced
 *     - ephemeral fallback when no node key is present
 *
 *   Beacon:
 *     - genesis anchor is publicly derivable from (domain, pubkey)
 *     - rounds chain correctly (prevBeta links, monotonic rounds)
 *     - unbiasable/deterministic: same key+genesis ⇒ identical chain
 *     - third-party verifyBeaconChain accepts an honest chain and rejects
 *       a tampered one
 *     - service beacon RPC (info/latest/round/range/verify)
 *     - retention ring buffer drops old rounds
 */

import sodium from 'sodium-universal'
import b4a from 'b4a'
import { VRFService } from '../packages/services/builtin/vrf-service.js'
import {
  VrfBeacon, verifyBeaconChain, computeGenesisBeta, beaconAlpha, DEFAULT_DOMAIN
} from '../packages/services/builtin/vrf/beacon.js'
import { prove, proofToHash, publicKey, verify, toHex } from '../packages/services/builtin/vrf/ecvrf.js'
import { weightedSample, seededShuffle } from '../packages/services/builtin/vrf/sortition.js'

let passed = 0
let failed = 0
function assert (cond, label) {
  if (cond) { console.log(`  PASS  ${label}`); passed++ } else { console.log(`  FAIL  ${label}`); failed++ }
}
async function rejects (fn, label) {
  try { await fn(); assert(false, label + ' (expected throw)') } catch { assert(true, label) }
}

function fakeNodeKeyPair () {
  const pk = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const sk = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(pk, sk)
  return { publicKey: pk, secretKey: sk }
}

async function main () {
  // ── 0. node-key derivation sanity ──────────────────────────────────────────
  console.log('── key derivation ──')
  const kp = fakeNodeKeyPair()
  const nodePubHex = b4a.toString(kp.publicKey, 'hex')

  const svc = new VRFService({ keyPair: kp })
  await svc.start({ node: null })
  const pk1 = (await svc.pubkey()).pubkey
  assert(/^[0-9a-f]{64}$/.test(pk1), 'derived VRF pubkey is 32-byte hex')
  assert(pk1 !== nodePubHex, 'VRF pubkey is domain-separated from node identity pubkey')

  const svc2 = new VRFService({ keyPair: kp })
  await svc2.start({ node: null })
  assert((await svc2.pubkey()).pubkey === pk1, 'derivation is deterministic for the same node key')

  // ── 1. prove / verify round-trip ────────────────────────────────────────────
  console.log('\n── prove / verify ──')
  const alpha = '0011223344aabbcc'
  const out = await svc.prove({ alpha })
  assert(out.pi.length === 160, 'pi is 80 bytes')
  assert(out.beta.length === 128, 'beta is 64 bytes')
  assert(out.pubkey === pk1, 'prove echoes the VRF pubkey')

  const v = await svc.verify({ pubkey: pk1, alpha, pi: out.pi })
  assert(v.valid === true, 'verify accepts an honest proof')
  assert(v.beta === out.beta, 'verify returns the matching beta')

  const pth = await svc['proof-to-hash']({ pi: out.pi })
  assert(pth.beta === out.beta, 'proof-to-hash matches prove beta')

  // determinism
  const out2 = await svc.prove({ alpha })
  assert(out2.pi === out.pi, 'prove is deterministic for the same (key, alpha)')

  // ── 2. negative cases ────────────────────────────────────────────────────────
  console.log('\n── negative cases ──')
  const tampered = out.pi.slice(0, -2) + (out.pi.endsWith('00') ? '01' : '00')
  assert((await svc.verify({ pubkey: pk1, alpha, pi: tampered })).valid === false, 'verify rejects tampered pi')
  assert((await svc.verify({ pubkey: pk1, alpha: alpha + '00', pi: out.pi })).valid === false, 'verify rejects wrong alpha')
  const otherPk = (await svc2.prove({ alpha })) && publicKey('11'.repeat(32))
  assert((await svc.verify({ pubkey: toHex(otherPk), alpha, pi: out.pi })).valid === false, 'verify rejects wrong pubkey')
  assert((await svc.verify({ pubkey: pk1, alpha, pi: 'zzzz' })).valid === false, 'verify returns false on malformed pi (no throw)')

  await rejects(() => svc.prove({}), 'prove without alpha throws')
  await rejects(() => svc.prove({ alpha: 'gg' }), 'prove with non-hex alpha throws')
  await rejects(() => svc.prove({ alpha: '00'.repeat(svc.maxAlphaBytes + 1) }), 'prove enforces alpha length cap')
  await rejects(() => svc['proof-to-hash']({ pi: '00'.repeat(10) }), 'proof-to-hash rejects wrong-length pi')

  // ── 3. ephemeral fallback ────────────────────────────────────────────────────
  console.log('\n── ephemeral fallback ──')
  const eph = new VRFService({})
  await eph.start({ node: null })
  const ephInfo = await eph.pubkey()
  assert(ephInfo.ephemeral === true, 'no node key ⇒ ephemeral flag set')
  const ephOut = await eph.prove({ alpha })
  assert((await eph.verify({ pubkey: ephInfo.pubkey, alpha, pi: ephOut.pi })).valid === true, 'ephemeral key still proves/verifies')

  // ── 4. beacon: genesis + chaining (pure VrfBeacon) ───────────────────────────
  console.log('\n── beacon chaining ──')
  const seed = '42'.repeat(32)
  const beaconPub = toHex(publicKey(seed))
  const proveFn = (a) => prove(seed, a)
  const beacon = new VrfBeacon({ proveFn, pubkey: beaconPub, domain: DEFAULT_DOMAIN, retain: 100 })

  // genesis must be publicly derivable
  const genHex = toHex(computeGenesisBeta(DEFAULT_DOMAIN, beaconPub))
  assert(beacon.genesis().beta === genHex, 'genesis beta = SHA-512(domain || pubkey)')

  const r1 = beacon.advance()
  const r2 = beacon.advance()
  const r3 = beacon.advance()
  assert(r1.round === 1 && r2.round === 2 && r3.round === 3, 'rounds increment monotonically')
  assert(r1.prevBeta === genHex, 'round 1 links to genesis')
  assert(r2.prevBeta === r1.beta && r3.prevBeta === r2.beta, 'each round links to the previous beta')
  // alpha is exactly prevBeta || uint64_le(round)
  assert(r2.alpha === toHex(beaconAlpha(b4a.from(r1.beta, 'hex'), 2)), 'alpha = prevBeta || round_le')
  // round output is the VRF hash of its alpha (unbiasable)
  assert(r2.beta === toHex(proofToHash(b4a.from(r2.pi, 'hex'))), 'beta = proofToHash(pi)')
  assert(verify(beaconPub, r2.alpha, r2.pi) === true, 'each round proof verifies under the beacon key')

  // deterministic replay: a fresh beacon with the same key + genesis reproduces the chain
  const beaconReplay = new VrfBeacon({ proveFn, pubkey: beaconPub, domain: DEFAULT_DOMAIN })
  const rr1 = beaconReplay.advance(); const rr2 = beaconReplay.advance(); const rr3 = beaconReplay.advance()
  assert(rr1.beta === r1.beta && rr2.beta === r2.beta && rr3.beta === r3.beta, 'chain is deterministic (operator cannot bias it)')

  // ── 5. third-party chain verification ────────────────────────────────────────
  console.log('\n── chain verification ──')
  const records = beacon.range(3)
  const chain = verifyBeaconChain({ pubkey: beaconPub, domain: DEFAULT_DOMAIN, records })
  assert(chain.valid === true && chain.checked === 3, 'verifyBeaconChain accepts an honest 3-round chain')

  // tamper a beta → broken link + beta mismatch detected
  const bad = records.map(r => ({ ...r }))
  bad[1] = { ...bad[1], beta: bad[1].beta.slice(0, -2) + (bad[1].beta.endsWith('00') ? '01' : '00') }
  const badResult = verifyBeaconChain({ pubkey: beaconPub, domain: DEFAULT_DOMAIN, records: bad })
  assert(badResult.valid === false && badResult.failures.length > 0, 'verifyBeaconChain rejects a tampered chain')

  // wrong domain ⇒ round-1 genesis link breaks
  const wrongDomain = verifyBeaconChain({ pubkey: beaconPub, domain: 'wrong/domain', records })
  assert(wrongDomain.valid === false, 'verifyBeaconChain rejects a wrong domain (genesis mismatch)')

  // ── 6. retention ring buffer ─────────────────────────────────────────────────
  console.log('\n── retention ──')
  const small = new VrfBeacon({ proveFn, pubkey: beaconPub, retain: 5 })
  for (let i = 0; i < 20; i++) small.advance()
  assert(small.currentRound === 20, 'currentRound tracks total advances')
  assert(small.range(1000).length === 5, 'retain caps in-memory history')
  assert(small.round(1) === null, 'evicted round is no longer retained')
  assert(small.round(20) !== null && small.latest().round === 20, 'most recent rounds are retained')

  // ── 7. service beacon RPC ────────────────────────────────────────────────────
  console.log('\n── service beacon RPC ──')
  const bsvc = new VRFService({ keyPair: kp, beacon: { enabled: true, intervalMs: 60_000, retain: 50 } })
  await bsvc.start({ node: null })
  // advance a few rounds deterministically (don't wait on the timer)
  bsvc.beacon.advance(); bsvc.beacon.advance(); bsvc.beacon.advance()
  const bi = await bsvc['beacon-info']()
  assert(bi.suite === 'ECVRF-EDWARDS25519-SHA512-TAI', 'beacon-info reports the suite')
  assert(bi.genesis.round === 0, 'beacon-info includes genesis')
  const latest = await bsvc['beacon-latest']()
  assert(latest.round >= 3, 'beacon-latest returns the newest round')
  const round2 = await bsvc['beacon-round']({ round: 2 })
  assert(round2.round === 2, 'beacon-round fetches a specific round')
  const rng = await bsvc['beacon-range']({ count: 2 })
  assert(rng.records.length === 2, 'beacon-range returns the requested count')
  const bv = await bsvc['beacon-verify']({})
  assert(bv.valid === true, 'beacon-verify validates the retained chain')
  await rejects(() => bsvc['beacon-round']({ round: -1 }), 'beacon-round rejects negative round')
  await bsvc.stop()

  // beacon disabled by default
  const noBeacon = new VRFService({ keyPair: kp })
  await noBeacon.start({ node: null })
  await rejects(() => noBeacon['beacon-latest'](), 'beacon RPC throws when beacon disabled')
  assert((await noBeacon.info()).beacon.enabled === false, 'info reports beacon disabled')

  // ── 8. sortition RPC: select (committee) ─────────────────────────────────────
  console.log('\n── select (committee sortition) ──')
  const pool = ['aa', 'bb', 'cc', 'dd', 'ee', 'ff', '11', '22']
  const ctx = '6469737075746531' // "dispute1" as hex — binds the draw to a context
  const sel = await svc.select({ alpha: ctx, candidates: pool, count: 3 })
  assert(sel.committee.length === 3 && new Set(sel.committee).size === 3, 'select draws a distinct committee of the requested size')
  assert(sel.committee.every(id => pool.includes(id)), 'committee members come from the pool')
  assert(sel.pi.length === 160 && sel.beta.length === 128, 'select returns a full proof + beta')
  assert(verify(pk1, ctx, sel.pi) === true, 'select proof verifies under the relay VRF key')

  // The committee is exactly what an independent party computes from beta.
  const betaBytes = proofToHash(b4a.from(sel.pi, 'hex'))
  const independent = weightedSample({ seed: betaBytes, candidates: pool, count: 3 })
  assert(JSON.stringify(independent) === JSON.stringify(sel.committee), 'committee is the deterministic sortition of beta (third-party reproducible)')

  // determinism: same context ⇒ same committee
  const sel2 = await svc.select({ alpha: ctx, candidates: pool, count: 3 })
  assert(JSON.stringify(sel2.committee) === JSON.stringify(sel.committee), 'select is deterministic for the same (key, alpha, candidates)')
  // different context ⇒ (almost surely) different draw / proof
  const selOther = await svc.select({ alpha: '6469737075746532', candidates: pool, count: 3 })
  assert(selOther.pi !== sel.pi, 'a different context yields a different proof')

  // weighted select stays within positive-weight candidates
  const wcands = [{ id: 'big', weight: 100 }, { id: 'mid', weight: 10 }, { id: 'low', weight: 1 }, { id: 'none', weight: 0 }]
  const wsel = await svc.select({ alpha: ctx, candidates: wcands, count: 3, weighted: true })
  assert(wsel.committee.length === 3 && !wsel.committee.includes('none'), 'weighted select never draws a zero-weight candidate')
  assert(wsel.weighted === true, 'select echoes the weighted flag')

  await rejects(() => svc.select({ candidates: pool, count: 3 }), 'select without alpha throws')
  await rejects(() => svc.select({ alpha: ctx, candidates: 'nope', count: 3 }), 'select with non-array candidates throws')
  await rejects(() => svc.select({ alpha: ctx, candidates: [{ id: 'x', weight: 1.5 }], count: 1, weighted: true }), 'weighted select rejects non-integer weights')

  // ── 9. select-verify ─────────────────────────────────────────────────────────
  console.log('\n── select-verify ──')
  const sv = await svc['select-verify']({ pubkey: pk1, alpha: ctx, pi: sel.pi, candidates: pool, count: 3, committee: sel.committee })
  assert(sv.valid === true && sv.vrfValid && sv.committeeValid, 'select-verify accepts an honest committee')
  const svTamper = await svc['select-verify']({ pubkey: pk1, alpha: ctx, pi: sel.pi, candidates: pool, count: 3, committee: sel.committee.slice().reverse() })
  assert(svTamper.valid === false && svTamper.vrfValid === true && svTamper.committeeValid === false, 'select-verify catches a reordered committee')
  const svWrongKey = await svc['select-verify']({ pubkey: toHex(publicKey('11'.repeat(32))), alpha: ctx, pi: sel.pi, candidates: pool, count: 3, committee: sel.committee })
  assert(svWrongKey.valid === false && svWrongKey.vrfValid === false, 'select-verify rejects a wrong VRF pubkey')

  // ── 10. shuffle + shuffle-verify ─────────────────────────────────────────────
  console.log('\n── shuffle ──')
  const items = Array.from({ length: 12 }, (_, i) => i)
  const sh = await svc.shuffle({ alpha: ctx, items })
  assert(sh.order.length === 12 && new Set(sh.order).size === 12, 'shuffle returns a full permutation')
  assert(JSON.stringify(sh.order.slice().sort((a, b) => a - b)) === JSON.stringify(items), 'shuffle preserves the multiset')
  const shBeta = proofToHash(b4a.from(sh.pi, 'hex'))
  assert(JSON.stringify(seededShuffle(shBeta, items)) === JSON.stringify(sh.order), 'shuffle order is the deterministic sortition of beta')
  const shv = await svc['shuffle-verify']({ pubkey: pk1, alpha: ctx, pi: sh.pi, items, order: sh.order })
  assert(shv.valid === true && shv.orderValid, 'shuffle-verify accepts an honest order')
  const shvBad = await svc['shuffle-verify']({ pubkey: pk1, alpha: ctx, pi: sh.pi, items, order: items })
  assert(shvBad.valid === false && shvBad.orderValid === false, 'shuffle-verify catches a wrong order')
  await rejects(() => svc.shuffle({ alpha: ctx, items: 'nope' }), 'shuffle with non-array items throws')

  console.log(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed === 0 ? 0 : 1)
}

main().catch(err => { console.error(err); process.exit(1) })
