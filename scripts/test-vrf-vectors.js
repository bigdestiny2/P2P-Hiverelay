#!/usr/bin/env node

/**
 * test-vrf-vectors.js
 *
 * The correctness gate for the ECVRF implementation: byte-exact validation
 * against the official RFC 9381 Appendix A.4 test vectors for
 * ECVRF-EDWARDS25519-SHA512-TAI (suite 0x03). These are the three canonical
 * examples published in the RFC.
 *
 * For each vector we assert:
 *   - publicKey(SK) == PK
 *   - prove(SK, alpha) == pi          (byte-exact, deterministic)
 *   - proofToHash(pi) == beta         (byte-exact)
 *   - verify(PK, alpha, pi) == true   (the honest proof verifies)
 *   - verify rejects: tampered pi, wrong alpha, wrong PK
 *
 * A subtly-wrong VRF is worse than no VRF, so this must be 100% green before
 * anything (poker shuffles, arbitrator selection, the beacon) is allowed to
 * depend on it.
 */

import {
  prove, verify, proofToHash, publicKey, verifyAndHash, toHex, params
} from '../packages/services/builtin/vrf/ecvrf.js'

let passed = 0
let failed = 0

function assert (condition, label) {
  if (condition) { console.log(`  PASS  ${label}`); passed++ } else { console.log(`  FAIL  ${label}`); failed++ }
}

function hexEq (got, want, label) {
  const g = got instanceof Uint8Array ? toHex(got) : got
  assert(g === want, `${label}\n          got:  ${g}\n          want: ${want}`)
}

// ── RFC 9381 Appendix A.4 vectors ────────────────────────────────────────────
const VECTORS = [
  {
    name: 'Example 16 (empty alpha)',
    sk: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    pk: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    alpha: '',
    pi: '8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805',
    beta: '90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae'
  },
  {
    name: 'Example 17 (alpha=0x72)',
    sk: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
    pk: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
    alpha: '72',
    pi: 'f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02',
    beta: 'eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031'
  },
  {
    name: 'Example 18 (alpha=0xaf82)',
    sk: 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
    pk: 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
    alpha: 'af82',
    pi: '9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e',
    beta: '645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f'
  }
]

console.log(`\nECVRF suite: ${params.suite}  (pi=${params.proofLen}B, beta=${params.betaLen}B)\n`)

for (const v of VECTORS) {
  console.log(`── ${v.name} ──`)
  hexEq(publicKey(v.sk), v.pk, 'publicKey(SK) == PK')

  const pi = prove(v.sk, v.alpha)
  hexEq(pi, v.pi, 'prove(SK, alpha) == pi')

  const beta = proofToHash(pi)
  hexEq(beta, v.beta, 'proofToHash(pi) == beta')

  assert(verify(v.pk, v.alpha, v.pi) === true, 'verify(PK, alpha, pi) == true')

  const vh = verifyAndHash(v.pk, v.alpha, v.pi)
  assert(vh.valid === true && toHex(vh.beta) === v.beta, 'verifyAndHash returns valid + correct beta')

  // ── negative cases ──
  const tampered = v.pi.slice(0, -2) + (v.pi.endsWith('00') ? '01' : '00')
  assert(verify(v.pk, v.alpha, tampered) === false, 'verify rejects tampered pi')

  const wrongAlpha = (v.alpha === '' ? '00' : v.alpha + '00')
  assert(verify(v.pk, wrongAlpha, v.pi) === false, 'verify rejects wrong alpha')

  const otherPk = VECTORS[(VECTORS.indexOf(v) + 1) % VECTORS.length].pk
  assert(verify(otherPk, v.alpha, v.pi) === false, 'verify rejects wrong public key')

  // malformed inputs must not throw, just return false
  let threw = false
  try { verify(v.pk, v.alpha, 'zz') } catch { threw = true }
  assert(threw === false, 'verify(malformed proof) returns false without throwing')

  console.log('')
}

// ── determinism + cross-check: a freshly proven message verifies & is stable ──
console.log('── determinism / round-trip ──')
{
  const sk = VECTORS[0].sk
  const alpha = 'deadbeefcafe'
  const pi1 = toHex(prove(sk, alpha))
  const pi2 = toHex(prove(sk, alpha))
  assert(pi1 === pi2, 'prove is deterministic for the same (SK, alpha)')
  const pk = publicKey(sk)
  assert(verify(pk, alpha, pi1) === true, 'self-generated proof verifies')
  assert(verify(pk, 'deadbeefcaff', pi1) === false, 'proof does not verify for a different alpha')
}

console.log(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed === 0 ? 0 : 1)
