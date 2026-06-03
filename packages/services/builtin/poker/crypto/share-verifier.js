/**
 * Reference arbitration evidence verifier for `poker/invalid-share`.
 *
 * Adapts the Chaum-Pedersen primitive in ./chaum-pedersen.js to the
 * `appEvidence` shape defined by arbitration-service.js. Drop it into
 * the arbitration service at startup:
 *
 *   import { ArbitrationService } from 'p2p-hiveservices/builtin/arbitration-service.js'
 *   import { makeInvalidShareVerifier } from 'p2p-hiveservices/builtin/poker/crypto/share-verifier.js'
 *
 *   const arb = new ArbitrationService()
 *   arb.setAppEvidenceVerifier('poker/invalid-share', makeInvalidShareVerifier())
 *
 * The factory pattern lets callers later inject options (alternate Fiat-
 * Shamir transcripts, point-decoding hooks for other curves) without
 * changing the call site.
 *
 * ─── Evidence shape this verifier expects ──────────────────────────────────
 *
 * `appEvidence` for a poker/invalid-share dispute, as defined by
 * arbitration-service.js, plus the Chaum-Pedersen-specific witness fields:
 *
 *   {
 *     tableKey, handId, cardIndex,
 *     ciphertext: <hex>,     // C1 (32 bytes hex)
 *     share:      <hex>,     // D  (32 bytes hex)
 *     witness: {
 *       Y: <hex>,            // threshold public key (32 bytes hex)
 *       proof: {
 *         A: <hex>, B: <hex>, z: <hex>  // each 32 bytes hex
 *       }
 *       // G is implied as the ed25519 base point. Override by adding
 *       // `G: <hex>` here if a future scheme uses a different generator.
 *     }
 *   }
 *
 * ─── Verdict mapping ───────────────────────────────────────────────────────
 *
 * The dispute claim is "share X is invalid." So:
 *
 *   - Chaum-Pedersen verify PASSES → share is provably valid → claim REFUTED
 *   - Chaum-Pedersen verify FAILS  → share is provably invalid → claim SUPPORTED
 *   - Inputs malformed / hex decode fails / wrong byte lengths → INCONCLUSIVE
 *     (don't slash on procedural errors — let voters inspect manually)
 *
 * ─── What it does NOT do ───────────────────────────────────────────────────
 *
 * The verifier does NOT independently look up the proof on the table's
 * signed log to confirm the respondent actually published it. That's the
 * arbitrator's job — the witness here is taken at face value. A claimant
 * who fabricates a proof of validity (e.g. by re-running prove with the
 * correct x they don't actually know) cannot succeed: they'd need x, which
 * they don't have. A claimant who submits the WRONG proof and hopes the
 * verifier passes the wrong claim is what cross-referencing the signed
 * log catches.
 */

import b4a from 'b4a'
import { verifyShareEquality, POINT_BYTES, SCALAR_BYTES } from './chaum-pedersen.js'

/**
 * Build a verifier function suitable for
 * `arbitration.setAppEvidenceVerifier('poker/invalid-share', fn)`.
 *
 * @param {object} [opts] Reserved for future extensions (curve override,
 *   transcript domain, etc.).
 * @returns {(ae: object) => { verdict: string, reason: string }}
 */
export function makeInvalidShareVerifier (opts = {}) {
  void opts
  return function verifyInvalidShareEvidence (ae) {
    // Defensive decode. Each `hexBuf` call returns null on bad input;
    // we collect failures and short-circuit to inconclusive.
    const C1 = hexBuf(ae && ae.ciphertext, POINT_BYTES)
    const D = hexBuf(ae && ae.share, POINT_BYTES)
    const witness = ae && ae.witness
    if (!witness || typeof witness !== 'object') {
      return { verdict: 'inconclusive', reason: 'witness-missing' }
    }
    const Y = hexBuf(witness.Y, POINT_BYTES)
    const proof = witness.proof
    if (!proof || typeof proof !== 'object') {
      return { verdict: 'inconclusive', reason: 'witness.proof-missing' }
    }
    const A = hexBuf(proof.A, POINT_BYTES)
    const B = hexBuf(proof.B, POINT_BYTES)
    const z = hexBuf(proof.z, SCALAR_BYTES)
    // Optional G override; default to ed25519 base point in verifier.
    const G = witness.G ? hexBuf(witness.G, POINT_BYTES) : undefined
    if (witness.G && !G) {
      return { verdict: 'inconclusive', reason: 'G-bad-hex' }
    }

    for (const [name, val] of [['C1', C1], ['D', D], ['Y', Y], ['A', A], ['B', B], ['z', z]]) {
      if (!val) return { verdict: 'inconclusive', reason: 'bad-hex:' + name }
    }

    const r = verifyShareEquality({ G, Y, C1, D, A, B, z })

    if (r.valid) {
      // Proof verifies → share is valid → claimant's claim of invalidity
      // is refuted.
      return { verdict: 'claim-refuted', reason: 'proof-verifies' }
    }
    // Proof fails → share is invalid → claim that share is invalid is
    // supported. Include the underlying reason for the operator log.
    return { verdict: 'claim-supported', reason: 'proof-fails:' + (r.reason || 'unknown') }
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Decode a hex string to a Buffer of expected byte length. Returns null
 * on any failure (not a string / wrong length / bad chars). We deliberately
 * never throw — the wrapping verifier converts null into 'inconclusive'.
 */
function hexBuf (s, expectedBytes) {
  if (typeof s !== 'string') return null
  if (s.length !== expectedBytes * 2) return null
  if (!/^[0-9a-f]+$/i.test(s)) return null
  try { return b4a.from(s, 'hex') }
  catch { return null }
}
