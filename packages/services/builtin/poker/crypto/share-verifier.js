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
 *       // G is fixed to the canonical ed25519 base point. A redundant
 *       // canonical encoding is accepted; any other value is inconclusive.
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
 * The verifier does not perform network or log lookups. Instead, evidence
 * must carry the respondent-signed share entry and respondent-signed DKG
 * round-2 publisher-key entry. It verifies both signatures and binds their
 * payloads to the contextual proof before evaluating the equations.
 */

import sodium from 'sodium-universal'
import b4a from 'b4a'
import { SignedLog } from '../signed-log.js'
import {
  verifyShareEquality,
  canonicalShareContext,
  baseG,
  POINT_BYTES,
  SCALAR_BYTES
} from './chaum-pedersen.js'

/**
 * Build a verifier function suitable for
 * `arbitration.setAppEvidenceVerifier('poker/invalid-share', fn)`.
 *
 * @param {object} [opts] Reserved for future transcript extensions.
 * @returns {(ae: object) => { verdict: string, reason: string }}
 */
export function makeInvalidShareVerifier (_opts = {}) {
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
    let context
    try {
      context = canonicalShareContext(witness.context)
    } catch (error) {
      return { verdict: 'inconclusive', reason: 'bad-context:' + error.message }
    }
    // This protocol fixes G to the ed25519 base point. G is claimant-controlled
    // and is not part of either respondent-signed entry, so accepting an
    // alternate value would let a claimant change the Fiat-Shamir challenge
    // and turn a valid proof into a slashable verification failure. Preserve
    // compatibility with clients that redundantly serialize the canonical G.
    if (witness.G !== undefined) {
      const suppliedG = hexBuf(witness.G, POINT_BYTES)
      if (!suppliedG) return { verdict: 'inconclusive', reason: 'G-bad-hex' }
      if (!b4a.equals(suppliedG, baseG())) {
        return { verdict: 'inconclusive', reason: 'noncanonical-generator' }
      }
    }

    for (const [name, val] of [['C1', C1], ['D', D], ['Y', Y], ['A', A], ['B', B], ['z', z]]) {
      if (!val) return { verdict: 'inconclusive', reason: 'bad-hex:' + name }
    }

    // Bind the accusation and public key to entries actually signed by the
    // respondent. Without these checks a claimant can substitute an arbitrary
    // writer/key/proof tuple and make a valid share appear invalid.
    const provenance = verifyProvenance(ae, context)
    if (!provenance.ok) return { verdict: 'inconclusive', reason: provenance.reason }

    const r = verifyShareEquality({ Y, C1, D, A, B, z, context })

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

function verifyProvenance (ae, context) {
  if (!isHex64(ae && ae.respondent)) return { ok: false, reason: 'respondent-missing' }
  const respondent = ae.respondent.toLowerCase()
  if (b4a.toString(context.writer, 'hex') !== respondent) return { ok: false, reason: 'context-writer-mismatch' }
  if (b4a.toString(context.tableKey, 'hex') !== String(ae.tableKey || '').toLowerCase()) return { ok: false, reason: 'context-table-mismatch' }
  if (String(context.hand) !== ae.handId || context.cardIndex !== ae.cardIndex) return { ok: false, reason: 'context-position-mismatch' }

  const shareEntry = ae.signedEntry
  if (!verifySignedEntry(shareEntry, respondent)) return { ok: false, reason: 'share-entry-signature' }
  const payload = shareEntry.payload
  if (String(shareEntry.tableKey || '').toLowerCase() !== String(ae.tableKey || '').toLowerCase() ||
      payload?.protocolVersion !== context.protocolVersion || payload?.kind !== context.proofKind ||
      payload?.hand !== context.hand || payload?.cardIdx !== context.cardIndex ||
      String(payload?.C1 || '').toLowerCase() !== String(ae.ciphertext || '').toLowerCase() ||
      String(payload?.D || '').toLowerCase() !== String(ae.share || '').toLowerCase() ||
      !sameProof(payload?.proof, ae.witness?.proof)) {
    return { ok: false, reason: 'share-entry-payload' }
  }
  const recipient = context.recipientSeat
  if (recipient == null ? payload.recipientSeat != null : payload.recipientSeat !== recipient) {
    return { ok: false, reason: 'share-entry-recipient' }
  }

  const keyEntry = ae.publisherKeyEntry
  if (!verifySignedEntry(keyEntry, respondent)) return { ok: false, reason: 'key-entry-signature' }
  const keyPayload = keyEntry.payload
  if (String(keyEntry.tableKey || '').toLowerCase() !== String(ae.tableKey || '').toLowerCase() ||
      keyPayload?.protocolVersion !== context.protocolVersion || keyPayload?.kind !== 'dkg-commit' ||
      keyPayload?.round !== 2 || keyPayload?.hand !== context.hand ||
      String(keyPayload?.X || '').toLowerCase() !== String(ae.witness?.Y || '').toLowerCase()) {
    return { ok: false, reason: 'key-entry-payload' }
  }
  return { ok: true }
}

function verifySignedEntry (entry, writer) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry) ||
      String(entry.writer || '').toLowerCase() !== writer ||
      !isHex64(entry.tableKey) || !isHex128(entry.signature) ||
      !Number.isSafeInteger(entry.seq) || entry.seq < 0 ||
      typeof entry.ts !== 'number' || !Number.isFinite(entry.ts)) return false
  try {
    const signature = b4a.from(entry.signature, 'hex')
    const publicKey = b4a.from(writer, 'hex')
    return sodium.crypto_sign_verify_detached(signature, SignedLog.canonicalBytes(entry), publicKey)
  } catch {
    return false
  }
}

function sameProof (a, b) {
  return !!a && !!b && ['A', 'B', 'z'].every(key =>
    typeof a[key] === 'string' && typeof b[key] === 'string' && a[key].toLowerCase() === b[key].toLowerCase())
}

function isHex64 (value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/i.test(value)
}

function isHex128 (value) {
  return typeof value === 'string' && /^[0-9a-f]{128}$/i.test(value)
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
  try { return b4a.from(s, 'hex') } catch { return null }
}
