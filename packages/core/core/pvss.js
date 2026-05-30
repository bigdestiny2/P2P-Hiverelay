/**
 * PVSS primitives — Publicly Verifiable Secret Sharing over secp256k1.
 *
 * Single source of truth for the Schoenmakers-style PVSS verification
 * transcript, shared by:
 *   - the dealer/shareholder side (the client SDK prover at
 *     packages/client/secret-sharing.js: split / decryptShare /
 *     reconstruct — runs wherever the secret lives, never on a relay), and
 *   - the relay side (verify-only): a relay custodying an encrypted share
 *     can publicly confirm it is consistent with the published commitments
 *     WITHOUT any secret key.
 *
 * Keeping prove + verify in one module is deliberate: the Fiat-Shamir
 * challenge is computed identically by both, so the two sides can never
 * drift apart over a transcript-ordering change. Core already depends on
 * @noble/secp256k1 + sodium-universal, so this adds no new dependency and
 * stays Bare-compatible (no Node `crypto`/`Buffer`).
 *
 * Two independent generators are essential. The recoverable secret lives
 * under the base point G (S = s*G); Feldman commitments live under a
 * separate nothing-up-my-sleeve generator C_GEN. One generator would
 * publish C_0 = G^s == S and destroy confidentiality; with two, recovering
 * S = G^s from public data is DDH-hard. PVSS confidentiality is therefore
 * COMPUTATIONAL (rests on DDH), the standard tradeoff for public
 * verifiability.
 */

import * as secp from '@noble/secp256k1'
import { sha256 } from '@noble/hashes/sha2.js'
import { hmac } from '@noble/hashes/hmac.js'
import sodium from 'sodium-universal'
import b4a from 'b4a'

// Wire noble hashes (required by @noble/secp256k1 v2+ for any ECDSA path).
// Guarded so it is a no-op when another module already wired the same
// module instance (e.g. zk-service.js). PVSS itself only needs EC point
// arithmetic + BLAKE2b challenges, but we wire it for safety/parity.
if (!secp.hashes.sha256) {
  secp.hashes.sha256 = (...msgs) => sha256(secp.etc.concatBytes(...msgs.filter(m => m != null)))
  secp.hashes.hmacSha256 = (key, ...msgs) => hmac(sha256, key, secp.etc.concatBytes(...msgs.filter(m => m != null)))
}

// ─── Constants ──────────────────────────────────────────────────────

export const G = secp.Point.BASE // secret generator: S = s*G
export const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n

// Independent commitment generator (nothing-up-my-sleeve, distinct seed
// from zk-service's Pedersen H so the two protocols never interact).
export const C_GEN = hashToCurveSimple('hiverelay-pvss-commit-generator-v1')

export const KEY_DOMAIN = 'hiverelay-pvss-key-v1:'
export const MAX_SHARES = 255

// ─── Field / curve helpers ──────────────────────────────────────────

export function modN (n) {
  return ((n % N) + N) % N
}

export function randomScalar () {
  const buf = b4a.alloc(32)
  let s
  do {
    sodium.randombytes_buf(buf)
    s = modN(secp.etc.bytesToNumberBE(buf))
  } while (s === 0n)
  return s
}

export function scalarToHex (s) {
  return s.toString(16).padStart(64, '0')
}

export function hexToScalar (h) {
  return BigInt('0x' + h)
}

export function pointToHex (P) {
  return P.toHex(true)
}

export function hexToPoint (h) {
  return secp.Point.fromHex(h)
}

/** Modular inverse mod N via the iterative extended Euclidean algorithm. */
export function invN (a) {
  const x = modN(a)
  if (x === 0n) throw new Error('SS_NOT_INVERTIBLE')
  let lm = 1n
  let hm = 0n
  let low = x
  let high = N
  while (low > 1n) {
    const ratio = high / low
    const nm = hm - lm * ratio
    const nw = high - low * ratio
    hm = lm
    high = low
    lm = nm
    low = nw
  }
  return modN(lm)
}

/** Hash arbitrary buffers/hex parts to a scalar mod N using BLAKE2b. */
export function hashToScalar (...parts) {
  const input = b4a.concat(parts.map(p => typeof p === 'string' ? b4a.from(p, 'hex') : b4a.from(p)))
  const hash = b4a.alloc(32)
  sodium.crypto_generichash(hash, input)
  return modN(secp.etc.bytesToNumberBE(hash))
}

/** Find a valid secp256k1 point from a seed string (nothing-up-my-sleeve). */
export function hashToCurveSimple (seed) {
  for (let counter = 0; counter < 256; counter++) {
    const input = b4a.from(seed + ':' + counter)
    const hash = b4a.alloc(32)
    sodium.crypto_generichash(hash, input)
    const compressed = b4a.concat([b4a.from([0x02]), hash])
    try {
      return secp.Point.fromHex(b4a.toString(compressed, 'hex'))
    } catch {
      continue
    }
  }
  throw new Error('hashToCurveSimple failed after 256 attempts')
}

/** Evaluate polynomial (coeffs[0] is the constant term) at x, mod N. */
export function polyEval (coeffs, x) {
  let acc = 0n
  for (let j = coeffs.length - 1; j >= 0; j--) acc = modN(acc * x + coeffs[j])
  return acc
}

/**
 * Lagrange coefficients evaluated at x = 0 for the given index set.
 * λ_i = Π_{j≠i} (0 - x_j) / (x_i - x_j)   (mod N)
 * Returns a Map of indexBigInt → λ.
 */
export function lagrangeAtZero (indices) {
  const out = new Map()
  for (const i of indices) {
    let num = 1n
    let den = 1n
    for (const j of indices) {
      if (j === i) continue
      num = modN(num * modN(-j))
      den = modN(den * modN(i - j))
    }
    out.set(i, modN(num * invN(den)))
  }
  return out
}

/** Derive a 32-byte symmetric key from the recovered secret point. */
export function deriveKey (S) {
  const buf = b4a.alloc(32)
  sodium.crypto_generichash(buf, b4a.from(KEY_DOMAIN + pointToHex(S)))
  return b4a.toString(buf, 'hex')
}

// ─── DLEQ (discrete-log equality) ───────────────────────────────────

/**
 * Prove log_{base1}(A) == log_{base2}(B) == x, without revealing x.
 * Fiat-Shamir, challenge over (base1, A, base2, B, R1, R2).
 *
 * DEALER/SHAREHOLDER side only — a relay never calls this. It lives here
 * so prover and verifier share one challenge construction.
 */
export function proveDleq (base1, A, base2, B, x) {
  const k = randomScalar()
  const R1 = base1.multiply(k)
  const R2 = base2.multiply(k)
  const e = hashToScalar(
    pointToHex(base1), pointToHex(A),
    pointToHex(base2), pointToHex(B),
    pointToHex(R1), pointToHex(R2)
  )
  const s = modN(k - e * x)
  return { e: scalarToHex(e), s: scalarToHex(s) }
}

export function verifyDleq (base1, A, base2, B, proof) {
  try {
    if (!proof || typeof proof.e !== 'string' || typeof proof.s !== 'string') return false
    const e = hexToScalar(proof.e)
    const s = hexToScalar(proof.s)
    const sOrN = s === 0n ? N : s
    const R1 = base1.multiply(sOrN).add(A.multiply(e))
    const R2 = base2.multiply(sOrN).add(B.multiply(e))
    const e2 = hashToScalar(
      pointToHex(base1), pointToHex(A),
      pointToHex(base2), pointToHex(B),
      pointToHex(R1), pointToHex(R2)
    )
    return e === e2
  } catch {
    return false
  }
}

// ─── Commitment math ────────────────────────────────────────────────

/** Recompute X_i = Π_j C_j^(i^j) = C_GEN^p(i) from parsed commitment points. */
export function commitmentShare (commitmentPoints, index) {
  const x = BigInt(index)
  let acc = null
  let xPow = 1n // x^0
  for (const Cj of commitmentPoints) {
    const term = Cj.multiply(modN(xPow) === 0n ? N : modN(xPow))
    acc = acc === null ? term : acc.add(term)
    xPow = modN(xPow * x)
  }
  return acc
}

/** BLAKE2b over the concatenation of commitment hexes → 64-hex anchor. */
export function commitmentRootOf (commitments) {
  const buf = b4a.alloc(32)
  sodium.crypto_generichash(buf, b4a.from(commitments.join('')))
  return b4a.toString(buf, 'hex')
}

/** Per-share commitment X_i as compressed hex, from commitment hexes. */
export function shareCommitmentAt (commitments, index) {
  const points = commitments.map(hexToPoint)
  return pointToHex(commitmentShare(points, index))
}

// ─── Relay-side public verification (no secret keys) ────────────────

/**
 * Verify a single encrypted share against the published commitments.
 * RELAY-SAFE: no secret key, no decryption. Recomputes X_i from the
 * commitments and checks the DLEQ binding X_i (under C_GEN) to the
 * encrypted share Y_i (under the recipient pubkey y_i).
 *
 * @param {string[]} commitments — Feldman commitment hexes
 * @param {{index:number,shareholder:string,encryptedShare:string,proof:object}} share
 * @returns {boolean}
 */
export function verifyEncryptedShare (commitments, share) {
  if (!Array.isArray(commitments) || commitments.length < 1) return false
  if (!share || !Number.isInteger(share.index) || share.index < 1) return false
  try {
    const points = commitments.map(hexToPoint)
    const Xi = commitmentShare(points, share.index)
    const yi = hexToPoint(share.shareholder)
    const Yi = hexToPoint(share.encryptedShare)
    return verifyDleq(C_GEN, Xi, yi, Yi, share.proof)
  } catch {
    return false
  }
}

/**
 * Verify a decrypted share's correctness proof. RELAY-SAFE.
 * Checks the DLEQ that Y_i = x_i * S_i (the shareholder decrypted honestly).
 *
 * @param {{share:string,shareholder:string,encryptedShare:string,proof:object}} decrypted
 * @returns {boolean}
 */
export function verifyDecryptedShare (decrypted) {
  if (!decrypted) return false
  try {
    const Si = hexToPoint(decrypted.share)
    const yi = hexToPoint(decrypted.shareholder)
    const Yi = hexToPoint(decrypted.encryptedShare)
    return verifyDleq(G, yi, Si, Yi, decrypted.proof)
  } catch {
    return false
  }
}

/**
 * Decide whether THIS relay holds a verifiable PVSS share for a v2 custody
 * intent, given the public share bundle replicated under intent.shareBundleKey.
 * RELAY-SAFE: pure, no secret key, no network. Returns the receipt's PVSS
 * fields on success, or a structured failure `reason` the caller surfaces as a
 * `custody:share-verify-failed` event (SD2: a failed verify must NOT anchor).
 *
 * The bundle is the `public` half of a client split:
 *   { commitments: string[], encryptedShares: [{index, shareholder,
 *     encryptedShare, proof}, ...] }
 *
 * Order of checks is defensive: establish the relay is actually assigned a
 * share before trusting any bundle bytes, then pin the bundle's commitment
 * vector to the publisher-signed commitmentRoot (so a swapped-but-internally-
 * consistent bundle can't pass), then verify the specific encrypted share.
 *
 * @param {object} intent normalized v2 custody-intent (shareScheme,
 *   commitmentRoot, shareAssignments)
 * @param {object} bundle replicated public share bundle
 * @param {string} relayPubkey this relay's pubkey hex (matches shareAssignments)
 * @returns {{ok:true, shareScheme:string, commitmentRoot:string,
 *   shareIndex:number, shareCommitment:string} | {ok:false, reason:string}}
 */
export function verifyShareBundleForRelay (intent, bundle, relayPubkey) {
  if (!intent || !intent.shareScheme) return { ok: false, reason: 'intent-not-pvss' }
  if (!Array.isArray(intent.shareAssignments)) return { ok: false, reason: 'intent-missing-assignments' }
  const assigned = intent.shareAssignments.find(a => a && a.relayPubkey === relayPubkey)
  if (!assigned) return { ok: false, reason: 'relay-not-assigned' }
  if (!bundle || !Array.isArray(bundle.commitments) || !Array.isArray(bundle.encryptedShares)) {
    return { ok: false, reason: 'bundle-malformed' }
  }
  // The replicated commitment vector must be the one the publisher signed into
  // the intent — otherwise a tampered-but-self-consistent bundle could pass.
  let root
  try {
    root = commitmentRootOf(bundle.commitments)
  } catch {
    return { ok: false, reason: 'bundle-malformed' }
  }
  if (root !== intent.commitmentRoot) return { ok: false, reason: 'commitmentRoot-mismatch' }
  const share = bundle.encryptedShares.find(s => s && s.index === assigned.shareIndex)
  if (!share) return { ok: false, reason: 'share-missing' }
  if (!verifyEncryptedShare(bundle.commitments, share)) return { ok: false, reason: 'share-verify-failed' }
  let shareCommitment
  try {
    shareCommitment = shareCommitmentAt(bundle.commitments, assigned.shareIndex)
  } catch {
    return { ok: false, reason: 'bundle-malformed' }
  }
  return {
    ok: true,
    shareScheme: intent.shareScheme,
    commitmentRoot: intent.commitmentRoot,
    shareIndex: assigned.shareIndex,
    shareCommitment
  }
}
