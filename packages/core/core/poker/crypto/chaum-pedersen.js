/**
 * Chaum-Pedersen discrete-log equality proof for threshold ElGamal share
 * validation, over the ed25519 curve.
 *
 * ─── Why this exists ────────────────────────────────────────────────────────
 *
 * The poker substrate registers application-level dispute types with the
 * arbitration service (see arbitration-service.js: `poker/invalid-share`).
 * To resolve those disputes an arbitrator must independently re-check the
 * cryptographic claim. This module provides the math for one of those
 * checks — "the published decryption share D = C1 ^ x where x is the same
 * secret as in the threshold public key Y = G ^ x" — without revealing x.
 *
 * Mathematically:
 *
 *   Setup:
 *     - G: a fixed generator of the ed25519 group
 *     - Threshold public key Y = G^x, where x is held in shares by N players
 *     - Ciphertext part C1 (the "r" component of an ElGamal pair (C1, C2))
 *
 *   Claim:
 *     - Player publishes D = C1^x and a proof showing log_G(Y) == log_C1(D)
 *
 *   Sigma protocol (Fiat-Shamir):
 *     1. Prover picks random k. Computes A = G^k, B = C1^k.
 *     2. Challenge e = H(G || Y || C1 || D || A || B).
 *     3. Response z = k + e*x  (mod the ed25519 group order ℓ).
 *
 *   Verification:
 *     - e' = H(G || Y || C1 || D || A || B)    (recompute, must equal e)
 *     - G^z  == A + Y^e        (point addition; non-multiplicative notation)
 *     - C1^z == B + D^e
 *
 * If both equations hold, the proof attests to validity of the share.
 *
 * ─── Status ─────────────────────────────────────────────────────────────────
 *
 * **Reference implementation.** Self-consistent — prover and verifier here
 * agree on byte ordering, hash domain, and curve choice — but NOT audited
 * for production stake. Real-money deployments should:
 *   1. Cross-verify against an independently-implemented prover for the
 *      same scheme (RFC 9497, libsignal, noble-curves, ...).
 *   2. Consider a curve with a prime-order group (ristretto255) if the
 *      threshold key generation depends on subgroup structure — ed25519's
 *      cofactor of 8 can be an issue for some DKG protocols.
 *
 * Operators who have an audited verifier for their actual production
 * scheme should register it via `arbitration.setAppEvidenceVerifier(
 * 'poker/invalid-share', fn)` and ignore this reference impl.
 *
 * ─── Byte ordering ─────────────────────────────────────────────────────────
 *
 * Sodium uses little-endian for ed25519 scalars. We follow the same
 * convention everywhere in this module. Points are 32 bytes in the standard
 * compressed Edwards encoding.
 */

import sodium from 'sodium-universal'
import b4a from 'b4a'

// ed25519 group order ℓ = 2^252 + 27742317777372353535851937790883648493.
// Sourced from RFC 8032 §5.1. Used here as the modulus for scalar
// arithmetic. The constant is BigInt at module load so we don't recompute
// it on every operation.
const ED25519_ORDER = 7237005577332262213973186563042994240857116359379907606001950938285454250989n

// Domain separator for the Fiat-Shamir hash. Any change to this string
// rotates all prior proofs out of validity, so DO NOT change it without a
// version bump in the evidence shape — proofs in the wild would silently
// stop verifying.
const FS_DOMAIN = 'hiverelay/poker/chaum-pedersen/v1'

const POINT_BYTES = 32
const SCALAR_BYTES = 32
const HASH_BYTES = 64 // we hash into 64 bytes then reduce mod ℓ

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Verify a Chaum-Pedersen proof of share equality.
 *
 * @param {object} args
 * @param {Buffer} args.G   Generator (32 bytes). Default: ed25519 base point.
 * @param {Buffer} args.Y   Threshold public key (32 bytes).
 * @param {Buffer} args.C1  Ciphertext "r" component (32 bytes).
 * @param {Buffer} args.D   Published decryption share (32 bytes).
 * @param {Buffer} args.A   Proof commitment A = G^k (32 bytes).
 * @param {Buffer} args.B   Proof commitment B = C1^k (32 bytes).
 * @param {Buffer} args.z   Proof response z = k + e*x (32 bytes, scalar).
 * @returns {{ valid: boolean, reason?: string }}
 */
export function verifyShareEquality (args) {
  const G = args.G || baseG()
  const { Y, C1, D, A, B, z } = args

  // Shape checks — return reason strings rather than throwing so the
  // arbitration verifier can map them to 'inconclusive' verdicts cleanly.
  for (const [name, val] of [['Y', Y], ['C1', C1], ['D', D], ['A', A], ['B', B], ['G', G]]) {
    if (!val || val.byteLength !== POINT_BYTES) return { valid: false, reason: 'bad-point:' + name }
  }
  if (!z || z.byteLength !== SCALAR_BYTES) return { valid: false, reason: 'bad-scalar:z' }

  // Recompute challenge e' = H(G || Y || C1 || D || A || B), reduce mod ℓ.
  const e = fsChallenge(G, Y, C1, D, A, B)

  // Check G^z == A + Y^e.
  let lhs1, rhs1
  try {
    lhs1 = pointMulBase(z)
    const Ye = pointMul(e, Y)
    rhs1 = pointAdd(A, Ye)
  } catch (err) {
    return { valid: false, reason: 'point-op-failed:eq1:' + err.message }
  }
  if (!b4a.equals(lhs1, rhs1)) return { valid: false, reason: 'eq1-mismatch' }

  // Check C1^z == B + D^e.
  let lhs2, rhs2
  try {
    lhs2 = pointMul(z, C1)
    const De = pointMul(e, D)
    rhs2 = pointAdd(B, De)
  } catch (err) {
    return { valid: false, reason: 'point-op-failed:eq2:' + err.message }
  }
  if (!b4a.equals(lhs2, rhs2)) return { valid: false, reason: 'eq2-mismatch' }

  return { valid: true }
}

/**
 * Produce a Chaum-Pedersen proof for known x with Y = G^x and D = C1^x.
 * Provided for testing and for client SDKs — the relay never needs to
 * prove, only verify.
 *
 * The randomness k is sampled from sodium's CSPRNG via scalar_random,
 * so reuse-safety is on the caller side only if they re-seed deterministic
 * RNGs (don't).
 *
 * @param {object} args
 * @param {Buffer} args.x   Secret scalar (32 bytes, little-endian).
 * @param {Buffer} args.Y   Threshold public key (32 bytes).
 * @param {Buffer} args.C1  Ciphertext "r" component (32 bytes).
 * @param {Buffer} args.D   Decryption share D = C1^x (32 bytes).
 * @param {Buffer} [args.G] Generator. Default ed25519 base point.
 * @returns {{ A: Buffer, B: Buffer, z: Buffer }}
 */
export function proveShareEquality (args) {
  const { x, Y, C1, D } = args
  const G = args.G || baseG()
  if (!x || x.byteLength !== SCALAR_BYTES) throw new Error('proveShareEquality: bad x')

  // Random nonce k.
  const k = b4a.alloc(SCALAR_BYTES)
  sodium.crypto_core_ed25519_scalar_random(k)

  // Commitments A = G^k, B = C1^k.
  const A = pointMulBase(k)
  const B = pointMul(k, C1)

  // Challenge e = H(G || Y || C1 || D || A || B) mod ℓ.
  const e = fsChallenge(G, Y, C1, D, A, B)

  // Response z = k + e*x mod ℓ.
  const ex = scalarMulMod(e, x)
  const z = b4a.alloc(SCALAR_BYTES)
  sodium.crypto_core_ed25519_scalar_add(z, k, ex)
  return { A, B, z }
}

/**
 * Convenience for callers without a precomputed threshold key — derive
 * Y = G^x from a secret scalar. Used by tests and example flows.
 */
export function publicFromSecret (x) {
  if (!x || x.byteLength !== SCALAR_BYTES) throw new Error('publicFromSecret: bad x')
  return pointMulBase(x)
}

/**
 * Compute D = C1^x for a published ciphertext C1 and secret x. Used by
 * tests and example flows — the relay never knows x.
 */
export function shareFor (x, C1) {
  return pointMul(x, C1)
}

/**
 * Public access to the canonical ed25519 base point as a 32-byte buffer.
 * Returned each call as a defensive copy so callers can mutate freely.
 */
export function baseG () {
  // Derive once and cache.
  if (!_cachedG) {
    const one = b4a.alloc(SCALAR_BYTES)
    one[0] = 1
    _cachedG = b4a.alloc(POINT_BYTES)
    sodium.crypto_scalarmult_ed25519_base_noclamp(_cachedG, one)
  }
  return b4a.from(_cachedG)
}
let _cachedG = null

// ─── Internal helpers ───────────────────────────────────────────────────────

/**
 * Variable-base scalar multiplication on ed25519: out = scalar * point.
 * Uses the no-clamp variant because we're doing generic group operations,
 * not Ed25519 signatures (which clamp the scalar).
 */
function pointMul (scalar, point) {
  const out = b4a.alloc(POINT_BYTES)
  sodium.crypto_scalarmult_ed25519_noclamp(out, scalar, point)
  return out
}

/**
 * Base-point scalar multiplication: out = scalar * G.
 */
function pointMulBase (scalar) {
  const out = b4a.alloc(POINT_BYTES)
  sodium.crypto_scalarmult_ed25519_base_noclamp(out, scalar)
  return out
}

/**
 * Point addition on the Edwards curve.
 */
function pointAdd (p, q) {
  const out = b4a.alloc(POINT_BYTES)
  sodium.crypto_core_ed25519_add(out, p, q)
  return out
}

/**
 * Fiat-Shamir challenge: a domain-separated BLAKE2b-512 of the proof
 * transcript, reduced mod ℓ. The domain string is included verbatim to
 * prevent cross-protocol replay (an A/B/z triple verifying under this
 * scheme can't pretend to be a proof from a different one that also
 * uses ed25519 point arithmetic).
 */
function fsChallenge (G, Y, C1, D, A, B) {
  const buf = b4a.alloc(HASH_BYTES)
  const domain = b4a.from(FS_DOMAIN, 'utf8')
  // crypto_generichash with input as a single concatenated buffer. The
  // transcript ordering matters; both prover and verifier must use the
  // same ordering. We pin it to (G, Y, C1, D, A, B) — same as the doc.
  const input = b4a.concat([domain, G, Y, C1, D, A, B])
  sodium.crypto_generichash(buf, input)
  // Reduce 64 → 32 mod ℓ for use as a scalar.
  const reduced = b4a.alloc(SCALAR_BYTES)
  sodium.crypto_core_ed25519_scalar_reduce(reduced, buf)
  return reduced
}

/**
 * Modular multiplication of two ed25519 scalars: (a * b) mod ℓ.
 *
 * Sodium-universal does not export `crypto_core_ed25519_scalar_mul`. We
 * implement it via BigInt — the scalar space is only 32 bytes, so big-int
 * arithmetic is cheap (sub-microsecond per call). All math is on the
 * group order ℓ, sourced from RFC 8032.
 *
 * Byte ordering: ed25519 scalars are little-endian (sodium convention).
 */
function scalarMulMod (aBytes, bBytes) {
  const a = leToBigInt(aBytes)
  const b = leToBigInt(bBytes)
  const c = (a * b) % ED25519_ORDER
  return bigIntToLe(c, SCALAR_BYTES)
}

function leToBigInt (buf) {
  let acc = 0n
  for (let i = buf.byteLength - 1; i >= 0; i--) {
    acc = (acc << 8n) | BigInt(buf[i])
  }
  return acc
}

function bigIntToLe (v, byteLength) {
  let n = v
  if (n < 0n) n = ((n % ED25519_ORDER) + ED25519_ORDER) % ED25519_ORDER
  const out = b4a.alloc(byteLength)
  for (let i = 0; i < byteLength; i++) {
    out[i] = Number(n & 0xffn)
    n >>= 8n
  }
  return out
}

export { ED25519_ORDER, FS_DOMAIN, POINT_BYTES, SCALAR_BYTES }
