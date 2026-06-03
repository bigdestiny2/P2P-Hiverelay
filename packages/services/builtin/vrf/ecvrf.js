/**
 * ecvrf.js — ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381)
 *
 * A Verifiable Random Function: the holder of a secret key produces, for any
 * input `alpha`, a deterministic pseudorandom output `beta` together with a
 * proof `pi`. Anyone holding the public key can verify that `beta` is the
 * unique correct output for `alpha` under that key — without learning the
 * secret, and without the prover being able to choose `beta`.
 *
 * This is the suite-0x03 "try-and-increment" (TAI) variant standardised in
 * RFC 9381. We pick TAI specifically because the RFC publishes byte-exact
 * test vectors for it (Appendix A.4), which we treat as the correctness gate
 * (see scripts/test-vrf-vectors.js). A subtly-wrong VRF is worse than none, so
 * every parameter below is pinned to the RFC and asserted against its vectors.
 *
 *   suite_string = 0x03
 *   curve        = edwards25519 (RFC 8032), cofactor = 8
 *   Hash         = SHA-512
 *   cLen         = 16   (challenge, octets)
 *   ptLen        = 32   (compressed point, octets)
 *   qLen         = 32   (scalar, octets)
 *   pi  length   = ptLen + cLen + qLen = 80 octets
 *   beta length  = 64 octets (full SHA-512 output)
 *
 * All integers are little-endian (consistent with RFC 8032 scalar encoding).
 *
 * Crypto backend: @noble/curves ed25519 Point/Fn (constant-time `multiply`
 * for secret scalars, variable-time `multiplyUnsafe` for public inputs) and
 * @noble/hashes SHA-512. We deliberately reuse the same vetted primitives the
 * poker Chaum-Pedersen module relies on rather than hand-rolling field math.
 */

import { ed25519 } from '@noble/curves/ed25519.js'
import { sha512 } from '@noble/hashes/sha2.js'

const Point = ed25519.Point
const Fn = Point.Fn // scalar field mod L (the prime group order)
const BASE = Point.BASE

// RFC 9381 §5.5 fixed parameters for ECVRF-EDWARDS25519-SHA512-TAI.
const SUITE = 0x03
const C_LEN = 16
const PT_LEN = 32
const Q_LEN = 32
export const PROOF_LEN = PT_LEN + C_LEN + Q_LEN // 80
export const BETA_LEN = 64
export const PUBKEY_LEN = 32
export const SECKEY_LEN = 32

// Domain separators (RFC 9381 §5.4).
const DS_ENCODE_FRONT = 0x01
const DS_ENCODE_BACK = 0x00
const DS_CHALLENGE_FRONT = 0x02
const DS_CHALLENGE_BACK = 0x00
const DS_PROOF_TO_HASH_FRONT = 0x03
const DS_PROOF_TO_HASH_BACK = 0x00

// The group order L must match the curve we think we're on. If a dependency
// bump ever changes this out from under us, fail loudly at import time rather
// than silently producing wrong proofs.
const ED25519_ORDER =
  7237005577332262213973186563042994240857116359379907606001950938285454250989n
if (Fn.ORDER !== ED25519_ORDER) {
  throw new Error('ecvrf: unexpected ed25519 scalar field order from @noble/curves')
}
if (Fn.isLE !== true) {
  throw new Error('ecvrf: expected little-endian scalar field')
}

// ── byte / bigint helpers ────────────────────────────────────────────────────

function leToBigInt (bytes) {
  let n = 0n
  for (let i = bytes.length - 1; i >= 0; i--) {
    n = (n << 8n) | BigInt(bytes[i])
  }
  return n
}

function bigIntToLE (n, len) {
  const out = new Uint8Array(len)
  let v = n
  for (let i = 0; i < len; i++) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  if (v !== 0n) throw new Error('ecvrf: integer does not fit in requested length')
  return out
}

function concatBytes (...arrays) {
  let total = 0
  for (const a of arrays) total += a.length
  const out = new Uint8Array(total)
  let off = 0
  for (const a of arrays) { out.set(a, off); off += a.length }
  return out
}

function asBytes (input, name) {
  if (input instanceof Uint8Array) return input
  if (typeof input === 'string') {
    // hex string
    if (input.length % 2 !== 0 || /[^0-9a-fA-F]/.test(input)) {
      throw new Error(`ecvrf: ${name} string must be valid hex`)
    }
    const out = new Uint8Array(input.length / 2)
    for (let i = 0; i < out.length; i++) out[i] = parseInt(input.slice(i * 2, i * 2 + 2), 16)
    return out
  }
  if (input == null) throw new Error(`ecvrf: ${name} is required`)
  if (Array.isArray(input)) return Uint8Array.from(input)
  throw new Error(`ecvrf: ${name} must be a Uint8Array or hex string`)
}

export function toHex (bytes) {
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0')
  return s
}

// ── key derivation (RFC 9381 §5.5 / RFC 8032 clamping) ───────────────────────

/**
 * Expand a 32-byte secret seed into the VRF secret scalar x, the RFC 8032
 * nonce prefix, and the corresponding public key Y = x*B.
 */
export function expandSeed (sk) {
  const seed = asBytes(sk, 'secret key')
  if (seed.length !== SECKEY_LEN) throw new Error('ecvrf: secret key must be 32 bytes')
  const h = sha512(seed)
  const scalarBytes = h.slice(0, 32)
  // RFC 8032 clamping.
  scalarBytes[0] &= 248
  scalarBytes[31] &= 127
  scalarBytes[31] |= 64
  // Reduce mod L: the clamped value can exceed L, but B has order L so the
  // public key (and every downstream scalar op) is unchanged by reduction.
  const x = Fn.create(leToBigInt(scalarBytes))
  const prefix = h.slice(32, 64)
  const Y = BASE.multiply(x)
  return { x, prefix, Y, pk: Y.toBytes() }
}

/** Derive just the 32-byte public key for a secret seed. */
export function publicKey (sk) {
  return expandSeed(sk).pk
}

// ── core algorithm pieces ────────────────────────────────────────────────────

/**
 * ECVRF_encode_to_curve_try_and_increment (RFC 9381 §5.4.1.1).
 * encode_to_curve_salt = the encoded public key (RFC 9381 §5.5).
 */
function encodeToCurveTAI (pk, alpha) {
  for (let ctr = 0; ctr <= 255; ctr++) {
    const hash = sha512(concatBytes(
      Uint8Array.of(SUITE),
      Uint8Array.of(DS_ENCODE_FRONT),
      pk,
      alpha,
      Uint8Array.of(ctr),
      Uint8Array.of(DS_ENCODE_BACK)
    ))
    let candidate
    try {
      // arbitrary_string_to_point: decode the leftmost 32 octets as a point.
      candidate = Point.fromBytes(hash.slice(0, 32))
    } catch {
      continue // not a valid point encoding → try next counter
    }
    // cofactor * H clears any small-order component, landing in the prime group.
    const H = candidate.clearCofactor()
    if (H.is0()) continue
    return { H, ctr }
  }
  throw new Error('ecvrf: encode_to_curve exhausted counter (unreachable)')
}

/** ECVRF_nonce_generation_RFC8032 (RFC 9381 §5.4.2.2). */
function nonceGeneration (prefix, hString) {
  const k = sha512(concatBytes(prefix, hString))
  return Fn.create(leToBigInt(k))
}

/** ECVRF_challenge_generation (RFC 9381 §5.4.3). Returns a bigint < 2^(8*cLen). */
function challengeGeneration (points) {
  const parts = [Uint8Array.of(SUITE), Uint8Array.of(DS_CHALLENGE_FRONT)]
  for (const P of points) parts.push(P.toBytes())
  parts.push(Uint8Array.of(DS_CHALLENGE_BACK))
  const cString = sha512(concatBytes(...parts))
  return leToBigInt(cString.slice(0, C_LEN))
}

/** ECVRF_decode_proof (RFC 9381 §5.4.4). Throws on malformed input. */
function decodeProof (pi) {
  const bytes = asBytes(pi, 'proof')
  if (bytes.length !== PROOF_LEN) throw new Error('ecvrf: proof must be 80 bytes')
  const Gamma = Point.fromBytes(bytes.slice(0, PT_LEN)) // throws if invalid
  const c = leToBigInt(bytes.slice(PT_LEN, PT_LEN + C_LEN))
  const s = leToBigInt(bytes.slice(PT_LEN + C_LEN, PROOF_LEN))
  if (s >= Fn.ORDER) throw new Error('ecvrf: proof scalar s out of range')
  return { Gamma, c, s }
}

// ── public API ───────────────────────────────────────────────────────────────

/**
 * ECVRF_prove (RFC 9381 §5.1). Returns the 80-byte proof pi.
 * @param {Uint8Array|string} sk    32-byte secret seed (or hex)
 * @param {Uint8Array|string} alpha input message (or hex)
 * @returns {Uint8Array} pi
 */
export function prove (sk, alpha) {
  const alphaBytes = asBytes(alpha ?? new Uint8Array(0), 'alpha')
  const { x, prefix, Y, pk } = expandSeed(sk)
  const { H } = encodeToCurveTAI(pk, alphaBytes)
  const hString = H.toBytes()
  const Gamma = H.multiply(x)
  const k = nonceGeneration(prefix, hString)
  const U = BASE.multiply(k) // k*B
  const V = H.multiply(k) // k*H
  const c = challengeGeneration([Y, H, Gamma, U, V])
  const s = Fn.add(k, Fn.mul(c, x)) // (k + c*x) mod L
  return concatBytes(Gamma.toBytes(), bigIntToLE(c, C_LEN), bigIntToLE(s, Q_LEN))
}

/**
 * ECVRF_proof_to_hash (RFC 9381 §5.2). Maps a valid proof to its 64-byte VRF
 * output beta. NOTE: this does NOT verify the proof — call verify() first if
 * the proof is from an untrusted source.
 * @param {Uint8Array|string} pi 80-byte proof
 * @returns {Uint8Array} beta (64 bytes)
 */
export function proofToHash (pi) {
  const { Gamma } = decodeProof(pi)
  return sha512(concatBytes(
    Uint8Array.of(SUITE),
    Uint8Array.of(DS_PROOF_TO_HASH_FRONT),
    Gamma.clearCofactor().toBytes(), // cofactor * Gamma
    Uint8Array.of(DS_PROOF_TO_HASH_BACK)
  ))
}

/**
 * ECVRF_verify (RFC 9381 §5.3). Returns true iff pi is a valid proof that the
 * holder of `pk` produced the VRF output for `alpha`.
 * @param {Uint8Array|string} pk    32-byte public key (or hex)
 * @param {Uint8Array|string} alpha input message (or hex)
 * @param {Uint8Array|string} pi    80-byte proof (or hex)
 * @returns {boolean}
 */
export function verify (pk, alpha, pi) {
  let Gamma, c, s, Y
  try {
    ({ Gamma, c, s } = decodeProof(pi))
    Y = Point.fromBytes(asBytes(pk, 'public key'))
  } catch {
    return false
  }
  const alphaBytes = asBytes(alpha ?? new Uint8Array(0), 'alpha')
  const pkBytes = Y.toBytes()
  const { H } = encodeToCurveTAI(pkBytes, alphaBytes)
  // U = s*B - c*Y ; V = s*H - c*Gamma. All scalars/points here are public, so
  // variable-time multiplyUnsafe is appropriate (and accepts a zero scalar).
  const U = BASE.multiplyUnsafe(s).subtract(Y.multiplyUnsafe(c))
  const V = H.multiplyUnsafe(s).subtract(Gamma.multiplyUnsafe(c))
  const cPrime = challengeGeneration([Y, H, Gamma, U, V])
  return c === cPrime
}

/**
 * Convenience: verify a proof and, if valid, return its VRF output beta.
 * @returns {{ valid: boolean, beta: Uint8Array|null }}
 */
export function verifyAndHash (pk, alpha, pi) {
  if (!verify(pk, alpha, pi)) return { valid: false, beta: null }
  return { valid: true, beta: proofToHash(pi) }
}

export const params = Object.freeze({
  suite: 'ECVRF-EDWARDS25519-SHA512-TAI',
  suiteByte: SUITE,
  cLen: C_LEN,
  ptLen: PT_LEN,
  qLen: Q_LEN,
  proofLen: PROOF_LEN,
  betaLen: BETA_LEN
})
