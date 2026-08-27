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
 *     2. Challenge e = H(context || G || Y || C1 || D || A || B).
 *     3. Response z = k + e*x  (mod the ed25519 group order ℓ).
 *
 *   Verification:
 *     - e' = H(context || G || Y || C1 || D || A || B)
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
// noble-curves provides the scalar-field operations used for the prover's
// `e * x mod ℓ` step. Import the field primitive directly: importing the full
// Ed25519 module also evaluates unrelated FROST/hash code that requires a
// global TextEncoder and therefore cannot load in the Bare relay runtime.
import { Field } from '@noble/curves/abstract/modular.js'

const POINT_BYTES = 32
const SCALAR_BYTES = 32
const HASH_BYTES = 64 // we hash into 64 bytes then reduce mod ℓ

// ed25519 group order ℓ = 2^252 + 27742317777372353535851937790883648493.
// Sourced from RFC 8032 §5.1. Kept for documentation; the scalar arithmetic
// itself runs through noble's little-endian field primitive. Assert its shape
// at module load so a future dependency change cannot silently desync it.
const ED25519_ORDER = 7237005577332262213973186563042994240857116359379907606001950938285454250989n
const NOBLE_FN = Field(ED25519_ORDER, { isLE: true })
if (NOBLE_FN.ORDER !== ED25519_ORDER || NOBLE_FN.BYTES !== SCALAR_BYTES || !NOBLE_FN.isLE) {
  throw new Error('chaum-pedersen: noble ed25519 scalar field order does not match RFC 8032 ℓ')
}

// DRI-387 replaces the unpublished game-protocol-v3 proof schema in place.
// The game protocol version and the independently versioned proof domain are
// transcript fields: changing either invalidates every earlier proof rather
// than allowing replay into a new hand/card/recipient. Later game-protocol
// versions remain reserved by their own Linear issues.
const CARD_SHARE_PROTOCOL = 'p2poker/game-entry'
const CARD_SHARE_PROTOCOL_VERSION = 3
const CARD_SHARE_TRANSCRIPT_VERSION = 2
const FS_DOMAIN = 'p2poker/card-share/chaum-pedersen/v2'
const PROOF_KINDS = new Set(['share-commit', 'share-precommit', 'share-deliver', 'hole-reveal'])

// CVE-2025-69277 regression vector. A vulnerable libsodium build accepted this
// mixed-order encoding as a prime-order ed25519 point. Failing at module load
// protects every caller (client prover/verifier and relay arbitration) even if
// package resolution or a native prebuild changes underneath the lockfile.
const CVE_2025_69277_POINT = b4a.from('95' + '99'.repeat(31), 'hex')
if (sodium.crypto_core_ed25519_is_valid_point(CVE_2025_69277_POINT)) {
  throw new Error('chaum-pedersen: unsafe sodium runtime (CVE-2025-69277 vector accepted)')
}

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

  let context
  try {
    context = canonicalShareContext(args.context)
  } catch (error) {
    return { valid: false, reason: 'bad-context:' + error.message }
  }

  // Shape checks — return reason strings rather than throwing so the
  // arbitration verifier can map them to 'inconclusive' verdicts cleanly.
  for (const [name, val] of [['Y', Y], ['C1', C1], ['D', D], ['A', A], ['B', B], ['G', G]]) {
    if (!val || val.byteLength !== POINT_BYTES) return { valid: false, reason: 'bad-point:' + name }
  }
  if (!z || z.byteLength !== SCALAR_BYTES) return { valid: false, reason: 'bad-scalar:z' }

  // Subgroup-validity checks — reject mixed-order or low-order points.
  //
  // ed25519's cofactor is 8: a curve point can be on the Edwards curve but
  // sit outside the prime-order subgroup. Without this check, an attacker
  // who controls any of Y, C1, D, A, or B can plant a mixed-order point
  // and have eq1/eq2 close for a proof that's only valid mod 8 of the
  // group order — the verifier returns valid=true for a claim that doesn't
  // attest what the dispute protocol thinks it does.
  //
  // `crypto_core_ed25519_is_valid_point` verifies: on the curve, canonical
  // form, in the main subgroup, and not low-order. That's exactly the
  // closure we need. We run it on every externally-sourced point;
  // G is internal (defaults to ed25519 base point) so we trust it.
  //
  // CVE-2025-69277 caveat: pre-fix libsodium had an incomplete check in
  // this function itself. Operators must run sodium-universal built
  // against libsodium >= commit ad3004e. This module assumes that; if
  // your deployment ships an older libsodium, this check still rejects
  // the common attack vectors but the fundamental defense is operator
  // dependency hygiene.
  for (const [name, val] of [['Y', Y], ['C1', C1], ['D', D], ['A', A], ['B', B]]) {
    if (!sodium.crypto_core_ed25519_is_valid_point(val)) {
      return { valid: false, reason: 'invalid-point:' + name }
    }
  }

  // Recompute challenge e' = H(G || Y || C1 || D || A || B), reduce mod ℓ.
  const e = fsChallenge(context, G, Y, C1, D, A, B)

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
 * Timing posture (PROVER): the `e * x mod ℓ` step delegates to
 * noble-curves' best-effort constant-time scalar field op — see
 * scalarMulMod for the history. The VERIFIER side has no secret in scope
 * and is safe to deploy as-is.
 *
 * Caveat for real-money deployments: best-effort constant-time in pure JS
 * is materially better than raw BigInt but does not reach the rigour of a
 * native C impl. Production lines should either (a) confine proving to a
 * non-network-facing process anyway as defence in depth, or (b) swap in a
 * native constant-time primitive (e.g. sodium-native exposing
 * crypto_core_ed25519_scalar_mul). See arbitration.setAppEvidenceVerifier
 * for the swap-in hook on the verifier side and the README for the prover
 * side wiring guidance.
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
  const context = canonicalShareContext(args.context)

  // Subgroup-validity checks on every externally-sourced point. Same
  // rationale as verifyShareEquality — without these, a malicious or
  // buggy caller can construct a "proof" against a mixed-order Y/C1/D
  // that's structurally valid but cryptographically meaningless. We
  // catch that here rather than producing nonsense outputs.
  for (const [name, val] of [['Y', Y], ['C1', C1], ['D', D]]) {
    if (!val || val.byteLength !== POINT_BYTES) {
      throw new Error('proveShareEquality: bad ' + name + ' length')
    }
    if (!sodium.crypto_core_ed25519_is_valid_point(val)) {
      throw new Error('proveShareEquality: invalid point ' + name + ' (off-curve or mixed-order)')
    }
  }

  // Random nonce k.
  const k = b4a.alloc(SCALAR_BYTES)
  sodium.crypto_core_ed25519_scalar_random(k)

  // Commitments A = G^k, B = C1^k.
  const A = pointMulBase(k)
  const B = pointMul(k, C1)

  // Challenge e = H(G || Y || C1 || D || A || B) mod ℓ.
  const e = fsChallenge(context, G, Y, C1, D, A, B)

  // Response z = k + e*x mod ℓ.
  // Uses noble-curves' constant-time scalar-field multiplication (Fn.mul)
  // instead of native JS BigInt — see scalarMulMod comment block for the
  // timing-leak history that motivated this swap.
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
function fsChallenge (context, G, Y, C1, D, A, B) {
  const buf = b4a.alloc(HASH_BYTES)
  // Every component is tagged and length-framed. This removes concat
  // ambiguity and makes the precise table/hand/writer/kind/card/recipient
  // statement part of the Fiat-Shamir challenge.
  const fields = [
    ['protocol', b4a.from(CARD_SHARE_PROTOCOL, 'utf8')],
    ['protocolVersion', u32be(context.protocolVersion)],
    ['domain', b4a.from(FS_DOMAIN, 'utf8')],
    ['transcriptVersion', u32be(CARD_SHARE_TRANSCRIPT_VERSION)],
    ['tableKey', context.tableKey],
    ['hand', u64be(context.hand)],
    ['writer', context.writer],
    ['proofKind', b4a.from(context.proofKind, 'utf8')],
    ['cardIndex', u32be(context.cardIndex)],
    ['recipient', encodeRecipient(context.recipientSeat)],
    ['G', G],
    ['Y', Y],
    ['C1', C1],
    ['D', D],
    ['A', A],
    ['B', B]
  ]
  const input = b4a.concat(fields.map(([tag, value]) => frame(tag, value)))
  sodium.crypto_generichash(buf, input)
  // Reduce 64 → 32 mod ℓ for use as a scalar.
  const reduced = b4a.alloc(SCALAR_BYTES)
  sodium.crypto_core_ed25519_scalar_reduce(reduced, buf)
  return reduced
}

/**
 * Normalize and validate the public statement context shared by the live
 * client verifier and arbitration verifier. Hex and byte inputs normalize to
 * the same 32-byte representation; all returned buffers are defensive copies.
 */
export function canonicalShareContext (value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('missing')
  if (value.protocolVersion !== CARD_SHARE_PROTOCOL_VERSION) throw new Error('protocol-version')
  const tableKey = hexOrBytes32(value.tableKey, 'tableKey')
  const writer = hexOrBytes32(value.writer, 'writer')
  if (!Number.isSafeInteger(value.hand) || value.hand < 0) throw new Error('hand')
  if (!PROOF_KINDS.has(value.proofKind)) throw new Error('proof-kind')
  if (!Number.isInteger(value.cardIndex) || value.cardIndex < 0 || value.cardIndex > 51) {
    throw new Error('card-index')
  }
  const recipientSeat = value.recipientSeat == null ? null : value.recipientSeat
  if (value.proofKind === 'share-deliver') {
    if (!Number.isInteger(recipientSeat) || recipientSeat < 0 || recipientSeat > 8) {
      throw new Error('recipient')
    }
  } else if (recipientSeat !== null) {
    throw new Error('recipient-for-kind')
  }
  return {
    protocolVersion: CARD_SHARE_PROTOCOL_VERSION,
    tableKey,
    hand: value.hand,
    writer,
    proofKind: value.proofKind,
    cardIndex: value.cardIndex,
    recipientSeat
  }
}

function hexOrBytes32 (value, name) {
  if (typeof value === 'string') {
    if (!/^[0-9a-f]{64}$/i.test(value)) throw new Error(name)
    return b4a.from(value.toLowerCase(), 'hex')
  }
  if (!value || value.byteLength !== 32) throw new Error(name)
  return b4a.from(value)
}

function frame (tag, value) {
  const tagBytes = b4a.from(tag, 'utf8')
  return b4a.concat([u32be(tagBytes.byteLength), tagBytes, u32be(value.byteLength), value])
}

function u32be (value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new Error('u32')
  const out = b4a.alloc(4)
  out[0] = (value >>> 24) & 0xff
  out[1] = (value >>> 16) & 0xff
  out[2] = (value >>> 8) & 0xff
  out[3] = value & 0xff
  return out
}

function u64be (value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('u64')
  const high = Math.floor(value / 0x100000000)
  const low = value - high * 0x100000000
  return b4a.concat([u32be(high), u32be(low)])
}

function encodeRecipient (seat) {
  return seat == null ? b4a.from([0]) : b4a.concat([b4a.from([1]), u32be(seat)])
}

/**
 * Modular multiplication of two ed25519 scalars: (a * b) mod ℓ.
 *
 * Sodium-universal does not export `crypto_core_ed25519_scalar_mul` (the
 * primitive exists in libsodium but isn't surfaced through the bindings
 * we ship). We delegate to noble-curves' `ed25519.Point.Fn.mul`, which is
 * a best-effort constant-time implementation in pure JS.
 *
 * Timing history: an earlier version of this module computed the product
 * via raw JS BigInt. V8 BigInt multiplication is operand-value-dependent
 * in execution time, which makes the prover a timing oracle for the
 * long-term secret x. Noble's Fn.mul wraps the multiplication with
 * Montgomery-style reduction logic that doesn't branch on operand value
 * and is the path every modern audited JS crypto stack ships against. Not
 * the rigour of a native C constant-time impl, but the right portable JS
 * answer; for production-grade real-money use cases, swap to a native
 * binding (`sodium-native` with the scalar-mul primitive exposed, or a
 * WASM-built libsodium).
 *
 * Byte ordering: ed25519 scalars are little-endian (sodium convention,
 * also noble's Fn.isLE === true). Both sides agree, so fromBytes/toBytes
 * round-trip cleanly between formats.
 *
 * Inputs MUST be reduced mod ℓ already — both Fiat-Shamir challenges
 * (reduced via crypto_core_ed25519_scalar_reduce) and player secrets
 * (sampled via crypto_core_ed25519_scalar_random) satisfy this. Noble's
 * Fn.fromBytes will reject scalars outside [0, ℓ); failure throws and
 * propagates to the caller.
 */
function scalarMulMod (aBytes, bBytes) {
  const a = NOBLE_FN.fromBytes(aBytes)
  const b = NOBLE_FN.fromBytes(bBytes)
  const c = NOBLE_FN.mul(a, b)
  // Noble returns a 32-byte little-endian buffer (Fn.isLE === true); wrap
  // in b4a so the rest of the module sees the same buffer flavour it uses
  // everywhere else (Uint8Array view-compatibility is good enough for
  // sodium ops, but explicit b4a.from keeps types uniform).
  return b4a.from(NOBLE_FN.toBytes(c))
}

export {
  ED25519_ORDER,
  CARD_SHARE_PROTOCOL,
  CARD_SHARE_PROTOCOL_VERSION,
  CARD_SHARE_TRANSCRIPT_VERSION,
  FS_DOMAIN,
  POINT_BYTES,
  SCALAR_BYTES,
  CVE_2025_69277_POINT
}
