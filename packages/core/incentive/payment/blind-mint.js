// blind-mint.js — Chaumian blind-signature mint (BDHKE), the unlinkable
// upgrade path for the bearer-voucher seam in incentive/lease/index.js.
//
// ⚠️  AUDIT BEFORE PRODUCTION USE.  This is a working REFERENCE implementation
//     of Cashu-style BDHKE (Blind Diffie–Hellman Key Exchange), not an audited
//     library. Real Cashu uses secp256k1; this uses ed25519 because that is
//     what sodium-universal ships here. It is provided so the lease seam has a
//     concrete, testable unlinkable token — swap in a vetted secp256k1/Cashu
//     mint (or Ristretto255 when available) before handling real value.
//
// Why it gives unlinkability the plain bearer voucher cannot:
//   The plain voucher is relay-SIGNED at issue time, so the operator can
//   correlate "invoice I settled" → "serial S I signed" → "serial S redeemed".
//   With BDHKE the payer BLINDS their own secret before the mint signs, so the
//   mint only ever sees a uniformly-random blinded point at issue time and the
//   cleartext secret at redeem time — it cannot link the two.
//
// Protocol (G = ed25519 basepoint, k = mint secret scalar, K = k·G):
//   1. payer:  Y = H2P(x)              (x = random secret; H2P = hash-to-point)
//              B_ = Y + r·G            (r = random blinding scalar)
//   2. mint:   C_ = k·B_               (blind signature; mint never sees x)
//   3. payer:  C  = C_ − r·K = k·Y     (unblind)  → token = (x, C)
//   4. mint:   accept iff C == k·H2P(x), and x unspent  (double-spend guard)
//
// Cofactor handling: ed25519 has cofactor 8. H2P clears the cofactor (×8) so Y
// lands in the prime-order subgroup, and blindSign() rejects any B_ that is not
// a valid prime-order point (crypto_core_ed25519_is_valid_point) — closing the
// small-subgroup avenue. All scalar mults are *noclamp* (exact group math).

import sodium from 'sodium-universal'
import b4a from 'b4a'

const POINT = sodium.crypto_core_ed25519_BYTES // 32
const SCALAR = sodium.crypto_core_ed25519_SCALARBYTES // 32
const UNIFORM = sodium.crypto_core_ed25519_UNIFORMBYTES // 32
const NONREDUCED = sodium.crypto_core_ed25519_NONREDUCEDSCALARBYTES // 64

// Multiply a point by the cofactor (8) via three doublings (P+P thrice). Maps
// any curve point into the prime-order subgroup (kills the 8-torsion).
function mulCofactor (p) {
  let q = b4a.from(p)
  for (let i = 0; i < 3; i++) {
    const r = b4a.alloc(POINT)
    sodium.crypto_core_ed25519_add(r, q, q)
    q = r
  }
  return q
}

// Deterministic hash-to-point in the prime-order subgroup.
export function hashToPoint (secret) {
  const msg = typeof secret === 'string' ? b4a.from(secret, 'hex') : secret
  const u = b4a.alloc(UNIFORM)
  sodium.crypto_generichash(u, msg)
  const p = b4a.alloc(POINT)
  sodium.crypto_core_ed25519_from_uniform(p, u)
  return mulCofactor(p)
}

// Derive a stable mint scalar from an Ed25519 secret key, so a relay's mint
// key survives restarts with no new persistence and only this relay can sign.
function deriveScalar (secretKey, domain) {
  const wide = b4a.alloc(NONREDUCED)
  sodium.crypto_generichash(wide, b4a.concat([b4a.from(secretKey), b4a.from(domain)]))
  const k = b4a.alloc(SCALAR)
  sodium.crypto_core_ed25519_scalar_reduce(k, wide)
  return k
}

// ─── Payer side (client) ─────────────────────────────────────────────
//
// Normally these run on the payer's machine. Exported here so the SDK / tests
// can drive the full flow.

/** Create a fresh 32-byte token secret. */
export function newSecret () {
  const x = b4a.alloc(32)
  sodium.randombytes_buf(x)
  return b4a.toString(x, 'hex')
}

/** Blind a secret. Returns { blinded: hex(B_), blindingFactor: hex(r) }. */
export function blind (secret) {
  const Y = hashToPoint(secret)
  const r = b4a.alloc(SCALAR)
  sodium.crypto_core_ed25519_scalar_random(r)
  const rG = b4a.alloc(POINT)
  sodium.crypto_scalarmult_ed25519_base_noclamp(rG, r)
  const Bp = b4a.alloc(POINT)
  sodium.crypto_core_ed25519_add(Bp, Y, rG)
  return { blinded: b4a.toString(Bp, 'hex'), blindingFactor: b4a.toString(r, 'hex') }
}

/** Unblind a mint's blind signature into the final token point C. */
export function unblind (blindSignatureHex, blindingFactorHex, mintPubkeyHex) {
  const Cp = b4a.from(blindSignatureHex, 'hex')
  const r = b4a.from(blindingFactorHex, 'hex')
  const K = b4a.from(mintPubkeyHex, 'hex')
  const rK = b4a.alloc(POINT)
  sodium.crypto_scalarmult_ed25519_noclamp(rK, r, K)
  const C = b4a.alloc(POINT)
  sodium.crypto_core_ed25519_sub(C, Cp, rK)
  return b4a.toString(C, 'hex')
}

// ─── Mint side (relay) ───────────────────────────────────────────────

export class BlindMint {
  /**
   * @param {object} opts
   * @param {object} [opts.keyPair]   relay Ed25519 keyPair (mint key derived from it)
   * @param {Buffer} [opts.secret]    explicit 32-byte mint scalar (overrides keyPair)
   * @param {string} [opts.domain]    derivation domain separator
   */
  constructor (opts = {}) {
    if (opts.secret) {
      if (opts.secret.length !== SCALAR) throw new Error('BlindMint: secret must be 32 bytes')
      this._k = b4a.from(opts.secret)
    } else if (opts.keyPair && opts.keyPair.secretKey) {
      this._k = deriveScalar(opts.keyPair.secretKey, opts.domain || 'hiverelay-blind-mint-v1')
    } else {
      throw new Error('BlindMint: keyPair or secret required')
    }
    this._K = b4a.alloc(POINT)
    sodium.crypto_scalarmult_ed25519_base_noclamp(this._K, this._k)
  }

  /** Mint public key K = k·G (advertise so payers can unblind). */
  get publicKey () {
    return b4a.toString(this._K, 'hex')
  }

  /**
   * Blind-sign a payer's blinded message B_. The mint learns nothing about the
   * underlying secret. Rejects any B_ that is not a valid prime-order point.
   * @param {string} blindedHex  hex(B_)
   * @returns {string} hex(C_)  blind signature
   */
  blindSign (blindedHex) {
    if (typeof blindedHex !== 'string' || blindedHex.length !== POINT * 2) {
      throw new Error('BLIND_BAD_INPUT: blinded message must be 32-byte hex')
    }
    const Bp = b4a.from(blindedHex, 'hex')
    if (!sodium.crypto_core_ed25519_is_valid_point(Bp)) {
      throw new Error('BLIND_INVALID_POINT: blinded message is not a valid prime-order point')
    }
    const Cp = b4a.alloc(POINT)
    sodium.crypto_scalarmult_ed25519_noclamp(Cp, this._k, Bp)
    return b4a.toString(Cp, 'hex')
  }

  /**
   * Verify a redeemed token (secret, C): C must equal k·H2P(secret).
   * Pure crypto check — double-spend tracking is the caller's responsibility.
   * @returns {boolean}
   */
  verifyToken (secret, cHex) {
    if (typeof cHex !== 'string' || cHex.length !== POINT * 2) return false
    const C = b4a.from(cHex, 'hex')
    if (!sodium.crypto_core_ed25519_is_valid_point(C)) return false
    const Y = hashToPoint(secret)
    const kY = b4a.alloc(POINT)
    sodium.crypto_scalarmult_ed25519_noclamp(kY, this._k, Y)
    return sodium.sodium_memcmp ? sodium.sodium_memcmp(C, kY) : b4a.equals(C, kY)
  }
}
