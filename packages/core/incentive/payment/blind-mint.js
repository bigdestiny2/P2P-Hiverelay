// blind-mint.js — Cashu NUT-00 BDHKE blind-signature mint (secp256k1).
//
// Chaumian blind signatures over secp256k1, implemented to the Cashu NUT-00
// spec so the tokens this relay mints ARE Cashu tokens (see cashu.js for the
// NUT-01/02 keyset + token wire formats). This is the unlinkable upgrade for
// the bearer-voucher seam in incentive/lease/index.js: the payer blinds their
// own secret, the mint only ever sees a blinded point at issue time and the
// cleartext secret at redeem time, so it cannot link the two.
//
// Crypto is composed from the audited @noble/curves secp256k1 (field/point
// arithmetic) — we only implement the NUT-00 composition on top, which is
// validated against the official NUT-00 test vectors in the test suite
// (hash_to_curve x3, blinded message x2, blind signature x2). secp256k1 is a
// prime-order group, so unlike a naive ed25519 build there are no cofactor /
// small-subgroup pitfalls; Point.fromBytes additionally rejects off-curve /
// identity points.
//
// Protocol (G = secp256k1 generator, k = mint secret scalar, K = k*G):
//   1. payer:  Y = hash_to_curve(x)         (x = secret bytes)
//              B_ = Y + r*G                  (r = random blinding scalar)
//   2. mint:   C_ = k*B_                     (blind signature; mint never sees x)
//   3. payer:  C  = C_ - r*K = k*Y           (unblind) -> token = (x, C)
//   4. mint:   accept iff k*hash_to_curve(x) == C, and x unspent (double-spend
//              guard lives in the caller).

import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { randomBytes, hexToBytes, bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js'

const Point = secp256k1.Point
const G = Point.BASE
// secp256k1 group order (public curve constant).
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const DOMAIN_SEPARATOR = utf8ToBytes('Secp256k1_HashToCurve_Cashu_')

const bytesToScalar = (b) => BigInt('0x' + bytesToHex(b)) % N
const scalarToHex = (n) => (((n % N) + N) % N).toString(16).padStart(64, '0')

function randomScalar () {
  for (;;) {
    const s = bytesToScalar(randomBytes(32))
    if (s !== 0n) return s
  }
}

/**
 * Cashu NUT-00 hash_to_curve. Deterministically maps a message to a secp256k1
 * point: Y = PublicKey('02' || SHA256(SHA256(DOMAIN||x) || counterLE32)),
 * incrementing the uint32 LE counter until the 33-byte compressed encoding is
 * a valid point.
 * @param {Uint8Array|string} msg  raw bytes, or a hex string (decoded to bytes)
 * @returns {Point}
 */
export function hashToCurve (msg) {
  const m = typeof msg === 'string' ? hexToBytes(msg) : msg
  const msgHash = sha256(concatBytes(DOMAIN_SEPARATOR, m))
  const counter = new Uint8Array(4)
  const dv = new DataView(counter.buffer)
  for (let i = 0; i < 0x10000; i++) {
    dv.setUint32(0, i, true) // little-endian
    try {
      return Point.fromBytes(concatBytes(Uint8Array.of(0x02), sha256(concatBytes(msgHash, counter))))
    } catch (_) { /* not a valid x-coordinate; try next counter */ }
  }
  throw new Error('hashToCurve: no valid point within 2^16 counters')
}

// ─── Payer side (client) ─────────────────────────────────────────────

/** Fresh 32-byte token secret, hex-encoded (the Proof's `secret` field). */
export function newSecret () {
  return bytesToHex(randomBytes(32))
}

/**
 * Blind a secret. Returns { blinded: hex(B_), blindingFactor: hex(r) }.
 * @param {string} secret  hex secret
 */
export function blind (secret) {
  const Y = hashToCurve(secret)
  const r = randomScalar()
  const B_ = Y.add(G.multiply(r))
  return { blinded: B_.toHex(true), blindingFactor: scalarToHex(r) }
}

/**
 * Unblind a mint's blind signature into the final token point C.
 * @param {string} blindSignatureHex  hex(C_)
 * @param {string} blindingFactorHex  hex(r)
 * @param {string} mintPubkeyHex      hex(K)
 * @returns {string} hex(C)
 */
export function unblind (blindSignatureHex, blindingFactorHex, mintPubkeyHex) {
  const C_ = Point.fromBytes(hexToBytes(blindSignatureHex))
  const r = BigInt('0x' + blindingFactorHex) % N
  const K = Point.fromBytes(hexToBytes(mintPubkeyHex))
  const C = C_.add(K.multiply(r).negate())
  return C.toHex(true)
}

// ─── Mint side (relay) ───────────────────────────────────────────────

export class BlindMint {
  /**
   * @param {object} opts
   * @param {object} [opts.keyPair]  relay keyPair (mint scalar derived from its secretKey)
   * @param {string} [opts.secret]   explicit mint scalar as 64-hex (overrides keyPair)
   * @param {string} [opts.domain]   derivation domain separator
   */
  constructor (opts = {}) {
    if (opts.secret) {
      this._k = BigInt('0x' + opts.secret) % N
      if (this._k === 0n) throw new Error('BlindMint: secret reduces to zero')
    } else if (opts.keyPair && opts.keyPair.secretKey) {
      this._k = this._deriveScalar(opts.keyPair.secretKey, opts.domain || 'hiverelay-cashu-mint-v1')
    } else {
      throw new Error('BlindMint: keyPair or secret required')
    }
    this._K = G.multiply(this._k)
  }

  _deriveScalar (secretKey, domain) {
    const base = concatBytes(Uint8Array.from(secretKey), utf8ToBytes(domain))
    // Astronomically unlikely to be zero; rehash with a counter if it is.
    for (let i = 0; i < 256; i++) {
      const s = bytesToScalar(sha256(concatBytes(base, Uint8Array.of(i))))
      if (s !== 0n) return s
    }
    throw new Error('BlindMint: could not derive a non-zero scalar')
  }

  /** Mint public key K = k*G, compressed hex (the NUT-01 key for its amount). */
  get publicKey () {
    return this._K.toHex(true)
  }

  /**
   * Blind-sign a payer's blinded message B_. Rejects anything that isn't a
   * valid curve point (Point.fromBytes throws on off-curve/identity input).
   * @param {string} blindedHex  hex(B_)
   * @returns {string} hex(C_)
   */
  blindSign (blindedHex) {
    let B_
    try {
      B_ = Point.fromBytes(hexToBytes(blindedHex))
    } catch (_) {
      throw new Error('BLIND_INVALID_POINT: blinded message is not a valid secp256k1 point')
    }
    return B_.multiply(this._k).toHex(true)
  }

  /**
   * Verify a redeemed token (secret, C): C must equal k*hash_to_curve(secret).
   * Double-spend tracking is the caller's responsibility.
   * @param {string} secret  hex secret
   * @param {string} cHex    hex(C)
   * @returns {boolean}
   */
  verifyToken (secret, cHex) {
    let C
    try {
      C = Point.fromBytes(hexToBytes(cHex))
    } catch (_) {
      return false
    }
    return hashToCurve(secret).multiply(this._k).equals(C)
  }
}
