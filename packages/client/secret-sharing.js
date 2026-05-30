/**
 * Publicly Verifiable Secret Sharing (PVSS) — client/dealer SDK surface.
 *
 * A Schoenmakers-style PVSS over secp256k1. This is the DEALER/SHAREHOLDER
 * side — the prover. It lives in the client SDK because the split and the
 * reconstruction happen wherever the secret lives (the publishing app, e.g.
 * Drop), never on a relay.
 *
 * BLIND BY CONSTRUCTION — the load-bearing invariant:
 *   - The dealer (this client) runs `split`. A relay NEVER sees the secret
 *     or runs the split.
 *   - Reconstruction runs client-side (`reconstruct`). A relay NEVER
 *     interpolates the secret.
 *   - Shares are ElGamal-encrypted to the *recipient/guardian* pubkeys,
 *     which MUST be disjoint from the custodying relays. A relay holds an
 *     opaque encrypted share it cannot open, yet can verify it against the
 *     public commitments without decrypting anything.
 *   - The publishable bundle (`result.public`) carries only commitments,
 *     encrypted shares and proofs — never the secret. `result.key` /
 *     `result.secretPoint` are returned to the dealer alone; do not publish
 *     them.
 *
 * BARE-SAFE. This ships inside Pear apps that run on Bare, not Node — so it
 * uses `sodium.randombytes_buf` + `b4a` and NEVER node `crypto`/`Buffer`.
 * (The dormant services build used `crypto.randomBytes`/`Buffer`, which throw
 * on Bare; that is precisely why this is a rewrite, not a copy.)
 *
 * The relay verifies these transcripts with the SAME challenge construction
 * via packages/core/core/pvss.js. The two are kept deliberately SEPARATE —
 * do NOT "DRY" them into a shared import: the client pins a published,
 * frozen p2p-hiverelay, so relay and client are independently-versioned
 * deployables that interoperate over the wire. Their byte-for-byte agreement
 * is the real interop contract, pinned by a cross-implementation test
 * (test/unit/custody-pvss.test.js), not by code sharing.
 *
 * Security note: PVSS confidentiality is COMPUTATIONAL (rests on DDH in
 * secp256k1), unlike the information-theoretic secrecy of plain Shamir. That
 * is the standard, expected tradeoff for public verifiability.
 */

import * as secp from '@noble/secp256k1'
import { sha256 } from '@noble/hashes/sha2.js'
import { hmac } from '@noble/hashes/hmac.js'
import sodium from 'sodium-universal'
import b4a from 'b4a'

// Wire noble hashes (required by @noble/secp256k1 v2+ for any ECDSA path).
// Guarded so it is a no-op when another module already wired the same module
// instance. PVSS itself only needs EC point arithmetic + BLAKE2b challenges.
if (!secp.hashes.sha256) {
  secp.hashes.sha256 = (...msgs) => sha256(secp.etc.concatBytes(...msgs.filter(m => m != null)))
  secp.hashes.hmacSha256 = (key, ...msgs) => hmac(sha256, key, secp.etc.concatBytes(...msgs.filter(m => m != null)))
}

// ─── Constants ──────────────────────────────────────────────────────

const G = secp.Point.BASE // secret generator: S = s*G
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n

// Independent commitment generator (nothing-up-my-sleeve). MUST match the
// seed used by packages/core/core/pvss.js or verification diverges.
const C_GEN = hashToCurveSimple('hiverelay-pvss-commit-generator-v1')

const KEY_DOMAIN = 'hiverelay-pvss-key-v1:'
const MAX_SHARES = 255

export const SCHEME = 'pvss-secp256k1-v1'

// ─── Field / curve helpers (Bare-safe) ──────────────────────────────

function modN (n) {
  return ((n % N) + N) % N
}

function randomScalar () {
  const buf = b4a.alloc(32)
  let s
  do {
    sodium.randombytes_buf(buf)
    s = modN(secp.etc.bytesToNumberBE(buf))
  } while (s === 0n)
  return s
}

function scalarToHex (s) {
  return s.toString(16).padStart(64, '0')
}

function hexToScalar (h) {
  return BigInt('0x' + h)
}

function pointToHex (P) {
  return P.toHex(true)
}

function hexToPoint (h) {
  return secp.Point.fromHex(h)
}

/** Modular inverse mod N via the iterative extended Euclidean algorithm. */
function invN (a) {
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
function hashToScalar (...parts) {
  const input = b4a.concat(parts.map(p => typeof p === 'string' ? b4a.from(p, 'hex') : b4a.from(p)))
  const hash = b4a.alloc(32)
  sodium.crypto_generichash(hash, input)
  return modN(secp.etc.bytesToNumberBE(hash))
}

/** Find a valid secp256k1 point from a seed string (nothing-up-my-sleeve). */
function hashToCurveSimple (seed) {
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
function polyEval (coeffs, x) {
  let acc = 0n
  for (let j = coeffs.length - 1; j >= 0; j--) acc = modN(acc * x + coeffs[j])
  return acc
}

/**
 * Lagrange coefficients evaluated at x = 0 for the given index set.
 * λ_i = Π_{j≠i} (0 - x_j) / (x_i - x_j)   (mod N)
 * Returns a Map of indexBigInt → λ.
 */
function lagrangeAtZero (indices) {
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

/** Derive a 32-byte symmetric key from a secret point. */
function keyFromPoint (S) {
  const buf = b4a.alloc(32)
  sodium.crypto_generichash(buf, b4a.from(KEY_DOMAIN + pointToHex(S)))
  return b4a.toString(buf, 'hex')
}

/** BLAKE2b over the concatenation of commitment hexes → 64-hex anchor. */
function commitmentRootOf (commitments) {
  const buf = b4a.alloc(32)
  sodium.crypto_generichash(buf, b4a.from(commitments.join('')))
  return b4a.toString(buf, 'hex')
}

// ─── DLEQ (discrete-log equality) ───────────────────────────────────

/**
 * Prove log_{base1}(A) == log_{base2}(B) == x, without revealing x.
 * Fiat-Shamir, challenge over (base1, A, base2, B, R1, R2).
 */
function proveDleq (base1, A, base2, B, x) {
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

function verifyDleq (base1, A, base2, B, proof) {
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

/** Recompute X_i = Π_j C_j^(i^j) = C_GEN^p(i) from parsed commitment points. */
function commitmentShare (commitmentPoints, index) {
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

function verifyShareConsistency (commitmentPoints, sh) {
  if (!sh || !Number.isInteger(sh.index) || sh.index < 1) return false
  try {
    const Xi = commitmentShare(commitmentPoints, sh.index)
    const yi = hexToPoint(sh.shareholder)
    const Yi = hexToPoint(sh.encryptedShare)
    return verifyDleq(C_GEN, Xi, yi, Yi, sh.proof)
  } catch {
    return false
  }
}

// ─── Public SDK surface ─────────────────────────────────────────────

/**
 * Generate a shareholder/recipient keypair (x, y = x*G).
 * @returns {Promise<{secretKey:string, publicKey:string}>}
 */
export async function keygen () {
  const x = randomScalar()
  return {
    secretKey: scalarToHex(x),
    publicKey: pointToHex(G.multiply(x))
  }
}

/**
 * Dealer step (CLIENT-SIDE ONLY). Split a secret t-of-n.
 *
 * @param {object} params
 * @param {number} params.threshold   minimum shares to reconstruct (>= 1)
 * @param {string[]} params.shareholders recipient pubkey hexes (length n >= t),
 *   MUST be disjoint from the custodying relays
 * @param {string} [params.secret]    optional 64-hex scalar; random if omitted
 * @returns {Promise<{threshold:number, secretPoint:string, key:string,
 *   public:{scheme:string, threshold:number, commitments:string[],
 *   commitmentRoot:string, encryptedShares:object[]}}>}
 *   secretPoint + key are DEALER-PRIVATE; only `public` is safe to publish.
 */
export async function split (params) {
  const { threshold, shareholders, secret } = params || {}
  if (!Number.isInteger(threshold) || threshold < 1) throw new Error('SS_INVALID_THRESHOLD')
  if (!Array.isArray(shareholders) || shareholders.length < threshold) {
    throw new Error('SS_THRESHOLD_EXCEEDS_SHAREHOLDERS')
  }
  if (shareholders.length > MAX_SHARES) throw new Error('SS_TOO_MANY_SHARES')

  const recipients = shareholders.map((pk, idx) => {
    try {
      return hexToPoint(pk)
    } catch {
      throw new Error('SS_BAD_SHAREHOLDER_PUBKEY:' + idx)
    }
  })

  // Polynomial p(x) = s + a_1 x + ... + a_{t-1} x^{t-1}, with p(0) = s.
  const s = secret ? modN(hexToScalar(secret)) : randomScalar()
  if (s === 0n) throw new Error('SS_INVALID_SECRET')
  const coeffs = [s]
  for (let j = 1; j < threshold; j++) coeffs.push(randomScalar())

  // Feldman commitments C_j = a_j * C_GEN.
  const commitmentPoints = coeffs.map(a => C_GEN.multiply(a))
  const commitments = commitmentPoints.map(pointToHex)

  const encryptedShares = recipients.map((yi, k) => {
    const index = k + 1 // x-coordinate, never 0
    const pi = polyEval(coeffs, BigInt(index))
    if (pi === 0n) throw new Error('SS_DEGENERATE_SHARE') // astronomically rare
    const Xi = C_GEN.multiply(pi) // public, == commitmentShare(commitments, index)
    const Yi = yi.multiply(pi) // encrypted share: only holder of xi can open
    const proof = proveDleq(C_GEN, Xi, yi, Yi, pi)
    return {
      index,
      shareholder: pointToHex(yi),
      encryptedShare: pointToHex(Yi),
      proof
    }
  })

  const S = G.multiply(s)
  return {
    threshold,
    secretPoint: pointToHex(S),
    key: keyFromPoint(S),
    public: {
      scheme: SCHEME,
      threshold,
      commitments,
      commitmentRoot: commitmentRootOf(commitments),
      encryptedShares
    }
  }
}

/**
 * Public verification (no secret keys, no decryption). Confirms each encrypted
 * share is consistent with the published Feldman commitments. Useful for a
 * dealer self-checking a bundle before publishing.
 *
 * @param {object} params
 * @param {string[]} params.commitments
 * @param {object[]} params.encryptedShares
 * @param {number} [params.index]  verify only this share index
 * @returns {Promise<{valid:boolean, verified:number, badIndices:number[]}>}
 */
export async function verifyShares (params) {
  const { commitments, encryptedShares, index } = params || {}
  if (!Array.isArray(commitments) || commitments.length < 1) throw new Error('SS_MISSING_COMMITMENTS')
  if (!Array.isArray(encryptedShares)) throw new Error('SS_MISSING_SHARES')

  let commitmentPoints
  try {
    commitmentPoints = commitments.map(hexToPoint)
  } catch {
    throw new Error('SS_BAD_COMMITMENT')
  }

  const subset = index === undefined
    ? encryptedShares
    : encryptedShares.filter(sh => sh && sh.index === index)
  if (index !== undefined && subset.length === 0) throw new Error('SS_INDEX_NOT_FOUND')

  const badIndices = []
  let verified = 0
  for (const sh of subset) {
    if (verifyShareConsistency(commitmentPoints, sh)) verified++
    else badIndices.push(sh && sh.index)
  }
  return { valid: badIndices.length === 0, verified, badIndices }
}

/**
 * Shareholder step (CLIENT-SIDE). Decrypt an encrypted share with the
 * shareholder secret key, producing the share value S_i = p(i)*G and a DLEQ
 * proof that the decryption is correct.
 *
 * @param {object} params
 * @param {{index:number, encryptedShare:string}} params.encryptedShare
 * @param {string} params.secretKey
 * @returns {Promise<{index:number, share:string, shareholder:string,
 *   encryptedShare:string, proof:object}>}
 */
export async function decryptShare (params) {
  const { encryptedShare, secretKey } = params || {}
  if (!encryptedShare || !secretKey) throw new Error('SS_MISSING_PARAMS')
  const x = modN(hexToScalar(secretKey))
  if (x === 0n) throw new Error('SS_BAD_SECRET_KEY')

  let Yi
  try {
    Yi = hexToPoint(encryptedShare.encryptedShare)
  } catch {
    throw new Error('SS_BAD_ENCRYPTED_SHARE')
  }
  const yi = G.multiply(x)
  const Si = Yi.multiply(invN(x)) // (1/x) * (p(i) * x * G) = p(i) * G
  // DLEQ: log_G(yi) == log_{Si}(Yi) == x  (Yi = x * Si)
  const proof = proveDleq(G, yi, Si, Yi, x)
  return {
    index: encryptedShare.index,
    share: pointToHex(Si),
    shareholder: pointToHex(yi),
    encryptedShare: pointToHex(Yi),
    proof
  }
}

/**
 * Public verification of a decrypted share (no secret key).
 * @param {{share:string, shareholder:string, encryptedShare:string, proof:object}} params
 * @returns {Promise<{valid:boolean}>}
 */
export async function verifyDecryptedShare (params) {
  const { share, shareholder, encryptedShare, proof } = params || {}
  if (!share || !shareholder || !encryptedShare) throw new Error('SS_MISSING_PARAMS')
  try {
    const Si = hexToPoint(share)
    const yi = hexToPoint(shareholder)
    const Yi = hexToPoint(encryptedShare)
    return { valid: verifyDleq(G, yi, Si, Yi, proof) }
  } catch {
    return { valid: false }
  }
}

/**
 * Reconstruct the secret (CLIENT-SIDE) from >= threshold decrypted shares via
 * Lagrange interpolation in the exponent. If a share carries proof material,
 * its decryption DLEQ is verified first and a bad share is rejected.
 *
 * @param {object} params
 * @param {object[]} params.shares  [{ index, share, shareholder?, encryptedShare?, proof? }]
 * @param {number} [params.threshold]
 * @returns {Promise<{secretPoint:string, key:string}>}
 */
export async function reconstruct (params) {
  const { shares, threshold } = params || {}
  if (!Array.isArray(shares) || shares.length < 1) throw new Error('SS_MISSING_SHARES')
  if (Number.isInteger(threshold) && shares.length < threshold) {
    throw new Error('SS_INSUFFICIENT_SHARES')
  }

  const seen = new Set()
  const points = []
  for (const sh of shares) {
    if (!sh || !Number.isInteger(sh.index) || sh.index < 1) throw new Error('SS_BAD_SHARE_INDEX')
    if (seen.has(sh.index)) throw new Error('SS_DUPLICATE_SHARE_INDEX')
    seen.add(sh.index)
    // If verification material is present, a bad share must not be used.
    if (sh.proof && sh.shareholder && sh.encryptedShare) {
      const ok = verifyDleq(G, hexToPoint(sh.shareholder), hexToPoint(sh.share), hexToPoint(sh.encryptedShare), sh.proof)
      if (!ok) throw new Error('SS_INVALID_SHARE_PROOF:' + sh.index)
    }
    points.push({ index: BigInt(sh.index), P: hexToPoint(sh.share) })
  }

  const lambdas = lagrangeAtZero(points.map(p => p.index))
  let S = null
  for (const { index, P } of points) {
    const lambda = lambdas.get(index)
    const term = P.multiply(lambda === 0n ? N : lambda)
    S = S === null ? term : S.add(term)
  }
  return {
    secretPoint: pointToHex(S),
    key: keyFromPoint(S)
  }
}

/**
 * Derive the symmetric key from a (reconstructed) secret point.
 * @param {{secretPoint:string}} params
 * @returns {Promise<{key:string}>}
 */
export async function deriveKey (params) {
  const { secretPoint } = params || {}
  if (!secretPoint) throw new Error('SS_MISSING_PARAMS')
  return { key: keyFromPoint(hexToPoint(secretPoint)) }
}
