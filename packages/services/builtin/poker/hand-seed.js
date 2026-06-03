/**
 * hand-seed.js — verifiable per-hand randomness anchor for card-blind poker
 *
 * The relay is card-blind by construction (see ./index.js): it never reads a
 * payload, so it cannot shuffle a deck. What it CAN provide is an unbiasable,
 * publicly-verifiable random number bound to a specific hand — a "hand seed" —
 * which the players fold into their own mental-poker shuffle off the log.
 *
 * The anchor is just a VRF evaluation over a canonical, public input:
 *
 *     alpha_hand = SHA-256( domain || tableKey || handId )
 *     pi_hand    = vrf.prove(alpha_hand)        // via the relay's VRF service
 *     beta_hand  = vrf.proof_to_hash(pi_hand)   // 64 bytes of public randomness
 *
 * Because alpha is fixed by (tableKey, handId) — both public and recorded in
 * the append-only signed log — every seat derives the SAME alpha and can call
 * verify(vrfPubkey, alpha, pi) to confirm beta was not cherry-picked. The relay
 * proved a number over a public string; it learned nothing about anyone's cards.
 *
 * ─── Recommended client recipe ──────────────────────────────────────────────
 *
 *   1. Seats agree on `handId` (a per-table monotonic counter, written to the
 *      log as an opaque entry so the ordering is itself auditable).
 *   2. Any seat computes `alpha = handSeedAlpha(tableKey, handId)` and requests
 *      `vrf.prove({ alpha })` (or `vrf.shuffle`) from the table's relay, then
 *      posts the returned `pi` to the log as an opaque payload.
 *   3. Every seat runs `verifyHandSeed(...)` before trusting `beta`.
 *   4. `beta` becomes the nothing-up-my-sleeve seed for the agreed base deck
 *      ordering (`handDeckOrder(beta)`); seats then layer their commutative
 *      encrypt-and-shuffle protocol on top. The relay never sees a card.
 *
 * ─── Removing trust in a single relay ───────────────────────────────────────
 *
 * The relay holds the VRF key, so in principle it could grind alpha. alpha is
 * pinned to (tableKey, handId), so grinding requires forking the log — which is
 * detectable — but for adversarial play you should remove the single point of
 * trust entirely: have EACH seat publish its own VRF beta over the same alpha
 * (under its own key) and `combineBetas([...])` them. The XOR is unbiasable
 * unless every contributor colludes, and each contribution is independently
 * verifiable. The combined value is the real hand seed.
 *
 * This module is pure and dependency-light (only @noble/hashes + the local
 * ecvrf/sortition helpers) so it runs unchanged in a Bare/Pear client.
 */

import { sha256 } from '@noble/hashes/sha2.js'
import { verify, proofToHash, toHex, BETA_LEN } from '../vrf/ecvrf.js'
import { seededShuffle } from '../vrf/sortition.js'

export const HAND_SEED_DOMAIN = 'hiverelay/poker/hand-seed/v1'
export const DECK_DOMAIN = 'hiverelay/poker/deck/v1'
export const DEFAULT_DECK_SIZE = 52
const MAX_HAND_ID_LEN = 128

function concatBytes (...arrays) {
  let total = 0
  for (const a of arrays) total += a.length
  const out = new Uint8Array(total)
  let off = 0
  for (const a of arrays) { out.set(a, off); off += a.length }
  return out
}

function hexToBytes (hex, name) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) {
    throw new Error(`hand-seed: ${name} must be a hex string`)
  }
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

function isHexKey (s) {
  return typeof s === 'string' && /^[0-9a-fA-F]{64}$/.test(s)
}

/** Normalise a handId (string or finite integer) to a bounded canonical string. */
function normalizeHandId (handId) {
  let s
  if (typeof handId === 'string') s = handId
  else if (typeof handId === 'number' && Number.isFinite(handId)) s = String(handId)
  else throw new Error('hand-seed: handId must be a string or finite number')
  if (s.length === 0 || s.length > MAX_HAND_ID_LEN) {
    throw new Error('hand-seed: handId must be 1..' + MAX_HAND_ID_LEN + ' chars')
  }
  return s
}

/**
 * Canonical VRF input for a hand. Every seat derives the same value, so all
 * agree on exactly what the relay should be proving.
 *
 * @param {string} tableKey  64-hex table pubkey
 * @param {string|number} handId  per-table hand identifier
 * @returns {string} alpha as a hex string, ready for vrf.prove({ alpha })
 */
export function handSeedAlpha (tableKey, handId) {
  if (!isHexKey(tableKey)) throw new Error('hand-seed: tableKey must be 64-hex')
  const hid = normalizeHandId(handId)
  const enc = new TextEncoder()
  const SEP = Uint8Array.of(0x00)
  const digest = sha256(concatBytes(
    enc.encode(HAND_SEED_DOMAIN), SEP,
    hexToBytes(tableKey, 'tableKey'), SEP,
    enc.encode(hid), SEP
  ))
  return toHex(digest)
}

/**
 * Verify a hand seed produced by the relay (or by a seat). Recomputes alpha,
 * checks the VRF proof under `vrfPubkey`, and — if a beta is supplied — checks
 * it equals proof_to_hash(pi). Never throws.
 *
 * @param {object} args
 * @param {string} args.vrfPubkey  the prover's 32-byte VRF pubkey (hex)
 * @param {string} args.tableKey
 * @param {string|number} args.handId
 * @param {string} args.pi         80-byte proof (hex)
 * @param {string} [args.beta]     optional 64-byte beta (hex) to cross-check
 * @returns {{ valid: boolean, reason: string|null, alpha: string|null, beta: string|null }}
 */
export function verifyHandSeed ({ vrfPubkey, tableKey, handId, pi, beta } = {}) {
  let alpha = null
  try {
    alpha = handSeedAlpha(tableKey, handId)
    if (!verify(vrfPubkey, alpha, pi)) {
      return { valid: false, reason: 'proof-invalid', alpha, beta: null }
    }
    const computed = toHex(proofToHash(pi))
    if (beta != null && computed !== String(beta).toLowerCase()) {
      return { valid: false, reason: 'beta-mismatch', alpha, beta: computed }
    }
    return { valid: true, reason: null, alpha, beta: computed }
  } catch (err) {
    return { valid: false, reason: 'malformed:' + (err?.message || 'unknown'), alpha, beta: null }
  }
}

/**
 * Derive a canonical public deck permutation from a hand seed. This is the
 * nothing-up-my-sleeve STARTING ordering that all seats agree on; the secret
 * mental-poker shuffle (commutative re-encryption) layers on top of it. Pure
 * and deterministic: same beta ⇒ same order.
 *
 * @param {string|Uint8Array} beta  the hand seed (64-byte hex or bytes)
 * @param {number} [deckSize=52]
 * @returns {number[]} a permutation of 0..deckSize-1
 */
export function handDeckOrder (beta, deckSize = DEFAULT_DECK_SIZE) {
  if (!Number.isInteger(deckSize) || deckSize <= 0) throw new Error('hand-seed: deckSize must be a positive integer')
  const cards = Array.from({ length: deckSize }, (_, i) => i)
  return seededShuffle(beta, cards, { domain: DECK_DOMAIN })
}

/**
 * XOR-combine independent betas from multiple seats into a single hand seed
 * that no single contributor controls. Each contribution should be the VRF beta
 * of that seat over the SAME alpha (and independently verifiable via
 * verifyHandSeed). Requires at least one beta; all must be equal length.
 *
 * @param {Array<string|Uint8Array>} betas
 * @returns {string} combined beta (hex)
 */
export function combineBetas (betas) {
  if (!Array.isArray(betas) || betas.length === 0) throw new Error('hand-seed: betas must be a non-empty array')
  const vectors = betas.map((b, i) => (b instanceof Uint8Array ? b : hexToBytes(String(b), 'beta[' + i + ']')))
  const len = vectors[0].length
  if (len !== BETA_LEN) throw new Error('hand-seed: beta must be ' + BETA_LEN + ' bytes')
  const out = new Uint8Array(len)
  for (const v of vectors) {
    if (v.length !== len) throw new Error('hand-seed: all betas must be the same length')
    for (let i = 0; i < len; i++) out[i] ^= v[i]
  }
  return toHex(out)
}
