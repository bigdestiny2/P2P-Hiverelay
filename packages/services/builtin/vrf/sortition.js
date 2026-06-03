/**
 * sortition.js — deterministic, verifiable selection from VRF randomness
 *
 * Given a uniformly random seed (in practice a VRF output `beta`, which the
 * producer cannot bias and verifiers can independently check), this module
 * derives:
 *
 *   - seededShuffle(seed, items)       a deterministic permutation of `items`
 *   - weightedSample({ seed, ... })    a committee drawn without replacement,
 *                                       optionally weighted by per-candidate
 *                                       integer weights (e.g. reputation)
 *
 * The whole point is *verifiability*: anyone re-running the same function with
 * the same seed and the same candidate set gets byte-identical results. To make
 * that true across machines and JS engines we avoid floating point entirely —
 * all randomness is consumed as integers from a counter-hash stream and all
 * weighting uses BigInt arithmetic with rejection sampling (no modulo bias, no
 * `Math.log`/`Math.pow` whose last ULP is implementation-defined).
 *
 * Randomness stream:
 *     block_i = SHA-512( utf8(domain) || seed || uint64_le(i) )   i = 0,1,2,...
 * consumed left-to-right, big blocks refilled on demand. A `domain` tag keeps
 * independent uses of the *same* seed (e.g. a shuffle and a committee draw off
 * one beacon round) from colliding.
 *
 * Canonical ordering: committee selection sorts candidates by id before drawing,
 * so the result depends only on the *set* of candidates and the seed — never on
 * the order a caller happened to enumerate them in (Maps, network replies, …).
 * seededShuffle, by contrast, permutes the sequence exactly as given: a shuffle
 * is a permutation *of an ordering*, so the caller must supply items in a
 * canonical order if cross-node agreement is required.
 */

import { sha512 } from '@noble/hashes/sha2.js'

export const SHUFFLE_DOMAIN = 'hiverelay/vrf-sortition/shuffle/v1'
export const SELECT_DOMAIN = 'hiverelay/vrf-sortition/select/v1'

// Default fixed-point scale for quantizeWeights(): six decimal places. Chosen
// so typical reputation composites (score x reliability x latencyFactor) map to
// integers with ample resolution while staying well inside BigInt's comfort.
export const DEFAULT_WEIGHT_SCALE = 1_000_000

// ── byte helpers ─────────────────────────────────────────────────────────────

function concatBytes (...arrays) {
  let total = 0
  for (const a of arrays) total += a.length
  const out = new Uint8Array(total)
  let off = 0
  for (const a of arrays) { out.set(a, off); off += a.length }
  return out
}

function asSeedBytes (seed) {
  if (seed instanceof Uint8Array) {
    if (seed.length === 0) throw new Error('sortition: seed must be non-empty')
    return seed
  }
  if (typeof seed === 'string') {
    if (seed.length === 0 || seed.length % 2 !== 0 || /[^0-9a-fA-F]/.test(seed)) {
      throw new Error('sortition: seed string must be non-empty hex')
    }
    const out = new Uint8Array(seed.length / 2)
    for (let i = 0; i < out.length; i++) out[i] = parseInt(seed.slice(i * 2, i * 2 + 2), 16)
    return out
  }
  if (Array.isArray(seed)) {
    if (seed.length === 0) throw new Error('sortition: seed must be non-empty')
    return Uint8Array.from(seed)
  }
  throw new Error('sortition: seed must be a Uint8Array or hex string')
}

function uint64le (n) {
  const out = new Uint8Array(8)
  let v = n
  for (let i = 0; i < 8; i++) { out[i] = Number(v & 0xffn); v >>= 8n }
  if (v !== 0n) throw new Error('sortition: stream counter overflow')
  return out
}

// ── deterministic randomness stream ──────────────────────────────────────────

class HashStream {
  constructor (seedBytes, domain) {
    const domainBytes = new TextEncoder().encode(domain)
    this._prefix = concatBytes(domainBytes, seedBytes)
    this._counter = 0n
    this._buf = new Uint8Array(0)
    this._off = 0
  }

  _refill () {
    this._buf = sha512(concatBytes(this._prefix, uint64le(this._counter)))
    this._counter += 1n
    this._off = 0
  }

  /** Read `n` raw bytes as a little-endian BigInt. */
  readUintLE (n) {
    let value = 0n
    let shift = 0n
    for (let i = 0; i < n; i++) {
      if (this._off >= this._buf.length) this._refill()
      value |= BigInt(this._buf[this._off++]) << shift
      shift += 8n
    }
    return value
  }
}

/**
 * Uniform BigInt in [0, bound) drawn from the stream with rejection sampling,
 * so there is zero modulo bias regardless of how `bound` relates to the byte
 * boundary. `bound` must be a positive BigInt.
 */
function randomBelow (stream, bound) {
  if (bound <= 0n) throw new Error('sortition: bound must be positive')
  if (bound === 1n) return 0n
  const byteLen = Math.ceil(bound.toString(2).length / 8)
  const range = 1n << BigInt(8 * byteLen)
  const limit = range - (range % bound) // largest multiple of bound <= range
  for (;;) {
    const v = stream.readUintLE(byteLen)
    if (v < limit) return v % bound
  }
}

// ── candidate normalisation ──────────────────────────────────────────────────

function normalizeCandidates (candidates, { needWeights }) {
  if (!Array.isArray(candidates)) throw new Error('sortition: candidates must be an array')
  const seen = new Set()
  const out = []
  for (const entry of candidates) {
    let id, weight
    if (typeof entry === 'string') {
      id = entry
      weight = 1n
    } else if (entry && typeof entry === 'object') {
      id = entry.id
      if (typeof id !== 'string') throw new Error('sortition: candidate.id must be a string')
      if (needWeights) {
        const w = entry.weight
        if (!Number.isInteger(w) || w < 0) {
          throw new Error('sortition: weighted candidate.weight must be a non-negative integer (use quantizeWeights for floats)')
        }
        weight = BigInt(w)
      } else {
        weight = 1n
      }
    } else {
      throw new Error('sortition: candidate must be a string id or { id, weight } object')
    }
    if (id.length === 0) throw new Error('sortition: candidate id must be non-empty')
    if (seen.has(id)) throw new Error('sortition: duplicate candidate id "' + id + '"')
    seen.add(id)
    out.push({ id, weight })
  }
  // Canonical order: sort by id so the result depends only on the candidate set.
  out.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
  return out
}

// ── public API ────────────────────────────────────────────────────────────────

/**
 * Deterministically permute `items` using Fisher-Yates driven by the seed.
 * Returns a new array; the input is not mutated. The permutation is a function
 * of (seed, domain, items.length) only — identical seeds yield identical orders.
 *
 * @param {Uint8Array|string} seed   randomness seed (typically a VRF beta)
 * @param {Array} items              sequence to permute (any element type)
 * @param {object} [opts]
 * @param {string} [opts.domain]     stream domain tag (default SHUFFLE_DOMAIN)
 * @returns {Array} a new, shuffled array
 */
export function seededShuffle (seed, items, opts = {}) {
  if (!Array.isArray(items)) throw new Error('sortition: items must be an array')
  const domain = opts.domain || SHUFFLE_DOMAIN
  const arr = items.slice()
  const stream = new HashStream(asSeedBytes(seed), domain)
  // Standard Fisher-Yates: i from n-1 down to 1, swap with j in [0, i].
  for (let i = arr.length - 1; i >= 1; i--) {
    const j = Number(randomBelow(stream, BigInt(i + 1)))
    const tmp = arr[i]
    arr[i] = arr[j]
    arr[j] = tmp
  }
  return arr
}

/**
 * Select `count` distinct candidates without replacement.
 *
 * Unweighted (weighted=false): a uniform k-subset — the candidate set is sorted
 * canonically, shuffled by the seed, and the first `count` taken.
 *
 * Weighted (weighted=true): sequential weighted draws without replacement. Each
 * round draws an integer r in [0, totalWeight) and walks the (canonically
 * ordered) remaining pool by cumulative weight to pick the winner, then removes
 * it. This is exact integer arithmetic — no floats — so every node computes the
 * same committee. Zero-weight candidates can never be drawn.
 *
 * @param {object} args
 * @param {Uint8Array|string} args.seed         randomness seed (VRF beta)
 * @param {Array<string|{id,weight}>} args.candidates
 * @param {number} args.count                   committee size to draw
 * @param {boolean} [args.weighted=false]
 * @param {string} [args.domain]                stream domain (default SELECT_DOMAIN)
 * @returns {string[]} selected ids, in selection order
 */
export function weightedSample ({ seed, candidates, count, weighted = false, domain } = {}) {
  if (!Number.isInteger(count) || count < 0) throw new Error('sortition: count must be a non-negative integer')
  const dom = domain || SELECT_DOMAIN
  const pool = normalizeCandidates(candidates, { needWeights: weighted })
  const stream = new HashStream(asSeedBytes(seed), dom)

  if (count === 0) return []

  if (!weighted) {
    const ids = seededShuffle(asSeedBytes(seed), pool.map(c => c.id), { domain: dom })
    return ids.slice(0, Math.min(count, ids.length))
  }

  // Weighted, without replacement.
  let totalWeight = 0n
  for (const c of pool) totalWeight += c.weight
  const remaining = pool.slice()
  const selected = []
  const want = Math.min(count, remaining.length)

  while (selected.length < want && totalWeight > 0n) {
    const r = randomBelow(stream, totalWeight)
    let acc = 0n
    let pickIdx = -1
    for (let i = 0; i < remaining.length; i++) {
      acc += remaining[i].weight
      if (r < acc) { pickIdx = i; break }
    }
    // r < totalWeight guarantees a pick when any weight is positive.
    if (pickIdx === -1) break
    const picked = remaining[pickIdx]
    selected.push(picked.id)
    totalWeight -= picked.weight
    remaining.splice(pickIdx, 1)
  }
  return selected
}

/**
 * Quantize floating-point weights to non-negative integers for use with
 * weightedSample({ weighted: true }). Both the producer of a committee and any
 * independent verifier must quantize the *same* float inputs with the *same*
 * scale to agree, so this shared helper is the canonical conversion.
 *
 * Each value is rounded to `scale` fixed-point units; any strictly-positive
 * weight is floored to 1 so a positive-reputation candidate is never silently
 * made undrawable, while a zero/negative weight maps to 0.
 *
 * @param {Array<{id,weight}|[string,number]>} entries
 * @param {number} [scale=DEFAULT_WEIGHT_SCALE]
 * @returns {Array<{id, weight}>} integer-weighted candidates
 */
export function quantizeWeights (entries, scale = DEFAULT_WEIGHT_SCALE) {
  if (!Array.isArray(entries)) throw new Error('sortition: entries must be an array')
  if (!Number.isInteger(scale) || scale <= 0) throw new Error('sortition: scale must be a positive integer')
  return entries.map((entry) => {
    let id, raw
    if (Array.isArray(entry)) { [id, raw] = entry } else { id = entry.id; raw = entry.weight }
    if (typeof id !== 'string' || id.length === 0) throw new Error('sortition: entry id must be a non-empty string')
    if (typeof raw !== 'number' || !Number.isFinite(raw)) throw new Error('sortition: entry weight must be a finite number')
    let weight = Math.round(raw * scale)
    if (weight < 0) weight = 0
    else if (weight === 0 && raw > 0) weight = 1
    return { id, weight }
  })
}

/**
 * Recompute a committee and compare it to an expected result. Order-sensitive:
 * weightedSample returns ids in selection order, and a faithful verifier should
 * reproduce that order exactly.
 *
 * @param {object} args  same as weightedSample, plus:
 * @param {string[]} args.expected  the committee to check against
 * @returns {boolean}
 */
export function verifyCommittee ({ seed, candidates, count, weighted = false, domain, expected }) {
  if (!Array.isArray(expected)) return false
  let actual
  try {
    actual = weightedSample({ seed, candidates, count, weighted, domain })
  } catch {
    return false
  }
  if (actual.length !== expected.length) return false
  for (let i = 0; i < actual.length; i++) {
    if (actual[i] !== expected[i]) return false
  }
  return true
}

/**
 * Recompute a shuffle and compare to an expected ordering. Elements are compared
 * with strict equality, so this is intended for arrays of primitives (ids,
 * indices, strings).
 *
 * @returns {boolean}
 */
export function verifyShuffle (seed, items, expected, opts = {}) {
  if (!Array.isArray(items) || !Array.isArray(expected)) return false
  let actual
  try {
    actual = seededShuffle(seed, items, opts)
  } catch {
    return false
  }
  if (actual.length !== expected.length) return false
  for (let i = 0; i < actual.length; i++) {
    if (actual[i] !== expected[i]) return false
  }
  return true
}
