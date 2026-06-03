/**
 * beacon.js — chained VRF randomness beacon
 *
 * A public, append-only chain of unbiasable randomness. Round N's output is
 *
 *     alpha_N = beta_{N-1} || uint64_le(N)
 *     pi_N    = ECVRF_prove(sk, alpha_N)
 *     beta_N  = ECVRF_proof_to_hash(pi_N)
 *
 * anchored at a publicly-derivable genesis:
 *
 *     beta_0  = SHA-512(domain || pubkey)
 *
 * Properties this gives us:
 *   - Unbiasable: the operator cannot choose beta_N. It is the unique VRF
 *     output for alpha_N under sk, and alpha_N is fixed by the prior round.
 *   - Unpredictable: nobody without sk can compute beta_N ahead of its round.
 *   - Self-verifying: anyone with the beacon's public key can recompute the
 *     genesis and check verify(pubkey, alpha_N, pi_N) + beta_N == proofToHash
 *     for every round, with no trust in the operator.
 *   - Chained: each round commits to the previous output, so the whole history
 *     is tamper-evident.
 *
 * This module is pure state + math: no timers, no I/O. The vrf-service drives
 * advance() on an interval and serves the retained records; tests drive it
 * synchronously. The beacon never sees the raw secret key — it is handed a
 * bound `proveFn(alpha) -> pi` closure by the service.
 */

import { sha512 } from '@noble/hashes/sha2.js'
import { proofToHash, verify, toHex, BETA_LEN, PUBKEY_LEN } from './ecvrf.js'

export const DEFAULT_DOMAIN = 'hiverelay/vrf-beacon/v1'
export const DEFAULT_RETAIN = 1024

function concatBytes (a, b) {
  const out = new Uint8Array(a.length + b.length)
  out.set(a, 0)
  out.set(b, a.length)
  return out
}

/** Encode a round number as an 8-byte little-endian unsigned integer. */
function roundToLE8 (round) {
  if (!Number.isInteger(round) || round < 0) throw new Error('beacon: round must be a non-negative integer')
  const out = new Uint8Array(8)
  let v = BigInt(round)
  for (let i = 0; i < 8; i++) { out[i] = Number(v & 0xffn); v >>= 8n }
  if (v !== 0n) throw new Error('beacon: round exceeds uint64')
  return out
}

function asPubkeyBytes (pubkey) {
  let bytes
  if (pubkey instanceof Uint8Array) bytes = pubkey
  else if (typeof pubkey === 'string') {
    bytes = new Uint8Array(pubkey.length / 2)
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(pubkey.slice(i * 2, i * 2 + 2), 16)
  } else throw new Error('beacon: pubkey must be Uint8Array or hex string')
  if (bytes.length !== PUBKEY_LEN) throw new Error('beacon: pubkey must be 32 bytes')
  return bytes
}

/** Genesis anchor beta_0 = SHA-512(utf8(domain) || pubkey). Publicly derivable. */
export function computeGenesisBeta (domain, pubkey) {
  const domainBytes = new TextEncoder().encode(domain)
  return sha512(concatBytes(domainBytes, asPubkeyBytes(pubkey)))
}

/** The alpha input fed to the VRF for a given round, given the previous beta. */
export function beaconAlpha (prevBetaBytes, round) {
  if (!(prevBetaBytes instanceof Uint8Array) || prevBetaBytes.length !== BETA_LEN) {
    throw new Error('beacon: prevBeta must be 64 bytes')
  }
  return concatBytes(prevBetaBytes, roundToLE8(round))
}

function hexToBytes (hex, len, name) {
  if (typeof hex !== 'string' || hex.length !== len * 2 || /[^0-9a-fA-F]/.test(hex)) {
    throw new Error(`beacon: ${name} must be ${len}-byte hex`)
  }
  const out = new Uint8Array(len)
  for (let i = 0; i < len; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

export class VrfBeacon {
  /**
   * @param {object} opts
   * @param {(alpha: Uint8Array) => Uint8Array} opts.proveFn  bound VRF prover (uses sk)
   * @param {Uint8Array|string} opts.pubkey  the beacon's 32-byte VRF public key
   * @param {string} [opts.domain]  domain-separation string (default DEFAULT_DOMAIN)
   * @param {number} [opts.retain]  number of recent rounds to keep in memory
   */
  constructor ({ proveFn, pubkey, domain = DEFAULT_DOMAIN, retain = DEFAULT_RETAIN } = {}) {
    if (typeof proveFn !== 'function') throw new Error('beacon: proveFn is required')
    this.proveFn = proveFn
    this.pubkeyBytes = asPubkeyBytes(pubkey)
    this.pubkey = toHex(this.pubkeyBytes)
    this.domain = domain
    this.retain = Math.max(1, retain | 0)
    this._genesisBeta = computeGenesisBeta(this.domain, this.pubkeyBytes)
    this._round = 0
    this._prevBeta = this._genesisBeta
    this._history = [] // records for rounds >= 1, oldest first
    this._byRound = new Map()
  }

  get currentRound () { return this._round }

  genesis () {
    return {
      round: 0,
      beta: toHex(this._genesisBeta),
      domain: this.domain,
      pubkey: this.pubkey
    }
  }

  /** Produce the next round, append it to the retained history, and return it. */
  advance () {
    const round = this._round + 1
    const alpha = beaconAlpha(this._prevBeta, round)
    const pi = this.proveFn(alpha)
    if (!(pi instanceof Uint8Array)) throw new Error('beacon: proveFn must return Uint8Array')
    const beta = proofToHash(pi)
    const record = {
      round,
      timestamp: Date.now(),
      pubkey: this.pubkey,
      domain: this.domain,
      prevBeta: toHex(this._prevBeta),
      alpha: toHex(alpha),
      pi: toHex(pi),
      beta: toHex(beta)
    }
    this._round = round
    this._prevBeta = beta
    this._history.push(record)
    this._byRound.set(round, record)
    while (this._history.length > this.retain) {
      const dropped = this._history.shift()
      this._byRound.delete(dropped.round)
    }
    return record
  }

  latest () {
    return this._history.length ? this._history[this._history.length - 1] : null
  }

  round (r) {
    return this._byRound.get(r) || null
  }

  /** Recent records, newest last. `count` caps how many are returned. */
  range (count = 16) {
    const n = Math.max(0, Math.min(count | 0, this._history.length))
    return this._history.slice(this._history.length - n)
  }

  info () {
    return {
      suite: 'ECVRF-EDWARDS25519-SHA512-TAI',
      pubkey: this.pubkey,
      domain: this.domain,
      genesisBeta: toHex(this._genesisBeta),
      currentRound: this._round,
      retained: this._history.length,
      retain: this.retain,
      oldestRound: this._history.length ? this._history[0].round : null
    }
  }
}

/**
 * Verify a single beacon record against a public key, with no trust in the
 * operator. Recomputes alpha from (prevBeta, round), checks the VRF proof, and
 * checks beta == proofToHash(pi).
 * @returns {{ round: number, valid: boolean, reason: string|null }}
 */
export function verifyBeaconRecord (pubkey, record) {
  try {
    const prevBeta = hexToBytes(record.prevBeta, BETA_LEN, 'prevBeta')
    const expectedAlpha = toHex(beaconAlpha(prevBeta, record.round))
    if (record.alpha !== expectedAlpha) {
      return { round: record.round, valid: false, reason: 'alpha-mismatch' }
    }
    if (!verify(pubkey, record.alpha, record.pi)) {
      return { round: record.round, valid: false, reason: 'proof-invalid' }
    }
    const beta = toHex(proofToHash(record.pi))
    if (beta !== record.beta) {
      return { round: record.round, valid: false, reason: 'beta-mismatch' }
    }
    return { round: record.round, valid: true, reason: null }
  } catch (err) {
    return { round: record?.round ?? null, valid: false, reason: 'malformed:' + err.message }
  }
}

/**
 * Verify a contiguous run of beacon records as a chain: every record verifies
 * standalone, each record's prevBeta links to the previous record's beta, and
 * (if the run starts at round 1) round 1 links to the derivable genesis.
 * @param {object} args
 * @param {Uint8Array|string} args.pubkey
 * @param {string} [args.domain]
 * @param {Array} args.records  contiguous, ascending by round
 * @returns {{ valid: boolean, checked: number, failures: Array }}
 */
export function verifyBeaconChain ({ pubkey, domain = DEFAULT_DOMAIN, records }) {
  const failures = []
  if (!Array.isArray(records) || records.length === 0) {
    return { valid: false, checked: 0, failures: [{ reason: 'no-records' }] }
  }
  const genesisBeta = toHex(computeGenesisBeta(domain, pubkey))
  let prev = null
  for (const record of records) {
    if (prev !== null && record.round !== prev.round + 1) {
      failures.push({ round: record.round, reason: 'non-contiguous' })
    }
    const link = prev === null ? (record.round === 1 ? genesisBeta : null) : prev.beta
    if (link !== null && record.prevBeta !== link) {
      failures.push({ round: record.round, reason: 'broken-link' })
    }
    const r = verifyBeaconRecord(pubkey, record)
    if (!r.valid) failures.push({ round: record.round, reason: r.reason })
    prev = record
  }
  return { valid: failures.length === 0, checked: records.length, failures }
}
