// subsidy/index.js — operator subsidy accrual (Phase 1, relay side).
//
// Implements the relay-local half of the bootstrap subsidy from
// docs/OPERATOR-INCENTIVES-Y1.md (Prong 2): operators running a blind
// peer accrue a streaming subsidy in sats, paid from BTC the founder
// commits to the network, capped per day ("up to ~$180/yr" at the
// default rate).
//
// What this module does:
//   - Samples the node's stats on a fixed epoch timer (default 10 min)
//     and records evidence per epoch (uptime, connections, seeded apps,
//     anchored count).
//   - Accrues a sats ESTIMATE at the configured rate, capped per UTC day.
//   - Holds the operator's payout destination (lightning-address, BOLT12
//     offer, or on-chain address). Non-custodial by design: the relay
//     never holds funds and there is no wallet in the app — the network
//     pays the destination the operator controls.
//   - Exports a signed claim (Ed25519 by the relay keypair, same
//     digest-then-detached-sign shape as services/signed-directory.js)
//     that the Phase-2 subsidy coordinator fetches, independently
//     verifies against fleet observations, and pays.
//
// What this module deliberately does NOT do:
//   - Move money. No Lightning/on-chain code paths here.
//   - Treat its own numbers as authoritative. The accrued figure is an
//     estimate; the coordinator's verification (Operator Score gates,
//     sybil checks, held schedule) decides the actual payout.
//
// Persistence: <storage>/subsidy.json via the atomic tmp+rename pattern
// (v0.10.6) — a crash mid-write must not zero an operator's accrual log.

import { EventEmitter } from 'events'
import { readFile, writeFile, rename, unlink, mkdir } from 'fs/promises'
import { dirname } from 'path'
import sodium from 'sodium-universal'
import b4a from 'b4a'

const DAY_MS = 86_400_000
const DEFAULT_EPOCH_MS = 10 * 60 * 1000
const DEFAULT_RATE_SATS_PER_DAY = 500 // ≈ $180/yr at $100k/BTC — see Y1 doc
const MIN_EPOCH_MS = 1_000
const MAX_EPOCHS_RETAINED = 5_000 // ~34 days at 10-min epochs
export const SUBSIDY_SCHEMA_VERSION = 1

// ─── Payout destinations ────────────────────────────────────────────
//
// Light-touch validation only: enough to catch paste mistakes in the UI.
// The coordinator re-validates before paying (it is the party that loses
// money on a bad destination, and rails evolve faster than relays).

const LIGHTNING_ADDRESS_RE = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i
const BOLT12_RE = /^lno1[02-9ac-hj-np-z]{20,}$/i
const ONCHAIN_BECH32_RE = /^(bc1|tb1)[02-9ac-hj-np-z]{8,87}$/i
const ONCHAIN_BASE58_RE = /^[13][1-9A-HJ-NP-Za-km-z]{25,34}$/

export function validatePayoutDestination (value) {
  if (typeof value !== 'string') return null
  const v = value.trim()
  if (!v || v.length > 320) return null
  if (BOLT12_RE.test(v)) return { type: 'bolt12', value: v }
  if (ONCHAIN_BECH32_RE.test(v) || ONCHAIN_BASE58_RE.test(v)) return { type: 'onchain', value: v }
  if (LIGHTNING_ADDRESS_RE.test(v)) return { type: 'lightning-address', value: v.toLowerCase() }
  return null
}

// ─── Claim signing ──────────────────────────────────────────────────
//
// Deterministic JSON (sorted keys, no whitespace) so signer and verifier
// derive the identical byte string from the same logical claim.

export function canonicalJson (obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj)
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJson).join(',') + ']'
  const keys = Object.keys(obj).sort()
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJson(obj[k])).join(',') + '}'
}

export function claimDigest (relayPubkey, claimBody) {
  const json = b4a.from(canonicalJson(claimBody), 'utf8')
  const concatenated = b4a.concat([relayPubkey, json])
  const out = b4a.alloc(32)
  sodium.crypto_hash_sha256(out, concatenated)
  return out
}

export function signClaim (keyPair, claimBody) {
  const digest = claimDigest(keyPair.publicKey, claimBody)
  const sig = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(sig, digest, keyPair.secretKey)
  return sig
}

/** Verify a signed claim envelope ({ body, relayPubkey, signature }). */
export function verifyClaim ({ body, relayPubkey, signature }) {
  if (!body || !relayPubkey || !signature) return false
  if (relayPubkey.byteLength !== 32 || signature.byteLength !== 64) return false
  const digest = claimDigest(relayPubkey, body)
  return sodium.crypto_sign_verify_detached(signature, digest, relayPubkey)
}

const utcDayKey = (ts) => new Date(ts).toISOString().slice(0, 10)

// Defensive number pluck — stats shapes vary across node configs.
const num = (x) => (Number.isFinite(x) ? x : 0)

export class SubsidyAccrual extends EventEmitter {
  constructor (opts = {}) {
    super()
    if (!opts.keyPair || !opts.keyPair.publicKey || !opts.keyPair.secretKey) {
      throw new Error('SubsidyAccrual: keyPair is required (claims are signed)')
    }
    this.keyPair = opts.keyPair
    this.statsFn = typeof opts.statsFn === 'function' ? opts.statsFn : () => ({})
    this.storagePath = opts.storagePath || null
    this.rateSatsPerDay = Number.isFinite(opts.rateSatsPerDay) && opts.rateSatsPerDay >= 0
      ? opts.rateSatsPerDay
      : DEFAULT_RATE_SATS_PER_DAY
    this.epochMs = Number.isFinite(opts.epochMs)
      ? Math.max(MIN_EPOCH_MS, opts.epochMs)
      : DEFAULT_EPOCH_MS

    this.payoutDestination = null
    if (opts.payoutDestination) {
      // Invalid configured destination is a hard error at construction —
      // silently dropping it would let an operator believe they enrolled.
      this.payoutDestination = validatePayoutDestination(opts.payoutDestination)
      if (!this.payoutDestination) {
        throw new Error('SubsidyAccrual: invalid payoutDestination: ' + opts.payoutDestination)
      }
    }

    this.periodStart = null // set on first epoch after start/claim reset
    this.accruedSatsTotal = 0
    this.epochs = []
    this._dayKey = null
    this._dayAccrued = 0
    this._lastEpochAt = null
    this._interval = null
    this._persisting = Promise.resolve()
  }

  async start () {
    await this._load()
    // Timer only marks elapsed wall-clock epochs; tests drive _tick(now)
    // directly for deterministic time.
    this._interval = setInterval(() => {
      this._tick(Date.now()).catch(err => this.emit('error', err))
    }, this.epochMs)
    if (this._interval.unref) this._interval.unref()
  }

  async destroy () {
    if (this._interval) {
      clearInterval(this._interval)
      this._interval = null
    }
    await this._persist()
  }

  /**
   * Record one elapsed epoch ending at `now`. Accrues capped estimate +
   * evidence snapshot. Exposed (not underscore-private in spirit) so
   * tests can drive time; production only calls it from the timer.
   */
  async _tick (now = Date.now()) {
    const stats = this.statsFn() || {}
    const day = utcDayKey(now)
    if (day !== this._dayKey) {
      this._dayKey = day
      this._dayAccrued = 0
    }

    const proRata = this.rateSatsPerDay * (this.epochMs / DAY_MS)
    const remaining = Math.max(0, this.rateSatsPerDay - this._dayAccrued)
    const accrued = Math.min(proRata, remaining)
    this._dayAccrued += accrued
    this.accruedSatsTotal += accrued
    if (this.periodStart === null) this.periodStart = now - this.epochMs
    this._lastEpochAt = now

    this.epochs.push({
      ts: now,
      ms: this.epochMs,
      sats: accrued,
      connections: num(stats.connections),
      seededApps: num(stats.seededApps),
      anchored: num(stats.appRegistry && stats.appRegistry.anchored)
    })
    if (this.epochs.length > MAX_EPOCHS_RETAINED) {
      this.epochs.splice(0, this.epochs.length - MAX_EPOCHS_RETAINED)
    }

    this.emit('epoch', { ts: now, accruedSats: accrued })
    await this._persist()
  }

  /**
   * Set/replace/clear the payout destination. Returns the normalized
   * { type, value }, null when cleared, or throws on an unrecognizable
   * destination.
   */
  async setPayoutDestination (value) {
    const previous = this.payoutDestination
    if (value === null || value === undefined || (typeof value === 'string' && value.trim() === '')) {
      this.payoutDestination = null
      try {
        await this._persist({ throwOnError: true })
      } catch (err) {
        this.payoutDestination = previous
        throw err
      }
      this.emit('destination', null)
      return null
    }
    const dest = validatePayoutDestination(value)
    if (!dest) throw new Error('Unrecognized payout destination (expected lightning address, BOLT12 offer, or bitcoin address)')
    this.payoutDestination = dest
    try {
      await this._persist({ throwOnError: true })
    } catch (err) {
      this.payoutDestination = previous
      throw err
    }
    this.emit('destination', dest)
    return dest
  }

  getSummary () {
    return {
      schemaVersion: SUBSIDY_SCHEMA_VERSION,
      estimate: true, // coordinator verification decides actual payout
      rateSatsPerDay: this.rateSatsPerDay,
      accruedSatsTotal: Math.floor(this.accruedSatsTotal),
      accruedSatsToday: Math.floor(this._dayAccrued),
      epochCount: this.epochs.length,
      periodStart: this.periodStart,
      lastEpochAt: this._lastEpochAt,
      payoutDestination: this.payoutDestination
    }
  }

  /**
   * Build the signed claim envelope for the current accrual period.
   * Wire-friendly: buffers rendered as hex.
   */
  buildClaim (now = Date.now()) {
    const first = this.epochs[0] || null
    const last = this.epochs[this.epochs.length - 1] || null
    const body = {
      schemaVersion: SUBSIDY_SCHEMA_VERSION,
      relayPubkey: b4a.toString(this.keyPair.publicKey, 'hex'),
      periodStart: first ? first.ts - first.ms : this.periodStart,
      periodEnd: last ? last.ts : this._lastEpochAt,
      epochCount: this.epochs.length,
      uptimeMs: this.epochs.reduce((a, e) => a + e.ms, 0),
      accruedSatsEstimate: Math.floor(this.accruedSatsTotal),
      evidence: {
        avgConnections: this.epochs.length
          ? Math.round(this.epochs.reduce((a, e) => a + e.connections, 0) / this.epochs.length)
          : 0,
        seededAppsAtEnd: last ? last.seededApps : 0,
        anchoredAtEnd: last ? last.anchored : 0
      },
      payoutDestination: this.payoutDestination,
      createdAt: now
    }
    const signature = signClaim(this.keyPair, body)
    return {
      body,
      relayPubkey: b4a.toString(this.keyPair.publicKey, 'hex'),
      signature: b4a.toString(signature, 'hex'),
      digest: b4a.toString(claimDigest(this.keyPair.publicKey, body), 'hex')
    }
  }

  // ─── Persistence (atomic tmp+rename, v0.10.6 pattern) ────────────

  async _load () {
    if (!this.storagePath) return
    try {
      const raw = await readFile(this.storagePath, 'utf8')
      const data = JSON.parse(raw)
      if (data.schemaVersion !== SUBSIDY_SCHEMA_VERSION) return
      this.accruedSatsTotal = num(data.accruedSatsTotal)
      this.epochs = Array.isArray(data.epochs) ? data.epochs.slice(-MAX_EPOCHS_RETAINED) : []
      this.periodStart = data.periodStart ?? null
      this._lastEpochAt = data.lastEpochAt ?? null
      this._dayKey = data.dayKey ?? null
      this._dayAccrued = num(data.dayAccrued)
      if (data.payoutDestination && validatePayoutDestination(data.payoutDestination.value)) {
        this.payoutDestination = data.payoutDestination
      }
    } catch {
      // Missing or corrupt file -> start fresh. Accrual evidence is also
      // reconstructable by the coordinator from fleet observations.
    }
  }

  async _persist ({ throwOnError = false } = {}) {
    if (!this.storagePath) return
    // Serialize writers: a tick and a destination change can race.
    const write = this._persisting.then(() => this._write())
    this._persisting = write.catch(err => {
      this.emit('persist-error', {
        message: err && err.message ? err.message : String(err || 'unknown error'),
        error: err
      })
    })
    return throwOnError ? write : this._persisting
  }

  async _write () {
    const tmp = this.storagePath + '.tmp'
    const data = JSON.stringify({
      schemaVersion: SUBSIDY_SCHEMA_VERSION,
      accruedSatsTotal: this.accruedSatsTotal,
      epochs: this.epochs,
      periodStart: this.periodStart,
      lastEpochAt: this._lastEpochAt,
      dayKey: this._dayKey,
      dayAccrued: this._dayAccrued,
      payoutDestination: this.payoutDestination
    })
    try {
      await mkdir(dirname(this.storagePath), { recursive: true })
      await writeFile(tmp, data)
      await rename(tmp, this.storagePath)
    } catch (err) {
      try { await unlink(tmp) } catch {}
      this.emit('persist-error', err)
    }
  }
}
