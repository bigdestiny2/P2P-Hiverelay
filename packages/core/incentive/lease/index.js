// lease/index.js — paid pin-lease manager (relay side).
//
// Turns the relay's free, opaque-keyed seed/pin into a PAID retention lease
// for the NETWORK case: a publisher paying a relay they do NOT own to keep
// their (encrypted) Hyperdrive online. The economics that make HiveRelay
// sustainable from the demand side, complementing the founder-funded subsidy
// (incentive/subsidy/index.js) which pays operators from the supply side.
//
// Design (see the payment-for-seeding design workflow):
//   - Zero-custody. The relay mints a Lightning invoice on the OPERATOR's OWN
//     node (provider.createInvoice) and verifies it settled (lookupInvoice).
//     Funds land directly in the operator's node — the relay never holds a
//     payer balance. The ONLY durable artifact a payment creates is the lease
//     deadline (entry.retainUntil), enforced by the existing custody-expiry
//     sweep (RelayNode._runCustodyExpiryPass).
//   - Blind model untouched. Pricing keys on (appKey, declared maxStorage,
//     leaseDays) — nothing here reads or inspects content.
//   - Stateless quotes. A quote is a relay-signed, self-contained token
//     (Ed25519 over its body, same digest-then-detached-sign shape as
//     subsidy claims). The relay stores no pending-quote state; only the set
//     of CONSUMED payment hashes is persisted, as a replay-guard.
//   - Self-host stays free: this only gates the publisher-signed seed path
//     (POST /api/v1/seed); operator-API-key seeds (POST /seed) never reach it.
//     Custody / social-recovery seeds are exempt (founder-subsidized, not
//     commercial hosting).
//
// Persistence: <storage>/lease.json via the atomic tmp+rename pattern.

import { EventEmitter } from 'events'
import { readFile, writeFile, rename, unlink, mkdir } from 'fs/promises'
import { dirname } from 'path'
import b4a from 'b4a'
import { canonicalJson, signClaim, verifyClaim } from '../subsidy/index.js'

const GIB = 1024 * 1024 * 1024
const DAY_MS = 86_400_000
export const LEASE_SCHEMA_VERSION = 1
const DEFAULT_SATS_PER_GIB_DAY = 10
const DEFAULT_QUOTE_TTL_MS = 60 * 60 * 1000 // 1h to pay; aligned with invoice expiry
const DEFAULT_MIN_DAYS = 1
const DEFAULT_MAX_DAYS = 3650
const MAX_CONSUMED_RETAINED = 50_000

const num = (x) => (Number.isFinite(x) ? x : 0)

export class LeaseManager extends EventEmitter {
  constructor (opts = {}) {
    super()
    if (!opts.keyPair || !opts.keyPair.publicKey || !opts.keyPair.secretKey) {
      throw new Error('LeaseManager: keyPair is required (quotes are signed)')
    }
    this.keyPair = opts.keyPair
    // PaymentProvider duck-type: needs createInvoice(amountSats, memo) ->
    // { bolt11, rHash } and lookupInvoice(rHash) -> { settled, amount } | null.
    this.provider = opts.provider || null
    this.storagePath = opts.storagePath || null
    this.satsPerGiBDay = Number.isFinite(opts.satsPerGiBDay) && opts.satsPerGiBDay >= 0
      ? opts.satsPerGiBDay
      : DEFAULT_SATS_PER_GIB_DAY
    this.quoteTtlMs = Number.isFinite(opts.quoteTtlMs) && opts.quoteTtlMs > 0
      ? opts.quoteTtlMs
      : DEFAULT_QUOTE_TTL_MS
    this.minDays = Number.isFinite(opts.minDays) && opts.minDays >= 1 ? Math.floor(opts.minDays) : DEFAULT_MIN_DAYS
    this.maxDays = Number.isFinite(opts.maxDays) && opts.maxDays >= 1 ? Math.floor(opts.maxDays) : DEFAULT_MAX_DAYS
    // Operator's own payout destination, informational only — the actual
    // payment instruction is the per-quote bolt11 minted on their node.
    this.payTo = typeof opts.payTo === 'string' ? opts.payTo : null

    this._consumed = new Set() // consumed paymentHash (rHash) — replay-guard
    this.totalLeasedSats = 0
    this.leaseCount = 0
    this._persisting = Promise.resolve()
  }

  async start () {
    await this._load()
    if (this.provider && !this.provider.connected && typeof this.provider.connect === 'function') {
      try { await this.provider.connect() } catch (err) { this.emit('provider-error', err) }
    }
  }

  async destroy () {
    await this._persist()
    if (this.provider && typeof this.provider.disconnect === 'function') {
      try { await this.provider.disconnect() } catch {}
    }
  }

  /** Byte-days price: ceil(maxStorageBytes / GiB) * leaseDays * satsPerGiBDay. */
  quoteSats (maxStorageBytes, leaseDays) {
    const gib = Math.max(1, Math.ceil(num(maxStorageBytes) / GIB))
    const days = Math.max(this.minDays, Math.min(this.maxDays, Math.floor(num(leaseDays) || this.minDays)))
    return { amountSats: gib * days * this.satsPerGiBDay, gib, days }
  }

  /**
   * Mint an invoice on the operator's node and return a self-contained,
   * relay-signed quote. The quoteId encodes { body, signature } so it can be
   * verified later with no server-side pending-quote state.
   */
  async createQuote ({ appKey, maxStorageBytes, leaseDays }, now = Date.now()) {
    if (!this.provider || typeof this.provider.createInvoice !== 'function') {
      throw new Error('LEASE_NO_PROVIDER: no payment provider configured')
    }
    const { amountSats, days } = this.quoteSats(maxStorageBytes, leaseDays)
    const memo = `hiverelay-lease:${String(appKey).slice(0, 16)}:${days}d`
    const inv = await this.provider.createInvoice(amountSats, memo, { expirySeconds: Math.floor(this.quoteTtlMs / 1000) })
    const paymentHash = inv.rHash || inv.paymentHash || inv.r_hash || null
    const bolt11 = inv.bolt11 || inv.invoice || inv.payment_request || null
    if (!paymentHash || !bolt11) throw new Error('LEASE_INVOICE_MALFORMED: provider returned no rHash/bolt11')

    const body = {
      v: LEASE_SCHEMA_VERSION,
      appKey: String(appKey).toLowerCase(),
      maxStorageBytes: Math.floor(num(maxStorageBytes)),
      leaseDays: days,
      amountSats,
      paymentHash,
      expiresAt: now + this.quoteTtlMs
    }
    const signature = b4a.toString(signClaim(this.keyPair, body), 'hex')
    const quoteId = b4a.toString(b4a.from(canonicalJson({ body, signature }), 'utf8'), 'base64url')

    this.emit('quote', { appKey: body.appKey, amountSats, leaseDays: days })
    return { amountSats, bolt11, quoteId, expiresAt: body.expiresAt, leaseDays: days, payTo: this.payTo }
  }

  /** Decode + verify the relay's own signature over a quoteId. */
  _decodeQuote (quoteId) {
    if (typeof quoteId !== 'string' || quoteId.length < 1 || quoteId.length > 8192) return null
    let parsed
    try {
      parsed = JSON.parse(b4a.toString(b4a.from(quoteId, 'base64url'), 'utf8'))
    } catch { return null }
    if (!parsed || typeof parsed !== 'object' || !parsed.body || typeof parsed.signature !== 'string') return null
    const ok = verifyClaim({
      body: parsed.body,
      relayPubkey: this.keyPair.publicKey,
      signature: b4a.from(parsed.signature, 'hex')
    })
    if (!ok) return null
    return parsed.body
  }

  /**
   * Verify a paid lease for a resubmitted seed request.
   * @returns {{ ok: true, paidUntil, amountSats, leaseDays } | { ok: false, error, status }}
   */
  async verifyLease ({ appKey, quoteId }, now = Date.now()) {
    const body = this._decodeQuote(quoteId)
    if (!body) return { ok: false, error: 'LEASE_BAD_QUOTE: quote missing or signature invalid', status: 402 }
    if (String(appKey).toLowerCase() !== body.appKey) {
      return { ok: false, error: 'LEASE_QUOTE_APPKEY_MISMATCH: quote is for a different appKey', status: 402 }
    }
    if (!Number.isFinite(body.expiresAt) || body.expiresAt <= now) {
      return { ok: false, error: 'LEASE_QUOTE_EXPIRED: request a fresh quote', status: 402 }
    }
    if (this._consumed.has(body.paymentHash)) {
      return { ok: false, error: 'LEASE_REPLAY: this payment was already redeemed', status: 402 }
    }
    if (!this.provider || typeof this.provider.lookupInvoice !== 'function') {
      return { ok: false, error: 'LEASE_NO_PROVIDER: cannot verify payment', status: 503 }
    }
    let status
    try {
      status = await this.provider.lookupInvoice(body.paymentHash)
    } catch (err) {
      return { ok: false, error: 'LEASE_LOOKUP_FAILED: ' + (err.message || String(err)), status: 503 }
    }
    if (!status || !status.settled) {
      return { ok: false, error: 'LEASE_UNPAID: invoice not settled yet', status: 402 }
    }
    if (num(status.amount) < body.amountSats) {
      return { ok: false, error: 'LEASE_UNDERPAID: settled amount below quote', status: 402 }
    }

    // Consume + record. Replay-guard must persist before we admit the lease.
    this._consumed.add(body.paymentHash)
    if (this._consumed.size > MAX_CONSUMED_RETAINED) {
      // Drop oldest insertion-order entries; a redeemed hash older than the
      // longest quote TTL can never be replayed against a live quote anyway.
      const overflow = this._consumed.size - MAX_CONSUMED_RETAINED
      let i = 0
      for (const h of this._consumed) { if (i++ >= overflow) break; this._consumed.delete(h) }
    }
    this.totalLeasedSats += body.amountSats
    this.leaseCount += 1
    await this._persist()

    const paidUntil = now + body.leaseDays * DAY_MS
    this.emit('lease-paid', { appKey: body.appKey, amountSats: body.amountSats, leaseDays: body.leaseDays, paidUntil })
    return { ok: true, paidUntil, amountSats: body.amountSats, leaseDays: body.leaseDays }
  }

  getSummary () {
    return {
      enabled: true,
      satsPerGiBDay: this.satsPerGiBDay,
      minDays: this.minDays,
      maxDays: this.maxDays,
      payTo: this.payTo,
      totalLeasedSats: Math.floor(this.totalLeasedSats),
      leaseCount: this.leaseCount,
      provider: this.provider ? (this.provider.constructor && this.provider.constructor.name) || 'unknown' : null,
      providerConnected: !!(this.provider && this.provider.connected)
    }
  }

  setRate (satsPerGiBDay) {
    if (!Number.isFinite(satsPerGiBDay) || satsPerGiBDay < 0) throw new Error('satsPerGiBDay must be a non-negative number')
    this.satsPerGiBDay = Math.floor(satsPerGiBDay)
    this._persist().catch(() => {})
    this.emit('rate', this.satsPerGiBDay)
    return this.satsPerGiBDay
  }

  // ─── Persistence (atomic tmp+rename) ───────────────────────────────

  async _load () {
    if (!this.storagePath) return
    try {
      const data = JSON.parse(await readFile(this.storagePath, 'utf8'))
      if (data.schemaVersion !== LEASE_SCHEMA_VERSION) return
      this._consumed = new Set(Array.isArray(data.consumed) ? data.consumed.slice(-MAX_CONSUMED_RETAINED) : [])
      this.totalLeasedSats = num(data.totalLeasedSats)
      this.leaseCount = num(data.leaseCount)
      if (Number.isFinite(data.satsPerGiBDay) && data.satsPerGiBDay >= 0) this.satsPerGiBDay = data.satsPerGiBDay
    } catch {
      // Missing/corrupt -> start fresh. A lost replay-guard only risks at most
      // one extra redemption per still-live quote window, never silent loss.
    }
  }

  async _persist () {
    if (!this.storagePath) return
    this._persisting = this._persisting.then(() => this._write()).catch(() => {})
    return this._persisting
  }

  async _write () {
    const tmp = this.storagePath + '.tmp'
    const data = JSON.stringify({
      schemaVersion: LEASE_SCHEMA_VERSION,
      consumed: Array.from(this._consumed),
      totalLeasedSats: this.totalLeasedSats,
      leaseCount: this.leaseCount,
      satsPerGiBDay: this.satsPerGiBDay
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
