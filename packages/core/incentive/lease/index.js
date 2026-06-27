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
import { randomBytes, createHash } from 'crypto'
import { readFile, writeFile, rename, unlink, mkdir } from 'fs/promises'
import { dirname } from 'path'
import b4a from 'b4a'
import { canonicalJson, signClaim, verifyClaim } from '../subsidy/index.js'
import { BlindMint } from '../payment/blind-mint.js'
import { buildKeyset, decodeToken } from '../payment/cashu.js'

const GIB = 1024 * 1024 * 1024
const DAY_MS = 86_400_000
export const LEASE_SCHEMA_VERSION = 1
const DEFAULT_SATS_PER_GIB_DAY = 10
const DEFAULT_QUOTE_TTL_MS = 60 * 60 * 1000 // 1h to pay; aligned with invoice expiry
const DEFAULT_MIN_DAYS = 1
const DEFAULT_MAX_DAYS = 3650
const DEFAULT_MAX_SATS_PER_GIB_DAY = 1_000_000
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
    this.maxSatsPerGiBDay = Number.isFinite(opts.maxSatsPerGiBDay) && opts.maxSatsPerGiBDay > 0
      ? Math.floor(opts.maxSatsPerGiBDay)
      : DEFAULT_MAX_SATS_PER_GIB_DAY
    // Operator's own payout destination, informational only — the actual
    // payment instruction is the per-quote bolt11 minted on their node.
    this.payTo = typeof opts.payTo === 'string' ? opts.payTo : null

    // Replay-guard: consumed paymentHash (rHash) -> the quote's expiresAt. A
    // consumed hash can never pass the expiresAt gate again, so once its quote
    // has expired it is safe to drop; we ONLY ever evict already-expired
    // entries, never a still-live one (which would re-open a replay).
    this._consumed = new Map()
    // Payment hashes (and voucher serials) with a settlement check IN FLIGHT.
    // Claimed synchronously before the async lookupInvoice so two concurrent
    // redemptions of the same payment can't both pass the consumed-check, both
    // settle, and both grant a lease (TOCTOU double-spend). Released in finally.
    this._inflight = new Set()
    this.totalLeasedSats = 0
    this.leaseCount = 0
    this._persisting = Promise.resolve()

    // Optional Chaumian-blind mint (full payer↔content unlinkability). The mint
    // key is derived deterministically from this relay's keyPair, so it is
    // stable across restarts with no extra persistence. Blind tokens are
    // single-DENOMINATION: an operator enables them by setting
    // blindDenomination = { maxStorageBytes, leaseDays }; a paid quote for
    // exactly that denomination can be converted to an unlinkable token.
    // (Production: per-denomination keysets + a dedicated spent-secret store.)
    try {
      this.blindMint = opts.blindMint || new BlindMint({ keyPair: this.keyPair })
    } catch (_) {
      this.blindMint = null
    }
    this.blindDenomination = (opts.blindDenomination && Number.isFinite(opts.blindDenomination.maxStorageBytes) && Number.isFinite(opts.blindDenomination.leaseDays))
      ? { maxStorageBytes: Math.floor(opts.blindDenomination.maxStorageBytes), leaseDays: Math.floor(opts.blindDenomination.leaseDays) }
      : null
  }

  async start (opts = {}) {
    await this._load(opts.now)
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
   * Run `fn` under a single-use lock on `key`, so a CONCURRENT redemption of
   * the same payment/voucher can't slip through the (async) settlement window.
   * Returns the REPLAY error if the key is already consumed or in flight.
   * @param {string} key  paymentHash or voucher serial guard key
   * @param {() => Promise<object>} fn
   */
  async _withRedemptionLock (key, fn) {
    if (this._consumed.has(key) || this._inflight.has(key)) {
      return { ok: false, error: 'LEASE_REPLAY: this payment was already redeemed', status: 402 }
    }
    this._inflight.add(key)
    try {
      return await fn()
    } finally {
      this._inflight.delete(key)
    }
  }

  /**
   * Verify a paid lease for a resubmitted seed request.
   * @returns {{ ok: true, paidUntil, amountSats, leaseDays } | { ok: false, error, status }}
   */
  async verifyLease ({ appKey, quoteId, maxStorageBytes }, now = Date.now()) {
    const body = this._decodeQuote(quoteId)
    if (!body) return { ok: false, error: 'LEASE_BAD_QUOTE: quote missing or signature invalid', status: 402 }
    if (String(appKey).toLowerCase() !== body.appKey) {
      return { ok: false, error: 'LEASE_QUOTE_APPKEY_MISMATCH: quote is for a different appKey', status: 402 }
    }
    // Bind storage: the seed can't ask for MORE than the quote was priced for
    // (else quote-cheap-at-1GiB, then seed-big). Equal/less is fine.
    if (Number.isFinite(maxStorageBytes) && Math.floor(maxStorageBytes) > body.maxStorageBytes) {
      return { ok: false, error: 'LEASE_STORAGE_EXCEEDS_QUOTE: requested maxStorage exceeds the quoted amount', status: 402 }
    }
    if (!Number.isFinite(body.expiresAt) || body.expiresAt <= now) {
      return { ok: false, error: 'LEASE_QUOTE_EXPIRED: request a fresh quote', status: 402 }
    }
    if (!this.provider || typeof this.provider.lookupInvoice !== 'function') {
      return { ok: false, error: 'LEASE_NO_PROVIDER: cannot verify payment', status: 503 }
    }
    return this._withRedemptionLock(body.paymentHash, async () => {
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

      // Overflow trim: drop ONLY entries whose quote already expired (those can
      // never pass the expiresAt gate again, so dropping them cannot re-open a
      // replay). If still at cap with every entry live, refuse rather than evict
      // a still-redeemable hash.
      if (this._consumed.size >= MAX_CONSUMED_RETAINED) {
        for (const [h, exp] of this._consumed) {
          if (!Number.isFinite(exp) || exp <= now) this._consumed.delete(h)
        }
        if (this._consumed.size >= MAX_CONSUMED_RETAINED) {
          return { ok: false, error: 'LEASE_GUARD_FULL: replay-guard saturated; retry shortly', status: 503 }
        }
      }

      // Consume + record. The replay-guard MUST be durable before we admit the
      // lease — if the write fails, roll back so we never admit an un-guarded
      // (replayable) lease.
      this._consumed.set(body.paymentHash, body.expiresAt)
      this.totalLeasedSats += body.amountSats
      this.leaseCount += 1
      try {
        await this._persist()
      } catch (err) {
        this._consumed.delete(body.paymentHash)
        this.totalLeasedSats -= body.amountSats
        this.leaseCount -= 1
        this.emit('persist-error', err)
        return { ok: false, error: 'LEASE_PERSIST_FAILED: could not durably record payment; retry', status: 503 }
      }

      const paidUntil = now + body.leaseDays * DAY_MS
      this.emit('lease-paid', { appKey: body.appKey, amountSats: body.amountSats, leaseDays: body.leaseDays, paidUntil })
      return { ok: true, paidUntil, amountSats: body.amountSats, leaseDays: body.leaseDays }
    })
  }

  // ─── Bearer vouchers (opt-in, payer-unlinkable to content) ─────────
  //
  // The standard quote BINDS the payment to a specific appKey (body.appKey,
  // checked in verifyLease). That binding lets the operator link "who paid"
  // to "what content" — the one linkage the rest of the blind design avoids.
  //
  // A bearer voucher breaks it: the payer buys a voucher (priced for
  // maxStorageBytes × leaseDays) that carries a RANDOM serial and NO appKey.
  // Later they redeem it to seed ANY appKey. verifyBearer never learns which
  // payment funded which content. Replay is guarded by serial, exactly like
  // paymentHash for quotes.
  //
  // Honesty bound: this decouples payment↔appKey (the primary leak). It does
  // NOT by itself blind issuance — an operator could still correlate the
  // invoice it settled at issue() time with the serial it signed. Full
  // issue↔redeem unlinkability requires a blind-signature/ecash provider
  // (e.g. Cashu) issuing the serial; such a provider can be plugged in by
  // having it mint the voucher body and this relay simply honor its
  // signatures. The seam is intentional and documented.

  /**
   * Issue a bearer voucher from an ALREADY-PAID quote. The quote proves
   * settlement (and is consumed here so it can't also be spent as a direct
   * lease); the returned voucher carries only a random serial + the byte-days
   * envelope — never the appKey, never the paymentHash.
   *
   * @returns {{ ok:true, voucherId, amountSats, leaseDays, expiresAt } | { ok:false, error, status }}
   */
  async issueBearerVoucher ({ quoteId }, now = Date.now()) {
    const body = this._decodeQuote(quoteId)
    if (!body) return { ok: false, error: 'LEASE_BAD_QUOTE: quote missing or signature invalid', status: 402 }
    if (!Number.isFinite(body.expiresAt) || body.expiresAt <= now) {
      return { ok: false, error: 'LEASE_QUOTE_EXPIRED: request a fresh quote', status: 402 }
    }
    if (!this.provider || typeof this.provider.lookupInvoice !== 'function') {
      return { ok: false, error: 'LEASE_NO_PROVIDER: cannot verify payment', status: 503 }
    }
    return this._withRedemptionLock(body.paymentHash, async () => {
      let status
      try {
        status = await this.provider.lookupInvoice(body.paymentHash)
      } catch (err) {
        return { ok: false, error: 'LEASE_LOOKUP_FAILED: ' + (err.message || String(err)), status: 503 }
      }
      if (!status || !status.settled) return { ok: false, error: 'LEASE_UNPAID: invoice not settled yet', status: 402 }
      if (num(status.amount) < body.amountSats) return { ok: false, error: 'LEASE_UNDERPAID: settled amount below quote', status: 402 }

      // Consume the paymentHash so it can't be redeemed twice (as a lease or a
      // second voucher). The voucher's own replay-guard is its serial.
      this._consumed.set(body.paymentHash, body.expiresAt)
      // Voucher lives for the lease window (generous): payer may seed later.
      const voucherExpiresAt = now + Math.max(this.maxDays, body.leaseDays) * DAY_MS
      const voucherBody = {
        v: LEASE_SCHEMA_VERSION,
        kind: 'bearer',
        serial: b4a.toString(randomBytes(32), 'hex'),
        maxStorageBytes: body.maxStorageBytes,
        leaseDays: body.leaseDays,
        amountSats: body.amountSats,
        expiresAt: voucherExpiresAt
      }
      const signature = b4a.toString(signClaim(this.keyPair, voucherBody), 'hex')
      const voucherId = b4a.toString(b4a.from(canonicalJson({ body: voucherBody, signature }), 'utf8'), 'base64url')
      try {
        await this._persist()
      } catch (err) {
        this._consumed.delete(body.paymentHash)
        this.emit('persist-error', err)
        return { ok: false, error: 'LEASE_PERSIST_FAILED: could not durably record issuance; retry', status: 503 }
      }
      this.emit('bearer-issued', { amountSats: body.amountSats, leaseDays: body.leaseDays })
      return { ok: true, voucherId, amountSats: body.amountSats, leaseDays: body.leaseDays, expiresAt: voucherExpiresAt }
    })
  }

  /** Decode + verify the relay's own signature over a bearer voucherId. */
  _decodeVoucher (voucherId) {
    if (typeof voucherId !== 'string' || voucherId.length < 1 || voucherId.length > 8192) return null
    let parsed
    try {
      parsed = JSON.parse(b4a.toString(b4a.from(voucherId, 'base64url'), 'utf8'))
    } catch { return null }
    if (!parsed || typeof parsed !== 'object' || !parsed.body || typeof parsed.signature !== 'string') return null
    if (parsed.body.kind !== 'bearer' || typeof parsed.body.serial !== 'string') return null
    const ok = verifyClaim({
      body: parsed.body,
      relayPubkey: this.keyPair.publicKey,
      signature: b4a.from(parsed.signature, 'hex')
    })
    return ok ? parsed.body : null
  }

  /**
   * Redeem a bearer voucher for a lease. Grants the lease WITHOUT inspecting
   * the appKey — payment and content stay unlinked. Single-use via serial.
   * @returns {{ ok:true, paidUntil, amountSats, leaseDays } | { ok:false, error, status }}
   */
  async verifyBearer ({ voucherId, maxStorageBytes }, now = Date.now()) {
    const body = this._decodeVoucher(voucherId)
    if (!body) return { ok: false, error: 'LEASE_BAD_VOUCHER: voucher missing or signature invalid', status: 402 }
    if (Number.isFinite(maxStorageBytes) && Math.floor(maxStorageBytes) > body.maxStorageBytes) {
      return { ok: false, error: 'LEASE_STORAGE_EXCEEDS_VOUCHER: requested maxStorage exceeds the voucher', status: 402 }
    }
    if (!Number.isFinite(body.expiresAt) || body.expiresAt <= now) {
      return { ok: false, error: 'LEASE_VOUCHER_EXPIRED', status: 402 }
    }
    const guardKey = 'bearer:' + body.serial
    if (this._consumed.has(guardKey)) {
      return { ok: false, error: 'LEASE_REPLAY: voucher already redeemed', status: 402 }
    }
    if (this._consumed.size >= MAX_CONSUMED_RETAINED) {
      for (const [h, exp] of this._consumed) {
        if (!Number.isFinite(exp) || exp <= now) this._consumed.delete(h)
      }
      if (this._consumed.size >= MAX_CONSUMED_RETAINED) {
        return { ok: false, error: 'LEASE_GUARD_FULL: replay-guard saturated; retry shortly', status: 503 }
      }
    }
    this._consumed.set(guardKey, body.expiresAt)
    this.totalLeasedSats += body.amountSats
    this.leaseCount += 1
    try {
      await this._persist()
    } catch (err) {
      this._consumed.delete(guardKey)
      this.totalLeasedSats -= body.amountSats
      this.leaseCount -= 1
      this.emit('persist-error', err)
      return { ok: false, error: 'LEASE_PERSIST_FAILED: could not durably record redemption; retry', status: 503 }
    }
    const paidUntil = now + body.leaseDays * DAY_MS
    this.emit('lease-paid', { bearer: true, amountSats: body.amountSats, leaseDays: body.leaseDays, paidUntil })
    return { ok: true, paidUntil, amountSats: body.amountSats, leaseDays: body.leaseDays }
  }

  // ─── Blind tokens (Cashu NUT-00, fully unlinkable — opt-in) ────────
  //
  // Strongest tier: the payer blinds their own secret, so the mint cannot link
  // the settled invoice to the redeemed token. Backed by a real secp256k1 Cashu
  // mint (incentive/payment/blind-mint.js + cashu.js), so a token IS a standard
  // Cashu Proof / `cashuA` token. Enabled only when blindDenomination is set.

  /** Sats price of the configured blind denomination (the Cashu amount). */
  _denomSats () {
    return this.quoteSats(this.blindDenomination.maxStorageBytes, this.blindDenomination.leaseDays).amountSats
  }

  /** The relay's NUT-01/02 keyset for the blind denomination (memoized). */
  _blindKeyset () {
    if (!this._keyset) this._keyset = buildKeyset(this.blindMint, this._denomSats(), 'sat')
    return this._keyset
  }

  /**
   * Mint advertisement for the capability doc, or null when disabled. Includes
   * a real Cashu keyset (id + amount->pubkey) so wallets can recognise it.
   */
  blindMintInfo () {
    if (!this.blindMint || !this.blindDenomination) return null
    return {
      pubkey: this.blindMint.publicKey,
      denomination: { ...this.blindDenomination },
      keyset: this._blindKeyset() // { id, unit, keys: { [sats]: pubkey } }
    }
  }

  /**
   * Convert a settled quote (priced for exactly the configured denomination)
   * into a blind signature over the payer's blinded message. The relay never
   * sees the token secret.
   * @returns {{ ok:true, blindSignature, mintPubkey, leaseDays, maxStorageBytes } | { ok:false, error, status }}
   */
  async issueBlindVoucher ({ quoteId, blinded }, now = Date.now()) {
    if (!this.blindMint || !this.blindDenomination) {
      return { ok: false, error: 'LEASE_BLIND_DISABLED: operator has not enabled blind tokens', status: 400 }
    }
    const body = this._decodeQuote(quoteId)
    if (!body) return { ok: false, error: 'LEASE_BAD_QUOTE: quote missing or signature invalid', status: 402 }
    // Denomination must match exactly — a single-denomination mint can't sign
    // for an arbitrary (storage, days) without leaking it into the token.
    if (body.maxStorageBytes !== this.blindDenomination.maxStorageBytes || body.leaseDays !== this.blindDenomination.leaseDays) {
      return { ok: false, error: 'LEASE_BLIND_DENOMINATION_MISMATCH: quote does not match the blind denomination', status: 402 }
    }
    if (!Number.isFinite(body.expiresAt) || body.expiresAt <= now) {
      return { ok: false, error: 'LEASE_QUOTE_EXPIRED: request a fresh quote', status: 402 }
    }
    if (!this.provider || typeof this.provider.lookupInvoice !== 'function') {
      return { ok: false, error: 'LEASE_NO_PROVIDER: cannot verify payment', status: 503 }
    }
    return this._withRedemptionLock(body.paymentHash, async () => {
      let status
      try {
        status = await this.provider.lookupInvoice(body.paymentHash)
      } catch (err) {
        return { ok: false, error: 'LEASE_LOOKUP_FAILED: ' + (err.message || String(err)), status: 503 }
      }
      if (!status || !status.settled) return { ok: false, error: 'LEASE_UNPAID: invoice not settled yet', status: 402 }
      if (num(status.amount) < body.amountSats) return { ok: false, error: 'LEASE_UNDERPAID: settled amount below quote', status: 402 }

      let blindSignature
      try {
        blindSignature = this.blindMint.blindSign(blinded)
      } catch (err) {
        return { ok: false, error: 'LEASE_BLIND_SIGN_FAILED: ' + (err.message || String(err)), status: 400 }
      }
      // Consume the funding payment so it can't also be spent elsewhere.
      this._consumed.set(body.paymentHash, body.expiresAt)
      try {
        await this._persist()
      } catch (err) {
        this._consumed.delete(body.paymentHash)
        this.emit('persist-error', err)
        return { ok: false, error: 'LEASE_PERSIST_FAILED: could not durably record issuance; retry', status: 503 }
      }
      this.emit('blind-issued', { amountSats: body.amountSats, leaseDays: body.leaseDays })
      const keyset = this._blindKeyset()
      // blindSignature is the NUT-00 C_; the payer unblinds it and assembles a
      // Proof { amount, id, secret, C }. amount/keysetId let them build a token.
      return {
        ok: true,
        blindSignature,
        mintPubkey: this.blindMint.publicKey,
        keysetId: keyset.id,
        amount: this._denomSats(),
        leaseDays: body.leaseDays,
        maxStorageBytes: body.maxStorageBytes
      }
    })
  }

  /**
   * Convenience: redeem a `cashuA` token string (decodes the proof, checks the
   * keyset id + amount match this mint's denomination, then redeems it).
   * Backwards-compatible call shapes:
   *   redeemCashuToken(token, now)
   *   redeemCashuToken(token, { maxStorageBytes }, now)
   * @returns {{ ok:true, paidUntil, leaseDays } | { ok:false, error, status }}
   */
  async redeemCashuToken (token, opts = {}, now = Date.now()) {
    if (Number.isFinite(opts)) {
      now = opts
      opts = {}
    }
    if (!opts || typeof opts !== 'object') opts = {}
    if (!this.blindMint || !this.blindDenomination) {
      return { ok: false, error: 'LEASE_BLIND_DISABLED', status: 400 }
    }
    let proof
    try {
      const decoded = decodeToken(token)
      proof = decoded.proofs && decoded.proofs[0]
    } catch (err) {
      return { ok: false, error: 'LEASE_BLIND_BAD_TOKEN: ' + (err.message || String(err)), status: 400 }
    }
    if (!proof || typeof proof.secret !== 'string' || typeof proof.C !== 'string') {
      return { ok: false, error: 'LEASE_BLIND_BAD_TOKEN: token has no usable proof', status: 400 }
    }
    const keyset = this._blindKeyset()
    if (proof.id && proof.id !== keyset.id) {
      return { ok: false, error: 'LEASE_BLIND_WRONG_KEYSET: token is for a different keyset', status: 402 }
    }
    if (Number.isFinite(proof.amount) && proof.amount !== this._denomSats()) {
      return { ok: false, error: 'LEASE_BLIND_WRONG_AMOUNT: token amount != denomination', status: 402 }
    }
    const maxStorageBytes = Number.isFinite(opts.maxStorageBytes) ? opts.maxStorageBytes : opts.maxStorage
    return this.redeemBlindVoucher({ secret: proof.secret, C: proof.C, maxStorageBytes }, now)
  }

  /**
   * Redeem a blind token (secret, C) for a lease at the configured
   * denomination. Single-use via a spent-secret guard. The relay learns
   * nothing tying this token to which payment funded it.
   * @returns {{ ok:true, paidUntil, leaseDays } | { ok:false, error, status }}
   */
  async redeemBlindVoucher ({ secret, C, maxStorageBytes }, now = Date.now()) {
    if (!this.blindMint || !this.blindDenomination) {
      return { ok: false, error: 'LEASE_BLIND_DISABLED', status: 400 }
    }
    if (typeof secret !== 'string' || typeof C !== 'string') {
      return { ok: false, error: 'LEASE_BLIND_BAD_TOKEN: secret and C required', status: 400 }
    }
    if (Number.isFinite(maxStorageBytes) && Math.floor(maxStorageBytes) > this.blindDenomination.maxStorageBytes) {
      return { ok: false, error: 'LEASE_STORAGE_EXCEEDS_VOUCHER: exceeds the blind denomination', status: 402 }
    }
    if (!this.blindMint.verifyToken(secret, C)) {
      return { ok: false, error: 'LEASE_BLIND_INVALID: token does not verify against the mint', status: 402 }
    }
    // Double-spend guard keyed on a hash of the secret. Blind tokens carry no
    // expiry of their own, so the spent marker must not expire either.
    const guardKey = 'blind:' + createHash('sha256').update(secret).digest('hex').slice(0, 32)
    const guardExpiry = Number.MAX_SAFE_INTEGER
    if (this._consumed.has(guardKey)) {
      return { ok: false, error: 'LEASE_REPLAY: blind token already redeemed', status: 402 }
    }
    if (this._consumed.size >= MAX_CONSUMED_RETAINED) {
      for (const [h, exp] of this._consumed) {
        if (!Number.isFinite(exp) || exp <= now) this._consumed.delete(h)
      }
      if (this._consumed.size >= MAX_CONSUMED_RETAINED) {
        return { ok: false, error: 'LEASE_GUARD_FULL: replay-guard saturated; retry shortly', status: 503 }
      }
    }
    const denomSats = this.quoteSats(this.blindDenomination.maxStorageBytes, this.blindDenomination.leaseDays).amountSats
    this._consumed.set(guardKey, guardExpiry)
    this.totalLeasedSats += denomSats
    this.leaseCount += 1
    try {
      await this._persist()
    } catch (err) {
      this._consumed.delete(guardKey)
      this.totalLeasedSats -= denomSats
      this.leaseCount -= 1
      this.emit('persist-error', err)
      return { ok: false, error: 'LEASE_PERSIST_FAILED: could not durably record redemption; retry', status: 503 }
    }
    const paidUntil = now + this.blindDenomination.leaseDays * DAY_MS
    this.emit('lease-paid', { blind: true, leaseDays: this.blindDenomination.leaseDays, paidUntil })
    return { ok: true, paidUntil, leaseDays: this.blindDenomination.leaseDays }
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
    const rate = this._normalizeRate(satsPerGiBDay)
    this.satsPerGiBDay = rate
    this._persist().catch((err) => { this.emit('persist-error', err) })
    this.emit('rate', this.satsPerGiBDay)
    return this.satsPerGiBDay
  }

  async setRateDurable (satsPerGiBDay) {
    const rate = this._normalizeRate(satsPerGiBDay)
    const previous = this.satsPerGiBDay
    this.satsPerGiBDay = rate
    try {
      await this._persist()
    } catch (err) {
      this.satsPerGiBDay = previous
      this.emit('persist-error', err)
      const wrapped = new Error('failed to persist lease rate')
      wrapped.code = 'LEASE_RATE_PERSIST_FAILED'
      wrapped.cause = err
      throw wrapped
    }
    this.emit('rate', this.satsPerGiBDay)
    return this.satsPerGiBDay
  }

  _normalizeRate (satsPerGiBDay) {
    if (!Number.isFinite(satsPerGiBDay) || satsPerGiBDay < 0) throw new Error('satsPerGiBDay must be a non-negative number')
    if (satsPerGiBDay > this.maxSatsPerGiBDay) throw new Error('satsPerGiBDay exceeds maximum (' + this.maxSatsPerGiBDay + ')')
    return Math.floor(satsPerGiBDay)
  }

  // ─── Persistence (atomic tmp+rename) ───────────────────────────────

  async _load (now = Date.now()) {
    if (!this.storagePath) return
    try {
      const data = JSON.parse(await readFile(this.storagePath, 'utf8'))
      if (data.schemaVersion !== LEASE_SCHEMA_VERSION) return
      // consumed is [ [paymentHash, expiresAt], ... ]. Drop already-expired on
      // load (they can never be replayed) and cap the retained set.
      const pairs = (Array.isArray(data.consumed) ? data.consumed : [])
        .filter(p => Array.isArray(p) && typeof p[0] === 'string' && Number.isFinite(p[1]) && p[1] > now)
        .slice(-MAX_CONSUMED_RETAINED)
      this._consumed = new Map(pairs)
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
    // Propagate write failures to awaiting callers (verifyLease rolls back on
    // failure) WITHOUT poisoning the serialized chain for later writes.
    const next = this._persisting.then(() => this._write(), () => this._write())
    this._persisting = next.catch(() => {})
    return next
  }

  async _write () {
    const tmp = this.storagePath + '.tmp'
    const data = JSON.stringify({
      schemaVersion: LEASE_SCHEMA_VERSION,
      consumed: Array.from(this._consumed.entries()),
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
      throw err
    }
  }
}
