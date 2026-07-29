import { createHash } from 'crypto'

export class X402ClaimStore {
  constructor (opts = {}) {
    this.ttlMs = opts.ttlMs || 10 * 60 * 1000
    this.maxClaims = opts.maxClaims || 50_000
    this.now = opts.now || Date.now
    this.claims = new Map()
  }

  claim (paymentHeader, routeKey) {
    const now = this.now()
    this.sweep(now)
    const id = paymentClaimId(paymentHeader)
    const existing = this.claims.get(id)
    if (existing && existing.expiresAt > now) {
      return { ok: false, id, existing }
    }
    if (this.claims.size >= this.maxClaims) {
      return { ok: false, id, full: true }
    }
    const claim = { routeKey, claimedAt: now, expiresAt: now + this.ttlMs }
    this.claims.set(id, claim)
    return { ok: true, id, claim }
  }

  release (id) {
    return this.claims.delete(id)
  }

  sweep (now = this.now()) {
    for (const [id, claim] of this.claims) {
      if (claim.expiresAt <= now) this.claims.delete(id)
    }
  }
}

export function paymentClaimId (paymentHeader) {
  if (typeof paymentHeader !== 'string' || paymentHeader.length === 0) {
    throw new Error('X402_PAYMENT_HEADER_MISSING')
  }
  return createHash('sha256')
    .update('hiverelay.x402.claim.v1\0')
    .update(paymentHeader)
    .digest('hex')
}
