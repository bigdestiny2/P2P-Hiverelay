import { createHash } from 'crypto'

const UINT256_MAX = (1n << 256n) - 1n
const PERMIT2_ADDRESS = '0x000000000022d473030f116ddee9f6b43ac78ba3'

export class X402ClaimStore {
  constructor (opts = {}) {
    this.ttlMs = opts.ttlMs || 10 * 60 * 1000
    this.maxClaims = opts.maxClaims || 50_000
    this.now = opts.now || Date.now
    this.claims = new Map()
  }

  claim (paymentPayload, requirements, routeKey) {
    const now = this.now()
    this.sweep(now)
    const { id, validUntil } = paymentIdentity(paymentPayload, requirements)
    if (validUntil <= now) throw new Error('X402_PAYMENT_AUTHORIZATION_EXPIRED')
    const existing = this.claims.get(id)
    if (existing) {
      return { ok: false, id, existing }
    }
    if (this.claims.size >= this.maxClaims) {
      return { ok: false, id, full: true }
    }
    const claim = { id, routeKey, claimedAt: now, validUntil, pending: true, expiresAt: null }
    this.claims.set(id, claim)
    return { ok: true, id, claim }
  }

  release (claim) {
    if (this.claims.get(claim.id) !== claim) return false
    return this.claims.delete(claim.id)
  }

  retain (claim) {
    if (this.claims.get(claim.id) !== claim) return false
    claim.pending = false
    claim.expiresAt = Math.max(claim.validUntil, Math.min(Number.MAX_SAFE_INTEGER, this.now() + this.ttlMs))
    return true
  }

  sweep (now = this.now()) {
    for (const [id, claim] of this.claims) {
      if (!claim.pending && claim.expiresAt <= now) this.claims.delete(id)
    }
  }
}

export function paymentClaimId (paymentPayload, requirements) {
  return paymentIdentity(paymentPayload, requirements).id
}

function paymentIdentity (payment, requirements) {
  if (payment?.x402Version !== 2 || requirements?.scheme !== 'exact' ||
      !/^eip155:[1-9][0-9]*$/.test(requirements?.network || '') ||
      !isObject(payment.payload) || typeof payment.payload.signature !== 'string') {
    throw new Error('X402_PAYMENT_AUTHORIZATION_INVALID')
  }
  const network = requirements.network
  const asset = address(requirements.asset)
  const payTo = address(requirements.payTo)
  const amount = uint256(requirements.amount)
  const body = payment.payload
  let parts
  let expiry
  if ('permit2Authorization' in body) {
    if ('authorization' in body) throw new Error('X402_PAYMENT_AUTHORIZATION_AMBIGUOUS')
    const auth = body.permit2Authorization
    if (!isObject(auth) || !isObject(auth.permitted) || !isObject(auth.witness)) {
      throw new Error('X402_PAYMENT_AUTHORIZATION_INVALID')
    }
    address(auth.spender)
    if (address(auth.permitted.token) !== asset || address(auth.witness.to) !== payTo ||
        uint256(auth.permitted.amount) !== amount) throw new Error('X402_PAYMENT_AUTHORIZATION_MISMATCH')
    expiry = uint256(auth.deadline)
    if (uint256(auth.witness.validAfter) >= expiry) throw new Error('X402_PAYMENT_AUTHORIZATION_INVALID')
    // Permit2 consumes the owner's nonce across tokens and spenders on this chain.
    parts = ['permit2', network, PERMIT2_ADDRESS, address(auth.from), uint256(auth.nonce).toString()]
  } else {
    const auth = body.authorization
    if (!isObject(auth)) throw new Error('X402_PAYMENT_AUTHORIZATION_INVALID')
    if (address(auth.to) !== payTo || uint256(auth.value) !== amount) throw new Error('X402_PAYMENT_AUTHORIZATION_MISMATCH')
    expiry = uint256(auth.validBefore)
    if (uint256(auth.validAfter) >= expiry) throw new Error('X402_PAYMENT_AUTHORIZATION_INVALID')
    if (typeof auth.nonce !== 'string' || !/^(?:0x)?[0-9a-f]{64}$/i.test(auth.nonce)) {
      throw new Error('X402_PAYMENT_AUTHORIZATION_INVALID')
    }
    // EIP-3009 consumes authorizationState(from, nonce) on the token contract.
    parts = ['eip3009', network, asset, address(auth.from), auth.nonce.replace(/^0x/i, '').toLowerCase()]
  }
  const expiryMs = expiry * 1000n
  if (expiryMs > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('X402_PAYMENT_AUTHORIZATION_EXPIRY_UNSUPPORTED')
  return {
    id: createHash('sha256').update('hiverelay.x402.claim.v2\0').update(JSON.stringify(parts)).digest('hex'),
    validUntil: Number(expiryMs)
  }
}

function address (value) {
  if (typeof value !== 'string' || !/^0x[0-9a-f]{40}$/i.test(value)) throw new Error('X402_PAYMENT_AUTHORIZATION_INVALID')
  return value.toLowerCase()
}

function uint256 (value) {
  if (typeof value !== 'string' || !/^[0-9]{1,78}$/.test(value)) throw new Error('X402_PAYMENT_AUTHORIZATION_INVALID')
  const number = BigInt(value)
  if (number > UINT256_MAX) throw new Error('X402_PAYMENT_AUTHORIZATION_INVALID')
  return number
}

function isObject (value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}
