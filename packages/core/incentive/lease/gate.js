// lease/gate.js — transport-agnostic paid-seeding gate.
//
// The lease gate MUST be applied at EVERY publisher-signed seed entry point,
// not just the HTTP route — otherwise a publisher can seed for free over the
// Protomux publish-channel or the legacy seed-protocol. This module is the
// single source of truth both transports call, so the gate can never again be
// wired on one path and forgotten on another.
//
// Operator self-seeds (POST /seed, API-key) never reach here, so self-host
// stays free.

/**
 * Is this seed exempt from charging?
 *
 * ONLY a VERIFIED custody intent exempts (founder-subsidized social-recovery,
 * not commercial hosting). storageClass/availabilityClass are publisher-
 * DECLARED and ride UNSIGNED, so they are NOT trustworthy for exemption — a
 * payer could set storageClass:'temporary' to dodge the fee. custodyIntentId
 * is likewise unsigned, so we require it to RESOLVE to an existing intent in
 * the registry whose publisherPubkey matches this seed's publisher (the same
 * cross-check the seed-request builder applies to the custody binding).
 *
 * @param {object} opts seedApp opts (carries custodyIntentId, publisherPubkey)
 * @param {object} [ctx]
 * @param {object} [ctx.seedingRegistry] registry handle (getCustodyIntent)
 */
export function isLeaseExempt (opts, ctx = {}) {
  if (!opts) return true
  const intentId = opts.custodyIntentId
  if (!intentId) return false
  const reg = ctx.seedingRegistry
  if (!reg || typeof reg.getCustodyIntent !== 'function') return false
  let intent
  try { intent = reg.getCustodyIntent(intentId) } catch { return false }
  if (!intent || !intent.publisherPubkey) return false
  const pub = (opts.publisherPubkey || '').toLowerCase()
  return !!pub && intent.publisherPubkey.toLowerCase() === pub
}

/**
 * Evaluate the lease for a publisher-signed seed on a transport that CAN carry
 * a payment proof (HTTP /api/v1/seed, Protomux publish-channel). Returns a
 * transport-agnostic outcome the caller maps to its own response shape:
 *
 *   { outcome: 'exempt' }                     — proceed free (no charge)
 *   { outcome: 'quote', quote, status:402 }   — payment required; quote is the
 *                                               402 body (amountSats/bolt11/
 *                                               quoteId/expiresAt/payTo) or null
 *                                               if leaseDays was missing
 *   { outcome: 'paid', retainUntil }          — verified; caller merges
 *                                               retainUntil + leaseManaged
 *   { outcome: 'error', error, status }       — quote/verify failure
 *
 * @param {object} args
 * @param {object} args.leaseManager  null when lease.enabled is off
 * @param {object} args.seedingRegistry
 * @param {string} args.appKey
 * @param {object} args.opts          built seedApp opts (maxStorage, etc.)
 * @param {object} args.body          raw request body (leaseDays, paymentProof)
 */
export async function evaluateSeedLease ({ leaseManager, seedingRegistry, appKey, opts, body }) {
  if (!leaseManager) return { outcome: 'exempt' }
  if (isLeaseExempt(opts, { seedingRegistry })) return { outcome: 'exempt' }

  const proof = body && body.paymentProof && typeof body.paymentProof === 'object' ? body.paymentProof : null

  if (!proof || typeof proof.quoteId !== 'string') {
    const leaseDays = Number.isFinite(body && body.leaseDays) ? Math.floor(body.leaseDays) : null
    if (!leaseDays || leaseDays < 1) {
      return { outcome: 'quote', quote: null, status: 402, error: 'PAYMENT_REQUIRED: this relay charges to seed; include leaseDays to get a quote' }
    }
    try {
      const quote = await leaseManager.createQuote({ appKey, maxStorageBytes: opts.maxStorage, leaseDays })
      return { outcome: 'quote', quote, status: 402, error: 'PAYMENT_REQUIRED' }
    } catch (err) {
      return { outcome: 'error', error: 'LEASE_QUOTE_FAILED: ' + (err.message || String(err)), status: 503 }
    }
  }

  try {
    // Pass the resubmitted maxStorage so verifyLease can reject a seed that
    // asks for MORE storage than the (cheaper) quote was priced for.
    const v = await leaseManager.verifyLease({ appKey, quoteId: proof.quoteId, maxStorageBytes: opts.maxStorage })
    if (!v.ok) return { outcome: 'error', error: v.error || 'LEASE_UNVERIFIED', status: v.status || 402 }
    return { outcome: 'paid', retainUntil: v.paidUntil }
  } catch (err) {
    return { outcome: 'error', error: 'LEASE_VERIFY_FAILED: ' + (err.message || String(err)), status: 503 }
  }
}
