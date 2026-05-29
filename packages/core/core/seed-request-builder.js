/**
 * Publisher-signed seed-request validator + opts builder.
 *
 * Validates a publisher-signed seed-request body and assembles the
 * canonical seedApp(opts) shape from it. Shared between two transports
 * so they speak the same vocabulary:
 *
 *   - HTTP route at /api/v1/seed (packages/core/core/relay-node/api.js)
 *   - Protomux hiverelay-publish channel, kind: 'seed'
 *     (packages/core/core/protocol/publish-channel.js)
 *
 * Returns:
 *   { ok: true, appKey, opts }
 *       Ready to invoke `node.seedApp(appKey, opts)`.
 *
 *   { ok: false, error, status, retryable? }
 *       The caller maps these to its own response shape.
 *       - status 400 — malformed request / bad value
 *       - status 403 — signature failed verification OR custody publisher mismatch
 *       (No 503 path here; transient store errors come from seedApp itself.)
 *
 * Validation order matches the previous inline implementation byte-for-byte
 * so error-message-string-based clients see the same surface.
 */

import b4a from 'b4a'
import {
  isValidHexKey,
  normalizeContentType,
  normalizeStorageClass,
  normalizeAvailabilityClass,
  normalizePrivacyTier,
  CONTENT_TYPES,
  STORAGE_CLASSES,
  AVAILABILITY_CLASSES
} from './constants.js'
import { verifySeedRequestSignature } from './protocol/seed-request.js'

export const MAX_DISCOVERY_KEYS = 100

const PRIVACY_TIER_ERROR = 'privacyTier must be one of: public, local-first, p2p-only'
const CONTENT_TYPE_ERROR = `type must be one of: ${Array.from(CONTENT_TYPES).join(', ')}`
const STORAGE_CLASS_ERROR = `storageClass must be one of: ${Array.from(STORAGE_CLASSES).join(', ')}`
const AVAILABILITY_CLASS_ERROR = `availabilityClass must be one of: ${Array.from(AVAILABILITY_CLASSES).join(', ')}`

function reject (error, status = 400) {
  return { ok: false, error, status }
}

/**
 * @param {object} body — parsed publisher-signed seed-request payload
 * @param {object} [opts]
 * @param {object} [opts.seedingRegistry] — optional registry handle for
 *   the custody-intent cross-check. If omitted, the custody publisher
 *   check is skipped (useful in tests).
 * @returns {{ ok: true, appKey: string, opts: object } | { ok: false, error: string, status: number }}
 */
export function buildPublisherSignedSeedOpts (body, opts = {}) {
  const seedingRegistry = opts.seedingRegistry || null

  // ── Presence + format ──
  if (!body || typeof body !== 'object') return reject('body required')
  if (!body.appKey) return reject('appKey required')
  if (!isValidHexKey(body.appKey, 64)) return reject('appKey must be 64 hex characters')
  if (!body.publisherPubkey) return reject('publisherPubkey required')
  if (!isValidHexKey(body.publisherPubkey, 64)) return reject('publisherPubkey must be 64 hex characters')
  if (!body.publisherSignature) return reject('publisherSignature required')
  if (!isValidHexKey(body.publisherSignature, 128)) return reject('publisherSignature must be 128 hex characters')

  // ── Discovery keys (optional) ──
  let discoveryKeys = []
  if (body.discoveryKeys !== undefined) {
    if (!Array.isArray(body.discoveryKeys)) {
      return reject('discoveryKeys must be an array of 64-hex strings')
    }
    if (body.discoveryKeys.length > MAX_DISCOVERY_KEYS) {
      return reject('discoveryKeys exceeds maximum (' + MAX_DISCOVERY_KEYS + ')')
    }
    for (const dk of body.discoveryKeys) {
      if (typeof dk !== 'string' || !isValidHexKey(dk, 64)) {
        return reject('each discoveryKey must be 64 hex characters')
      }
    }
    discoveryKeys = body.discoveryKeys.map(dk => b4a.from(dk, 'hex'))
  }

  // ── Numeric defaults + bounds ──
  // Defaults match the Protomux SeedProtocol layout so a publisher who
  // only sets appKey + a signature over the empty-defaults payload still
  // verifies.
  const replicationFactor = Number.isFinite(body.replicationFactor) ? body.replicationFactor : 3
  if (replicationFactor < 1 || replicationFactor > 255) {
    return reject('replicationFactor must be in [1,255]')
  }
  const maxStorageBytes = Number.isFinite(body.maxStorageBytes) ? body.maxStorageBytes : 500 * 1024 * 1024
  if (maxStorageBytes < 0) return reject('maxStorageBytes must be non-negative')
  const ttlSeconds = Number.isFinite(body.ttlSeconds) ? body.ttlSeconds : 30 * 24 * 3600
  if (ttlSeconds < 0) return reject('ttlSeconds must be non-negative')
  const bountyRate = Number.isFinite(body.bountyRate) ? body.bountyRate : 0
  if (bountyRate < 0) return reject('bountyRate must be non-negative')
  const revocable = body.revocable !== false
  const unseedFreezeMs = Number.isFinite(body.unseedFreezeMs) && body.unseedFreezeMs > 0
    ? Math.floor(body.unseedFreezeMs)
    : 0
  const durability = Number.isFinite(body.durability) && body.durability > 0
    ? Math.floor(body.durability)
    : 0

  // ── Signature verification ──
  const sigMsg = {
    appKey: b4a.from(body.appKey, 'hex'),
    discoveryKeys,
    replicationFactor,
    maxStorageBytes,
    ttlSeconds,
    bountyRate,
    revocable,
    unseedFreezeMs,
    durability,
    publisherPubkey: b4a.from(body.publisherPubkey, 'hex'),
    publisherSignature: b4a.from(body.publisherSignature, 'hex')
  }
  if (!verifySeedRequestSignature(sigMsg)) {
    return reject(
      'INVALID_SIGNATURE: publisher signature does not match canonical seed-request payload (v2 layout)',
      403
    )
  }

  // ── Assemble core seedOpts ──
  const seedOpts = {
    replicas: replicationFactor,
    maxStorage: maxStorageBytes,
    ttlDays: Math.max(1, Math.round(ttlSeconds / 86400)),
    bountyRate,
    revocable,
    unseedFreezeMs,
    durability,
    publisherPubkey: body.publisherPubkey.toLowerCase(),
    publisherSignature: body.publisherSignature.toLowerCase()
  }

  // ── Optional content metadata ──
  if (body.type !== undefined) {
    const type = normalizeContentType(body.type, null)
    if (!type) return reject(CONTENT_TYPE_ERROR)
    seedOpts.type = type
  }
  if (body.storageClass !== undefined) {
    const sc = normalizeStorageClass(body.storageClass, null)
    if (!sc) return reject(STORAGE_CLASS_ERROR)
    seedOpts.storageClass = sc
  }
  if (body.availabilityClass !== undefined) {
    const ac = normalizeAvailabilityClass(body.availabilityClass, null)
    if (!ac) return reject(AVAILABILITY_CLASS_ERROR)
    seedOpts.availabilityClass = ac
  }
  if (body.privacyTier !== undefined) {
    const tier = normalizePrivacyTier(body.privacyTier, null)
    if (!tier) return reject(PRIVACY_TIER_ERROR)
    seedOpts.privacyTier = tier
  }
  if (body.blind !== undefined) {
    if (typeof body.blind !== 'boolean') return reject('blind must be a boolean')
    seedOpts.blind = body.blind
  }

  // ── Atomic-custody binding ──
  for (const field of ['custodyIntentId', 'blindContentId', 'ciphertextRoot']) {
    if (body[field] !== undefined) {
      if (typeof body[field] !== 'string' || !isValidHexKey(body[field], 64)) {
        return reject(`${field} must be 64 hex characters`)
      }
      seedOpts[field] = body[field].toLowerCase()
    }
  }
  if (body.contentVersion !== undefined) {
    if (!Number.isFinite(body.contentVersion) || body.contentVersion < 0) {
      return reject('contentVersion must be a non-negative number')
    }
    seedOpts.contentVersion = Math.floor(body.contentVersion)
  }
  if (body.retainUntil !== undefined) {
    if (!Number.isFinite(body.retainUntil) || body.retainUntil < 0) {
      return reject('retainUntil must be a non-negative number')
    }
    seedOpts.retainUntil = Math.floor(body.retainUntil)
  }
  if (body.shardIds !== undefined) {
    if (!Array.isArray(body.shardIds)) return reject('shardIds must be an array')
    seedOpts.shardIds = []
    for (const shardId of body.shardIds) {
      if (!Number.isInteger(shardId) || shardId < 0) {
        return reject('shardIds must contain non-negative integers')
      }
      seedOpts.shardIds.push(shardId)
    }
  }

  // ── Custody cross-check ──
  // If the seed binds to an existing custody intent, the publisher of
  // this seed-request MUST be the same publisher who signed the intent.
  // Otherwise a different publisher could anchor their own appKey to
  // someone else's custody intent.
  if (seedOpts.custodyIntentId && seedingRegistry && typeof seedingRegistry.getCustodyIntent === 'function') {
    try {
      const intent = seedingRegistry.getCustodyIntent(seedOpts.custodyIntentId)
      if (intent && intent.publisherPubkey &&
          intent.publisherPubkey.toLowerCase() !== body.publisherPubkey.toLowerCase()) {
        return reject(
          'CUSTODY_PUBLISHER_MISMATCH: seed publisherPubkey does not match the publisher who signed this custodyIntentId',
          403
        )
      }
    } catch (_) {
      // Registry lookup is best-effort here; a failure shouldn't block the seed.
    }
  }

  return { ok: true, appKey: body.appKey, opts: seedOpts }
}

/**
 * Pull the optional atomic-custody linkage off a seed-request-like object
 * into a `seedApp()`-ready opts fragment. Used by the legacy Protomux
 * seed-protocol handlers (`_onSeedRequest`) so they keep the custody binding
 * the publisher-signed publish-channel / HTTP path keeps via
 * `buildPublisherSignedSeedOpts`. Without it, a custody seed accepted over
 * the legacy path lands with no `custodyIntentId`/`retainUntil`, so the
 * relay can never sign a non-serving-proof for it (it would silently never
 * attest).
 *
 * Only well-formed fields are included; anything absent or malformed is
 * omitted (seedApp normalizes missing custody fields to null). This is
 * deliberately permissive on read — it does NOT re-verify the publisher
 * signature, because the legacy seed-protocol already gates acceptance
 * upstream and the binary wire encoding doesn't yet carry (or sign) these
 * fields. Treat the publish channel as the authenticated custody path.
 *
 * @param {object} msg seed-request message (decoded wire msg or enriched object)
 * @returns {object} fragment to spread into seedApp opts
 */
export function extractCustodySeedOpts (msg) {
  const out = {}
  if (!msg || typeof msg !== 'object') return out
  for (const field of ['custodyIntentId', 'blindContentId', 'ciphertextRoot']) {
    if (typeof msg[field] === 'string' && isValidHexKey(msg[field], 64)) {
      out[field] = msg[field].toLowerCase()
    }
  }
  if (Number.isFinite(msg.contentVersion) && msg.contentVersion >= 0) {
    out.contentVersion = Math.floor(msg.contentVersion)
  }
  if (Number.isFinite(msg.retainUntil) && msg.retainUntil >= 0) {
    out.retainUntil = Math.floor(msg.retainUntil)
  }
  return out
}
