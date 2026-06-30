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
import {
  SEED_REQUEST_REPLAY_SIGNATURE_DOMAIN,
  verifySeedRequestSignatureDetails
} from './protocol/seed-request.js'

export const MAX_DISCOVERY_KEYS = 100
export const PUBLISHER_SEED_REPLAY_WINDOW_MS = 60 * 60 * 1000
export const PUBLISHER_SEED_REPLAY_FUTURE_SKEW_MS = 60 * 1000
export const PUBLISHER_SEED_REPLAY_CACHE_MAX = 50_000

const PRIVACY_TIER_ERROR = 'privacyTier must be one of: public, local-first, p2p-only'
const CONTENT_TYPE_ERROR = `type must be one of: ${Array.from(CONTENT_TYPES).join(', ')}`
const STORAGE_CLASS_ERROR = `storageClass must be one of: ${Array.from(STORAGE_CLASSES).join(', ')}`
const AVAILABILITY_CLASS_ERROR = `availabilityClass must be one of: ${Array.from(AVAILABILITY_CLASSES).join(', ')}`
const PUBLISHER_SEED_FIELDS = new Set([
  'appKey',
  'discoveryKeys',
  'replicationFactor',
  'maxStorageBytes',
  'ttlSeconds',
  'bountyRate',
  'revocable',
  'unseedFreezeMs',
  'durability',
  'publisherPubkey',
  'publisherSignature',
  'issuedAt',
  'requestNonce',
  'type',
  'storageClass',
  'availabilityClass',
  'privacyTier',
  'blind',
  'custodyIntentId',
  'blindContentId',
  'ciphertextRoot',
  'commitmentRoot',
  'contentVersion',
  'retainUntil',
  'shardIds',
  'shareScheme',
  'shareThreshold',
  'leaseDays',
  'paymentProof'
])
const PAYMENT_PROOF_FIELDS = new Set(['quoteId', 'voucherId', 'blindToken', 'cashuToken'])
const BLIND_TOKEN_FIELDS = new Set(['secret', 'C'])

function reject (error, status = 400) {
  return { ok: false, error, status }
}

function rejectUnknownObjectFields (obj, allowed, label) {
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) return reject(`unknown ${label} field: ${key}`)
  }
  return null
}

function validateAuxiliaryPublisherFields (body) {
  const unknown = rejectUnknownObjectFields(body, PUBLISHER_SEED_FIELDS, 'publisher seed')
  if (unknown) return unknown

  if (body.leaseDays !== undefined && (!Number.isFinite(body.leaseDays) || body.leaseDays < 1)) {
    return reject('leaseDays must be a positive number')
  }

  if (body.paymentProof !== undefined) {
    if (!body.paymentProof || typeof body.paymentProof !== 'object' || Array.isArray(body.paymentProof)) {
      return reject('paymentProof must be an object')
    }
    const paymentUnknown = rejectUnknownObjectFields(body.paymentProof, PAYMENT_PROOF_FIELDS, 'paymentProof')
    if (paymentUnknown) return paymentUnknown
    if (body.paymentProof.blindToken !== undefined) {
      const token = body.paymentProof.blindToken
      if (!token || typeof token !== 'object' || Array.isArray(token)) return reject('paymentProof.blindToken must be an object')
      const tokenUnknown = rejectUnknownObjectFields(token, BLIND_TOKEN_FIELDS, 'paymentProof.blindToken')
      if (tokenUnknown) return tokenUnknown
    }
  }

  return null
}

export function consumePublisherSeedReplayNonce (replay, cache, opts = {}) {
  if (!replay) return { ok: true }
  if (!cache || typeof cache.has !== 'function' || typeof cache.set !== 'function') return { ok: true }

  const now = Number.isSafeInteger(opts.now) ? opts.now : Date.now()
  const windowMs = replayWindowMs(opts)
  evictPublisherSeedReplayCache(cache, now, windowMs)

  if (cache.has(replay.cacheKey)) {
    return reject('SEED_REQUEST_REPLAY: requestNonce already seen for publisher', 409)
  }
  cache.set(replay.cacheKey, now)
  if (cache.size > PUBLISHER_SEED_REPLAY_CACHE_MAX) {
    const overflow = cache.size - PUBLISHER_SEED_REPLAY_CACHE_MAX
    let removed = 0
    for (const key of cache.keys()) {
      cache.delete(key)
      removed++
      if (removed >= overflow) break
    }
  }
  return { ok: true }
}

function evictPublisherSeedReplayCache (cache, now, windowMs) {
  for (const [key, seenAt] of cache) {
    if (!Number.isSafeInteger(seenAt) || now - seenAt > windowMs) cache.delete(key)
  }
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
  const auxiliaryProblem = validateAuxiliaryPublisherFields(body)
  if (auxiliaryProblem) return auxiliaryProblem

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
  const replayEnvelope = validatePublisherSeedReplayEnvelope(body, opts)
  if (!replayEnvelope.ok) return replayEnvelope

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
  if (replayEnvelope.replay) {
    sigMsg.issuedAt = replayEnvelope.replay.issuedAt
    sigMsg.requestNonce = b4a.from(replayEnvelope.replay.requestNonce, 'hex')
  }
  const sigDetails = verifySeedRequestSignatureDetails(sigMsg)
  if (!sigDetails.ok) {
    return reject(
      'INVALID_SIGNATURE: publisher signature does not match canonical seed-request payload',
      403
    )
  }
  if (replayEnvelope.replay && sigDetails.domain !== SEED_REQUEST_REPLAY_SIGNATURE_DOMAIN) {
    return reject('INVALID_SIGNATURE: seed replay envelope must use replay-v1 signature profile', 403)
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
    publisherSignature: body.publisherSignature.toLowerCase(),
    seedSignatureProfile: sigDetails.layout
  }
  if (replayEnvelope.replay) {
    seedOpts.issuedAt = replayEnvelope.replay.issuedAt
    seedOpts.requestNonce = replayEnvelope.replay.requestNonce
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
  // commitmentRoot rides alongside the existing 64-hex custody anchors: it is
  // the BLAKE2b root over the published PVSS Feldman commitments. Like the
  // other custody fields it carries UNSIGNED (added after the signature check)
  // — the authenticated binding lives in the publisher-signed custody-intent,
  // and the relay re-derives + verifies commitments independently anyway.
  for (const field of ['custodyIntentId', 'blindContentId', 'ciphertextRoot', 'commitmentRoot']) {
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
  // PVSS share-scheme metadata (mirrors contentVersion/retainUntil: a bare
  // scalar/string carried unsigned alongside the custody anchors). shareScheme
  // names the protocol the commitmentRoot belongs to; shareThreshold is the
  // recovery threshold t the dealer chose (1..255, ≤ replicationFactor).
  if (body.shareScheme !== undefined) {
    if (typeof body.shareScheme !== 'string' || body.shareScheme.length < 1 || body.shareScheme.length > 64) {
      return reject('shareScheme must be a string of 1-64 characters')
    }
    seedOpts.shareScheme = body.shareScheme
  }
  if (body.shareThreshold !== undefined) {
    if (!Number.isInteger(body.shareThreshold) || body.shareThreshold < 1 || body.shareThreshold > 255) {
      return reject('shareThreshold must be in [1,255]')
    }
    seedOpts.shareThreshold = body.shareThreshold
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

  return { ok: true, appKey: body.appKey, opts: seedOpts, replay: replayEnvelope.replay }
}

function validatePublisherSeedReplayEnvelope (body, opts) {
  const hasIssuedAt = body.issuedAt !== undefined
  const hasNonce = body.requestNonce !== undefined
  if (!hasIssuedAt && !hasNonce) return { ok: true, replay: null }
  if (!hasIssuedAt) return reject('issuedAt required when requestNonce is present')
  if (!hasNonce) return reject('requestNonce required when issuedAt is present')
  if (!Number.isSafeInteger(body.issuedAt) || body.issuedAt < 0) {
    return reject('issuedAt must be a non-negative safe integer')
  }
  if (typeof body.requestNonce !== 'string' || !/^[0-9a-f]{32}$/i.test(body.requestNonce)) {
    return reject('requestNonce must be 32 hex characters')
  }

  const now = Number.isSafeInteger(opts.now) ? opts.now : Date.now()
  const windowMs = replayWindowMs(opts)
  const futureSkewMs = replayFutureSkewMs(opts)
  if (body.issuedAt > now + futureSkewMs) return reject('issuedAt is too far in the future')
  if (now - body.issuedAt > windowMs) return reject('issuedAt is outside the replay window')

  const publisherPubkey = body.publisherPubkey.toLowerCase()
  const requestNonce = body.requestNonce.toLowerCase()
  return {
    ok: true,
    replay: {
      publisherPubkey,
      requestNonce,
      issuedAt: body.issuedAt,
      cacheKey: publisherPubkey + ':' + requestNonce
    }
  }
}

function replayWindowMs (opts) {
  return Number.isSafeInteger(opts.seedReplayWindowMs) && opts.seedReplayWindowMs >= 0
    ? opts.seedReplayWindowMs
    : PUBLISHER_SEED_REPLAY_WINDOW_MS
}

function replayFutureSkewMs (opts) {
  return Number.isSafeInteger(opts.seedReplayFutureSkewMs) && opts.seedReplayFutureSkewMs >= 0
    ? opts.seedReplayFutureSkewMs
    : PUBLISHER_SEED_REPLAY_FUTURE_SKEW_MS
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
  for (const field of ['custodyIntentId', 'blindContentId', 'ciphertextRoot', 'commitmentRoot']) {
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
  // PVSS metadata mirrors the permissive read of the other custody fields:
  // include only when well-formed, omit otherwise (seedApp normalizes missing
  // custody fields to null).
  if (typeof msg.shareScheme === 'string' && msg.shareScheme.length >= 1 && msg.shareScheme.length <= 64) {
    out.shareScheme = msg.shareScheme
  }
  if (Number.isInteger(msg.shareThreshold) && msg.shareThreshold >= 1 && msg.shareThreshold <= 255) {
    out.shareThreshold = msg.shareThreshold
  }
  return out
}
