import { isValidHexKey } from '../constants.js'

export const MAX_REGISTRY_STATUS_REQUESTS = 500
export const MAX_REGISTRY_STATUS_RELAYS_PER_REQUEST = 100

function errorPayload (message) {
  return { error: message }
}

function normalizeLimit (value, max) {
  if (!Number.isSafeInteger(value)) return max
  if (value < 0) return 0
  return Math.min(value, max)
}

function hexKeyOrNull (value, length = 64) {
  if (typeof value === 'string' && isValidHexKey(value, length)) return value.toLowerCase()
  if (value && typeof value.length === 'number' && value.length === length / 2) return Buffer.from(value).toString('hex')
  return null
}

function safeString (value, maxBytes = 128) {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  if (!trimmed || Buffer.byteLength(trimmed, 'utf8') > maxBytes) return null
  return trimmed
}

function safeStringArray (value, maxItems, maxBytes) {
  if (!Array.isArray(value)) return []
  const out = []
  for (const item of value) {
    const text = safeString(item, maxBytes)
    if (!text) continue
    out.push(text)
    if (out.length >= maxItems) break
  }
  return out
}

function safeNumber (value) {
  return Number.isFinite(value) ? value : null
}

function sanitizeRequest (request) {
  const appKey = hexKeyOrNull(request && request.appKey)
  const publisherPubkey = hexKeyOrNull(request && request.publisherPubkey)
  return {
    type: safeString(request && request.type, 64),
    timestamp: safeNumber(request && request.timestamp),
    appKey,
    discoveryKeys: safeStringArray(request && request.discoveryKeys, 100, 64).filter(key => isValidHexKey(key, 64)),
    contentType: safeString(request && request.contentType, 64),
    parentKey: hexKeyOrNull(request && request.parentKey),
    mountPath: safeString(request && request.mountPath, 256),
    replicationFactor: safeNumber(request && request.replicationFactor),
    geoPreference: safeStringArray(request && request.geoPreference, 64, 64),
    maxStorageBytes: safeNumber(request && request.maxStorageBytes),
    bountyRate: safeNumber(request && request.bountyRate),
    ttlSeconds: safeNumber(request && request.ttlSeconds),
    privacyTier: safeString(request && request.privacyTier, 64),
    blind: (request && request.blind) === true,
    storageClass: safeString(request && request.storageClass, 64),
    availabilityClass: safeString(request && request.availabilityClass, 64),
    publisherPubkey
  }
}

function sanitizeRelay (relay) {
  return {
    pubkey: hexKeyOrNull(relay && relay.relayPubkey),
    region: safeString(relay && relay.region, 64)
  }
}

export async function buildRegistryStatusPayload ({
  registry = null,
  maxRequests = MAX_REGISTRY_STATUS_REQUESTS,
  maxRelaysPerRequest = MAX_REGISTRY_STATUS_RELAYS_PER_REQUEST
} = {}) {
  if (!registry || typeof registry.getActiveRequests !== 'function') {
    return { ok: false, status: 503, payload: errorPayload('Registry not running') }
  }
  const requestLimit = normalizeLimit(maxRequests, MAX_REGISTRY_STATUS_REQUESTS)
  const relayLimit = normalizeLimit(maxRelaysPerRequest, MAX_REGISTRY_STATUS_RELAYS_PER_REQUEST)
  const requests = await registry.getActiveRequests()
  const source = Array.isArray(requests) ? requests : []
  const selected = source.slice(0, requestLimit)
  const enriched = await Promise.all(selected.map(async (request) => {
    const item = sanitizeRequest(request)
    let relays = []
    if (item.appKey && typeof registry.getRelaysForApp === 'function') {
      try {
        const list = await registry.getRelaysForApp(item.appKey)
        relays = Array.isArray(list) ? list : []
      } catch (_) {
        relays = []
      }
    }
    const relayItems = relays.slice(0, relayLimit).map(sanitizeRelay)
    return {
      ...item,
      acceptedRelays: relays.length,
      relays: relayItems,
      relaysTruncated: relays.length > relayItems.length
    }
  }))

  const total = source.length
  return {
    ok: true,
    payload: {
      key: hexKeyOrNull(registry.key),
      activeRequests: total,
      count: enriched.length,
      total,
      truncated: total > enriched.length,
      maxRequests: requestLimit,
      requests: enriched
    }
  }
}
