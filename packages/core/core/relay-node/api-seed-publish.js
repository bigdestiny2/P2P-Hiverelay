import {
  AVAILABILITY_CLASSES,
  CONTENT_TYPES,
  STORAGE_CLASSES,
  isValidHexKey,
  normalizeAvailabilityClass,
  normalizeContentType,
  normalizePrivacyTier,
  normalizeStorageClass
} from '../constants.js'
import {
  buildPublisherSignedSeedOpts,
  consumePublisherSeedReplayNonce
} from '../seed-request-builder.js'
import { evaluateSeedLease } from '../../incentive/lease/gate.js'
import { custodyDisabledResult } from './api-custody-disabled.js'
import { validatePositiveInt } from './api-validation.js'

export const MAX_DISCOVERY_KEYS = 100
export const MAX_REGISTRY_GEO_ITEMS = 64
export const MAX_REGISTRY_GEO_BYTES = 2048
export const MAX_REGISTRY_TTL_DAYS = 3650
export const MAX_REGISTRY_MAX_STORAGE_BYTES = 10e12
export const MAX_REGISTRY_BOUNTY_RATE = 0xFFFFFFFF
export const PRIVACY_TIER_ERROR = 'privacyTier must be one of: public, local-first, p2p-only'
export const CONTENT_TYPE_ERROR = `type must be one of: ${Array.from(CONTENT_TYPES).join(', ')}`
export const STORAGE_CLASS_ERROR = `storageClass must be one of: ${Array.from(STORAGE_CLASSES).join(', ')}`
export const AVAILABILITY_CLASS_ERROR = `availabilityClass must be one of: ${Array.from(AVAILABILITY_CLASSES).join(', ')}`
export const OPERATOR_SEED_AUTH_MESSAGE = 'Unauthorized — API key required for /seed'
export const REGISTRY_PUBLISH_AUTH_MESSAGE = 'Unauthorized — API key required for /registry/publish'

const CUSTODY_SEED_FIELDS = ['custodyIntentId', 'blindContentId', 'ciphertextRoot']

function errorPayload (message) {
  return { error: message }
}

function publisherSeedReplayCache (node) {
  if (!node) return null
  if (!node._publisherSeedReplayCache) node._publisherSeedReplayCache = new Map()
  return node._publisherSeedReplayCache
}

function badRequest (message) {
  return { ok: false, kind: 'bad-request', status: 400, payload: errorPayload(message) }
}

function hasCustodySeedFields (body) {
  if (!body || typeof body !== 'object') return false
  return CUSTODY_SEED_FIELDS.some(field => body[field] !== undefined)
}

function cloneSeedOpts (opts) {
  if (opts === undefined || opts === null) return { ok: true, seedOpts: {} }
  if (typeof opts !== 'object' || Array.isArray(opts)) {
    return { ok: false, result: badRequest('opts must be an object') }
  }
  return { ok: true, seedOpts: { ...opts } }
}

function validateMountFields ({ parentKey, mountPath, type }) {
  if ((parentKey || mountPath) && type && type !== 'drive') {
    return badRequest('parentKey and mountPath are only supported when type is "drive"')
  }
  return null
}

function optionalRegistryInt (body, field, fallback, min, max) {
  if (body[field] === undefined || body[field] === null) return { ok: true, value: fallback }
  const result = validatePositiveInt(body[field], min, max, field)
  if (!result.ok) return { ok: false, result: badRequest(result.error) }
  return { ok: true, value: result.value }
}

function normalizeRegistryGeoPreference (geo) {
  if (geo === undefined || geo === null) return { ok: true, value: [] }
  const list = Array.isArray(geo) ? geo : [geo]
  if (list.length > MAX_REGISTRY_GEO_ITEMS) {
    return { ok: false, result: badRequest(`geo must be a string or array of at most ${MAX_REGISTRY_GEO_ITEMS} strings`) }
  }

  const out = []
  for (const item of list) {
    if (typeof item !== 'string') return { ok: false, result: badRequest('geo must be a string or array of strings') }
    const value = item.trim()
    if (!value) continue
    if (value.length > 64) return { ok: false, result: badRequest('geo entries must be at most 64 characters') }
    out.push(value)
  }

  if (Buffer.byteLength(JSON.stringify(out), 'utf8') > MAX_REGISTRY_GEO_BYTES) {
    return { ok: false, result: badRequest(`geo preference exceeds max size (${MAX_REGISTRY_GEO_BYTES} bytes)`) }
  }
  return { ok: true, value: out }
}

function normalizeSeedOptions (body) {
  const cloned = cloneSeedOpts(body.opts)
  if (!cloned.ok) return cloned
  const seedOpts = cloned.seedOpts
  const requestedType = body.type !== undefined ? body.type : seedOpts.type
  if (requestedType !== undefined) {
    const type = normalizeContentType(requestedType, null)
    if (!type) return { ok: false, result: badRequest(CONTENT_TYPE_ERROR) }
    seedOpts.type = type
  }

  const requestedStorageClass = body.storageClass !== undefined ? body.storageClass : seedOpts.storageClass
  if (requestedStorageClass !== undefined) {
    const storageClass = normalizeStorageClass(requestedStorageClass, null)
    if (!storageClass) return { ok: false, result: badRequest(STORAGE_CLASS_ERROR) }
    seedOpts.storageClass = storageClass
  }

  const requestedAvailabilityClass = body.availabilityClass !== undefined ? body.availabilityClass : seedOpts.availabilityClass
  if (requestedAvailabilityClass !== undefined) {
    const availabilityClass = normalizeAvailabilityClass(requestedAvailabilityClass, null)
    if (!availabilityClass) return { ok: false, result: badRequest(AVAILABILITY_CLASS_ERROR) }
    seedOpts.availabilityClass = availabilityClass
  }

  const requestedDurability = body.durability !== undefined ? body.durability : seedOpts.durability
  if (requestedDurability !== undefined) {
    const durability = Number(requestedDurability)
    if (!Number.isInteger(durability) || durability < 0 || durability > 255) {
      return { ok: false, result: badRequest('durability must be an integer 0-255 (0=standard, 1=archive)') }
    }
    seedOpts.durability = durability
  }

  if (body.appId && typeof body.appId === 'string') seedOpts.appId = body.appId
  if (body.version && typeof body.version === 'string') seedOpts.version = body.version

  if (body.parentKey !== undefined) {
    if (typeof body.parentKey !== 'string' || !isValidHexKey(body.parentKey, 64)) {
      return { ok: false, result: badRequest('parentKey must be a 64-character hex key') }
    }
    seedOpts.parentKey = body.parentKey
  }

  if (body.mountPath !== undefined) {
    if (typeof body.mountPath !== 'string') return { ok: false, result: badRequest('mountPath must be a string') }
    const mountPath = body.mountPath.trim()
    if (!mountPath.startsWith('/')) return { ok: false, result: badRequest('mountPath must start with "/"') }
    if (mountPath.length > 256) return { ok: false, result: badRequest('mountPath exceeds max length (256)') }
    seedOpts.mountPath = mountPath
  }

  if ((seedOpts.parentKey || seedOpts.mountPath) && !seedOpts.type) {
    seedOpts.type = 'drive'
  }
  const mountError = validateMountFields(seedOpts)
  if (mountError) return { ok: false, result: mountError }

  if (body.name !== undefined) {
    if (typeof body.name !== 'string') return { ok: false, result: badRequest('name must be a string') }
    seedOpts.name = body.name.trim().slice(0, 120)
  }
  if (body.description !== undefined) {
    if (typeof body.description !== 'string') return { ok: false, result: badRequest('description must be a string') }
    seedOpts.description = body.description.slice(0, 2000)
  }
  if (body.author !== undefined) {
    if (typeof body.author !== 'string') return { ok: false, result: badRequest('author must be a string') }
    seedOpts.author = body.author.trim().slice(0, 120)
  }
  if (body.categories !== undefined) {
    if (!Array.isArray(body.categories)) return { ok: false, result: badRequest('categories must be an array of strings') }
    const categories = []
    for (const category of body.categories) {
      if (typeof category !== 'string') return { ok: false, result: badRequest('categories must be an array of strings') }
      const normalized = category.trim()
      if (!normalized) continue
      categories.push(normalized.slice(0, 64))
    }
    seedOpts.categories = [...new Set(categories)].slice(0, 20)
  }

  if (body.privacyTier !== undefined) {
    const tier = normalizePrivacyTier(body.privacyTier, null)
    if (!tier) return { ok: false, result: badRequest(PRIVACY_TIER_ERROR) }
    seedOpts.privacyTier = tier
  }

  if (seedOpts.blind !== undefined && typeof seedOpts.blind !== 'boolean') {
    return { ok: false, result: badRequest('blind must be a boolean') }
  }
  if (body.blind !== undefined) {
    if (typeof body.blind !== 'boolean') return { ok: false, result: badRequest('blind must be a boolean') }
    seedOpts.blind = body.blind
  }

  for (const field of ['custodyIntentId', 'blindContentId', 'ciphertextRoot']) {
    if (body[field] !== undefined) {
      if (typeof body[field] !== 'string' || !isValidHexKey(body[field], 64)) {
        return { ok: false, result: badRequest(`${field} must be 64 hex characters`) }
      }
      seedOpts[field] = body[field].toLowerCase()
    }
  }

  if (body.contentVersion !== undefined) {
    if (!Number.isFinite(body.contentVersion) || body.contentVersion < 0) {
      return { ok: false, result: badRequest('contentVersion must be a non-negative number') }
    }
    seedOpts.contentVersion = Math.floor(body.contentVersion)
  }
  if (body.retainUntil !== undefined) {
    if (!Number.isFinite(body.retainUntil) || body.retainUntil < 0) {
      return { ok: false, result: badRequest('retainUntil must be a non-negative number') }
    }
    seedOpts.retainUntil = Math.floor(body.retainUntil)
  }
  if (body.shardIds !== undefined) {
    if (!Array.isArray(body.shardIds)) return { ok: false, result: badRequest('shardIds must be an array') }
    seedOpts.shardIds = []
    for (const shardId of body.shardIds) {
      if (!Number.isInteger(shardId) || shardId < 0) {
        return { ok: false, result: badRequest('shardIds must contain non-negative integers') }
      }
      seedOpts.shardIds.push(shardId)
    }
  }

  return { ok: true, seedOpts }
}

function buildRegistryPublishRequest (body, node) {
  const rawContentType = body.contentType !== undefined ? body.contentType : body.type
  const contentType = normalizeContentType(rawContentType, 'app')
  if (rawContentType !== undefined && normalizeContentType(rawContentType, null) === null) {
    return { ok: false, result: badRequest(CONTENT_TYPE_ERROR) }
  }

  let parentKey = null
  if (body.parentKey !== undefined) {
    if (typeof body.parentKey !== 'string' || !isValidHexKey(body.parentKey, 64)) {
      return { ok: false, result: badRequest('parentKey must be a 64-character hex key') }
    }
    parentKey = body.parentKey
  }

  let mountPath = null
  if (body.mountPath !== undefined) {
    if (typeof body.mountPath !== 'string') return { ok: false, result: badRequest('mountPath must be a string') }
    mountPath = body.mountPath.trim()
    if (!mountPath.startsWith('/')) return { ok: false, result: badRequest('mountPath must start with "/"') }
    if (mountPath.length > 256) return { ok: false, result: badRequest('mountPath exceeds max length (256)') }
  }

  const mountError = validateMountFields({ parentKey, mountPath, type: contentType })
  if (mountError) return { ok: false, result: mountError }

  const dks = body.discoveryKeys || []
  if (!Array.isArray(dks) || dks.length > MAX_DISCOVERY_KEYS) {
    return { ok: false, result: badRequest(`discoveryKeys must be an array of at most ${MAX_DISCOVERY_KEYS} items`) }
  }
  for (const dk of dks) {
    if (!isValidHexKey(dk, 64)) return { ok: false, result: badRequest('Each discoveryKey must be 64 hex characters') }
  }

  const privacyTier = body.privacyTier === undefined
    ? 'public'
    : normalizePrivacyTier(body.privacyTier, null)
  if (!privacyTier) return { ok: false, result: badRequest(PRIVACY_TIER_ERROR) }

  const storageClass = body.storageClass === undefined
    ? (body.blind === true ? 'temporary' : 'persistent')
    : normalizeStorageClass(body.storageClass, null)
  if (!storageClass) return { ok: false, result: badRequest(STORAGE_CLASS_ERROR) }

  const availabilityClass = body.availabilityClass === undefined
    ? (body.blind === true ? 'atomic-handoff' : 'always-on')
    : normalizeAvailabilityClass(body.availabilityClass, null)
  if (!availabilityClass) return { ok: false, result: badRequest(AVAILABILITY_CLASS_ERROR) }

  if (body.blind !== undefined && typeof body.blind !== 'boolean') {
    return { ok: false, result: badRequest('blind must be a boolean') }
  }

  let appKeyBuf, dkBufs
  try {
    appKeyBuf = Buffer.from(body.appKey, 'hex')
    dkBufs = dks.map(dk => Buffer.from(dk, 'hex'))
  } catch (err) {
    return { ok: false, result: badRequest('Invalid hex encoding: ' + err.message) }
  }

  const replicationFactor = optionalRegistryInt(body, 'replicas', 3, 1, 255)
  if (!replicationFactor.ok) return replicationFactor
  const geoPreference = normalizeRegistryGeoPreference(body.geo)
  if (!geoPreference.ok) return geoPreference
  const maxStorageBytes = optionalRegistryInt(body, 'maxStorageBytes', 0, 0, MAX_REGISTRY_MAX_STORAGE_BYTES)
  if (!maxStorageBytes.ok) return maxStorageBytes
  const bountyRate = optionalRegistryInt(body, 'bountyRate', 0, 0, MAX_REGISTRY_BOUNTY_RATE)
  if (!bountyRate.ok) return bountyRate
  const ttlDays = optionalRegistryInt(body, 'ttlDays', 30, 1, MAX_REGISTRY_TTL_DAYS)
  if (!ttlDays.ok) return ttlDays

  return {
    ok: true,
    request: {
      appKey: appKeyBuf,
      discoveryKeys: dkBufs,
      contentType,
      parentKey,
      mountPath,
      blind: body.blind === true,
      storageClass,
      availabilityClass,
      replicationFactor: replicationFactor.value,
      geoPreference: geoPreference.value,
      maxStorageBytes: maxStorageBytes.value,
      bountyRate: bountyRate.value,
      ttlSeconds: ttlDays.value * 86400,
      privacyTier,
      publisherPubkey: node.swarm ? node.swarm.keyPair.publicKey : Buffer.alloc(32)
    }
  }
}

export function resolveSeedPublishRoute (method, path) {
  if (method !== 'POST') return null
  if (path === '/seed') {
    return {
      kind: 'operator-seed',
      authMessage: OPERATOR_SEED_AUTH_MESSAGE
    }
  }
  if (path === '/registry/publish') {
    return {
      kind: 'registry-publish',
      authMessage: REGISTRY_PUBLISH_AUTH_MESSAGE
    }
  }
  if (path === '/api/v1/seed') return { kind: 'publisher-seed' }
  return null
}

export async function runOperatorSeedAction ({
  body = {},
  node,
  disabled = false
}) {
  body = body || {}
  if (disabled && hasCustodySeedFields(body)) return custodyDisabledResult()

  if (!body.appKey) return badRequest('appKey required')
  if (!isValidHexKey(body.appKey, 64)) return badRequest('appKey must be 64 hex characters')

  const built = normalizeSeedOptions(body)
  if (!built.ok) return built.result

  const result = await node.seedApp(body.appKey, built.seedOpts)
  return { ok: true, payload: { ok: true, ...result } }
}

export async function runRegistryPublishAction ({
  body = {},
  node
}) {
  body = body || {}
  if (!node.seedingRegistry) return { ok: false, kind: 'unavailable', status: 503, payload: errorPayload('Registry not running') }
  if (!body.appKey) return badRequest('appKey required')
  if (!isValidHexKey(body.appKey, 64)) return badRequest('appKey must be 64 hex characters')

  const built = buildRegistryPublishRequest(body, node)
  if (!built.ok) return built.result

  const entry = await node.seedingRegistry.publishRequest(built.request)
  return { ok: true, payload: { ok: true, ...entry } }
}

export async function runPublisherSeedAction ({
  body = {},
  node,
  disabled = false
}) {
  body = body || {}
  if (disabled && hasCustodySeedFields(body)) return custodyDisabledResult()

  if (!node || typeof node.seedApp !== 'function') {
    return { ok: false, kind: 'unavailable', status: 503, payload: errorPayload('seedApp not available') }
  }

  const built = buildPublisherSignedSeedOpts(body, {
    seedingRegistry: node.seedingRegistry
  })
  if (!built.ok) {
    return { ok: false, kind: 'bad-request', status: built.status || 400, payload: errorPayload(built.error) }
  }

  const gate = await evaluateSeedLease({
    leaseManager: node.leaseManager,
    seedingRegistry: node.seedingRegistry,
    appKey: built.appKey,
    opts: built.opts,
    body
  })
  if (gate.outcome === 'quote') {
    return { ok: false, kind: 'lease-required', status: gate.status, payload: { error: gate.error, leaseRequired: true, ...(gate.quote || {}) } }
  }
  if (gate.outcome === 'error') {
    return { ok: false, kind: 'lease-required', status: gate.status, payload: { error: gate.error, leaseRequired: true } }
  }
  if (gate.outcome === 'paid') {
    built.opts.retainUntil = gate.retainUntil
    built.opts.leaseManaged = true
  }

  const replay = consumePublisherSeedReplayNonce(built.replay, publisherSeedReplayCache(node))
  if (!replay.ok) {
    return { ok: false, kind: 'bad-request', status: replay.status || 400, payload: errorPayload(replay.error) }
  }

  try {
    const result = await node.seedApp(built.appKey, built.opts)
    return { ok: true, payload: { ok: true, ...result } }
  } catch (err) {
    return { ok: false, kind: 'seed-error', error: err }
  }
}

export async function runSeedPublishRouteAction ({
  route,
  body = {},
  node,
  disabled = false
} = {}) {
  const kind = route && route.kind
  if (kind === 'operator-seed') return runOperatorSeedAction({ body, node, disabled })
  if (kind === 'registry-publish') return runRegistryPublishAction({ body, node })
  if (kind === 'publisher-seed') return runPublisherSeedAction({ body, node, disabled })
  return { ok: false, kind: 'bad-request', status: 404, payload: errorPayload('unknown seed publish route') }
}
