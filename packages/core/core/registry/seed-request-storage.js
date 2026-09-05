import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  isValidHexKey,
  normalizeAvailabilityClass,
  normalizeContentType,
  normalizePrivacyTier,
  normalizeStorageClass
} from '../constants.js'
import { positiveStorageBound } from '../../config/storage-cap.js'
import { verifySeedRequestSignatureDetails } from '../protocol/seed-request.js'
import { validateSeedDiscoveryHints } from '../protocol/seed-discovery-hints.js'

export const STORED_SEED_REQUEST_VERSION = 1
export const STORED_SEED_REQUEST_KINDS = Object.freeze([
  'publisher-signed',
  'authenticated-peer-legacy',
  'authenticated-local-management',
  'quarantine'
])
export const SEED_REQUEST_QUARANTINE_REASONS = Object.freeze([
  'missing-provenance',
  'invalid-provenance',
  'signature-invalid',
  'origin-drift',
  'unsupported-discovery-key-set',
  'schema-invalid'
])

const SIGNATURE_PROFILES = new Set(['replay-v1', 'domain-v3', 'legacy-v2', 'legacy-v1'])
const REQUEST_FIELDS = Object.freeze([
  'type', 'timestamp', 'appKey', 'discoveryKeys', 'replicationFactor',
  'maxStorageBytes', 'ttlSeconds', 'bountyRate', 'revocable',
  'unseedFreezeMs', 'durability', 'publisherPubkey', 'publisherSignature',
  'issuedAt', 'requestNonce', 'signatureProfile'
])
const METADATA_FIELDS = Object.freeze([
  'contentType', 'parentKey', 'mountPath', 'geoPreference', 'privacyTier',
  'blind', 'storageClass', 'availabilityClass', 'custodyIntentId',
  'blindContentId', 'ciphertextRoot', 'commitmentRoot', 'contentVersion',
  'retainUntil', 'shardIds', 'shareScheme', 'shareThreshold', 'leaseDays'
])
function hex (value, bytes) {
  if (b4a.isBuffer(value)) return value.byteLength === bytes ? b4a.toString(value, 'hex') : null
  if (typeof value !== 'string' || !isValidHexKey(value, bytes * 2)) return null
  return value.toLowerCase()
}

function safeInteger (value, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  return Number.isSafeInteger(value) && value >= min && value <= max ? value : null
}

function exactKeys (value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const keys = Object.keys(value).sort()
  const expected = [...fields].sort()
  return keys.length === expected.length && keys.every((key, index) => key === expected[index])
}

function nullableHex (value, bytes = 32) {
  return value === null ? null : hex(value, bytes)
}

function normalizeRequest (input, { exact = false } = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null
  if (exact && !exactKeys(input, REQUEST_FIELDS)) return null
  const appKey = hex(input.appKey, 32)
  const publisherPubkey = hex(input.publisherPubkey, 32)
  const publisherSignature = input.publisherSignature == null ? null : hex(input.publisherSignature, 64)
  const timestamp = safeInteger(input.timestamp, { min: 1 })
  const replicationFactor = safeInteger(input.replicationFactor, { min: 1, max: 255 })
  const maxStorageBytes = positiveStorageBound(input.maxStorageBytes)
  const ttlSeconds = safeInteger(input.ttlSeconds)
  const bountyRate = safeInteger(input.bountyRate, { max: 0xffffffff })
  const unseedFreezeMs = safeInteger(input.unseedFreezeMs)
  const durability = safeInteger(input.durability, { max: 255 })
  if (input.type !== 'seed-request' || !appKey || !publisherPubkey || timestamp === null ||
      replicationFactor === null || maxStorageBytes === null || ttlSeconds === null ||
      bountyRate === null || typeof input.revocable !== 'boolean' ||
      unseedFreezeMs === null || durability === null ||
      !Array.isArray(input.discoveryKeys) ||
      (input.publisherSignature != null && publisherSignature === null)) return null
  const discoveryKeys = input.discoveryKeys.map(value => hex(value, 32))
  if (discoveryKeys.some(value => value === null)) return null
  const hints = validateSeedDiscoveryHints(appKey, discoveryKeys)
  if (!hints.ok) return { error: 'unsupported-discovery-key-set' }

  const issuedAt = input.issuedAt == null ? null : safeInteger(input.issuedAt)
  const requestNonce = input.requestNonce == null ? null : hex(input.requestNonce, 16)
  const signatureProfile = input.signatureProfile == null ? null : input.signatureProfile
  if ((input.issuedAt != null && issuedAt === null) ||
      (input.requestNonce != null && requestNonce === null) ||
      (issuedAt === null) !== (requestNonce === null) ||
      (signatureProfile !== null && !SIGNATURE_PROFILES.has(signatureProfile))) return null

  return {
    type: 'seed-request',
    timestamp,
    appKey,
    discoveryKeys,
    replicationFactor,
    maxStorageBytes,
    ttlSeconds,
    bountyRate,
    revocable: input.revocable,
    unseedFreezeMs,
    durability,
    publisherPubkey,
    publisherSignature,
    issuedAt,
    requestNonce,
    signatureProfile
  }
}

function normalizeMetadata (input, { exact = false } = {}) {
  input = input && typeof input === 'object' && !Array.isArray(input) ? input : {}
  if (exact && !exactKeys(input, METADATA_FIELDS)) return null
  const contentType = normalizeContentType(input.contentType, null)
  const privacyTier = normalizePrivacyTier(input.privacyTier, null)
  const blind = input.blind === true
  const storageClass = normalizeStorageClass(input.storageClass, null)
  const availabilityClass = normalizeAvailabilityClass(input.availabilityClass, null)
  if (!contentType || !privacyTier || !storageClass || !availabilityClass || typeof input.blind !== 'boolean') return null

  const parentKey = nullableHex(input.parentKey)
  if (input.parentKey !== null && parentKey === null) return null
  const hexFields = {}
  for (const field of ['custodyIntentId', 'blindContentId', 'ciphertextRoot', 'commitmentRoot']) {
    hexFields[field] = nullableHex(input[field])
    if (input[field] !== null && hexFields[field] === null) return null
  }
  if (input.mountPath !== null && typeof input.mountPath !== 'string') return null
  if (!Array.isArray(input.geoPreference) || input.geoPreference.some(value => typeof value !== 'string')) return null
  if (!Array.isArray(input.shardIds) || input.shardIds.some(value => safeInteger(value) === null)) return null

  const contentVersion = input.contentVersion == null ? null : safeInteger(input.contentVersion)
  const retainUntil = input.retainUntil == null ? null : safeInteger(input.retainUntil)
  const shareThreshold = input.shareThreshold == null ? null : safeInteger(input.shareThreshold, { min: 1, max: 255 })
  const leaseDays = input.leaseDays == null ? null : safeInteger(input.leaseDays, { min: 1 })
  if ((input.contentVersion != null && contentVersion === null) ||
      (input.retainUntil != null && retainUntil === null) ||
      (input.shareThreshold != null && shareThreshold === null) ||
      (input.leaseDays != null && leaseDays === null) ||
      (input.shareScheme !== null && typeof input.shareScheme !== 'string')) return null

  return {
    contentType,
    parentKey,
    mountPath: input.mountPath,
    geoPreference: [...input.geoPreference],
    privacyTier,
    blind,
    storageClass,
    availabilityClass,
    ...hexFields,
    contentVersion,
    retainUntil,
    shardIds: [...input.shardIds],
    shareScheme: input.shareScheme,
    shareThreshold,
    leaseDays
  }
}

function requestFromFlatEntry (entry) {
  return normalizeRequest({
    type: 'seed-request',
    timestamp: entry.timestamp,
    appKey: entry.appKey,
    discoveryKeys: entry.discoveryKeys ?? [],
    replicationFactor: entry.replicationFactor ?? 3,
    maxStorageBytes: entry.maxStorageBytes,
    ttlSeconds: entry.ttlSeconds ?? 30 * 24 * 3600,
    bountyRate: entry.bountyRate ?? 0,
    revocable: entry.revocable !== false,
    unseedFreezeMs: entry.unseedFreezeMs ?? 0,
    durability: entry.durability ?? 0,
    publisherPubkey: entry.publisherPubkey,
    publisherSignature: entry.publisherSignature ?? null,
    issuedAt: entry.issuedAt ?? null,
    requestNonce: entry.requestNonce ?? null,
    signatureProfile: entry.signatureProfile ?? entry.seedSignatureProfile ?? null
  })
}

function metadataFromFlatEntry (entry) {
  const blind = entry.blind === true
  return normalizeMetadata({
    contentType: normalizeContentType(entry.contentType || 'app', 'app'),
    parentKey: entry.parentKey ? hex(entry.parentKey, 32) : null,
    mountPath: typeof entry.mountPath === 'string' ? entry.mountPath : null,
    geoPreference: Array.isArray(entry.geoPreference) ? entry.geoPreference : [],
    privacyTier: normalizePrivacyTier(entry.privacyTier, 'public'),
    blind,
    storageClass: normalizeStorageClass(entry.storageClass, blind ? 'temporary' : 'persistent'),
    availabilityClass: normalizeAvailabilityClass(entry.availabilityClass, blind ? 'atomic-handoff' : 'always-on'),
    custodyIntentId: hex(entry.custodyIntentId, 32),
    blindContentId: hex(entry.blindContentId, 32),
    ciphertextRoot: hex(entry.ciphertextRoot, 32),
    commitmentRoot: hex(entry.commitmentRoot, 32),
    contentVersion: entry.contentVersion ?? null,
    retainUntil: entry.retainUntil ?? null,
    shardIds: Array.isArray(entry.shardIds) ? entry.shardIds : [],
    shareScheme: typeof entry.shareScheme === 'string' ? entry.shareScheme : null,
    shareThreshold: entry.shareThreshold ?? null,
    leaseDays: entry.leaseDays ?? null
  })
}

function signatureResult (request) {
  if (!request.publisherSignature) return { ok: false, reason: 'signature-invalid' }
  const msg = {
    ...request,
    appKey: b4a.from(request.appKey, 'hex'),
    discoveryKeys: request.discoveryKeys.map(value => b4a.from(value, 'hex')),
    publisherPubkey: b4a.from(request.publisherPubkey, 'hex'),
    publisherSignature: b4a.from(request.publisherSignature, 'hex')
  }
  if (request.requestNonce !== null) msg.requestNonce = b4a.from(request.requestNonce, 'hex')
  else delete msg.requestNonce
  if (request.issuedAt === null) delete msg.issuedAt
  const details = verifySeedRequestSignatureDetails(msg)
  return details.ok ? details : { ok: false, reason: 'signature-invalid' }
}

function storedKeysForKind (kind) {
  if (kind === 'publisher-signed') {
    return ['kind', 'version', 'request', 'metadata', 'authenticatedPeerPubkey', 'originLogKey']
  }
  if (kind === 'authenticated-peer-legacy') {
    return ['kind', 'version', 'request', 'metadata', 'authenticatedPeerPubkey', 'originLogKey']
  }
  if (kind === 'authenticated-local-management') {
    return ['kind', 'version', 'request', 'metadata', 'localSwarmPubkey', 'originLogKey']
  }
  return ['kind', 'version', 'reason', 'observedPeerPubkey', 'observedLogKey', 'recordSha256']
}

export function isStoredSeedRequest (value) {
  return !!value && typeof value === 'object' && STORED_SEED_REQUEST_KINDS.includes(value.kind)
}

export function quarantineSeedRequest (raw, reason, context = {}) {
  if (!SEED_REQUEST_QUARANTINE_REASONS.includes(reason)) reason = 'schema-invalid'
  const bytes = b4a.isBuffer(raw) ? raw : b4a.from(typeof raw === 'string' ? raw : JSON.stringify(raw ?? null))
  const digest = b4a.alloc(32)
  sodium.crypto_hash_sha256(digest, bytes)
  return {
    kind: 'quarantine',
    version: STORED_SEED_REQUEST_VERSION,
    reason,
    observedPeerPubkey: hex(context.authenticatedPeerPubkey, 32),
    observedLogKey: hex(context.originLogKey, 32),
    recordSha256: b4a.toString(digest, 'hex')
  }
}

export function storeLegacySeedRequest (entry, context = {}) {
  const request = requestFromFlatEntry(entry)
  if (!request) return { ok: false, reason: 'schema-invalid' }
  if (request.error) return { ok: false, reason: request.error }
  const metadata = metadataFromFlatEntry(entry)
  if (!metadata) return { ok: false, reason: 'schema-invalid' }

  const authenticatedPeerPubkey = hex(context.authenticatedPeerPubkey, 32)
  const originLogKey = hex(context.originLogKey, 32)
  const localSwarmPubkey = hex(context.localSwarmPubkey, 32)
  if (request.publisherSignature) {
    const verified = signatureResult(request)
    if (!verified.ok) return { ok: false, reason: 'signature-invalid' }
    request.signatureProfile = verified.layout
    return {
      ok: true,
      stored: {
        kind: 'publisher-signed',
        version: STORED_SEED_REQUEST_VERSION,
        request,
        metadata,
        authenticatedPeerPubkey: authenticatedPeerPubkey || localSwarmPubkey,
        originLogKey
      }
    }
  }

  request.signatureProfile = null
  request.issuedAt = null
  request.requestNonce = null
  if (authenticatedPeerPubkey && originLogKey && request.publisherPubkey === authenticatedPeerPubkey) {
    return {
      ok: true,
      stored: {
        kind: 'authenticated-peer-legacy',
        version: STORED_SEED_REQUEST_VERSION,
        request,
        metadata,
        authenticatedPeerPubkey,
        originLogKey
      }
    }
  }
  if (context.local === true && localSwarmPubkey && originLogKey && request.publisherPubkey === localSwarmPubkey) {
    return {
      ok: true,
      stored: {
        kind: 'authenticated-local-management',
        version: STORED_SEED_REQUEST_VERSION,
        request,
        metadata,
        localSwarmPubkey,
        originLogKey
      }
    }
  }
  return { ok: false, reason: authenticatedPeerPubkey || localSwarmPubkey ? 'invalid-provenance' : 'missing-provenance' }
}

export function verifyStoredSeedRequest (stored, context = {}) {
  if (!isStoredSeedRequest(stored) || stored.version !== STORED_SEED_REQUEST_VERSION ||
      !exactKeys(stored, storedKeysForKind(stored?.kind))) return { ok: false, reason: 'schema-invalid' }
  if (stored.kind === 'quarantine') {
    const peer = nullableHex(stored.observedPeerPubkey)
    const log = nullableHex(stored.observedLogKey)
    if (!SEED_REQUEST_QUARANTINE_REASONS.includes(stored.reason) ||
        (stored.observedPeerPubkey !== null && peer === null) ||
        (stored.observedLogKey !== null && log === null) ||
        !hex(stored.recordSha256, 32)) return { ok: false, reason: 'schema-invalid' }
    return { ok: true, quarantine: true, stored }
  }

  const request = normalizeRequest(stored.request, { exact: true })
  if (!request) return { ok: false, reason: 'schema-invalid' }
  if (request.error) return { ok: false, reason: request.error }
  const metadata = normalizeMetadata(stored.metadata, { exact: true })
  if (!metadata) return { ok: false, reason: 'schema-invalid' }
  const actualPeer = hex(context.authenticatedPeerPubkey, 32)
  const actualLog = hex(context.originLogKey, 32)

  if (stored.kind === 'publisher-signed') {
    const peer = nullableHex(stored.authenticatedPeerPubkey)
    const log = nullableHex(stored.originLogKey)
    if ((stored.authenticatedPeerPubkey !== null && peer === null) ||
        (stored.originLogKey !== null && log === null)) return { ok: false, reason: 'invalid-provenance' }
    if ((actualPeer && peer && actualPeer !== peer) || (actualLog && log && actualLog !== log)) {
      return { ok: false, reason: 'origin-drift' }
    }
    const verified = signatureResult(request)
    if (!verified.ok || verified.layout !== request.signatureProfile) return { ok: false, reason: 'signature-invalid' }
  } else if (stored.kind === 'authenticated-peer-legacy') {
    const peer = hex(stored.authenticatedPeerPubkey, 32)
    const log = hex(stored.originLogKey, 32)
    if (!peer || !log || peer !== request.publisherPubkey || request.publisherSignature !== null ||
        request.signatureProfile !== null || request.issuedAt !== null || request.requestNonce !== null) {
      return { ok: false, reason: 'invalid-provenance' }
    }
    if ((actualPeer && actualPeer !== peer) || (actualLog && actualLog !== log)) return { ok: false, reason: 'origin-drift' }
  } else {
    const local = hex(stored.localSwarmPubkey, 32)
    const log = hex(stored.originLogKey, 32)
    const currentLocal = hex(context.localSwarmPubkey, 32)
    const currentLog = hex(context.localLogKey, 32)
    if (!local || !log || !currentLocal || !currentLog || local !== currentLocal ||
        log !== currentLog || local !== request.publisherPubkey || request.publisherSignature !== null ||
        request.signatureProfile !== null || request.issuedAt !== null || request.requestNonce !== null) {
      return { ok: false, reason: 'origin-drift' }
    }
  }

  return {
    ok: true,
    quarantine: false,
    stored: { ...stored, request, metadata },
    entry: { ...request, ...metadata, seedSignatureProfile: request.signatureProfile }
  }
}

export const STORED_SEED_REQUEST_FIELDS = Object.freeze({
  request: REQUEST_FIELDS,
  metadata: METADATA_FIELDS
})
