/**
 * HiveRelay Wire Protocol Messages
 *
 * All messages are encoded using compact-encoding and framed over
 * protomux channels on Hyperswarm connections.
 *
 * Protocol ID: 'hiverelay/1.0.0'
 */

import c from 'compact-encoding'
import b4a from 'b4a'

// Message type constants
export const MSG = {
  // Seeding Registry (0x01 - 0x0F)
  SEED_REQUEST: 0x01,
  SEED_ACCEPT: 0x02,
  SEED_REJECT: 0x03,
  SEED_CANCEL: 0x04,
  SEED_HEARTBEAT: 0x05,
  SEED_STATUS: 0x06,
  SEED_UNSEED: 0x07,

  // Circuit Relay (0x10 - 0x1F)
  RELAY_RESERVE: 0x10,
  RELAY_RESERVE_OK: 0x11,
  RELAY_RESERVE_DENY: 0x12,
  RELAY_CONNECT: 0x13,
  RELAY_CONNECT_OK: 0x14,
  RELAY_CONNECT_DENY: 0x15,
  RELAY_DATA: 0x16,
  RELAY_CLOSE: 0x17,
  RELAY_UPGRADE: 0x18,

  // Proof of Relay (0x20 - 0x2F)
  PROOF_CHALLENGE: 0x20,
  PROOF_RESPONSE: 0x21,
  BANDWIDTH_RECEIPT: 0x22,
  RECEIPT_ACK: 0x23,

  // Peer Discovery (0x30 - 0x3F)
  PEER_ANNOUNCE: 0x30,
  PEER_QUERY: 0x31,
  PEER_RESPONSE: 0x32
}

// Error codes
export const ERR = {
  NONE: 0x00,
  CAPACITY_FULL: 0x01,
  INVALID_REQUEST: 0x02,
  NOT_FOUND: 0x03,
  TIMEOUT: 0x04,
  STORAGE_EXCEEDED: 0x05,
  BANDWIDTH_EXCEEDED: 0x06,
  DURATION_EXCEEDED: 0x07,
  PROOF_FAILED: 0x08,
  UNAUTHORIZED: 0x09,
  PROTOCOL_ERROR: 0x0A,
  INTERNAL_ERROR: 0xFF
}

// Region codes (ISO 3166-1 alpha-2 + continent codes)
export const REGIONS = {
  NA: 'North America',
  SA: 'South America',
  EU: 'Europe',
  AF: 'Africa',
  AS: 'Asia',
  OC: 'Oceania'
}

// --- Encoding schemas ---

// Durability tiers — controls how aggressively the network maintains
// replicas of a drive. Encoded as uint at the end of the seed request.
//
//   0  STANDARD  — current default. Network seeds N times where the
//                  publisher requested. No active replication enforcement.
//   1  ARCHIVE   — auto-heal target. Network maintains the drive at a
//                  diversity threshold (≥7 replicas, ≥4 regions, ≥5
//                  operators). When a replica drops, healthy relays
//                  recruit themselves to restore the threshold.
//
// Higher tiers are reserved for future use (PINNED, MIRROR, etc.). Like
// revocability, this is committed by publisher signature so the publisher
// cannot lie about the tier they originally requested.
export const DURABILITY_STANDARD = 0
export const DURABILITY_ARCHIVE = 1

export const MAX_SEED_DISCOVERY_KEYS = 64
export const MAX_SEED_GEO_PREFERENCE_BYTES = 2048
export const MAX_SEED_REGION_BYTES = 64
export const MAX_SEED_DENY_REASON_BYTES = 128
export const MAX_SEED_DENY_DETAIL_BYTES = 512
export const MAX_PROOF_BLOCK_BYTES = 1024 * 1024
export const MAX_PROOF_MERKLE_PROOF_BYTES = 64 * 1024

function validDecodeState (state) {
  const buffer = state && state.buffer
  if (!buffer || !Number.isSafeInteger(state.start) || !Number.isSafeInteger(state.end)) return false
  return state.start >= 0 && state.end >= state.start && state.end <= buffer.length
}

function malformed (state, error) {
  if (state && Number.isSafeInteger(state.end)) {
    const buffer = state.buffer
    state.start = Math.min(Math.max(state.end, 0), buffer ? buffer.length : state.end)
  }
  return { error }
}

function assertFixedBytes (value, size, field) {
  if (!value || value.byteLength !== size) throw new Error(`${field} must be ${size} bytes`)
  return value
}

function encodeUintValue (value, field) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${field} must be a non-negative integer`)
  return value
}

function encodeStringValue (value, field, maxBytes) {
  const text = value == null ? '' : String(value)
  if (b4a.byteLength(text) > maxBytes) throw new Error(`${field} too large`)
  return text
}

function encodeJsonValue (value, field, maxBytes) {
  const text = JSON.stringify(value == null ? null : value)
  if (typeof text !== 'string') throw new Error(`${field} must be JSON serializable`)
  if (b4a.byteLength(text) > maxBytes) throw new Error(`${field} too large`)
  return text
}

function decodeUint (state, error = 'malformed uint') {
  if (!validDecodeState(state)) return malformed(state, error)
  let value
  try {
    value = c.uint.decode(state)
  } catch (_) {
    return malformed(state, error)
  }
  if (!Number.isSafeInteger(value) || value < 0) return malformed(state, error)
  return { value }
}

function decodeOptionalUint (state, fallback, error = 'malformed uint') {
  if (!validDecodeState(state)) return malformed(state, error)
  if (state.start >= state.end) return { value: fallback }
  return decodeUint(state, error)
}

function decodeFixedBytes (state, size, error) {
  if (!validDecodeState(state)) return malformed(state, error)
  const end = state.start + size
  if (end > state.end) return malformed(state, error)
  const value = state.buffer.subarray(state.start, end)
  state.start = end
  return { value }
}

function decodeBytes (state, maxBytes, tooLargeError, malformedError) {
  if (!validDecodeState(state)) return malformed(state, malformedError)
  let len
  const lenState = { buffer: state.buffer, start: state.start, end: state.end }
  try {
    len = c.uint.decode(lenState)
  } catch (_) {
    return malformed(state, malformedError)
  }
  if (!Number.isSafeInteger(len) || len < 0) return malformed(state, malformedError)
  if (len > maxBytes) {
    state.start = Math.min(state.end, lenState.start + len)
    return { error: tooLargeError }
  }
  const end = lenState.start + len
  if (end > state.end) return malformed(state, malformedError)
  const value = state.buffer.subarray(lenState.start, end)
  state.start = end
  return { value }
}

function decodeString (state, maxBytes, tooLargeError, malformedError) {
  const decoded = decodeBytes(state, maxBytes, tooLargeError, malformedError)
  if (decoded.error) return decoded
  return { value: b4a.toString(decoded.value, 'utf8') }
}

function decodeJsonString (state, maxBytes, tooLargeError, malformedError) {
  const decoded = decodeString(state, maxBytes, tooLargeError, malformedError)
  if (decoded.error) return decoded
  try {
    return { value: JSON.parse(decoded.value) }
  } catch (_) {
    return malformed(state, malformedError)
  }
}

function normalizeSeedRequest (msg) {
  const appKey = assertFixedBytes(msg.appKey, 32, 'appKey')
  const discoveryKeys = Array.isArray(msg.discoveryKeys) ? msg.discoveryKeys : []
  if (discoveryKeys.length > MAX_SEED_DISCOVERY_KEYS) throw new Error('too many discovery keys')
  for (const dk of discoveryKeys) assertFixedBytes(dk, 32, 'discoveryKey')
  const geoPreference = encodeJsonValue(msg.geoPreference || [], 'geoPreference', MAX_SEED_GEO_PREFERENCE_BYTES)
  return {
    appKey,
    discoveryKeys,
    replicationFactor: encodeUintValue(msg.replicationFactor, 'replicationFactor'),
    geoPreference,
    maxStorageBytes: encodeUintValue(msg.maxStorageBytes, 'maxStorageBytes'),
    bountyRate: encodeUintValue(msg.bountyRate || 0, 'bountyRate'),
    ttlSeconds: encodeUintValue(msg.ttlSeconds, 'ttlSeconds'),
    publisherPubkey: assertFixedBytes(msg.publisherPubkey, 32, 'publisherPubkey'),
    publisherSignature: assertFixedBytes(msg.publisherSignature, 64, 'publisherSignature'),
    revocable: msg.revocable === false ? 0 : 1,
    unseedFreezeMs: encodeUintValue(msg.unseedFreezeMs || 0, 'unseedFreezeMs'),
    durability: encodeUintValue(msg.durability || DURABILITY_STANDARD, 'durability')
  }
}

function seedRequestError (error, appKey = null, discoveryKeys = []) {
  return {
    appKey,
    discoveryKeys,
    replicationFactor: 0,
    geoPreference: null,
    maxStorageBytes: 0,
    bountyRate: 0,
    ttlSeconds: 0,
    publisherPubkey: null,
    publisherSignature: null,
    revocable: true,
    unseedFreezeMs: 0,
    durability: DURABILITY_STANDARD,
    error
  }
}

function normalizeSeedAccept (msg) {
  return {
    appKey: assertFixedBytes(msg.appKey, 32, 'appKey'),
    relayPubkey: assertFixedBytes(msg.relayPubkey, 32, 'relayPubkey'),
    region: encodeStringValue(msg.region, 'region', MAX_SEED_REGION_BYTES),
    availableStorageBytes: encodeUintValue(msg.availableStorageBytes, 'availableStorageBytes'),
    relaySignature: assertFixedBytes(msg.relaySignature, 64, 'relaySignature')
  }
}

function normalizeSeedDeny (msg) {
  return {
    appKey: assertFixedBytes(msg.appKey, 32, 'appKey'),
    relayPubkey: assertFixedBytes(msg.relayPubkey, 32, 'relayPubkey'),
    reasonCode: encodeStringValue(msg.reasonCode, 'reasonCode', MAX_SEED_DENY_REASON_BYTES),
    detail: encodeStringValue(msg.detail || '', 'detail', MAX_SEED_DENY_DETAIL_BYTES),
    relaySignature: assertFixedBytes(msg.relaySignature, 64, 'relaySignature')
  }
}

function normalizeUnseedRequest (msg) {
  return {
    appKey: assertFixedBytes(msg.appKey, 32, 'appKey'),
    timestamp: encodeUintValue(msg.timestamp, 'timestamp'),
    publisherPubkey: assertFixedBytes(msg.publisherPubkey, 32, 'publisherPubkey'),
    publisherSignature: assertFixedBytes(msg.publisherSignature, 64, 'publisherSignature')
  }
}

function normalizeProofChallenge (msg) {
  return {
    coreKey: assertFixedBytes(msg.coreKey, 32, 'coreKey'),
    blockIndex: encodeUintValue(msg.blockIndex, 'blockIndex'),
    nonce: assertFixedBytes(msg.nonce, 32, 'nonce'),
    maxLatencyMs: encodeUintValue(msg.maxLatencyMs, 'maxLatencyMs')
  }
}

function proofChallengeError (error, coreKey = null, nonce = null) {
  return {
    coreKey,
    blockIndex: 0,
    nonce,
    maxLatencyMs: 0,
    error
  }
}

function normalizeProofResponse (msg) {
  return {
    coreKey: assertFixedBytes(msg.coreKey, 32, 'coreKey'),
    blockIndex: encodeUintValue(msg.blockIndex, 'blockIndex'),
    blockData: assertBytesWithin(msg.blockData, MAX_PROOF_BLOCK_BYTES, 'blockData'),
    merkleProof: assertBytesWithin(msg.merkleProof || b4a.alloc(0), MAX_PROOF_MERKLE_PROOF_BYTES, 'merkleProof'),
    nonce: assertFixedBytes(msg.nonce, 32, 'nonce')
  }
}

function proofResponseError (error, coreKey = null, nonce = null) {
  return {
    coreKey,
    blockIndex: 0,
    blockData: null,
    merkleProof: null,
    nonce,
    error
  }
}

function assertBytesWithin (value, maxBytes, field) {
  if (!value || !b4a.isBuffer(value)) throw new Error(`${field} must be a buffer`)
  if (value.byteLength > maxBytes) throw new Error(`${field} too large`)
  return value
}

// Wire format for the seed-request includes three newer fields:
// `revocable`, `unseedFreezeMs`, and `durability`. All three are appended
// after the existing payload for forward compatibility; older peers
// decode the prefix successfully and ignore the trailing bytes.
//
// All three values are committed to the publisher signature (see
// SeedProtocol._serializeForSigning).
export const seedRequestEncoding = {
  preencode (state, msg) {
    const normalized = normalizeSeedRequest(msg)
    c.fixed32.preencode(state, normalized.appKey)
    c.uint.preencode(state, normalized.discoveryKeys.length)
    for (const dk of normalized.discoveryKeys) {
      c.fixed32.preencode(state, dk)
    }
    c.uint.preencode(state, normalized.replicationFactor)
    c.string.preencode(state, normalized.geoPreference)
    c.uint.preencode(state, normalized.maxStorageBytes)
    c.uint.preencode(state, normalized.bountyRate)
    c.uint.preencode(state, normalized.ttlSeconds)
    c.fixed32.preencode(state, normalized.publisherPubkey)
    c.fixed64.preencode(state, normalized.publisherSignature)
    c.uint.preencode(state, normalized.revocable)
    c.uint.preencode(state, normalized.unseedFreezeMs)
    c.uint.preencode(state, normalized.durability)
  },
  encode (state, msg) {
    const normalized = normalizeSeedRequest(msg)
    c.fixed32.encode(state, normalized.appKey)
    c.uint.encode(state, normalized.discoveryKeys.length)
    for (const dk of normalized.discoveryKeys) {
      c.fixed32.encode(state, dk)
    }
    c.uint.encode(state, normalized.replicationFactor)
    c.string.encode(state, normalized.geoPreference)
    c.uint.encode(state, normalized.maxStorageBytes)
    c.uint.encode(state, normalized.bountyRate)
    c.uint.encode(state, normalized.ttlSeconds)
    c.fixed32.encode(state, normalized.publisherPubkey)
    c.fixed64.encode(state, normalized.publisherSignature)
    c.uint.encode(state, normalized.revocable)
    c.uint.encode(state, normalized.unseedFreezeMs)
    c.uint.encode(state, normalized.durability)
  },
  decode (state) {
    const appKeyDecoded = decodeFixedBytes(state, 32, 'malformed seed request')
    if (appKeyDecoded.error) return seedRequestError(appKeyDecoded.error)
    const appKey = appKeyDecoded.value

    const dkLenDecoded = decodeUint(state, 'malformed seed request')
    if (dkLenDecoded.error) return seedRequestError(dkLenDecoded.error, appKey)
    if (dkLenDecoded.value > MAX_SEED_DISCOVERY_KEYS) return seedRequestError('too many discovery keys', appKey)

    const discoveryKeys = []
    for (let i = 0; i < dkLenDecoded.value; i++) {
      const dk = decodeFixedBytes(state, 32, 'malformed seed request')
      if (dk.error) return seedRequestError(dk.error, appKey, discoveryKeys)
      discoveryKeys.push(dk.value)
    }

    const replicationFactor = decodeUint(state, 'malformed seed request')
    if (replicationFactor.error) return seedRequestError(replicationFactor.error, appKey, discoveryKeys)
    const geoPreference = decodeJsonString(state, MAX_SEED_GEO_PREFERENCE_BYTES, 'geoPreference too large', 'malformed seed request')
    if (geoPreference.error) return seedRequestError(geoPreference.error, appKey, discoveryKeys)
    const maxStorageBytes = decodeUint(state, 'malformed seed request')
    if (maxStorageBytes.error) return seedRequestError(maxStorageBytes.error, appKey, discoveryKeys)
    const bountyRate = decodeUint(state, 'malformed seed request')
    if (bountyRate.error) return seedRequestError(bountyRate.error, appKey, discoveryKeys)
    const ttlSeconds = decodeUint(state, 'malformed seed request')
    if (ttlSeconds.error) return seedRequestError(ttlSeconds.error, appKey, discoveryKeys)
    const publisherPubkey = decodeFixedBytes(state, 32, 'malformed seed request')
    if (publisherPubkey.error) return seedRequestError(publisherPubkey.error, appKey, discoveryKeys)
    const publisherSignature = decodeFixedBytes(state, 64, 'malformed seed request')
    if (publisherSignature.error) return seedRequestError(publisherSignature.error, appKey, discoveryKeys)

    const out = {
      appKey,
      discoveryKeys,
      replicationFactor: replicationFactor.value,
      geoPreference: geoPreference.value,
      maxStorageBytes: maxStorageBytes.value,
      bountyRate: bountyRate.value,
      ttlSeconds: ttlSeconds.value,
      publisherPubkey: publisherPubkey.value,
      publisherSignature: publisherSignature.value
    }
    // Backward-compatible decode of the revocability + durability tail.
    // Older clients produce wire data without these fields; treat the
    // absence as the permissive default.
    const revocable = decodeOptionalUint(state, 1, 'malformed seed request')
    if (revocable.error) return seedRequestError(revocable.error, appKey, discoveryKeys)
    out.revocable = revocable.value !== 0
    const unseedFreezeMs = decodeOptionalUint(state, 0, 'malformed seed request')
    if (unseedFreezeMs.error) return seedRequestError(unseedFreezeMs.error, appKey, discoveryKeys)
    out.unseedFreezeMs = unseedFreezeMs.value
    const durability = decodeOptionalUint(state, DURABILITY_STANDARD, 'malformed seed request')
    if (durability.error) return seedRequestError(durability.error, appKey, discoveryKeys)
    out.durability = durability.value
    return out
  }
}

export const seedAcceptEncoding = {
  preencode (state, msg) {
    const normalized = normalizeSeedAccept(msg)
    c.fixed32.preencode(state, normalized.appKey)
    c.fixed32.preencode(state, normalized.relayPubkey)
    c.string.preencode(state, normalized.region)
    c.uint.preencode(state, normalized.availableStorageBytes)
    c.fixed64.preencode(state, normalized.relaySignature)
  },
  encode (state, msg) {
    const normalized = normalizeSeedAccept(msg)
    c.fixed32.encode(state, normalized.appKey)
    c.fixed32.encode(state, normalized.relayPubkey)
    c.string.encode(state, normalized.region)
    c.uint.encode(state, normalized.availableStorageBytes)
    c.fixed64.encode(state, normalized.relaySignature)
  },
  decode (state) {
    const appKey = decodeFixedBytes(state, 32, 'malformed seed accept')
    if (appKey.error) return { appKey: null, relayPubkey: null, region: '', availableStorageBytes: 0, relaySignature: null, error: appKey.error }
    const relayPubkey = decodeFixedBytes(state, 32, 'malformed seed accept')
    if (relayPubkey.error) return { appKey: appKey.value, relayPubkey: null, region: '', availableStorageBytes: 0, relaySignature: null, error: relayPubkey.error }
    const region = decodeString(state, MAX_SEED_REGION_BYTES, 'region too large', 'malformed seed accept')
    if (region.error) return { appKey: appKey.value, relayPubkey: relayPubkey.value, region: '', availableStorageBytes: 0, relaySignature: null, error: region.error }
    const availableStorageBytes = decodeUint(state, 'malformed seed accept')
    if (availableStorageBytes.error) return { appKey: appKey.value, relayPubkey: relayPubkey.value, region: region.value, availableStorageBytes: 0, relaySignature: null, error: availableStorageBytes.error }
    const relaySignature = decodeFixedBytes(state, 64, 'malformed seed accept')
    if (relaySignature.error) return { appKey: appKey.value, relayPubkey: relayPubkey.value, region: region.value, availableStorageBytes: availableStorageBytes.value, relaySignature: null, error: relaySignature.error }
    return {
      appKey: appKey.value,
      relayPubkey: relayPubkey.value,
      region: region.value,
      availableStorageBytes: availableStorageBytes.value,
      relaySignature: relaySignature.value
    }
  }
}

/**
 * Seed deny: relay tells the requesting publisher WHY a seed request was
 * refused (or queued), instead of going silent and letting the publisher
 * time out. Reason codes are stable machine-readable strings:
 *
 *   'signature-required'                    — no publisher signature at all
 *   'archive-requires-publisher-signature'  — durability ≥ 1 without a valid
 *                                             v2 publisher signature
 *   'bad-signature'                         — signature present but invalid
 *   'insufficient-storage'                  — relay capacity exhausted
 *   'accept-mode:<mode>'                    — relay policy refused (allowlist/closed)
 *   'delegation:<reason>'                   — delegation cert chain failed
 *   'queued-for-review'                     — NOT terminal: pending operator approval
 *
 * Sent only on the requesting channel (never broadcast), signed by the
 * relay's keyPair when available. Old peers that predate this message
 * ignore it (protomux drops unknown message ids), so the worst case
 * degrades to today's behavior: timeout.
 */
export const seedDenyEncoding = {
  preencode (state, msg) {
    const normalized = normalizeSeedDeny(msg)
    c.fixed32.preencode(state, normalized.appKey)
    c.fixed32.preencode(state, normalized.relayPubkey)
    c.string.preencode(state, normalized.reasonCode)
    c.string.preencode(state, normalized.detail)
    c.fixed64.preencode(state, normalized.relaySignature)
  },
  encode (state, msg) {
    const normalized = normalizeSeedDeny(msg)
    c.fixed32.encode(state, normalized.appKey)
    c.fixed32.encode(state, normalized.relayPubkey)
    c.string.encode(state, normalized.reasonCode)
    c.string.encode(state, normalized.detail)
    c.fixed64.encode(state, normalized.relaySignature)
  },
  decode (state) {
    const appKey = decodeFixedBytes(state, 32, 'malformed seed deny')
    if (appKey.error) return { appKey: null, relayPubkey: null, reasonCode: 'protocol-error', detail: appKey.error, relaySignature: null, error: appKey.error }
    const relayPubkey = decodeFixedBytes(state, 32, 'malformed seed deny')
    if (relayPubkey.error) return { appKey: appKey.value, relayPubkey: null, reasonCode: 'protocol-error', detail: relayPubkey.error, relaySignature: null, error: relayPubkey.error }
    const reasonCode = decodeString(state, MAX_SEED_DENY_REASON_BYTES, 'reasonCode too large', 'malformed seed deny')
    if (reasonCode.error) return { appKey: appKey.value, relayPubkey: relayPubkey.value, reasonCode: 'protocol-error', detail: reasonCode.error, relaySignature: null, error: reasonCode.error }
    const detail = decodeString(state, MAX_SEED_DENY_DETAIL_BYTES, 'detail too large', 'malformed seed deny')
    if (detail.error) return { appKey: appKey.value, relayPubkey: relayPubkey.value, reasonCode: reasonCode.value, detail: detail.error, relaySignature: null, error: detail.error }
    const relaySignature = decodeFixedBytes(state, 64, 'malformed seed deny')
    if (relaySignature.error) return { appKey: appKey.value, relayPubkey: relayPubkey.value, reasonCode: reasonCode.value, detail: detail.value, relaySignature: null, error: relaySignature.error }
    return {
      appKey: appKey.value,
      relayPubkey: relayPubkey.value,
      reasonCode: reasonCode.value,
      detail: detail.value,
      relaySignature: relaySignature.value
    }
  }
}

/**
 * Unseed request: developer requests relay to stop seeding their app.
 * Signed by the publisher's key to prove ownership.
 * { appKey: Buffer(32), timestamp: uint, publisherPubkey: Buffer(32), publisherSignature: Buffer(64) }
 */
export const unseedRequestEncoding = {
  preencode (state, msg) {
    const normalized = normalizeUnseedRequest(msg)
    c.fixed32.preencode(state, normalized.appKey)
    c.uint.preencode(state, normalized.timestamp)
    c.fixed32.preencode(state, normalized.publisherPubkey)
    c.fixed64.preencode(state, normalized.publisherSignature)
  },
  encode (state, msg) {
    const normalized = normalizeUnseedRequest(msg)
    c.fixed32.encode(state, normalized.appKey)
    c.uint.encode(state, normalized.timestamp)
    c.fixed32.encode(state, normalized.publisherPubkey)
    c.fixed64.encode(state, normalized.publisherSignature)
  },
  decode (state) {
    const appKey = decodeFixedBytes(state, 32, 'malformed unseed request')
    if (appKey.error) return { appKey: null, timestamp: 0, publisherPubkey: null, publisherSignature: null, error: appKey.error }
    const timestamp = decodeUint(state, 'malformed unseed request')
    if (timestamp.error) return { appKey: appKey.value, timestamp: 0, publisherPubkey: null, publisherSignature: null, error: timestamp.error }
    const publisherPubkey = decodeFixedBytes(state, 32, 'malformed unseed request')
    if (publisherPubkey.error) return { appKey: appKey.value, timestamp: timestamp.value, publisherPubkey: null, publisherSignature: null, error: publisherPubkey.error }
    const publisherSignature = decodeFixedBytes(state, 64, 'malformed unseed request')
    if (publisherSignature.error) return { appKey: appKey.value, timestamp: timestamp.value, publisherPubkey: publisherPubkey.value, publisherSignature: null, error: publisherSignature.error }
    return {
      appKey: appKey.value,
      timestamp: timestamp.value,
      publisherPubkey: publisherPubkey.value,
      publisherSignature: publisherSignature.value
    }
  }
}

export const proofChallengeEncoding = {
  preencode (state, msg) {
    const normalized = normalizeProofChallenge(msg)
    c.fixed32.preencode(state, normalized.coreKey)
    c.uint.preencode(state, normalized.blockIndex)
    c.fixed32.preencode(state, normalized.nonce)
    c.uint.preencode(state, normalized.maxLatencyMs)
  },
  encode (state, msg) {
    const normalized = normalizeProofChallenge(msg)
    c.fixed32.encode(state, normalized.coreKey)
    c.uint.encode(state, normalized.blockIndex)
    c.fixed32.encode(state, normalized.nonce)
    c.uint.encode(state, normalized.maxLatencyMs)
  },
  decode (state) {
    const coreKey = decodeFixedBytes(state, 32, 'malformed proof challenge')
    if (coreKey.error) return proofChallengeError(coreKey.error)
    const blockIndex = decodeUint(state, 'malformed proof challenge')
    if (blockIndex.error) return proofChallengeError(blockIndex.error, coreKey.value)
    const nonce = decodeFixedBytes(state, 32, 'malformed proof challenge')
    if (nonce.error) return proofChallengeError(nonce.error, coreKey.value)
    const maxLatencyMs = decodeUint(state, 'malformed proof challenge')
    if (maxLatencyMs.error) return proofChallengeError(maxLatencyMs.error, coreKey.value, nonce.value)
    return {
      coreKey: coreKey.value,
      blockIndex: blockIndex.value,
      nonce: nonce.value,
      maxLatencyMs: maxLatencyMs.value
    }
  }
}

export const proofResponseEncoding = {
  preencode (state, msg) {
    const normalized = normalizeProofResponse(msg)
    c.fixed32.preencode(state, normalized.coreKey)
    c.uint.preencode(state, normalized.blockIndex)
    c.buffer.preencode(state, normalized.blockData)
    c.buffer.preencode(state, normalized.merkleProof)
    c.fixed32.preencode(state, normalized.nonce)
  },
  encode (state, msg) {
    const normalized = normalizeProofResponse(msg)
    c.fixed32.encode(state, normalized.coreKey)
    c.uint.encode(state, normalized.blockIndex)
    c.buffer.encode(state, normalized.blockData)
    c.buffer.encode(state, normalized.merkleProof)
    c.fixed32.encode(state, normalized.nonce)
  },
  decode (state) {
    const coreKey = decodeFixedBytes(state, 32, 'malformed proof response')
    if (coreKey.error) return proofResponseError(coreKey.error)
    const blockIndex = decodeUint(state, 'malformed proof response')
    if (blockIndex.error) return proofResponseError(blockIndex.error, coreKey.value)
    const blockData = decodeBytes(state, MAX_PROOF_BLOCK_BYTES, 'blockData too large', 'malformed proof response')
    if (blockData.error) return proofResponseError(blockData.error, coreKey.value)
    const merkleProof = decodeBytes(state, MAX_PROOF_MERKLE_PROOF_BYTES, 'merkleProof too large', 'malformed proof response')
    if (merkleProof.error) return proofResponseError(merkleProof.error, coreKey.value)
    const nonce = decodeFixedBytes(state, 32, 'malformed proof response')
    if (nonce.error) return proofResponseError(nonce.error, coreKey.value)
    return {
      coreKey: coreKey.value,
      blockIndex: blockIndex.value,
      blockData: blockData.value,
      merkleProof: merkleProof.value,
      nonce: nonce.value
    }
  }
}

// bandwidthReceiptEncoding removed — BandwidthReceipt class does its own signing/encoding

export const relayReserveEncoding = {
  preencode (state, msg) {
    c.fixed32.preencode(state, msg.peerPubkey)
    c.uint.preencode(state, msg.maxDurationMs)
    c.uint.preencode(state, msg.maxBytes)
  },
  encode (state, msg) {
    c.fixed32.encode(state, msg.peerPubkey)
    c.uint.encode(state, msg.maxDurationMs)
    c.uint.encode(state, msg.maxBytes)
  },
  decode (state) {
    return {
      peerPubkey: c.fixed32.decode(state),
      maxDurationMs: c.uint.decode(state),
      maxBytes: c.uint.decode(state)
    }
  }
}
