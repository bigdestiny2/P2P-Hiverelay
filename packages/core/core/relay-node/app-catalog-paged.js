import b4a from 'b4a'
import sodium from 'sodium-universal'

export const APP_CATALOG_PAGED_PROTOCOL = 'hiverelay/app-catalog-paged'
export const APP_CATALOG_PAGED_ID = b4a.from('app-catalog-paged-v1')

export const APP_CATALOG_MESSAGE = Object.freeze({
  CAPABILITY_CHALLENGE: 0,
  CAPABILITY_PROOF: 1,
  PAGE: 2,
  ACK: 3,
  ABORT: 4
})

export const APP_CATALOG_ABORT_CODES = Object.freeze([
  'HISTORY_EXPIRED',
  'CURSOR_EXPIRED',
  'CATALOG_ENTRY_TOO_LARGE',
  'SNAPSHOT_MISMATCH',
  'RESOURCE_LIMIT',
  'PROTOCOL_ERROR'
])

export const APP_CATALOG_LIMITS = Object.freeze({
  maxPayloadBytes: 65_536,
  maxPageEntries: 128,
  maxSnapshotEntries: 262_144,
  maxPagesPerTurn: 16,
  maxMvccRecords: 4_096,
  maxMvccBytes: 16_777_216,
  maxOutboundPeers: 256,
  maxInboundPeers: 256,
  maxInboundSessionBytes: 67_108_864,
  maxInboundStagingBytes: 268_435_456,
  negotiationTimeoutMs: 30_000,
  capabilityClockSkewMs: 60_000,
  ackTimeoutMs: 30_000,
  maxPageRetransmits: 2,
  inboundIdleTimeoutMs: 30_000,
  inboundHardTimeoutMs: 2 * 60 * 60 * 1_000,
  maxLegacyEntries: 128,
  externalApiMaxPageEntries: 500,
  externalStatusMaxPageEntries: 200
})

const HEX_64 = /^[0-9a-f]{64}$/
const HEX_128 = /^[0-9a-f]{128}$/
const PRINTABLE_ASCII = /^[\x20-\x7e]+$/
const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/

const CHALLENGE_FIELDS = ['type', 'nonce']
const PROOF_FIELDS = [
  'type',
  'nonce',
  'senderPubkey',
  'protocolMajor',
  'protocolMinor',
  'features',
  'issuedAt',
  'signature'
]
const PAGE_FIELDS = [
  'type',
  'version',
  'senderPubkey',
  'receiverPubkey',
  'snapshotId',
  'highWater',
  'rootDigest',
  'entryCount',
  'sequence',
  'cursor',
  'nextCursor',
  'complete',
  'entries',
  'pageDigest',
  'signature'
]
const ACK_FIELDS = [
  'type',
  'version',
  'senderPubkey',
  'receiverPubkey',
  'snapshotId',
  'highWater',
  'rootDigest',
  'sequence',
  'pageDigest',
  'nextCursor',
  'signature'
]
const ABORT_FIELDS = [
  'type',
  'version',
  'senderPubkey',
  'receiverPubkey',
  'snapshotId',
  'code',
  'signature'
]
const EXTERNAL_CURSOR_FIELDS = [
  'kind',
  'version',
  'highWater',
  'rootDigest',
  'lastRowKey',
  'signerPubkey',
  'signature'
]
const RAW_APP_CATALOG_FRAMES = new WeakMap()

export const APP_CATALOG_ROW_FIELDS = Object.freeze([
  'rowKey',
  'appKey',
  'appId',
  'type',
  'parentKey',
  'mountPath',
  'version',
  'discoveryKey',
  'blind',
  'storageClass',
  'availabilityClass',
  'privacyTier',
  'seededAt',
  'redacted',
  'metadataVisibility',
  'blindContentId',
  'anchored',
  'maxStorageBytes',
  'publisherPubkey',
  'durability',
  'revocable',
  'retainUntil'
])

const APP_CATALOG_RECORD_FIELDS = APP_CATALOG_ROW_FIELDS.slice(1)

export class AppCatalogProtocolError extends Error {
  constructor (code, message = code) {
    super(message)
    this.name = 'AppCatalogProtocolError'
    this.code = code
    this.catalogChannelFatal = true
  }
}

function fail (code, message) {
  throw new AppCatalogProtocolError(code, message)
}

function own (value, key) {
  return Object.prototype.hasOwnProperty.call(value, key)
}

function assertExactObject (value, fields, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('PROTOCOL_ERROR', `${name} must be a JSON object`)
  }
  const keys = Object.keys(value)
  if (keys.length !== fields.length) {
    fail('PROTOCOL_ERROR', `${name} has an unknown or missing field`)
  }
  const expected = new Set(fields)
  for (const key of keys) {
    if (!expected.has(key)) fail('PROTOCOL_ERROR', `${name} has unknown field ${key}`)
  }
  for (const field of fields) {
    if (!own(value, field)) fail('PROTOCOL_ERROR', `${name} is missing ${field}`)
  }
  return value
}

function assertSafeInteger (value, field, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < 0 || value > max || Object.is(value, -0)) {
    fail('PROTOCOL_ERROR', `${field} must be a non-negative safe integer`)
  }
  return value
}

function assertHex (value, size, field, nullable = false) {
  if (nullable && value === null) return null
  const pattern = size === 64 ? HEX_64 : HEX_128
  if (typeof value !== 'string' || !pattern.test(value)) {
    fail('PROTOCOL_ERROR', `${field} must be lowercase ${size}-hex`)
  }
  return value
}

function assertBoolean (value, field) {
  if (typeof value !== 'boolean') fail('PROTOCOL_ERROR', `${field} must be boolean`)
  return value
}

function strictUtf8Bytes (value, field) {
  if (typeof value !== 'string') fail('PROTOCOL_ERROR', `${field} must be a string`)
  const encoded = b4a.from(value, 'utf8')
  if (b4a.toString(encoded, 'utf8') !== value) {
    fail('PROTOCOL_ERROR', `${field} must be strict UTF-8`)
  }
  return encoded
}

function hasControlCharacters (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) return true
  }
  return false
}

function assertNfcText (value, field, minBytes, maxBytes, nullable = false) {
  if (nullable && value === null) return null
  const encoded = strictUtf8Bytes(value, field)
  if (value !== value.normalize('NFC')) fail('PROTOCOL_ERROR', `${field} must be NFC`)
  if (hasControlCharacters(value)) fail('PROTOCOL_ERROR', `${field} contains control characters`)
  if (encoded.byteLength < minBytes || encoded.byteLength > maxBytes) {
    fail('PROTOCOL_ERROR', `${field} byte length is outside ${minBytes}..${maxBytes}`)
  }
  return value
}

function assertPrintableAscii (value, field, maxBytes, nullable = false) {
  if (nullable && value === null) return null
  if (typeof value !== 'string' || !PRINTABLE_ASCII.test(value) || b4a.byteLength(value) > maxBytes) {
    fail('PROTOCOL_ERROR', `${field} must be 1..${maxBytes} printable ASCII bytes`)
  }
  return value
}

function assertEnum (value, allowed, field) {
  if (!allowed.includes(value)) fail('PROTOCOL_ERROR', `${field} is outside its closed inventory`)
  return value
}

function freezeArray (values) {
  return Object.freeze(values.slice())
}

function uint32Bytes (value) {
  assertSafeInteger(value, 'uint32', 0xffffffff)
  const bytes = b4a.alloc(4)
  bytes.writeUInt32BE(value, 0)
  return bytes
}

function uint64Bytes (value) {
  assertSafeInteger(value, 'uint64')
  const bytes = b4a.alloc(8)
  const high = Math.floor(value / 0x100000000)
  const low = value - (high * 0x100000000)
  bytes.writeUInt32BE(high, 0)
  bytes.writeUInt32BE(low, 4)
  return bytes
}

export function blake2b256Hex (bytes) {
  const digest = b4a.alloc(32)
  sodium.crypto_generichash(digest, b4a.from(bytes))
  return b4a.toString(digest, 'hex')
}

function signHex (bytes, secretKey) {
  if (!secretKey || secretKey.byteLength !== sodium.crypto_sign_SECRETKEYBYTES) {
    fail('PROTOCOL_ERROR', 'Ed25519 secret key is unavailable')
  }
  const signature = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(signature, bytes, secretKey)
  return b4a.toString(signature, 'hex')
}

function verifyHexSignature (signature, bytes, publicKey) {
  assertHex(signature, 128, 'signature')
  if (!publicKey || publicKey.byteLength !== sodium.crypto_sign_PUBLICKEYBYTES) return false
  try {
    return sodium.crypto_sign_verify_detached(
      b4a.from(signature, 'hex'),
      bytes,
      publicKey
    )
  } catch {
    return false
  }
}

function keyPairPubkeyHex (keyPair) {
  if (!keyPair || !keyPair.publicKey || keyPair.publicKey.byteLength !== sodium.crypto_sign_PUBLICKEYBYTES) {
    fail('PROTOCOL_ERROR', 'Ed25519 public key is unavailable')
  }
  return b4a.toString(keyPair.publicKey, 'hex')
}

// JSON.parse accepts duplicate object members. The wire contract does not.
// This grammar walk decodes every member name before the one whole-document
// JSON.parse, so `"a"` and `"\u0061"` are duplicates too.
function assertNoDuplicateJsonKeys (text) {
  let offset = 0

  function whitespace () {
    while (offset < text.length) {
      const code = text.charCodeAt(offset)
      if (code !== 0x09 && code !== 0x0a && code !== 0x0d && code !== 0x20) break
      offset++
    }
  }

  function string () {
    const start = offset
    if (text[offset++] !== '"') fail('PROTOCOL_ERROR', 'malformed JSON string')
    while (offset < text.length) {
      const code = text.charCodeAt(offset)
      if (code === 0x22) {
        offset++
        try {
          return JSON.parse(text.slice(start, offset))
        } catch {
          fail('PROTOCOL_ERROR', 'malformed JSON string')
        }
      }
      if (code < 0x20) fail('PROTOCOL_ERROR', 'malformed JSON string')
      if (code === 0x5c) {
        offset++
        if (offset >= text.length) fail('PROTOCOL_ERROR', 'malformed JSON escape')
        const escape = text[offset++]
        if ('"\\/bfnrt'.includes(escape)) continue
        if (escape !== 'u' || !/^[0-9A-Fa-f]{4}$/.test(text.slice(offset, offset + 4))) {
          fail('PROTOCOL_ERROR', 'malformed JSON escape')
        }
        offset += 4
        continue
      }
      offset++
    }
    fail('PROTOCOL_ERROR', 'unterminated JSON string')
  }

  function number () {
    const rest = text.slice(offset)
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(rest)
    if (!match) fail('PROTOCOL_ERROR', 'malformed JSON number')
    offset += match[0].length
  }

  function literal (word) {
    if (text.slice(offset, offset + word.length) !== word) fail('PROTOCOL_ERROR', 'malformed JSON literal')
    offset += word.length
  }

  function array () {
    offset++
    whitespace()
    if (text[offset] === ']') {
      offset++
      return
    }
    while (true) {
      value()
      whitespace()
      if (text[offset] === ']') {
        offset++
        return
      }
      if (text[offset++] !== ',') fail('PROTOCOL_ERROR', 'malformed JSON array')
      whitespace()
    }
  }

  function object () {
    offset++
    whitespace()
    const names = new Set()
    if (text[offset] === '}') {
      offset++
      return
    }
    while (true) {
      if (text[offset] !== '"') fail('PROTOCOL_ERROR', 'malformed JSON object key')
      const name = string()
      if (names.has(name)) fail('PROTOCOL_ERROR', `duplicate JSON key ${name}`)
      names.add(name)
      whitespace()
      if (text[offset++] !== ':') fail('PROTOCOL_ERROR', 'malformed JSON object')
      whitespace()
      value()
      whitespace()
      if (text[offset] === '}') {
        offset++
        return
      }
      if (text[offset++] !== ',') fail('PROTOCOL_ERROR', 'malformed JSON object')
      whitespace()
    }
  }

  function value () {
    whitespace()
    const token = text[offset]
    if (token === '{') return object()
    if (token === '[') return array()
    if (token === '"') return string()
    if (token === '-' || (token >= '0' && token <= '9')) return number()
    if (token === 't') return literal('true')
    if (token === 'f') return literal('false')
    if (token === 'n') return literal('null')
    fail('PROTOCOL_ERROR', 'malformed JSON value')
  }

  whitespace()
  value()
  whitespace()
  if (offset !== text.length) fail('PROTOCOL_ERROR', 'trailing JSON bytes')
}

function decodeJsonPayload (payload) {
  const text = b4a.toString(payload, 'utf8')
  if (!b4a.equals(b4a.from(text, 'utf8'), payload)) fail('PROTOCOL_ERROR', 'malformed UTF-8')
  assertNoDuplicateJsonKeys(text)
  try {
    return JSON.parse(text)
  } catch {
    fail('PROTOCOL_ERROR', 'malformed JSON')
  }
}

function rememberRawFrame (message, frame) {
  if (message && typeof message === 'object') RAW_APP_CATALOG_FRAMES.set(message, b4a.from(frame))
  return message
}

function inheritRawFrame (source, target) {
  const frame = source && typeof source === 'object' ? RAW_APP_CATALOG_FRAMES.get(source) : null
  if (frame) RAW_APP_CATALOG_FRAMES.set(target, frame)
  return target
}

export function appCatalogPageRetransmitEquals (left, right) {
  const leftFrame = left && typeof left === 'object' ? RAW_APP_CATALOG_FRAMES.get(left) : null
  const rightFrame = right && typeof right === 'object' ? RAW_APP_CATALOG_FRAMES.get(right) : null
  if (leftFrame || rightFrame) return !!leftFrame && !!rightFrame && b4a.equals(leftFrame, rightFrame)
  return JSON.stringify(left) === JSON.stringify(right)
}

function encodedJson (message) {
  let json
  try {
    json = JSON.stringify(message)
  } catch {
    fail('PROTOCOL_ERROR', 'message is not JSON encodable')
  }
  if (typeof json !== 'string') fail('PROTOCOL_ERROR', 'message is not JSON encodable')
  const bytes = b4a.from(json, 'utf8')
  if (bytes.byteLength > APP_CATALOG_LIMITS.maxPayloadBytes) {
    fail('CATALOG_ENTRY_TOO_LARGE', 'catalog message exceeds 65,536 bytes')
  }
  return bytes
}

export function encodeAppCatalogFrame (message) {
  const payload = encodedJson(message)
  const frame = b4a.alloc(4 + payload.byteLength)
  frame.writeUInt32BE(payload.byteLength, 0)
  payload.copy(frame, 4)
  return frame
}

export function decodeAppCatalogFrame (frame) {
  if (!frame || !b4a.isBuffer(frame) || frame.byteLength < 4) {
    fail('PROTOCOL_ERROR', 'catalog frame is truncated')
  }
  const declared = frame.readUInt32BE(0)
  if (declared > APP_CATALOG_LIMITS.maxPayloadBytes) {
    fail('RESOURCE_LIMIT', 'declared catalog payload exceeds 65,536 bytes')
  }
  if (frame.byteLength !== declared + 4) fail('PROTOCOL_ERROR', 'catalog frame length mismatch')
  return rememberRawFrame(decodeJsonPayload(frame.subarray(4)), frame)
}

function decodeFailure (error) {
  return Object.freeze({
    type: -1,
    catalogProtocolError: true,
    code: error instanceof AppCatalogProtocolError ? error.code : 'PROTOCOL_ERROR',
    error: error instanceof Error ? error.message : 'catalog decode failure'
  })
}

export const appCatalogPagedJsonEncoding = Object.freeze({
  preencode (state, message) {
    const payload = encodedJson(message)
    state.end += 4 + payload.byteLength
  },
  encode (state, message) {
    const payload = encodedJson(message)
    state.buffer.writeUInt32BE(payload.byteLength, state.start)
    payload.copy(state.buffer, state.start + 4)
    state.start += 4 + payload.byteLength
  },
  decode (state) {
    const buffer = state && state.buffer
    const start = state && state.start
    const end = state && state.end
    if (!buffer || !Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end < start || end > buffer.byteLength) {
      if (state && buffer) state.start = buffer.byteLength
      return decodeFailure(new AppCatalogProtocolError('PROTOCOL_ERROR', 'invalid catalog decode state'))
    }
    if (start + 4 > end) {
      state.start = end
      return decodeFailure(new AppCatalogProtocolError('PROTOCOL_ERROR', 'catalog frame is truncated'))
    }
    const declared = buffer.readUInt32BE(start)
    if (declared > APP_CATALOG_LIMITS.maxPayloadBytes) {
      // Do not slice, decode UTF-8, or invoke JSON.parse on an overbound
      // declared payload. Protomux already owns the enclosing frame buffer.
      state.start = end
      return decodeFailure(new AppCatalogProtocolError('RESOURCE_LIMIT', 'declared catalog payload exceeds 65,536 bytes'))
    }
    const payloadStart = start + 4
    const payloadEnd = payloadStart + declared
    if (payloadEnd !== end) {
      state.start = end
      return decodeFailure(new AppCatalogProtocolError('PROTOCOL_ERROR', 'catalog frame length mismatch'))
    }
    state.start = end
    try {
      return rememberRawFrame(
        decodeJsonPayload(buffer.subarray(payloadStart, payloadEnd)),
        buffer.subarray(start, end)
      )
    } catch (err) {
      return decodeFailure(err)
    }
  }
})

export function validateCapabilityChallenge (message) {
  assertExactObject(message, CHALLENGE_FIELDS, 'CAPABILITY_CHALLENGE')
  if (message.type !== APP_CATALOG_MESSAGE.CAPABILITY_CHALLENGE) fail('PROTOCOL_ERROR', 'wrong challenge type')
  assertHex(message.nonce, 64, 'nonce')
  return Object.freeze({ type: message.type, nonce: message.nonce })
}

export function capabilityProofSignable (proof) {
  return b4a.from(JSON.stringify([
    'hiverelay.app-catalog.capability.v1',
    proof.nonce,
    proof.senderPubkey,
    1,
    1,
    ['app-catalog-paged-v1'],
    proof.issuedAt
  ]), 'utf8')
}

export function validateCapabilityProof (message) {
  assertExactObject(message, PROOF_FIELDS, 'CAPABILITY_PROOF')
  if (message.type !== APP_CATALOG_MESSAGE.CAPABILITY_PROOF) fail('PROTOCOL_ERROR', 'wrong proof type')
  assertHex(message.nonce, 64, 'nonce')
  assertHex(message.senderPubkey, 64, 'senderPubkey')
  if (message.protocolMajor !== 1 || message.protocolMinor !== 1) fail('PROTOCOL_ERROR', 'unsupported catalog protocol version')
  if (!Array.isArray(message.features) || message.features.length !== 1 || message.features[0] !== 'app-catalog-paged-v1') {
    fail('PROTOCOL_ERROR', 'catalog capability features are not canonical')
  }
  assertSafeInteger(message.issuedAt, 'issuedAt')
  assertHex(message.signature, 128, 'signature')
  return Object.freeze({
    type: 1,
    nonce: message.nonce,
    senderPubkey: message.senderPubkey,
    protocolMajor: 1,
    protocolMinor: 1,
    features: Object.freeze(['app-catalog-paged-v1']),
    issuedAt: message.issuedAt,
    signature: message.signature
  })
}

function parseSemver (version) {
  if (typeof version !== 'string') return null
  const match = SEMVER.exec(version)
  if (!match) return null
  return {
    major: match[1],
    minor: match[2],
    patch: match[3],
    prerelease: match[4] == null ? null : match[4].split('.')
  }
}

function compareNumericText (a, b) {
  if (a.length !== b.length) return a.length > b.length ? 1 : -1
  return a === b ? 0 : (a > b ? 1 : -1)
}

function comparePrerelease (a, b) {
  if (a === null && b === null) return 0
  if (a === null) return 1
  if (b === null) return -1
  const length = Math.max(a.length, b.length)
  for (let i = 0; i < length; i++) {
    if (a[i] === undefined) return -1
    if (b[i] === undefined) return 1
    if (a[i] === b[i]) continue
    const aNumeric = /^\d+$/.test(a[i])
    const bNumeric = /^\d+$/.test(b[i])
    if (aNumeric && bNumeric) return compareNumericText(a[i], b[i])
    if (aNumeric !== bNumeric) return aNumeric ? -1 : 1
    return a[i] > b[i] ? 1 : -1
  }
  return 0
}

// The accepted contract permits null/printable non-SemVer row bytes while
// requiring duplicate appIds to select the highest semantic version. This
// exported classification makes the necessary deterministic inference exact:
// valid SemVer 2.0 outranks null/invalid; equal precedence and invalid values
// tie, leaving the lowercase appKey tie-break to compareCatalogAppWinners().
export function classifyCatalogSemanticVersion (version) {
  const parsed = parseSemver(version)
  return Object.freeze({ valid: parsed !== null, parsed })
}

export function compareCatalogSemanticVersions (a, b) {
  const left = parseSemver(a)
  const right = parseSemver(b)
  if (!left || !right) {
    if (left) return 1
    if (right) return -1
    return 0
  }
  for (const field of ['major', 'minor', 'patch']) {
    const compared = compareNumericText(left[field], right[field])
    if (compared !== 0) return compared
  }
  return comparePrerelease(left.prerelease, right.prerelease)
}

export function compareCatalogAppWinners (left, right) {
  const version = compareCatalogSemanticVersions(left[6], right[6])
  if (version !== 0) return version
  if (left[1] === right[1]) return 0
  return left[1] < right[1] ? 1 : -1
}

function catalogRowIdentity (record) {
  if (record.redacted) return ['redacted', record.blindContentId]
  if (record.type === 'app' && record.appId !== null) return ['public-app', record.appId]
  return ['public-key', record.appKey]
}

export function catalogRowKey (identity) {
  if (!Array.isArray(identity) || identity.length !== 2) fail('PROTOCOL_ERROR', 'catalog row identity is invalid')
  if (!['public-app', 'public-key', 'redacted'].includes(identity[0])) fail('PROTOCOL_ERROR', 'catalog row identity domain is invalid')
  if (typeof identity[1] !== 'string') fail('PROTOCOL_ERROR', 'catalog row identity value is invalid')
  return blake2b256Hex(b4a.from(JSON.stringify(identity), 'utf8'))
}

function validateCatalogRecord (record) {
  assertExactObject(record, APP_CATALOG_RECORD_FIELDS, 'catalog record')
  assertHex(record.appKey, 64, 'appKey', record.redacted === true)
  assertNfcText(record.appId, 'appId', 1, 256, true)
  assertEnum(record.type, ['app', 'drive', 'dataset', 'media'], 'type')
  assertHex(record.parentKey, 64, 'parentKey', true)
  assertNfcText(record.mountPath, 'mountPath', 1, 1_024, true)
  assertPrintableAscii(record.version, 'version', 128, true)
  assertHex(record.discoveryKey, 64, 'discoveryKey', true)
  assertBoolean(record.blind, 'blind')
  assertEnum(record.storageClass, ['persistent', 'temporary'], 'storageClass')
  assertEnum(record.availabilityClass, ['always-on', 'best-effort', 'atomic-handoff'], 'availabilityClass')
  assertEnum(record.privacyTier, ['public', 'local-first', 'p2p-only'], 'privacyTier')
  if (record.seededAt !== null) assertSafeInteger(record.seededAt, 'seededAt')
  assertBoolean(record.redacted, 'redacted')
  assertEnum(record.metadataVisibility, ['public', 'redacted'], 'metadataVisibility')
  assertHex(record.blindContentId, 64, 'blindContentId', true)
  assertBoolean(record.anchored, 'anchored')
  if (record.maxStorageBytes !== null) assertSafeInteger(record.maxStorageBytes, 'maxStorageBytes')
  assertHex(record.publisherPubkey, 64, 'publisherPubkey', true)
  if (record.durability !== null) assertSafeInteger(record.durability, 'durability')
  assertBoolean(record.revocable, 'revocable')
  if (record.retainUntil !== null) assertSafeInteger(record.retainUntil, 'retainUntil')

  if (record.redacted) {
    if (record.metadataVisibility !== 'redacted') fail('PROTOCOL_ERROR', 'redacted row metadataVisibility must be redacted')
    for (const field of ['appKey', 'appId', 'parentKey', 'mountPath', 'version', 'discoveryKey', 'publisherPubkey', 'retainUntil']) {
      if (record[field] !== null) fail('PROTOCOL_ERROR', `redacted row ${field} must be null`)
    }
    if (record.durability !== 0) fail('PROTOCOL_ERROR', 'redacted row durability must be 0')
    if (record.revocable !== true) fail('PROTOCOL_ERROR', 'redacted row revocable must be true')
  } else {
    if (record.metadataVisibility !== 'public') fail('PROTOCOL_ERROR', 'public row metadataVisibility must be public')
    assertHex(record.appKey, 64, 'appKey')
  }
  return record
}

export function projectCatalogRecord (record) {
  validateCatalogRecord(record)
  if (record.redacted && record.blindContentId === null) {
    return Object.freeze({ eligible: false, reason: 'REDACTED_IDENTIFIER_MISSING', row: null })
  }
  const identity = catalogRowIdentity(record)
  const row = [catalogRowKey(identity)]
  for (const field of APP_CATALOG_RECORD_FIELDS) row.push(record[field])
  return Object.freeze({ eligible: true, reason: null, row: freezeArray(row) })
}

export function projectAppCatalogSource (source) {
  assertExactObject(source, ['catalogPublic', 'record'], 'catalog source')
  if (typeof source.catalogPublic !== 'boolean') fail('PROTOCOL_ERROR', 'catalogPublic must be boolean')
  if (!source.catalogPublic) {
    return Object.freeze({ eligible: false, reason: 'NON_PUBLIC_SOURCE', row: null })
  }
  return projectCatalogRecord(source.record)
}

export function createCanonicalCatalogRow (record) {
  const projected = projectCatalogRecord(record)
  if (!projected.eligible) fail('PROTOCOL_ERROR', 'redacted catalog row has no public blindContentId')
  assertCatalogRowFitsPage(projected.row)
  return projected.row
}

export function validateCanonicalCatalogRow (row) {
  if (!Array.isArray(row) || row.length !== APP_CATALOG_ROW_FIELDS.length) {
    fail('PROTOCOL_ERROR', 'canonical catalog row has the wrong array shape')
  }
  const record = {}
  for (let i = 0; i < APP_CATALOG_RECORD_FIELDS.length; i++) {
    record[APP_CATALOG_RECORD_FIELDS[i]] = row[i + 1]
  }
  const projected = projectCatalogRecord(record)
  if (!projected.eligible) fail('PROTOCOL_ERROR', 'redacted catalog row has no public blindContentId')
  assertHex(row[0], 64, 'rowKey')
  if (row[0] !== projected.row[0]) fail('PROTOCOL_ERROR', 'catalog rowKey is not canonical')
  if (JSON.stringify(row) !== JSON.stringify(projected.row)) fail('PROTOCOL_ERROR', 'catalog row is not canonical')
  return projected.row
}

function rowIdentityKey (row) {
  if (row[13]) return `redacted:${row[15]}`
  if (row[3] === 'app' && row[2] !== null) return `public-app:${row[2]}`
  return `public-key:${row[1]}`
}

export function selectCanonicalCatalogWinners (inputRows) {
  if (!Array.isArray(inputRows)) fail('PROTOCOL_ERROR', 'catalog rows must be an array')
  const winners = new Map()
  for (const input of inputRows) {
    const row = validateCanonicalCatalogRow(input)
    const identity = rowIdentityKey(row)
    const current = winners.get(identity)
    if (!current || (identity.startsWith('public-app:') && compareCatalogAppWinners(row, current) > 0)) {
      winners.set(identity, row)
    }
  }
  const collisions = new Map()
  for (const [identity, row] of winners) {
    const prior = collisions.get(row[0])
    if (prior && prior !== identity) fail('SNAPSHOT_MISMATCH', 'catalog row-key collision')
    collisions.set(row[0], identity)
  }
  return Object.freeze([...winners.values()].sort((a, b) => b4a.compare(b4a.from(a[0]), b4a.from(b[0]))).map(row => row))
}

function pageSignableValues (page) {
  return [
    'hiverelay.app-catalog.page.v1',
    1,
    page.senderPubkey,
    page.receiverPubkey,
    page.snapshotId,
    page.highWater,
    page.rootDigest,
    page.entryCount,
    page.sequence,
    page.cursor,
    page.nextCursor,
    page.complete,
    page.entries
  ]
}

export function appCatalogPageSignable (page) {
  return b4a.from(JSON.stringify(pageSignableValues(page)), 'utf8')
}

function validatePageUnsigned (page) {
  if (page.type !== APP_CATALOG_MESSAGE.PAGE || page.version !== 1) fail('PROTOCOL_ERROR', 'wrong PAGE type/version')
  assertHex(page.senderPubkey, 64, 'senderPubkey')
  assertHex(page.receiverPubkey, 64, 'receiverPubkey')
  assertHex(page.snapshotId, 64, 'snapshotId')
  assertSafeInteger(page.highWater, 'highWater')
  assertHex(page.rootDigest, 64, 'rootDigest')
  assertSafeInteger(page.entryCount, 'entryCount', APP_CATALOG_LIMITS.maxSnapshotEntries)
  assertSafeInteger(page.sequence, 'sequence')
  assertHex(page.cursor, 64, 'cursor', true)
  assertHex(page.nextCursor, 64, 'nextCursor', true)
  assertBoolean(page.complete, 'complete')
  if (!Array.isArray(page.entries) || page.entries.length > APP_CATALOG_LIMITS.maxPageEntries) {
    fail('RESOURCE_LIMIT', 'PAGE entries exceed 128')
  }
  const entries = page.entries.map(validateCanonicalCatalogRow)
  let prior = page.cursor
  for (const row of entries) {
    if (prior !== null && b4a.compare(b4a.from(row[0]), b4a.from(prior)) <= 0) {
      fail('SNAPSHOT_MISMATCH', 'PAGE rows are not strictly ordered after cursor')
    }
    prior = row[0]
  }
  if (page.sequence === 0 && page.cursor !== null) fail('SNAPSHOT_MISMATCH', 'first PAGE cursor must be null')
  if (!page.complete) {
    if (entries.length === 0) fail('SNAPSHOT_MISMATCH', 'nonterminal PAGE must be nonempty')
    if (page.nextCursor !== entries[entries.length - 1][0]) fail('SNAPSHOT_MISMATCH', 'nonterminal PAGE nextCursor mismatch')
  } else {
    if (page.nextCursor !== null) fail('SNAPSHOT_MISMATCH', 'terminal PAGE nextCursor must be null')
    if (entries.length === 0 && page.entryCount !== 0) fail('SNAPSHOT_MISMATCH', 'only an empty snapshot may have an empty terminal PAGE')
    if (page.entryCount === 0 && (page.sequence !== 0 || page.cursor !== null)) {
      fail('SNAPSHOT_MISMATCH', 'empty snapshot PAGE chain is not canonical')
    }
  }
  return entries
}

export function validateAppCatalogPage (message) {
  assertExactObject(message, PAGE_FIELDS, 'PAGE')
  const entries = validatePageUnsigned(message)
  assertHex(message.pageDigest, 64, 'pageDigest')
  assertHex(message.signature, 128, 'signature')
  const signable = appCatalogPageSignable(message)
  if (blake2b256Hex(signable) !== message.pageDigest) fail('SNAPSHOT_MISMATCH', 'PAGE digest mismatch')
  if (b4a.byteLength(JSON.stringify(message)) > APP_CATALOG_LIMITS.maxPayloadBytes) {
    fail('CATALOG_ENTRY_TOO_LARGE', 'encoded PAGE exceeds 65,536 bytes')
  }
  return inheritRawFrame(message, Object.freeze({ ...message, entries: Object.freeze(entries) }))
}

export function createAppCatalogPage (values, keyPair) {
  const page = {
    type: 2,
    version: 1,
    senderPubkey: keyPairPubkeyHex(keyPair),
    receiverPubkey: values.receiverPubkey,
    snapshotId: values.snapshotId,
    highWater: values.highWater,
    rootDigest: values.rootDigest,
    entryCount: values.entryCount,
    sequence: values.sequence,
    cursor: values.cursor,
    nextCursor: values.nextCursor,
    complete: values.complete,
    entries: values.entries,
    pageDigest: '',
    signature: ''
  }
  validatePageUnsigned(page)
  const signable = appCatalogPageSignable(page)
  page.pageDigest = blake2b256Hex(signable)
  page.signature = signHex(signable, keyPair.secretKey)
  return validateAppCatalogPage(page)
}

export function verifyAppCatalogPage (message, peers) {
  const page = validateAppCatalogPage(message)
  const local = assertHex(peers.localPubkey, 64, 'authenticated localPubkey')
  const remote = assertHex(peers.remotePubkey, 64, 'authenticated remotePubkey')
  if (page.senderPubkey !== remote || page.receiverPubkey !== local) {
    fail('PROTOCOL_ERROR', 'PAGE authenticated peer binding mismatch')
  }
  if (!verifyHexSignature(page.signature, appCatalogPageSignable(page), b4a.from(remote, 'hex'))) {
    fail('PROTOCOL_ERROR', 'PAGE signature is invalid')
  }
  return page
}

export function assertCatalogRowFitsPage (row) {
  const canonical = validateCanonicalCatalogRow(row)
  const worstCasePage = {
    type: 2,
    version: 1,
    senderPubkey: 'f'.repeat(64),
    receiverPubkey: 'f'.repeat(64),
    snapshotId: 'f'.repeat(64),
    highWater: Number.MAX_SAFE_INTEGER,
    rootDigest: 'f'.repeat(64),
    entryCount: APP_CATALOG_LIMITS.maxSnapshotEntries,
    sequence: Number.MAX_SAFE_INTEGER,
    cursor: 'f'.repeat(64),
    nextCursor: null,
    complete: true,
    entries: [canonical],
    pageDigest: 'f'.repeat(64),
    signature: 'f'.repeat(128)
  }
  if (b4a.byteLength(JSON.stringify(worstCasePage)) > APP_CATALOG_LIMITS.maxPayloadBytes) {
    fail('CATALOG_ENTRY_TOO_LARGE', 'catalog row cannot fit alone in one PAGE')
  }
  return canonical
}

export function appCatalogAckSignable (ack) {
  return b4a.from(JSON.stringify([
    'hiverelay.app-catalog.ack.v1',
    1,
    ack.senderPubkey,
    ack.receiverPubkey,
    ack.snapshotId,
    ack.highWater,
    ack.rootDigest,
    ack.sequence,
    ack.pageDigest,
    ack.nextCursor
  ]), 'utf8')
}

export function validateAppCatalogAck (message) {
  assertExactObject(message, ACK_FIELDS, 'ACK')
  if (message.type !== APP_CATALOG_MESSAGE.ACK || message.version !== 1) fail('PROTOCOL_ERROR', 'wrong ACK type/version')
  for (const field of ['senderPubkey', 'receiverPubkey', 'snapshotId', 'rootDigest', 'pageDigest']) assertHex(message[field], 64, field)
  assertSafeInteger(message.highWater, 'highWater')
  assertSafeInteger(message.sequence, 'sequence')
  assertHex(message.nextCursor, 64, 'nextCursor', true)
  assertHex(message.signature, 128, 'signature')
  return Object.freeze({ ...message })
}

export function createAppCatalogAck (page, keyPair) {
  validateAppCatalogPage(page)
  const ack = {
    type: 3,
    version: 1,
    senderPubkey: keyPairPubkeyHex(keyPair),
    receiverPubkey: page.senderPubkey,
    snapshotId: page.snapshotId,
    highWater: page.highWater,
    rootDigest: page.rootDigest,
    sequence: page.sequence,
    pageDigest: page.pageDigest,
    nextCursor: page.nextCursor,
    signature: ''
  }
  ack.signature = signHex(appCatalogAckSignable(ack), keyPair.secretKey)
  return validateAppCatalogAck(ack)
}

export function verifyAppCatalogAck (message, peers) {
  const ack = validateAppCatalogAck(message)
  const local = assertHex(peers.localPubkey, 64, 'authenticated localPubkey')
  const remote = assertHex(peers.remotePubkey, 64, 'authenticated remotePubkey')
  if (ack.senderPubkey !== remote || ack.receiverPubkey !== local) fail('PROTOCOL_ERROR', 'ACK authenticated peer binding mismatch')
  if (!verifyHexSignature(ack.signature, appCatalogAckSignable(ack), b4a.from(remote, 'hex'))) {
    fail('PROTOCOL_ERROR', 'ACK signature is invalid')
  }
  return ack
}

export function appCatalogAbortSignable (abort) {
  return b4a.from(JSON.stringify([
    'hiverelay.app-catalog.abort.v1',
    1,
    abort.senderPubkey,
    abort.receiverPubkey,
    abort.snapshotId,
    abort.code
  ]), 'utf8')
}

export function validateAppCatalogAbort (message) {
  assertExactObject(message, ABORT_FIELDS, 'ABORT')
  if (message.type !== APP_CATALOG_MESSAGE.ABORT || message.version !== 1) fail('PROTOCOL_ERROR', 'wrong ABORT type/version')
  for (const field of ['senderPubkey', 'receiverPubkey', 'snapshotId']) assertHex(message[field], 64, field)
  assertEnum(message.code, APP_CATALOG_ABORT_CODES, 'ABORT code')
  assertHex(message.signature, 128, 'signature')
  return Object.freeze({ ...message })
}

export function createAppCatalogAbort (values, keyPair) {
  const abort = {
    type: 4,
    version: 1,
    senderPubkey: keyPairPubkeyHex(keyPair),
    receiverPubkey: values.receiverPubkey,
    snapshotId: values.snapshotId,
    code: values.code,
    signature: ''
  }
  abort.signature = signHex(appCatalogAbortSignable(abort), keyPair.secretKey)
  return validateAppCatalogAbort(abort)
}

export function verifyAppCatalogAbort (message, peers) {
  const abort = validateAppCatalogAbort(message)
  const local = assertHex(peers.localPubkey, 64, 'authenticated localPubkey')
  const remote = assertHex(peers.remotePubkey, 64, 'authenticated remotePubkey')
  if (abort.senderPubkey !== remote || abort.receiverPubkey !== local) fail('PROTOCOL_ERROR', 'ABORT authenticated peer binding mismatch')
  if (!verifyHexSignature(abort.signature, appCatalogAbortSignable(abort), b4a.from(remote, 'hex'))) {
    fail('PROTOCOL_ERROR', 'ABORT signature is invalid')
  }
  return abort
}

export function validateAppCatalogMessage (message) {
  if (!message || typeof message !== 'object' || Array.isArray(message)) fail('PROTOCOL_ERROR', 'catalog message must be an object')
  if (!Number.isSafeInteger(message.type)) fail('PROTOCOL_ERROR', 'catalog message type must be a safe integer')
  switch (message.type) {
    case 0: return validateCapabilityChallenge(message)
    case 1: return validateCapabilityProof(message)
    case 2: return validateAppCatalogPage(message)
    case 3: return validateAppCatalogAck(message)
    case 4: return validateAppCatalogAbort(message)
    default: fail('PROTOCOL_ERROR', 'unknown catalog message type')
  }
}

export class AppCatalogDigestBuilder {
  constructor (highWater, entryCount) {
    this.highWater = assertSafeInteger(highWater, 'highWater')
    this.entryCount = assertSafeInteger(entryCount, 'entryCount', APP_CATALOG_LIMITS.maxSnapshotEntries)
    this.count = 0
    this.lastRowKey = null
    this.done = false
    this._state = b4a.alloc(sodium.crypto_generichash_STATEBYTES)
    sodium.crypto_generichash_init(this._state, null, 32)
    sodium.crypto_generichash_update(this._state, b4a.from('hiverelay.app-catalog.snapshot.v1', 'utf8'))
    sodium.crypto_generichash_update(this._state, b4a.from([0]))
    sodium.crypto_generichash_update(this._state, uint64Bytes(this.highWater))
    sodium.crypto_generichash_update(this._state, uint32Bytes(this.entryCount))
  }

  update (input) {
    if (this.done) fail('PROTOCOL_ERROR', 'snapshot digest is already finalized')
    if (this.count >= this.entryCount) fail('SNAPSHOT_MISMATCH', 'snapshot digest received too many rows')
    const row = validateCanonicalCatalogRow(input)
    if (this.lastRowKey !== null && b4a.compare(b4a.from(row[0]), b4a.from(this.lastRowKey)) <= 0) {
      fail('SNAPSHOT_MISMATCH', 'snapshot digest rows are not strictly ordered')
    }
    const record = b4a.from(JSON.stringify(row), 'utf8')
    sodium.crypto_generichash_update(this._state, uint32Bytes(record.byteLength))
    sodium.crypto_generichash_update(this._state, record)
    this.lastRowKey = row[0]
    this.count++
  }

  final () {
    if (this.done) fail('PROTOCOL_ERROR', 'snapshot digest is already finalized')
    if (this.count !== this.entryCount) fail('SNAPSHOT_MISMATCH', 'snapshot digest entry count mismatch')
    const digest = b4a.alloc(32)
    sodium.crypto_generichash_final(this._state, digest)
    this._state.fill(0)
    this.done = true
    return b4a.toString(digest, 'hex')
  }
}

export function appCatalogSnapshotId ({ senderPubkey, highWater, rootDigest, entryCount }) {
  assertHex(senderPubkey, 64, 'senderPubkey')
  assertSafeInteger(highWater, 'highWater')
  assertHex(rootDigest, 64, 'rootDigest')
  assertSafeInteger(entryCount, 'entryCount', APP_CATALOG_LIMITS.maxSnapshotEntries)
  return blake2b256Hex(b4a.from(JSON.stringify([
    'hiverelay.app-catalog.snapshot-id.v1',
    senderPubkey,
    highWater,
    rootDigest,
    entryCount
  ]), 'utf8'))
}

export function createAppCatalogSnapshotIdentity ({ senderPubkey, highWater, rows }) {
  const winners = selectCanonicalCatalogWinners(rows)
  if (winners.length > APP_CATALOG_LIMITS.maxSnapshotEntries) fail('RESOURCE_LIMIT', 'catalog snapshot exceeds 262,144 entries')
  const digest = new AppCatalogDigestBuilder(highWater, winners.length)
  for (const row of winners) digest.update(row)
  const rootDigest = digest.final()
  return Object.freeze({
    snapshotId: appCatalogSnapshotId({ senderPubkey, highWater, rootDigest, entryCount: winners.length }),
    highWater,
    rootDigest,
    entryCount: winners.length,
    rows: winners
  })
}

export function appCatalogExternalCursorSignable (cursor) {
  return b4a.from(JSON.stringify([
    'hiverelay.app-catalog.external-cursor.v1',
    1,
    cursor.highWater,
    cursor.rootDigest,
    cursor.lastRowKey,
    cursor.signerPubkey
  ]), 'utf8')
}

export function validateAppCatalogExternalCursor (cursor) {
  assertExactObject(cursor, EXTERNAL_CURSOR_FIELDS, 'external catalog cursor')
  if (cursor.kind !== 'HiveRelayCatalogCursorV1' || cursor.version !== 1) fail('PROTOCOL_ERROR', 'wrong external catalog cursor kind/version')
  assertSafeInteger(cursor.highWater, 'highWater')
  assertHex(cursor.rootDigest, 64, 'rootDigest')
  assertHex(cursor.lastRowKey, 64, 'lastRowKey', true)
  assertHex(cursor.signerPubkey, 64, 'signerPubkey')
  assertHex(cursor.signature, 128, 'signature')
  return Object.freeze({ ...cursor })
}

export function createAppCatalogExternalCursor (values, keyPair) {
  const cursor = {
    kind: 'HiveRelayCatalogCursorV1',
    version: 1,
    highWater: values.highWater,
    rootDigest: values.rootDigest,
    lastRowKey: values.lastRowKey,
    signerPubkey: keyPairPubkeyHex(keyPair),
    signature: ''
  }
  cursor.signature = signHex(appCatalogExternalCursorSignable(cursor), keyPair.secretKey)
  return validateAppCatalogExternalCursor(cursor)
}

export function verifyAppCatalogExternalCursor (input, expectedSignerPubkey) {
  const cursor = validateAppCatalogExternalCursor(input)
  const expected = assertHex(expectedSignerPubkey, 64, 'expected signerPubkey')
  if (cursor.signerPubkey !== expected) fail('CURSOR_EXPIRED', 'external catalog cursor signer mismatch')
  if (!verifyHexSignature(cursor.signature, appCatalogExternalCursorSignable(cursor), b4a.from(expected, 'hex'))) {
    fail('CURSOR_EXPIRED', 'external catalog cursor signature is invalid')
  }
  return cursor
}

export function createLegacyCatalogEnvelope ({ apps, keyPair, catalogTimestamp }) {
  if (!Array.isArray(apps)) fail('PROTOCOL_ERROR', 'legacy catalog apps must be an array')
  assertSafeInteger(catalogTimestamp, 'catalogTimestamp')
  const relayPubkey = keyPairPubkeyHex(keyPair)
  const signedEnvelope = (selected) => {
    const signable = b4a.from(JSON.stringify({ apps: selected, relayPubkey, catalogTimestamp }), 'utf8')
    const signature = signHex(signable, keyPair.secretKey)
    return { type: 7, apps: selected, relayPubkey, catalogTimestamp, signature }
  }
  let reason = null
  let candidate = apps.length <= APP_CATALOG_LIMITS.maxLegacyEntries
    ? signedEnvelope(apps)
    : null
  if (candidate === null || b4a.byteLength(JSON.stringify(candidate)) > APP_CATALOG_LIMITS.maxPayloadBytes) {
    candidate = signedEnvelope([])
    reason = 'CATALOG_LEGACY_OVERBOUND'
  }
  const envelope = Object.freeze({ ...candidate, apps: Object.freeze(candidate.apps.slice()) })
  if (b4a.byteLength(JSON.stringify(envelope)) > APP_CATALOG_LIMITS.maxPayloadBytes) {
    fail('RESOURCE_LIMIT', 'canonical empty legacy catalog envelope exceeds wire limit')
  }
  return Object.freeze({ envelope, reason })
}
