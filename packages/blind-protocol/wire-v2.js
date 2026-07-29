import b4a from 'b4a'
import { decodeCanonical, encodeCanonical } from './codec.js'
import { protocolError } from './errors.js'
import { blake2b256 } from './hashes.js'
import {
  blindErrorV1,
  blindForwardCloseV1,
  blindForwardDataV1,
  blindForwardOpenResultV1,
  blindForwardOpenV1,
  blindForwardWindowV1
} from './schemas.js'

const MAX_U64 = (1n << 64n) - 1n
const ZERO_32 = b4a.alloc(32)
const REQUEST_MAGIC = b4a.from('HFQR', 'ascii')
const RESULT_MAGIC = b4a.from('HFQS', 'ascii')

export const WIRE_V2_PROTOCOL = Object.freeze({ major: 1, minor: 1, abiFormatVersion: 2 })

export const WIRE_V2_SCHEMA = Object.freeze({
  BlindForwardHttpsTurnRequestV1: 74,
  BlindForwardHttpsTurnResultV1: 75
})

export const RELEASE_PROFILE_V2 = Object.freeze({
  LIMITED_PUBLIC_TEST_V1: Object.freeze({ id: 1, operationBits: 0x0001ffff, isDefault: true }),
  LIMITED_PUBLIC_TEST_FORWARD_ONE_HOP_V1: Object.freeze({ id: 2, operationBits: 0x003dffff, isDefault: false })
})

export const RELEASE_PROFILE_INPUT_ALIAS_V2 = Object.freeze({
  BASELINE_17: 'LIMITED_PUBLIC_TEST_V1'
})

export const DIRECT_HTTPS_ROUTE_KIND_V2 = Object.freeze({
  DIRECT_HTTPS_FORWARD_ONE_HOP: 7
})

export const FORWARD_HTTPS_TURN_KIND_V1 = Object.freeze({
  OPEN: 1,
  DATA: 2,
  WINDOW: 3,
  CLOSE: 4
})

export const FORWARD_HTTPS_RESULT_OUTCOME_V1 = Object.freeze({
  SUCCESS: 1,
  ERROR: 2
})

export const FORWARD_HTTPS_DOMAIN_V2 = Object.freeze({
  REQUEST: Object.freeze({
    domainId: 17,
    name: 'FORWARD_HTTPS_TURN',
    exactAsciiBytes: 'hiverelay.blind.forward-https-turn-request.v1'
  }),
  RESULT: Object.freeze({
    domainId: 112,
    name: 'FORWARD_HTTPS_TURN_RESULT',
    exactAsciiBytes: 'hiverelay.blind.forward-https-turn-result.v1'
  }),
  PARENT_CAPABILITY: Object.freeze({
    domainId: 214,
    name: 'FORWARD_HTTPS_PARENT_CAPABILITY',
    exactAsciiBytes: 'hiverelay.blind.forward-https-parent-capability.v1'
  })
})

export const FORWARD_HTTPS_LIMITS_V1 = Object.freeze({
  EXACT_REQUEST_BYTES: 65_536,
  EXACT_RESULT_BYTES: 65_536,
  PARENT_CAPABILITY_BYTES: 390,
  PARENT_CAPABILITY_UNSIGNED_BYTES: 326,
  REQUEST_HEADER_BYTES: 475,
  RESULT_HEADER_BYTES: 221,
  MAX_REQUEST_INNER_BYTES: 65_061,
  MAX_RESULT_INNER_BYTES: 65_315,
  MAX_RELAY_COUNT: 2,
  REMAINING_TRANSITIONS: 1,
  CIRCUIT_CLASS: 1,
  MAX_CIRCUIT_BYTES: 16n * 1024n * 1024n,
  INITIAL_WINDOW_BYTES: 65_536,
  IDLE_MILLIS: 30_000,
  LIFETIME_MILLIS: 600_000,
  LIFETIME_SECONDS: 600
})

export const FORWARD_HTTPS_TRANSPORT_VARIANTS_V2 = Object.freeze([
  ...Object.entries(FORWARD_HTTPS_TURN_KIND_V1).map(([turnName, turnKind]) => Object.freeze({
    family: 'FORWARD',
    operation: turnName,
    routeKind: DIRECT_HTTPS_ROUTE_KIND_V2.DIRECT_HTTPS_FORWARD_ONE_HOP,
    releaseProfileId: RELEASE_PROFILE_V2.LIMITED_PUBLIC_TEST_FORWARD_ONE_HOP_V1.id,
    requestSchemaId: WIRE_V2_SCHEMA.BlindForwardHttpsTurnRequestV1,
    resultSchemaId: WIRE_V2_SCHEMA.BlindForwardHttpsTurnResultV1,
    requestBytes: FORWARD_HTTPS_LIMITS_V1.EXACT_REQUEST_BYTES,
    resultBytes: FORWARD_HTTPS_LIMITS_V1.EXACT_RESULT_BYTES,
    turnKind
  }))
])

export const WIRE_V2_SCHEMA_DECLARATIONS = Object.freeze([
  Object.freeze({
    schemaId: 74,
    schemaName: 'BlindForwardHttpsTurnRequestV1',
    fields: Object.freeze([
      'magic:fixed4=HFQR', 'version:u8=1', 'routeKind:u8=7', 'releaseProfileId:u8=2',
      'turnKind:u8[OPEN=1|DATA=2|WINDOW=3|CLOSE=4]', 'flags:u8=0',
      'sessionId:fixed32[nonzero]', 'sequence:u64be', 'requestNonce:fixed32[nonzero]',
      'parentCapability:BlindForwardHttpsParentCapabilityV1[exact390;catalog-id+relay-key+descriptor-pinned;no-url-host-ip]',
      'innerLength:u32be',
      'inner:closed(turnKind){OPEN:BlindForwardOpenV1|DATA:BlindForwardDataV1|WINDOW:BlindForwardWindowV1|CLOSE:BlindForwardCloseV1}',
      'padding:bytes[65536-475-innerLength]', 'exactBytes:65536'
    ])
  }),
  Object.freeze({
    schemaId: 75,
    schemaName: 'BlindForwardHttpsTurnResultV1',
    fields: Object.freeze([
      'magic:fixed4=HFQS', 'version:u8=1', 'routeKind:u8=7', 'releaseProfileId:u8=2',
      'turnKind:u8[OPEN=1|DATA=2|WINDOW=3|CLOSE=4]', 'outcome:u8[SUCCESS=1|ERROR=2]',
      'sessionId:fixed32[nonzero]', 'sequence:u64be', 'requestCommitment:fixed32[nonzero]',
      'relayPublicKey:fixed32[nonzero]', 'descriptorSequence:u64be', 'descriptorHash:fixed32[nonzero]',
      'signature:fixed64', 'innerLength:u32be',
      'inner:closed(outcome,turnKind){ERROR:BlindErrorV1|SUCCESS.OPEN:BlindForwardOpenResultV1|SUCCESS.DATA:BlindForwardDataV1|SUCCESS.WINDOW:BlindForwardWindowV1|SUCCESS.CLOSE:BlindForwardCloseV1}',
      'padding:bytes[65536-221-innerLength]', 'exactBytes:65536', 'no-ACK-schema'
    ])
  })
])

const REQUEST_CODECS = Object.freeze({
  [FORWARD_HTTPS_TURN_KIND_V1.OPEN]: blindForwardOpenV1,
  [FORWARD_HTTPS_TURN_KIND_V1.DATA]: blindForwardDataV1,
  [FORWARD_HTTPS_TURN_KIND_V1.WINDOW]: blindForwardWindowV1,
  [FORWARD_HTTPS_TURN_KIND_V1.CLOSE]: blindForwardCloseV1
})

const RESULT_CODECS = Object.freeze({
  [FORWARD_HTTPS_TURN_KIND_V1.OPEN]: blindForwardOpenResultV1,
  [FORWARD_HTTPS_TURN_KIND_V1.DATA]: blindForwardDataV1,
  [FORWARD_HTTPS_TURN_KIND_V1.WINDOW]: blindForwardWindowV1,
  [FORWARD_HTTPS_TURN_KIND_V1.CLOSE]: blindForwardCloseV1
})

function resultCodec (outcome, turnKind) {
  if (outcome === FORWARD_HTTPS_RESULT_OUTCOME_V1.ERROR) return blindErrorV1
  if (outcome !== FORWARD_HTTPS_RESULT_OUTCOME_V1.SUCCESS) fail('result outcome is unknown')
  const codec = RESULT_CODECS[turnKind]
  if (!codec) fail('result turnKind is unknown')
  return codec
}

function fail (message, code = 'BAD_FORWARD_HTTPS_TURN') {
  protocolError(code, message)
}

function bytes (value, length, field, nonzero = false) {
  if (!value || typeof value.byteLength !== 'number') fail(`${field} must be bytes`)
  value = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (value.byteLength !== length) fail(`${field} must be exactly ${length} bytes`)
  if (nonzero && isZero(value)) fail(`${field} must be nonzero`)
  return value
}

function isZero (value) {
  for (const byte of value) if (byte !== 0) return false
  return true
}

function unsigned (value, maximum, field) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) fail(`${field} is outside its unsigned range`)
  return value
}

function u64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${field} must be an unsigned safe integer or bigint`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) fail(`${field} is outside u64`)
  return value
}

function writeU32 (output, value, offset, field) {
  value = unsigned(value, 0xffffffff, field)
  output[offset] = value >>> 24
  output[offset + 1] = value >>> 16
  output[offset + 2] = value >>> 8
  output[offset + 3] = value
  return offset + 4
}

function readU32 (input, offset) {
  return input[offset] * 0x1000000 + input[offset + 1] * 0x10000 + input[offset + 2] * 0x100 + input[offset + 3]
}

function writeU64 (output, value, offset, field) {
  value = u64(value, field)
  for (let i = 7; i >= 0; i--) {
    output[offset + i] = Number(value & 0xffn)
    value >>= 8n
  }
  return offset + 8
}

function readU64 (input, offset) {
  let value = 0n
  for (let i = 0; i < 8; i++) value = (value << 8n) | BigInt(input[offset + i])
  return value
}

function put (output, value, offset) {
  b4a.copy(value, output, offset)
  return offset + value.byteLength
}

function take (input, offset, length) {
  return b4a.from(input.subarray(offset, offset + length))
}

function assertObject (value, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${name} must be an object`)
}

function validateCapability (value, includeSignature = true) {
  assertObject(value, 'parentCapability')
  for (const forbidden of ['url', 'host', 'hostname', 'ip', 'ipAddress', 'dialAddress']) {
    if (forbidden in value) fail(`parentCapability.${forbidden} is forbidden`)
  }
  if (value.version !== 1) fail('parentCapability.version must be 1')
  if (value.routeKind !== DIRECT_HTTPS_ROUTE_KIND_V2.DIRECT_HTTPS_FORWARD_ONE_HOP) fail('parentCapability.routeKind must be 7')
  if (value.releaseProfileId !== RELEASE_PROFILE_V2.LIMITED_PUBLIC_TEST_FORWARD_ONE_HOP_V1.id) fail('parentCapability.releaseProfileId must be 2')
  const sourceRelayPublicKey = bytes(value.sourceRelayPublicKey, 32, 'sourceRelayPublicKey', true)
  const targetRelayPublicKey = bytes(value.targetRelayPublicKey, 32, 'targetRelayPublicKey', true)
  const routePrefixRelayPublicKey = bytes(value.routePrefixRelayPublicKey, 32, 'routePrefixRelayPublicKey', true)
  if (b4a.equals(sourceRelayPublicKey, targetRelayPublicKey)) fail('source and target relay keys must differ')
  if (!b4a.equals(sourceRelayPublicKey, routePrefixRelayPublicKey)) fail('route prefix must contain exactly the source relay')
  bytes(value.sourceDescriptorHash, 32, 'sourceDescriptorHash', true)
  bytes(value.targetDescriptorHash, 32, 'targetDescriptorHash', true)
  bytes(value.targetCatalogEntryId, 32, 'targetCatalogEntryId', true)
  bytes(value.routeId, 16, 'routeId', true)
  bytes(value.circuitNonce, 32, 'circuitNonce', true)
  bytes(value.tlsExporterBindingHash, 32, 'tlsExporterBindingHash', true)
  if (includeSignature) bytes(value.signature, 64, 'signature')
  u64(value.sourceDescriptorSequence, 'sourceDescriptorSequence')
  u64(value.targetDescriptorSequence, 'targetDescriptorSequence')
  if (value.maxRelayCount !== FORWARD_HTTPS_LIMITS_V1.MAX_RELAY_COUNT) fail('maxRelayCount must be 2')
  if (value.remainingTransitions !== FORWARD_HTTPS_LIMITS_V1.REMAINING_TRANSITIONS) fail('remainingTransitions must be 1')
  if (value.circuitClass !== FORWARD_HTTPS_LIMITS_V1.CIRCUIT_CLASS) fail('circuitClass must be F1')
  if (u64(value.maxCircuitBytes, 'maxCircuitBytes') !== FORWARD_HTTPS_LIMITS_V1.MAX_CIRCUIT_BYTES) fail('maxCircuitBytes must be exactly 16 MiB')
  if (value.initialWindowBytes !== FORWARD_HTTPS_LIMITS_V1.INITIAL_WINDOW_BYTES) fail('initialWindowBytes must be exactly 64 KiB')
  if (value.idleMillis !== FORWARD_HTTPS_LIMITS_V1.IDLE_MILLIS) fail('idleMillis must be exactly 30000')
  if (value.lifetimeMillis !== FORWARD_HTTPS_LIMITS_V1.LIFETIME_MILLIS) fail('lifetimeMillis must be exactly 600000')
  unsigned(value.issuedAtEpoch, 0xffffffff, 'issuedAtEpoch')
  unsigned(value.expiresAtEpoch, 0xffffffff, 'expiresAtEpoch')
  if (value.expiresAtEpoch !== value.issuedAtEpoch + FORWARD_HTTPS_LIMITS_V1.LIFETIME_SECONDS) fail('capability lifetime must be exactly 600 seconds')
  return value
}

export function encodeForwardHttpsParentCapabilityV1 (value, options = {}) {
  const includeSignature = options.includeSignature !== false
  validateCapability(value, includeSignature)
  const output = b4a.alloc(includeSignature
    ? FORWARD_HTTPS_LIMITS_V1.PARENT_CAPABILITY_BYTES
    : FORWARD_HTTPS_LIMITS_V1.PARENT_CAPABILITY_UNSIGNED_BYTES)
  let offset = 0
  offset = put(output, b4a.from('HFPC', 'ascii'), offset)
  output[offset++] = 1
  output[offset++] = 7
  output[offset++] = 2
  offset = put(output, bytes(value.sourceRelayPublicKey, 32, 'sourceRelayPublicKey'), offset)
  offset = writeU64(output, value.sourceDescriptorSequence, offset, 'sourceDescriptorSequence')
  offset = put(output, bytes(value.sourceDescriptorHash, 32, 'sourceDescriptorHash'), offset)
  offset = put(output, bytes(value.targetRelayPublicKey, 32, 'targetRelayPublicKey'), offset)
  offset = writeU64(output, value.targetDescriptorSequence, offset, 'targetDescriptorSequence')
  offset = put(output, bytes(value.targetDescriptorHash, 32, 'targetDescriptorHash'), offset)
  offset = put(output, bytes(value.targetCatalogEntryId, 32, 'targetCatalogEntryId'), offset)
  offset = put(output, bytes(value.routeId, 16, 'routeId'), offset)
  offset = put(output, bytes(value.routePrefixRelayPublicKey, 32, 'routePrefixRelayPublicKey'), offset)
  output[offset++] = value.maxRelayCount
  output[offset++] = value.remainingTransitions
  output[offset++] = value.circuitClass
  offset = writeU64(output, value.maxCircuitBytes, offset, 'maxCircuitBytes')
  offset = writeU32(output, value.initialWindowBytes, offset, 'initialWindowBytes')
  offset = writeU32(output, value.idleMillis, offset, 'idleMillis')
  offset = writeU32(output, value.lifetimeMillis, offset, 'lifetimeMillis')
  offset = writeU32(output, value.issuedAtEpoch, offset, 'issuedAtEpoch')
  offset = writeU32(output, value.expiresAtEpoch, offset, 'expiresAtEpoch')
  offset = put(output, bytes(value.circuitNonce, 32, 'circuitNonce'), offset)
  offset = put(output, bytes(value.tlsExporterBindingHash, 32, 'tlsExporterBindingHash'), offset)
  if (includeSignature) offset = put(output, bytes(value.signature, 64, 'signature'), offset)
  if (offset !== output.byteLength) fail('parent capability encoder length mismatch')
  return output
}

export function decodeForwardHttpsParentCapabilityV1 (input) {
  input = bytes(input, FORWARD_HTTPS_LIMITS_V1.PARENT_CAPABILITY_BYTES, 'parent capability')
  let offset = 0
  if (!b4a.equals(input.subarray(0, 4), b4a.from('HFPC', 'ascii'))) fail('parent capability magic is invalid')
  offset += 4
  const value = {
    version: input[offset++],
    routeKind: input[offset++],
    releaseProfileId: input[offset++],
    sourceRelayPublicKey: take(input, offset, 32)
  }
  offset += 32
  value.sourceDescriptorSequence = readU64(input, offset); offset += 8
  value.sourceDescriptorHash = take(input, offset, 32); offset += 32
  value.targetRelayPublicKey = take(input, offset, 32); offset += 32
  value.targetDescriptorSequence = readU64(input, offset); offset += 8
  value.targetDescriptorHash = take(input, offset, 32); offset += 32
  value.targetCatalogEntryId = take(input, offset, 32); offset += 32
  value.routeId = take(input, offset, 16); offset += 16
  value.routePrefixRelayPublicKey = take(input, offset, 32); offset += 32
  value.maxRelayCount = input[offset++]
  value.remainingTransitions = input[offset++]
  value.circuitClass = input[offset++]
  value.maxCircuitBytes = readU64(input, offset); offset += 8
  value.initialWindowBytes = readU32(input, offset); offset += 4
  value.idleMillis = readU32(input, offset); offset += 4
  value.lifetimeMillis = readU32(input, offset); offset += 4
  value.issuedAtEpoch = readU32(input, offset); offset += 4
  value.expiresAtEpoch = readU32(input, offset); offset += 4
  value.circuitNonce = take(input, offset, 32); offset += 32
  value.tlsExporterBindingHash = take(input, offset, 32); offset += 32
  value.signature = take(input, offset, 64); offset += 64
  if (offset !== input.byteLength) fail('parent capability decoder length mismatch')
  validateCapability(value)
  return value
}

function signaturePayload (domain, unsignedBytes) {
  const length = b4a.alloc(8)
  writeU64(length, unsignedBytes.byteLength, 0, 'signature payload length')
  return b4a.concat([b4a.from(domain.exactAsciiBytes, 'ascii'), length, unsignedBytes])
}

export function forwardHttpsParentCapabilitySignaturePayloadV1 (value) {
  return signaturePayload(
    FORWARD_HTTPS_DOMAIN_V2.PARENT_CAPABILITY,
    encodeForwardHttpsParentCapabilityV1(value, { includeSignature: false })
  )
}

export function forwardHttpsSessionIdV1 (parentCapability) {
  return blake2b256(b4a.concat([
    b4a.from(FORWARD_HTTPS_DOMAIN_V2.PARENT_CAPABILITY.exactAsciiBytes, 'ascii'),
    encodeForwardHttpsParentCapabilityV1(parentCapability)
  ]))
}

export function assertForwardHttpsCatalogTargetV1 (parentCapability, catalogEntry) {
  validateCapability(parentCapability)
  assertObject(catalogEntry, 'catalogEntry')
  if ('url' in catalogEntry || 'host' in catalogEntry || 'hostname' in catalogEntry ||
      'ip' in catalogEntry || 'ipAddress' in catalogEntry || 'dialAddress' in catalogEntry) {
    fail('catalog target input must not contain caller dial fields')
  }
  if (!b4a.equals(bytes(catalogEntry.catalogEntryId, 32, 'catalogEntry.catalogEntryId', true), parentCapability.targetCatalogEntryId) ||
      !b4a.equals(bytes(catalogEntry.relayPublicKey, 32, 'catalogEntry.relayPublicKey', true), parentCapability.targetRelayPublicKey) ||
      u64(catalogEntry.descriptorSequence, 'catalogEntry.descriptorSequence') !== u64(parentCapability.targetDescriptorSequence, 'targetDescriptorSequence') ||
      !b4a.equals(bytes(catalogEntry.descriptorHash, 32, 'catalogEntry.descriptorHash', true), parentCapability.targetDescriptorHash)) {
    fail('catalog entry does not exactly match the capability target')
  }
  return true
}

function validateInnerBinding (turnKind, inner, capability) {
  if (!inner || typeof inner !== 'object') fail('inner turn must be an object')
  if (turnKind === FORWARD_HTTPS_TURN_KIND_V1.OPEN) {
    if (!b4a.equals(bytes(inner.routeId, 16, 'inner.routeId'), capability.routeId)) fail('OPEN routeId does not match parent capability')
    if (u64(inner.nextDescriptorSequence, 'inner.nextDescriptorSequence') !== u64(capability.targetDescriptorSequence, 'targetDescriptorSequence')) fail('OPEN target descriptor sequence does not match parent capability')
    if (!b4a.equals(bytes(inner.nextDescriptorHash, 32, 'inner.nextDescriptorHash'), capability.targetDescriptorHash)) fail('OPEN target descriptor hash does not match parent capability')
    if (inner.circuitClass !== capability.circuitClass) fail('OPEN circuitClass does not match parent capability')
    if (!b4a.equals(bytes(inner.circuitNonce, 32, 'inner.circuitNonce'), capability.circuitNonce)) fail('OPEN circuitNonce does not match parent capability')
    if (!b4a.equals(bytes(inner.parentRouteScopeHash, 32, 'inner.parentRouteScopeHash'), ZERO_32)) fail('nested or forwarded parent OPEN is forbidden')
    return
  }
  if (!b4a.equals(bytes(inner.circuitNonce, 32, 'inner.circuitNonce'), capability.circuitNonce)) fail('turn circuitNonce does not match parent capability')
}

function padding (value, length) {
  if (value == null) return b4a.alloc(length)
  return bytes(value, length, 'padding')
}

function encodeRequest (value) {
  assertObject(value, 'BlindForwardHttpsTurnRequestV1')
  if (value.version !== 1 || value.routeKind !== 7 || value.releaseProfileId !== 2 || value.flags !== 0) fail('request fixed header is invalid')
  const codec = REQUEST_CODECS[value.turnKind]
  if (!codec) fail('request turnKind is unknown')
  const capabilityBytes = encodeForwardHttpsParentCapabilityV1(value.parentCapability)
  if (!b4a.equals(bytes(value.sessionId, 32, 'sessionId', true), forwardHttpsSessionIdV1(value.parentCapability))) fail('sessionId does not bind the parent capability')
  u64(value.sequence, 'sequence')
  bytes(value.requestNonce, 32, 'requestNonce', true)
  validateInnerBinding(value.turnKind, value.inner, value.parentCapability)
  const inner = encodeCanonical(codec, value.inner)
  if (inner.byteLength > FORWARD_HTTPS_LIMITS_V1.MAX_REQUEST_INNER_BYTES) fail('request inner turn exceeds exact-body capacity', 'TOO_LARGE')
  const output = b4a.alloc(FORWARD_HTTPS_LIMITS_V1.EXACT_REQUEST_BYTES)
  let offset = 0
  offset = put(output, REQUEST_MAGIC, offset)
  output[offset++] = 1
  output[offset++] = 7
  output[offset++] = 2
  output[offset++] = value.turnKind
  output[offset++] = 0
  offset = put(output, value.sessionId, offset)
  offset = writeU64(output, value.sequence, offset, 'sequence')
  offset = put(output, value.requestNonce, offset)
  offset = put(output, capabilityBytes, offset)
  offset = writeU32(output, inner.byteLength, offset, 'innerLength')
  offset = put(output, inner, offset)
  offset = put(output, padding(value.padding, output.byteLength - offset), offset)
  if (offset !== output.byteLength) fail('request encoder length mismatch')
  return output
}

function decodeRequest (input) {
  input = bytes(input, FORWARD_HTTPS_LIMITS_V1.EXACT_REQUEST_BYTES, 'request body')
  let offset = 0
  if (!b4a.equals(input.subarray(0, 4), REQUEST_MAGIC)) fail('request magic is invalid')
  offset += 4
  const value = {
    version: input[offset++],
    routeKind: input[offset++],
    releaseProfileId: input[offset++],
    turnKind: input[offset++],
    flags: input[offset++],
    sessionId: take(input, offset, 32)
  }
  offset += 32
  value.sequence = readU64(input, offset); offset += 8
  value.requestNonce = take(input, offset, 32); offset += 32
  value.parentCapability = decodeForwardHttpsParentCapabilityV1(input.subarray(offset, offset + FORWARD_HTTPS_LIMITS_V1.PARENT_CAPABILITY_BYTES)); offset += FORWARD_HTTPS_LIMITS_V1.PARENT_CAPABILITY_BYTES
  const innerLength = readU32(input, offset); offset += 4
  if (innerLength > FORWARD_HTTPS_LIMITS_V1.MAX_REQUEST_INNER_BYTES) fail('request innerLength exceeds exact-body capacity')
  const codec = REQUEST_CODECS[value.turnKind]
  if (!codec) fail('request turnKind is unknown')
  value.inner = decodeCanonical(codec, input.subarray(offset, offset + innerLength), { copyBytes: true }); offset += innerLength
  value.padding = take(input, offset, input.byteLength - offset)
  validateInnerBinding(value.turnKind, value.inner, value.parentCapability)
  const canonical = encodeRequest(value)
  if (!b4a.equals(canonical, input)) fail('request body is not canonical')
  return value
}

function encodeResultUnsigned (value, inner) {
  const output = b4a.alloc(FORWARD_HTTPS_LIMITS_V1.RESULT_HEADER_BYTES - 64 + inner.byteLength)
  let offset = 0
  offset = put(output, RESULT_MAGIC, offset)
  output[offset++] = 1
  output[offset++] = 7
  output[offset++] = 2
  output[offset++] = value.turnKind
  output[offset++] = value.outcome
  offset = put(output, bytes(value.sessionId, 32, 'sessionId', true), offset)
  offset = writeU64(output, value.sequence, offset, 'sequence')
  offset = put(output, bytes(value.requestCommitment, 32, 'requestCommitment', true), offset)
  offset = put(output, bytes(value.relayPublicKey, 32, 'relayPublicKey', true), offset)
  if (u64(value.descriptorSequence, 'descriptorSequence') === 0n) fail('descriptorSequence must be nonzero')
  offset = writeU64(output, value.descriptorSequence, offset, 'descriptorSequence')
  offset = put(output, bytes(value.descriptorHash, 32, 'descriptorHash', true), offset)
  offset = writeU32(output, inner.byteLength, offset, 'innerLength')
  offset = put(output, inner, offset)
  if (offset !== output.byteLength) fail('result unsigned encoder length mismatch')
  return output
}

function encodeResult (value) {
  assertObject(value, 'BlindForwardHttpsTurnResultV1')
  if (value.version !== 1 || value.routeKind !== 7 || value.releaseProfileId !== 2) fail('result fixed header is invalid')
  const codec = resultCodec(value.outcome, value.turnKind)
  const inner = encodeCanonical(codec, value.inner)
  if (inner.byteLength > FORWARD_HTTPS_LIMITS_V1.MAX_RESULT_INNER_BYTES) fail('result inner turn exceeds exact-body capacity', 'TOO_LARGE')
  const unsignedBytes = encodeResultUnsigned(value, inner)
  const output = b4a.alloc(FORWARD_HTTPS_LIMITS_V1.EXACT_RESULT_BYTES)
  let offset = 0
  offset = put(output, unsignedBytes.subarray(0, 153), offset)
  offset = put(output, bytes(value.signature, 64, 'signature'), offset)
  offset = put(output, unsignedBytes.subarray(153), offset)
  offset = put(output, padding(value.padding, output.byteLength - offset), offset)
  if (offset !== output.byteLength) fail('result encoder length mismatch')
  return output
}

function decodeResult (input) {
  input = bytes(input, FORWARD_HTTPS_LIMITS_V1.EXACT_RESULT_BYTES, 'result body')
  let offset = 0
  if (!b4a.equals(input.subarray(0, 4), RESULT_MAGIC)) fail('result magic is invalid')
  offset += 4
  const value = {
    version: input[offset++],
    routeKind: input[offset++],
    releaseProfileId: input[offset++],
    turnKind: input[offset++],
    outcome: input[offset++],
    sessionId: take(input, offset, 32)
  }
  offset += 32
  value.sequence = readU64(input, offset); offset += 8
  value.requestCommitment = take(input, offset, 32); offset += 32
  value.relayPublicKey = take(input, offset, 32); offset += 32
  value.descriptorSequence = readU64(input, offset); offset += 8
  value.descriptorHash = take(input, offset, 32); offset += 32
  value.signature = take(input, offset, 64); offset += 64
  const innerLength = readU32(input, offset); offset += 4
  if (innerLength > FORWARD_HTTPS_LIMITS_V1.MAX_RESULT_INNER_BYTES) fail('result innerLength exceeds exact-body capacity')
  const codec = resultCodec(value.outcome, value.turnKind)
  value.inner = decodeCanonical(codec, input.subarray(offset, offset + innerLength), { copyBytes: true }); offset += innerLength
  value.padding = take(input, offset, input.byteLength - offset)
  const canonical = encodeResult(value)
  if (!b4a.equals(canonical, input)) fail('result body is not canonical')
  return value
}

function fixedTurnCodec (length, encode, decode) {
  return Object.freeze({
    preencode (state, value) {
      encode(value)
      state.end += length
    },
    encode (state, value) {
      const encoded = encode(value)
      if (state.end - state.start < length) fail('truncated output allocation')
      b4a.copy(encoded, state.buffer, state.start)
      state.start += length
    },
    decode (state) {
      if (state.end - state.start < length) fail('truncated exact-size body')
      const value = decode(state.buffer.subarray(state.start, state.start + length))
      state.start += length
      return value
    }
  })
}

export const blindForwardHttpsTurnRequestV1 = fixedTurnCodec(
  FORWARD_HTTPS_LIMITS_V1.EXACT_REQUEST_BYTES,
  encodeRequest,
  decodeRequest
)

export const blindForwardHttpsTurnResultV1 = fixedTurnCodec(
  FORWARD_HTTPS_LIMITS_V1.EXACT_RESULT_BYTES,
  encodeResult,
  decodeResult
)

export function forwardHttpsTurnRequestCommitmentV1 (requestOrBytes) {
  const encoded = requestOrBytes && typeof requestOrBytes === 'object' && typeof requestOrBytes.byteLength !== 'number'
    ? encodeCanonical(blindForwardHttpsTurnRequestV1, requestOrBytes)
    : bytes(requestOrBytes, FORWARD_HTTPS_LIMITS_V1.EXACT_REQUEST_BYTES, 'request body')
  return blake2b256(b4a.concat([
    b4a.from(FORWARD_HTTPS_DOMAIN_V2.REQUEST.exactAsciiBytes, 'ascii'),
    encoded
  ]))
}

export function forwardHttpsTurnResultSignaturePayloadV1 (value) {
  const encoded = encodeResult(value)
  const unsigned = b4a.concat([
    encoded.subarray(0, 153),
    encoded.subarray(217)
  ])
  return signaturePayload(FORWARD_HTTPS_DOMAIN_V2.RESULT, unsigned)
}

export function normalizeReleaseProfileInputV2 (input) {
  if (input === 'BASELINE_17') return 'LIMITED_PUBLIC_TEST_V1'
  if (input === 'LIMITED_PUBLIC_TEST_V1' || input === 'LIMITED_PUBLIC_TEST_FORWARD_ONE_HOP_V1') return input
  fail('unknown release profile input', 'UNKNOWN_RELEASE_PROFILE')
}

export function releaseProfileV2 (input) {
  const canonicalName = normalizeReleaseProfileInputV2(input)
  return Object.freeze({ canonicalName, ...RELEASE_PROFILE_V2[canonicalName] })
}

export class ForwardHttpsTurnReplayWindowV1 {
  constructor (sessionId, nextSequence = 0n) {
    this.sessionId = bytes(sessionId, 32, 'sessionId', true)
    this.nextSequence = u64(nextSequence, 'nextSequence')
    this.outstanding = null
    this.terminal = false
  }

  accept (requestBytes) {
    if (this.terminal) fail('session is terminal', 'TERMINAL_REPLAY')
    requestBytes = bytes(requestBytes, FORWARD_HTTPS_LIMITS_V1.EXACT_REQUEST_BYTES, 'request body')
    const request = decodeRequest(requestBytes)
    if (!b4a.equals(request.sessionId, this.sessionId)) return this.#terminate('request session does not match')
    if (request.sequence !== this.nextSequence) return this.#terminate('request sequence is not the next sequence')
    if (this.outstanding) {
      if (b4a.equals(this.outstanding.bytes, requestBytes)) return Object.freeze({ disposition: 'IDEMPOTENT_RETRY', request })
      return this.#terminate('changed bytes reused the outstanding sequence')
    }
    this.outstanding = Object.freeze({
      bytes: b4a.from(requestBytes),
      commitment: forwardHttpsTurnRequestCommitmentV1(requestBytes),
      turnKind: request.turnKind
    })
    return Object.freeze({ disposition: 'ACCEPTED', request })
  }

  complete (resultBytes) {
    if (this.terminal) fail('session is terminal', 'TERMINAL_REPLAY')
    if (!this.outstanding) return this.#terminate('result has no outstanding request')
    const result = decodeResult(resultBytes)
    if (!b4a.equals(result.sessionId, this.sessionId) || result.sequence !== this.nextSequence ||
        result.turnKind !== this.outstanding.turnKind || !b4a.equals(result.requestCommitment, this.outstanding.commitment)) {
      return this.#terminate('result does not bind the outstanding request')
    }
    this.outstanding = null
    this.nextSequence++
    return result
  }

  #terminate (message) {
    this.terminal = true
    fail(message, 'TERMINAL_REPLAY')
  }
}
