import b4a from 'b4a'
import sodium from './crypto.js'
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
import {
  forwardHttpsParentCapabilitySignaturePayloadV1
} from './wire-v2.js'

const MAX_U64 = (1n << 64n) - 1n
const ZERO_32 = b4a.alloc(32)
const ZERO_64 = b4a.alloc(64)
const REQUEST_MAGIC = b4a.from('HFOQ', 'ascii')
const RESULT_MAGIC = b4a.from('HFOS', 'ascii')
const CAPABILITY_MAGIC = b4a.from('HFPC', 'ascii')

export const WIRE_V3_PROTOCOL = Object.freeze({ major: 1, minor: 2, abiFormatVersion: 3 })

export const WIRE_V3_SCHEMA = Object.freeze({
  BlindForwardHttpsOriginForwardTurnRequestV1: 76,
  BlindForwardHttpsOriginForwardTurnResultV1: 77
})

export const FORWARD_HTTPS_REQUEST_ROLE_V1 = Object.freeze({
  ORIGIN_TEMPLATE: 0,
  FORWARDED: 1
})

export const FORWARD_HTTPS_REQUEST_KIND_V1 = Object.freeze({
  OPEN: 1,
  DATA: 2,
  WINDOW: 3,
  CLOSE: 4,
  POLL: 5
})

export const FORWARD_HTTPS_RESULT_ROLE_V1 = Object.freeze({
  TARGET_RESULT: 1,
  SOURCE_PRE_FORWARD_ERROR: 2,
  SOURCE_POST_FORWARD_AMBIGUOUS: 3
})

export const FORWARD_HTTPS_RESPONSE_KIND_V1 = Object.freeze({
  OPEN_ACCEPT: 1,
  ACK: 2,
  NOOP: 3,
  DATA: 4,
  WINDOW: 5,
  CLOSE: 6,
  ERROR: 7,
  AMBIGUOUS: 8
})

export const FORWARD_HTTPS_DOMAIN_V3 = Object.freeze({
  REQUEST: Object.freeze({
    domainId: 18,
    purpose: 'REQUEST_COMMITMENT',
    purposeId: 1,
    recipeId: 1,
    name: 'FORWARD_HTTPS_ORIGIN_FORWARD_TURN',
    exactAsciiBytes: 'hiverelay.blind.forward-https-origin-forward-turn-request.v1'
  }),
  TARGET_RESULT: Object.freeze({
    domainId: 113,
    purpose: 'RESULT_SIGNATURE',
    purposeId: 2,
    recipeId: 2,
    name: 'FORWARD_HTTPS_TARGET_TURN_RESULT',
    exactAsciiBytes: 'hiverelay.blind.forward-https-target-turn-result.v1'
  }),
  SOURCE_PRE_FORWARD_ERROR: Object.freeze({
    domainId: 114,
    purpose: 'RESULT_SIGNATURE',
    purposeId: 2,
    recipeId: 2,
    name: 'FORWARD_HTTPS_SOURCE_PRE_FORWARD_ERROR',
    exactAsciiBytes: 'hiverelay.blind.forward-https-source-pre-forward-error.v1'
  }),
  SOURCE_POST_FORWARD_AMBIGUOUS: Object.freeze({
    domainId: 115,
    purpose: 'RESULT_SIGNATURE',
    purposeId: 2,
    recipeId: 2,
    name: 'FORWARD_HTTPS_SOURCE_POST_FORWARD_AMBIGUOUS',
    exactAsciiBytes: 'hiverelay.blind.forward-https-source-post-forward-ambiguous.v1'
  }),
  SOURCE_TRANSFORM: Object.freeze({
    domainId: 215,
    purpose: 'AUXILIARY_SIGNATURE',
    purposeId: 3,
    recipeId: 2,
    name: 'FORWARD_HTTPS_SOURCE_TRANSFORM',
    exactAsciiBytes: 'hiverelay.blind.forward-https-source-transform.v1'
  }),
  STABLE_SESSION: Object.freeze({
    domainId: 216,
    purpose: 'HASH_DOMAIN',
    purposeId: 4,
    recipeId: 4,
    name: 'FORWARD_HTTPS_STABLE_SESSION',
    exactAsciiBytes: 'hiverelay.blind.forward-https-stable-session.v1'
  }),
  TARGET_RESULT_CHAIN: Object.freeze({
    domainId: 217,
    purpose: 'HASH_DOMAIN',
    purposeId: 4,
    recipeId: 3,
    name: 'FORWARD_HTTPS_TARGET_RESULT_CHAIN',
    exactAsciiBytes: 'hiverelay.blind.forward-https-target-result-chain.v1'
  }),
  TLS_EXPORTER_CONTEXT: Object.freeze({
    domainId: 218,
    purpose: 'HASH_DOMAIN',
    purposeId: 4,
    recipeId: 3,
    name: 'FORWARD_HTTPS_TLS_EXPORTER_CONTEXT',
    exactAsciiBytes: 'hiverelay.blind.forward-https-tls-exporter-context.v1'
  }),
  TLS_EXPORTER_BINDING: Object.freeze({
    domainId: 219,
    purpose: 'HASH_DOMAIN',
    purposeId: 4,
    recipeId: 4,
    name: 'FORWARD_HTTPS_TLS_EXPORTER_BINDING',
    exactAsciiBytes: 'hiverelay.blind.forward-https-tls-exporter-binding.v1'
  })
})

export const WIRE_V3_HASH_DOMAIN_PURPOSE = Object.freeze({ purposeId: 4, name: 'HASH_DOMAIN' })

export const WIRE_V3_HASH_RECIPES = Object.freeze([
  Object.freeze({
    recipeId: 3,
    name: 'BLAKE2B256_ASCII_DOMAIN_PAYLOAD',
    canonicalPreimage: 'ASCII(domain) || exact fixed-shape payload'
  }),
  Object.freeze({
    recipeId: 4,
    name: 'BLAKE2B256_ASCII_DOMAIN_LEN64_PAYLOAD',
    canonicalPreimage: 'ASCII(domain) || u64be(payloadLength) || payload'
  })
])

export const FORWARD_HTTPS_V3_LIMITS = Object.freeze({
  EXACT_REQUEST_BYTES: 65_536,
  EXACT_RESULT_BYTES: 65_536,
  REQUEST_HEADER_BYTES: 668,
  RESULT_HEADER_BYTES: 773,
  MAX_REQUEST_INNER_BYTES: 64_868,
  MAX_RESULT_INNER_BYTES: 64_763,
  MAX_DATA_BYTES: 64_000,
  CAPABILITY_BYTES: 390,
  CAPABILITY_IMMUTABLE_PREFIX_BYTES: 294,
  CAPABILITY_EXPORTER_OFFSET: 294,
  CAPABILITY_SIGNATURE_OFFSET: 326,
  SOURCE_TRANSFORM_UNSIGNED_BYTES: 65_472,
  RESULT_UNSIGNED_BYTES: 65_472,
  TRANSPORT_EXCHANGE_BYTES: 131_072,
  TRANSPORT_BUDGET_BYTES: 16 * 1024 * 1024
})

export const FORWARD_HTTPS_V3_RESULT_MATRIX = Object.freeze({
  [FORWARD_HTTPS_REQUEST_KIND_V1.OPEN]: Object.freeze([
    FORWARD_HTTPS_RESPONSE_KIND_V1.OPEN_ACCEPT,
    FORWARD_HTTPS_RESPONSE_KIND_V1.ERROR
  ]),
  [FORWARD_HTTPS_REQUEST_KIND_V1.DATA]: Object.freeze([
    FORWARD_HTTPS_RESPONSE_KIND_V1.ACK,
    FORWARD_HTTPS_RESPONSE_KIND_V1.DATA,
    FORWARD_HTTPS_RESPONSE_KIND_V1.WINDOW,
    FORWARD_HTTPS_RESPONSE_KIND_V1.CLOSE,
    FORWARD_HTTPS_RESPONSE_KIND_V1.ERROR
  ]),
  [FORWARD_HTTPS_REQUEST_KIND_V1.WINDOW]: Object.freeze([
    FORWARD_HTTPS_RESPONSE_KIND_V1.ACK,
    FORWARD_HTTPS_RESPONSE_KIND_V1.DATA,
    FORWARD_HTTPS_RESPONSE_KIND_V1.WINDOW,
    FORWARD_HTTPS_RESPONSE_KIND_V1.CLOSE,
    FORWARD_HTTPS_RESPONSE_KIND_V1.ERROR
  ]),
  [FORWARD_HTTPS_REQUEST_KIND_V1.CLOSE]: Object.freeze([
    FORWARD_HTTPS_RESPONSE_KIND_V1.ACK,
    FORWARD_HTTPS_RESPONSE_KIND_V1.CLOSE,
    FORWARD_HTTPS_RESPONSE_KIND_V1.ERROR
  ]),
  [FORWARD_HTTPS_REQUEST_KIND_V1.POLL]: Object.freeze([
    FORWARD_HTTPS_RESPONSE_KIND_V1.NOOP,
    FORWARD_HTTPS_RESPONSE_KIND_V1.DATA,
    FORWARD_HTTPS_RESPONSE_KIND_V1.WINDOW,
    FORWARD_HTTPS_RESPONSE_KIND_V1.CLOSE,
    FORWARD_HTTPS_RESPONSE_KIND_V1.ERROR
  ])
})

export const FORWARD_HTTPS_SUCCESSOR_TRANSPORT_VARIANTS_V3 = Object.freeze([
  ['OPEN', FORWARD_HTTPS_REQUEST_KIND_V1.OPEN],
  ['DATA', FORWARD_HTTPS_REQUEST_KIND_V1.DATA],
  ['WINDOW', FORWARD_HTTPS_REQUEST_KIND_V1.WINDOW],
  ['CLOSE', FORWARD_HTTPS_REQUEST_KIND_V1.CLOSE]
].map(([operation, requestKind]) => Object.freeze({
  family: 'FORWARD',
  operation,
  routeKind: 7,
  releaseProfileId: 2,
  requestSchemaId: 76,
  resultSchemaId: 77,
  requestBytes: 65_536,
  resultBytes: 65_536,
  requestKind
})))

export const FORWARD_HTTPS_ADAPTER_LEGALITY_V3 = Object.freeze({
  requestKinds: FORWARD_HTTPS_REQUEST_KIND_V1,
  responseKinds: FORWARD_HTTPS_RESPONSE_KIND_V1,
  resultMatrix: FORWARD_HTTPS_V3_RESULT_MATRIX,
  adapterOnly: Object.freeze(['POLL', 'ACK', 'NOOP']),
  globalOperations: Object.freeze(['OPEN', 'DATA', 'WINDOW', 'CLOSE'])
})

export const WIRE_V3_SCHEMA_DECLARATIONS = Object.freeze([
  Object.freeze({
    schemaId: 76,
    schemaName: 'BlindForwardHttpsOriginForwardTurnRequestV1',
    fields: Object.freeze([
      'magic:fixed4=HFOQ', 'version:u8=1', 'routeKind:u8=7', 'releaseProfileId:u8=2',
      'requestRole:u8[ORIGIN_TEMPLATE=0|FORWARDED=1]',
      'requestKind:u8[OPEN=1|DATA=2|WINDOW=3|CLOSE=4|POLL=5]', 'flags:u8=0',
      'stableSessionId:fixed32[nonzero]', 'sequence:u64be', 'clientSessionNonce:fixed32[nonzero]',
      'requestNonce:fixed32[nonzero]', 'previousTargetResultHash:fixed32',
      'parentCapabilitySlot:fixed390[origin-zero-exporter-signature|forwarded-finalized]',
      'turnTlsExporterBindingHash:fixed32', 'originRequestCommitment:fixed32',
      'sourceTransformSignature:fixed64', 'innerLength:u32be',
      'inner:closed(requestKind){OPEN:BlindForwardOpenV1|DATA:BlindForwardDataV1[maxBytes=64000]|WINDOW:BlindForwardWindowV1|CLOSE:BlindForwardCloseV1|POLL:empty}',
      'padding:zero[65536-668-innerLength]', 'exactBytes:65536'
    ])
  }),
  Object.freeze({
    schemaId: 77,
    schemaName: 'BlindForwardHttpsOriginForwardTurnResultV1',
    fields: Object.freeze([
      'magic:fixed4=HFOS', 'version:u8=1', 'routeKind:u8=7', 'releaseProfileId:u8=2',
      'resultRole:u8[TARGET_RESULT=1|SOURCE_PRE_FORWARD_ERROR=2|SOURCE_POST_FORWARD_AMBIGUOUS=3]',
      'requestKind:u8[OPEN=1|DATA=2|WINDOW=3|CLOSE=4|POLL=5]',
      'responseKind:u8[OPEN_ACCEPT=1|ACK=2|NOOP=3|DATA=4|WINDOW=5|CLOSE=6|ERROR=7|AMBIGUOUS=8]',
      'flags:u8=0', 'stableSessionId:fixed32[nonzero]', 'sequence:u64be',
      'previousTargetResultHash:fixed32', 'originRequestCommitment:fixed32[nonzero]',
      'forwardedRequestCommitment:fixed32[nonzero]', 'finalizedParentCapability:fixed390',
      'turnTlsExporterBindingHash:fixed32[nonzero]', 'sourceTransformSignature:fixed64[nonzero]',
      'signerPublicKey:fixed32[nonzero]', 'signerDescriptorSequence:u64be[nonzero]',
      'signerDescriptorHash:fixed32[nonzero]', 'resultSignature:fixed64', 'innerLength:u32be',
      'inner:closed(resultRole,requestKind,responseKind)',
      'padding:zero[65536-773-innerLength]', 'exactBytes:65536'
    ])
  })
])

function fail (message, code = 'BAD_FORWARD_HTTPS_ORIGIN_TURN') {
  protocolError(code, message)
}

function asBytes (value, length, field, nonzero = false) {
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

function assertZero (value, field) {
  if (!isZero(value)) fail(`${field} must be all zero`)
  return value
}

function assertObject (value, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${field} must be an object`)
  return value
}

function unsigned (value, maximum, field) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) fail(`${field} is outside its unsigned range`)
  return value
}

function u64 (value, field, nonzero = false) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${field} must be an unsigned safe integer or bigint`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64 || (nonzero && value === 0n)) fail(`${field} is outside u64`)
  return value
}

function put (output, value, offset) {
  b4a.copy(value, output, offset)
  return offset + value.byteLength
}

function take (input, offset, length) {
  return b4a.from(input.subarray(offset, offset + length))
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

function length64 (length) {
  const output = b4a.alloc(8)
  writeU64(output, BigInt(length), 0, 'preimage length')
  return output
}

function signaturePayload (domain, unsignedBytes) {
  return b4a.concat([b4a.from(domain.exactAsciiBytes, 'ascii'), length64(unsignedBytes.byteLength), unsignedBytes])
}

function capabilityFields (value, role) {
  assertObject(value, 'parentCapability')
  for (const forbidden of ['url', 'host', 'hostname', 'ip', 'ipAddress', 'dialAddress']) {
    if (forbidden in value) fail(`parentCapability.${forbidden} is forbidden`)
  }
  if (value.version !== 1 || value.routeKind !== 7 || value.releaseProfileId !== 2) fail('parent capability fixed header is invalid')
  const sourceRelayPublicKey = asBytes(value.sourceRelayPublicKey, 32, 'sourceRelayPublicKey', true)
  const targetRelayPublicKey = asBytes(value.targetRelayPublicKey, 32, 'targetRelayPublicKey', true)
  const routePrefixRelayPublicKey = asBytes(value.routePrefixRelayPublicKey, 32, 'routePrefixRelayPublicKey', true)
  if (b4a.equals(sourceRelayPublicKey, targetRelayPublicKey)) fail('source and target relay keys must differ')
  if (!b4a.equals(sourceRelayPublicKey, routePrefixRelayPublicKey)) fail('route prefix must contain exactly the source relay')
  for (const field of ['sourceDescriptorHash', 'targetDescriptorHash', 'targetCatalogEntryId', 'circuitNonce']) {
    asBytes(value[field], 32, field, true)
  }
  asBytes(value.routeId, 16, 'routeId', true)
  u64(value.sourceDescriptorSequence, 'sourceDescriptorSequence', true)
  u64(value.targetDescriptorSequence, 'targetDescriptorSequence', true)
  if (value.maxRelayCount !== 2 || value.remainingTransitions !== 1 || value.circuitClass !== 1 ||
      u64(value.maxCircuitBytes, 'maxCircuitBytes') !== 16n * 1024n * 1024n ||
      value.initialWindowBytes !== 65_536 || value.idleMillis !== 30_000 || value.lifetimeMillis !== 600_000) {
    fail('parent capability fixed bounds are invalid')
  }
  unsigned(value.issuedAtEpoch, 0xffffffff, 'issuedAtEpoch')
  unsigned(value.expiresAtEpoch, 0xffffffff, 'expiresAtEpoch')
  if (value.expiresAtEpoch !== value.issuedAtEpoch + 600) fail('parent capability lifetime must be exactly 600 seconds')
  const exporter = asBytes(value.tlsExporterBindingHash, 32, 'tlsExporterBindingHash')
  const signature = asBytes(value.signature, 64, 'signature')
  if (role === FORWARD_HTTPS_REQUEST_ROLE_V1.ORIGIN_TEMPLATE) {
    assertZero(exporter, 'origin capability exporter')
    assertZero(signature, 'origin capability signature')
  } else if (role === FORWARD_HTTPS_REQUEST_ROLE_V1.FORWARDED) {
    if (isZero(exporter) || isZero(signature)) fail('forwarded capability exporter and signature must be nonzero')
  } else fail('requestRole is unknown')
  return value
}

export function encodeForwardHttpsParentCapabilitySlotV1 (value, role) {
  capabilityFields(value, role)
  const output = b4a.alloc(FORWARD_HTTPS_V3_LIMITS.CAPABILITY_BYTES)
  let offset = put(output, CAPABILITY_MAGIC, 0)
  output[offset++] = 1
  output[offset++] = 7
  output[offset++] = 2
  offset = put(output, value.sourceRelayPublicKey, offset)
  offset = writeU64(output, value.sourceDescriptorSequence, offset, 'sourceDescriptorSequence')
  offset = put(output, value.sourceDescriptorHash, offset)
  offset = put(output, value.targetRelayPublicKey, offset)
  offset = writeU64(output, value.targetDescriptorSequence, offset, 'targetDescriptorSequence')
  offset = put(output, value.targetDescriptorHash, offset)
  offset = put(output, value.targetCatalogEntryId, offset)
  offset = put(output, value.routeId, offset)
  offset = put(output, value.routePrefixRelayPublicKey, offset)
  output[offset++] = value.maxRelayCount
  output[offset++] = value.remainingTransitions
  output[offset++] = value.circuitClass
  offset = writeU64(output, value.maxCircuitBytes, offset, 'maxCircuitBytes')
  offset = writeU32(output, value.initialWindowBytes, offset, 'initialWindowBytes')
  offset = writeU32(output, value.idleMillis, offset, 'idleMillis')
  offset = writeU32(output, value.lifetimeMillis, offset, 'lifetimeMillis')
  offset = writeU32(output, value.issuedAtEpoch, offset, 'issuedAtEpoch')
  offset = writeU32(output, value.expiresAtEpoch, offset, 'expiresAtEpoch')
  offset = put(output, value.circuitNonce, offset)
  offset = put(output, value.tlsExporterBindingHash, offset)
  offset = put(output, value.signature, offset)
  if (offset !== output.byteLength) fail('parent capability slot encoder length mismatch')
  return output
}

export function decodeForwardHttpsParentCapabilitySlotV1 (input, role) {
  input = asBytes(input, FORWARD_HTTPS_V3_LIMITS.CAPABILITY_BYTES, 'parent capability slot')
  if (!b4a.equals(input.subarray(0, 4), CAPABILITY_MAGIC)) fail('parent capability magic is invalid')
  let offset = 4
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
  if (offset !== input.byteLength) fail('parent capability slot decoder length mismatch')
  capabilityFields(value, role)
  if (!b4a.equals(encodeForwardHttpsParentCapabilitySlotV1(value, role), input)) fail('parent capability slot is not canonical')
  return value
}

function capabilityPrefixBytes (capability) {
  return encodeForwardHttpsParentCapabilitySlotV1(
    { ...capability, tlsExporterBindingHash: ZERO_32, signature: ZERO_64 },
    FORWARD_HTTPS_REQUEST_ROLE_V1.ORIGIN_TEMPLATE
  ).subarray(0, FORWARD_HTTPS_V3_LIMITS.CAPABILITY_IMMUTABLE_PREFIX_BYTES)
}

export function forwardHttpsStableSessionIdV1 (parentCapability, clientSessionNonce) {
  const prefix = capabilityPrefixBytes(parentCapability)
  clientSessionNonce = asBytes(clientSessionNonce, 32, 'clientSessionNonce', true)
  return blake2b256(b4a.concat([
    b4a.from(FORWARD_HTTPS_DOMAIN_V3.STABLE_SESSION.exactAsciiBytes, 'ascii'),
    length64(prefix.byteLength + clientSessionNonce.byteLength),
    prefix,
    clientSessionNonce
  ]))
}

function requestCodec (requestKind) {
  switch (requestKind) {
    case FORWARD_HTTPS_REQUEST_KIND_V1.OPEN: return blindForwardOpenV1
    case FORWARD_HTTPS_REQUEST_KIND_V1.DATA: return blindForwardDataV1
    case FORWARD_HTTPS_REQUEST_KIND_V1.WINDOW: return blindForwardWindowV1
    case FORWARD_HTTPS_REQUEST_KIND_V1.CLOSE: return blindForwardCloseV1
    case FORWARD_HTTPS_REQUEST_KIND_V1.POLL: return null
    default: fail('requestKind is unknown')
  }
}

function resultCodec (responseKind) {
  switch (responseKind) {
    case FORWARD_HTTPS_RESPONSE_KIND_V1.OPEN_ACCEPT: return blindForwardOpenResultV1
    case FORWARD_HTTPS_RESPONSE_KIND_V1.DATA: return blindForwardDataV1
    case FORWARD_HTTPS_RESPONSE_KIND_V1.WINDOW: return blindForwardWindowV1
    case FORWARD_HTTPS_RESPONSE_KIND_V1.CLOSE: return blindForwardCloseV1
    case FORWARD_HTTPS_RESPONSE_KIND_V1.ERROR: return blindErrorV1
    case FORWARD_HTTPS_RESPONSE_KIND_V1.ACK:
    case FORWARD_HTTPS_RESPONSE_KIND_V1.NOOP:
    case FORWARD_HTTPS_RESPONSE_KIND_V1.AMBIGUOUS:
      return null
    default: fail('responseKind is unknown')
  }
}

function validateRequestInner (value) {
  const codec = requestCodec(value.requestKind)
  if (!codec) {
    if (value.inner != null) fail('POLL inner must be absent')
    return b4a.alloc(0)
  }
  assertObject(value.inner, 'request inner')
  const capability = value.parentCapability
  if (value.requestKind === FORWARD_HTTPS_REQUEST_KIND_V1.OPEN) {
    if (value.sequence !== 0n || !isZero(value.previousTargetResultHash)) fail('OPEN requires sequence zero and zero previous result hash')
    if (!b4a.equals(asBytes(value.inner.routeId, 16, 'inner.routeId'), capability.routeId) ||
        u64(value.inner.nextDescriptorSequence, 'inner.nextDescriptorSequence') !== u64(capability.targetDescriptorSequence, 'targetDescriptorSequence') ||
        !b4a.equals(asBytes(value.inner.nextDescriptorHash, 32, 'inner.nextDescriptorHash'), capability.targetDescriptorHash) ||
        value.inner.circuitClass !== capability.circuitClass ||
        !b4a.equals(asBytes(value.inner.circuitNonce, 32, 'inner.circuitNonce'), capability.circuitNonce) ||
        !isZero(asBytes(value.inner.parentRouteScopeHash, 32, 'inner.parentRouteScopeHash'))) {
      fail('OPEN inner does not bind the parent capability')
    }
  } else {
    if (value.sequence === 0n || isZero(value.previousTargetResultHash)) fail('non-OPEN request requires sequence and previous target result hash')
    if (!b4a.equals(asBytes(value.inner.circuitNonce, 32, 'inner.circuitNonce'), capability.circuitNonce)) {
      fail('request inner circuitNonce does not bind the parent capability')
    }
  }
  if (value.requestKind === FORWARD_HTTPS_REQUEST_KIND_V1.DATA &&
      (!value.inner.bytes || value.inner.bytes.byteLength > FORWARD_HTTPS_V3_LIMITS.MAX_DATA_BYTES)) {
    fail('DATA bytes exceed the direct-HTTPS 64000-byte clamp', 'TOO_LARGE')
  }
  return encodeCanonical(codec, value.inner)
}

function validateRequest (value) {
  assertObject(value, 'BlindForwardHttpsOriginForwardTurnRequestV1')
  if (value.version !== 1 || value.routeKind !== 7 || value.releaseProfileId !== 2 || value.flags !== 0) fail('request fixed header is invalid')
  if (!Object.values(FORWARD_HTTPS_REQUEST_ROLE_V1).includes(value.requestRole)) fail('requestRole is unknown')
  if (!Object.values(FORWARD_HTTPS_REQUEST_KIND_V1).includes(value.requestKind)) fail('requestKind is unknown')
  value.sequence = u64(value.sequence, 'sequence')
  value.stableSessionId = asBytes(value.stableSessionId, 32, 'stableSessionId', true)
  value.clientSessionNonce = asBytes(value.clientSessionNonce, 32, 'clientSessionNonce', true)
  value.requestNonce = asBytes(value.requestNonce, 32, 'requestNonce', true)
  value.previousTargetResultHash = asBytes(value.previousTargetResultHash, 32, 'previousTargetResultHash')
  capabilityFields(value.parentCapability, value.requestRole)
  if (!b4a.equals(value.stableSessionId, forwardHttpsStableSessionIdV1(value.parentCapability, value.clientSessionNonce))) {
    fail('stableSessionId does not bind the immutable capability prefix and client nonce')
  }
  value.turnTlsExporterBindingHash = asBytes(value.turnTlsExporterBindingHash, 32, 'turnTlsExporterBindingHash')
  value.originRequestCommitment = asBytes(value.originRequestCommitment, 32, 'originRequestCommitment')
  value.sourceTransformSignature = asBytes(value.sourceTransformSignature, 64, 'sourceTransformSignature')
  if (value.requestRole === FORWARD_HTTPS_REQUEST_ROLE_V1.ORIGIN_TEMPLATE) {
    assertZero(value.turnTlsExporterBindingHash, 'origin exporter mirror')
    assertZero(value.originRequestCommitment, 'origin commitment slot')
    assertZero(value.sourceTransformSignature, 'origin transform signature')
  } else {
    if (isZero(value.turnTlsExporterBindingHash) || isZero(value.originRequestCommitment) || isZero(value.sourceTransformSignature)) {
      fail('forwarded exporter, origin commitment, and transform signature must be nonzero')
    }
    if (!b4a.equals(value.turnTlsExporterBindingHash, value.parentCapability.tlsExporterBindingHash)) {
      fail('forwarded exporter mirror does not match the finalized capability')
    }
  }
  if (value.requestKind === FORWARD_HTTPS_REQUEST_KIND_V1.POLL) {
    if (value.sequence === 0n || isZero(value.previousTargetResultHash)) fail('POLL requires a prior definitive target result')
  }
  return validateRequestInner(value)
}

function encodeRequest (value) {
  const inner = validateRequest(value)
  if (inner.byteLength > FORWARD_HTTPS_V3_LIMITS.MAX_REQUEST_INNER_BYTES) fail('request inner exceeds exact-body capacity', 'TOO_LARGE')
  const output = b4a.alloc(FORWARD_HTTPS_V3_LIMITS.EXACT_REQUEST_BYTES)
  let offset = put(output, REQUEST_MAGIC, 0)
  output[offset++] = 1
  output[offset++] = 7
  output[offset++] = 2
  output[offset++] = value.requestRole
  output[offset++] = value.requestKind
  output[offset++] = 0
  offset = put(output, value.stableSessionId, offset)
  offset = writeU64(output, value.sequence, offset, 'sequence')
  offset = put(output, value.clientSessionNonce, offset)
  offset = put(output, value.requestNonce, offset)
  offset = put(output, value.previousTargetResultHash, offset)
  offset = put(output, encodeForwardHttpsParentCapabilitySlotV1(value.parentCapability, value.requestRole), offset)
  offset = put(output, value.turnTlsExporterBindingHash, offset)
  offset = put(output, value.originRequestCommitment, offset)
  offset = put(output, value.sourceTransformSignature, offset)
  offset = writeU32(output, inner.byteLength, offset, 'innerLength')
  offset = put(output, inner, offset)
  const paddingLength = output.byteLength - offset
  if (value.padding != null) assertZero(asBytes(value.padding, paddingLength, 'padding'), 'padding')
  offset += paddingLength
  if (offset !== output.byteLength) fail('request encoder length mismatch')
  return output
}

function decodeRequest (input) {
  input = asBytes(input, FORWARD_HTTPS_V3_LIMITS.EXACT_REQUEST_BYTES, 'request body')
  if (!b4a.equals(input.subarray(0, 4), REQUEST_MAGIC)) fail('request magic is invalid')
  let offset = 4
  const value = {
    version: input[offset++],
    routeKind: input[offset++],
    releaseProfileId: input[offset++],
    requestRole: input[offset++],
    requestKind: input[offset++],
    flags: input[offset++],
    stableSessionId: take(input, offset, 32)
  }
  offset += 32
  value.sequence = readU64(input, offset); offset += 8
  value.clientSessionNonce = take(input, offset, 32); offset += 32
  value.requestNonce = take(input, offset, 32); offset += 32
  value.previousTargetResultHash = take(input, offset, 32); offset += 32
  value.parentCapability = decodeForwardHttpsParentCapabilitySlotV1(input.subarray(offset, offset + 390), value.requestRole); offset += 390
  value.turnTlsExporterBindingHash = take(input, offset, 32); offset += 32
  value.originRequestCommitment = take(input, offset, 32); offset += 32
  value.sourceTransformSignature = take(input, offset, 64); offset += 64
  const innerLength = readU32(input, offset); offset += 4
  if (innerLength > FORWARD_HTTPS_V3_LIMITS.MAX_REQUEST_INNER_BYTES) fail('request innerLength exceeds exact-body capacity')
  const codec = requestCodec(value.requestKind)
  if (codec) value.inner = decodeCanonical(codec, input.subarray(offset, offset + innerLength), { copyBytes: true })
  else if (innerLength !== 0) fail('POLL innerLength must be zero')
  else value.inner = null
  offset += innerLength
  value.padding = take(input, offset, input.byteLength - offset)
  assertZero(value.padding, 'padding')
  if (!b4a.equals(encodeRequest(value), input)) fail('request body is not canonical')
  return value
}

function resultDomain (role) {
  if (role === FORWARD_HTTPS_RESULT_ROLE_V1.TARGET_RESULT) return FORWARD_HTTPS_DOMAIN_V3.TARGET_RESULT
  if (role === FORWARD_HTTPS_RESULT_ROLE_V1.SOURCE_PRE_FORWARD_ERROR) return FORWARD_HTTPS_DOMAIN_V3.SOURCE_PRE_FORWARD_ERROR
  if (role === FORWARD_HTTPS_RESULT_ROLE_V1.SOURCE_POST_FORWARD_AMBIGUOUS) return FORWARD_HTTPS_DOMAIN_V3.SOURCE_POST_FORWARD_AMBIGUOUS
  fail('resultRole is unknown')
}

function validateResultInner (value) {
  const codec = resultCodec(value.responseKind)
  if (!codec) {
    if (value.inner != null) fail('zero-inner response must not carry inner data')
    return b4a.alloc(0)
  }
  assertObject(value.inner, 'result inner')
  if (value.responseKind === FORWARD_HTTPS_RESPONSE_KIND_V1.DATA &&
      (!value.inner.bytes || value.inner.bytes.byteLength > FORWARD_HTTPS_V3_LIMITS.MAX_DATA_BYTES)) {
    fail('result DATA bytes exceed the direct-HTTPS 64000-byte clamp', 'TOO_LARGE')
  }
  if ([
    FORWARD_HTTPS_RESPONSE_KIND_V1.DATA,
    FORWARD_HTTPS_RESPONSE_KIND_V1.WINDOW,
    FORWARD_HTTPS_RESPONSE_KIND_V1.CLOSE
  ].includes(value.responseKind) && !b4a.equals(asBytes(value.inner.circuitNonce, 32, 'result inner circuitNonce'), value.finalizedParentCapability.circuitNonce)) {
    fail('result inner circuitNonce does not bind the finalized capability')
  }
  return encodeCanonical(codec, value.inner)
}

function validateResult (value) {
  assertObject(value, 'BlindForwardHttpsOriginForwardTurnResultV1')
  if (value.version !== 1 || value.routeKind !== 7 || value.releaseProfileId !== 2 || value.flags !== 0) fail('result fixed header is invalid')
  resultDomain(value.resultRole)
  if (!Object.values(FORWARD_HTTPS_REQUEST_KIND_V1).includes(value.requestKind)) fail('result requestKind is unknown')
  if (!Object.values(FORWARD_HTTPS_RESPONSE_KIND_V1).includes(value.responseKind)) fail('responseKind is unknown')
  if (value.resultRole === FORWARD_HTTPS_RESULT_ROLE_V1.TARGET_RESULT) {
    if (!FORWARD_HTTPS_V3_RESULT_MATRIX[value.requestKind].includes(value.responseKind)) fail('target response is illegal for requestKind')
  } else if (value.resultRole === FORWARD_HTTPS_RESULT_ROLE_V1.SOURCE_PRE_FORWARD_ERROR) {
    if (value.responseKind !== FORWARD_HTTPS_RESPONSE_KIND_V1.ERROR) fail('source pre-forward result must be ERROR')
  } else if (value.responseKind !== FORWARD_HTTPS_RESPONSE_KIND_V1.AMBIGUOUS) {
    fail('source post-forward result must be AMBIGUOUS')
  }
  value.stableSessionId = asBytes(value.stableSessionId, 32, 'stableSessionId', true)
  value.sequence = u64(value.sequence, 'sequence')
  value.previousTargetResultHash = asBytes(value.previousTargetResultHash, 32, 'previousTargetResultHash')
  if ((value.sequence === 0n) !== isZero(value.previousTargetResultHash)) fail('result previous target hash does not match sequence')
  for (const field of ['originRequestCommitment', 'forwardedRequestCommitment', 'turnTlsExporterBindingHash', 'signerPublicKey', 'signerDescriptorHash']) {
    value[field] = asBytes(value[field], 32, field, true)
  }
  value.sourceTransformSignature = asBytes(value.sourceTransformSignature, 64, 'sourceTransformSignature', true)
  value.resultSignature = asBytes(value.resultSignature, 64, 'resultSignature')
  capabilityFields(value.finalizedParentCapability, FORWARD_HTTPS_REQUEST_ROLE_V1.FORWARDED)
  // A result intentionally does not repeat clientSessionNonce. Exact stable-session
  // reconstruction is enforced when the result is bound to its origin request.
  if (!b4a.equals(value.turnTlsExporterBindingHash, value.finalizedParentCapability.tlsExporterBindingHash)) {
    fail('result exporter mirror does not match finalized capability')
  }
  const sourceRole = value.resultRole !== FORWARD_HTTPS_RESULT_ROLE_V1.TARGET_RESULT
  const expectedKey = sourceRole ? value.finalizedParentCapability.sourceRelayPublicKey : value.finalizedParentCapability.targetRelayPublicKey
  const expectedSequence = sourceRole ? value.finalizedParentCapability.sourceDescriptorSequence : value.finalizedParentCapability.targetDescriptorSequence
  const expectedHash = sourceRole ? value.finalizedParentCapability.sourceDescriptorHash : value.finalizedParentCapability.targetDescriptorHash
  if (!b4a.equals(value.signerPublicKey, expectedKey) || u64(value.signerDescriptorSequence, 'signerDescriptorSequence', true) !== expectedSequence ||
      !b4a.equals(value.signerDescriptorHash, expectedHash)) {
    fail('result signer does not match the role-selected capability descriptor')
  }
  return validateResultInner(value)
}

function encodeResult (value) {
  const inner = validateResult(value)
  if (inner.byteLength > FORWARD_HTTPS_V3_LIMITS.MAX_RESULT_INNER_BYTES) fail('result inner exceeds exact-body capacity', 'TOO_LARGE')
  const output = b4a.alloc(FORWARD_HTTPS_V3_LIMITS.EXACT_RESULT_BYTES)
  let offset = put(output, RESULT_MAGIC, 0)
  output[offset++] = 1
  output[offset++] = 7
  output[offset++] = 2
  output[offset++] = value.resultRole
  output[offset++] = value.requestKind
  output[offset++] = value.responseKind
  output[offset++] = 0
  offset = put(output, value.stableSessionId, offset)
  offset = writeU64(output, value.sequence, offset, 'sequence')
  offset = put(output, value.previousTargetResultHash, offset)
  offset = put(output, value.originRequestCommitment, offset)
  offset = put(output, value.forwardedRequestCommitment, offset)
  offset = put(output, encodeForwardHttpsParentCapabilitySlotV1(value.finalizedParentCapability, FORWARD_HTTPS_REQUEST_ROLE_V1.FORWARDED), offset)
  offset = put(output, value.turnTlsExporterBindingHash, offset)
  offset = put(output, value.sourceTransformSignature, offset)
  offset = put(output, value.signerPublicKey, offset)
  offset = writeU64(output, value.signerDescriptorSequence, offset, 'signerDescriptorSequence')
  offset = put(output, value.signerDescriptorHash, offset)
  offset = put(output, value.resultSignature, offset)
  offset = writeU32(output, inner.byteLength, offset, 'innerLength')
  offset = put(output, inner, offset)
  const paddingLength = output.byteLength - offset
  if (value.padding != null) assertZero(asBytes(value.padding, paddingLength, 'padding'), 'padding')
  offset += paddingLength
  if (offset !== output.byteLength) fail('result encoder length mismatch')
  return output
}

function decodeResult (input) {
  input = asBytes(input, FORWARD_HTTPS_V3_LIMITS.EXACT_RESULT_BYTES, 'result body')
  if (!b4a.equals(input.subarray(0, 4), RESULT_MAGIC)) fail('result magic is invalid')
  let offset = 4
  const value = {
    version: input[offset++],
    routeKind: input[offset++],
    releaseProfileId: input[offset++],
    resultRole: input[offset++],
    requestKind: input[offset++],
    responseKind: input[offset++],
    flags: input[offset++],
    stableSessionId: take(input, offset, 32)
  }
  offset += 32
  value.sequence = readU64(input, offset); offset += 8
  value.previousTargetResultHash = take(input, offset, 32); offset += 32
  value.originRequestCommitment = take(input, offset, 32); offset += 32
  value.forwardedRequestCommitment = take(input, offset, 32); offset += 32
  value.finalizedParentCapability = decodeForwardHttpsParentCapabilitySlotV1(input.subarray(offset, offset + 390), FORWARD_HTTPS_REQUEST_ROLE_V1.FORWARDED); offset += 390
  value.turnTlsExporterBindingHash = take(input, offset, 32); offset += 32
  value.sourceTransformSignature = take(input, offset, 64); offset += 64
  value.signerPublicKey = take(input, offset, 32); offset += 32
  value.signerDescriptorSequence = readU64(input, offset); offset += 8
  value.signerDescriptorHash = take(input, offset, 32); offset += 32
  value.resultSignature = take(input, offset, 64); offset += 64
  const innerLength = readU32(input, offset); offset += 4
  if (innerLength > FORWARD_HTTPS_V3_LIMITS.MAX_RESULT_INNER_BYTES) fail('result innerLength exceeds exact-body capacity')
  const codec = resultCodec(value.responseKind)
  if (codec) value.inner = decodeCanonical(codec, input.subarray(offset, offset + innerLength), { copyBytes: true })
  else if (innerLength !== 0) fail('zero-inner response innerLength must be zero')
  else value.inner = null
  offset += innerLength
  value.padding = take(input, offset, input.byteLength - offset)
  assertZero(value.padding, 'padding')
  if (!b4a.equals(encodeResult(value), input)) fail('result body is not canonical')
  return value
}

function fixedCodec (length, encode, decode) {
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

export const blindForwardHttpsOriginForwardTurnRequestV1 = fixedCodec(65_536, encodeRequest, decodeRequest)
export const blindForwardHttpsOriginForwardTurnResultV1 = fixedCodec(65_536, encodeResult, decodeResult)

function exactRequestBytes (value) {
  return value && typeof value === 'object' && typeof value.byteLength !== 'number'
    ? encodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, value)
    : asBytes(value, 65_536, 'request body')
}

function exactResultBytes (value) {
  return value && typeof value === 'object' && typeof value.byteLength !== 'number'
    ? encodeCanonical(blindForwardHttpsOriginForwardTurnResultV1, value)
    : asBytes(value, 65_536, 'result body')
}

export function forwardHttpsOriginOrForwardedRequestCommitmentV1 (requestOrBytes) {
  const encoded = exactRequestBytes(requestOrBytes)
  return blake2b256(b4a.concat([b4a.from(FORWARD_HTTPS_DOMAIN_V3.REQUEST.exactAsciiBytes, 'ascii'), encoded]))
}

export function forwardHttpsOriginRequestCommitmentV1 (requestOrBytes) {
  const encoded = exactRequestBytes(requestOrBytes)
  if (encoded[7] !== FORWARD_HTTPS_REQUEST_ROLE_V1.ORIGIN_TEMPLATE) fail('origin commitment requires an origin request')
  return forwardHttpsOriginOrForwardedRequestCommitmentV1(encoded)
}

export function forwardHttpsForwardedRequestCommitmentV1 (requestOrBytes) {
  const encoded = exactRequestBytes(requestOrBytes)
  if (encoded[7] !== FORWARD_HTTPS_REQUEST_ROLE_V1.FORWARDED) fail('forwarded commitment requires a forwarded request')
  return forwardHttpsOriginOrForwardedRequestCommitmentV1(encoded)
}

export function forwardHttpsParentCapabilityPrefixHashV1 (parentCapability) {
  return blake2b256(capabilityPrefixBytes(parentCapability))
}

export function forwardHttpsCapabilityPrefixHashV1 (originOrBytes) {
  const encoded = exactRequestBytes(originOrBytes)
  const origin = decodeRequest(encoded)
  if (origin.requestRole !== FORWARD_HTTPS_REQUEST_ROLE_V1.ORIGIN_TEMPLATE) fail('capability prefix hash requires an origin request')
  const hash = forwardHttpsParentCapabilityPrefixHashV1(origin.parentCapability)
  if (!b4a.equals(hash, blake2b256(encoded.subarray(146, 440)))) fail('origin capability prefix hash is inconsistent')
  return hash
}

export function forwardHttpsSourceTransformSignaturePayloadV1 (requestOrBytes) {
  const encoded = exactRequestBytes(requestOrBytes)
  if (encoded[7] !== FORWARD_HTTPS_REQUEST_ROLE_V1.FORWARDED) fail('source transform signature requires a forwarded request')
  const unsigned = b4a.concat([encoded.subarray(0, 600), encoded.subarray(664)])
  if (unsigned.byteLength !== FORWARD_HTTPS_V3_LIMITS.SOURCE_TRANSFORM_UNSIGNED_BYTES) fail('source transform unsigned length mismatch')
  return signaturePayload(FORWARD_HTTPS_DOMAIN_V3.SOURCE_TRANSFORM, unsigned)
}

export function forwardHttpsResultSignaturePayloadV1 (resultOrBytes) {
  const encoded = exactResultBytes(resultOrBytes)
  const role = encoded[7]
  const unsigned = b4a.concat([encoded.subarray(0, 705), encoded.subarray(769)])
  if (unsigned.byteLength !== FORWARD_HTTPS_V3_LIMITS.RESULT_UNSIGNED_BYTES) fail('result unsigned length mismatch')
  return signaturePayload(resultDomain(role), unsigned)
}

export function forwardHttpsTargetResultChainHashV1 (resultOrBytes) {
  const encoded = exactResultBytes(resultOrBytes)
  if (encoded[7] !== FORWARD_HTTPS_RESULT_ROLE_V1.TARGET_RESULT) fail('only a TARGET_RESULT may advance the result chain')
  return blake2b256(b4a.concat([b4a.from(FORWARD_HTTPS_DOMAIN_V3.TARGET_RESULT_CHAIN.exactAsciiBytes, 'ascii'), encoded]))
}

export const FORWARD_HTTPS_TLS_EXPORTER_LABEL_V1 = 'EXPORTER-HiveRelay-Blind-Forward-Origin-v1'

export function forwardHttpsTlsExporterContextV1 (stableSessionId, sequence, originRequestCommitment) {
  return blake2b256(b4a.concat([
    b4a.from(FORWARD_HTTPS_DOMAIN_V3.TLS_EXPORTER_CONTEXT.exactAsciiBytes, 'ascii'),
    asBytes(stableSessionId, 32, 'stableSessionId', true),
    (() => {
      const encoded = b4a.alloc(8)
      writeU64(encoded, sequence, 0, 'sequence')
      return encoded
    })(),
    asBytes(originRequestCommitment, 32, 'originRequestCommitment', true)
  ]))
}

export function forwardHttpsTlsExporterBindingHashV1 (exporterSecret, context) {
  exporterSecret = asBytes(exporterSecret, 32, 'TLS exporter secret', true)
  context = asBytes(context, 32, 'TLS exporter context', true)
  return blake2b256(b4a.concat([
    b4a.from(FORWARD_HTTPS_DOMAIN_V3.TLS_EXPORTER_BINDING.exactAsciiBytes, 'ascii'),
    length64(64),
    exporterSecret,
    context
  ]))
}

export function assertForwardHttpsSourceTransformationV1 (originOrBytes, forwardedOrBytes) {
  const origin = exactRequestBytes(originOrBytes)
  const forwarded = exactRequestBytes(forwardedOrBytes)
  if (origin[7] !== 0 || forwarded[7] !== 1) fail('transformation roles must be origin then forwarded')
  const mutable = new Set([7])
  for (let i = 440; i < 664; i++) mutable.add(i)
  for (let i = 0; i < origin.byteLength; i++) {
    if (!mutable.has(i) && origin[i] !== forwarded[i]) fail(`source transform changed forbidden byte ${i}`)
  }
  const decodedOrigin = decodeRequest(origin)
  const decodedForwarded = decodeRequest(forwarded)
  if (!b4a.equals(decodedForwarded.originRequestCommitment, forwardHttpsOriginRequestCommitmentV1(origin))) {
    fail('forwarded request does not contain the exact origin commitment')
  }
  if (!b4a.equals(decodedOrigin.stableSessionId, decodedForwarded.stableSessionId) || decodedOrigin.sequence !== decodedForwarded.sequence) {
    fail('source transform changed stable session or sequence')
  }
  return true
}

export function createForwardHttpsForwardedRequestV1 (originOrBytes, finalizedCapability, tlsExporterBindingHash, sourceSecretKey) {
  const originBytes = exactRequestBytes(originOrBytes)
  const origin = decodeRequest(originBytes)
  if (origin.requestRole !== FORWARD_HTTPS_REQUEST_ROLE_V1.ORIGIN_TEMPLATE) fail('source transform requires an origin request')
  finalizedCapability = { ...finalizedCapability }
  const binding = asBytes(tlsExporterBindingHash, 32, 'tlsExporterBindingHash', true)
  if (!b4a.equals(asBytes(finalizedCapability.tlsExporterBindingHash, 32, 'capability exporter'), binding)) {
    fail('finalized capability exporter does not equal selected TLS binding')
  }
  const forwarded = {
    ...origin,
    requestRole: FORWARD_HTTPS_REQUEST_ROLE_V1.FORWARDED,
    parentCapability: finalizedCapability,
    turnTlsExporterBindingHash: binding,
    originRequestCommitment: forwardHttpsOriginRequestCommitmentV1(originBytes),
    sourceTransformSignature: b4a.alloc(64),
    padding: origin.padding
  }
  // The structural encoder requires a nonzero signature; use a deterministic placeholder only for payload construction.
  forwarded.sourceTransformSignature = b4a.alloc(64, 1)
  const provisional = encodeRequest(forwarded)
  const signature = b4a.alloc(64)
  sodium.crypto_sign_detached(signature, forwardHttpsSourceTransformSignaturePayloadV1(provisional), asBytes(sourceSecretKey, 64, 'sourceSecretKey', true))
  forwarded.sourceTransformSignature = signature
  const encoded = encodeRequest(forwarded)
  assertForwardHttpsSourceTransformationV1(originBytes, encoded)
  return encoded
}

export function verifyForwardHttpsParentCapabilitySignatureV1 (capability) {
  capabilityFields(capability, FORWARD_HTTPS_REQUEST_ROLE_V1.FORWARDED)
  return sodium.crypto_sign_verify_detached(
    capability.signature,
    forwardHttpsParentCapabilitySignaturePayloadV1(capability),
    capability.sourceRelayPublicKey
  )
}

export function verifyForwardHttpsSourceTransformSignatureV1 (requestOrBytes) {
  const encoded = exactRequestBytes(requestOrBytes)
  const request = decodeRequest(encoded)
  if (request.requestRole !== FORWARD_HTTPS_REQUEST_ROLE_V1.FORWARDED) return false
  return sodium.crypto_sign_verify_detached(
    request.sourceTransformSignature,
    forwardHttpsSourceTransformSignaturePayloadV1(encoded),
    request.parentCapability.sourceRelayPublicKey
  )
}

export function verifyForwardHttpsResultSignatureV1 (resultOrBytes) {
  const encoded = exactResultBytes(resultOrBytes)
  const result = decodeResult(encoded)
  return sodium.crypto_sign_verify_detached(
    result.resultSignature,
    forwardHttpsResultSignaturePayloadV1(encoded),
    result.signerPublicKey
  )
}

function assertForwardHttpsResultBindsForwardedRequestV1 (forwardedBytes, resultBytes, requiredRole = null) {
  const forwarded = decodeRequest(forwardedBytes)
  const result = decodeResult(resultBytes)
  if (forwarded.requestRole !== FORWARD_HTTPS_REQUEST_ROLE_V1.FORWARDED) fail('result binding requires a forwarded request')
  if (requiredRole != null && result.resultRole !== requiredRole) fail('result role is not authorized for this binding')
  if (!b4a.equals(result.stableSessionId, forwarded.stableSessionId) || result.sequence !== forwarded.sequence ||
      result.requestKind !== forwarded.requestKind || !b4a.equals(result.previousTargetResultHash, forwarded.previousTargetResultHash) ||
      !b4a.equals(result.originRequestCommitment, forwarded.originRequestCommitment) ||
      !b4a.equals(result.forwardedRequestCommitment, forwardHttpsForwardedRequestCommitmentV1(forwardedBytes)) ||
      !b4a.equals(encodeForwardHttpsParentCapabilitySlotV1(result.finalizedParentCapability, 1), encodeForwardHttpsParentCapabilitySlotV1(forwarded.parentCapability, 1)) ||
      !b4a.equals(result.turnTlsExporterBindingHash, forwarded.turnTlsExporterBindingHash) ||
      !b4a.equals(result.sourceTransformSignature, forwarded.sourceTransformSignature)) {
    fail('result provenance does not bind the exact forwarded request')
  }
  if (!verifyForwardHttpsParentCapabilitySignatureV1(forwarded.parentCapability)) fail('parent capability signature is invalid')
  if (!verifyForwardHttpsSourceTransformSignatureV1(forwardedBytes)) fail('source transform signature is invalid')
  if (!verifyForwardHttpsResultSignatureV1(resultBytes)) fail('result signature is invalid')
  return { forwarded, result }
}

export function assertForwardHttpsForwardedRequestAuthorityV1 (forwardedOrBytes) {
  const requestBytes = exactRequestBytes(forwardedOrBytes)
  const request = decodeRequest(requestBytes)
  if (request.requestRole !== FORWARD_HTTPS_REQUEST_ROLE_V1.FORWARDED) fail('forwarded authority requires role FORWARDED')
  if (!verifyForwardHttpsParentCapabilitySignatureV1(request.parentCapability)) fail('parent capability signature is invalid')
  if (!verifyForwardHttpsSourceTransformSignatureV1(requestBytes)) fail('source transform signature is invalid')
  return Object.freeze({
    request,
    requestBytes: b4a.from(requestBytes),
    forwardedRequestCommitment: forwardHttpsForwardedRequestCommitmentV1(requestBytes)
  })
}

export function assertForwardHttpsTargetResultForForwardedRequestV1 (forwardedOrBytes, resultOrBytes) {
  const requestBytes = exactRequestBytes(forwardedOrBytes)
  const resultBytes = exactResultBytes(resultOrBytes)
  const { forwarded: request, result } = assertForwardHttpsResultBindsForwardedRequestV1(
    requestBytes,
    resultBytes,
    FORWARD_HTTPS_RESULT_ROLE_V1.TARGET_RESULT
  )
  return Object.freeze({
    request,
    result,
    requestBytes: b4a.from(requestBytes),
    resultBytes: b4a.from(resultBytes),
    forwardedRequestCommitment: forwardHttpsForwardedRequestCommitmentV1(requestBytes),
    targetResultChainHash: forwardHttpsTargetResultChainHashV1(resultBytes)
  })
}

export function assertForwardHttpsResultForRequestV1 (originOrBytes, forwardedOrBytes, resultOrBytes) {
  const originBytes = exactRequestBytes(originOrBytes)
  const forwardedBytes = exactRequestBytes(forwardedOrBytes)
  const resultBytes = exactResultBytes(resultOrBytes)
  assertForwardHttpsSourceTransformationV1(originBytes, forwardedBytes)
  const origin = decodeRequest(originBytes)
  const { result } = assertForwardHttpsResultBindsForwardedRequestV1(forwardedBytes, resultBytes)
  if (!b4a.equals(result.stableSessionId, origin.stableSessionId) || result.sequence !== origin.sequence ||
      result.requestKind !== origin.requestKind || !b4a.equals(result.previousTargetResultHash, origin.previousTargetResultHash) ||
      !b4a.equals(result.originRequestCommitment, forwardHttpsOriginRequestCommitmentV1(originBytes))) {
    fail('result provenance does not bind the exact origin and forwarded request')
  }
  return result
}

export function assertForwardHttpsResultForOriginRequestV1 (originOrBytes, resultOrBytes) {
  const originBytes = exactRequestBytes(originOrBytes)
  const resultBytes = exactResultBytes(resultOrBytes)
  const origin = decodeRequest(originBytes)
  const result = decodeResult(resultBytes)
  if (origin.requestRole !== FORWARD_HTTPS_REQUEST_ROLE_V1.ORIGIN_TEMPLATE) fail('origin result assertion requires role ORIGIN_TEMPLATE')
  const forwardedBytes = encodeRequest({
    ...origin,
    requestRole: FORWARD_HTTPS_REQUEST_ROLE_V1.FORWARDED,
    parentCapability: result.finalizedParentCapability,
    turnTlsExporterBindingHash: result.turnTlsExporterBindingHash,
    originRequestCommitment: result.originRequestCommitment,
    sourceTransformSignature: result.sourceTransformSignature
  })
  const verified = assertForwardHttpsResultForRequestV1(originBytes, forwardedBytes, resultBytes)
  const target = verified.resultRole === FORWARD_HTTPS_RESULT_ROLE_V1.TARGET_RESULT
  return Object.freeze({
    origin,
    forwarded: decodeRequest(forwardedBytes),
    result: verified,
    originBytes: b4a.from(originBytes),
    forwardedBytes: b4a.from(forwardedBytes),
    resultBytes: b4a.from(resultBytes),
    targetResultChainHash: target ? forwardHttpsTargetResultChainHashV1(resultBytes) : null,
    normalClose: target && origin.requestKind === FORWARD_HTTPS_REQUEST_KIND_V1.CLOSE,
    targetFin: target && verified.responseKind === FORWARD_HTTPS_RESPONSE_KIND_V1.CLOSE
  })
}

export class ForwardHttpsTransportBudgetV1 {
  #limit
  #reserved

  constructor (limit = FORWARD_HTTPS_V3_LIMITS.TRANSPORT_BUDGET_BYTES) {
    this.#limit = unsigned(limit, Number.MAX_SAFE_INTEGER, 'transport budget limit')
    this.#reserved = 0
  }

  get limit () { return this.#limit }
  get reserved () { return this.#reserved }

  reserveExchange () {
    const next = this.#reserved + FORWARD_HTTPS_V3_LIMITS.TRANSPORT_EXCHANGE_BYTES
    if (next > this.#limit) fail('independent transport budget exhausted', 'FORWARD_HTTPS_BUDGET_EXHAUSTED')
    this.#reserved = next
    return this.#reserved
  }
}

export class ForwardHttpsDefinitiveResultCacheV1 {
  #relayRole
  #budget
  #records
  #terminal
  #terminalReason
  #lastNowEpoch

  constructor (relayRole, budget = new ForwardHttpsTransportBudgetV1()) {
    if (relayRole !== 'SOURCE' && relayRole !== 'TARGET') fail('cache relayRole must be SOURCE or TARGET')
    this.#relayRole = relayRole
    this.#budget = budget
    this.#records = new Map()
    this.#terminal = false
    this.#terminalReason = null
    this.#lastNowEpoch = 0
  }

  get relayRole () { return this.#relayRole }
  get budget () { return this.#budget }
  get terminal () { return this.#terminal }
  get terminalReason () { return this.#terminalReason }
  get recordCount () { return this.#records.size }

  persist (requestOrBytes, resultOrBytes) {
    this.#assertActive()
    const candidate = this.#candidate(requestOrBytes)
    const resultBytes = exactResultBytes(resultOrBytes)
    const existing = this.#records.get(candidate.key)
    let verified
    try {
      verified = this.#relayRole === 'SOURCE'
        ? assertForwardHttpsResultForOriginRequestV1(candidate.requestBytes, resultBytes)
        : assertForwardHttpsTargetResultForForwardedRequestV1(candidate.requestBytes, resultBytes)
      if (verified.result.resultRole !== FORWARD_HTTPS_RESULT_ROLE_V1.TARGET_RESULT) fail('definitive cache accepts only TARGET_RESULT')
    } catch (error) {
      if (existing) return this.#terminate('definitive result cache remint or request conflict')
      throw error
    }
    const expiresAtEpoch = unsigned(verified.result.finalizedParentCapability.expiresAtEpoch, 0xffffffff, 'expiresAtEpoch')
    if (existing) {
      if (!b4a.equals(existing.requestBytes, candidate.requestBytes) ||
          !b4a.equals(existing.resultBytes, resultBytes) || existing.expiresAtEpoch !== expiresAtEpoch) {
        return this.#terminate('definitive result cache remint or request conflict')
      }
      return b4a.from(existing.resultBytes)
    }
    this.#records.set(candidate.key, {
      requestBytes: b4a.from(candidate.requestBytes),
      resultBytes: b4a.from(resultBytes),
      expiresAtEpoch
    })
    return b4a.from(resultBytes)
  }

  lookup (requestOrBytes, nowEpoch) {
    this.#assertActive()
    const candidate = this.#candidate(requestOrBytes)
    nowEpoch = unsigned(nowEpoch, 0xffffffff, 'nowEpoch')
    const record = this.#records.get(candidate.key)
    if (!record || !b4a.equals(record.requestBytes, candidate.requestBytes)) return this.#terminate('definitive result cache authentication failed')
    if (nowEpoch > this.#lastNowEpoch) this.#lastNowEpoch = nowEpoch
    if (this.#lastNowEpoch > record.expiresAtEpoch + 900) {
      return this.#terminate('definitive target result recovery grace expired', 'FORWARD_HTTPS_RECOVERY_GRACE_EXPIRED')
    }
    try {
      this.#budget.reserveExchange()
    } catch (error) {
      if (error && error.code === 'FORWARD_HTTPS_BUDGET_EXHAUSTED') {
        this.#terminal = true
        this.#terminalReason = error.code
      }
      throw error
    }
    return b4a.from(record.resultBytes)
  }

  inspectRecord (requestOrBytes) {
    const candidate = this.#candidate(requestOrBytes)
    const record = this.#records.get(candidate.key)
    if (!record || !b4a.equals(record.requestBytes, candidate.requestBytes)) return null
    return Object.freeze({
      requestBytes: b4a.from(record.requestBytes),
      resultBytes: b4a.from(record.resultBytes),
      expiresAtEpoch: record.expiresAtEpoch
    })
  }

  #candidate (requestOrBytes) {
    const requestBytes = exactRequestBytes(requestOrBytes)
    const request = decodeRequest(requestBytes)
    const expectedRole = this.#relayRole === 'SOURCE'
      ? FORWARD_HTTPS_REQUEST_ROLE_V1.ORIGIN_TEMPLATE
      : FORWARD_HTTPS_REQUEST_ROLE_V1.FORWARDED
    if (request.requestRole !== expectedRole) fail(`definitive ${this.#relayRole} cache request role is invalid`)
    if (this.#relayRole === 'TARGET') assertForwardHttpsForwardedRequestAuthorityV1(requestBytes)
    return {
      requestBytes,
      request,
      key: `${this.#relayRole}:${b4a.toString(request.stableSessionId, 'hex')}:${request.sequence}`
    }
  }

  #assertActive () {
    if (this.#terminal) fail('definitive result cache is terminal', this.#terminalReason)
  }

  #terminate (message, reason = 'TERMINAL_FORWARD_HTTPS_CACHE') {
    if (!this.#terminal) {
      this.#terminal = true
      this.#terminalReason = reason
    }
    fail(message, this.#terminalReason)
  }
}

export class ForwardHttpsOriginSessionContractV1 {
  #stableSessionId
  #nextSequence
  #previousTargetResultHash
  #outstanding
  #completed
  #terminal
  #terminalReason
  #closed
  #targetFin
  #budget
  #lastNowEpoch

  constructor (stableSessionId, options = {}) {
    this.#stableSessionId = b4a.from(asBytes(stableSessionId, 32, 'stableSessionId', true))
    this.#nextSequence = 0n
    this.#previousTargetResultHash = b4a.alloc(32)
    this.#outstanding = null
    this.#completed = new Map()
    this.#terminal = false
    this.#terminalReason = null
    this.#closed = false
    this.#targetFin = false
    this.#budget = options.budget || new ForwardHttpsTransportBudgetV1()
    this.#lastNowEpoch = 0
  }

  get stableSessionId () { return b4a.from(this.#stableSessionId) }
  get nextSequence () { return this.#nextSequence }
  get previousTargetResultHash () { return b4a.from(this.#previousTargetResultHash) }
  get terminal () { return this.#terminal }
  get terminalReason () { return this.#terminalReason }
  get closed () { return this.#closed }
  get targetFin () { return this.#targetFin }
  get budget () { return this.#budget }
  get completedCount () { return this.#completed.size }
  get outstanding () {
    if (!this.#outstanding) return null
    return Object.freeze({
      originBytes: b4a.from(this.#outstanding.originBytes),
      forwardedBytes: this.#outstanding.forwardedBytes && b4a.from(this.#outstanding.forwardedBytes),
      request: decodeRequest(this.#outstanding.originBytes)
    })
  }

  acceptOrigin (originOrBytes, options = {}) {
    this.#assertActive()
    const bytes = exactRequestBytes(originOrBytes)
    const request = decodeRequest(bytes)
    if (request.requestRole !== 0 || !b4a.equals(request.stableSessionId, this.#stableSessionId)) return this.#terminate('origin session binding is invalid')
    const cached = this.#completed.get(request.sequence.toString())
    if (cached) {
      if (b4a.equals(cached.originBytes, bytes)) {
        const nowEpoch = options.nowEpoch == null ? cached.expiresAtEpoch : unsigned(options.nowEpoch, 0xffffffff, 'nowEpoch')
        if (nowEpoch > this.#lastNowEpoch) this.#lastNowEpoch = nowEpoch
        if (this.#lastNowEpoch > cached.expiresAtEpoch + 900) return this.#terminate('definitive target result recovery grace expired', 'FORWARD_HTTPS_RECOVERY_GRACE_EXPIRED')
        this.#reserveExchange()
        return Object.freeze({ disposition: 'CACHED_TARGET_RESULT', resultBytes: b4a.from(cached.resultBytes), request })
      }
      return this.#terminate('changed bytes replay a completed sequence')
    }
    if (this.#closed) return this.#terminate('session is closed')
    const nowEpoch = options.nowEpoch == null ? request.parentCapability.issuedAtEpoch : unsigned(options.nowEpoch, 0xffffffff, 'nowEpoch')
    if (nowEpoch > this.#lastNowEpoch) this.#lastNowEpoch = nowEpoch
    if (this.#outstanding) {
      if (b4a.equals(this.#outstanding.originBytes, bytes)) {
        this.#reserveExchange()
        return Object.freeze({ disposition: 'EXACT_RETRY', request })
      }
      return this.#terminate('changed bytes reuse the outstanding sequence')
    }
    if (this.#lastNowEpoch > request.parentCapability.expiresAtEpoch) return this.#terminate('live parent capability expired before new dispatch')
    if (request.sequence !== this.#nextSequence || !b4a.equals(request.previousTargetResultHash, this.#previousTargetResultHash)) {
      return this.#terminate('origin sequence or target result chain is invalid')
    }
    if (request.requestKind === FORWARD_HTTPS_REQUEST_KIND_V1.OPEN && request.sequence !== 0n) return this.#terminate('OPEN may occur only once at sequence zero')
    if (request.requestKind !== FORWARD_HTTPS_REQUEST_KIND_V1.OPEN && request.sequence === 0n) return this.#terminate('sequence zero must be OPEN')
    this.#reserveExchange()
    this.#outstanding = { originBytes: b4a.from(bytes), forwardedBytes: null, request }
    return Object.freeze({ disposition: 'ACCEPTED', request })
  }

  recordForwarded (forwardedOrBytes) {
    this.#assertActive()
    if (this.#closed) return this.#terminate('session is closed')
    if (!this.#outstanding) return this.#terminate('forwarded request has no outstanding origin')
    const forwardedBytes = exactRequestBytes(forwardedOrBytes)
    try {
      assertForwardHttpsSourceTransformationV1(this.#outstanding.originBytes, forwardedBytes)
      assertForwardHttpsForwardedRequestAuthorityV1(forwardedBytes)
    } catch {
      return this.#terminate('forwarded request authority or transformation is invalid')
    }
    if (this.#outstanding.forwardedBytes && !b4a.equals(this.#outstanding.forwardedBytes, forwardedBytes)) {
      return this.#terminate('retry attempted to remint forwarded bytes')
    }
    this.#outstanding.forwardedBytes = b4a.from(forwardedBytes)
    return Object.freeze({ disposition: 'PREPARED', forwardedBytes: b4a.from(forwardedBytes) })
  }

  complete (resultOrBytes) {
    this.#assertActive()
    if (this.#closed) return this.#terminate('session is closed')
    if (!this.#outstanding || !this.#outstanding.forwardedBytes) return this.#terminate('result has no prepared forwarded request')
    const resultBytes = exactResultBytes(resultOrBytes)
    let result
    try {
      result = assertForwardHttpsResultForRequestV1(
        this.#outstanding.originBytes,
        this.#outstanding.forwardedBytes,
        resultBytes
      )
    } catch {
      return this.#terminate('result provenance is invalid')
    }
    if (result.resultRole !== FORWARD_HTTPS_RESULT_ROLE_V1.TARGET_RESULT) {
      return Object.freeze({ disposition: result.resultRole === 2 ? 'NONDEFINITIVE_PRE_FORWARD_ERROR' : 'NONDEFINITIVE_POST_FORWARD_AMBIGUOUS', result })
    }
    this.#completed.set(result.sequence.toString(), {
      originBytes: b4a.from(this.#outstanding.originBytes),
      resultBytes: b4a.from(resultBytes),
      expiresAtEpoch: this.#outstanding.request.parentCapability.expiresAtEpoch
    })
    this.#previousTargetResultHash = forwardHttpsTargetResultChainHashV1(resultBytes)
    this.#nextSequence++
    const requestKind = this.#outstanding.request.requestKind
    this.#outstanding = null
    if (result.responseKind === FORWARD_HTTPS_RESPONSE_KIND_V1.CLOSE) this.#targetFin = true
    if (requestKind === FORWARD_HTTPS_REQUEST_KIND_V1.CLOSE) this.#closed = true
    return Object.freeze({ disposition: 'DEFINITIVE_TARGET_RESULT', result })
  }

  inspectCompleted (sequence) {
    const record = this.#completed.get(u64(sequence, 'sequence').toString())
    if (!record) return null
    return Object.freeze({
      originBytes: b4a.from(record.originBytes),
      resultBytes: b4a.from(record.resultBytes),
      expiresAtEpoch: record.expiresAtEpoch
    })
  }

  #assertActive () {
    if (this.#terminal) fail('session is terminal', this.#terminalReason)
  }

  #terminate (message, reason = 'TERMINAL_FORWARD_HTTPS_SESSION') {
    if (!this.#terminal) {
      this.#terminal = true
      this.#terminalReason = reason
    }
    fail(message, this.#terminalReason)
  }

  #reserveExchange () {
    try {
      return this.#budget.reserveExchange()
    } catch (error) {
      if (error && error.code === 'FORWARD_HTTPS_BUDGET_EXHAUSTED') {
        this.#terminal = true
        this.#terminalReason = error.code
      }
      throw error
    }
  }
}

export function assertForwardHttpsV2UnselectableV3 (schemaId) {
  if (schemaId === 74 || schemaId === 75) fail('WIRE v2 IDs 74 and 75 are frozen and unselectable', 'WIRE_V2_FORWARD_UNSELECTABLE')
  if (schemaId !== 76 && schemaId !== 77) fail('schema is not a WIRE v3 direct-HTTPS successor')
  return true
}
