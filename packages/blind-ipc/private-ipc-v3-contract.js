import b4a from 'b4a'
import c from 'compact-encoding'
import {
  decodeForwardHttpsParentCapabilityV1,
  encodeForwardHttpsParentCapabilityV1,
  forwardHttpsSessionIdV1,
  blindForwardHttpsTurnRequestV1,
  blindForwardHttpsTurnResultV1
} from '@hiverelay/blind-protocol'
import { decodeCanonical } from '@hiverelay/blind-protocol/codec'
import { privateBlake2b256 } from './private-hashes.js'

const MAX_U64 = (1n << 64n) - 1n
const FORMAT_DOMAIN = b4a.from('hiverelay.blind.private-ipc-format-hash.v3', 'ascii')
const VECTOR_DOMAIN = b4a.from('hiverelay.blind.private-ipc-vector-set-hash.v3', 'ascii')
const BINDING_MAGIC = b4a.from('LFE3', 'ascii')
const CAPABILITY_MAGIC = b4a.from('LFC3', 'ascii')
const TURN_MAGIC = b4a.from('LFT3', 'ascii')

export const PRIVATE_IPC_V3_MAGIC = 'hiverelay-blind-private-ipc-v3'
export const PRIVATE_IPC_V3_FORMAT_VERSION = 3

export const PRIVATE_IPC_V3_SCHEMA = Object.freeze({
  LocalForwardHttpsExporterBindingV3: 13,
  LocalForwardHttpsParentCapabilityV3: 14,
  LocalForwardHttpsTurnV3: 15
})

export const LOCAL_FORWARD_HTTPS_DIRECTION_V3 = Object.freeze({
  REQUEST: 1,
  RESULT: 2
})

export const PRIVATE_IPC_V3_LIMITS = Object.freeze({
  EXPORTER_BINDING_BYTES: 336,
  PARENT_CAPABILITY_BYTES: 427,
  TURN_HEADER_BYTES: 48,
  TURN_BODY_BYTES: 65_536,
  TURN_BYTES: 65_584
})

export const PRIVATE_IPC_V3_ADDITIONAL_SCHEMAS = Object.freeze([
  Object.freeze({
    schemaId: 13,
    schemaName: 'LocalForwardHttpsExporterBindingV3',
    fields: Object.freeze([
      'magic:fixed4=LFE3', 'version:u8=3', 'authorityKind:u8=TLS_EXPORTER_BINDING_HASH_BY_PEERCRED_EDGE',
      'releaseProfileId:u8=2', 'routeKind:u8=7',
      'edgeProcessNonce:fixed32[nonzero]', 'localChannelNonce:fixed32[nonzero]',
      'tlsExporterBindingHash:fixed32[nonzero;never-raw-exporter]',
      'sourceRelayPublicKey:fixed32[nonzero]', 'sourceDescriptorSequence:u64be', 'sourceDescriptorHash:fixed32[nonzero]',
      'targetCatalogEntryId:fixed32[nonzero]', 'targetRelayPublicKey:fixed32[nonzero;different-source]',
      'targetDescriptorSequence:u64be', 'targetDescriptorHash:fixed32[nonzero]',
      'routeId:fixed16[nonzero]', 'circuitNonce:fixed32[nonzero]',
      'issuedAtEpoch:u32be', 'expiresAtEpoch:u32be=issued+600',
      'no-url-host-ip-dial-fields', 'exactBytes:336'
    ])
  }),
  Object.freeze({
    schemaId: 14,
    schemaName: 'LocalForwardHttpsParentCapabilityV3',
    fields: Object.freeze([
      'magic:fixed4=LFC3', 'version:u8=3', 'sessionId:fixed32[nonzero]',
      'parentCapability:BlindForwardHttpsParentCapabilityV1[exact390]',
      'sessionId=BLAKE2b256(aux-domain||parentCapability)', 'exactBytes:427'
    ])
  }),
  Object.freeze({
    schemaId: 15,
    schemaName: 'LocalForwardHttpsTurnV3',
    fields: Object.freeze([
      'magic:fixed4=LFT3', 'version:u8=3', 'direction:u8[REQUEST=1|RESULT=2]', 'flags:u8=0', 'reserved:u8=0',
      'sessionId:fixed32[nonzero]', 'sequence:u64be',
      'body:closed(direction){REQUEST:BlindForwardHttpsTurnRequestV1|RESULT:BlindForwardHttpsTurnResultV1}[exact65536]',
      'sessionId+sequence=body', 'exactBytes:65584'
    ])
  })
])

function fail (message, code = 'BAD_PRIVATE_IPC_V3_CONTRACT') {
  const error = new Error(message)
  error.code = code
  throw error
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

function u32 (value, field) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) fail(`${field} is outside u32`)
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

function put (output, value, offset) {
  b4a.copy(value, output, offset)
  return offset + value.byteLength
}

function take (input, offset, length) {
  return b4a.from(input.subarray(offset, offset + length))
}

function writeU32 (output, value, offset, field) {
  value = u32(value, field)
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

function validateExporterBinding (value) {
  if (!value || typeof value !== 'object') fail('exporter binding must be an object')
  for (const forbidden of ['tlsExporter', 'url', 'host', 'hostname', 'ip', 'ipAddress', 'dialAddress']) {
    if (forbidden in value) fail(`${forbidden} is forbidden in exporter binding IPC`)
  }
  if (value.version !== 3 || value.authorityKind !== 1 || value.releaseProfileId !== 2 || value.routeKind !== 7) {
    fail('exporter binding fixed header is invalid')
  }
  for (const field of [
    'edgeProcessNonce', 'localChannelNonce', 'tlsExporterBindingHash', 'sourceRelayPublicKey',
    'sourceDescriptorHash', 'targetCatalogEntryId', 'targetRelayPublicKey', 'targetDescriptorHash', 'circuitNonce'
  ]) bytes(value[field], 32, field, true)
  bytes(value.routeId, 16, 'routeId', true)
  u64(value.sourceDescriptorSequence, 'sourceDescriptorSequence')
  u64(value.targetDescriptorSequence, 'targetDescriptorSequence')
  if (b4a.equals(value.sourceRelayPublicKey, value.targetRelayPublicKey)) fail('source and target relay keys must differ')
  u32(value.issuedAtEpoch, 'issuedAtEpoch')
  u32(value.expiresAtEpoch, 'expiresAtEpoch')
  if (value.expiresAtEpoch !== value.issuedAtEpoch + 600) fail('exporter binding lifetime must be exactly 600 seconds')
}

export function encodeLocalForwardHttpsExporterBindingV3 (value) {
  validateExporterBinding(value)
  const output = b4a.alloc(PRIVATE_IPC_V3_LIMITS.EXPORTER_BINDING_BYTES)
  let offset = put(output, BINDING_MAGIC, 0)
  output[offset++] = 3
  output[offset++] = 1
  output[offset++] = 2
  output[offset++] = 7
  offset = put(output, value.edgeProcessNonce, offset)
  offset = put(output, value.localChannelNonce, offset)
  offset = put(output, value.tlsExporterBindingHash, offset)
  offset = put(output, value.sourceRelayPublicKey, offset)
  offset = writeU64(output, value.sourceDescriptorSequence, offset, 'sourceDescriptorSequence')
  offset = put(output, value.sourceDescriptorHash, offset)
  offset = put(output, value.targetCatalogEntryId, offset)
  offset = put(output, value.targetRelayPublicKey, offset)
  offset = writeU64(output, value.targetDescriptorSequence, offset, 'targetDescriptorSequence')
  offset = put(output, value.targetDescriptorHash, offset)
  offset = put(output, value.routeId, offset)
  offset = put(output, value.circuitNonce, offset)
  offset = writeU32(output, value.issuedAtEpoch, offset, 'issuedAtEpoch')
  offset = writeU32(output, value.expiresAtEpoch, offset, 'expiresAtEpoch')
  if (offset !== output.byteLength) fail('exporter binding encoder length mismatch')
  return output
}

export function decodeLocalForwardHttpsExporterBindingV3 (input) {
  input = bytes(input, PRIVATE_IPC_V3_LIMITS.EXPORTER_BINDING_BYTES, 'exporter binding')
  if (!b4a.equals(input.subarray(0, 4), BINDING_MAGIC)) fail('exporter binding magic is invalid')
  let offset = 4
  const value = {
    version: input[offset++],
    authorityKind: input[offset++],
    releaseProfileId: input[offset++],
    routeKind: input[offset++],
    edgeProcessNonce: take(input, offset, 32)
  }
  offset += 32
  value.localChannelNonce = take(input, offset, 32); offset += 32
  value.tlsExporterBindingHash = take(input, offset, 32); offset += 32
  value.sourceRelayPublicKey = take(input, offset, 32); offset += 32
  value.sourceDescriptorSequence = readU64(input, offset); offset += 8
  value.sourceDescriptorHash = take(input, offset, 32); offset += 32
  value.targetCatalogEntryId = take(input, offset, 32); offset += 32
  value.targetRelayPublicKey = take(input, offset, 32); offset += 32
  value.targetDescriptorSequence = readU64(input, offset); offset += 8
  value.targetDescriptorHash = take(input, offset, 32); offset += 32
  value.routeId = take(input, offset, 16); offset += 16
  value.circuitNonce = take(input, offset, 32); offset += 32
  value.issuedAtEpoch = readU32(input, offset); offset += 4
  value.expiresAtEpoch = readU32(input, offset); offset += 4
  if (offset !== input.byteLength) fail('exporter binding decoder length mismatch')
  validateExporterBinding(value)
  if (!b4a.equals(encodeLocalForwardHttpsExporterBindingV3(value), input)) fail('exporter binding is not canonical')
  return value
}

export function encodeLocalForwardHttpsParentCapabilityV3 (value) {
  if (!value || typeof value !== 'object' || value.version !== 3) fail('parent capability IPC fixed header is invalid')
  const capability = encodeForwardHttpsParentCapabilityV1(value.parentCapability)
  const sessionId = bytes(value.sessionId, 32, 'sessionId', true)
  if (!b4a.equals(sessionId, forwardHttpsSessionIdV1(value.parentCapability))) fail('sessionId does not bind parentCapability')
  const output = b4a.alloc(PRIVATE_IPC_V3_LIMITS.PARENT_CAPABILITY_BYTES)
  let offset = put(output, CAPABILITY_MAGIC, 0)
  output[offset++] = 3
  offset = put(output, sessionId, offset)
  offset = put(output, capability, offset)
  if (offset !== output.byteLength) fail('parent capability IPC encoder length mismatch')
  return output
}

export function decodeLocalForwardHttpsParentCapabilityV3 (input) {
  input = bytes(input, PRIVATE_IPC_V3_LIMITS.PARENT_CAPABILITY_BYTES, 'parent capability IPC')
  if (!b4a.equals(input.subarray(0, 4), CAPABILITY_MAGIC) || input[4] !== 3) fail('parent capability IPC fixed header is invalid')
  const value = {
    version: 3,
    sessionId: take(input, 5, 32),
    parentCapability: decodeForwardHttpsParentCapabilityV1(input.subarray(37))
  }
  if (!b4a.equals(encodeLocalForwardHttpsParentCapabilityV3(value), input)) fail('parent capability IPC is not canonical')
  return value
}

export function encodeLocalForwardHttpsTurnV3 (value) {
  if (!value || typeof value !== 'object' || value.version !== 3 || value.flags !== 0) fail('local turn fixed header is invalid')
  if (value.direction !== LOCAL_FORWARD_HTTPS_DIRECTION_V3.REQUEST && value.direction !== LOCAL_FORWARD_HTTPS_DIRECTION_V3.RESULT) {
    fail('local turn direction is invalid')
  }
  const body = bytes(value.body, PRIVATE_IPC_V3_LIMITS.TURN_BODY_BYTES, 'local turn body')
  const decoded = decodeCanonical(
    value.direction === LOCAL_FORWARD_HTTPS_DIRECTION_V3.REQUEST
      ? blindForwardHttpsTurnRequestV1
      : blindForwardHttpsTurnResultV1,
    body,
    { copyBytes: true }
  )
  const sessionId = bytes(value.sessionId, 32, 'sessionId', true)
  const sequence = u64(value.sequence, 'sequence')
  if (!b4a.equals(sessionId, decoded.sessionId) || sequence !== decoded.sequence) fail('local turn sessionId or sequence does not match body')
  const output = b4a.alloc(PRIVATE_IPC_V3_LIMITS.TURN_BYTES)
  let offset = put(output, TURN_MAGIC, 0)
  output[offset++] = 3
  output[offset++] = value.direction
  output[offset++] = 0
  output[offset++] = 0
  offset = put(output, sessionId, offset)
  offset = writeU64(output, sequence, offset, 'sequence')
  offset = put(output, body, offset)
  if (offset !== output.byteLength) fail('local turn encoder length mismatch')
  return output
}

export function decodeLocalForwardHttpsTurnV3 (input) {
  input = bytes(input, PRIVATE_IPC_V3_LIMITS.TURN_BYTES, 'local turn')
  if (!b4a.equals(input.subarray(0, 4), TURN_MAGIC) || input[4] !== 3 || input[6] !== 0 || input[7] !== 0) {
    fail('local turn fixed header is invalid')
  }
  const value = {
    version: 3,
    direction: input[5],
    flags: 0,
    sessionId: take(input, 8, 32),
    sequence: readU64(input, 40),
    body: take(input, 48, PRIVATE_IPC_V3_LIMITS.TURN_BODY_BYTES)
  }
  if (!b4a.equals(encodeLocalForwardHttpsTurnV3(value), input)) fail('local turn is not canonical')
  return value
}

function list (encoding) {
  return {
    preencode (state, values) {
      c.uint.preencode(state, values.length)
      for (const value of values) encoding.preencode(state, value)
    },
    encode (state, values) {
      c.uint.encode(state, values.length)
      for (const value of values) encoding.encode(state, value)
    },
    decode (state) {
      const length = c.uint.decode(state)
      const values = []
      for (let i = 0; i < length; i++) values.push(encoding.decode(state))
      return values
    }
  }
}

const schemaEncoding = {
  preencode (state, value) {
    c.uint.preencode(state, value.schemaId)
    c.string.preencode(state, value.schemaName)
    c.buffer.preencode(state, value.canonicalDeclarationBytes)
  },
  encode (state, value) {
    c.uint.encode(state, value.schemaId)
    c.string.encode(state, value.schemaName)
    c.buffer.encode(state, value.canonicalDeclarationBytes)
  },
  decode (state) {
    return {
      schemaId: c.uint.decode(state),
      schemaName: c.string.decode(state),
      canonicalDeclarationBytes: b4a.from(c.buffer.decode(state))
    }
  }
}

const schemasEncoding = list(schemaEncoding)

export const privateIpcV3RegistryEncoding = {
  preencode (state, value) {
    c.string.preencode(state, value.magic)
    c.uint.preencode(state, value.formatVersion)
    c.buffer.preencode(state, value.importedWireV2AbiHash)
    c.buffer.preencode(state, value.basePrivateIpcV2FormatHash)
    c.uint.preencode(state, value.baseSchemaCount)
    schemasEncoding.preencode(state, value.additionalSchemas)
    c.uint.preencode(state, value.forwardReadinessOperationBits)
  },
  encode (state, value) {
    c.string.encode(state, value.magic)
    c.uint.encode(state, value.formatVersion)
    c.buffer.encode(state, value.importedWireV2AbiHash)
    c.buffer.encode(state, value.basePrivateIpcV2FormatHash)
    c.uint.encode(state, value.baseSchemaCount)
    schemasEncoding.encode(state, value.additionalSchemas)
    c.uint.encode(state, value.forwardReadinessOperationBits)
  },
  decode (state) {
    return {
      magic: c.string.decode(state),
      formatVersion: c.uint.decode(state),
      importedWireV2AbiHash: b4a.from(c.buffer.decode(state)),
      basePrivateIpcV2FormatHash: b4a.from(c.buffer.decode(state)),
      baseSchemaCount: c.uint.decode(state),
      additionalSchemas: schemasEncoding.decode(state),
      forwardReadinessOperationBits: c.uint.decode(state)
    }
  }
}

export function createPrivateIpcV3RegistryValue (importedWireV2AbiHash, basePrivateIpcV2FormatHash) {
  return {
    magic: PRIVATE_IPC_V3_MAGIC,
    formatVersion: PRIVATE_IPC_V3_FORMAT_VERSION,
    importedWireV2AbiHash: bytes(importedWireV2AbiHash, 32, 'importedWireV2AbiHash'),
    basePrivateIpcV2FormatHash: bytes(basePrivateIpcV2FormatHash, 32, 'basePrivateIpcV2FormatHash'),
    baseSchemaCount: 12,
    additionalSchemas: PRIVATE_IPC_V3_ADDITIONAL_SCHEMAS.map(schema => ({
      schemaId: schema.schemaId,
      schemaName: schema.schemaName,
      canonicalDeclarationBytes: b4a.from(JSON.stringify({ name: schema.schemaName, fields: schema.fields }), 'utf8')
    })),
    forwardReadinessOperationBits: 0
  }
}

export function encodePrivateIpcV3Registry (value) {
  const state = { start: 0, end: 0, buffer: null }
  privateIpcV3RegistryEncoding.preencode(state, value)
  state.buffer = b4a.alloc(state.end)
  state.start = 0
  privateIpcV3RegistryEncoding.encode(state, value)
  if (state.start !== state.end) fail('private IPC v3 registry encoder length mismatch')
  return state.buffer
}

export function decodePrivateIpcV3Registry (input) {
  const state = { start: 0, end: input.byteLength, buffer: input }
  const value = privateIpcV3RegistryEncoding.decode(state)
  if (state.start !== state.end) fail('trailing bytes after private IPC v3 registry')
  if (!b4a.equals(encodePrivateIpcV3Registry(value), input)) fail('private IPC v3 registry is not canonical')
  if (value.magic !== PRIVATE_IPC_V3_MAGIC || value.formatVersion !== 3 || value.baseSchemaCount !== 12 ||
      value.additionalSchemas.length !== 3 || value.additionalSchemas[0].schemaId !== 13 ||
      value.additionalSchemas[2].schemaId !== 15 || value.forwardReadinessOperationBits !== 0) {
    fail('private IPC v3 registry fixed allocation is invalid')
  }
  return value
}

function length64 (length) {
  const output = b4a.alloc(8)
  writeU64(output, BigInt(length), 0, 'hash input length')
  return output
}

function domainLengthHash (domain, input) {
  return privateBlake2b256(b4a.concat([domain, length64(input.byteLength), input]))
}

export const hashPrivateIpcV3Registry = input => domainLengthHash(FORMAT_DOMAIN, input)
export const hashPrivateIpcV3VectorManifest = input => domainLengthHash(VECTOR_DOMAIN, input)
