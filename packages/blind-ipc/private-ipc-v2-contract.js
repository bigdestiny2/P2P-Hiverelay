import b4a from 'b4a'
import {
  FAMILY,
  FRAME_KIND,
  OPERATION,
  OUTER_CLASS,
  STREAM_WIRE_CLASS,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  operationBit,
  operationProfile
} from '@hiverelay/blind-protocol/wire-runtime-authority'
import { ENDPOINT_ROLE } from '@hiverelay/blind-protocol/registry'
import { decodeOuterEnvelope } from '@hiverelay/blind-protocol/outer-envelope'
import { privateBlake2b256 } from './private-hashes.js'
import {
  PRIVATE_IPC_SCHEMAS,
  privateIpcRegistryEncoding,
  privateIpcRegistryValue
} from './registry.js'
import { LOCAL_ABORT_CODE } from './policy.js'

const FORMAT_DOMAIN = b4a.from('hiverelay.blind.private-ipc-format-hash.v2', 'ascii')
const VECTOR_DOMAIN = b4a.from('hiverelay.blind.private-ipc-vector-set-hash.v2', 'ascii')
const TLS_EXPORTER_CONTEXT_DOMAIN = b4a.from('hiverelay.blind.tls-exporter-context.v2', 'ascii')
const PUBLIC_SESSION_BINDING_DOMAIN = b4a.from('hiverelay.blind.public-session-binding.v2', 'ascii')
const LOCAL_OPEN_BINDING_DOMAIN = b4a.from('hiverelay.blind.local-staged-open-binding.v2', 'ascii')
const REPLAY_TUPLE_DOMAIN = b4a.from('hiverelay.blind.local-staged-replay-tuple.v2', 'ascii')
const MAX_U64 = (1n << 64n) - 1n
const MAX_PRIVATE_IPC_REGISTRY_BYTES = 1024 * 1024
const VERIFIED_STAGED_OPEN_AUTHORITIES = new WeakMap()

export const PRIVATE_IPC_V2_MAGIC = 'hiverelay-blind-private-ipc-v2'
export const PRIVATE_IPC_V2_FORMAT_VERSION = 2
export const TLS_EXPORTER_LABEL_V2 = 'EXPORTER-HiveRelay-Blind-Staged-Cell-Put-v2'

export const LOCAL_TRANSPORT_AUTHORITY_KIND_V2 = Object.freeze({
  TLS_EXPORTER_BY_PEERCRED_EDGE: 1,
  NOISE_TRANSCRIPT_BY_PEERCRED_EDGE: 2
})

export const LOCAL_STAGED_REQUEST_KIND_V2 = Object.freeze({
  STAGED_CELL_PUT_OUTER_ENVELOPE_V1: 1
})

export const LOCAL_STAGED_RESULT_KIND_V2 = Object.freeze({
  CELL_PUT_OUTER_RESULT_ENVELOPE_V1: 1
})

export const LOCAL_IPC_CHANNEL_CLASS_V2 = Object.freeze({ LOCAL_64K: 1 })
export const LOCAL_STAGED_DIRECTION_V2 = Object.freeze({ REQUEST: 1, RESULT: 2 })
export const LOCAL_STAGED_FRAME_KIND_V2 = Object.freeze({ CONTENT: 1, ABORT: 2 })
export const LOCAL_STAGED_FLAG_V2 = Object.freeze({ FIN: 0x01 })
export const LOCAL_READY_CONTROL_KIND_V2 = Object.freeze({ PROBE: 1, ACK: 2 })

export const LOCAL_IPC_FEATURE_V2 = Object.freeze({
  STAGED_CELL_PUT: 0x01,
  FULL_OUTER_ENVELOPE: 0x02,
  PEERCRED_EDGE_AUTHORITY: 0x04,
  TLS_EXPORTER_BINDING: 0x08,
  PRECOMMIT_OUTER_CLASS_AUTHORITY: 0x10,
  OUTER_RESULT_ENVELOPE: 0x20
})

export const REQUIRED_LOCAL_IPC_FEATURE_BITS_V2 = Object.values(LOCAL_IPC_FEATURE_V2)
  .reduce((mask, bit) => mask | bit, 0)
export const CELL_PUT_OPERATION_BIT_V2 = operationBit(FAMILY.CELL, OPERATION.CELL.PUT)
export const CELL_PUT_ENDPOINT_ROLE_BIT_V2 = ENDPOINT_ROLE.STORAGE

if (CELL_PUT_OPERATION_BIT_V2 === 0) throw new Error('generated CELL.PUT operation bit is absent')

const cellPutProfile = operationProfile(FAMILY.CELL, OPERATION.CELL.PUT)
if (!cellPutProfile) throw new Error('generated CELL.PUT operation profile is absent')

export const PRIVATE_IPC_V2_LIMITS = Object.freeze({
  TRANSPORT_BINDING_BYTES: 162,
  STAGED_OPEN_HEADER_BYTES: 38,
  STAGED_OPEN_BYTES: 200,
  STAGED_FRAME_HEADER_BYTES: 20,
  LOCAL_FRAME_BYTES: 65_535,
  LOCAL_FRAME_CONTENT_BYTES: 65_515,
  READY_PROBE_BYTES: 95,
  READY_ACK_BYTES: 133,
  OPEN_DEADLINE_MILLIS: 15_000,
  READY_DEADLINE_MILLIS: 2_000,
  TLS_EXPORTER_BYTES: 32,
  TLS_EXPORTER_CONTEXT_BYTES: 32,
  PUBLIC_SESSION_BINDING_HASH_BYTES: 32,
  OUTER_HEADER_BYTES: 6,
  DISPATCH_HEADER_BYTES: 45,
  CELL_PUT_MAX_RESULT_BODY_BYTES: cellPutProfile.maxResultBodyBytes,
  CELL_PUT_WORST_CASE_RESULT_ENVELOPE_BYTES: 6 + 45 + cellPutProfile.maxResultBodyBytes,
  CELL_PUT_WORST_CASE_MINIMUM_OUTER_CLASS: 3
})

if (PRIVATE_IPC_V2_LIMITS.CELL_PUT_WORST_CASE_RESULT_ENVELOPE_BYTES !== 16_435 ||
    OUTER_CLASS[2] !== 16_384 || OUTER_CLASS[3] !== 65_536) {
  throw new Error('generated CELL.PUT response-fit authority changed')
}

export const PRIVATE_IPC_V2_ADDITIONAL_SCHEMAS = Object.freeze([
  Object.freeze({
    schemaId: 8,
    schemaName: 'LocalTransportBindingV2',
    fields: Object.freeze([
      'version:u8=2', 'authorityKind:u8[1..2]',
      'edgeProcessNonce:fixed32[nonzero]', 'localChannelNonce:fixed32[nonzero]',
      'transportProfileHash:fixed32[nonzero]', 'publicSessionBindingHash:fixed32[nonzero]',
      'openBindingHash:fixed32[nonzero]', 'exactBytes:162',
      'authority:peercred-authenticates-edge-attestation',
      'tls-or-noise-binding:session-material-not-independent-edge-proof'
    ])
  }),
  Object.freeze({
    schemaId: 9,
    schemaName: 'LocalStagedCellPutOpenV2',
    fields: Object.freeze([
      'totalLength:u32be=196', 'version:u8=2',
      'requestKind:u8=STAGED_CELL_PUT_OUTER_ENVELOPE_V1',
      'resultKind:u8=CELL_PUT_OUTER_RESULT_ENVELOPE_V1',
      'authorityKind:u8=TLS_EXPORTER_BY_PEERCRED_EDGE',
      'transportId:u8=HTTPS_DIRECT', 'transportSupportBit:u16be=DIRECT_HTTP',
      'endpointId:u8[1..255]', 'outerClass:u8[1..6]',
      'ipcChannelClass:u8=LOCAL_64K', 'acceptedMonotonicMillis:u64be',
      'openDeadlineMonotonicMillis:u64be[accepted+1..15000]',
      'requestEnvelopeBytes:u32be=OUTER_CLASS[outerClass]',
      'contextLength:u32be=162', 'context:LocalTransportBindingV2',
      'request-envelope:exact-REQUEST-CELL.PUT-full-BlindOuterEnvelopeV1',
      'result-envelope:same-class-correlated-RESPONSE-or-ERROR',
      'exactHeaderBytesIncludingPrefix:38', 'exactBytes:200'
    ])
  }),
  Object.freeze({
    schemaId: 10,
    schemaName: 'LocalStagedCellPutFrameV2',
    fields: Object.freeze([
      'totalLength:u32be=16+bodyLength', 'version:u8=2',
      'direction:u8[1-request|2-result]', 'frameKind:u8[1-content|2-abort]',
      'sequence:u64be[first0-exact+1-per-direction]', 'flags:u8[FIN-only]',
      'bodyLength:u32be[0..65515]', 'bytes:bytes[bodyLength]',
      'CONTENT:1..65515|zero-only-with-FIN',
      'ABORT:flags0|exactly-one-registered-generic-abort-code-byte',
      'request-direction:full-REQUEST-CELL.PUT-outer-envelope',
      'result-direction:same-class-correlated-RESPONSE-or-ERROR-outer-envelope',
      'exactHeaderBytesIncludingPrefix:20'
    ])
  }),
  Object.freeze({
    schemaId: 11,
    schemaName: 'LocalReadyProbeV2',
    fields: Object.freeze([
      'totalLength:u32be=91', 'version:u8=2', 'controlKind:u8=PROBE',
      'endpointId:u8[1..255]', 'edgeProcessNonce:fixed32[nonzero]',
      'launchTopologyHash:fixed32[nonzero]', 'edgeFeatureBits:u32be=required-v2-mask',
      'requestedWriteOperationBits:u32be=CELL.PUT-bit',
      'acceptedMonotonicMillis:u64be',
      'absoluteDeadlineMonotonicMillis:u64be=accepted+2000', 'exactBytes:95'
    ])
  }),
  Object.freeze({
    schemaId: 12,
    schemaName: 'LocalReadyAckV2',
    fields: Object.freeze([
      'totalLength:u32be=129', 'version:u8=2', 'controlKind:u8=ACK',
      'endpointId:u8[1..255]', 'edgeProcessNonce:fixed32[nonzero]',
      'launchTopologyHash:fixed32[nonzero]', 'descriptorSequence:u64be[nonzero]',
      'descriptorHash:fixed32[nonzero]', 'readyRoleBits:u16be[descriptor-subset]',
      'readyOperationBits:u32be[descriptor-subset]',
      'readyWriteOperationBits:u32be=CELL.PUT-bit-and-readyOperationBits-subset',
      'readyIpcFeatureBits:u32be=required-v2-mask',
      'expiresMonotonicMillis:u64be[descriptor-and-probe-freshness]', 'exactBytes:133'
    ])
  })
])

export const PRIVATE_IPC_V2_SCHEMAS = Object.freeze([
  ...PRIVATE_IPC_SCHEMAS,
  ...PRIVATE_IPC_V2_ADDITIONAL_SCHEMAS
])

export const PRIVATE_IPC_V2_TRANSPORT_AUTHORITY = Object.freeze({
  [TRANSPORT_ID.HTTPS_DIRECT]: Object.freeze({
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    authorityKind: LOCAL_TRANSPORT_AUTHORITY_KIND_V2.TLS_EXPORTER_BY_PEERCRED_EDGE,
    sessionBinding: 'tls-exporter-32',
    peerCredentialRequired: true
  }),
  [TRANSPORT_ID.DIRECT_PROTOMUX_NOISE]: Object.freeze({
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_NATIVE,
    authorityKind: LOCAL_TRANSPORT_AUTHORITY_KIND_V2.NOISE_TRANSCRIPT_BY_PEERCRED_EDGE,
    sessionBinding: 'noise-final-transcript-hash-32',
    peerCredentialRequired: true
  })
})

function fail (message, code = 'BAD_PRIVATE_IPC_V2_CONTRACT') {
  const error = new Error(message)
  error.code = code
  throw error
}

function asBuffer (value, field) {
  if (!value || typeof value.byteLength !== 'number') fail(`${field} must be bytes`)
  if (b4a.isBuffer(value)) return value
  if (ArrayBuffer.isView(value)) return b4a.from(value.buffer, value.byteOffset, value.byteLength)
  return b4a.from(value)
}

function snapshot (value, field) {
  return b4a.from(asBuffer(value, field))
}

function isZero (bytes) {
  for (const byte of bytes) if (byte !== 0) return false
  return true
}

function fixed (value, length, field, nonzero = true) {
  const bytes = snapshot(value, field)
  if (bytes.byteLength !== length) fail(`${field} must be exactly ${length} bytes`)
  if (nonzero && isZero(bytes)) fail(`${field} must be nonzero`)
  return bytes
}

function u8 (value, field, minimum = 0, maximum = 0xff) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) fail(`${field} is outside ${minimum}..${maximum}`)
  return value
}

function u16 (value, field) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) fail(`${field} is outside u16`)
  return value
}

function u32 (value, field) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) fail(`${field} is outside u32`)
  return value
}

function u64 (value, field, nonzero = false) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${field} must be an unsigned safe integer or bigint`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64 || (nonzero && value === 0n)) {
    fail(`${field} is outside ${nonzero ? 'nonzero ' : ''}u64`)
  }
  return value
}

function writeU16 (output, value, offset) {
  value = u16(value, 'u16')
  output[offset] = value >>> 8
  output[offset + 1] = value & 0xff
}

function readU16 (input, offset) {
  return input[offset] * 0x100 + input[offset + 1]
}

function writeU64 (output, value, offset) {
  value = u64(value, 'u64')
  for (let index = 7; index >= 0; index--) {
    output[offset + index] = Number(value & 0xffn)
    value >>= 8n
  }
}

function readU64 (input, offset) {
  let value = 0n
  for (let index = 0; index < 8; index++) value = (value << 8n) | BigInt(input[offset + index])
  return value
}

function u64Bytes (value) {
  const output = b4a.alloc(8)
  writeU64(output, value, 0)
  return output
}

function len64 (length) {
  return u64Bytes(BigInt(length))
}

function exactFrame (input, exactBytes, field) {
  const bytes = snapshot(input, field)
  if (bytes.byteLength !== exactBytes) fail(`${field} must be exactly ${exactBytes} bytes`)
  if (b4a.readUInt32BE(bytes, 0) !== exactBytes - 4) fail(`${field} totalLength is not exact`)
  return bytes
}

function fixedDeclaredLength (input, exactBytes, headerBytes, field, controlKind = null) {
  const bytes = snapshot(input, field)
  if (bytes.byteLength < 4) return null
  if (b4a.readUInt32BE(bytes, 0) !== exactBytes - 4) fail(`${field} has an impossible declared length`)
  if (bytes.byteLength < 5) return null
  if (bytes[4] !== 2) fail(`${field} is not version 2`, 'PRIVATE_IPC_V2_NO_FALLBACK')
  if (bytes.byteLength < headerBytes) return null
  if (controlKind !== null && bytes[5] !== controlKind) fail(`${field} has the wrong control kind`)
  return exactBytes
}

function declaredFrame (input, minimumBytes, maximumBytes, field) {
  const bytes = snapshot(input, field)
  if (bytes.byteLength < minimumBytes || bytes.byteLength > maximumBytes) {
    fail(`${field} is outside its complete-frame bound`)
  }
  if (b4a.readUInt32BE(bytes, 0) !== bytes.byteLength - 4) fail(`${field} totalLength is not exact`)
  return bytes
}

function exactEnum (values, value, field) {
  if (!Object.values(values).includes(value)) fail(`${field} is not registered`)
  return value
}

function enumBindings (name, values) {
  return {
    name,
    entries: Object.entries(values)
      .map(([entryName, raw]) => ({ name: entryName, id: Number(raw), value: Number(raw) }))
      .sort((left, right) => left.id - right.id || (left.name < right.name ? -1 : left.name > right.name ? 1 : 0))
  }
}

function namedBindings (name, values) {
  return {
    name,
    entries: Object.entries(values)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([entryName, value], index) => ({ name: entryName, id: index + 1, value: Number(value) }))
  }
}

function encodeCompact (encoding, value) {
  const state = { start: 0, end: 0, buffer: null }
  encoding.preencode(state, value)
  state.buffer = b4a.alloc(state.end)
  state.start = 0
  encoding.encode(state, value)
  return state.buffer
}

function decodeCompact (encoding, input, field) {
  const bytes = snapshot(input, field)
  if (bytes.byteLength < 1 || bytes.byteLength > MAX_PRIVATE_IPC_REGISTRY_BYTES) fail(`${field} is outside its byte bound`)
  const state = { start: 0, end: bytes.byteLength, buffer: bytes }
  let value
  try {
    value = encoding.decode(state)
  } catch {
    fail(`${field} is truncated or malformed`)
  }
  if (state.start !== state.end) fail(`${field} has trailing bytes`)
  if (!b4a.equals(encodeCompact(encoding, value), bytes)) fail(`${field} is not canonical`)
  return { bytes, value }
}

export function privateIpcV2RegistryValue (wireAbiBytes) {
  const v1 = privateIpcRegistryValue(asBuffer(wireAbiBytes, 'public WIRE ABI'))
  return {
    magic: PRIVATE_IPC_V2_MAGIC,
    formatVersion: PRIVATE_IPC_V2_FORMAT_VERSION,
    wireAbiHash: b4a.from(v1.wireAbiHash),
    schemas: PRIVATE_IPC_V2_SCHEMAS,
    importedWireBindings: [
      ...v1.importedWireBindings,
      enumBindings('FRAME_KIND', FRAME_KIND),
      enumBindings('OPERATION_CELL', OPERATION.CELL)
    ],
    localBindings: [
      ...v1.localBindings,
      enumBindings('v2TransportAuthorityKind', LOCAL_TRANSPORT_AUTHORITY_KIND_V2),
      enumBindings('v2RequestKind', LOCAL_STAGED_REQUEST_KIND_V2),
      enumBindings('v2ResultKind', LOCAL_STAGED_RESULT_KIND_V2),
      enumBindings('v2IpcChannelClass', LOCAL_IPC_CHANNEL_CLASS_V2),
      enumBindings('v2Direction', LOCAL_STAGED_DIRECTION_V2),
      enumBindings('v2FrameKind', LOCAL_STAGED_FRAME_KIND_V2),
      enumBindings('v2Flag', LOCAL_STAGED_FLAG_V2),
      enumBindings('v2ReadyControlKind', LOCAL_READY_CONTROL_KIND_V2),
      enumBindings('v2IpcFeature', LOCAL_IPC_FEATURE_V2),
      namedBindings('v2CellPutAuthority', {
        CELL_PUT_FAMILY_ID: FAMILY.CELL,
        CELL_PUT_OPERATION_ID: OPERATION.CELL.PUT,
        CELL_PUT_OPERATION_BIT: CELL_PUT_OPERATION_BIT_V2,
        CELL_PUT_REQUEST_FRAME_KIND: FRAME_KIND.REQUEST,
        CELL_PUT_RESPONSE_FRAME_KIND: FRAME_KIND.RESPONSE,
        CELL_PUT_ERROR_FRAME_KIND: FRAME_KIND.ERROR,
        STORAGE_ROLE_BIT: CELL_PUT_ENDPOINT_ROLE_BIT_V2
      }),
      namedBindings('v2Limits', PRIVATE_IPC_V2_LIMITS),
      namedBindings('v2RequiredBits', { REQUIRED_IPC_FEATURE_BITS: REQUIRED_LOCAL_IPC_FEATURE_BITS_V2 }),
      namedBindings('v2HttpsTransport', {
        AUTHORITY_KIND: LOCAL_TRANSPORT_AUTHORITY_KIND_V2.TLS_EXPORTER_BY_PEERCRED_EDGE,
        TRANSPORT_ID: TRANSPORT_ID.HTTPS_DIRECT,
        TRANSPORT_SUPPORT_BIT: TRANSPORT_SUPPORT.DIRECT_HTTP
      })
    ]
  }
}

export function encodePrivateIpcV2Registry (wireAbiBytes) {
  return encodeCompact(privateIpcRegistryEncoding, privateIpcV2RegistryValue(wireAbiBytes))
}

export function decodePrivateIpcV2Registry (input) {
  const decoded = decodeCompact(privateIpcRegistryEncoding, input, 'private IPC v2 registry')
  if (decoded.value.magic !== PRIVATE_IPC_V2_MAGIC || decoded.value.formatVersion !== PRIVATE_IPC_V2_FORMAT_VERSION) {
    fail('private IPC v2 registry has the wrong magic or version', 'PRIVATE_IPC_V2_NO_FALLBACK')
  }
  return decoded.value
}

export function verifyPrivateIpcV2Registry (input, wireAbiBytes) {
  const bytes = snapshot(input, 'private IPC v2 registry')
  decodePrivateIpcV2Registry(bytes)
  const expected = encodePrivateIpcV2Registry(asBuffer(wireAbiBytes, 'public WIRE ABI'))
  if (!b4a.equals(bytes, expected)) fail('private IPC v2 registry does not equal the exact V1-plus-V2 authority')
  return decodePrivateIpcV2Registry(bytes)
}

export function hashPrivateIpcV2Registry (input) {
  const bytes = snapshot(input, 'private IPC v2 registry')
  return privateBlake2b256(b4a.concat([FORMAT_DOMAIN, len64(bytes.byteLength), bytes]))
}

export function hashPrivateIpcV2VectorManifest (input) {
  const bytes = snapshot(input, 'private IPC v2 vector manifest')
  return privateBlake2b256(b4a.concat([VECTOR_DOMAIN, len64(bytes.byteLength), bytes]))
}

function normalizedOpenFields (input) {
  if (!input || typeof input !== 'object') fail('staged CELL.PUT open must be an object')
  const accepted = u64(input.acceptedMonotonicMillis, 'acceptedMonotonicMillis')
  const deadline = u64(input.openDeadlineMonotonicMillis, 'openDeadlineMonotonicMillis')
  if (deadline <= accepted || deadline - accepted > BigInt(PRIVATE_IPC_V2_LIMITS.OPEN_DEADLINE_MILLIS)) {
    fail('staged CELL.PUT open deadline is inverted or exceeds 15000 ms')
  }
  const outerClass = u8(input.outerClass, 'outerClass', 1, 6)
  const value = {
    version: 2,
    requestKind: input.requestKind == null
      ? LOCAL_STAGED_REQUEST_KIND_V2.STAGED_CELL_PUT_OUTER_ENVELOPE_V1
      : exactEnum(LOCAL_STAGED_REQUEST_KIND_V2, input.requestKind, 'requestKind'),
    resultKind: input.resultKind == null
      ? LOCAL_STAGED_RESULT_KIND_V2.CELL_PUT_OUTER_RESULT_ENVELOPE_V1
      : exactEnum(LOCAL_STAGED_RESULT_KIND_V2, input.resultKind, 'resultKind'),
    authorityKind: input.authorityKind == null
      ? LOCAL_TRANSPORT_AUTHORITY_KIND_V2.TLS_EXPORTER_BY_PEERCRED_EDGE
      : exactEnum(LOCAL_TRANSPORT_AUTHORITY_KIND_V2, input.authorityKind, 'authorityKind'),
    transportId: input.transportId == null ? TRANSPORT_ID.HTTPS_DIRECT : u8(input.transportId, 'transportId'),
    transportSupportBit: input.transportSupportBit == null
      ? TRANSPORT_SUPPORT.DIRECT_HTTP
      : u16(input.transportSupportBit, 'transportSupportBit'),
    endpointId: u8(input.endpointId, 'endpointId', 1, 0xff),
    outerClass,
    ipcChannelClass: input.ipcChannelClass == null
      ? LOCAL_IPC_CHANNEL_CLASS_V2.LOCAL_64K
      : exactEnum(LOCAL_IPC_CHANNEL_CLASS_V2, input.ipcChannelClass, 'ipcChannelClass'),
    acceptedMonotonicMillis: accepted,
    openDeadlineMonotonicMillis: deadline,
    requestEnvelopeBytes: input.requestEnvelopeBytes == null
      ? OUTER_CLASS[outerClass]
      : u32(input.requestEnvelopeBytes, 'requestEnvelopeBytes'),
    contextLength: PRIVATE_IPC_V2_LIMITS.TRANSPORT_BINDING_BYTES
  }
  if (value.authorityKind !== LOCAL_TRANSPORT_AUTHORITY_KIND_V2.TLS_EXPORTER_BY_PEERCRED_EDGE ||
      value.transportId !== TRANSPORT_ID.HTTPS_DIRECT ||
      value.transportSupportBit !== TRANSPORT_SUPPORT.DIRECT_HTTP) {
    fail('HTTPS staged CELL.PUT accepts only HTTPS_DIRECT/DIRECT_HTTP with TLS-exporter peercred-edge authority')
  }
  if (value.requestEnvelopeBytes !== OUTER_CLASS[outerClass]) fail('requestEnvelopeBytes must equal the exact selected public outer class')
  return value
}

export function encodeLocalStagedCellPutOpenFieldsV2 (input) {
  const value = normalizedOpenFields(input)
  const output = b4a.alloc(PRIVATE_IPC_V2_LIMITS.STAGED_OPEN_HEADER_BYTES - 4)
  output[0] = 2
  output[1] = value.requestKind
  output[2] = value.resultKind
  output[3] = value.authorityKind
  output[4] = value.transportId
  writeU16(output, value.transportSupportBit, 5)
  output[7] = value.endpointId
  output[8] = value.outerClass
  output[9] = value.ipcChannelClass
  writeU64(output, value.acceptedMonotonicMillis, 10)
  writeU64(output, value.openDeadlineMonotonicMillis, 18)
  b4a.writeUInt32BE(output, value.requestEnvelopeBytes, 26)
  b4a.writeUInt32BE(output, value.contextLength, 30)
  return output
}

export function encodeLocalTransportBindingV2 (input) {
  if (!input || typeof input !== 'object') fail('local transport binding must be an object')
  const authorityKind = exactEnum(LOCAL_TRANSPORT_AUTHORITY_KIND_V2, input.authorityKind, 'authorityKind')
  const output = b4a.alloc(PRIVATE_IPC_V2_LIMITS.TRANSPORT_BINDING_BYTES)
  output[0] = 2
  output[1] = authorityKind
  b4a.copy(fixed(input.edgeProcessNonce, 32, 'edgeProcessNonce'), output, 2)
  b4a.copy(fixed(input.localChannelNonce, 32, 'localChannelNonce'), output, 34)
  b4a.copy(fixed(input.transportProfileHash, 32, 'transportProfileHash'), output, 66)
  b4a.copy(fixed(input.publicSessionBindingHash, 32, 'publicSessionBindingHash'), output, 98)
  b4a.copy(fixed(input.openBindingHash, 32, 'openBindingHash'), output, 130)
  return output
}

export function decodeLocalTransportBindingV2 (input) {
  const bytes = snapshot(input, 'local transport binding v2')
  if (bytes.byteLength !== PRIVATE_IPC_V2_LIMITS.TRANSPORT_BINDING_BYTES || bytes[0] !== 2) {
    fail('local transport binding v2 has an invalid exact shape', 'PRIVATE_IPC_V2_NO_FALLBACK')
  }
  const value = {
    version: 2,
    authorityKind: exactEnum(LOCAL_TRANSPORT_AUTHORITY_KIND_V2, bytes[1], 'authorityKind'),
    edgeProcessNonce: fixed(bytes.subarray(2, 34), 32, 'edgeProcessNonce'),
    localChannelNonce: fixed(bytes.subarray(34, 66), 32, 'localChannelNonce'),
    transportProfileHash: fixed(bytes.subarray(66, 98), 32, 'transportProfileHash'),
    publicSessionBindingHash: fixed(bytes.subarray(98, 130), 32, 'publicSessionBindingHash'),
    openBindingHash: fixed(bytes.subarray(130, 162), 32, 'openBindingHash')
  }
  return Object.freeze(value)
}

export function deriveTlsExporterContextHashV2 (input) {
  const fields = encodeLocalStagedCellPutOpenFieldsV2(input.open)
  return privateBlake2b256(b4a.concat([
    TLS_EXPORTER_CONTEXT_DOMAIN,
    fixed(input.launchTopologyHash, 32, 'launchTopologyHash'),
    fields,
    fixed(input.edgeProcessNonce, 32, 'edgeProcessNonce'),
    fixed(input.localChannelNonce, 32, 'localChannelNonce')
  ]))
}

export function derivePublicSessionBindingHashV2 (input) {
  const authorityKind = exactEnum(LOCAL_TRANSPORT_AUTHORITY_KIND_V2, input.authorityKind, 'authorityKind')
  return privateBlake2b256(b4a.concat([
    PUBLIC_SESSION_BINDING_DOMAIN,
    b4a.from([authorityKind]),
    fixed(input.transportProfileHash, 32, 'transportProfileHash'),
    fixed(input.exporterContextHash, 32, 'exporterContextHash'),
    fixed(input.sessionBindingMaterial, 32, 'sessionBindingMaterial')
  ]))
}

export function deriveLocalStagedOpenBindingHashV2 (input) {
  const fields = encodeLocalStagedCellPutOpenFieldsV2(input.open)
  const authorityKind = exactEnum(LOCAL_TRANSPORT_AUTHORITY_KIND_V2, input.authorityKind, 'authorityKind')
  return privateBlake2b256(b4a.concat([
    LOCAL_OPEN_BINDING_DOMAIN,
    fixed(input.launchTopologyHash, 32, 'launchTopologyHash'),
    fields,
    b4a.from([authorityKind]),
    fixed(input.edgeProcessNonce, 32, 'edgeProcessNonce'),
    fixed(input.localChannelNonce, 32, 'localChannelNonce'),
    fixed(input.transportProfileHash, 32, 'transportProfileHash'),
    fixed(input.publicSessionBindingHash, 32, 'publicSessionBindingHash')
  ]))
}

export function encodeLocalStagedCellPutOpenV2 (input) {
  const fields = encodeLocalStagedCellPutOpenFieldsV2(input)
  const context = encodeLocalTransportBindingV2(input.context)
  const output = b4a.alloc(PRIVATE_IPC_V2_LIMITS.STAGED_OPEN_BYTES)
  b4a.writeUInt32BE(output, output.byteLength - 4, 0)
  b4a.copy(fields, output, 4)
  b4a.copy(context, output, PRIVATE_IPC_V2_LIMITS.STAGED_OPEN_HEADER_BYTES)
  return output
}

export function readLocalStagedCellPutOpenLengthV2 (input) {
  const bytes = snapshot(input, 'local staged CELL.PUT open v2 prefix/header')
  const length = fixedDeclaredLength(bytes, PRIVATE_IPC_V2_LIMITS.STAGED_OPEN_BYTES,
    PRIVATE_IPC_V2_LIMITS.STAGED_OPEN_HEADER_BYTES, 'local staged CELL.PUT open v2 prefix/header')
  if (length === null) return null
  const raw = {
    requestKind: bytes[5],
    resultKind: bytes[6],
    authorityKind: bytes[7],
    transportId: bytes[8],
    transportSupportBit: readU16(bytes, 9),
    endpointId: bytes[11],
    outerClass: bytes[12],
    ipcChannelClass: bytes[13],
    acceptedMonotonicMillis: readU64(bytes, 14),
    openDeadlineMonotonicMillis: readU64(bytes, 22),
    requestEnvelopeBytes: b4a.readUInt32BE(bytes, 30)
  }
  normalizedOpenFields(raw)
  if (b4a.readUInt32BE(bytes, 34) !== PRIVATE_IPC_V2_LIMITS.TRANSPORT_BINDING_BYTES) {
    fail('local staged CELL.PUT open contextLength is not exact')
  }
  return length
}

export function decodeLocalStagedCellPutOpenV2 (input) {
  readLocalStagedCellPutOpenLengthV2(input)
  const bytes = exactFrame(input, PRIVATE_IPC_V2_LIMITS.STAGED_OPEN_BYTES, 'local staged CELL.PUT open v2')
  if (bytes[4] !== 2) fail('local staged CELL.PUT open is not version 2', 'PRIVATE_IPC_V2_NO_FALLBACK')
  const raw = {
    requestKind: bytes[5],
    resultKind: bytes[6],
    authorityKind: bytes[7],
    transportId: bytes[8],
    transportSupportBit: readU16(bytes, 9),
    endpointId: bytes[11],
    outerClass: bytes[12],
    ipcChannelClass: bytes[13],
    acceptedMonotonicMillis: readU64(bytes, 14),
    openDeadlineMonotonicMillis: readU64(bytes, 22),
    requestEnvelopeBytes: b4a.readUInt32BE(bytes, 30)
  }
  if (b4a.readUInt32BE(bytes, 34) !== PRIVATE_IPC_V2_LIMITS.TRANSPORT_BINDING_BYTES) {
    fail('local staged CELL.PUT open contextLength is not exact')
  }
  const value = normalizedOpenFields(raw)
  const context = decodeLocalTransportBindingV2(bytes.subarray(PRIVATE_IPC_V2_LIMITS.STAGED_OPEN_HEADER_BYTES))
  if (context.authorityKind !== value.authorityKind) fail('open and transport binding authority kinds differ')
  return Object.freeze({ ...value, context })
}

export function verifyLocalStagedCellPutOpenBindingV2 (input, options) {
  const open = input && input.context ? input : decodeLocalStagedCellPutOpenV2(input)
  if (!options || options.peerCredentialAuthenticated !== true) {
    fail('peer credentials must authenticate the edge before its transport-binding attestation is considered', 'PRIVATE_IPC_V2_PEERCRED_REQUIRED')
  }
  const expectedTopology = fixed(options.launchTopologyHash, 32, 'launchTopologyHash')
  const expectedProfile = fixed(options.transportProfileHash, 32, 'transportProfileHash')
  if (!b4a.equals(open.context.transportProfileHash, expectedProfile)) fail('transport profile hash does not match')
  const expectedOpenBinding = deriveLocalStagedOpenBindingHashV2({
    open,
    launchTopologyHash: expectedTopology,
    authorityKind: open.authorityKind,
    edgeProcessNonce: open.context.edgeProcessNonce,
    localChannelNonce: open.context.localChannelNonce,
    transportProfileHash: open.context.transportProfileHash,
    publicSessionBindingHash: open.context.publicSessionBindingHash
  })
  if (!b4a.equals(open.context.openBindingHash, expectedOpenBinding)) fail('local staged open binding hash does not match')
  const state = Object.freeze({
    authority: 'peercred-authenticated-edge-attestation',
    endpointId: open.endpointId,
    outerClass: open.outerClass,
    replayTupleHash: replayTupleHashV2(open.context)
  })
  const handle = Object.freeze(Object.create(null))
  VERIFIED_STAGED_OPEN_AUTHORITIES.set(handle, state)
  return handle
}

export function localStagedCellPutAuthorityV2 (handle) {
  const state = VERIFIED_STAGED_OPEN_AUTHORITIES.get(handle)
  if (!state) fail('staged CELL.PUT authority requires an opaque verified handle', 'PRIVATE_IPC_V2_AUTHORITY_REQUIRED')
  return Object.freeze({
    ...state,
    replayTupleHash: b4a.from(state.replayTupleHash)
  })
}

export function replayTupleHashV2 (input) {
  const context = input && input.version === 2 && input.publicSessionBindingHash
    ? input
    : decodeLocalTransportBindingV2(input)
  return privateBlake2b256(b4a.concat([
    REPLAY_TUPLE_DOMAIN,
    fixed(context.edgeProcessNonce, 32, 'edgeProcessNonce'),
    fixed(context.localChannelNonce, 32, 'localChannelNonce'),
    fixed(context.publicSessionBindingHash, 32, 'publicSessionBindingHash')
  ]))
}

export function encodeLocalStagedCellPutFrameV2 (input) {
  if (!input || typeof input !== 'object') fail('local staged CELL.PUT frame must be an object')
  const direction = exactEnum(LOCAL_STAGED_DIRECTION_V2, input.direction, 'direction')
  const frameKind = exactEnum(LOCAL_STAGED_FRAME_KIND_V2, input.frameKind, 'frameKind')
  const sequence = u64(input.sequence, 'sequence')
  const flags = input.flags == null ? 0 : u8(input.flags, 'flags')
  if ((flags & ~LOCAL_STAGED_FLAG_V2.FIN) !== 0) fail('frame has a reserved flag')
  const body = input.bytes == null ? b4a.alloc(0) : snapshot(input.bytes, 'frame bytes')
  if (body.byteLength > PRIVATE_IPC_V2_LIMITS.LOCAL_FRAME_CONTENT_BYTES) fail('frame body exceeds 65515 bytes')
  if (frameKind === LOCAL_STAGED_FRAME_KIND_V2.CONTENT) {
    if (body.byteLength === 0 && flags !== LOCAL_STAGED_FLAG_V2.FIN) fail('zero CONTENT is legal only with FIN')
  } else {
    if (flags !== 0 || body.byteLength !== 1 || !Object.values(LOCAL_ABORT_CODE).includes(body[0])) {
      fail('ABORT must have zero flags and exactly one registered generic abort code')
    }
  }
  const output = b4a.alloc(PRIVATE_IPC_V2_LIMITS.STAGED_FRAME_HEADER_BYTES + body.byteLength)
  b4a.writeUInt32BE(output, output.byteLength - 4, 0)
  output[4] = 2
  output[5] = direction
  output[6] = frameKind
  writeU64(output, sequence, 7)
  output[15] = flags
  b4a.writeUInt32BE(output, body.byteLength, 16)
  b4a.copy(body, output, PRIVATE_IPC_V2_LIMITS.STAGED_FRAME_HEADER_BYTES)
  return output
}

export function readLocalStagedCellPutFrameLengthV2 (input) {
  const bytes = snapshot(input, 'local staged CELL.PUT frame v2 prefix/header')
  if (bytes.byteLength < 4) return null
  const length = b4a.readUInt32BE(bytes, 0) + 4
  if (length < PRIVATE_IPC_V2_LIMITS.STAGED_FRAME_HEADER_BYTES || length > PRIVATE_IPC_V2_LIMITS.LOCAL_FRAME_BYTES) {
    fail('local staged CELL.PUT frame has an impossible declared length')
  }
  if (bytes.byteLength < 5) return null
  if (bytes[4] !== 2) fail('local staged CELL.PUT frame is not version 2', 'PRIVATE_IPC_V2_NO_FALLBACK')
  if (bytes.byteLength < PRIVATE_IPC_V2_LIMITS.STAGED_FRAME_HEADER_BYTES) return null
  exactEnum(LOCAL_STAGED_DIRECTION_V2, bytes[5], 'direction')
  const frameKind = exactEnum(LOCAL_STAGED_FRAME_KIND_V2, bytes[6], 'frameKind')
  if ((bytes[15] & ~LOCAL_STAGED_FLAG_V2.FIN) !== 0) fail('frame has a reserved flag')
  const bodyLength = b4a.readUInt32BE(bytes, 16)
  if (bodyLength !== length - PRIVATE_IPC_V2_LIMITS.STAGED_FRAME_HEADER_BYTES ||
      bodyLength > PRIVATE_IPC_V2_LIMITS.LOCAL_FRAME_CONTENT_BYTES) {
    fail('local staged CELL.PUT frame bodyLength contradicts its declaration')
  }
  if (frameKind === LOCAL_STAGED_FRAME_KIND_V2.ABORT && (bytes[15] !== 0 || bodyLength !== 1)) {
    fail('ABORT header must declare zero flags and exactly one code byte')
  }
  if (frameKind === LOCAL_STAGED_FRAME_KIND_V2.CONTENT && bodyLength === 0 && bytes[15] !== LOCAL_STAGED_FLAG_V2.FIN) {
    fail('zero CONTENT is legal only with FIN')
  }
  return length
}

export function decodeLocalStagedCellPutFrameV2 (input) {
  readLocalStagedCellPutFrameLengthV2(input)
  const bytes = declaredFrame(input, PRIVATE_IPC_V2_LIMITS.STAGED_FRAME_HEADER_BYTES,
    PRIVATE_IPC_V2_LIMITS.LOCAL_FRAME_BYTES, 'local staged CELL.PUT frame v2')
  if (bytes[4] !== 2) fail('local staged CELL.PUT frame is not version 2', 'PRIVATE_IPC_V2_NO_FALLBACK')
  const bodyLength = b4a.readUInt32BE(bytes, 16)
  if (bytes.byteLength !== PRIVATE_IPC_V2_LIMITS.STAGED_FRAME_HEADER_BYTES + bodyLength) {
    fail('local staged CELL.PUT frame bodyLength is not exact')
  }
  const value = {
    version: 2,
    direction: bytes[5],
    frameKind: bytes[6],
    sequence: readU64(bytes, 7),
    flags: bytes[15],
    bytes: b4a.from(bytes.subarray(PRIVATE_IPC_V2_LIMITS.STAGED_FRAME_HEADER_BYTES))
  }
  encodeLocalStagedCellPutFrameV2(value)
  return Object.freeze(value)
}

export function decodeLocalStagedCellPutFramesV2 (input, options = {}) {
  const bytes = snapshot(input, 'staged CELL.PUT frame buffer')
  const allowIncomplete = options.allowIncomplete === true
  const frames = []
  let offset = 0
  while (offset < bytes.byteLength) {
    if (bytes.byteLength - offset < 4) {
      if (allowIncomplete) break
      fail('staged CELL.PUT frame buffer ends in a partial prefix')
    }
    const length = b4a.readUInt32BE(bytes, offset) + 4
    if (length < PRIVATE_IPC_V2_LIMITS.STAGED_FRAME_HEADER_BYTES || length > PRIVATE_IPC_V2_LIMITS.LOCAL_FRAME_BYTES) {
      fail('staged CELL.PUT frame declaration is outside its bound')
    }
    if (offset + length > bytes.byteLength) {
      if (allowIncomplete) break
      fail('staged CELL.PUT frame buffer ends in a partial frame')
    }
    frames.push(decodeLocalStagedCellPutFrameV2(bytes.subarray(offset, offset + length)))
    offset += length
  }
  return Object.freeze({ frames: Object.freeze(frames), remainder: b4a.from(bytes.subarray(offset)) })
}

export function verifyLocalStagedCellPutExchangeV2 (openInput, frameInputs) {
  const open = openInput && openInput.context ? openInput : decodeLocalStagedCellPutOpenV2(openInput)
  if (!Array.isArray(frameInputs) || frameInputs.length < 1) fail('staged CELL.PUT exchange requires frames')
  let phase = LOCAL_STAGED_DIRECTION_V2.REQUEST
  let requestSequence = 0n
  let resultSequence = 0n
  let requestBytes = 0
  let resultBytes = 0
  let requestFinished = false
  let resultFinished = false
  let aborted = false
  for (const frameInput of frameInputs) {
    const frame = frameInput && frameInput.version === 2 ? frameInput : decodeLocalStagedCellPutFrameV2(frameInput)
    if (aborted || resultFinished) fail('frame follows terminal exchange state')
    if (frame.direction !== phase) fail('frame direction violates request/result state')
    const expectedSequence = phase === LOCAL_STAGED_DIRECTION_V2.REQUEST ? requestSequence : resultSequence
    if (frame.sequence !== expectedSequence) fail('frame sequence is not first-zero exact +1')
    if (phase === LOCAL_STAGED_DIRECTION_V2.REQUEST) requestSequence++
    else resultSequence++
    if (frame.frameKind === LOCAL_STAGED_FRAME_KIND_V2.ABORT) {
      aborted = true
      continue
    }
    if (phase === LOCAL_STAGED_DIRECTION_V2.REQUEST) requestBytes += frame.bytes.byteLength
    else resultBytes += frame.bytes.byteLength
    if ((frame.flags & LOCAL_STAGED_FLAG_V2.FIN) !== 0) {
      if (phase === LOCAL_STAGED_DIRECTION_V2.REQUEST) {
        if (requestBytes !== open.requestEnvelopeBytes) fail('request FIN does not complete the exact full outer envelope')
        requestFinished = true
        phase = LOCAL_STAGED_DIRECTION_V2.RESULT
      } else {
        if (resultBytes !== OUTER_CLASS[open.outerClass]) fail('result FIN does not complete the exact same-class outer envelope')
        resultFinished = true
      }
    }
  }
  if (!aborted && (!requestFinished || !resultFinished)) fail('staged CELL.PUT exchange is incomplete')
  return Object.freeze({ requestBytes, resultBytes, requestFinished, resultFinished, aborted })
}

export function verifyStagedCellPutPublicOuterEnvelopeV2 (input, openInput, direction, requestId = null) {
  const open = openInput && openInput.context ? openInput : decodeLocalStagedCellPutOpenV2(openInput)
  direction = exactEnum(LOCAL_STAGED_DIRECTION_V2, direction, 'direction')
  let decoded
  try {
    decoded = decodeOuterEnvelope(asBuffer(input, 'public outer envelope'), { copyInner: false, copyBody: false })
  } catch {
    fail('staged CELL.PUT bytes are not one canonical public outer envelope')
  }
  if (decoded.outerClass !== open.outerClass || asBuffer(input, 'public outer envelope').byteLength !== open.requestEnvelopeBytes) {
    fail('staged CELL.PUT public outer envelope does not match the selected class')
  }
  const frame = decoded.frame
  if (frame.familyId !== FAMILY.CELL || frame.operationId !== OPERATION.CELL.PUT) {
    fail('staged public dispatch is not exact CELL.PUT')
  }
  if (frame.flags !== 0 || frame.streamId !== 0n || frame.sequence !== 0n) {
    fail('staged CELL.PUT requires unary zero-flags/stream/sequence invariants')
  }
  if (direction === LOCAL_STAGED_DIRECTION_V2.REQUEST) {
    if (frame.frameKind !== FRAME_KIND.REQUEST) fail('staged CELL.PUT request is not a REQUEST dispatch')
  } else {
    if (frame.frameKind !== FRAME_KIND.RESPONSE && frame.frameKind !== FRAME_KIND.ERROR) {
      fail('staged CELL.PUT result is not a RESPONSE or ERROR dispatch')
    }
    const expectedRequestId = fixed(requestId, 16, 'requestId')
    if (!b4a.equals(frame.requestId, expectedRequestId)) fail('staged CELL.PUT result requestId is not correlated')
  }
  return Object.freeze({ outerClass: decoded.outerClass, frame })
}

export function encodeLocalReadyProbeV2 (input) {
  if (!input || typeof input !== 'object') fail('local ready probe v2 must be an object')
  const accepted = u64(input.acceptedMonotonicMillis, 'acceptedMonotonicMillis')
  const deadline = u64(input.absoluteDeadlineMonotonicMillis, 'absoluteDeadlineMonotonicMillis')
  if (deadline !== accepted + BigInt(PRIVATE_IPC_V2_LIMITS.READY_DEADLINE_MILLIS)) {
    fail('local ready probe deadline must equal accepted+2000')
  }
  const featureBits = u32(input.edgeFeatureBits, 'edgeFeatureBits')
  const writeBits = u32(input.requestedWriteOperationBits, 'requestedWriteOperationBits')
  if (featureBits !== REQUIRED_LOCAL_IPC_FEATURE_BITS_V2 || writeBits !== CELL_PUT_OPERATION_BIT_V2) {
    fail('local ready probe must request the exact initial V2 feature and CELL.PUT write bits')
  }
  const output = b4a.alloc(PRIVATE_IPC_V2_LIMITS.READY_PROBE_BYTES)
  b4a.writeUInt32BE(output, output.byteLength - 4, 0)
  output[4] = 2
  output[5] = LOCAL_READY_CONTROL_KIND_V2.PROBE
  output[6] = u8(input.endpointId, 'endpointId', 1, 0xff)
  b4a.copy(fixed(input.edgeProcessNonce, 32, 'edgeProcessNonce'), output, 7)
  b4a.copy(fixed(input.launchTopologyHash, 32, 'launchTopologyHash'), output, 39)
  b4a.writeUInt32BE(output, featureBits, 71)
  b4a.writeUInt32BE(output, writeBits, 75)
  writeU64(output, accepted, 79)
  writeU64(output, deadline, 87)
  return output
}

export function readLocalReadyProbeLengthV2 (input) {
  return fixedDeclaredLength(input, PRIVATE_IPC_V2_LIMITS.READY_PROBE_BYTES, 7,
    'local ready probe v2 prefix/header', LOCAL_READY_CONTROL_KIND_V2.PROBE)
}

export function decodeLocalReadyProbeV2 (input) {
  readLocalReadyProbeLengthV2(input)
  const bytes = exactFrame(input, PRIVATE_IPC_V2_LIMITS.READY_PROBE_BYTES, 'local ready probe v2')
  if (bytes[4] !== 2) fail('local ready probe is not version 2', 'PRIVATE_IPC_V2_NO_FALLBACK')
  if (bytes[5] !== LOCAL_READY_CONTROL_KIND_V2.PROBE) fail('local ready probe has the wrong control kind')
  const value = {
    version: 2,
    controlKind: bytes[5],
    endpointId: bytes[6],
    edgeProcessNonce: b4a.from(bytes.subarray(7, 39)),
    launchTopologyHash: b4a.from(bytes.subarray(39, 71)),
    edgeFeatureBits: b4a.readUInt32BE(bytes, 71),
    requestedWriteOperationBits: b4a.readUInt32BE(bytes, 75),
    acceptedMonotonicMillis: readU64(bytes, 79),
    absoluteDeadlineMonotonicMillis: readU64(bytes, 87)
  }
  encodeLocalReadyProbeV2(value)
  return Object.freeze(value)
}

export function encodeLocalReadyAckV2 (input) {
  if (!input || typeof input !== 'object') fail('local ready ACK v2 must be an object')
  const readyRoleBits = u16(input.readyRoleBits, 'readyRoleBits')
  const readyOperationBits = u32(input.readyOperationBits, 'readyOperationBits')
  const readyWriteOperationBits = u32(input.readyWriteOperationBits, 'readyWriteOperationBits')
  const readyIpcFeatureBits = u32(input.readyIpcFeatureBits, 'readyIpcFeatureBits')
  if (readyWriteOperationBits !== CELL_PUT_OPERATION_BIT_V2 ||
      (readyWriteOperationBits & readyOperationBits) !== readyWriteOperationBits) {
    fail('ready write bits must be the exact initial CELL.PUT bit and a ready-operation subset')
  }
  if (readyIpcFeatureBits !== REQUIRED_LOCAL_IPC_FEATURE_BITS_V2) fail('ready IPC feature bits must equal the required V2 mask')
  if ((readyRoleBits & CELL_PUT_ENDPOINT_ROLE_BIT_V2) === 0) fail('ready role bits omit STORAGE')
  const output = b4a.alloc(PRIVATE_IPC_V2_LIMITS.READY_ACK_BYTES)
  b4a.writeUInt32BE(output, output.byteLength - 4, 0)
  output[4] = 2
  output[5] = LOCAL_READY_CONTROL_KIND_V2.ACK
  output[6] = u8(input.endpointId, 'endpointId', 1, 0xff)
  b4a.copy(fixed(input.edgeProcessNonce, 32, 'edgeProcessNonce'), output, 7)
  b4a.copy(fixed(input.launchTopologyHash, 32, 'launchTopologyHash'), output, 39)
  writeU64(output, u64(input.descriptorSequence, 'descriptorSequence', true), 71)
  b4a.copy(fixed(input.descriptorHash, 32, 'descriptorHash'), output, 79)
  writeU16(output, readyRoleBits, 111)
  b4a.writeUInt32BE(output, readyOperationBits, 113)
  b4a.writeUInt32BE(output, readyWriteOperationBits, 117)
  b4a.writeUInt32BE(output, readyIpcFeatureBits, 121)
  writeU64(output, u64(input.expiresMonotonicMillis, 'expiresMonotonicMillis', true), 125)
  return output
}

export function readLocalReadyAckLengthV2 (input) {
  return fixedDeclaredLength(input, PRIVATE_IPC_V2_LIMITS.READY_ACK_BYTES, 7,
    'local ready ACK v2 prefix/header', LOCAL_READY_CONTROL_KIND_V2.ACK)
}

export function decodeLocalReadyAckV2 (input) {
  readLocalReadyAckLengthV2(input)
  const bytes = exactFrame(input, PRIVATE_IPC_V2_LIMITS.READY_ACK_BYTES, 'local ready ACK v2')
  if (bytes[4] !== 2) fail('local ready ACK is not version 2', 'PRIVATE_IPC_V2_NO_FALLBACK')
  if (bytes[5] !== LOCAL_READY_CONTROL_KIND_V2.ACK) fail('local ready ACK has the wrong control kind')
  const value = {
    version: 2,
    controlKind: bytes[5],
    endpointId: bytes[6],
    edgeProcessNonce: b4a.from(bytes.subarray(7, 39)),
    launchTopologyHash: b4a.from(bytes.subarray(39, 71)),
    descriptorSequence: readU64(bytes, 71),
    descriptorHash: b4a.from(bytes.subarray(79, 111)),
    readyRoleBits: readU16(bytes, 111),
    readyOperationBits: b4a.readUInt32BE(bytes, 113),
    readyWriteOperationBits: b4a.readUInt32BE(bytes, 117),
    readyIpcFeatureBits: b4a.readUInt32BE(bytes, 121),
    expiresMonotonicMillis: readU64(bytes, 125)
  }
  encodeLocalReadyAckV2(value)
  return Object.freeze(value)
}

export function localReadyDecisionV2 (probeInput, ackInput, descriptor, nowMonotonicMillis) {
  const probe = probeInput && probeInput.version === 2 ? probeInput : decodeLocalReadyProbeV2(probeInput)
  const ack = ackInput && ackInput.version === 2 ? ackInput : decodeLocalReadyAckV2(ackInput)
  const now = u64(nowMonotonicMillis, 'nowMonotonicMillis')
  const reasons = []
  if (probe.endpointId !== ack.endpointId) reasons.push('endpoint-mismatch')
  if (!b4a.equals(probe.edgeProcessNonce, ack.edgeProcessNonce)) reasons.push('edge-nonce-mismatch')
  if (!b4a.equals(probe.launchTopologyHash, ack.launchTopologyHash)) reasons.push('topology-mismatch')
  if (now > probe.absoluteDeadlineMonotonicMillis || now > ack.expiresMonotonicMillis) reasons.push('expired')
  if (!descriptor || typeof descriptor !== 'object') reasons.push('descriptor-absent')
  else {
    const sequence = u64(descriptor.sequence, 'descriptor.sequence', true)
    const expires = u64(descriptor.expiresMonotonicMillis, 'descriptor.expiresMonotonicMillis', true)
    const descriptorHash = fixed(descriptor.hash, 32, 'descriptor.hash')
    const roleBits = u16(descriptor.roleBits, 'descriptor.roleBits')
    const operationBits = u32(descriptor.enabledOperationBits, 'descriptor.enabledOperationBits')
    if (ack.descriptorSequence !== sequence || !b4a.equals(ack.descriptorHash, descriptorHash)) reasons.push('descriptor-freshness-mismatch')
    if ((ack.readyRoleBits & ~roleBits) !== 0 || (ack.readyRoleBits & CELL_PUT_ENDPOINT_ROLE_BIT_V2) === 0) reasons.push('descriptor-role-subset-mismatch')
    if ((ack.readyOperationBits & ~operationBits) !== 0 || (ack.readyWriteOperationBits & ~operationBits) !== 0) reasons.push('descriptor-operation-subset-mismatch')
    if (ack.expiresMonotonicMillis > expires) reasons.push('descriptor-expiry-mismatch')
  }
  if (probe.edgeFeatureBits !== REQUIRED_LOCAL_IPC_FEATURE_BITS_V2 ||
      ack.readyIpcFeatureBits !== REQUIRED_LOCAL_IPC_FEATURE_BITS_V2) reasons.push('feature-bits-missing-or-unknown')
  if (probe.requestedWriteOperationBits !== CELL_PUT_OPERATION_BIT_V2 ||
      ack.readyWriteOperationBits !== CELL_PUT_OPERATION_BIT_V2 ||
      (ack.readyWriteOperationBits & ack.readyOperationBits) !== ack.readyWriteOperationBits) reasons.push('write-readiness-mismatch')
  return Object.freeze({ ready: reasons.length === 0, reasons: Object.freeze(reasons) })
}

export function localIpcChannelClassForOuterClassV2 (outerClass) {
  u8(outerClass, 'outerClass', 1, 6)
  return LOCAL_IPC_CHANNEL_CLASS_V2.LOCAL_64K
}

export function cellPutWorstCaseResultFitsOuterClassV2 (outerClass) {
  return cellPutPredictedResultFitsOuterClassV2(outerClass, PRIVATE_IPC_V2_LIMITS.CELL_PUT_MAX_RESULT_BODY_BYTES)
}

export function cellPutPredictedResultFitsOuterClassV2 (outerClass, authenticatedPredictedResultBodyBytes) {
  outerClass = u8(outerClass, 'outerClass', 1, 6)
  const bodyBytes = u32(authenticatedPredictedResultBodyBytes, 'authenticatedPredictedResultBodyBytes')
  if (bodyBytes > PRIVATE_IPC_V2_LIMITS.CELL_PUT_MAX_RESULT_BODY_BYTES) {
    fail('authenticated predicted CELL.PUT result exceeds the generated public operation cap')
  }
  return PRIVATE_IPC_V2_LIMITS.OUTER_HEADER_BYTES + PRIVATE_IPC_V2_LIMITS.DISPATCH_HEADER_BYTES + bodyBytes <= OUTER_CLASS[outerClass]
}

export function assertPrecommitCellPutResultFitV2 (
  outerClass,
  authenticatedPredictedResultBodyBytes = PRIVATE_IPC_V2_LIMITS.CELL_PUT_MAX_RESULT_BODY_BYTES
) {
  if (!cellPutPredictedResultFitsOuterClassV2(outerClass, authenticatedPredictedResultBodyBytes)) {
    fail('authenticated predicted CELL.PUT correlated result does not fit selected outer class before commit', 'PRIVATE_IPC_V2_PRECOMMIT_RESULT_CLASS')
  }
  return outerClass
}

export const PRIVATE_IPC_V2_CONTRACT = Object.freeze({
  magic: PRIVATE_IPC_V2_MAGIC,
  formatVersion: PRIVATE_IPC_V2_FORMAT_VERSION,
  schemaIds: Object.freeze(PRIVATE_IPC_V2_ADDITIONAL_SCHEMAS.map(schema => schema.schemaId)),
  schemaCount: PRIVATE_IPC_V2_SCHEMAS.length,
  v1SchemaCount: PRIVATE_IPC_SCHEMAS.length,
  v1FallbackPermitted: false,
  publicWireOperation: Object.freeze({
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    operationBit: CELL_PUT_OPERATION_BIT_V2,
    requestFrameKind: FRAME_KIND.REQUEST,
    resultFrameKinds: Object.freeze([FRAME_KIND.RESPONSE, FRAME_KIND.ERROR]),
    endpointRoleBit: ENDPOINT_ROLE.STORAGE
  }),
  httpsTransport: Object.freeze({
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    authorityKind: LOCAL_TRANSPORT_AUTHORITY_KIND_V2.TLS_EXPORTER_BY_PEERCRED_EDGE,
    tlsExporterLabel: TLS_EXPORTER_LABEL_V2,
    tlsExporterBytes: PRIVATE_IPC_V2_LIMITS.TLS_EXPORTER_BYTES
  }),
  localChannelClassByOuterClass: Object.freeze(Object.fromEntries(
    Object.keys(OUTER_CLASS).map(outerClass => [outerClass, LOCAL_IPC_CHANNEL_CLASS_V2.LOCAL_64K])
  )),
  precommitOrder: Object.freeze([
    'peer-credentials', 'exact-shape', 'transport-profile', 'topology', 'endpoint',
    'deadline', 'replay-consume', 'open-binding', 'outer-request-decode',
    'same-class-result-fit', 'admission', 'publish-or-wal-or-spend-or-sign'
  ]),
  requiredFeatureBits: REQUIRED_LOCAL_IPC_FEATURE_BITS_V2,
  limits: PRIVATE_IPC_V2_LIMITS
})

export { LOCAL_ABORT_CODE, OUTER_CLASS, STREAM_WIRE_CLASS, TRANSPORT_ID, TRANSPORT_SUPPORT }
