import b4a from 'b4a'
import {
  FAMILY,
  OUTER_CLASS,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT
} from '@hiverelay/blind-protocol/wire-runtime-authority'
import { PRIVATE_IPC_LIMITS, PRIVATE_IPC_TIMING_MILLIS } from './policy.js'

export const LOCAL_FRAME_PREFIX_BYTES = 4
export const LOCAL_DISPATCH_BASE_HEADER_BYTES = PRIVATE_IPC_LIMITS.UNARY_BASE_HEADER_BYTES
export const LOCAL_DISPATCH_ADJACENT_HEADER_BYTES = PRIVATE_IPC_LIMITS.UNARY_ADJACENT_HEADER_BYTES
export const LOCAL_RESPONSE_HEADER_BYTES = PRIVATE_IPC_LIMITS.UNARY_RESPONSE_HEADER_BYTES
export const LOCAL_STREAM_FRAME_HEADER_BYTES = PRIVATE_IPC_LIMITS.STREAM_FRAME_HEADER_BYTES
export const MAX_LOCAL_BODY_BYTES = Math.max(...Object.values(OUTER_CLASS))
export const LOCAL_READY_PROBE_BODY_BYTES = PRIVATE_IPC_LIMITS.READY_PROBE_BODY_BYTES
export const LOCAL_READY_ACK_BODY_BYTES = PRIVATE_IPC_LIMITS.READY_ACK_BODY_BYTES
const MAX_U64 = (1n << 64n) - 1n

export const LOCAL_RESPONSE_KIND = Object.freeze({
  EXTERNAL_CANONICAL: 1,
  LOCAL_BROKER_ERROR: 2,
  LOCAL_READY_ACK: 3
})

export const LOCAL_CONTROL_KIND = Object.freeze({ EDGE_READY: 1 })

export const LOCAL_BROKER_ERROR = Object.freeze({
  MALFORMED_IPC: 1,
  UNAUTHORIZED_EDGE_PEER: 2,
  TOPOLOGY_PROFILE_ENDPOINT_MISMATCH: 3,
  CLASS_LENGTH_CAP: 4,
  DAEMON_DRAINING: 5,
  INTERNAL_IPC_FAILURE: 6
})

export const PRIVATE_IPC_STATUS = Object.freeze({
  profile: 'private-ipc-authority-v1',
  authorityArtifactPath: 'packages/blind-ipc/hiverelay-blind-private-ipc-v1.cenc',
  vectorManifestPath: 'packages/blind-ipc/vector-manifest-v1.cenc',
  authorityMetadataPath: 'packages/blind-ipc/hiverelay-blind-private-ipc-authority-v1.json',
  importedWireAbiHash: 'aaf29c8225ee33a59a02f1d27b898aa5b4f9aec005c6e509dee450ffc87b1b0d',
  privateIpcFormatHash: '02aa29d91367bbb9a6ade977017a148cd78e7c184a4234084b82498ef5cc2bed',
  privateIpcVectorSetHash: 'fa58b38f6edf4a9d0390c7af7f454150ccfe2d1398b105686ff8e0f2883893cb',
  schemaCount: 7,
  vectorCount: 79,
  requiredSchemaNames: Object.freeze([
    'LocalDispatchV1',
    'LocalUnaryResponseV1',
    'LocalStreamOpenV1',
    'LocalStreamFrameV1',
    'LocalAuthenticatedChannelV1',
    'LocalStreamAttachContextV1',
    'LocalStreamControlV1'
  ]),
  implementedSchemaNames: Object.freeze([
    'LocalDispatchV1',
    'LocalUnaryResponseV1',
    'LocalStreamOpenV1',
    'LocalStreamFrameV1',
    'LocalAuthenticatedChannelV1',
    'LocalStreamAttachContextV1',
    'LocalStreamControlV1'
  ]),
  missingSchemaNames: Object.freeze([]),
  releaseBlockers: Object.freeze([]),
  releaseReady: true
})

export function assertPrivateIpcReady () {
  if (PRIVATE_IPC_STATUS.releaseReady) return
  const error = new Error(`blind private IPC authority is incomplete; ${PRIVATE_IPC_STATUS.releaseBlockers.length} release blockers remain`)
  error.code = 'BLIND_PRIVATE_IPC_INCOMPLETE'
  error.missingSchemaNames = [...PRIVATE_IPC_STATUS.missingSchemaNames]
  error.releaseBlockers = [...PRIVATE_IPC_STATUS.releaseBlockers]
  throw error
}

export * from './private-ipc-v3-contract.js'
export * from './private-ipc-v3-status.js'
export * from './private-ipc-v4-contract.js'
export * from './private-ipc-v4-status.js'

function fail (message) {
  const error = new Error(message)
  error.code = 'BAD_LOCAL_DISPATCH'
  throw error
}

function asBuffer (value, field) {
  if (!value || typeof value.byteLength !== 'number') fail(`${field} must be bytes`)
  if (b4a.isBuffer(value)) return value
  if (ArrayBuffer.isView(value)) return b4a.from(value.buffer, value.byteOffset, value.byteLength)
  return b4a.from(value)
}

function snapshotBuffer (value, field) {
  return b4a.from(asBuffer(value, field))
}

function isZero (value) {
  for (const byte of value) if (byte !== 0) return false
  return true
}

function knownValue (registry, value, field) {
  if (!Number.isInteger(value) || !Object.values(registry).includes(value)) fail(`${field} is not registered`)
  return value
}

function oneHotTransportSupport (value) {
  const mask = Object.values(TRANSPORT_SUPPORT).reduce((sum, bit) => sum | bit, 0)
  if (!Number.isInteger(value) || value < 1 || value > 0xffff ||
      (value & (value - 1)) !== 0 || (value & ~mask) !== 0) {
    fail('transportSupportBit must be one explicit registered one-hot bit')
  }
  return value
}

function endpointId (value) {
  if (!Number.isInteger(value) || value < 1 || value > 0xff) fail('endpointId is outside 1..255')
  return value
}

function classForLength (length) {
  for (const [id, bytes] of Object.entries(OUTER_CLASS)) {
    if (bytes === length) return Number(id)
  }
  return null
}

function asU64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${field} must be an unsigned safe integer or bigint`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > ((1n << 64n) - 1n)) fail(`${field} is outside u64`)
  return value
}

function readU64BE (buffer, offset) {
  let value = 0n
  for (let index = 0; index < 8; index++) value = (value << 8n) | BigInt(buffer[offset + index])
  return value
}

function writeU64BE (buffer, value, offset) {
  for (let index = 7; index >= 0; index--) {
    buffer[offset + index] = Number(value & 0xffn)
    value >>= 8n
  }
}

export function encodeLocalReadyProbeBody (input) {
  if (!input || typeof input !== 'object') fail('ready probe must be an object')
  const edgeInstanceNonce = snapshotBuffer(input.edgeInstanceNonce, 'edgeInstanceNonce')
  const launchTopologyHash = snapshotBuffer(input.launchTopologyHash, 'launchTopologyHash')
  if (edgeInstanceNonce.byteLength !== 32) fail('edgeInstanceNonce must be exactly 32 bytes')
  if (launchTopologyHash.byteLength !== 32) fail('launchTopologyHash must be exactly 32 bytes')
  const output = b4a.alloc(LOCAL_READY_PROBE_BODY_BYTES)
  output[0] = LOCAL_CONTROL_KIND.EDGE_READY
  b4a.copy(edgeInstanceNonce, output, 1)
  b4a.copy(launchTopologyHash, output, 33)
  return output
}

export function decodeLocalReadyProbeBody (input) {
  const body = snapshotBuffer(input, 'ready probe')
  if (body.byteLength !== LOCAL_READY_PROBE_BODY_BYTES || body[0] !== LOCAL_CONTROL_KIND.EDGE_READY) {
    fail('ready probe has an invalid control shape')
  }
  return {
    controlKind: LOCAL_CONTROL_KIND.EDGE_READY,
    edgeInstanceNonce: b4a.from(body.subarray(1, 33)),
    launchTopologyHash: b4a.from(body.subarray(33, 65))
  }
}

export function encodeLocalReadyAckBody (input) {
  if (!input || typeof input !== 'object') fail('ready ACK must be an object')
  const edgeInstanceNonce = snapshotBuffer(input.edgeInstanceNonce, 'edgeInstanceNonce')
  const launchTopologyHash = snapshotBuffer(input.launchTopologyHash, 'launchTopologyHash')
  const descriptorHash = snapshotBuffer(input.descriptorHash, 'descriptorHash')
  if (edgeInstanceNonce.byteLength !== 32) fail('edgeInstanceNonce must be exactly 32 bytes')
  if (launchTopologyHash.byteLength !== 32) fail('launchTopologyHash must be exactly 32 bytes')
  if (descriptorHash.byteLength !== 32) fail('descriptorHash must be exactly 32 bytes')
  const endpoint = endpointId(input.endpointId)
  const descriptorSequence = asU64(input.descriptorSequence, 'descriptorSequence')
  const expiresMonotonicMillis = asU64(input.expiresMonotonicMillis, 'expiresMonotonicMillis')
  if (!Number.isInteger(input.readyRoleBits) || input.readyRoleBits < 0 || input.readyRoleBits > 0xffff) {
    fail('readyRoleBits is outside u16')
  }
  if (!Number.isInteger(input.readyOperationBits) || input.readyOperationBits < 0 || input.readyOperationBits > 0xffffffff) {
    fail('readyOperationBits is outside u32')
  }
  const output = b4a.alloc(LOCAL_READY_ACK_BODY_BYTES)
  output[0] = LOCAL_CONTROL_KIND.EDGE_READY
  b4a.copy(edgeInstanceNonce, output, 1)
  b4a.copy(launchTopologyHash, output, 33)
  output[65] = endpoint
  writeU64BE(output, descriptorSequence, 66)
  b4a.copy(descriptorHash, output, 74)
  output[106] = input.readyRoleBits >>> 8
  output[107] = input.readyRoleBits & 0xff
  b4a.writeUInt32BE(output, input.readyOperationBits, 108)
  writeU64BE(output, expiresMonotonicMillis, 112)
  return output
}

export function decodeLocalReadyAckBody (input) {
  const body = snapshotBuffer(input, 'ready ACK')
  if (body.byteLength !== LOCAL_READY_ACK_BODY_BYTES || body[0] !== LOCAL_CONTROL_KIND.EDGE_READY) {
    fail('ready ACK has an invalid control shape')
  }
  return {
    controlKind: LOCAL_CONTROL_KIND.EDGE_READY,
    edgeInstanceNonce: b4a.from(body.subarray(1, 33)),
    launchTopologyHash: b4a.from(body.subarray(33, 65)),
    endpointId: endpointId(body[65]),
    descriptorSequence: readU64BE(body, 66),
    descriptorHash: b4a.from(body.subarray(74, 106)),
    readyRoleBits: (body[106] << 8) | body[107],
    readyOperationBits: b4a.readUInt32BE(body, 108),
    expiresMonotonicMillis: readU64BE(body, 112)
  }
}

function declaredFrameLength (buffer, field) {
  if (buffer.byteLength < LOCAL_FRAME_PREFIX_BYTES) return null
  const totalLength = b4a.readUInt32BE(buffer, 0)
  if (totalLength > LOCAL_DISPATCH_ADJACENT_HEADER_BYTES - LOCAL_FRAME_PREFIX_BYTES + MAX_LOCAL_BODY_BYTES) {
    fail(`${field} totalLength exceeds the private IPC cap`)
  }
  return LOCAL_FRAME_PREFIX_BYTES + totalLength
}

export function localRequestFrameLength (input) {
  const buffer = asBuffer(input, 'local request')
  const frameLength = declaredFrameLength(buffer, 'local request')
  if (frameLength == null || buffer.byteLength < 28) return null
  if (buffer[4] !== 1) fail('local dispatch version must be 1')
  if (buffer[27] > 1) fail('adjacentRelayKey presence tag must be 0 or 1')
  const family = knownValue(FAMILY, buffer[5], 'family')
  const transportId = buffer[6]
  const transportSupportBit = (buffer[7] << 8) | buffer[8]
  endpointId(buffer[9])
  const outerClass = buffer[10]
  const accepted = readU64BE(buffer, 11)
  const deadline = readU64BE(buffer, 19)
  if (deadline <= accepted) fail('absoluteDeadlineMonotonicMillis must be after acceptedMonotonicMillis')
  const adjacentPresent = buffer[27] === 1
  const control = transportId === 0 || transportSupportBit === 0 || outerClass === 0
  if (control) {
    if (family !== FAMILY.DESCRIBE || transportId !== 0 || transportSupportBit !== 0 || outerClass !== 0 || adjacentPresent) {
      fail('local readiness control tuple is invalid')
    }
  } else {
    knownValue(TRANSPORT_ID, transportId, 'transportId')
    oneHotTransportSupport(transportSupportBit)
    if (!OUTER_CLASS[outerClass]) fail('outerClass is not registered')
  }
  const headerBytes = adjacentPresent ? LOCAL_DISPATCH_ADJACENT_HEADER_BYTES : LOCAL_DISPATCH_BASE_HEADER_BYTES
  if (frameLength < headerBytes) fail('local request totalLength is shorter than its header')
  if (buffer.byteLength < headerBytes) return null
  if (adjacentPresent && isZero(buffer.subarray(28, 60))) fail('adjacentRelayKey must be nonzero')
  const bodyLengthOffset = adjacentPresent ? 60 : 28
  const bodyLength = b4a.readUInt32BE(buffer, bodyLengthOffset)
  if (control) {
    if (bodyLength !== LOCAL_READY_PROBE_BODY_BYTES || deadline - accepted !== BigInt(PRIVATE_IPC_TIMING_MILLIS.READY_PROBE_ABSOLUTE)) {
      fail('local readiness control body or deadline is invalid')
    }
  } else if (!classForLength(bodyLength)) fail('local request body length is not an outer class')
  if (frameLength !== headerBytes + bodyLength) fail('local request totalLength does not match its fields')
  if (control && buffer.byteLength >= frameLength) decodeLocalReadyProbeBody(buffer.subarray(headerBytes, frameLength))
  return frameLength
}

export function encodeLocalRequest (input) {
  if (!input || typeof input !== 'object') fail('local request must be an object')
  const family = knownValue(FAMILY, input.family, 'family')
  const transportId = input.transportId
  const transportSupportBit = input.transportSupportBit
  const endpoint = endpointId(input.endpointId)
  const outerClass = Number(input.outerClass)
  const acceptedMonotonicMillis = asU64(input.acceptedMonotonicMillis, 'acceptedMonotonicMillis')
  const absoluteDeadlineMonotonicMillis = asU64(input.absoluteDeadlineMonotonicMillis, 'absoluteDeadlineMonotonicMillis')
  if (absoluteDeadlineMonotonicMillis <= acceptedMonotonicMillis) {
    fail('absoluteDeadlineMonotonicMillis must be after acceptedMonotonicMillis')
  }
  const adjacentRelayKeyValue = input.adjacentRelayKey
  const adjacentRelayKey = adjacentRelayKeyValue == null ? null : snapshotBuffer(adjacentRelayKeyValue, 'adjacentRelayKey')
  if (adjacentRelayKey && adjacentRelayKey.byteLength !== 32) fail('adjacentRelayKey must be exactly 32 bytes')
  if (adjacentRelayKey && isZero(adjacentRelayKey)) fail('adjacentRelayKey must be nonzero')
  const bodyValue = input.body
  const body = snapshotBuffer(bodyValue == null ? input.externalCanonicalBytes : bodyValue, 'externalCanonicalBytes')
  const control = transportId === 0 || transportSupportBit === 0 || outerClass === 0
  if (control) {
    if (family !== FAMILY.DESCRIBE || transportId !== 0 || transportSupportBit !== 0 || outerClass !== 0 || adjacentRelayKey) {
      fail('local readiness control tuple is invalid')
    }
    if (absoluteDeadlineMonotonicMillis - acceptedMonotonicMillis !== BigInt(PRIVATE_IPC_TIMING_MILLIS.READY_PROBE_ABSOLUTE)) {
      fail('local readiness control deadline must be exactly two seconds')
    }
    decodeLocalReadyProbeBody(body)
  } else {
    knownValue(TRANSPORT_ID, transportId, 'transportId')
    oneHotTransportSupport(transportSupportBit)
    if (!OUTER_CLASS[outerClass]) fail('outerClass is not registered')
    if (body.byteLength !== OUTER_CLASS[outerClass]) fail('body length does not match outerClass')
  }

  const headerBytes = adjacentRelayKey ? LOCAL_DISPATCH_ADJACENT_HEADER_BYTES : LOCAL_DISPATCH_BASE_HEADER_BYTES
  const output = b4a.alloc(headerBytes + body.byteLength)
  b4a.writeUInt32BE(output, output.byteLength - LOCAL_FRAME_PREFIX_BYTES, 0)
  output[4] = 1
  output[5] = family
  output[6] = transportId
  output[7] = transportSupportBit >>> 8
  output[8] = transportSupportBit & 0xff
  output[9] = endpoint
  output[10] = outerClass
  writeU64BE(output, acceptedMonotonicMillis, 11)
  writeU64BE(output, absoluteDeadlineMonotonicMillis, 19)
  output[27] = adjacentRelayKey ? 1 : 0
  let offset = 28
  if (adjacentRelayKey) {
    b4a.copy(adjacentRelayKey, output, offset)
    offset += adjacentRelayKey.byteLength
  }
  b4a.writeUInt32BE(output, body.byteLength, offset)
  b4a.copy(body, output, offset + 4)
  return output
}

export function decodeLocalRequest (input, options = {}) {
  const buffer = snapshotBuffer(input, 'local request')
  const expectedLength = localRequestFrameLength(buffer)
  if (expectedLength == null || buffer.byteLength < expectedLength) fail('local request is truncated')
  if (buffer.byteLength !== expectedLength) fail('local request length mismatch or trailing bytes')

  const family = knownValue(FAMILY, buffer[5], 'family')
  const transportId = buffer[6]
  const transportSupportBit = (buffer[7] << 8) | buffer[8]
  const endpoint = endpointId(buffer[9])
  const outerClass = buffer[10]
  const control = transportId === 0 || transportSupportBit === 0 || outerClass === 0
  if (!control) {
    knownValue(TRANSPORT_ID, transportId, 'transportId')
    oneHotTransportSupport(transportSupportBit)
    if (!OUTER_CLASS[outerClass]) fail('outerClass is not registered')
  }
  const adjacentPresent = buffer[27] === 1
  const bodyOffset = adjacentPresent ? LOCAL_DISPATCH_ADJACENT_HEADER_BYTES : LOCAL_DISPATCH_BASE_HEADER_BYTES
  const body = options.copyBody === true ? b4a.from(buffer.subarray(bodyOffset)) : buffer.subarray(bodyOffset)
  if (!control && body.byteLength !== OUTER_CLASS[outerClass]) fail('body length does not match outerClass')

  const decoded = {
    version: 1,
    family,
    transportId,
    transportSupportBit,
    endpointId: endpoint,
    outerClass,
    acceptedMonotonicMillis: readU64BE(buffer, 11),
    absoluteDeadlineMonotonicMillis: readU64BE(buffer, 19),
    adjacentRelayKey: adjacentPresent ? b4a.from(buffer.subarray(28, 60)) : null,
    externalCanonicalBytes: body
  }
  if (control) decoded.readyProbe = decodeLocalReadyProbeBody(body)
  return decoded
}

export function encodeLocalReadyProbe (input) {
  if (!input || typeof input !== 'object') fail('ready probe must be an object')
  const acceptedMonotonicMillis = asU64(input.acceptedMonotonicMillis, 'acceptedMonotonicMillis')
  if (acceptedMonotonicMillis > MAX_U64 - BigInt(PRIVATE_IPC_TIMING_MILLIS.READY_PROBE_ABSOLUTE)) {
    fail('ready probe deadline overflows u64')
  }
  return encodeLocalRequest({
    family: FAMILY.DESCRIBE,
    transportId: 0,
    transportSupportBit: 0,
    endpointId: input.endpointId,
    outerClass: 0,
    acceptedMonotonicMillis,
    absoluteDeadlineMonotonicMillis: acceptedMonotonicMillis + BigInt(PRIVATE_IPC_TIMING_MILLIS.READY_PROBE_ABSOLUTE),
    body: encodeLocalReadyProbeBody(input)
  })
}

export function localResponseFrameLength (input) {
  const buffer = asBuffer(input, 'local response')
  const frameLength = declaredFrameLength(buffer, 'local response')
  if (frameLength == null || buffer.byteLength < LOCAL_RESPONSE_HEADER_BYTES) return null
  if (buffer[4] !== 1) fail('local response version must be 1')
  const kind = buffer[5]
  const localError = buffer[6]
  const bodyLength = b4a.readUInt32BE(buffer, 7)
  if (kind === LOCAL_RESPONSE_KIND.EXTERNAL_CANONICAL) {
    if (localError !== 0 || !classForLength(bodyLength)) fail('external local response shape is invalid')
  } else if (kind === LOCAL_RESPONSE_KIND.LOCAL_BROKER_ERROR) {
    if (!Object.values(LOCAL_BROKER_ERROR).includes(localError) || bodyLength !== 0) fail('local broker error shape is invalid')
  } else if (kind === LOCAL_RESPONSE_KIND.LOCAL_READY_ACK) {
    if (localError !== 0 || bodyLength !== LOCAL_READY_ACK_BODY_BYTES) fail('local ready ACK shape is invalid')
  } else fail('local response kind is not registered')
  if (frameLength !== LOCAL_RESPONSE_HEADER_BYTES + bodyLength) fail('local response totalLength does not match its fields')
  if (kind === LOCAL_RESPONSE_KIND.LOCAL_READY_ACK && buffer.byteLength >= frameLength) {
    decodeLocalReadyAckBody(buffer.subarray(LOCAL_RESPONSE_HEADER_BYTES, frameLength))
  }
  return frameLength
}

export function encodeLocalResponse (input, options = {}) {
  let responseKind = options.responseKind == null ? LOCAL_RESPONSE_KIND.EXTERNAL_CANONICAL : options.responseKind
  let localBrokerError = options.localBrokerError == null ? 0 : options.localBrokerError
  let body = input
  if (input && typeof input === 'object' && typeof input.byteLength !== 'number' && !ArrayBuffer.isView(input)) {
    responseKind = input.responseKind
    localBrokerError = input.localBrokerError
    body = input.body == null ? input.externalCanonicalBytes : input.body
  }
  if (responseKind === LOCAL_RESPONSE_KIND.EXTERNAL_CANONICAL) {
    body = snapshotBuffer(body, 'externalCanonicalBytes')
    if (localBrokerError !== 0 || !classForLength(body.byteLength)) fail('external local response shape is invalid')
    if (options.outerClass != null && body.byteLength !== OUTER_CLASS[options.outerClass]) fail('response body does not match selected outerClass')
  } else if (responseKind === LOCAL_RESPONSE_KIND.LOCAL_BROKER_ERROR) {
    if (!Object.values(LOCAL_BROKER_ERROR).includes(localBrokerError)) fail('localBrokerError is not registered')
    body = b4a.alloc(0)
  } else if (responseKind === LOCAL_RESPONSE_KIND.LOCAL_READY_ACK) {
    body = snapshotBuffer(body, 'ready ACK')
    if (localBrokerError !== 0) fail('local ready ACK cannot carry a broker error')
    decodeLocalReadyAckBody(body)
  } else fail('local response kind is not registered')

  const output = b4a.alloc(LOCAL_RESPONSE_HEADER_BYTES + body.byteLength)
  b4a.writeUInt32BE(output, output.byteLength - LOCAL_FRAME_PREFIX_BYTES, 0)
  output[4] = 1
  output[5] = responseKind
  output[6] = localBrokerError
  b4a.writeUInt32BE(output, body.byteLength, 7)
  if (body.byteLength > 0) b4a.copy(body, output, LOCAL_RESPONSE_HEADER_BYTES)
  return output
}

export function decodeLocalResponse (input, options = {}) {
  const buffer = snapshotBuffer(input, 'local response')
  const expectedLength = localResponseFrameLength(buffer)
  if (expectedLength == null || buffer.byteLength < expectedLength) fail('local response is truncated')
  if (buffer.byteLength !== expectedLength) fail('local response length mismatch or trailing bytes')
  const view = buffer.subarray(LOCAL_RESPONSE_HEADER_BYTES)
  const body = options.copyBody === true ? b4a.from(view) : view
  const decoded = {
    version: 1,
    responseKind: buffer[5],
    localBrokerError: buffer[6],
    externalCanonicalBytes: body
  }
  if (decoded.responseKind === LOCAL_RESPONSE_KIND.LOCAL_READY_ACK) {
    decoded.readyAck = decodeLocalReadyAckBody(body)
  }
  return decoded
}

export function encodeLocalReadyAck (input) {
  return encodeLocalResponse({
    responseKind: LOCAL_RESPONSE_KIND.LOCAL_READY_ACK,
    localBrokerError: 0,
    body: encodeLocalReadyAckBody(input)
  })
}

export * from './registry.js'
export * from './policy.js'
export * from './stream.js'
export * from './framing-vectors.js'
