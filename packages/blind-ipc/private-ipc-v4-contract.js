import b4a from 'b4a'
import c from 'compact-encoding'
import {
  FORWARD_HTTPS_REQUEST_KIND_V1,
  FORWARD_HTTPS_REQUEST_ROLE_V1,
  FORWARD_HTTPS_RESPONSE_KIND_V1,
  assertForwardHttpsForwardedRequestAuthorityV1,
  assertForwardHttpsTargetResultForForwardedRequestV1,
  blindForwardHttpsOriginForwardTurnRequestV1,
  blindForwardHttpsOriginForwardTurnResultV1,
  forwardHttpsForwardedRequestCommitmentV1,
  forwardHttpsOriginRequestCommitmentV1,
  forwardHttpsTargetResultChainHashV1
} from '@hiverelay/blind-protocol'
import { decodeCanonical } from '@hiverelay/blind-protocol/codec'
import { privateBlake2b256 } from './private-hashes.js'

const MAX_U64 = (1n << 64n) - 1n
const ZERO_32 = b4a.alloc(32)
const ORIGIN_AUTHORITY_MAGIC = b4a.from('LFA4', 'ascii')
const TURN_MAGIC = b4a.from('LFT4', 'ascii')
const TARGET_INGRESS_MAGIC = b4a.from('LTI4', 'ascii')
const FORMAT_DOMAIN = b4a.from('hiverelay.blind.private-ipc-format-hash.v4', 'ascii')
const VECTOR_DOMAIN = b4a.from('hiverelay.blind.private-ipc-vector-set-hash.v4', 'ascii')
const SOURCE_EXCHANGE_DOMAIN = b4a.from('hiverelay.blind.private-ipc-forward-exchange.v4', 'ascii')
const TARGET_EXCHANGE_DOMAIN = b4a.from('hiverelay.blind.private-ipc-forward-target-exchange.v4', 'ascii')
const SOURCE_REPLAY_DOMAIN = b4a.from('hiverelay.blind.private-ipc-forward-replay.v4', 'ascii')
const TARGET_REPLAY_DOMAIN = b4a.from('hiverelay.blind.private-ipc-forward-target-replay.v4', 'ascii')
const TARGET_TLS_CONTEXT_DOMAIN = b4a.from('hiverelay.blind.private-ipc-forward-target-tls-context.v4', 'ascii')
const TARGET_TLS_BINDING_DOMAIN = b4a.from('hiverelay.blind.private-ipc-forward-target-tls-binding.v4', 'ascii')
const JOURNAL_SNAPSHOT_DOMAIN = b4a.from('hiverelay.blind.private-ipc-forward-journal-model.v4', 'ascii')

export const PRIVATE_IPC_V4_MAGIC = 'hiverelay-blind-private-ipc-v4'
export const PRIVATE_IPC_V4_FORMAT_VERSION = 4
export const FORWARD_HTTPS_TARGET_TLS_EXPORTER_LABEL_V4 = 'EXPORTER-HiveRelay-Blind-Forward-Target-v1'

export const PRIVATE_IPC_V4_SCHEMA = Object.freeze({
  LocalForwardHttpsOriginAuthorityV4: 16,
  LocalForwardHttpsTurnV4: 17,
  LocalForwardHttpsTargetIngressV4: 18
})

export const LOCAL_FORWARD_HTTPS_DIRECTION_V4 = Object.freeze({
  ORIGIN_REQUEST: 1,
  RESULT: 2
})

export const PRIVATE_IPC_V4_LIMITS = Object.freeze({
  ORIGIN_AUTHORITY_BYTES: 292,
  TURN_HEADER_BYTES: 148,
  TURN_BODY_BYTES: 65_536,
  TURN_BYTES: 65_684,
  TARGET_AUTHORITY_BYTES: 292,
  TARGET_INGRESS_BYTES: 65_828,
  SOURCE_ORIGIN_TRANSCRIPT_BYTES: 65_976,
  TARGET_INGRESS_TRANSCRIPT_BYTES: 65_828,
  RESULT_TRANSCRIPT_BYTES: 65_684,
  TARGET_LOCAL_REQUEST_PLUS_RESULT_BYTES: 131_512,
  EXCHANGE_PREIMAGE_BYTES: 260,
  REPLAY_PAYLOAD_BYTES: 232,
  REPLAY_CAPACITY: 4096,
  MAX_DEADLINE_MILLIS: 15_000
})

const targetDeclarationTail = Object.freeze([
  'targetTlsExporterLabel:ASCII(EXPORTER-HiveRelay-Blind-Forward-Target-v1)',
  'targetTlsExporterContext:BLAKE2b256(ASCII(hiverelay.blind.private-ipc-forward-target-tls-context.v4)||stableSessionId32||u64be(sequence)||forwardedRequestCommitment32)',
  'targetTlsExporterBindingHash:BLAKE2b256(ASCII(hiverelay.blind.private-ipc-forward-target-tls-binding.v4)||u64be(64)||targetTlsExporterSecret32||targetTlsExporterContext32)',
  'targetLocalExchangeId:BLAKE2b256(ASCII(hiverelay.blind.private-ipc-forward-target-exchange.v4)||u64be(260)||bytes[0:260])',
  'body:exact canonical WIRE ID76 requestRole FORWARDED; commitment/session/sequence match header; no origin/outer-envelope/native-stream/fallback form',
  'raw target TLS exporter, source address, URL, host, IP, cookies, authorization, credentials, and app metadata are unrepresentable'
])

export const PRIVATE_IPC_V4_ADDITIONAL_SCHEMAS = Object.freeze([
  Object.freeze({
    schemaId: 16,
    schemaName: 'LocalForwardHttpsOriginAuthorityV4',
    fields: Object.freeze([
      '0:4 magic=LFA4', '4 version=4', '5 authorityKind=1[TLS_EXPORTER_BINDING_HASH_BY_PEERCRED_EDGE]', '6 transportId=1[HTTPS_DIRECT]', '7 endpointId:1..255',
      '8:10 flags=0', '10:12 reserved=0', '12:44 wireV3AbiHash', '44:76 signedLaunchTopologyHash',
      '76:108 edgeProcessNonce', '108:140 localChannelNonce', '140:172 tlsExporterBindingHash',
      '172:204 originRequestCommitment', '204:236 stableSessionId', '236:244 sequence:u64be',
      '244:252 acceptedMonotonicMillis:u64be', '252:260 absoluteDeadlineMonotonicMillis:u64be', '260:292 localExchangeId'
    ])
  }),
  Object.freeze({
    schemaId: 17,
    schemaName: 'LocalForwardHttpsTurnV4',
    fields: Object.freeze([
      '0:4 magic=LFT4', '4 version=4', '5 direction[ORIGIN_REQUEST=1|RESULT=2]', '6 wireRole[ORIGIN_REQUEST:ORIGIN_TEMPLATE=0|RESULT:TARGET_RESULT=1|SOURCE_PRE_FORWARD_ERROR=2|SOURCE_POST_FORWARD_AMBIGUOUS=3]', '7 flags=0', '8:40 wireV3AbiHash',
      '40:72 localExchangeId', '72:104 originRequestCommitment', '104:136 stableSessionId', '136:144 sequence:u64be',
      '144:148 bodyLength=65536', '148:65684 canonical WIRE v3 body[ORIGIN_REQUEST:ID76 role ORIGIN_TEMPLATE|RESULT:ID77 resultRole equals wireRole]'
    ])
  }),
  Object.freeze({
    schemaId: 18,
    schemaName: 'LocalForwardHttpsTargetIngressV4',
    fields: Object.freeze([
      '0:4 magic=LTI4', '4 version=4', '5 authorityKind=2[TARGET_TLS_EXPORTER_BINDING_HASH_BY_PEERCRED_EDGE]', '6 transportId=1[HTTPS_DIRECT]', '7 endpointId:1..255',
      '8:10 flags=0', '10:12 reserved=0', '12:44 wireV3AbiHash[nonzero]', '44:76 signedLaunchTopologyHash[nonzero]',
      '76:108 edgeProcessNonce[nonzero]', '108:140 localChannelNonce[nonzero;single-use]', '140:172 targetTlsExporterBindingHash[nonzero]',
      '172:204 forwardedRequestCommitment[nonzero]', '204:236 stableSessionId[nonzero]', '236:244 sequence:u64be',
      '244:252 acceptedMonotonicMillis:u64be', '252:260 absoluteDeadlineMonotonicMillis:u64be', '260:292 targetLocalExchangeId[nonzero]',
      '292:65828 exact canonical WIRE ID76 role FORWARDED body',
      ...targetDeclarationTail
    ])
  })
])

function fail (message, code = 'BAD_PRIVATE_IPC_V4_CONTRACT') {
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

function u64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${field} must be an unsigned safe integer or bigint`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) fail(`${field} is outside u64`)
  return value
}

function endpointId (value) {
  if (!Number.isInteger(value) || value < 1 || value > 255) fail('endpointId is outside 1..255')
  return value
}

function put (output, value, offset) {
  b4a.copy(value, output, offset)
  return offset + value.byteLength
}

function take (input, offset, length) {
  return b4a.from(input.subarray(offset, offset + length))
}

function writeU16 (output, value, offset, field) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) fail(`${field} is outside u16`)
  output[offset] = value >>> 8
  output[offset + 1] = value
  return offset + 2
}

function readU16 (input, offset) {
  return input[offset] * 0x100 + input[offset + 1]
}

function writeU32 (output, value, offset, field) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) fail(`${field} is outside u32`)
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
  writeU64(output, BigInt(length), 0, 'hash input length')
  return output
}

function domainLengthHash (domain, input) {
  input = b4a.from(input)
  return privateBlake2b256(b4a.concat([domain, length64(input.byteLength), input]))
}

function assertNoAuthorityLeaks (value, boundary) {
  for (const forbidden of [
    'tlsExporter', 'targetTlsExporterSecret', 'sourceAddress', 'remoteAddress', 'url', 'host', 'hostname', 'ip',
    'ipAddress', 'dialAddress', 'cookies', 'authorization', 'credentials', 'appMetadata'
  ]) {
    if (forbidden in value) fail(`${boundary}.${forbidden} is forbidden`)
  }
}

function validateDeadline (value) {
  const accepted = u64(value.acceptedMonotonicMillis, 'acceptedMonotonicMillis')
  const deadline = u64(value.absoluteDeadlineMonotonicMillis, 'absoluteDeadlineMonotonicMillis')
  if (deadline <= accepted || deadline - accepted > BigInt(PRIVATE_IPC_V4_LIMITS.MAX_DEADLINE_MILLIS)) {
    fail('absolute deadline must be after acceptance and at most 15000ms later')
  }
  return { accepted, deadline }
}

function writeAuthorityPrefix (output, value, magic, authorityKind, commitmentField, bindingField) {
  assertNoAuthorityLeaks(value, magic === ORIGIN_AUTHORITY_MAGIC ? 'originAuthority' : 'targetIngress')
  if (value.version !== 4 || value.authorityKind !== authorityKind || value.transportId !== 1 || value.flags !== 0) {
    fail('local authority fixed header is invalid')
  }
  endpointId(value.endpointId)
  const { accepted, deadline } = validateDeadline(value)
  let offset = put(output, magic, 0)
  output[offset++] = 4
  output[offset++] = authorityKind
  output[offset++] = 1
  output[offset++] = value.endpointId
  offset = writeU16(output, 0, offset, 'flags')
  offset = writeU16(output, 0, offset, 'reserved')
  for (const field of [
    'wireV3AbiHash', 'signedLaunchTopologyHash', 'edgeProcessNonce', 'localChannelNonce', bindingField,
    commitmentField, 'stableSessionId'
  ]) offset = put(output, bytes(value[field], 32, field, true), offset)
  offset = writeU64(output, value.sequence, offset, 'sequence')
  offset = writeU64(output, accepted, offset, 'acceptedMonotonicMillis')
  offset = writeU64(output, deadline, offset, 'absoluteDeadlineMonotonicMillis')
  if (offset !== PRIVATE_IPC_V4_LIMITS.EXCHANGE_PREIMAGE_BYTES) fail('local authority prefix length mismatch')
  return offset
}

function decodeAuthorityPrefix (input, magic, authorityKind, commitmentField, bindingField) {
  if (!b4a.equals(input.subarray(0, 4), magic)) fail('local authority magic is invalid')
  let offset = 4
  const value = {
    version: input[offset++],
    authorityKind: input[offset++],
    transportId: input[offset++],
    endpointId: input[offset++],
    flags: readU16(input, offset)
  }
  offset += 2
  const reserved = readU16(input, offset); offset += 2
  if (reserved !== 0) fail('local authority reserved bytes must be zero')
  value.wireV3AbiHash = take(input, offset, 32); offset += 32
  value.signedLaunchTopologyHash = take(input, offset, 32); offset += 32
  value.edgeProcessNonce = take(input, offset, 32); offset += 32
  value.localChannelNonce = take(input, offset, 32); offset += 32
  value[bindingField] = take(input, offset, 32); offset += 32
  value[commitmentField] = take(input, offset, 32); offset += 32
  value.stableSessionId = take(input, offset, 32); offset += 32
  value.sequence = readU64(input, offset); offset += 8
  value.acceptedMonotonicMillis = readU64(input, offset); offset += 8
  value.absoluteDeadlineMonotonicMillis = readU64(input, offset); offset += 8
  if (offset !== PRIVATE_IPC_V4_LIMITS.EXCHANGE_PREIMAGE_BYTES) fail('local authority prefix decode length mismatch')
  return value
}

export function localForwardHttpsExchangeIdV4 (originAuthorityOrPrefix) {
  const prefix = originAuthorityOrPrefix && originAuthorityOrPrefix.byteLength != null
    ? bytes(originAuthorityOrPrefix, 260, 'origin authority prefix')
    : (() => {
        const output = b4a.alloc(260)
        writeAuthorityPrefix(output, originAuthorityOrPrefix, ORIGIN_AUTHORITY_MAGIC, 1, 'originRequestCommitment', 'tlsExporterBindingHash')
        return output
      })()
  return domainLengthHash(SOURCE_EXCHANGE_DOMAIN, prefix)
}

export function targetLocalForwardHttpsExchangeIdV4 (targetIngressOrPrefix) {
  let prefix
  if (targetIngressOrPrefix && targetIngressOrPrefix.byteLength != null) {
    const input = b4a.from(targetIngressOrPrefix)
    if (input.byteLength !== 260 && input.byteLength !== PRIVATE_IPC_V4_LIMITS.TARGET_INGRESS_BYTES) {
      fail('target ingress or prefix must be exactly 260 or 65828 bytes')
    }
    prefix = input.subarray(0, 260)
  } else {
    prefix = b4a.alloc(260)
    writeAuthorityPrefix(prefix, targetIngressOrPrefix, TARGET_INGRESS_MAGIC, 2, 'forwardedRequestCommitment', 'targetTlsExporterBindingHash')
  }
  return domainLengthHash(TARGET_EXCHANGE_DOMAIN, prefix)
}

export function createLocalForwardHttpsOriginAuthorityV4 (value) {
  const output = { ...value, localExchangeId: ZERO_32 }
  output.localExchangeId = localForwardHttpsExchangeIdV4(output)
  return output
}

export function encodeLocalForwardHttpsOriginAuthorityV4 (value) {
  const output = b4a.alloc(PRIVATE_IPC_V4_LIMITS.ORIGIN_AUTHORITY_BYTES)
  let offset = writeAuthorityPrefix(output, value, ORIGIN_AUTHORITY_MAGIC, 1, 'originRequestCommitment', 'tlsExporterBindingHash')
  const expected = localForwardHttpsExchangeIdV4(output.subarray(0, 260))
  const actual = bytes(value.localExchangeId, 32, 'localExchangeId', true)
  if (!b4a.equals(actual, expected)) fail('localExchangeId does not bind exact ID16 bytes 0:260')
  offset = put(output, actual, offset)
  if (offset !== output.byteLength) fail('origin authority encoder length mismatch')
  return output
}

export function decodeLocalForwardHttpsOriginAuthorityV4 (input) {
  input = bytes(input, PRIVATE_IPC_V4_LIMITS.ORIGIN_AUTHORITY_BYTES, 'origin authority')
  const value = decodeAuthorityPrefix(input, ORIGIN_AUTHORITY_MAGIC, 1, 'originRequestCommitment', 'tlsExporterBindingHash')
  value.localExchangeId = take(input, 260, 32)
  if (!b4a.equals(encodeLocalForwardHttpsOriginAuthorityV4(value), input)) fail('origin authority is not canonical')
  return value
}

function decodeWireRequest (body) {
  return decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, body, { copyBytes: true })
}

function decodeWireResult (body) {
  return decodeCanonical(blindForwardHttpsOriginForwardTurnResultV1, body, { copyBytes: true })
}

export function encodeLocalForwardHttpsTurnV4 (value) {
  if (!value || typeof value !== 'object' || value.version !== 4 || value.flags !== 0) fail('local turn fixed header is invalid')
  const wireV3AbiHash = bytes(value.wireV3AbiHash, 32, 'wireV3AbiHash', true)
  const localExchangeId = bytes(value.localExchangeId, 32, 'localExchangeId', true)
  const originRequestCommitment = bytes(value.originRequestCommitment, 32, 'originRequestCommitment', true)
  const stableSessionId = bytes(value.stableSessionId, 32, 'stableSessionId', true)
  const sequence = u64(value.sequence, 'sequence')
  const body = bytes(value.body, PRIVATE_IPC_V4_LIMITS.TURN_BODY_BYTES, 'local turn body')
  let decoded
  if (value.direction === LOCAL_FORWARD_HTTPS_DIRECTION_V4.ORIGIN_REQUEST) {
    if (value.wireRole !== FORWARD_HTTPS_REQUEST_ROLE_V1.ORIGIN_TEMPLATE) fail('origin request turn wireRole must be ORIGIN_TEMPLATE')
    decoded = decodeWireRequest(body)
    if (decoded.requestRole !== FORWARD_HTTPS_REQUEST_ROLE_V1.ORIGIN_TEMPLATE ||
        !b4a.equals(forwardHttpsOriginRequestCommitmentV1(body), originRequestCommitment)) {
      fail('origin turn body role or commitment is invalid')
    }
  } else if (value.direction === LOCAL_FORWARD_HTTPS_DIRECTION_V4.RESULT) {
    if (![1, 2, 3].includes(value.wireRole)) fail('result turn wireRole is invalid')
    decoded = decodeWireResult(body)
    if (decoded.resultRole !== value.wireRole || !b4a.equals(decoded.originRequestCommitment, originRequestCommitment)) {
      fail('result turn body role or commitment is invalid')
    }
  } else fail('local turn direction is invalid')
  if (!b4a.equals(decoded.stableSessionId, stableSessionId) || decoded.sequence !== sequence) {
    fail('local turn sessionId or sequence does not match body')
  }
  const output = b4a.alloc(PRIVATE_IPC_V4_LIMITS.TURN_BYTES)
  let offset = put(output, TURN_MAGIC, 0)
  output[offset++] = 4
  output[offset++] = value.direction
  output[offset++] = value.wireRole
  output[offset++] = 0
  offset = put(output, wireV3AbiHash, offset)
  offset = put(output, localExchangeId, offset)
  offset = put(output, originRequestCommitment, offset)
  offset = put(output, stableSessionId, offset)
  offset = writeU64(output, sequence, offset, 'sequence')
  offset = writeU32(output, body.byteLength, offset, 'bodyLength')
  offset = put(output, body, offset)
  if (offset !== output.byteLength) fail('local turn encoder length mismatch')
  return output
}

export function decodeLocalForwardHttpsTurnV4 (input) {
  input = bytes(input, PRIVATE_IPC_V4_LIMITS.TURN_BYTES, 'local turn')
  if (!b4a.equals(input.subarray(0, 4), TURN_MAGIC) || input[4] !== 4 || input[7] !== 0) {
    fail('local turn fixed header is invalid')
  }
  const value = {
    version: 4,
    direction: input[5],
    wireRole: input[6],
    flags: 0,
    wireV3AbiHash: take(input, 8, 32),
    localExchangeId: take(input, 40, 32),
    originRequestCommitment: take(input, 72, 32),
    stableSessionId: take(input, 104, 32),
    sequence: readU64(input, 136),
    body: take(input, 148, 65_536)
  }
  if (readU32(input, 144) !== 65_536) fail('local turn bodyLength must be exactly 65536')
  if (!b4a.equals(encodeLocalForwardHttpsTurnV4(value), input)) fail('local turn is not canonical')
  return value
}

export function forwardHttpsTargetTlsExporterContextV4 (stableSessionId, sequence, forwardedRequestCommitment) {
  const payload = b4a.concat([
    bytes(stableSessionId, 32, 'stableSessionId', true),
    (() => {
      const output = b4a.alloc(8)
      writeU64(output, sequence, 0, 'sequence')
      return output
    })(),
    bytes(forwardedRequestCommitment, 32, 'forwardedRequestCommitment', true)
  ])
  if (payload.byteLength !== 72) fail('target TLS exporter context payload length mismatch')
  return privateBlake2b256(b4a.concat([TARGET_TLS_CONTEXT_DOMAIN, payload]))
}

export function forwardHttpsTargetTlsExporterBindingHashV4 (targetTlsExporterSecret, context) {
  const secret = b4a.from(bytes(targetTlsExporterSecret, 32, 'target TLS exporter secret', true))
  context = bytes(context, 32, 'target TLS exporter context', true)
  try {
    return privateBlake2b256(b4a.concat([TARGET_TLS_BINDING_DOMAIN, length64(64), secret, context]))
  } finally {
    secret.fill(0)
  }
}

export function createLocalForwardHttpsTargetIngressV4 (value) {
  const body = bytes(value.body, 65_536, 'target ingress body')
  const request = decodeWireRequest(body)
  if (request.requestRole !== FORWARD_HTTPS_REQUEST_ROLE_V1.FORWARDED) fail('target ingress requires role FORWARDED ID76')
  const output = {
    ...value,
    version: 4,
    authorityKind: 2,
    transportId: 1,
    flags: 0,
    forwardedRequestCommitment: forwardHttpsForwardedRequestCommitmentV1(body),
    stableSessionId: request.stableSessionId,
    sequence: request.sequence,
    targetLocalExchangeId: ZERO_32,
    body
  }
  output.targetLocalExchangeId = targetLocalForwardHttpsExchangeIdV4(output)
  return output
}

export function encodeLocalForwardHttpsTargetIngressV4 (value) {
  const body = bytes(value.body, 65_536, 'target ingress body')
  const request = decodeWireRequest(body)
  if (request.requestRole !== FORWARD_HTTPS_REQUEST_ROLE_V1.FORWARDED) fail('target ingress requires role FORWARDED ID76')
  const commitment = forwardHttpsForwardedRequestCommitmentV1(body)
  if (!b4a.equals(commitment, bytes(value.forwardedRequestCommitment, 32, 'forwardedRequestCommitment', true)) ||
      !b4a.equals(request.stableSessionId, bytes(value.stableSessionId, 32, 'stableSessionId', true)) ||
      request.sequence !== u64(value.sequence, 'sequence')) {
    fail('target ingress commitment, session, or sequence does not match body')
  }
  const output = b4a.alloc(PRIVATE_IPC_V4_LIMITS.TARGET_INGRESS_BYTES)
  let offset = writeAuthorityPrefix(output, value, TARGET_INGRESS_MAGIC, 2, 'forwardedRequestCommitment', 'targetTlsExporterBindingHash')
  const expected = targetLocalForwardHttpsExchangeIdV4(output.subarray(0, 260))
  const actual = bytes(value.targetLocalExchangeId, 32, 'targetLocalExchangeId', true)
  if (!b4a.equals(actual, expected)) fail('targetLocalExchangeId does not bind exact ID18 bytes 0:260')
  offset = put(output, actual, offset)
  offset = put(output, body, offset)
  if (offset !== output.byteLength) fail('target ingress encoder length mismatch')
  return output
}

export function decodeLocalForwardHttpsTargetIngressV4 (input) {
  input = bytes(input, PRIVATE_IPC_V4_LIMITS.TARGET_INGRESS_BYTES, 'target ingress')
  const value = decodeAuthorityPrefix(input, TARGET_INGRESS_MAGIC, 2, 'forwardedRequestCommitment', 'targetTlsExporterBindingHash')
  value.targetLocalExchangeId = take(input, 260, 32)
  value.body = take(input, 292, 65_536)
  if (!b4a.equals(encodeLocalForwardHttpsTargetIngressV4(value), input)) fail('target ingress is not canonical')
  return value
}

export function decodeLocalForwardHttpsSourceOriginTranscriptV4 (input, options = {}) {
  input = bytes(input, PRIVATE_IPC_V4_LIMITS.SOURCE_ORIGIN_TRANSCRIPT_BYTES, 'source-origin transcript')
  if (options.eof !== true) fail('source-origin transcript requires daemon-observed EOF before response')
  const authority = decodeLocalForwardHttpsOriginAuthorityV4(input.subarray(0, 292))
  const turn = decodeLocalForwardHttpsTurnV4(input.subarray(292))
  if (turn.direction !== LOCAL_FORWARD_HTTPS_DIRECTION_V4.ORIGIN_REQUEST ||
      turn.wireRole !== FORWARD_HTTPS_REQUEST_ROLE_V1.ORIGIN_TEMPLATE ||
      !b4a.equals(turn.wireV3AbiHash, authority.wireV3AbiHash) ||
      !b4a.equals(turn.localExchangeId, authority.localExchangeId) ||
      !b4a.equals(turn.originRequestCommitment, authority.originRequestCommitment) ||
      !b4a.equals(turn.stableSessionId, authority.stableSessionId) || turn.sequence !== authority.sequence) {
    fail('source-origin ID16 and ID17 records do not bind one exact exchange')
  }
  return Object.freeze({ authority, turn })
}

export function encodeLocalForwardHttpsSourceOriginTranscriptV4 (authority, turn) {
  const output = b4a.concat([
    encodeLocalForwardHttpsOriginAuthorityV4(authority),
    encodeLocalForwardHttpsTurnV4(turn)
  ])
  decodeLocalForwardHttpsSourceOriginTranscriptV4(output, { eof: true })
  return output
}

export function decodeLocalForwardHttpsTargetIngressTranscriptV4 (input, options = {}) {
  if (options.eof !== true) fail('target-ingress transcript requires daemon-observed EOF before response')
  return decodeLocalForwardHttpsTargetIngressV4(
    bytes(input, PRIVATE_IPC_V4_LIMITS.TARGET_INGRESS_TRANSCRIPT_BYTES, 'target-ingress transcript')
  )
}

export function assertLocalForwardHttpsResultTranscriptV4 (input, authority, requiredRole = null) {
  const turn = decodeLocalForwardHttpsTurnV4(bytes(input, PRIVATE_IPC_V4_LIMITS.RESULT_TRANSCRIPT_BYTES, 'result transcript'))
  const exchangeId = authority.targetLocalExchangeId || authority.localExchangeId
  const commitment = authority.originRequestCommitment || decodeWireRequest(authority.body).originRequestCommitment
  if (turn.direction !== LOCAL_FORWARD_HTTPS_DIRECTION_V4.RESULT ||
      (requiredRole != null && turn.wireRole !== requiredRole) ||
      !b4a.equals(turn.wireV3AbiHash, authority.wireV3AbiHash) ||
      !b4a.equals(turn.localExchangeId, exchangeId) ||
      !b4a.equals(turn.originRequestCommitment, commitment) ||
      !b4a.equals(turn.stableSessionId, authority.stableSessionId) || turn.sequence !== authority.sequence) {
    fail('result transcript does not bind the authenticated local exchange')
  }
  return turn
}

export function assertLocalForwardHttpsSocketSeparationV4 (identities) {
  if (!identities || typeof identities !== 'object') fail('socket identities must be an object')
  const fields = ['sourceOrigin', 'targetIngress', 'genericUnary', 'nativeV2Stream']
  const values = fields.map(field => {
    const value = identities[field]
    if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'bigint') fail(`${field} socket identity is invalid`)
    return String(value)
  })
  if (new Set(values).size !== values.length) fail('private IPC v4 socket identities must not alias')
  return true
}

export class LocalForwardHttpsTranscriptAccumulatorV4 {
  #role
  #limit
  #chunks
  #length
  #ended
  #validated

  constructor (role) {
    if (role !== 'SOURCE_ORIGIN' && role !== 'TARGET_INGRESS') fail('transcript accumulator role is invalid')
    this.#role = role
    this.#limit = role === 'SOURCE_ORIGIN'
      ? PRIVATE_IPC_V4_LIMITS.SOURCE_ORIGIN_TRANSCRIPT_BYTES
      : PRIVATE_IPC_V4_LIMITS.TARGET_INGRESS_TRANSCRIPT_BYTES
    this.#chunks = []
    this.#length = 0
    this.#ended = false
    this.#validated = false
    Object.defineProperty(this, 'responseAllowed', {
      enumerable: true,
      configurable: false,
      get: () => this.#validated
    })
    Object.freeze(this)
  }

  write (chunk) {
    if (this.#ended) fail('transcript cannot accept bytes after EOF')
    if (!chunk || typeof chunk.byteLength !== 'number') fail('transcript chunk must be bytes')
    chunk = b4a.from(chunk)
    if (this.#length + chunk.byteLength > this.#limit) fail('transcript exceeds its exact byte limit')
    this.#chunks.push(b4a.from(chunk))
    this.#length += chunk.byteLength
    return this.#length
  }

  end () {
    if (this.#ended) fail('transcript EOF may occur only once')
    this.#ended = true
    if (this.#length !== this.#limit) fail('transcript EOF arrived before its exact byte limit')
    const input = b4a.concat(this.#chunks, this.#length)
    const transcript = this.#role === 'SOURCE_ORIGIN'
      ? decodeLocalForwardHttpsSourceOriginTranscriptV4(input, { eof: true })
      : decodeLocalForwardHttpsTargetIngressTranscriptV4(input, { eof: true })
    this.#validated = true
    return transcript
  }
}

function replayPayload (value, commitmentField, exchangeField) {
  const output = b4a.alloc(PRIVATE_IPC_V4_LIMITS.REPLAY_PAYLOAD_BYTES)
  let offset = 0
  for (const field of [
    'wireV3AbiHash', 'signedLaunchTopologyHash', 'edgeProcessNonce', 'localChannelNonce', commitmentField, 'stableSessionId'
  ]) offset = put(output, bytes(value[field], 32, field, true), offset)
  offset = writeU64(output, value.sequence, offset, 'sequence')
  offset = put(output, bytes(value[exchangeField], 32, exchangeField, true), offset)
  if (offset !== output.byteLength) fail('private IPC v4 replay payload length mismatch')
  return output
}

export function localForwardHttpsSourceReplayTupleV4 (authority) {
  const encoded = encodeLocalForwardHttpsOriginAuthorityV4(authority)
  const decoded = decodeLocalForwardHttpsOriginAuthorityV4(encoded)
  const recomputed = localForwardHttpsExchangeIdV4(encoded.subarray(0, 260))
  if (!b4a.equals(recomputed, decoded.localExchangeId)) fail('source replay requires recomputed localExchangeId')
  return domainLengthHash(SOURCE_REPLAY_DOMAIN, replayPayload(decoded, 'originRequestCommitment', 'localExchangeId'))
}

export function localForwardHttpsTargetReplayTupleV4 (ingress) {
  const encoded = encodeLocalForwardHttpsTargetIngressV4(ingress)
  const decoded = decodeLocalForwardHttpsTargetIngressV4(encoded)
  const recomputed = targetLocalForwardHttpsExchangeIdV4(encoded.subarray(0, 260))
  if (!b4a.equals(recomputed, decoded.targetLocalExchangeId)) fail('target replay requires recomputed targetLocalExchangeId')
  return domainLengthHash(TARGET_REPLAY_DOMAIN, replayPayload(decoded, 'forwardedRequestCommitment', 'targetLocalExchangeId'))
}

export class LocalForwardHttpsReplayJournalModelV4 {
  #namespace
  #capacity
  #entries
  #lastMonotonicMillis
  #quarantined

  constructor (namespace, options = {}) {
    if (namespace !== 'SOURCE_ORIGIN' && namespace !== 'TARGET_INGRESS') fail('journal namespace must be SOURCE_ORIGIN or TARGET_INGRESS')
    this.#namespace = namespace
    this.#capacity = options.capacity == null ? PRIVATE_IPC_V4_LIMITS.REPLAY_CAPACITY : options.capacity
    if (!Number.isInteger(this.#capacity) || this.#capacity < 1 || this.#capacity > 4096) fail('journal capacity is outside 1..4096')
    this.#entries = new Map()
    this.#lastMonotonicMillis = 0n
    this.#quarantined = false
  }

  get namespace () { return this.#namespace }
  get capacity () { return this.#capacity }
  get lastMonotonicMillis () { return this.#lastMonotonicMillis }
  get quarantined () { return this.#quarantined }
  get size () { return this.#entries.size }

  reserve (tuple, acceptedMonotonicMillis, deadlineMonotonicMillis, nowMonotonicMillis) {
    this.#assertActive()
    tuple = bytes(tuple, 32, 'replay tuple', true)
    const accepted = u64(acceptedMonotonicMillis, 'acceptedMonotonicMillis')
    const deadline = u64(deadlineMonotonicMillis, 'deadlineMonotonicMillis')
    const now = u64(nowMonotonicMillis, 'nowMonotonicMillis')
    if (now < this.#lastMonotonicMillis) {
      this.#quarantined = true
      fail('journal model monotonic clock regressed', 'PRIVATE_IPC_V4_CLOCK_REGRESSION')
    }
    if (accepted > now || now > deadline || deadline <= accepted || deadline - accepted > 15_000n) {
      fail('journal replay record is outside its bounded deadline')
    }
    const entries = new Map()
    for (const [entryKey, entry] of this.#entries) {
      if (entry.state !== 'CONSUMED' || now <= entry.deadline) entries.set(entryKey, { ...entry })
    }
    const key = b4a.toString(tuple, 'hex')
    if (entries.has(key)) fail('private IPC v4 replay tuple already exists', 'PRIVATE_IPC_V4_REPLAY')
    if (entries.size >= this.#capacity) fail('private IPC v4 replay journal capacity exhausted', 'PRIVATE_IPC_V4_JOURNAL_CAPACITY')
    entries.set(key, { accepted, deadline, state: 'PENDING' })
    this.#entries = entries
    this.#lastMonotonicMillis = now
    return key
  }

  commit (key) {
    this.#assertActive()
    const entry = this.#entries.get(String(key))
    if (!entry || entry.state !== 'PENDING') fail('journal model has no pending reservation')
    this.#entries.set(String(key), { accepted: entry.accepted, deadline: entry.deadline, state: 'CONSUMED' })
    return true
  }

  crashSnapshot () {
    const records = [...this.#entries].map(([key, value]) => ({
      key,
      accepted: value.accepted.toString(),
      deadline: value.deadline.toString(),
      state: value.state
    })).sort((left, right) => left.key.localeCompare(right.key))
    const payload = b4a.from(JSON.stringify({
      version: 1,
      namespace: this.#namespace,
      capacity: this.#capacity,
      lastMonotonicMillis: this.#lastMonotonicMillis.toString(),
      quarantined: this.#quarantined,
      records
    }), 'utf8')
    return Object.freeze({ payload: b4a.from(payload), checksum: domainLengthHash(JOURNAL_SNAPSHOT_DOMAIN, payload) })
  }

  inspectEntries () {
    return Object.freeze([...this.#entries].map(([key, entry]) => Object.freeze({
      key,
      accepted: entry.accepted,
      deadline: entry.deadline,
      state: entry.state
    })).sort((left, right) => left.key.localeCompare(right.key)))
  }

  static restart (snapshot, options = {}) {
    const expectedNamespace = options.expectedNamespace
    const expectedCapacity = options.expectedCapacity
    const now = u64(options.nowMonotonicMillis, 'nowMonotonicMillis')
    const clean = new LocalForwardHttpsReplayJournalModelV4(expectedNamespace, { capacity: expectedCapacity })
    const quarantine = () => {
      const model = new LocalForwardHttpsReplayJournalModelV4(expectedNamespace, { capacity: expectedCapacity })
      model.#lastMonotonicMillis = now
      model.#quarantined = true
      return model
    }
    try {
      if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot) ||
          Object.keys(snapshot).length !== 2 || !Object.prototype.hasOwnProperty.call(snapshot, 'payload') ||
          !Object.prototype.hasOwnProperty.call(snapshot, 'checksum')) return quarantine()
      const payload = bytes(snapshot.payload, snapshot.payload.byteLength, 'journal snapshot payload')
      const checksum = bytes(snapshot.checksum, 32, 'journal checksum')
      if (!b4a.equals(domainLengthHash(JOURNAL_SNAPSHOT_DOMAIN, payload), checksum)) return quarantine()
      const parsed = JSON.parse(b4a.toString(payload, 'utf8'))
      const keys = ['version', 'namespace', 'capacity', 'lastMonotonicMillis', 'quarantined', 'records']
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) ||
          Object.keys(parsed).length !== keys.length || Object.keys(parsed).some((key, index) => key !== keys[index]) ||
          !b4a.equals(b4a.from(JSON.stringify(parsed), 'utf8'), payload)) return quarantine()
      if (parsed.version !== 1 || parsed.namespace !== expectedNamespace || parsed.capacity !== expectedCapacity ||
          typeof parsed.quarantined !== 'boolean' || !Array.isArray(parsed.records) || parsed.records.length > expectedCapacity) return quarantine()
      const decimalU64 = (value, field) => {
        if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) fail(`${field} is not canonical u64 text`)
        return u64(BigInt(value), field)
      }
      const last = decimalU64(parsed.lastMonotonicMillis, 'lastMonotonicMillis')
      if (last > now || parsed.quarantined) return quarantine()
      const entries = new Map()
      let previousKey = null
      for (const record of parsed.records) {
        const recordKeys = ['key', 'accepted', 'deadline', 'state']
        if (!record || typeof record !== 'object' || Array.isArray(record) ||
            Object.keys(record).length !== recordKeys.length || Object.keys(record).some((key, index) => key !== recordKeys[index]) ||
            typeof record.key !== 'string' || !/^[0-9a-f]{64}$/.test(record.key) ||
            (previousKey != null && previousKey.localeCompare(record.key) >= 0) ||
            (record.state !== 'PENDING' && record.state !== 'CONSUMED')) return quarantine()
        const accepted = decimalU64(record.accepted, 'accepted')
        const deadline = decimalU64(record.deadline, 'deadline')
        if (accepted > last || accepted > now || deadline <= accepted || deadline - accepted > 15_000n || record.state === 'PENDING') return quarantine()
        if (now <= deadline) entries.set(record.key, { accepted, deadline, state: 'CONSUMED' })
        previousKey = record.key
      }
      clean.#entries = entries
      clean.#lastMonotonicMillis = now
      return clean
    } catch {
      return quarantine()
    }
  }

  #assertActive () {
    if (this.#quarantined) fail('journal model is quarantined', 'PRIVATE_IPC_V4_JOURNAL_QUARANTINED')
  }
}

export class LocalForwardHttpsTargetClaimModelV4 {
  #stableSessionId
  #claims
  #outstandingKey
  #nextSequence
  #previousTargetResultHash
  #terminal
  #terminalReason
  #closed
  #targetFin

  constructor () {
    this.#stableSessionId = null
    this.#claims = new Map()
    this.#outstandingKey = null
    this.#nextSequence = 0n
    this.#previousTargetResultHash = b4a.alloc(32)
    this.#terminal = false
    this.#terminalReason = null
    this.#closed = false
    this.#targetFin = false
  }

  get stableSessionId () { return this.#stableSessionId && b4a.from(this.#stableSessionId) }
  get nextSequence () { return this.#nextSequence }
  get previousTargetResultHash () { return b4a.from(this.#previousTargetResultHash) }
  get terminal () { return this.#terminal }
  get terminalReason () { return this.#terminalReason }
  get closed () { return this.#closed }
  get targetFin () { return this.#targetFin }
  get claimCount () { return this.#claims.size }

  claim (forwardedRequestBytes) {
    this.#assertActive()
    forwardedRequestBytes = b4a.from(bytes(forwardedRequestBytes, 65_536, 'forwarded request'))
    let request
    try {
      request = assertForwardHttpsForwardedRequestAuthorityV1(forwardedRequestBytes).request
    } catch {
      return this.#terminate('target claim forwarded authority is invalid')
    }
    const key = `${b4a.toString(request.stableSessionId, 'hex')}:${request.sequence}`
    const commitment = forwardHttpsForwardedRequestCommitmentV1(forwardedRequestBytes)
    const existing = this.#claims.get(key)
    if (existing) {
      if (!b4a.equals(existing.requestBytes, forwardedRequestBytes) || !b4a.equals(existing.commitment, commitment)) {
        return this.#terminate('changed forwarded bytes reuse a target claim')
      }
      return Object.freeze({ disposition: 'EXACT_RETRY', resultBytes: existing.resultBytes && b4a.from(existing.resultBytes) })
    }
    if (this.#closed) return this.#terminate('target session is normally closed')
    if (this.#stableSessionId == null) {
      if (request.requestKind !== FORWARD_HTTPS_REQUEST_KIND_V1.OPEN || request.sequence !== 0n) return this.#terminate('target session must begin with OPEN at sequence zero')
      this.#stableSessionId = b4a.from(request.stableSessionId)
    } else if (!b4a.equals(request.stableSessionId, this.#stableSessionId)) {
      return this.#terminate('target claim model cannot bind a second stable session')
    }
    if (this.#outstandingKey != null) return this.#terminate('target session already has an outstanding request')
    if (request.sequence !== this.#nextSequence || !b4a.equals(request.previousTargetResultHash, this.#previousTargetResultHash)) {
      return this.#terminate('target sequence or previous result chain is invalid')
    }
    if (request.requestKind === FORWARD_HTTPS_REQUEST_KIND_V1.OPEN && request.sequence !== 0n) return this.#terminate('target OPEN may occur only once')
    if (request.requestKind !== FORWARD_HTTPS_REQUEST_KIND_V1.OPEN && request.sequence === 0n) return this.#terminate('target sequence zero must be OPEN')
    this.#claims.set(key, { requestBytes: b4a.from(forwardedRequestBytes), commitment: b4a.from(commitment), resultBytes: null })
    this.#outstandingKey = key
    return Object.freeze({ disposition: 'CLAIMED', resultBytes: null })
  }

  persistResult (forwardedRequestBytes, resultBytes) {
    this.#assertActive()
    forwardedRequestBytes = b4a.from(bytes(forwardedRequestBytes, 65_536, 'forwarded request'))
    resultBytes = b4a.from(bytes(resultBytes, 65_536, 'target result'))
    let authority
    try {
      authority = assertForwardHttpsTargetResultForForwardedRequestV1(forwardedRequestBytes, resultBytes)
    } catch {
      return this.#terminate('target result does not bind the exact authenticated claim')
    }
    const { request, result } = authority
    const key = `${b4a.toString(request.stableSessionId, 'hex')}:${request.sequence}`
    const claim = this.#claims.get(key)
    if (!claim || !b4a.equals(claim.requestBytes, forwardedRequestBytes)) return this.#terminate('target result has no exact request claim')
    if (claim.resultBytes) {
      if (!b4a.equals(claim.resultBytes, resultBytes)) return this.#terminate('target claim cannot remint a definitive result')
      return b4a.from(claim.resultBytes)
    }
    if (this.#outstandingKey !== key) return this.#terminate('target result is not for the outstanding request')
    claim.resultBytes = b4a.from(resultBytes)
    this.#previousTargetResultHash = forwardHttpsTargetResultChainHashV1(resultBytes)
    this.#nextSequence++
    this.#outstandingKey = null
    if (result.responseKind === FORWARD_HTTPS_RESPONSE_KIND_V1.CLOSE) this.#targetFin = true
    if (request.requestKind === FORWARD_HTTPS_REQUEST_KIND_V1.CLOSE) this.#closed = true
    return b4a.from(claim.resultBytes)
  }

  inspectClaim (forwardedRequestBytes) {
    forwardedRequestBytes = bytes(forwardedRequestBytes, 65_536, 'forwarded request')
    const request = decodeWireRequest(forwardedRequestBytes)
    const key = `${b4a.toString(request.stableSessionId, 'hex')}:${request.sequence}`
    const claim = this.#claims.get(key)
    if (!claim || !b4a.equals(claim.requestBytes, forwardedRequestBytes)) return null
    return Object.freeze({
      requestBytes: b4a.from(claim.requestBytes),
      commitment: b4a.from(claim.commitment),
      resultBytes: claim.resultBytes && b4a.from(claim.resultBytes)
    })
  }

  #assertActive () {
    if (this.#terminal) fail('target claim model is terminal', this.#terminalReason)
  }

  #terminate (message) {
    if (!this.#terminal) {
      this.#terminal = true
      this.#terminalReason = 'TERMINAL_FORWARD_HTTPS_TARGET_CLAIM'
    }
    fail(message, this.#terminalReason)
  }
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

export const privateIpcV4RegistryEncoding = {
  preencode (state, value) {
    c.string.preencode(state, value.magic)
    c.uint.preencode(state, value.formatVersion)
    c.buffer.preencode(state, value.importedWireV3AbiHash)
    c.buffer.preencode(state, value.basePrivateIpcV3FormatHash)
    c.uint.preencode(state, value.baseSchemaCount)
    schemasEncoding.preencode(state, value.additionalSchemas)
    c.uint.preencode(state, value.forwardReadinessOperationBits)
  },
  encode (state, value) {
    c.string.encode(state, value.magic)
    c.uint.encode(state, value.formatVersion)
    c.buffer.encode(state, value.importedWireV3AbiHash)
    c.buffer.encode(state, value.basePrivateIpcV3FormatHash)
    c.uint.encode(state, value.baseSchemaCount)
    schemasEncoding.encode(state, value.additionalSchemas)
    c.uint.encode(state, value.forwardReadinessOperationBits)
  },
  decode (state) {
    return {
      magic: c.string.decode(state),
      formatVersion: c.uint.decode(state),
      importedWireV3AbiHash: b4a.from(c.buffer.decode(state)),
      basePrivateIpcV3FormatHash: b4a.from(c.buffer.decode(state)),
      baseSchemaCount: c.uint.decode(state),
      additionalSchemas: schemasEncoding.decode(state),
      forwardReadinessOperationBits: c.uint.decode(state)
    }
  }
}

const declarationBytes = schema => b4a.from(JSON.stringify({ name: schema.schemaName, fields: schema.fields }), 'utf8')

export function createPrivateIpcV4RegistryValue (importedWireV3AbiHash, basePrivateIpcV3FormatHash) {
  return {
    magic: PRIVATE_IPC_V4_MAGIC,
    formatVersion: 4,
    importedWireV3AbiHash: bytes(importedWireV3AbiHash, 32, 'importedWireV3AbiHash', true),
    basePrivateIpcV3FormatHash: bytes(basePrivateIpcV3FormatHash, 32, 'basePrivateIpcV3FormatHash', true),
    baseSchemaCount: 15,
    additionalSchemas: PRIVATE_IPC_V4_ADDITIONAL_SCHEMAS.map(schema => ({
      schemaId: schema.schemaId,
      schemaName: schema.schemaName,
      canonicalDeclarationBytes: declarationBytes(schema)
    })),
    forwardReadinessOperationBits: 0
  }
}

export function encodePrivateIpcV4Registry (value) {
  const state = { start: 0, end: 0, buffer: null }
  privateIpcV4RegistryEncoding.preencode(state, value)
  state.buffer = b4a.alloc(state.end)
  state.start = 0
  privateIpcV4RegistryEncoding.encode(state, value)
  if (state.start !== state.end) fail('private IPC v4 registry encoder length mismatch')
  return state.buffer
}

export function decodePrivateIpcV4Registry (input) {
  input = b4a.from(input)
  const state = { start: 0, end: input.byteLength, buffer: input }
  const value = privateIpcV4RegistryEncoding.decode(state)
  if (state.start !== state.end || !b4a.equals(encodePrivateIpcV4Registry(value), input)) fail('private IPC v4 registry is not canonical')
  if (value.magic !== PRIVATE_IPC_V4_MAGIC || value.formatVersion !== 4 || value.baseSchemaCount !== 15 ||
      value.forwardReadinessOperationBits !== 0 || value.additionalSchemas.length !== 3 ||
      value.additionalSchemas.some((schema, index) => schema.schemaId !== index + 16 ||
        !b4a.equals(schema.canonicalDeclarationBytes, declarationBytes(PRIVATE_IPC_V4_ADDITIONAL_SCHEMAS[index])))) {
    fail('private IPC v4 registry fixed allocation or declarations are invalid')
  }
  return value
}

export const hashPrivateIpcV4Registry = input => domainLengthHash(FORMAT_DOMAIN, input)
export const hashPrivateIpcV4VectorManifest = input => domainLengthHash(VECTOR_DOMAIN, input)
