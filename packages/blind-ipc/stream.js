import crypto from 'node:crypto'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  DISPATCH_LIMITS,
  STREAM_WIRE_CLASS,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT
} from '@hiverelay/blind-protocol/wire-runtime-authority'
import { privateBlake2b256 } from './private-hashes.js'
import {
  LOCAL_ABORT_CODE,
  LOCAL_CIPHERTEXT_BYTES,
  LOCAL_CIPHERTEXT_PHASE,
  LOCAL_STREAM_ADJACENT_POLICY,
  LOCAL_STREAM_CONTEXT_KIND,
  LOCAL_STREAM_CONTROL_BYTES,
  LOCAL_STREAM_CONTROL_KIND,
  LOCAL_STREAM_DIRECTION,
  LOCAL_STREAM_FLAG,
  LOCAL_STREAM_FRAME_KIND,
  LOCAL_STREAM_MODE,
  LOCAL_STREAM_OPEN_KIND,
  LOCAL_STREAM_OPEN_TABLE,
  PRIVATE_IPC_LIMITS,
  PRIVATE_IPC_TIMING_MILLIS
} from './policy.js'

const MAX_U64 = (1n << 64n) - 1n
const EXPORTER_DOMAIN = b4a.from('hiverelay.blind.native-session-exporter.v1', 'ascii')
const PARENT_DOMAIN = b4a.from('hiverelay.blind.private-parent-session.v1', 'ascii')
const CHANNEL_DOMAIN = b4a.from('hiverelay.blind.private-channel-binding.v1', 'ascii')
const ATTACH_DOMAIN = b4a.from('hiverelay.blind.private-attach-binding.v1', 'ascii')
const VERIFIED_CHANNELS = new WeakMap()
const VERIFIED_ATTACHMENTS = new WeakMap()

function fail (message, code = 'BAD_LOCAL_STREAM') {
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

function snapshotBuffer (value, field) {
  return b4a.from(asBuffer(value, field))
}

function fixed (value, length, field, nonzero = false) {
  const bytes = snapshotBuffer(value, field)
  if (bytes.byteLength !== length) fail(`${field} must be exactly ${length} bytes`)
  if (nonzero && isZero(bytes)) fail(`${field} must be nonzero`)
  return bytes
}

function isZero (value) {
  for (const byte of value) if (byte !== 0) return false
  return true
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

function writeU64BE (buffer, value, offset) {
  value = u64(value, 'u64')
  for (let index = 7; index >= 0; index--) {
    buffer[offset + index] = Number(value & 0xffn)
    value >>= 8n
  }
}

function readU64BE (buffer, offset) {
  let value = 0n
  for (let index = 0; index < 8; index++) value = (value << 8n) | BigInt(buffer[offset + index])
  return value
}

function u64Bytes (value) {
  const output = b4a.alloc(8)
  writeU64BE(output, value, 0)
  return output
}

function u16Bytes (value, field) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) fail(`${field} is outside u16`)
  return b4a.from([value >>> 8, value & 0xff])
}

function endpointId (value) {
  if (!Number.isInteger(value) || value < 1 || value > 0xff) fail('endpointId is outside 1..255')
  return value
}

function oneHotTransportSupport (value) {
  const mask = Object.values(TRANSPORT_SUPPORT).reduce((sum, bit) => sum | bit, 0)
  if (!Number.isInteger(value) || value < 1 || value > 0xffff || (value & (value - 1)) !== 0 || (value & ~mask) !== 0) {
    fail('transportSupportBit must be one explicit registered one-hot bit')
  }
  return value
}

function known (values, value, field) {
  if (!Number.isInteger(value) || !Object.values(values).includes(value)) fail(`${field} is not registered`)
  return value
}

function declaredLength (input, maximum, field) {
  const buffer = asBuffer(input, field)
  if (buffer.byteLength < 4) return null
  const total = b4a.readUInt32BE(buffer, 0)
  if (total > maximum - 4) fail(`${field} totalLength exceeds its cap`)
  return total + 4
}

function openCombination (openKind, streamMode, channelClass, adjacentPresent) {
  const row = LOCAL_STREAM_OPEN_TABLE.find(row => row.openKind === openKind && row.streamMode === streamMode &&
    channelClass >= row.classMinimum && channelClass <= row.classMaximum)
  if (!row) fail('stream open kind/mode/class combination is not registered')
  if (row.adjacentPolicy === LOCAL_STREAM_ADJACENT_POLICY.REQUIRED && !adjacentPresent) fail('stream open combination requires an adjacent relay key')
  if (row.adjacentPolicy === LOCAL_STREAM_ADJACENT_POLICY.FORBIDDEN && adjacentPresent) fail('stream open combination forbids an adjacent relay key')
  return row
}

function contextBytesFor (contextKind) {
  if (contextKind === LOCAL_STREAM_CONTEXT_KIND.AUTHENTICATED_CHANNEL) return PRIVATE_IPC_LIMITS.AUTHENTICATED_CHANNEL_CONTEXT_BYTES
  if (contextKind === LOCAL_STREAM_CONTEXT_KIND.ONE_USE_ATTACH) return PRIVATE_IPC_LIMITS.ATTACH_CONTEXT_BYTES
  fail('stream context kind is not registered')
}

function normalizedOpenBinding (input) {
  if (!input || typeof input !== 'object') fail('stream open binding must be an object')
  const transportId = known(TRANSPORT_ID, input.transportId, 'transportId')
  const transportSupportBit = oneHotTransportSupport(input.transportSupportBit)
  const adjacentRelayKeyValue = input.adjacentRelayKey
  const adjacentRelayKey = adjacentRelayKeyValue == null ? null : fixed(adjacentRelayKeyValue, 32, 'adjacentRelayKey', true)
  const openDeadlineValue = input.openDeadlineMonotonicMillis
  const value = {
    openKind: known(LOCAL_STREAM_OPEN_KIND, input.openKind, 'openKind'),
    transportId,
    transportSupportBit,
    endpointId: endpointId(input.endpointId),
    streamMode: known(LOCAL_STREAM_MODE, input.streamMode, 'streamMode'),
    channelClass: input.channelClass,
    acceptedMonotonicMillis: u64(input.acceptedMonotonicMillis, 'acceptedMonotonicMillis'),
    openDeadlineMonotonicMillis: u64(openDeadlineValue == null
      ? input.absoluteDeadlineMonotonicMillis
      : openDeadlineValue, 'openDeadlineMonotonicMillis'),
    adjacentRelayKey
  }
  if (value.openDeadlineMonotonicMillis <= value.acceptedMonotonicMillis ||
      value.openDeadlineMonotonicMillis - value.acceptedMonotonicMillis > BigInt(PRIVATE_IPC_TIMING_MILLIS.STREAM_OPEN_ABSOLUTE)) {
    fail('stream open deadline is inverted or exceeds the 15000 ms cap')
  }
  if (!Number.isInteger(value.channelClass) || value.channelClass < 0 || value.channelClass > 3) fail('channelClass is outside 0..3')
  value.combination = openCombination(value.openKind, value.streamMode, value.channelClass, adjacentRelayKey != null)
  return value
}

function openBindingPreimage (open, context) {
  const adjacent = open.adjacentRelayKey == null ? [b4a.from([0])] : [b4a.from([1]), open.adjacentRelayKey]
  return b4a.concat([
    CHANNEL_DOMAIN,
    context.launchTopologyHash,
    b4a.from([open.openKind, open.transportId]),
    u16Bytes(open.transportSupportBit, 'transportSupportBit'),
    b4a.from([open.endpointId, open.streamMode, open.channelClass]),
    u64Bytes(open.acceptedMonotonicMillis),
    u64Bytes(open.openDeadlineMonotonicMillis),
    ...adjacent,
    context.edgeProcessNonce,
    context.localChannelNonce,
    context.parentSessionId,
    context.transportProfileHash,
    context.finalNoiseHandshakeHash
  ])
}

function keyedBlake2b256 (key, input) {
  const output = b4a.alloc(32)
  sodium.crypto_generichash(output, input, key)
  return output
}

export function deriveAuthenticatedSessionExporter (transportProfileHash, finalNoiseHandshakeHash) {
  transportProfileHash = fixed(transportProfileHash, 32, 'transportProfileHash', true)
  finalNoiseHandshakeHash = fixed(finalNoiseHandshakeHash, 64, 'finalNoiseHandshakeHash', true)
  return privateBlake2b256(b4a.concat([EXPORTER_DOMAIN, transportProfileHash, finalNoiseHandshakeHash]))
}

export function deriveLocalParentSessionId (input) {
  const launchTopologyHash = fixed(input.launchTopologyHash, 32, 'launchTopologyHash', true)
  const edgeProcessNonce = fixed(input.edgeProcessNonce, 32, 'edgeProcessNonce', true)
  const localChannelNonce = fixed(input.localChannelNonce, 32, 'localChannelNonce', true)
  const exporter = fixed(input.authenticatedSessionExporter, 32, 'authenticatedSessionExporter', true)
  return privateBlake2b256(b4a.concat([PARENT_DOMAIN, launchTopologyHash, edgeProcessNonce, localChannelNonce, exporter]))
}

export function encodeLocalAuthenticatedChannelContext (input) {
  const output = b4a.alloc(PRIVATE_IPC_LIMITS.AUTHENTICATED_CHANNEL_CONTEXT_BYTES)
  output[0] = 1
  b4a.copy(fixed(input.edgeProcessNonce, 32, 'edgeProcessNonce', true), output, 1)
  b4a.copy(fixed(input.localChannelNonce, 32, 'localChannelNonce', true), output, 33)
  b4a.copy(fixed(input.parentSessionId, 32, 'parentSessionId', true), output, 65)
  b4a.copy(fixed(input.transportProfileHash, 32, 'transportProfileHash', true), output, 97)
  b4a.copy(fixed(input.finalNoiseHandshakeHash, 64, 'finalNoiseHandshakeHash', true), output, 129)
  b4a.copy(fixed(input.channelBindingMac, 32, 'channelBindingMac', true), output, 193)
  return output
}

export function decodeLocalAuthenticatedChannelContext (input) {
  const body = snapshotBuffer(input, 'authenticated channel context')
  if (body.byteLength !== PRIVATE_IPC_LIMITS.AUTHENTICATED_CHANNEL_CONTEXT_BYTES || body[0] !== 1) {
    fail('authenticated channel context has an invalid exact shape')
  }
  return Object.freeze({
    version: 1,
    edgeProcessNonce: b4a.from(fixed(body.subarray(1, 33), 32, 'edgeProcessNonce', true)),
    localChannelNonce: b4a.from(fixed(body.subarray(33, 65), 32, 'localChannelNonce', true)),
    parentSessionId: b4a.from(fixed(body.subarray(65, 97), 32, 'parentSessionId', true)),
    transportProfileHash: b4a.from(fixed(body.subarray(97, 129), 32, 'transportProfileHash', true)),
    finalNoiseHandshakeHash: b4a.from(fixed(body.subarray(129, 193), 64, 'finalNoiseHandshakeHash', true)),
    channelBindingMac: b4a.from(fixed(body.subarray(193, 225), 32, 'channelBindingMac', true))
  })
}

export function createLocalAuthenticatedChannelContext (input, openInput) {
  const open = normalizedOpenBinding(openInput)
  if (open.combination.contextKind !== LOCAL_STREAM_CONTEXT_KIND.AUTHENTICATED_CHANNEL) {
    fail('authenticated channel context is invalid for this stream open combination')
  }
  const transportProfileHash = fixed(input.transportProfileHash, 32, 'transportProfileHash', true)
  const finalNoiseHandshakeHash = fixed(input.finalNoiseHandshakeHash, 64, 'finalNoiseHandshakeHash', true)
  const launchTopologyHash = fixed(input.launchTopologyHash, 32, 'launchTopologyHash', true)
  const edgeProcessNonce = fixed(input.edgeProcessNonce, 32, 'edgeProcessNonce', true)
  const localChannelNonce = fixed(input.localChannelNonce, 32, 'localChannelNonce', true)
  const authenticatedSessionExporter = deriveAuthenticatedSessionExporter(transportProfileHash, finalNoiseHandshakeHash)
  const parentSessionId = deriveLocalParentSessionId({ launchTopologyHash, edgeProcessNonce, localChannelNonce, authenticatedSessionExporter })
  const base = { launchTopologyHash, edgeProcessNonce, localChannelNonce, parentSessionId, transportProfileHash, finalNoiseHandshakeHash }
  const channelBindingMac = keyedBlake2b256(authenticatedSessionExporter, openBindingPreimage(open, base))
  return encodeLocalAuthenticatedChannelContext({ ...base, channelBindingMac })
}

export function verifyLocalAuthenticatedChannelContext (input, openInput, options = {}) {
  const open = normalizedOpenBinding(openInput)
  if (open.combination.contextKind !== LOCAL_STREAM_CONTEXT_KIND.AUTHENTICATED_CHANNEL) {
    fail('authenticated channel context is invalid for this stream open combination')
  }
  const context = input && input.version === 1 && input.channelBindingMac
    ? decodeLocalAuthenticatedChannelContext(encodeLocalAuthenticatedChannelContext(input))
    : decodeLocalAuthenticatedChannelContext(input)
  const launchTopologyHash = fixed(options.launchTopologyHash, 32, 'launchTopologyHash', true)
  const expectedTransportProfileHash = fixed(options.transportProfileHash, 32, 'expected transportProfileHash', true)
  if (!sodium.sodium_memcmp(context.transportProfileHash, expectedTransportProfileHash)) {
    fail('authenticated channel transport profile does not match')
  }
  const exporter = deriveAuthenticatedSessionExporter(context.transportProfileHash, context.finalNoiseHandshakeHash)
  const parent = deriveLocalParentSessionId({
    launchTopologyHash,
    edgeProcessNonce: context.edgeProcessNonce,
    localChannelNonce: context.localChannelNonce,
    authenticatedSessionExporter: exporter
  })
  if (!sodium.sodium_memcmp(parent, context.parentSessionId)) fail('authenticated channel parent session derivation does not match')
  const expectedMac = keyedBlake2b256(exporter, openBindingPreimage(open, { ...context, launchTopologyHash }))
  if (!sodium.sodium_memcmp(expectedMac, context.channelBindingMac)) fail('authenticated channel binding MAC does not match')
  const handle = Object.freeze(Object.create(null))
  VERIFIED_CHANNELS.set(handle, Object.freeze({
    parentSessionId: b4a.from(parent),
    authenticatedSessionExporter: b4a.from(exporter),
    transportProfileHash: b4a.from(context.transportProfileHash),
    edgeProcessNonce: b4a.from(context.edgeProcessNonce),
    localChannelNonce: b4a.from(context.localChannelNonce),
    endpointId: open.endpointId,
    transportId: open.transportId,
    transportSupportBit: open.transportSupportBit
  }))
  return handle
}

export function localAuthenticatedChannelAuthority (handle) {
  const state = VERIFIED_CHANNELS.get(handle)
  if (!state) fail('authenticated channel authority requires a verified branded handle', 'LOCAL_CHANNEL_AUTHORITY_REQUIRED')
  return Object.freeze({
    ...state,
    parentSessionId: b4a.from(state.parentSessionId),
    authenticatedSessionExporter: b4a.from(state.authenticatedSessionExporter),
    transportProfileHash: b4a.from(state.transportProfileHash),
    edgeProcessNonce: b4a.from(state.edgeProcessNonce),
    localChannelNonce: b4a.from(state.localChannelNonce)
  })
}

export function encodeLocalStreamAttachContext (input) {
  const output = b4a.alloc(PRIVATE_IPC_LIMITS.ATTACH_CONTEXT_BYTES)
  output[0] = 1
  b4a.copy(fixed(input.ticket, 32, 'ticket', true), output, 1)
  b4a.copy(fixed(input.parentSessionId, 32, 'parentSessionId', true), output, 33)
  writeU64BE(output, u64(input.descriptorSequence, 'descriptorSequence', true), 65)
  b4a.copy(fixed(input.descriptorHash, 32, 'descriptorHash', true), output, 73)
  b4a.copy(fixed(input.bindingHash, 32, 'bindingHash', true), output, 105)
  return output
}

export function decodeLocalStreamAttachContext (input) {
  const body = snapshotBuffer(input, 'stream attach context')
  if (body.byteLength !== PRIVATE_IPC_LIMITS.ATTACH_CONTEXT_BYTES || body[0] !== 1) fail('stream attach context has an invalid exact shape')
  return Object.freeze({
    version: 1,
    ticket: b4a.from(fixed(body.subarray(1, 33), 32, 'ticket', true)),
    parentSessionId: b4a.from(fixed(body.subarray(33, 65), 32, 'parentSessionId', true)),
    descriptorSequence: u64(readU64BE(body, 65), 'descriptorSequence', true),
    descriptorHash: b4a.from(fixed(body.subarray(73, 105), 32, 'descriptorHash', true)),
    bindingHash: b4a.from(fixed(body.subarray(105, 137), 32, 'bindingHash', true))
  })
}

function attachBinding (value) {
  return privateBlake2b256(b4a.concat([
    ATTACH_DOMAIN,
    value.parentSessionId,
    u64Bytes(value.descriptorSequence),
    value.descriptorHash,
    value.bindingHash
  ]))
}

function randomNonzero32 (randomBytes) {
  for (let attempt = 0; attempt < 8; attempt++) {
    const value = fixed(randomBytes(32), 32, 'random ticket')
    if (!isZero(value)) return b4a.from(value)
  }
  fail('ticket entropy source repeatedly returned all-zero bytes', 'LOCAL_TICKET_ENTROPY')
}

export class OneUseLocalStreamTickets {
  constructor (options = {}) {
    this.now = typeof options.monotonicMillis === 'function' ? options.monotonicMillis : () => process.hrtime.bigint() / 1_000_000n
    this.randomBytes = typeof options.randomBytes === 'function' ? options.randomBytes : crypto.randomBytes
    this.maxTickets = options.maxTickets == null ? PRIVATE_IPC_LIMITS.MAX_PENDING_CHILD_TICKETS : options.maxTickets
    this.ttlMillis = options.ttlMillis == null ? PRIVATE_IPC_TIMING_MILLIS.CHILD_TICKET_TTL : options.ttlMillis
    if (!Number.isSafeInteger(this.maxTickets) || this.maxTickets < 1 || this.maxTickets > PRIVATE_IPC_LIMITS.MAX_PENDING_CHILD_TICKETS) {
      throw new TypeError('maxTickets is outside the private IPC bound')
    }
    if (!Number.isSafeInteger(this.ttlMillis) || this.ttlMillis < 1 || this.ttlMillis > PRIVATE_IPC_TIMING_MILLIS.CHILD_TICKET_TTL) {
      throw new TypeError('ttlMillis is outside the private IPC bound')
    }
    this.records = new Map()
  }

  issue (input) {
    this.sweep()
    if (this.records.size >= this.maxTickets) fail('one-use child ticket capacity is exhausted', 'LOCAL_TICKET_BUSY')
    const normalized = decodeLocalStreamAttachContext(encodeLocalStreamAttachContext({ ...input, ticket: b4a.alloc(32, 1) }))
    let ticket
    let key
    for (let attempt = 0; attempt < 8; attempt++) {
      ticket = randomNonzero32(this.randomBytes)
      key = b4a.toString(ticket, 'hex')
      if (!this.records.has(key)) break
      ticket = null
    }
    if (!ticket) fail('ticket entropy source repeatedly collided', 'LOCAL_TICKET_ENTROPY')
    const now = u64(this.now(), 'monotonicMillis')
    if (now > MAX_U64 - BigInt(this.ttlMillis)) fail('one-use child ticket expiry overflows u64')
    this.records.set(key, {
      binding: attachBinding(normalized),
      expiresMonotonicMillis: now + BigInt(this.ttlMillis)
    })
    return Object.freeze({
      ticket: b4a.from(ticket),
      context: encodeLocalStreamAttachContext({ ...normalized, ticket })
    })
  }

  consume (input, expected = {}) {
    const context = input && input.version === 1 && input.ticket
      ? decodeLocalStreamAttachContext(encodeLocalStreamAttachContext(input))
      : decodeLocalStreamAttachContext(input)
    const key = b4a.toString(context.ticket, 'hex')
    const record = this.records.get(key)
    if (!record) fail('one-use child ticket is unknown or already consumed', 'LOCAL_TICKET_TERMINAL')
    this.records.delete(key)
    const now = u64(this.now(), 'monotonicMillis')
    if (record.expiresMonotonicMillis <= now || !sodium.sodium_memcmp(record.binding, attachBinding(context))) {
      fail('one-use child ticket is expired or bound to another child', 'LOCAL_TICKET_TERMINAL')
    }
    for (const field of ['parentSessionId', 'descriptorHash', 'bindingHash']) {
      if (expected[field] != null && !sodium.sodium_memcmp(context[field], fixed(expected[field], 32, field, true))) {
        fail(`one-use child ticket ${field} does not match`, 'LOCAL_TICKET_TERMINAL')
      }
    }
    if (expected.descriptorSequence != null && context.descriptorSequence !== u64(expected.descriptorSequence, 'descriptorSequence', true)) {
      fail('one-use child ticket descriptorSequence does not match', 'LOCAL_TICKET_TERMINAL')
    }
    const handle = Object.freeze(Object.create(null))
    VERIFIED_ATTACHMENTS.set(handle, Object.freeze({ ...context, ticket: undefined }))
    return handle
  }

  sweep () {
    const now = u64(this.now(), 'monotonicMillis')
    for (const [key, record] of this.records) if (record.expiresMonotonicMillis <= now) this.records.delete(key)
  }

  clear () { this.records.clear() }
  get size () { this.sweep(); return this.records.size }
}

export function localStreamAttachmentAuthority (handle) {
  const state = VERIFIED_ATTACHMENTS.get(handle)
  if (!state) fail('stream attachment authority requires a consumed branded handle', 'LOCAL_ATTACHMENT_AUTHORITY_REQUIRED')
  return Object.freeze({
    parentSessionId: b4a.from(state.parentSessionId),
    descriptorSequence: state.descriptorSequence,
    descriptorHash: b4a.from(state.descriptorHash),
    bindingHash: b4a.from(state.bindingHash)
  })
}

export function localStreamOpenFrameLength (input) {
  const buffer = asBuffer(input, 'local stream open')
  const maximum = PRIVATE_IPC_LIMITS.STREAM_OPEN_ADJACENT_HEADER_BYTES + PRIVATE_IPC_LIMITS.MAX_STREAM_CONTEXT_BYTES
  const frameLength = declaredLength(buffer, maximum, 'local stream open')
  if (frameLength == null || buffer.byteLength < 29) return null
  if (buffer[4] !== 1) fail('local stream open version must be 1')
  const openKind = known(LOCAL_STREAM_OPEN_KIND, buffer[5], 'openKind')
  known(TRANSPORT_ID, buffer[6], 'transportId')
  oneHotTransportSupport((buffer[7] << 8) | buffer[8])
  endpointId(buffer[9])
  const streamMode = known(LOCAL_STREAM_MODE, buffer[10], 'streamMode')
  const channelClass = buffer[11]
  const accepted = readU64BE(buffer, 12)
  const deadline = readU64BE(buffer, 20)
  if (deadline <= accepted || deadline - accepted > BigInt(PRIVATE_IPC_TIMING_MILLIS.STREAM_OPEN_ABSOLUTE)) fail('stream open deadline is invalid')
  if (buffer[28] > 1) fail('stream open adjacent presence tag must be 0 or 1')
  const adjacentPresent = buffer[28] === 1
  const row = openCombination(openKind, streamMode, channelClass, adjacentPresent)
  const headerBytes = adjacentPresent ? PRIVATE_IPC_LIMITS.STREAM_OPEN_ADJACENT_HEADER_BYTES : PRIVATE_IPC_LIMITS.STREAM_OPEN_BASE_HEADER_BYTES
  if (frameLength < headerBytes || buffer.byteLength < headerBytes) return buffer.byteLength < headerBytes ? null : fail('stream open totalLength is shorter than its header')
  const lengthOffset = adjacentPresent ? 61 : 29
  const contextLength = b4a.readUInt32BE(buffer, lengthOffset)
  const expectedContextLength = contextBytesFor(row.contextKind)
  if (contextLength !== expectedContextLength) fail('stream open context length does not match its registered combination')
  if (frameLength !== headerBytes + contextLength) fail('stream open totalLength does not match its fields')
  if (buffer.byteLength >= frameLength) {
    const context = buffer.subarray(headerBytes, frameLength)
    if (row.contextKind === LOCAL_STREAM_CONTEXT_KIND.AUTHENTICATED_CHANNEL) decodeLocalAuthenticatedChannelContext(context)
    else decodeLocalStreamAttachContext(context)
  }
  return frameLength
}

export function encodeLocalStreamOpen (input) {
  const open = normalizedOpenBinding(input)
  const context = snapshotBuffer(input.context, 'stream open context')
  if (context.byteLength !== contextBytesFor(open.combination.contextKind)) fail('stream open context length does not match its registered combination')
  if (open.combination.contextKind === LOCAL_STREAM_CONTEXT_KIND.AUTHENTICATED_CHANNEL) decodeLocalAuthenticatedChannelContext(context)
  else decodeLocalStreamAttachContext(context)
  const headerBytes = open.adjacentRelayKey == null
    ? PRIVATE_IPC_LIMITS.STREAM_OPEN_BASE_HEADER_BYTES
    : PRIVATE_IPC_LIMITS.STREAM_OPEN_ADJACENT_HEADER_BYTES
  const output = b4a.alloc(headerBytes + context.byteLength)
  b4a.writeUInt32BE(output, output.byteLength - 4, 0)
  output[4] = 1
  output[5] = open.openKind
  output[6] = open.transportId
  output[7] = open.transportSupportBit >>> 8
  output[8] = open.transportSupportBit & 0xff
  output[9] = open.endpointId
  output[10] = open.streamMode
  output[11] = open.channelClass
  writeU64BE(output, open.acceptedMonotonicMillis, 12)
  writeU64BE(output, open.openDeadlineMonotonicMillis, 20)
  output[28] = open.adjacentRelayKey == null ? 0 : 1
  let offset = 29
  if (open.adjacentRelayKey != null) {
    b4a.copy(open.adjacentRelayKey, output, offset)
    offset += 32
  }
  b4a.writeUInt32BE(output, context.byteLength, offset)
  b4a.copy(context, output, offset + 4)
  return output
}

export function decodeLocalStreamOpen (input, options = {}) {
  const buffer = snapshotBuffer(input, 'local stream open')
  const expected = localStreamOpenFrameLength(buffer)
  if (expected == null || buffer.byteLength < expected) fail('local stream open is truncated')
  if (buffer.byteLength !== expected) fail('local stream open length mismatch or trailing bytes')
  const adjacentPresent = buffer[28] === 1
  const headerBytes = adjacentPresent ? PRIVATE_IPC_LIMITS.STREAM_OPEN_ADJACENT_HEADER_BYTES : PRIVATE_IPC_LIMITS.STREAM_OPEN_BASE_HEADER_BYTES
  const contextView = buffer.subarray(headerBytes)
  const open = normalizedOpenBinding({
    openKind: buffer[5],
    transportId: buffer[6],
    transportSupportBit: (buffer[7] << 8) | buffer[8],
    endpointId: buffer[9],
    streamMode: buffer[10],
    channelClass: buffer[11],
    acceptedMonotonicMillis: readU64BE(buffer, 12),
    openDeadlineMonotonicMillis: readU64BE(buffer, 20),
    adjacentRelayKey: adjacentPresent ? buffer.subarray(29, 61) : null
  })
  const contextBytes = options.copyContext === true ? b4a.from(contextView) : contextView
  return Object.freeze({
    version: 1,
    openKind: open.openKind,
    transportId: open.transportId,
    transportSupportBit: open.transportSupportBit,
    endpointId: open.endpointId,
    streamMode: open.streamMode,
    channelClass: open.channelClass,
    acceptedMonotonicMillis: open.acceptedMonotonicMillis,
    openDeadlineMonotonicMillis: open.openDeadlineMonotonicMillis,
    adjacentRelayKey: open.adjacentRelayKey == null ? null : b4a.from(open.adjacentRelayKey),
    contextKind: open.combination.contextKind,
    contextBytes,
    context: open.combination.contextKind === LOCAL_STREAM_CONTEXT_KIND.AUTHENTICATED_CHANNEL
      ? decodeLocalAuthenticatedChannelContext(contextBytes)
      : decodeLocalStreamAttachContext(contextBytes)
  })
}

function controlId (value) { return u64(value, 'controlId', true) }

export function encodeLocalStreamControl (input) {
  if (!input || typeof input !== 'object') fail('stream control must be an object')
  const kind = known(LOCAL_STREAM_CONTROL_KIND, input.controlKind, 'controlKind')
  const id = controlId(input.controlId)
  let output
  if (kind === LOCAL_STREAM_CONTROL_KIND.CHANNEL_ACCEPT) {
    output = b4a.alloc(LOCAL_STREAM_CONTROL_BYTES.CHANNEL_ACCEPT)
    b4a.copy(fixed(input.bindingHash, 32, 'bindingHash', true), output, 10)
  } else if (kind === LOCAL_STREAM_CONTROL_KIND.CHANNEL_REJECT) {
    output = b4a.alloc(LOCAL_STREAM_CONTROL_BYTES.CHANNEL_REJECT)
    if (!Number.isInteger(input.localBrokerError) || input.localBrokerError < 1 || input.localBrokerError > 6) fail('localBrokerError is outside 1..6')
    output[10] = input.localBrokerError
  } else if (kind === LOCAL_STREAM_CONTROL_KIND.ATTACH_TICKET) {
    output = b4a.alloc(LOCAL_STREAM_CONTROL_BYTES.ATTACH_TICKET)
    b4a.copy(fixed(input.ticket, 32, 'ticket', true), output, 10)
    b4a.copy(fixed(input.bindingHash, 32, 'bindingHash', true), output, 42)
  } else if (kind === LOCAL_STREAM_CONTROL_KIND.EGRESS_DIAL) {
    output = b4a.alloc(LOCAL_STREAM_CONTROL_BYTES.EGRESS_DIAL)
    let offset = 10
    for (const [field, length] of [['endpointBindingHash', 32], ['bindingTableHash', 32], ['transportProfileHash', 32]]) {
      b4a.copy(fixed(input[field], length, field, true), output, offset); offset += length
    }
    if (!STREAM_WIRE_CLASS[input.wireClass]) fail('wireClass is outside 1..3')
    output[offset++] = input.wireClass
    writeU64BE(output, u64(input.connectDeadlineMonotonicMillis, 'connectDeadlineMonotonicMillis', true), offset); offset += 8
    for (const [field, bytes] of [['maxOpenBytes', 4], ['maxStreamBytes', 8], ['idleMillis', 4], ['lifetimeMillis', 4]]) {
      const value = field === 'maxStreamBytes' ? u64(input[field], field, true) : input[field]
      if (bytes === 8) writeU64BE(output, value, offset)
      else {
        if (!Number.isSafeInteger(value) || value < 1 || value > 0xffffffff) fail(`${field} is outside nonzero u32`)
        b4a.writeUInt32BE(output, value, offset)
      }
      offset += bytes
    }
    b4a.copy(fixed(input.ticket, 32, 'ticket', true), output, offset)
  } else if (kind === LOCAL_STREAM_CONTROL_KIND.EGRESS_RESULT) {
    const adjacentPresent = input.adjacentRelayKey != null
    output = b4a.alloc(adjacentPresent
      ? LOCAL_STREAM_CONTROL_BYTES.EGRESS_RESULT_SUCCESS
      : LOCAL_STREAM_CONTROL_BYTES.EGRESS_RESULT_FAILURE)
    if (!Number.isInteger(input.status) || input.status < 0 || input.status > 6) fail('egress result status is outside 0..6')
    output[10] = input.status
    b4a.copy(fixed(input.endpointBindingHash, 32, 'endpointBindingHash', true), output, 11)
    output[43] = adjacentPresent ? 1 : 0
    let offset = 44
    if (adjacentPresent) { b4a.copy(fixed(input.adjacentRelayKey, 32, 'adjacentRelayKey', true), output, offset); offset += 32 }
    b4a.copy(fixed(input.ticket, 32, 'ticket', true), output, offset)
    if ((input.status === 0) !== adjacentPresent) fail('successful egress result requires exactly one adjacent relay key')
  } else if (kind === LOCAL_STREAM_CONTROL_KIND.CORE_CHILD_OPEN) {
    output = b4a.alloc(LOCAL_STREAM_CONTROL_BYTES.CORE_CHILD_OPEN)
    writeU64BE(output, u64(input.streamId, 'streamId', true), 10)
    b4a.copy(fixed(input.ticket, 32, 'ticket', true), output, 18)
    b4a.copy(fixed(input.bindingHash, 32, 'bindingHash', true), output, 50)
  } else {
    output = b4a.alloc(LOCAL_STREAM_CONTROL_BYTES.NOISE_SESSION_OPEN)
    let offset = 10
    for (const field of ['endpointBindingHash', 'handshakeProfileHash', 'prologueHash']) {
      b4a.copy(fixed(input[field], 32, field, true), output, offset); offset += 32
    }
    if (!STREAM_WIRE_CLASS[input.wireClass]) fail('wireClass is outside 1..3')
    output[offset++] = input.wireClass
    b4a.copy(fixed(input.ticket, 32, 'ticket', true), output, offset)
  }
  output[0] = 1
  output[1] = kind
  writeU64BE(output, id, 2)
  return output
}

export function decodeLocalStreamControl (input) {
  const body = snapshotBuffer(input, 'stream control')
  if (body.byteLength < 10 || body[0] !== 1) fail('stream control has an invalid prefix')
  const kind = known(LOCAL_STREAM_CONTROL_KIND, body[1], 'controlKind')
  const id = controlId(readU64BE(body, 2))
  const value = { version: 1, controlKind: kind, controlId: id }
  if (kind === LOCAL_STREAM_CONTROL_KIND.CHANNEL_ACCEPT) {
    if (body.byteLength !== LOCAL_STREAM_CONTROL_BYTES.CHANNEL_ACCEPT) fail('CHANNEL_ACCEPT has an invalid exact length')
    value.bindingHash = b4a.from(fixed(body.subarray(10, 42), 32, 'bindingHash', true))
  } else if (kind === LOCAL_STREAM_CONTROL_KIND.CHANNEL_REJECT) {
    if (body.byteLength !== LOCAL_STREAM_CONTROL_BYTES.CHANNEL_REJECT || body[10] < 1 || body[10] > 6) fail('CHANNEL_REJECT has an invalid exact shape')
    value.localBrokerError = body[10]
  } else if (kind === LOCAL_STREAM_CONTROL_KIND.ATTACH_TICKET) {
    if (body.byteLength !== LOCAL_STREAM_CONTROL_BYTES.ATTACH_TICKET) fail('ATTACH_TICKET has an invalid exact length')
    value.ticket = b4a.from(fixed(body.subarray(10, 42), 32, 'ticket', true))
    value.bindingHash = b4a.from(fixed(body.subarray(42, 74), 32, 'bindingHash', true))
  } else if (kind === LOCAL_STREAM_CONTROL_KIND.EGRESS_DIAL) {
    if (body.byteLength !== LOCAL_STREAM_CONTROL_BYTES.EGRESS_DIAL) fail('EGRESS_DIAL has an invalid exact length')
    let offset = 10
    for (const field of ['endpointBindingHash', 'bindingTableHash', 'transportProfileHash']) {
      value[field] = b4a.from(fixed(body.subarray(offset, offset + 32), 32, field, true)); offset += 32
    }
    value.wireClass = body[offset++]
    if (!STREAM_WIRE_CLASS[value.wireClass]) fail('EGRESS_DIAL wireClass is outside 1..3')
    value.connectDeadlineMonotonicMillis = u64(readU64BE(body, offset), 'connectDeadlineMonotonicMillis', true); offset += 8
    value.maxOpenBytes = b4a.readUInt32BE(body, offset); offset += 4
    value.maxStreamBytes = u64(readU64BE(body, offset), 'maxStreamBytes', true); offset += 8
    value.idleMillis = b4a.readUInt32BE(body, offset); offset += 4
    value.lifetimeMillis = b4a.readUInt32BE(body, offset); offset += 4
    if (value.maxOpenBytes === 0 || value.idleMillis === 0 || value.lifetimeMillis === 0) fail('EGRESS_DIAL contains a zero bound')
    value.ticket = b4a.from(fixed(body.subarray(offset, offset + 32), 32, 'ticket', true))
  } else if (kind === LOCAL_STREAM_CONTROL_KIND.EGRESS_RESULT) {
    if (body.byteLength !== LOCAL_STREAM_CONTROL_BYTES.EGRESS_RESULT_FAILURE &&
        body.byteLength !== LOCAL_STREAM_CONTROL_BYTES.EGRESS_RESULT_SUCCESS) fail('EGRESS_RESULT has an invalid exact length')
    value.status = body[10]
    if (value.status > 6) fail('EGRESS_RESULT status is outside 0..6')
    value.endpointBindingHash = b4a.from(fixed(body.subarray(11, 43), 32, 'endpointBindingHash', true))
    const present = body[43]
    if (present > 1 || (present === 1) !== (body.byteLength === LOCAL_STREAM_CONTROL_BYTES.EGRESS_RESULT_SUCCESS) ||
        (value.status === 0) !== (present === 1)) fail('EGRESS_RESULT adjacent/status shape is invalid')
    let offset = 44
    value.adjacentRelayKey = present
      ? b4a.from(fixed(body.subarray(offset, offset + 32), 32, 'adjacentRelayKey', true))
      : null
    if (present) offset += 32
    value.ticket = b4a.from(fixed(body.subarray(offset, offset + 32), 32, 'ticket', true))
  } else if (kind === LOCAL_STREAM_CONTROL_KIND.CORE_CHILD_OPEN) {
    if (body.byteLength !== LOCAL_STREAM_CONTROL_BYTES.CORE_CHILD_OPEN) fail('CORE_CHILD_OPEN has an invalid exact length')
    value.streamId = u64(readU64BE(body, 10), 'streamId', true)
    value.ticket = b4a.from(fixed(body.subarray(18, 50), 32, 'ticket', true))
    value.bindingHash = b4a.from(fixed(body.subarray(50, 82), 32, 'bindingHash', true))
  } else {
    if (body.byteLength !== LOCAL_STREAM_CONTROL_BYTES.NOISE_SESSION_OPEN) fail('NOISE_SESSION_OPEN has an invalid exact length')
    let offset = 10
    for (const field of ['endpointBindingHash', 'handshakeProfileHash', 'prologueHash']) {
      value[field] = b4a.from(fixed(body.subarray(offset, offset + 32), 32, field, true)); offset += 32
    }
    value.wireClass = body[offset++]
    if (!STREAM_WIRE_CLASS[value.wireClass]) fail('NOISE_SESSION_OPEN wireClass is outside 1..3')
    value.ticket = b4a.from(fixed(body.subarray(offset, offset + 32), 32, 'ticket', true))
  }
  return Object.freeze(value)
}

function validateFrameShape (frameKind, wireClass, flags, body, phase = null) {
  known(LOCAL_STREAM_FRAME_KIND, frameKind, 'frameKind')
  if (phase != null) known(LOCAL_CIPHERTEXT_PHASE, phase, 'ciphertextPhase')
  if (!Number.isInteger(flags) || (flags & ~LOCAL_STREAM_FLAG.FIN) !== 0) fail('local stream flags contain a reserved bit')
  const fin = (flags & LOCAL_STREAM_FLAG.FIN) !== 0
  if (frameKind === LOCAL_STREAM_FRAME_KIND.CONTENT) {
    const classBytes = STREAM_WIRE_CLASS[wireClass]
    if (!classBytes || body.byteLength > classBytes - PRIVATE_IPC_LIMITS.STREAM_CONTENT_OVERHEAD_BYTES ||
        (body.byteLength === 0 && !fin)) {
      fail('CONTENT frame exceeds its selected wire-class content cap or is empty without FIN')
    }
  } else if (frameKind === LOCAL_STREAM_FRAME_KIND.CORE_RAW) {
    if (wireClass !== 0 || body.byteLength > PRIVATE_IPC_LIMITS.MAX_CORE_RAW_BYTES || (body.byteLength === 0 && !fin)) {
      fail('CORE_RAW frame has an invalid class, length, or empty non-FIN body')
    }
  } else if (frameKind === LOCAL_STREAM_FRAME_KIND.CIPHERTEXT) {
    if (fin) fail('CIPHERTEXT frame cannot carry a local FIN flag')
    if (wireClass === 0) {
      const allowed = phase === LOCAL_CIPHERTEXT_PHASE.FLIGHT_1
        ? LOCAL_CIPHERTEXT_BYTES.FLIGHT_1
        : phase === LOCAL_CIPHERTEXT_PHASE.FLIGHT_2
          ? LOCAL_CIPHERTEXT_BYTES.FLIGHT_2
          : phase === LOCAL_CIPHERTEXT_PHASE.FLIGHT_3 ? LOCAL_CIPHERTEXT_BYTES.FLIGHT_3 : null
      if (phase === LOCAL_CIPHERTEXT_PHASE.TRANSPORT ||
          (allowed == null ? !Object.values(LOCAL_CIPHERTEXT_BYTES).includes(body.byteLength) : body.byteLength !== allowed)) {
        fail('CIPHERTEXT handshake frame length does not match its phase')
      }
    } else if (!STREAM_WIRE_CLASS[wireClass] || body.byteLength !== STREAM_WIRE_CLASS[wireClass] ||
      (phase != null && phase !== LOCAL_CIPHERTEXT_PHASE.TRANSPORT)) {
      fail('CIPHERTEXT transport frame does not match its exact wire class or phase')
    }
  } else if (frameKind === LOCAL_STREAM_FRAME_KIND.CONTROL) {
    if (wireClass !== 0 || flags !== 0 || body.byteLength < 1 || body.byteLength > PRIVATE_IPC_LIMITS.CONTROL_BODY_BYTES) {
      fail('CONTROL frame has an invalid class, flags, or bound')
    }
    decodeLocalStreamControl(body)
  } else {
    if (wireClass !== 0 || flags !== 0 || body.byteLength !== 1 || !Object.values(LOCAL_ABORT_CODE).includes(body[0])) {
      fail('ABORT frame must carry one registered generic code')
    }
  }
}

export function localStreamFrameLength (input, options = {}) {
  const buffer = asBuffer(input, 'local stream frame')
  const maximum = PRIVATE_IPC_LIMITS.STREAM_FRAME_HEADER_BYTES + PRIVATE_IPC_LIMITS.MAX_STREAM_FRAME_BODY_BYTES
  const frameLength = declaredLength(buffer, maximum, 'local stream frame')
  if (frameLength == null || buffer.byteLength < PRIVATE_IPC_LIMITS.STREAM_FRAME_HEADER_BYTES) return null
  if (buffer[4] !== 1) fail('local stream frame version must be 1')
  known(LOCAL_STREAM_DIRECTION, buffer[5], 'direction')
  const frameKind = known(LOCAL_STREAM_FRAME_KIND, buffer[6], 'frameKind')
  const wireClass = buffer[15]
  const flags = buffer[16]
  const bodyLength = b4a.readUInt32BE(buffer, 17)
  if (frameLength !== PRIVATE_IPC_LIMITS.STREAM_FRAME_HEADER_BYTES + bodyLength) fail('local stream frame totalLength does not match its fields')
  if (buffer.byteLength >= frameLength) {
    validateFrameShape(frameKind, wireClass, flags,
      buffer.subarray(PRIVATE_IPC_LIMITS.STREAM_FRAME_HEADER_BYTES, frameLength), options.ciphertextPhase)
  }
  return frameLength
}

export function encodeLocalStreamFrame (input, options = {}) {
  if (!input || typeof input !== 'object') fail('local stream frame must be an object')
  const direction = known(LOCAL_STREAM_DIRECTION, input.direction, 'direction')
  const frameKind = known(LOCAL_STREAM_FRAME_KIND, input.frameKind, 'frameKind')
  const sequence = u64(input.sequence, 'sequence')
  const wireClass = input.wireClass == null ? 0 : input.wireClass
  const flags = input.flags == null ? 0 : input.flags
  const bodyValue = input.body
  const body = snapshotBuffer(bodyValue == null ? input.bytes : bodyValue, 'stream frame bytes')
  validateFrameShape(frameKind, wireClass, flags, body, options.ciphertextPhase)
  const output = b4a.alloc(PRIVATE_IPC_LIMITS.STREAM_FRAME_HEADER_BYTES + body.byteLength)
  b4a.writeUInt32BE(output, output.byteLength - 4, 0)
  output[4] = 1
  output[5] = direction
  output[6] = frameKind
  writeU64BE(output, sequence, 7)
  output[15] = wireClass
  output[16] = flags
  b4a.writeUInt32BE(output, body.byteLength, 17)
  b4a.copy(body, output, PRIVATE_IPC_LIMITS.STREAM_FRAME_HEADER_BYTES)
  return output
}

export function decodeLocalStreamFrame (input, options = {}) {
  const buffer = snapshotBuffer(input, 'local stream frame')
  const expected = localStreamFrameLength(buffer, options)
  if (expected == null || buffer.byteLength < expected) fail('local stream frame is truncated')
  if (buffer.byteLength !== expected) fail('local stream frame length mismatch or trailing bytes')
  const view = buffer.subarray(PRIVATE_IPC_LIMITS.STREAM_FRAME_HEADER_BYTES)
  const bytes = options.copyBody === true ? b4a.from(view) : view
  const value = {
    version: 1,
    direction: buffer[5],
    frameKind: buffer[6],
    sequence: readU64BE(buffer, 7),
    wireClass: buffer[15],
    flags: buffer[16],
    bytes,
    externalCanonicalBytes: bytes
  }
  if (value.frameKind === LOCAL_STREAM_FRAME_KIND.CONTROL) value.control = decodeLocalStreamControl(bytes)
  if (value.frameKind === LOCAL_STREAM_FRAME_KIND.ABORT) value.abortCode = bytes[0]
  return Object.freeze(value)
}

export function validateLocalStreamFrameForOpen (frame, open, options = {}) {
  if (!frame || typeof frame !== 'object') fail('decoded stream frame is required')
  const mode = open.streamMode
  const allowed = mode === LOCAL_STREAM_MODE.CORE_RAW
    ? [LOCAL_STREAM_FRAME_KIND.CORE_RAW, LOCAL_STREAM_FRAME_KIND.CONTROL, LOCAL_STREAM_FRAME_KIND.ABORT]
    : mode === LOCAL_STREAM_MODE.NOISE_ENDPOINT
      ? [LOCAL_STREAM_FRAME_KIND.CONTENT, LOCAL_STREAM_FRAME_KIND.CIPHERTEXT, LOCAL_STREAM_FRAME_KIND.CONTROL, LOCAL_STREAM_FRAME_KIND.ABORT]
      : [LOCAL_STREAM_FRAME_KIND.CONTENT, LOCAL_STREAM_FRAME_KIND.CONTROL, LOCAL_STREAM_FRAME_KIND.ABORT]
  if (!allowed.includes(frame.frameKind)) fail('stream frame kind is invalid for the opened stream mode')
  if ((frame.frameKind === LOCAL_STREAM_FRAME_KIND.CONTENT ||
       (frame.frameKind === LOCAL_STREAM_FRAME_KIND.CIPHERTEXT && frame.wireClass !== 0)) && frame.wireClass !== open.channelClass) {
    fail('stream frame wireClass differs from the opened channel class')
  }
  validateFrameShape(frame.frameKind, frame.wireClass, frame.flags, frame.bytes || frame.externalCanonicalBytes,
    options.ciphertextPhase)
  return frame
}

export class LocalStreamSequenceGuard {
  constructor (open = null) {
    this.open = open
    this.nextByDirection = new Map([
      [LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON, 0n],
      [LOCAL_STREAM_DIRECTION.DAEMON_TO_EDGE, 0n]
    ])
    this.finByDirection = new Set()
    this.closed = false
  }

  accept (frame, options = {}) {
    if (this.closed) fail('local stream is already closed')
    const direction = known(LOCAL_STREAM_DIRECTION, frame.direction, 'direction')
    const sequence = u64(frame.sequence, 'sequence')
    const expected = this.nextByDirection.get(direction)
    if (sequence !== expected) fail('local stream physical sequence is not first-zero exact +1')
    if (this.finByDirection.has(direction) && frame.frameKind !== LOCAL_STREAM_FRAME_KIND.ABORT) fail('local stream direction received bytes after FIN')
    if (this.open) {
      validateLocalStreamFrameForOpen(frame, this.open, options)
    } else {
      validateFrameShape(frame.frameKind, frame.wireClass, frame.flags,
        frame.bytes || frame.externalCanonicalBytes, options.ciphertextPhase)
    }
    this.nextByDirection.set(direction, expected + 1n)
    if ((frame.flags & LOCAL_STREAM_FLAG.FIN) !== 0) this.finByDirection.add(direction)
    if (frame.frameKind === LOCAL_STREAM_FRAME_KIND.ABORT) this.closed = true
    return frame
  }
}

export function fragmentLocalContent (input, options) {
  const bytes = snapshotBuffer(input, 'content bytes')
  if (!options || typeof options !== 'object') fail('content fragmentation options must be an object')
  const wireClass = options.wireClass
  if (!STREAM_WIRE_CLASS[wireClass]) fail('wireClass is outside 1..3')
  const maximum = STREAM_WIRE_CLASS[wireClass] - PRIVATE_IPC_LIMITS.STREAM_CONTENT_OVERHEAD_BYTES
  let sequence = u64(options.sequence == null ? 0n : options.sequence, 'sequence')
  const frames = []
  if (bytes.byteLength === 0) {
    if (options.fin !== true) fail('empty content fragmentation requires FIN')
    frames.push(encodeLocalStreamFrame({
      direction: options.direction,
      frameKind: LOCAL_STREAM_FRAME_KIND.CONTENT,
      sequence,
      wireClass,
      flags: options.fin === true ? LOCAL_STREAM_FLAG.FIN : 0,
      body: b4a.alloc(0)
    }))
    return frames
  }
  for (let offset = 0; offset < bytes.byteLength; offset += maximum) {
    const end = Math.min(bytes.byteLength, offset + maximum)
    const last = end === bytes.byteLength
    frames.push(encodeLocalStreamFrame({
      direction: options.direction,
      frameKind: LOCAL_STREAM_FRAME_KIND.CONTENT,
      sequence,
      wireClass,
      flags: last && options.fin === true ? LOCAL_STREAM_FLAG.FIN : 0,
      body: bytes.subarray(offset, end)
    }))
    if (sequence === MAX_U64 && !last) fail('content fragmentation sequence overflows u64')
    sequence++
  }
  return frames
}

export class LocalLengthPrefixedReassembler {
  constructor (options = {}) {
    this.maxItemBytes = options.maxItemBytes == null ? DISPATCH_LIMITS.MAX_WIRE_BYTES : options.maxItemBytes
    if (!Number.isSafeInteger(this.maxItemBytes) || this.maxItemBytes < 4 || this.maxItemBytes > DISPATCH_LIMITS.MAX_WIRE_BYTES) {
      throw new TypeError('maxItemBytes is outside the canonical dispatch cap')
    }
    this.maxBufferedBytes = options.maxBufferedBytes == null
      ? this.maxItemBytes + Math.max(...Object.values(STREAM_WIRE_CLASS))
      : options.maxBufferedBytes
    if (!Number.isSafeInteger(this.maxBufferedBytes) || this.maxBufferedBytes < this.maxItemBytes ||
        this.maxBufferedBytes > this.maxItemBytes + Math.max(...Object.values(STREAM_WIRE_CLASS))) {
      throw new TypeError('maxBufferedBytes is outside the one-item-plus-one-record cap')
    }
    this.wireClass = options.wireClass == null ? null : options.wireClass
    if (this.wireClass != null && !STREAM_WIRE_CLASS[this.wireClass]) throw new TypeError('wireClass is outside 1..3')
    this.prefix = b4a.alloc(4)
    this.prefixBytes = 0
    this.item = null
    this.itemBytes = 0
    this.ended = false
  }

  push (frame) {
    if (this.ended) fail('content reassembler is already finished')
    if (frame.frameKind !== LOCAL_STREAM_FRAME_KIND.CONTENT) fail('content reassembler accepts only CONTENT frames')
    const frameBytes = frame.bytes
    const bytes = snapshotBuffer(frameBytes || frame.externalCanonicalBytes, 'content frame bytes')
    validateFrameShape(frame.frameKind, frame.wireClass, frame.flags, bytes)
    if (this.wireClass == null) this.wireClass = frame.wireClass
    if (frame.wireClass !== this.wireClass) fail('content reassembly wireClass changed within one stream')
    const reservedBytes = this.item == null ? this.prefixBytes : this.item.byteLength
    if (reservedBytes + bytes.byteLength > this.maxBufferedBytes) fail('content reassembly exceeds its bounded buffer')
    const complete = []
    let offset = 0
    while (offset < bytes.byteLength) {
      if (this.item == null) {
        const copied = Math.min(4 - this.prefixBytes, bytes.byteLength - offset)
        b4a.copy(bytes, this.prefix, this.prefixBytes, offset, offset + copied)
        this.prefixBytes += copied
        offset += copied
        if (this.prefixBytes < 4) continue
        const itemLength = 4 + b4a.readUInt32BE(this.prefix, 0)
        if (itemLength < 4 || itemLength > this.maxItemBytes) fail('length-prefixed content item exceeds its canonical cap')
        if (itemLength + bytes.byteLength > this.maxBufferedBytes) fail('content reassembly reservation exceeds its bounded buffer')
        this.item = b4a.allocUnsafe(itemLength)
        b4a.copy(this.prefix, this.item, 0)
        this.itemBytes = 4
      }
      const copied = Math.min(this.item.byteLength - this.itemBytes, bytes.byteLength - offset)
      if (copied > 0) {
        b4a.copy(bytes, this.item, this.itemBytes, offset, offset + copied)
        this.itemBytes += copied
        offset += copied
      }
      if (this.itemBytes === this.item.byteLength) {
        complete.push(this.item)
        this.item = null
        this.itemBytes = 0
        this.prefixBytes = 0
      }
    }
    if ((frame.flags & LOCAL_STREAM_FLAG.FIN) !== 0) {
      this.ended = true
      if (this.bufferedBytes !== 0) fail('content stream ended with an incomplete canonical item')
    }
    return complete
  }

  get bufferedBytes () { return this.item == null ? this.prefixBytes : this.itemBytes }
}
