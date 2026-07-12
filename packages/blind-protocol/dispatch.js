import b4a from 'b4a'
import {
  DISPATCH_LIMITS,
  FAMILY,
  FRAME_KIND,
  OPERATION,
  isKnownOperation,
  operationProfile
} from './wire-runtime-authority.js'
import { protocolError } from './errors.js'

const MAX_U64 = (1n << 64n) - 1n
const WIRE_HEADER_BYTES = DISPATCH_LIMITS.PREFIX_BYTES + DISPATCH_LIMITS.HEADER_BYTES

function asBuffer (value, field) {
  if (!value || typeof value.byteLength !== 'number') {
    protocolError('BAD_ENCODING', `${field} must be bytes`)
  }
  if (b4a.isBuffer(value)) return value
  if (ArrayBuffer.isView(value)) return b4a.from(value.buffer, value.byteOffset, value.byteLength)
  return b4a.from(value)
}

function asU64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) {
      protocolError('BAD_ENCODING', `${field} must be an unsigned safe integer or bigint`)
    }
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
    protocolError('BAD_ENCODING', `${field} is outside u64`)
  }
  return value
}

function readU64BE (buffer, offset) {
  let value = 0n
  for (let i = 0; i < 8; i++) value = (value << 8n) | BigInt(buffer[offset + i])
  return value
}

function writeU64BE (buffer, value, offset) {
  for (let i = 7; i >= 0; i--) {
    buffer[offset + i] = Number(value & 0xffn)
    value >>= 8n
  }
}

function isAllZero (buffer) {
  for (let i = 0; i < buffer.byteLength; i++) {
    if (buffer[i] !== 0) return false
  }
  return true
}

function validateIds (familyId, operationId) {
  if (!Number.isInteger(familyId) || familyId < 1 || familyId > 255) {
    protocolError('BAD_ENCODING', 'familyId must be a nonzero u8')
  }
  if (!Number.isInteger(operationId) || operationId < 1 || operationId > 255) {
    protocolError('BAD_ENCODING', 'operationId must be a nonzero u8')
  }
  if (!isKnownOperation(familyId, operationId)) {
    protocolError('BAD_ENCODING', 'unknown family/operation pair')
  }
}

function isStreamingOpen (familyId, operationId) {
  return (familyId === FAMILY.FORWARD && operationId === OPERATION.FORWARD.OPEN) ||
    (familyId === FAMILY.CORE && operationId === OPERATION.CORE.OPEN_REPLICATION)
}

function isStreamOperation (familyId, operationId) {
  if (familyId !== FAMILY.FORWARD) return false
  return operationId === OPERATION.FORWARD.DATA ||
    operationId === OPERATION.FORWARD.WINDOW ||
    operationId === OPERATION.FORWARD.CLOSE
}

function validateFrameShape (frame) {
  if (frame.version !== 1) protocolError('BAD_VERSION', 'dispatch version must be 1')
  if (!Object.values(FRAME_KIND).includes(frame.frameKind)) {
    protocolError('BAD_ENCODING', 'unknown frame kind')
  }
  validateIds(frame.familyId, frame.operationId)
  const profile = operationProfile(frame.familyId, frame.operationId)
  if (profile) {
    const bit = 1 << (frame.frameKind - 1)
    const allowedBits = frame.frameKind === FRAME_KIND.REQUEST
      ? profile.allowedRequestKindBits
      : frame.frameKind === FRAME_KIND.STREAM
        ? profile.allowedRequestKindBits | profile.allowedResultKindBits
        : profile.allowedResultKindBits
    if ((allowedBits & bit) === 0) protocolError('BAD_ENCODING', 'frame kind is not allowed for the operation')
  }
  if (frame.flags !== 0) protocolError('BAD_ENCODING', 'dispatch flags are reserved')

  const requestId = asBuffer(frame.requestId, 'requestId')
  if (requestId.byteLength !== DISPATCH_LIMITS.REQUEST_ID_BYTES) {
    protocolError('BAD_ENCODING', 'requestId must be exactly 16 bytes')
  }
  const requestIdIsZero = isAllZero(requestId)
  const streamId = asU64(frame.streamId, 'streamId')
  const sequence = asU64(frame.sequence, 'sequence')

  if (frame.frameKind === FRAME_KIND.REQUEST) {
    if (requestIdIsZero || streamId !== 0n || sequence !== 0n) {
      protocolError('BAD_ENCODING', 'request frame correlation fields are invalid')
    }
  } else if (frame.frameKind === FRAME_KIND.RESPONSE) {
    if (requestIdIsZero || sequence !== 0n) {
      protocolError('BAD_ENCODING', 'response frame correlation fields are invalid')
    }
    const opensStream = isStreamingOpen(frame.familyId, frame.operationId)
    if ((opensStream && streamId === 0n) || (!opensStream && streamId !== 0n)) {
      protocolError('BAD_ENCODING', 'response streamId does not match the operation')
    }
  } else if (frame.frameKind === FRAME_KIND.ERROR) {
    const unary = !requestIdIsZero && streamId === 0n && sequence === 0n
    const stream = requestIdIsZero && streamId !== 0n && isStreamOperation(frame.familyId, frame.operationId)
    if (!unary && !stream) protocolError('BAD_ENCODING', 'error correlation fields are invalid')
  } else {
    if (!requestIdIsZero || streamId === 0n || !isStreamOperation(frame.familyId, frame.operationId)) {
      protocolError('BAD_ENCODING', 'stream frame correlation fields are invalid')
    }
  }

  return { requestId, streamId, sequence }
}

function validateOperationBodyCap (frameKind, familyId, operationId, bodyLength) {
  const profile = operationProfile(familyId, operationId)
  if (!profile) return
  const cap = frameKind === FRAME_KIND.REQUEST
    ? profile.maxRequestBodyBytes
    : frameKind === FRAME_KIND.STREAM
      ? Math.max(profile.maxRequestBodyBytes, profile.maxResultBodyBytes)
      : profile.maxResultBodyBytes
  if (bodyLength > cap) protocolError('TOO_LARGE', 'dispatch body exceeds the operation cap')
}

export function readDispatchLengthPrefix (prefix) {
  prefix = asBuffer(prefix, 'dispatch length prefix')
  if (prefix.byteLength < DISPATCH_LIMITS.PREFIX_BYTES) {
    protocolError('BAD_ENCODING', 'truncated dispatch length prefix')
  }
  const frameLength = b4a.readUInt32BE(prefix, 0)
  if (frameLength < DISPATCH_LIMITS.HEADER_BYTES) {
    protocolError('BAD_ENCODING', 'declared dispatch frame is shorter than its header')
  }
  if (frameLength > DISPATCH_LIMITS.MAX_FRAME_AFTER_PREFIX_BYTES) {
    protocolError('TOO_LARGE', 'declared dispatch frame exceeds the absolute cap')
  }
  return frameLength
}

export function encodeDispatchFrame (input) {
  if (!input || typeof input !== 'object') protocolError('BAD_ENCODING', 'dispatch frame must be an object')
  const body = input.body == null ? b4a.alloc(0) : asBuffer(input.body, 'body')
  if (body.byteLength > DISPATCH_LIMITS.MAX_BODY_BYTES) {
    protocolError('TOO_LARGE', 'dispatch body exceeds the absolute cap')
  }

  const frame = {
    version: input.version == null ? 1 : input.version,
    frameKind: input.frameKind,
    familyId: input.familyId,
    operationId: input.operationId,
    flags: input.flags == null ? 0 : input.flags,
    requestId: input.requestId,
    streamId: input.streamId == null ? 0n : input.streamId,
    sequence: input.sequence == null ? 0n : input.sequence
  }
  const normalized = validateFrameShape(frame)
  validateOperationBodyCap(frame.frameKind, frame.familyId, frame.operationId, body.byteLength)
  const frameLength = DISPATCH_LIMITS.HEADER_BYTES + body.byteLength
  if (frameLength > DISPATCH_LIMITS.MAX_FRAME_AFTER_PREFIX_BYTES) {
    protocolError('TOO_LARGE', 'dispatch frame exceeds the absolute cap')
  }

  const output = b4a.alloc(DISPATCH_LIMITS.PREFIX_BYTES + frameLength)
  b4a.writeUInt32BE(output, frameLength, 0)
  output[4] = frame.version
  output[5] = frame.frameKind
  output[6] = frame.familyId
  output[7] = frame.operationId
  output[8] = frame.flags
  b4a.copy(normalized.requestId, output, 9)
  writeU64BE(output, normalized.streamId, 25)
  writeU64BE(output, normalized.sequence, 33)
  b4a.writeUInt32BE(output, body.byteLength, 41)
  if (body.byteLength > 0) b4a.copy(body, output, WIRE_HEADER_BYTES)
  return output
}

export function decodeDispatchFrame (input, options = {}) {
  input = asBuffer(input, 'dispatch frame')
  if (input.byteLength < DISPATCH_LIMITS.PREFIX_BYTES) {
    protocolError('BAD_ENCODING', 'truncated dispatch frame')
  }
  const frameLength = readDispatchLengthPrefix(input)
  if (input.byteLength !== DISPATCH_LIMITS.PREFIX_BYTES + frameLength) {
    protocolError('BAD_ENCODING', 'dispatch frame length mismatch or trailing bytes')
  }

  const bodyLength = b4a.readUInt32BE(input, 41)
  if (bodyLength > DISPATCH_LIMITS.MAX_BODY_BYTES) {
    protocolError('TOO_LARGE', 'dispatch body exceeds the absolute cap')
  }
  if (frameLength !== DISPATCH_LIMITS.HEADER_BYTES + bodyLength) {
    protocolError('BAD_ENCODING', 'dispatch body length mismatch')
  }

  const frame = {
    version: input[4],
    frameKind: input[5],
    familyId: input[6],
    operationId: input[7],
    flags: input[8],
    requestId: b4a.from(input.subarray(9, 25)),
    streamId: readU64BE(input, 25),
    sequence: readU64BE(input, 33)
  }
  validateFrameShape(frame)
  validateOperationBodyCap(frame.frameKind, frame.familyId, frame.operationId, bodyLength)
  frame.body = options.copyBody === true
    ? b4a.from(input.subarray(WIRE_HEADER_BYTES))
    : input.subarray(WIRE_HEADER_BYTES)
  return frame
}

export class DispatchSequenceGuard {
  constructor (options = {}) {
    this.maxStreams = Number.isSafeInteger(options.maxStreams) && options.maxStreams > 0
      ? options.maxStreams
      : 1024
    this.lastByStream = new Map()
  }

  accept (frame) {
    if (!frame || (frame.frameKind !== FRAME_KIND.STREAM &&
      !(frame.frameKind === FRAME_KIND.ERROR && frame.streamId !== 0n))) return
    const streamId = asU64(frame.streamId, 'streamId')
    const sequence = asU64(frame.sequence, 'sequence')
    const key = streamId.toString(16)
    const previous = this.lastByStream.get(key)
    if (previous != null && sequence <= previous) {
      protocolError('BAD_ENCODING', 'stream sequence is duplicate or non-monotonic')
    }
    if (previous == null && this.lastByStream.size >= this.maxStreams) {
      protocolError('BUSY', 'stream sequence guard is full')
    }
    this.lastByStream.set(key, sequence)
  }

  close (streamId) {
    streamId = asU64(streamId, 'streamId')
    this.lastByStream.delete(streamId.toString(16))
  }

  clear () {
    this.lastByStream.clear()
  }
}

export { MAX_U64 }
