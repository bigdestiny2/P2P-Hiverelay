import b4a from 'b4a'
import sodium from './crypto.js'
import { decodeDispatchFrame } from './dispatch.js'
import { DISPATCH_LIMITS, OUTER_CLASS } from './wire-runtime-authority.js'
import { protocolError } from './errors.js'

export const OUTER_ENVELOPE_HEADER_BYTES = 6

function asBuffer (value, field) {
  if (!value || typeof value.byteLength !== 'number') {
    protocolError('BAD_ENCODING', `${field} must be bytes`)
  }
  if (b4a.isBuffer(value)) return value
  if (ArrayBuffer.isView(value)) return b4a.from(value.buffer, value.byteOffset, value.byteLength)
  return b4a.from(value)
}

function defaultRandomFill (buffer) {
  if (buffer.byteLength > 0) sodium.randombytes_buf(buffer)
}

export function smallestOuterClass (innerLength) {
  if (!Number.isSafeInteger(innerLength) || innerLength < 0) {
    protocolError('BAD_ENCODING', 'innerLength must be a non-negative safe integer')
  }
  const required = OUTER_ENVELOPE_HEADER_BYTES + innerLength
  for (const [id, bytes] of Object.entries(OUTER_CLASS)) {
    if (required <= bytes) return Number(id)
  }
  protocolError('TOO_LARGE', 'dispatch does not fit an outer class')
}

export function encodeOuterEnvelope (input, options = {}) {
  if (!input || typeof input !== 'object') protocolError('BAD_ENCODING', 'outer envelope must be an object')
  const innerDispatch = asBuffer(input.innerDispatch, 'innerDispatch')
  if (innerDispatch.byteLength < DISPATCH_LIMITS.PREFIX_BYTES + DISPATCH_LIMITS.HEADER_BYTES) {
    protocolError('BAD_ENCODING', 'inner dispatch is truncated')
  }
  decodeDispatchFrame(innerDispatch)

  const outerClass = input.outerClass == null
    ? smallestOuterClass(innerDispatch.byteLength)
    : input.outerClass
  const classBytes = OUTER_CLASS[outerClass]
  if (!classBytes) protocolError('BAD_ENCODING', 'unknown outer class')
  if (OUTER_ENVELOPE_HEADER_BYTES + innerDispatch.byteLength > classBytes) {
    protocolError('TOO_LARGE', 'dispatch does not fit the selected outer class')
  }

  const output = b4a.alloc(classBytes)
  output[0] = 1
  output[1] = outerClass
  b4a.writeUInt32BE(output, innerDispatch.byteLength, 2)
  b4a.copy(innerDispatch, output, OUTER_ENVELOPE_HEADER_BYTES)
  const padding = output.subarray(OUTER_ENVELOPE_HEADER_BYTES + innerDispatch.byteLength)
  const randomFill = options.randomFill || defaultRandomFill
  if (typeof randomFill !== 'function') protocolError('BAD_ENCODING', 'randomFill must be a function')
  randomFill(padding)
  return output
}

export function decodeOuterEnvelope (input, options = {}) {
  input = asBuffer(input, 'outer envelope')
  if (input.byteLength < OUTER_ENVELOPE_HEADER_BYTES) {
    protocolError('BAD_ENCODING', 'outer envelope is truncated')
  }
  if (input[0] !== 1) protocolError('BAD_VERSION', 'outer envelope version must be 1')
  const outerClass = input[1]
  const classBytes = OUTER_CLASS[outerClass]
  if (!classBytes) protocolError('BAD_ENCODING', 'unknown outer class')
  if (input.byteLength !== classBytes) {
    protocolError('BAD_ENCODING', 'outer envelope does not exactly match its class')
  }

  const innerLength = b4a.readUInt32BE(input, 2)
  if (innerLength < DISPATCH_LIMITS.PREFIX_BYTES + DISPATCH_LIMITS.HEADER_BYTES) {
    protocolError('BAD_ENCODING', 'inner dispatch is truncated')
  }
  if (OUTER_ENVELOPE_HEADER_BYTES + innerLength > classBytes) {
    protocolError('BAD_ENCODING', 'inner dispatch exceeds the outer class')
  }
  const view = input.subarray(OUTER_ENVELOPE_HEADER_BYTES, OUTER_ENVELOPE_HEADER_BYTES + innerLength)
  const innerDispatch = options.copyInner === true ? b4a.from(view) : view
  const frame = decodeDispatchFrame(innerDispatch, { copyBody: options.copyBody === true })
  return { version: 1, outerClass, innerDispatch, frame }
}
