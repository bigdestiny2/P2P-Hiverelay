import b4a from 'b4a'
import { fail } from './errors.js'

export function asBytes (value, field, exactLength = null) {
  let bytes
  if (b4a.isBuffer(value)) bytes = value
  else if (ArrayBuffer.isView(value)) bytes = b4a.from(value.buffer, value.byteOffset, value.byteLength)
  else if (value instanceof ArrayBuffer) bytes = b4a.from(value)
  else fail('BAD_CLIENT_INPUT', `${field} must be bytes`)
  if (exactLength != null && bytes.byteLength !== exactLength) {
    fail('BAD_CLIENT_INPUT', `${field} must be exactly ${exactLength} bytes`)
  }
  return bytes
}

export function randomBytes (runtime, length, field = 'random bytes') {
  if (!runtime || typeof runtime.randomBytes !== 'function') {
    fail('CRYPTO_UNAVAILABLE', 'runtime.randomBytes is required')
  }
  const bytes = asBytes(runtime.randomBytes(length), field, length)
  return b4a.from(bytes)
}

export function encodeU32 (value, field) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    fail('BAD_CLIENT_INPUT', `${field} is outside u32`)
  }
  const output = b4a.alloc(4)
  b4a.writeUInt32BE(output, value, 0)
  return output
}

export function wipe (value) {
  if (value && typeof value.fill === 'function') value.fill(0)
}
