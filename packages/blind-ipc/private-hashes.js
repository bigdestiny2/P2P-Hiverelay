import b4a from 'b4a'
import sodium from 'sodium-universal'

const WIRE_ABI_DOMAIN = b4a.from('hiverelay.blind.abi-hash.v1', 'ascii')

function fail (message) {
  const error = new Error(message)
  error.code = 'BAD_PRIVATE_IPC_HASH_INPUT'
  throw error
}

function snapshotBytes (value, field) {
  if (!value || typeof value.byteLength !== 'number') fail(`${field} must be bytes`)
  if (ArrayBuffer.isView(value)) return b4a.from(value.buffer, value.byteOffset, value.byteLength)
  return b4a.from(value)
}

function len64 (length) {
  if (!Number.isSafeInteger(length) || length < 0) fail('hash input length is outside a safe u64')
  let value = BigInt(length)
  const output = b4a.alloc(8)
  for (let index = 7; index >= 0; index--) {
    output[index] = Number(value & 0xffn)
    value >>= 8n
  }
  return output
}

export function privateBlake2b256 (input) {
  const bytes = snapshotBytes(input, 'hash input')
  const output = b4a.alloc(32)
  sodium.crypto_generichash(output, bytes)
  return output
}

export function hashImportedWireAbi (input) {
  const bytes = snapshotBytes(input, 'public WIRE ABI')
  return privateBlake2b256(b4a.concat([WIRE_ABI_DOMAIN, len64(bytes.byteLength), bytes]))
}
