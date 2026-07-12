import b4a from 'b4a'
import { CELL_SIZE_CLASS } from '@hiverelay/blind-protocol/wire-runtime-authority'
import { blake2b256 } from '@hiverelay/blind-protocol/hashes'
import { asBytes, encodeU32, randomBytes, wipe } from './bytes.js'
import { fail } from './errors.js'

export const CELL_BLOB_FORMAT_VERSION = 1
export const CELL_NONCE_BYTES = 12
export const CELL_TAG_BYTES = 16
export const CELL_LENGTH_BYTES = 4
export const CELL_KEY_BYTES = 32

const CELL_AAD_DOMAIN = b4a.from('hiverelay.blind.cell.v1', 'ascii')

function classBytes (sizeClass) {
  if (!Number.isInteger(sizeClass) || CELL_SIZE_CLASS[sizeClass] == null) {
    fail('BAD_CLIENT_INPUT', 'sizeClass is outside the frozen cell classes')
  }
  return CELL_SIZE_CLASS[sizeClass]
}

function cellAad (storageSlot, sizeClass) {
  return b4a.concat([
    CELL_AAD_DOMAIN,
    b4a.from([CELL_BLOB_FORMAT_VERSION, sizeClass]),
    asBytes(storageSlot, 'storageSlot', 32)
  ])
}

function assertRuntime (runtime) {
  if (!runtime || typeof runtime.aes256GcmEncrypt !== 'function' || typeof runtime.aes256GcmDecrypt !== 'function') {
    fail('CRYPTO_UNAVAILABLE', 'runtime AES-256-GCM methods are required')
  }
}

export function maximumCellContentBytes (sizeClass) {
  return classBytes(sizeClass) - CELL_BLOB_FORMAT_VERSION - CELL_NONCE_BYTES - CELL_TAG_BYTES - CELL_LENGTH_BYTES
}

export async function sealCell (options) {
  if (!options || typeof options !== 'object') fail('BAD_CLIENT_INPUT', 'cell options are required')
  const runtime = options.runtime
  assertRuntime(runtime)
  const storageSlot = asBytes(options.storageSlot, 'storageSlot', 32)
  const structuredContent = asBytes(options.structuredContent, 'structuredContent')
  const sizeClass = options.sizeClass
  const totalBytes = classBytes(sizeClass)
  const maxContentBytes = maximumCellContentBytes(sizeClass)
  if (structuredContent.byteLength > maxContentBytes) {
    fail('CELL_CONTENT_TOO_LARGE', `structuredContent exceeds sizeClass ${sizeClass}`)
  }

  const cellKey = options.cellKey == null
    ? randomBytes(runtime, CELL_KEY_BYTES, 'cell key')
    : b4a.from(asBytes(options.cellKey, 'cellKey', CELL_KEY_BYTES))
  const nonce = options.nonce == null
    ? randomBytes(runtime, CELL_NONCE_BYTES, 'cell nonce')
    : b4a.from(asBytes(options.nonce, 'nonce', CELL_NONCE_BYTES))
  const plaintextBytes = totalBytes - 1 - CELL_NONCE_BYTES - CELL_TAG_BYTES
  const plaintext = b4a.alloc(plaintextBytes)
  b4a.copy(encodeU32(structuredContent.byteLength, 'structuredContent length'), plaintext, 0)
  b4a.copy(structuredContent, plaintext, CELL_LENGTH_BYTES)
  const padding = plaintext.subarray(CELL_LENGTH_BYTES + structuredContent.byteLength)
  if (padding.byteLength > 0) b4a.copy(randomBytes(runtime, padding.byteLength, 'cell padding'), padding)

  try {
    const sealed = asBytes(await runtime.aes256GcmEncrypt({
      key: cellKey,
      nonce,
      aad: cellAad(storageSlot, sizeClass),
      plaintext
    }), 'sealed cell')
    if (sealed.byteLength !== totalBytes - 1 - CELL_NONCE_BYTES) {
      fail('CRYPTO_FAILURE', 'AES-256-GCM returned an unexpected length')
    }
    return {
      cellKey,
      cellBlob: b4a.concat([b4a.from([CELL_BLOB_FORMAT_VERSION]), nonce, sealed])
    }
  } catch (error) {
    if (options.cellKey == null) wipe(cellKey)
    if (error && error.code) throw error
    fail('CRYPTO_FAILURE', 'cell encryption failed', { cause: error })
  } finally {
    wipe(plaintext)
  }
}

export async function openCell (options) {
  if (!options || typeof options !== 'object') fail('BAD_CLIENT_INPUT', 'cell options are required')
  const runtime = options.runtime
  assertRuntime(runtime)
  const storageSlot = asBytes(options.storageSlot, 'storageSlot', 32)
  const cellKey = asBytes(options.cellKey, 'cellKey', CELL_KEY_BYTES)
  const sizeClass = options.sizeClass
  const totalBytes = classBytes(sizeClass)
  const cellBlob = asBytes(options.cellBlob, 'cellBlob', totalBytes)
  if (options.expectedCellBlobHash != null) {
    const expected = asBytes(options.expectedCellBlobHash, 'expectedCellBlobHash', 32)
    if (!b4a.equals(blake2b256(cellBlob), expected)) {
      fail('CELL_HASH_MISMATCH', 'cell blob does not match the read capability')
    }
  }
  if (cellBlob[0] !== CELL_BLOB_FORMAT_VERSION) fail('BAD_CELL_BLOB', 'unsupported cell blob version')
  const nonce = cellBlob.subarray(1, 1 + CELL_NONCE_BYTES)
  const sealed = cellBlob.subarray(1 + CELL_NONCE_BYTES)
  let plaintext
  try {
    plaintext = asBytes(await runtime.aes256GcmDecrypt({
      key: cellKey,
      nonce,
      aad: cellAad(storageSlot, sizeClass),
      sealed
    }), 'cell plaintext', totalBytes - 1 - CELL_NONCE_BYTES - CELL_TAG_BYTES)
  } catch (error) {
    fail('CELL_AUTHENTICATION_FAILED', 'cell authentication failed', { cause: error })
  }
  try {
    const structuredLength = b4a.readUInt32BE(plaintext, 0)
    if (structuredLength > plaintext.byteLength - CELL_LENGTH_BYTES) {
      fail('BAD_CELL_BLOB', 'authenticated cell length exceeds its class')
    }
    return b4a.from(plaintext.subarray(CELL_LENGTH_BYTES, CELL_LENGTH_BYTES + structuredLength))
  } finally {
    wipe(plaintext)
  }
}
