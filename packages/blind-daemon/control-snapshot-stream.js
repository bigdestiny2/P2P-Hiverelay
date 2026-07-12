import fs from 'node:fs/promises'
import { constants as FS_CONSTANTS } from 'node:fs'
import path from 'node:path'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { HASH_DOMAIN } from '@hiverelay/blind-protocol'

const FIXED_HEADER_BYTES = 137
const MINIMUM_ENTRY_BYTES = 4
const MAX_SCHEMA_ENTRIES = 0x1000000
const MAX_U64 = (1n << 64n) - 1n
const DEFAULT_READ_CHUNK_BYTES = 64 * 1024

export class BlindControlSnapshotIntegrityError extends Error {
  constructor (message, code = 'BLIND_CONTROL_SNAPSHOT_INVALID') {
    super(message)
    this.name = 'BlindControlSnapshotIntegrityError'
    this.code = code
  }
}

function canonicalAbsolutePath (value, field) {
  if (typeof value !== 'string' || value.includes('\0') || !path.isAbsolute(value) || path.normalize(value) !== value) {
    throw new TypeError(`${field} must be a canonical absolute path`)
  }
  return value
}

function boundedInteger (value, minimum, maximum, field) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${field} is outside ${minimum}..${maximum}`)
  }
  return value
}

function asU64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${field} must be an unsigned safe integer or bigint`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) throw new TypeError(`${field} is outside u64`)
  return value
}

function asBytes (value, length, field, nonzero = false) {
  if (!value || typeof value.byteLength !== 'number') throw new TypeError(`${field} must be bytes`)
  value = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (length != null && value.byteLength !== length) throw new TypeError(`${field} must be exactly ${length} bytes`)
  if (nonzero && isZero(value)) throw new TypeError(`${field} must be nonzero`)
  return value
}

function isZero (value) {
  for (const byte of value) if (byte !== 0) return false
  return true
}

function sameBytes (left, right) {
  return b4a.equals(asBytes(left, null, 'left bytes'), asBytes(right, null, 'right bytes'))
}

function writeU64be (value) {
  value = asU64(value, 'snapshot byte length')
  const output = b4a.alloc(8)
  for (let index = 7; index >= 0; index--) {
    output[index] = Number(value & 0xffn)
    value >>= 8n
  }
  return output
}

function readU64be (value) {
  let output = 0n
  for (const byte of value) output = (output << 8n) | BigInt(byte)
  return output
}

function readU16le (value) {
  return value[0] + value[1] * 0x100
}

function readU32le (value) {
  return value[0] + value[1] * 0x100 + value[2] * 0x10000 + value[3] * 0x1000000
}

function readU64le (value) {
  let output = 0n
  for (let index = 7; index >= 0; index--) output = (output << 8n) | BigInt(value[index])
  return output
}

function assertPrivateFile (stat, field) {
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
    throw new BlindControlSnapshotIntegrityError(`${field} is not a single-link regular file`)
  }
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
    throw new BlindControlSnapshotIntegrityError(`${field} is not owned by the daemon uid`)
  }
  if ((stat.mode & 0o600) !== 0o600 || (stat.mode & 0o077) !== 0) {
    throw new BlindControlSnapshotIntegrityError(`${field} permissions are not private`)
  }
}

function sameFileState (left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.nlink === right.nlink && left.mode === right.mode && left.uid === right.uid &&
    left.gid === right.gid && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs
}

function createHashState (byteLength) {
  const state = b4a.alloc(sodium.crypto_generichash_STATEBYTES)
  sodium.crypto_generichash_init(state, null, 32)
  sodium.crypto_generichash_update(state, b4a.from(HASH_DOMAIN.CONTROL_SNAPSHOT, 'ascii'))
  sodium.crypto_generichash_update(state, writeU64be(BigInt(byteLength)))
  return {
    update (value) { sodium.crypto_generichash_update(state, value) },
    digest () {
      const output = b4a.alloc(32)
      sodium.crypto_generichash_final(state, output)
      return output
    }
  }
}

class BufferedFileReader {
  constructor (handle, byteLength, hashState, readChunkBytes) {
    this.handle = handle
    this.byteLength = byteLength
    this.hashState = hashState
    this.buffer = b4a.alloc(readChunkBytes)
    this.bufferStart = 0
    this.bufferEnd = 0
    this.fileOffset = 0
    this.consumed = 0
  }

  async _fill () {
    if (this.fileOffset >= this.byteLength) {
      throw new BlindControlSnapshotIntegrityError('control snapshot is truncated')
    }
    const wanted = Math.min(this.buffer.byteLength, this.byteLength - this.fileOffset)
    const { bytesRead } = await this.handle.read(this.buffer, 0, wanted, this.fileOffset)
    if (bytesRead <= 0) throw new BlindControlSnapshotIntegrityError('control snapshot read made no progress')
    const chunk = this.buffer.subarray(0, bytesRead)
    this.hashState.update(chunk)
    this.fileOffset += bytesRead
    this.bufferStart = 0
    this.bufferEnd = bytesRead
  }

  async read (length, field) {
    boundedInteger(length, 0, 0x10000, `${field} length`)
    if (this.consumed + length > this.byteLength) {
      throw new BlindControlSnapshotIntegrityError(`control snapshot has truncated ${field}`)
    }
    const output = b4a.alloc(length)
    let offset = 0
    while (offset < length) {
      if (this.bufferStart === this.bufferEnd) await this._fill()
      const available = Math.min(length - offset, this.bufferEnd - this.bufferStart)
      b4a.copy(this.buffer, output, offset, this.bufferStart, this.bufferStart + available)
      this.bufferStart += available
      this.consumed += available
      offset += available
    }
    return output
  }

  async byte (field) {
    return (await this.read(1, field))[0]
  }
}

async function readCompactUint (reader, field) {
  const marker = await reader.byte(`${field} prefix`)
  if (marker <= 0xfc) return marker
  if (marker === 0xfd) {
    const value = readU16le(await reader.read(2, field))
    if (value <= 0xfc) throw new BlindControlSnapshotIntegrityError(`${field} uses a non-canonical compact integer`)
    return value
  }
  if (marker === 0xfe) {
    const value = readU32le(await reader.read(4, field))
    if (value <= 0xffff) throw new BlindControlSnapshotIntegrityError(`${field} uses a non-canonical compact integer`)
    return value
  }
  const value = readU64le(await reader.read(8, field))
  if (value <= 0xffffffffn || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new BlindControlSnapshotIntegrityError(`${field} uses a non-canonical or unsupported compact integer`)
  }
  return Number(value)
}

function compareEntryKey (leftKind, leftKey, rightKind, rightKey) {
  return leftKind - rightKind || b4a.compare(leftKey, rightKey)
}

function expectedTuple (value = {}) {
  const output = {}
  if (value.relayPublicKey != null) output.relayPublicKey = asBytes(value.relayPublicKey, 32, 'expected relayPublicKey', true)
  if (value.storeId != null) output.storeId = asBytes(value.storeId, 32, 'expected storeId', true)
  if (value.durabilityContinuityHash != null) {
    output.durabilityContinuityHash = asBytes(value.durabilityContinuityHash, 32, 'expected durabilityContinuityHash', true)
  }
  if (value.walSequence != null) output.walSequence = asU64(value.walSequence, 'expected walSequence')
  if (value.walHash != null) output.walHash = asBytes(value.walHash, 32, 'expected walHash', true)
  return output
}

function assertTuple (actual, expected, label) {
  for (const field of ['relayPublicKey', 'storeId', 'durabilityContinuityHash', 'walHash']) {
    if (expected[field] != null && !sameBytes(actual[field], expected[field])) {
      throw new BlindControlSnapshotIntegrityError(`${label} ${field} does not match`)
    }
  }
  if (expected.walSequence != null && actual.walSequence !== expected.walSequence) {
    throw new BlindControlSnapshotIntegrityError(`${label} walSequence does not match`)
  }
}

function immutableHeader (header) {
  return Object.freeze({
    relayPublicKey: b4a.from(header.relayPublicKey),
    storeId: b4a.from(header.storeId),
    durabilityContinuityHash: b4a.from(header.durabilityContinuityHash),
    walSequence: header.walSequence,
    walHash: b4a.from(header.walHash)
  })
}

// The semantic verifier must consume the supplied async iterable completely and
// reconstruct the storage-engine control state. Its returned tuple is checked
// against the canonical file header so a tuple-only parser cannot authorize a
// checkpoint by itself.
export async function verifyBlindControlStateSnapshotFile (options = {}) {
  const filePath = canonicalAbsolutePath(options.filePath, 'control snapshot path')
  const maximumSnapshotBytes = boundedInteger(options.maximumSnapshotBytes, FIXED_HEADER_BYTES + 1, 0x7fffffff, 'maximumSnapshotBytes')
  const maximumEntries = boundedInteger(
    options.maximumEntries == null ? MAX_SCHEMA_ENTRIES : options.maximumEntries,
    0,
    MAX_SCHEMA_ENTRIES,
    'maximumEntries'
  )
  const readChunkBytes = boundedInteger(
    options.readChunkBytes == null ? DEFAULT_READ_CHUNK_BYTES : options.readChunkBytes,
    1024,
    1024 * 1024,
    'readChunkBytes'
  )
  const expectedByteLength = options.expectedByteLength == null
    ? null
    : asU64(options.expectedByteLength, 'expectedByteLength')
  const expectedHash = options.expectedHash == null
    ? null
    : asBytes(options.expectedHash, 32, 'expectedHash', true)
  const expected = expectedTuple(options.expected)
  if (typeof options.semanticVerifier !== 'function') {
    throw new TypeError('semanticVerifier must be a function that consumes the snapshot entry stream')
  }
  if (!FS_CONSTANTS.O_NOFOLLOW) {
    throw new BlindControlSnapshotIntegrityError('O_NOFOLLOW is required for snapshot validation')
  }

  const linkedBefore = await fs.lstat(filePath)
  assertPrivateFile(linkedBefore, 'control snapshot')
  let handle
  try {
    handle = await fs.open(filePath, FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW)
    const openedBefore = await handle.stat()
    assertPrivateFile(openedBefore, 'opened control snapshot')
    if (openedBefore.dev !== linkedBefore.dev || openedBefore.ino !== linkedBefore.ino) {
      throw new BlindControlSnapshotIntegrityError('control snapshot path and opened inode disagree')
    }
    if (!Number.isSafeInteger(openedBefore.size) || openedBefore.size < FIXED_HEADER_BYTES + 1 || openedBefore.size > maximumSnapshotBytes) {
      throw new BlindControlSnapshotIntegrityError('control snapshot byte length is outside its configured bound')
    }
    if (expectedByteLength != null && BigInt(openedBefore.size) !== expectedByteLength) {
      throw new BlindControlSnapshotIntegrityError('control snapshot byte length does not match its checkpoint')
    }

    const hashState = createHashState(openedBefore.size)
    const reader = new BufferedFileReader(handle, openedBefore.size, hashState, readChunkBytes)
    const version = await reader.byte('version')
    if (version !== 1) throw new BlindControlSnapshotIntegrityError('control snapshot version is not 1')
    const header = immutableHeader({
      relayPublicKey: await reader.read(32, 'relayPublicKey'),
      storeId: await reader.read(32, 'storeId'),
      durabilityContinuityHash: await reader.read(32, 'durabilityContinuityHash'),
      walSequence: readU64be(await reader.read(8, 'walSequence')),
      walHash: await reader.read(32, 'walHash')
    })
    for (const field of ['relayPublicKey', 'storeId', 'durabilityContinuityHash', 'walHash']) {
      if (isZero(header[field])) throw new BlindControlSnapshotIntegrityError(`control snapshot ${field} must be nonzero`)
    }
    if (header.walSequence === 0n) throw new BlindControlSnapshotIntegrityError('local control snapshot WAL sequence must be nonzero')
    assertTuple(header, expected, 'control snapshot')

    const declaredEntryCount = await readCompactUint(reader, 'entry count')
    if (declaredEntryCount > maximumEntries) {
      throw new BlindControlSnapshotIntegrityError('control snapshot entry count exceeds its configured bound')
    }
    const remainingBytes = openedBefore.size - reader.consumed
    if (declaredEntryCount > Math.floor(remainingBytes / MINIMUM_ENTRY_BYTES)) {
      throw new BlindControlSnapshotIntegrityError('control snapshot entry count cannot fit in the declared file length')
    }

    let previousKind = 0
    let previousKey = null
    let parsedEntryCount = 0
    let completed = false
    const entries = (async function * () {
      for (let index = 0; index < declaredEntryCount; index++) {
        const entryKind = await reader.byte('entry kind')
        if (entryKind < 1 || entryKind > 8) throw new BlindControlSnapshotIntegrityError('control snapshot entry kind is outside 1..8')
        const keyLength = await readCompactUint(reader, 'entry key length')
        if (keyLength < 1 || keyLength > 256) throw new BlindControlSnapshotIntegrityError('control snapshot entry key length is outside 1..256')
        const key = await reader.read(keyLength, 'entry key')
        const valueLength = await readCompactUint(reader, 'entry value length')
        if (valueLength > 0xffff) throw new BlindControlSnapshotIntegrityError('control snapshot entry value length exceeds 65535')
        const value = await reader.read(valueLength, 'entry value')
        if (previousKey != null && compareEntryKey(previousKind, previousKey, entryKind, key) >= 0) {
          throw new BlindControlSnapshotIntegrityError('control snapshot entries are not strictly sorted and duplicate-free')
        }
        previousKind = entryKind
        previousKey = b4a.from(key)
        parsedEntryCount++
        yield Object.freeze({ index, entryKind, key, value })
      }
      if (reader.consumed !== openedBefore.size) {
        throw new BlindControlSnapshotIntegrityError('control snapshot contains trailing bytes')
      }
      completed = true
    })()

    const verifierHeader = immutableHeader(header)
    const echo = await options.semanticVerifier(Object.freeze({
      header: verifierHeader,
      declaredEntryCount,
      entries
    }))
    if (!completed || parsedEntryCount !== declaredEntryCount) {
      if (typeof entries.return === 'function') await entries.return().catch(() => {})
      throw new BlindControlSnapshotIntegrityError('semantic verifier did not consume the complete snapshot entry stream')
    }
    if (!echo || typeof echo !== 'object') {
      throw new BlindControlSnapshotIntegrityError('semantic verifier did not return a reconstruction echo')
    }
    assertTuple(echo, header, 'semantic reconstruction')
    if (echo.entryCount !== declaredEntryCount) {
      throw new BlindControlSnapshotIntegrityError('semantic reconstruction entry count does not match')
    }

    const snapshotHash = hashState.digest()
    if (expectedHash != null && !sameBytes(snapshotHash, expectedHash)) {
      throw new BlindControlSnapshotIntegrityError('control snapshot hash does not match its checkpoint')
    }
    const [openedAfter, linkedAfter] = await Promise.all([handle.stat(), fs.lstat(filePath)])
    assertPrivateFile(openedAfter, 'opened control snapshot')
    assertPrivateFile(linkedAfter, 'control snapshot')
    if (!sameFileState(openedBefore, openedAfter) || !sameFileState(openedAfter, linkedAfter)) {
      throw new BlindControlSnapshotIntegrityError('control snapshot changed while it was verified')
    }
    return Object.freeze({
      filePath,
      byteLength: BigInt(openedBefore.size),
      snapshotHash,
      header: immutableHeader(header),
      entryCount: declaredEntryCount,
      semanticEcho: echo
    })
  } finally {
    if (handle) await handle.close().catch(() => {})
  }
}

export const BLIND_CONTROL_SNAPSHOT_STREAM_LIMITS = Object.freeze({
  fixedHeaderBytes: FIXED_HEADER_BYTES,
  minimumEntryBytes: MINIMUM_ENTRY_BYTES,
  maximumSchemaEntries: MAX_SCHEMA_ENTRIES,
  defaultReadChunkBytes: DEFAULT_READ_CHUNK_BYTES
})
