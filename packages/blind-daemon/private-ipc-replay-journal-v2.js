import { constants as FS_CONSTANTS } from 'node:fs'
import fs from 'node:fs/promises'
import path from 'node:path'
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import b4a from 'b4a'
import { PRIVATE_IPC_V2_REPLAY_POLICY } from '@hiverelay/blind-ipc/private-ipc-v2-contract'
import { blake2b256 } from '@hiverelay/blind-protocol'
import {
  releaseExclusiveFileLock,
  renameFileNoReplace,
  renameFileNoReplacePlatformSupported,
  tryExclusiveFileLock
} from '@hiverelay/blind-peercred'

const HEADER_MAGIC = b4a.from('HRRPJ002', 'ascii')
const FRAME_MAGIC = b4a.from('HRR2', 'ascii')
const FORMAT_VERSION = 2
const HEADER_BYTES = 320
const FRAME_BYTES = 160
const CAPACITY = PRIVATE_IPC_V2_REPLAY_POLICY.capacity
const MAXIMUM_RECORDS = CAPACITY * 2
const LOCK_FILE = 'writer.lock.v2'
const JOURNAL_FILE = 'replay-journal.v2'
const TEMP_FILE = /^\.replay-journal\.v2\.([0-9a-f]{32})\.tmp$/
const MAXIMUM_TEMP_FILES = 16
const MAX_U64 = (1n << 64n) - 1n

const FRAME_TYPE = Object.freeze({ CONSUME: 1, EXPIRE: 2 })
const STATE = Object.freeze({ OPEN: 'OPEN', POISONED: 'POISONED', CLOSING: 'CLOSING', CLOSED: 'CLOSED' })

const KEY_DERIVATION_DOMAIN = b4a.from('hiverelay.blind.private-ipc-replay-journal-key.v2', 'ascii')
const HEADER_KEY_DOMAIN = b4a.from('hiverelay.blind.private-ipc-replay-journal-header-key.v2', 'ascii')
const RECORD_KEY_DOMAIN = b4a.from('hiverelay.blind.private-ipc-replay-journal-record-key.v2', 'ascii')
const HEADER_MAC_DOMAIN = b4a.from('hiverelay.blind.private-ipc-replay-journal-header-mac.v2', 'ascii')
const FRAME_CHECKSUM_DOMAIN = b4a.from('hiverelay.blind.private-ipc-replay-journal-frame-checksum.v2', 'ascii')
const FRAME_MAC_DOMAIN = b4a.from('hiverelay.blind.private-ipc-replay-journal-frame-mac.v2', 'ascii')
const CHAIN_ANCHOR_DOMAIN = b4a.from('hiverelay.blind.private-ipc-replay-journal-chain-anchor.v2', 'ascii')
const FRAME_HASH_DOMAIN = b4a.from('hiverelay.blind.private-ipc-replay-journal-frame-hash.v2', 'ascii')

const AUTHORITIES = new WeakMap()
const RECEIPTS = new WeakMap()
const ACTIVE_ROOTS = new Set()

if (!Object.isFrozen(PRIVATE_IPC_V2_REPLAY_POLICY) ||
    PRIVATE_IPC_V2_REPLAY_POLICY.capacity !== 4096 ||
    PRIVATE_IPC_V2_REPLAY_POLICY.acceptedRecordMaximumTtlMillis !== 15_000 ||
    PRIVATE_IPC_V2_REPLAY_POLICY.freshEntryExpiry !== 'exact-open-deadline' ||
    PRIVATE_IPC_V2_REPLAY_POLICY.recoveredEntryMinimumRetentionMillis !== 15_000 ||
    PRIVATE_IPC_V2_REPLAY_POLICY.recoveredRetentionBasis !==
      'conservative-startup-fence-not-accepted-record-ttl' ||
    PRIVATE_IPC_V2_REPLAY_POLICY.startupWriteQuarantineMillis !== 15_000 ||
    PRIVATE_IPC_V2_REPLAY_POLICY.liveEntryEvictionPermitted !== false) {
  throw new Error('private IPC replay journal implementation does not match the frozen V2 replay policy')
}

const ACCEPTED_RECORD_MAXIMUM_TTL_MILLIS = BigInt(
  PRIVATE_IPC_V2_REPLAY_POLICY.acceptedRecordMaximumTtlMillis)
const RECOVERED_ENTRY_MINIMUM_RETENTION_MILLIS = BigInt(
  PRIVATE_IPC_V2_REPLAY_POLICY.recoveredEntryMinimumRetentionMillis)
const STARTUP_WRITE_QUARANTINE_MILLIS = BigInt(
  PRIVATE_IPC_V2_REPLAY_POLICY.startupWriteQuarantineMillis)

export const PRIVATE_IPC_REPLAY_JOURNAL_V2_LIMITS = Object.freeze({
  headerBytes: HEADER_BYTES,
  frameBytes: FRAME_BYTES,
  capacity: CAPACITY,
  acceptedRecordMaximumTtlMillis: PRIVATE_IPC_V2_REPLAY_POLICY.acceptedRecordMaximumTtlMillis,
  recoveredEntryMinimumRetentionMillis: PRIVATE_IPC_V2_REPLAY_POLICY.recoveredEntryMinimumRetentionMillis,
  startupWriteQuarantineMillis: PRIVATE_IPC_V2_REPLAY_POLICY.startupWriteQuarantineMillis,
  maximumRecords: MAXIMUM_RECORDS
})

export const PRIVATE_IPC_REPLAY_JOURNAL_V2_INTEGRATION_STATUS = Object.freeze({
  exactFormatImplemented: true,
  durableReplayImplemented: true,
  startupQuarantineRequired: true,
  restartPolicy: 'MANDATORY_FULL_HORIZON_STARTUP_QUARANTINE',
  externalBootGenerationFenceRequired: false,
  externalBootGenerationFenceImplemented: false,
  onDiskGenerationPurpose: 'COMPACTION_CHAIN_GENERATION_ONLY',
  acceptedRecordMaximumTtlMillis: PRIVATE_IPC_V2_REPLAY_POLICY.acceptedRecordMaximumTtlMillis,
  recoveredEntryMinimumRetentionMillis: PRIVATE_IPC_V2_REPLAY_POLICY.recoveredEntryMinimumRetentionMillis,
  startupWriteQuarantineMillis: PRIVATE_IPC_V2_REPLAY_POLICY.startupWriteQuarantineMillis,
  serverWired: true,
  assemblerWired: true,
  productionRuntimeWired: false,
  productionEntrypointWired: false,
  releaseReady: false,
  blocker: 'PRODUCTION_ENTRYPOINT_CELL_ADMISSION_ASSEMBLY_UNWIRED',
  blockers: Object.freeze([
    'PRODUCTION_ENTRYPOINT_CELL_ADMISSION_ASSEMBLY_UNWIRED',
    'PRIVATE_IPC_V2_AGGREGATE_DEPLOYMENT_GATES_UNSATISFIED'
  ])
})

export class PrivateIpcReplayJournalV2Error extends Error {
  constructor (message, code = 'PRIVATE_IPC_V2_REPLAY_JOURNAL_INVALID') {
    super(message)
    this.name = 'PrivateIpcReplayJournalV2Error'
    this.code = code
  }
}

function fail (message, code) {
  throw new PrivateIpcReplayJournalV2Error(message, code)
}

function canonicalRoot (value) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0') ||
      !path.isAbsolute(value) || path.normalize(value) !== value) {
    throw new TypeError('private IPC replay journal root must be a canonical absolute path')
  }
  return value
}

function asBytes (value, length, field, options = {}) {
  if (!value || typeof value.byteLength !== 'number') throw new TypeError(`${field} must be bytes`)
  const output = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (output.byteLength !== length) throw new TypeError(`${field} must be exactly ${length} bytes`)
  if (options.nonzero === true && isZero(output)) throw new TypeError(`${field} must be nonzero`)
  return output
}

function ownedBytes (value, length, field, options = {}) {
  return b4a.from(asBytes(value, length, field, options))
}

function isZero (value) {
  for (const byte of value) if (byte !== 0) return false
  return true
}

function asU64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${field} must be a u64`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
    throw new TypeError(`${field} must be a u64`)
  }
  return value
}

function writeU16 (buffer, offset, value) {
  buffer.writeUInt16BE(value, offset)
}

function writeU32 (buffer, offset, value) {
  buffer.writeUInt32BE(value, offset)
}

function writeU64 (buffer, offset, value) {
  buffer.writeBigUInt64BE(asU64(value, 'u64'), offset)
}

function readU16 (buffer, offset) {
  return buffer.readUInt16BE(offset)
}

function readU32 (buffer, offset) {
  return buffer.readUInt32BE(offset)
}

function readU64 (buffer, offset) {
  return buffer.readBigUInt64BE(offset)
}

function hmac (key, domain, ...parts) {
  const instance = createHmac('sha256', key)
  instance.update(domain)
  for (const part of parts) instance.update(part)
  return instance.digest()
}

function hash (domain, value) {
  return blake2b256(b4a.concat([domain, value]))
}

function sameSecret (left, right) {
  return left.byteLength === right.byteLength && timingSafeEqual(left, right)
}

function encodeU64 (value) {
  const output = b4a.alloc(8)
  writeU64(output, 0, value)
  return output
}

function identityBytes (identity) {
  return b4a.concat([
    identity.launchTopologyHash,
    identity.relayPublicKey,
    identity.storeId,
    identity.durabilityContinuityHash,
    identity.durabilityProfileHash,
    identity.storeFormatHash,
    encodeU64(identity.mapGeneration),
    identity.ownerFenceTokenHash
  ])
}

function deriveKeys (partitionKeyInput, identity) {
  const partitionKey = ownedBytes(partitionKeyInput, 32, 'partitionKey', { nonzero: true })
  let master = null
  try {
    master = hmac(partitionKey, KEY_DERIVATION_DOMAIN, identityBytes(identity))
    return Object.freeze({
      headerKey: hmac(master, HEADER_KEY_DOMAIN),
      recordKey: hmac(master, RECORD_KEY_DOMAIN)
    })
  } finally {
    partitionKey.fill(0)
    if (master) master.fill(0)
  }
}

function exactIdentity (options) {
  const mapGeneration = asU64(options.mapGeneration, 'mapGeneration')
  if (mapGeneration === 0n) throw new TypeError('mapGeneration must be nonzero')
  return Object.freeze({
    launchTopologyHash: ownedBytes(options.launchTopologyHash, 32, 'launchTopologyHash', { nonzero: true }),
    relayPublicKey: ownedBytes(options.relayPublicKey, 32, 'relayPublicKey', { nonzero: true }),
    storeId: ownedBytes(options.storeId, 32, 'storeId', { nonzero: true }),
    durabilityContinuityHash: ownedBytes(options.durabilityContinuityHash, 32,
      'durabilityContinuityHash', { nonzero: true }),
    durabilityProfileHash: ownedBytes(options.durabilityProfileHash, 32,
      'durabilityProfileHash', { nonzero: true }),
    storeFormatHash: ownedBytes(options.storeFormatHash, 32, 'storeFormatHash', { nonzero: true }),
    mapGeneration,
    ownerFenceTokenHash: ownedBytes(options.ownerFenceTokenHash, 32,
      'ownerFenceTokenHash', { nonzero: true })
  })
}

function encodeHeader (identity, generation, headerKey) {
  generation = asU64(generation, 'journal generation')
  if (generation === 0n) throw new TypeError('journal generation must be nonzero')
  const output = b4a.alloc(HEADER_BYTES)
  b4a.copy(HEADER_MAGIC, output, 0)
  writeU16(output, 8, FORMAT_VERSION)
  writeU16(output, 10, HEADER_BYTES)
  writeU16(output, 12, FRAME_BYTES)
  writeU16(output, 14, CAPACITY)
  writeU32(output, 16, Number(ACCEPTED_RECORD_MAXIMUM_TTL_MILLIS))
  writeU64(output, 20, generation)
  writeU32(output, 28, 0)
  b4a.copy(identity.launchTopologyHash, output, 32)
  b4a.copy(identity.relayPublicKey, output, 64)
  b4a.copy(identity.storeId, output, 96)
  b4a.copy(identity.durabilityContinuityHash, output, 128)
  b4a.copy(identity.durabilityProfileHash, output, 160)
  b4a.copy(identity.storeFormatHash, output, 192)
  writeU64(output, 224, identity.mapGeneration)
  b4a.copy(identity.ownerFenceTokenHash, output, 232)
  b4a.copy(hmac(headerKey, HEADER_MAC_DOMAIN, output.subarray(0, 288)), output, 288)
  return output
}

function assertIdentityField (header, offset, expected, field) {
  if (!sameSecret(header.subarray(offset, offset + 32), expected)) {
    fail(`private IPC replay journal ${field} does not match this launch`,
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_IDENTITY_MISMATCH')
  }
}

function decodeHeader (input, identity, headerKey) {
  const header = asBytes(input, HEADER_BYTES, 'private IPC replay journal header')
  if (!b4a.equals(header.subarray(0, 8), HEADER_MAGIC) ||
      readU16(header, 8) !== FORMAT_VERSION ||
      readU16(header, 10) !== HEADER_BYTES ||
      readU16(header, 12) !== FRAME_BYTES ||
      readU16(header, 14) !== CAPACITY ||
      readU32(header, 16) !== Number(ACCEPTED_RECORD_MAXIMUM_TTL_MILLIS) ||
      readU32(header, 28) !== 0 || !isZero(header.subarray(264, 288))) {
    fail('private IPC replay journal header has an unknown or non-canonical format',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_INTEGRITY')
  }
  const generation = readU64(header, 20)
  if (generation === 0n) {
    fail('private IPC replay journal generation zero is forbidden',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_INTEGRITY')
  }
  assertIdentityField(header, 32, identity.launchTopologyHash, 'launchTopologyHash')
  assertIdentityField(header, 64, identity.relayPublicKey, 'relayPublicKey')
  assertIdentityField(header, 96, identity.storeId, 'storeId')
  assertIdentityField(header, 128, identity.durabilityContinuityHash, 'durabilityContinuityHash')
  assertIdentityField(header, 160, identity.durabilityProfileHash, 'durabilityProfileHash')
  assertIdentityField(header, 192, identity.storeFormatHash, 'storeFormatHash')
  if (readU64(header, 224) !== identity.mapGeneration) {
    fail('private IPC replay journal mapGeneration does not match this launch',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_IDENTITY_MISMATCH')
  }
  assertIdentityField(header, 232, identity.ownerFenceTokenHash, 'ownerFenceTokenHash')
  const expectedMac = hmac(headerKey, HEADER_MAC_DOMAIN, header.subarray(0, 288))
  if (!sameSecret(header.subarray(288), expectedMac)) {
    fail('private IPC replay journal header MAC is invalid',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_INTEGRITY')
  }
  return Object.freeze({ generation, bytes: b4a.from(header) })
}

function chainAnchor (header) {
  return hash(CHAIN_ANCHOR_DOMAIN, header)
}

function frameHash (frame) {
  return hash(FRAME_HASH_DOMAIN, frame)
}

function encodeFrame (value, header, recordKey) {
  const type = value.type
  if (type !== FRAME_TYPE.CONSUME && type !== FRAME_TYPE.EXPIRE) {
    throw new TypeError('private IPC replay journal frame type is invalid')
  }
  const ttlMillis = value.ttlMillis
  if (!Number.isSafeInteger(ttlMillis) ||
      (type === FRAME_TYPE.CONSUME &&
        (ttlMillis < 1 || ttlMillis > Number(ACCEPTED_RECORD_MAXIMUM_TTL_MILLIS))) ||
      (type === FRAME_TYPE.EXPIRE && ttlMillis !== 0)) {
    throw new TypeError('private IPC replay journal frame TTL is invalid')
  }
  const output = b4a.alloc(FRAME_BYTES)
  b4a.copy(FRAME_MAGIC, output, 0)
  output[4] = FORMAT_VERSION
  output[5] = type
  writeU16(output, 6, FRAME_BYTES)
  writeU64(output, 8, value.sequence)
  writeU64(output, 16, value.generation)
  b4a.copy(asBytes(value.replayTupleHash, 32, 'replayTupleHash'), output, 24)
  writeU32(output, 56, ttlMillis)
  writeU32(output, 60, 0)
  b4a.copy(asBytes(value.previousFrameHash, 32, 'previousFrameHash'), output, 64)
  b4a.copy(hash(FRAME_CHECKSUM_DOMAIN, output.subarray(0, 96)), output, 96)
  b4a.copy(hmac(recordKey, FRAME_MAC_DOMAIN, chainAnchor(header), output.subarray(0, 128)), output, 128)
  return output
}

function decodeFrame (input, expected, header, recordKey) {
  const frame = asBytes(input, FRAME_BYTES, 'private IPC replay journal frame')
  if (!b4a.equals(frame.subarray(0, 4), FRAME_MAGIC) || frame[4] !== FORMAT_VERSION ||
      readU16(frame, 6) !== FRAME_BYTES || readU32(frame, 60) !== 0) {
    fail('private IPC replay journal frame has an unknown or non-canonical format',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_INTEGRITY')
  }
  const type = frame[5]
  if (type !== FRAME_TYPE.CONSUME && type !== FRAME_TYPE.EXPIRE) {
    fail('private IPC replay journal frame type is unknown',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_INTEGRITY')
  }
  const sequence = readU64(frame, 8)
  const generation = readU64(frame, 16)
  if (sequence !== expected.sequence || generation !== expected.generation ||
      !sameSecret(frame.subarray(64, 96), expected.previousFrameHash)) {
    fail('private IPC replay journal sequence, generation, or hash chain is invalid',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_INTEGRITY')
  }
  const checksum = hash(FRAME_CHECKSUM_DOMAIN, frame.subarray(0, 96))
  const mac = hmac(recordKey, FRAME_MAC_DOMAIN, chainAnchor(header), frame.subarray(0, 128))
  if (!sameSecret(frame.subarray(96, 128), checksum) || !sameSecret(frame.subarray(128), mac)) {
    fail('private IPC replay journal frame checksum or MAC is invalid',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_INTEGRITY')
  }
  const ttlMillis = readU32(frame, 56)
  if ((type === FRAME_TYPE.CONSUME &&
        (ttlMillis < 1 || ttlMillis > Number(ACCEPTED_RECORD_MAXIMUM_TTL_MILLIS))) ||
      (type === FRAME_TYPE.EXPIRE && ttlMillis !== 0)) {
    fail('private IPC replay journal frame TTL is invalid',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_INTEGRITY')
  }
  return Object.freeze({
    type,
    sequence,
    generation,
    replayTupleHash: b4a.from(frame.subarray(24, 56)),
    ttlMillis,
    hash: frameHash(frame)
  })
}

function sameInode (left, right) {
  return left.dev === right.dev && left.ino === right.ino
}

function assertPrivateDirectoryStat (stat, field) {
  if (!stat.isDirectory() || stat.isSymbolicLink() ||
      (typeof process.getuid !== 'function') || stat.uid !== process.getuid() ||
      (stat.mode & 0o777) !== 0o700) {
    fail(`${field} must be a daemon-owned mode-0700 directory`,
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_FILESYSTEM_INVALID')
  }
}

function assertPrivateFileStat (stat, field, options = {}) {
  if (!stat.isFile() || stat.isSymbolicLink() ||
      (typeof process.getuid !== 'function') || stat.uid !== process.getuid() ||
      (stat.mode & 0o777) !== 0o600 || stat.nlink !== 1 ||
      (options.empty === true && stat.size !== 0)) {
    fail(`${field} must be a daemon-owned single-link mode-0600 regular file`,
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_FILESYSTEM_INVALID')
  }
}

async function verifyRoot (root, expected = null) {
  const before = await fs.lstat(root)
  assertPrivateDirectoryStat(before, 'private IPC replay journal root')
  if (await fs.realpath(root) !== root) {
    fail('private IPC replay journal root must not traverse a symlink',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_FILESYSTEM_INVALID')
  }
  const after = await fs.lstat(root)
  assertPrivateDirectoryStat(after, 'private IPC replay journal root')
  if (!sameInode(before, after) || (expected && !sameInode(after, expected))) {
    fail('private IPC replay journal root changed during validation',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_FILESYSTEM_INVALID')
  }
  return after
}

async function verifyOpenedFile (handle, file, field, options = {}) {
  const [opened, linked] = await Promise.all([handle.stat(), fs.lstat(file)])
  assertPrivateFileStat(opened, field, options)
  assertPrivateFileStat(linked, field, options)
  if (!sameInode(opened, linked)) {
    fail(`${field} path and opened inode disagree`,
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_FILESYSTEM_INVALID')
  }
  return opened
}

async function syncDirectory (directory) {
  const handle = await fs.open(directory, FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW)
  try {
    const stat = await handle.stat()
    assertPrivateDirectoryStat(stat, 'private IPC replay journal root')
    await handle.sync()
  } finally {
    await handle.close()
  }
}

async function writeAll (handle, input, position) {
  let written = 0
  while (written < input.byteLength) {
    const result = await handle.write(input, written, input.byteLength - written, position + written)
    if (result.bytesWritten === 0) throw new Error('private IPC replay journal write made no progress')
    written += result.bytesWritten
  }
}

async function readAtMost (handle, output, position) {
  let read = 0
  while (read < output.byteLength) {
    const result = await handle.read(output, read, output.byteLength - read, position + read)
    if (result.bytesRead === 0) break
    read += result.bytesRead
  }
  return read
}

function abortError () {
  const error = new Error('private IPC replay reservation was aborted before durable consumption')
  error.name = 'AbortError'
  error.code = 'ABORT_ERR'
  return error
}

function exactSignal (value) {
  if (value == null) return null
  if (typeof value !== 'object' || typeof value.aborted !== 'boolean' ||
      typeof value.addEventListener !== 'function' || typeof value.removeEventListener !== 'function') {
    throw new TypeError('signal must be an AbortSignal')
  }
  return value
}

function poison (state, error) {
  if (state.phase === STATE.CLOSED || state.phase === STATE.CLOSING) return
  state.phase = STATE.POISONED
  state.poisonReason = error && typeof error.code === 'string'
    ? error.code
    : 'PRIVATE_IPC_V2_REPLAY_JOURNAL_POISONED'
  if (state.headerKey) state.headerKey.fill(0)
  if (state.recordKey) state.recordKey.fill(0)
}

function stateFor (authority) {
  if (!authority || typeof authority !== 'object') {
    throw new PrivateIpcReplayJournalV2Error(
      'private IPC replay journal authority is forged or unsupported',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_AUTHORITY_INVALID'
    )
  }
  const state = AUTHORITIES.get(authority)
  if (!state || state.authority !== authority) {
    throw new PrivateIpcReplayJournalV2Error(
      'private IPC replay journal authority is forged or unsupported',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_AUTHORITY_INVALID'
    )
  }
  return state
}

function sampleNow (state) {
  let now
  try {
    now = asU64(state.monotonicMillis(), 'monotonicMillis')
  } catch (error) {
    poison(state, error)
    throw error
  }
  if (state.lastNow != null && now < state.lastNow) {
    const error = new PrivateIpcReplayJournalV2Error(
      'private IPC replay journal monotonic clock regressed',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_CLOCK_UNSAFE'
    )
    poison(state, error)
    throw error
  }
  state.lastNow = now
  return now
}

function serialize (state, callback) {
  const previous = state.serial
  let release
  state.serial = new Promise(resolve => { release = resolve })
  return previous.then(async () => {
    try {
      return await callback()
    } finally {
      release()
    }
  })
}

async function fault (state, point, context = {}) {
  if (!state.faultInjector) return
  await state.faultInjector(point, Object.freeze({
    root: state.root,
    generation: state.generation,
    sequence: state.sequence,
    occupied: state.entries.size,
    ...context
  }))
}

async function openWriterLock (state) {
  let created = false
  try {
    state.lockHandle = await fs.open(state.lockPath,
      FS_CONSTANTS.O_RDWR | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL | FS_CONSTANTS.O_NOFOLLOW,
      0o600)
    created = true
  } catch (error) {
    if (!error || error.code !== 'EEXIST') throw error
    state.lockHandle = await fs.open(state.lockPath, FS_CONSTANTS.O_RDWR | FS_CONSTANTS.O_NOFOLLOW)
  }
  await verifyOpenedFile(state.lockHandle, state.lockPath, 'private IPC replay journal writer lock', { empty: true })
  if (!tryExclusiveFileLock(state.lockHandle)) {
    fail('private IPC replay journal already has an active writer',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_LOCKED')
  }
  state.lockHeld = true
  if (created) {
    await state.lockHandle.sync()
    await syncDirectory(state.root)
  }
  await verifyOpenedFile(state.lockHandle, state.lockPath, 'private IPC replay journal writer lock', { empty: true })
}

async function inspectInventory (state) {
  const names = (await fs.readdir(state.root)).sort()
  const unknown = names.find(name => name !== LOCK_FILE && name !== JOURNAL_FILE && !TEMP_FILE.test(name))
  if (unknown) {
    fail(`private IPC replay journal root contains unrecognized entry ${unknown}`,
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_FILESYSTEM_INVALID')
  }
  const temps = names.filter(name => TEMP_FILE.test(name))
  if (temps.length > MAXIMUM_TEMP_FILES) {
    fail('private IPC replay journal temporary-file bound is exceeded',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_FILESYSTEM_INVALID')
  }
  for (const name of temps) {
    const temporary = path.join(state.root, name)
    const stat = await fs.lstat(temporary)
    assertPrivateFileStat(stat, 'private IPC replay journal temporary')
    await fs.unlink(temporary)
  }
  if (temps.length > 0) await syncDirectory(state.root)
  return names.includes(JOURNAL_FILE)
}

async function assertLiveFiles (state, expectedJournalSize = state.offset) {
  await verifyRoot(state.root, state.rootState)
  await verifyOpenedFile(state.lockHandle, state.lockPath,
    'private IPC replay journal writer lock', { empty: true })
  const active = await verifyOpenedFile(state.handle, state.journalPath, 'private IPC replay journal file')
  if (active.size !== expectedJournalSize) {
    fail('private IPC replay journal length changed outside its serialized writer',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_INTEGRITY')
  }
  return active
}

async function installInitialJournal (state) {
  if (!renameFileNoReplacePlatformSupported()) {
    fail('private IPC replay journal requires atomic rename-no-replace for bootstrap',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_PLATFORM_UNSUPPORTED')
  }
  const header = encodeHeader(state.identity, 1n, state.headerKey)
  const temporary = path.join(state.root, `.replay-journal.v2.${randomBytes(16).toString('hex')}.tmp`)
  let handle = null
  try {
    handle = await fs.open(temporary,
      FS_CONSTANTS.O_RDWR | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL | FS_CONSTANTS.O_NOFOLLOW,
      0o600)
    await writeAll(handle, header, 0)
    await fault(state, 'bootstrap:after-temp-write', { byteLength: header.byteLength })
    await handle.sync()
    await fault(state, 'bootstrap:after-temp-sync', { byteLength: header.byteLength })
    await handle.close()
    handle = null
    const installed = renameFileNoReplace(temporary, state.journalPath)
    if (!installed) {
      fail('private IPC replay journal appeared during locked bootstrap',
        'PRIVATE_IPC_V2_REPLAY_JOURNAL_FILESYSTEM_INVALID')
    }
    await fault(state, 'bootstrap:after-no-replace-rename')
    await syncDirectory(state.root)
    await fault(state, 'bootstrap:after-directory-sync')
  } finally {
    if (handle) await handle.close().catch(() => {})
    await fs.unlink(temporary).catch(error => {
      if (!error || error.code !== 'ENOENT') throw error
    })
  }
}

async function openActiveJournal (state) {
  state.handle = await fs.open(state.journalPath, FS_CONSTANTS.O_RDWR | FS_CONSTANTS.O_NOFOLLOW)
  return verifyOpenedFile(state.handle, state.journalPath, 'private IPC replay journal file')
}

async function recoverJournal (state) {
  const stat = await openActiveJournal(state)
  if (stat.size < HEADER_BYTES) {
    fail('private IPC replay journal is shorter than its complete header',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_INTEGRITY')
  }
  if (stat.size > HEADER_BYTES + (MAXIMUM_RECORDS * FRAME_BYTES) + FRAME_BYTES - 1) {
    fail('private IPC replay journal exceeds its bounded on-disk record limit',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_INTEGRITY')
  }
  const headerBytes = b4a.alloc(HEADER_BYTES)
  if (await readAtMost(state.handle, headerBytes, 0) !== HEADER_BYTES) {
    fail('private IPC replay journal header could not be read completely',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_INTEGRITY')
  }
  const decodedHeader = decodeHeader(headerBytes, state.identity, state.headerKey)
  const bodyBytes = stat.size - HEADER_BYTES
  const completeFrames = Math.floor(bodyBytes / FRAME_BYTES)
  const tornBytes = bodyBytes % FRAME_BYTES
  if (completeFrames > MAXIMUM_RECORDS) {
    fail('private IPC replay journal contains too many complete records',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_INTEGRITY')
  }
  const recovered = new Map()
  let previousFrameHash = chainAnchor(decodedHeader.bytes)
  for (let index = 0; index < completeFrames; index++) {
    const frameBytes = b4a.alloc(FRAME_BYTES)
    const offset = HEADER_BYTES + (index * FRAME_BYTES)
    if (await readAtMost(state.handle, frameBytes, offset) !== FRAME_BYTES) {
      fail('private IPC replay journal complete frame could not be read completely',
        'PRIVATE_IPC_V2_REPLAY_JOURNAL_INTEGRITY')
    }
    const frame = decodeFrame(frameBytes, {
      sequence: BigInt(index + 1),
      generation: decodedHeader.generation,
      previousFrameHash
    }, decodedHeader.bytes, state.recordKey)
    const key = b4a.toString(frame.replayTupleHash, 'hex')
    if (frame.type === FRAME_TYPE.CONSUME) {
      if (recovered.has(key) || recovered.size >= CAPACITY) {
        fail('private IPC replay journal recovered a duplicate or over-capacity consume',
          'PRIVATE_IPC_V2_REPLAY_JOURNAL_INTEGRITY')
      }
      recovered.set(key, Object.freeze({
        replayTupleHash: b4a.from(frame.replayTupleHash),
        generation: frame.generation,
        sequence: frame.sequence
      }))
    } else {
      if (!recovered.delete(key)) {
        fail('private IPC replay journal recovered an expire without a live consume',
          'PRIVATE_IPC_V2_REPLAY_JOURNAL_INTEGRITY')
      }
    }
    previousFrameHash = frame.hash
  }
  if (tornBytes > 0) {
    const validLength = HEADER_BYTES + (completeFrames * FRAME_BYTES)
    await state.handle.truncate(validLength)
    await fault(state, 'recovery:after-torn-tail-truncate', { removedBytes: tornBytes })
    await state.handle.sync()
    await syncDirectory(state.root)
    await fault(state, 'recovery:after-torn-tail-sync', { removedBytes: tornBytes })
  }
  state.header = decodedHeader.bytes
  state.generation = decodedHeader.generation
  state.sequence = BigInt(completeFrames)
  state.previousFrameHash = previousFrameHash
  state.offset = HEADER_BYTES + (completeFrames * FRAME_BYTES)
  state.recordCount = completeFrames
  state.recoveredHashes = recovered
}

async function appendFrameSpecs (state, specs, label) {
  if (specs.length === 0) return
  await assertLiveFiles(state)
  let sequence = state.sequence
  let previousFrameHash = state.previousFrameHash
  const frames = []
  for (const spec of specs) {
    sequence++
    const frame = encodeFrame({
      ...spec,
      sequence,
      generation: state.generation,
      previousFrameHash
    }, state.header, state.recordKey)
    frames.push(frame)
    previousFrameHash = frameHash(frame)
  }
  const bytes = b4a.concat(frames, frames.length * FRAME_BYTES)
  try {
    await fault(state, `${label}:before-write`, { frameCount: specs.length, byteLength: bytes.byteLength })
    await writeAll(state.handle, bytes, state.offset)
    await fault(state, `${label}:after-write`, { frameCount: specs.length, byteLength: bytes.byteLength })
    await state.handle.sync()
    await fault(state, `${label}:after-sync`, { frameCount: specs.length, byteLength: bytes.byteLength })
    await assertLiveFiles(state, state.offset + bytes.byteLength)
  } catch (error) {
    poison(state, error)
    throw error
  }
  state.sequence = sequence
  state.previousFrameHash = previousFrameHash
  state.offset += bytes.byteLength
  state.recordCount += specs.length
}

function liveSnapshot (entries, now, expiredKeys) {
  const output = []
  for (const [key, entry] of entries) {
    if (expiredKeys.has(key)) continue
    const remaining = entry.expiresMonotonicMillis - now
    if (remaining < 1n || remaining > ACCEPTED_RECORD_MAXIMUM_TTL_MILLIS) {
      throw new PrivateIpcReplayJournalV2Error(
        'private IPC replay journal live entry has an invalid remaining horizon',
        'PRIVATE_IPC_V2_REPLAY_JOURNAL_CLOCK_UNSAFE'
      )
    }
    output.push({
      key,
      replayTupleHash: b4a.from(entry.replayTupleHash),
      expiresMonotonicMillis: entry.expiresMonotonicMillis,
      ttlMillis: Number(remaining)
    })
  }
  output.sort((left, right) => left.key < right.key ? -1 : left.key > right.key ? 1 : 0)
  return output
}

async function compactJournal (state, now, expiredKeys) {
  if (state.generation === MAX_U64) {
    const error = new PrivateIpcReplayJournalV2Error(
      'private IPC replay journal generation overflowed',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_CLOCK_UNSAFE'
    )
    poison(state, error)
    throw error
  }
  const snapshot = liveSnapshot(state.entries, now, expiredKeys)
  const generation = state.generation + 1n
  const header = encodeHeader(state.identity, generation, state.headerKey)
  let previousFrameHash = chainAnchor(header)
  const frames = []
  for (let index = 0; index < snapshot.length; index++) {
    const frame = encodeFrame({
      type: FRAME_TYPE.CONSUME,
      sequence: BigInt(index + 1),
      generation,
      replayTupleHash: snapshot[index].replayTupleHash,
      ttlMillis: snapshot[index].ttlMillis,
      previousFrameHash
    }, header, state.recordKey)
    frames.push(frame)
    previousFrameHash = frameHash(frame)
  }
  const bytes = b4a.concat([header, ...frames], HEADER_BYTES + (frames.length * FRAME_BYTES))
  const temporary = path.join(state.root, `.replay-journal.v2.${randomBytes(16).toString('hex')}.tmp`)
  let replacement = null
  let renamed = false
  try {
    await assertLiveFiles(state)
    replacement = await fs.open(temporary,
      FS_CONSTANTS.O_RDWR | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL | FS_CONSTANTS.O_NOFOLLOW,
      0o600)
    await writeAll(replacement, bytes, 0)
    await fault(state, 'compaction:after-temp-write', { byteLength: bytes.byteLength, liveCount: snapshot.length })
    await replacement.sync()
    await fault(state, 'compaction:after-temp-sync', { byteLength: bytes.byteLength, liveCount: snapshot.length })
    await verifyOpenedFile(replacement, temporary, 'private IPC replay journal compaction temporary')
    await fs.rename(temporary, state.journalPath)
    renamed = true
    await fault(state, 'compaction:after-rename', { liveCount: snapshot.length })
    await syncDirectory(state.root)
    await fault(state, 'compaction:after-directory-sync', { liveCount: snapshot.length })
    await verifyRoot(state.root, state.rootState)
    await verifyOpenedFile(state.lockHandle, state.lockPath,
      'private IPC replay journal writer lock', { empty: true })
    const installed = await verifyOpenedFile(replacement, state.journalPath,
      'private IPC replay journal compacted file')
    if (installed.size !== bytes.byteLength) {
      fail('private IPC replay journal compacted file has the wrong length',
        'PRIVATE_IPC_V2_REPLAY_JOURNAL_INTEGRITY')
    }
    const oldHandle = state.handle
    state.handle = replacement
    replacement = null
    state.header = header
    state.generation = generation
    state.sequence = BigInt(frames.length)
    state.previousFrameHash = previousFrameHash
    state.offset = bytes.byteLength
    state.recordCount = frames.length
    state.entries = new Map(snapshot.map((entry, index) => [entry.key, Object.freeze({
      replayTupleHash: b4a.from(entry.replayTupleHash),
      expiresMonotonicMillis: entry.expiresMonotonicMillis,
      generation,
      sequence: BigInt(index + 1)
    })]))
    await oldHandle.close()
  } catch (error) {
    poison(state, error)
    throw error
  } finally {
    if (replacement) await replacement.close().catch(() => {})
    if (!renamed) {
      await fs.unlink(temporary).catch(error => {
        if (!error || error.code !== 'ENOENT') throw error
      })
    }
  }
}

function normalizeOptions (options) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('private IPC replay journal options are required')
  }
  const root = canonicalRoot(options.root)
  const identity = exactIdentity(options)
  const monotonicMillis = options.monotonicMillis == null
    ? () => process.hrtime.bigint() / 1_000_000n
    : options.monotonicMillis
  if (typeof monotonicMillis !== 'function') throw new TypeError('monotonicMillis must be a function')
  if (options.faultInjector != null && typeof options.faultInjector !== 'function') {
    throw new TypeError('faultInjector must be a function')
  }
  const compactionRecordLimit = options.compactionRecordLimit == null
    ? MAXIMUM_RECORDS
    : options.compactionRecordLimit
  if (!Number.isSafeInteger(compactionRecordLimit) ||
      compactionRecordLimit < 1 || compactionRecordLimit > MAXIMUM_RECORDS) {
    throw new TypeError(`compactionRecordLimit must be an integer inside 1..${MAXIMUM_RECORDS}`)
  }
  const keys = deriveKeys(options.partitionKey, identity)
  return {
    root,
    identity,
    keys,
    monotonicMillis,
    compactionRecordLimit,
    faultInjector: options.faultInjector || null
  }
}

async function cleanupFailedOpen (state) {
  if (state.handle) await state.handle.close().catch(() => {})
  state.handle = null
  if (state.lockHandle) {
    try {
      if (state.lockHeld) releaseExclusiveFileLock(state.lockHandle)
    } catch {}
    await state.lockHandle.close().catch(() => {})
  }
  state.lockHandle = null
  state.lockHeld = false
  if (state.headerKey) state.headerKey.fill(0)
  if (state.recordKey) state.recordKey.fill(0)
  ACTIVE_ROOTS.delete(state.root)
}

export async function openPrivateIpcReplayJournalV2 (options = {}) {
  if (!FS_CONSTANTS.O_NOFOLLOW) {
    fail('private IPC replay journal requires O_NOFOLLOW',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_PLATFORM_UNSUPPORTED')
  }
  const normalized = normalizeOptions(options)
  if (ACTIVE_ROOTS.has(normalized.root)) {
    normalized.keys.headerKey.fill(0)
    normalized.keys.recordKey.fill(0)
    fail('private IPC replay journal root is already open in this process',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_LOCKED')
  }
  const state = {
    root: normalized.root,
    lockPath: path.join(normalized.root, LOCK_FILE),
    journalPath: path.join(normalized.root, JOURNAL_FILE),
    identity: normalized.identity,
    headerKey: normalized.keys.headerKey,
    recordKey: normalized.keys.recordKey,
    monotonicMillis: normalized.monotonicMillis,
    compactionRecordLimit: normalized.compactionRecordLimit,
    faultInjector: normalized.faultInjector,
    phase: null,
    poisonReason: null,
    rootState: null,
    lockHandle: null,
    lockHeld: false,
    handle: null,
    header: null,
    generation: 0n,
    sequence: 0n,
    previousFrameHash: null,
    offset: 0,
    recordCount: 0,
    recoveredHashes: null,
    entries: new Map(),
    lastNow: null,
    quarantineUntilMonotonicMillis: null,
    serial: Promise.resolve(),
    closePromise: null,
    authority: null
  }
  ACTIVE_ROOTS.add(state.root)
  try {
    state.rootState = await verifyRoot(state.root)
    await openWriterLock(state)
    await verifyRoot(state.root, state.rootState)
    const active = await inspectInventory(state)
    if (!active) await installInitialJournal(state)
    await recoverJournal(state)
    await assertLiveFiles(state)
    const startupNow = asU64(state.monotonicMillis(), 'monotonicMillis')
    if (startupNow > MAX_U64 - STARTUP_WRITE_QUARANTINE_MILLIS ||
        startupNow > MAX_U64 - RECOVERED_ENTRY_MINIMUM_RETENTION_MILLIS) {
      fail('private IPC replay journal startup clock cannot represent its quarantine horizon',
        'PRIVATE_IPC_V2_REPLAY_JOURNAL_CLOCK_UNSAFE')
    }
    state.lastNow = startupNow
    state.quarantineUntilMonotonicMillis = startupNow + STARTUP_WRITE_QUARANTINE_MILLIS
    const recoveredUntilMonotonicMillis = startupNow + RECOVERED_ENTRY_MINIMUM_RETENTION_MILLIS
    for (const [key, recovered] of state.recoveredHashes) {
      state.entries.set(key, Object.freeze({
        replayTupleHash: b4a.from(recovered.replayTupleHash),
        expiresMonotonicMillis: recoveredUntilMonotonicMillis,
        generation: recovered.generation,
        sequence: recovered.sequence
      }))
    }
    state.recoveredHashes = null
    state.phase = STATE.OPEN
    const authority = Object.freeze({})
    state.authority = authority
    AUTHORITIES.set(authority, state)
    return authority
  } catch (error) {
    await cleanupFailedOpen(state)
    throw error
  }
}

export function privateIpcReplayJournalV2Status (authority) {
  const state = stateFor(authority)
  let now = state.lastNow
  if (state.phase === STATE.OPEN) {
    try {
      now = sampleNow(state)
    } catch {}
  }
  const quarantined = state.phase === STATE.OPEN && now < state.quarantineUntilMonotonicMillis
  let occupied = state.entries.size
  if (state.phase === STATE.OPEN) {
    occupied = 0
    for (const entry of state.entries.values()) {
      if (entry.expiresMonotonicMillis > now) occupied++
    }
  }
  const atCapacity = occupied >= CAPACITY
  return Object.freeze({
    state: state.phase,
    ready: state.phase === STATE.OPEN && !quarantined && !atCapacity,
    reason: state.phase === STATE.POISONED
      ? state.poisonReason
      : quarantined
        ? 'PRIVATE_IPC_V2_REPLAY_JOURNAL_STARTUP_QUARANTINE'
        : atCapacity
          ? 'PRIVATE_IPC_V2_REPLAY_JOURNAL_CAPACITY'
          : state.phase === STATE.OPEN
            ? null
            : `PRIVATE_IPC_V2_REPLAY_JOURNAL_${state.phase}`,
    capacity: CAPACITY,
    occupied,
    recordCount: state.recordCount,
    generation: state.generation,
    acceptedRecordMaximumTtlMillis: PRIVATE_IPC_V2_REPLAY_POLICY.acceptedRecordMaximumTtlMillis,
    recoveredEntryMinimumRetentionMillis: PRIVATE_IPC_V2_REPLAY_POLICY.recoveredEntryMinimumRetentionMillis,
    startupWriteQuarantineMillis: PRIVATE_IPC_V2_REPLAY_POLICY.startupWriteQuarantineMillis,
    compactionRecordLimit: state.compactionRecordLimit,
    quarantineUntilMonotonicMillis: state.quarantineUntilMonotonicMillis
  })
}

function reservationInput (input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('private IPC replay reservation input is required')
  }
  const allowed = new Set(['replayTupleHash', 'expiresMonotonicMillis', 'signal'])
  const unknown = Object.keys(input).find(key => !allowed.has(key))
  if (unknown) throw new TypeError(`private IPC replay reservation contains unknown field ${unknown}`)
  return Object.freeze({
    replayTupleHash: ownedBytes(input.replayTupleHash, 32, 'replayTupleHash'),
    expiresMonotonicMillis: asU64(input.expiresMonotonicMillis, 'expiresMonotonicMillis'),
    signal: exactSignal(input.signal)
  })
}

function expectedReservationBinding (expected) {
  if (!expected || typeof expected !== 'object' || Array.isArray(expected)) {
    throw new TypeError('expected replay reservation binding is required')
  }
  const keys = Reflect.ownKeys(expected)
  if (keys.length !== 2 ||
      !keys.includes('replayTupleHash') ||
      !keys.includes('expiresMonotonicMillis')) {
    throw new TypeError('expected replay reservation binding must contain exactly replayTupleHash and expiresMonotonicMillis')
  }
  return Object.freeze({
    replayTupleHash: ownedBytes(expected.replayTupleHash, 32, 'expected replayTupleHash'),
    expiresMonotonicMillis: asU64(expected.expiresMonotonicMillis, 'expected expiresMonotonicMillis')
  })
}

function mintReceipt (state, entry) {
  const receiptState = {
    authority: state.authority,
    replayTupleHash: b4a.from(entry.replayTupleHash),
    expiresMonotonicMillis: entry.expiresMonotonicMillis,
    generation: entry.generation,
    sequence: entry.sequence
  }
  const receipt = Object.freeze({})
  RECEIPTS.set(receipt, receiptState)
  return receipt
}

export function reservePrivateIpcReplayTupleV2 (authority, input) {
  const state = stateFor(authority)
  const value = reservationInput(input)
  if (state.phase !== STATE.OPEN) {
    return Promise.reject(new PrivateIpcReplayJournalV2Error(
      'private IPC replay journal is not open for reservations',
      state.phase === STATE.POISONED
        ? 'PRIVATE_IPC_V2_REPLAY_JOURNAL_POISONED'
        : 'PRIVATE_IPC_V2_REPLAY_JOURNAL_UNAVAILABLE'
    ))
  }
  if (value.signal && value.signal.aborted) return Promise.reject(abortError())
  return serialize(state, async () => {
    if (state.phase !== STATE.OPEN) {
      fail('private IPC replay journal became unavailable before reservation',
        'PRIVATE_IPC_V2_REPLAY_JOURNAL_UNAVAILABLE')
    }
    if (value.signal && value.signal.aborted) throw abortError()
    const now = sampleNow(state)
    if (now < state.quarantineUntilMonotonicMillis) {
      fail('private IPC replay journal is inside its mandatory startup quarantine',
        'PRIVATE_IPC_V2_REPLAY_JOURNAL_STARTUP_QUARANTINE')
    }
    if (value.expiresMonotonicMillis <= now ||
        value.expiresMonotonicMillis - now > ACCEPTED_RECORD_MAXIMUM_TTL_MILLIS) {
      fail('private IPC replay reservation expiry is not live and bounded',
        'PRIVATE_IPC_V2_EXPIRED')
    }
    try {
      await assertLiveFiles(state)
    } catch (error) {
      poison(state, error)
      throw error
    }
    const key = b4a.toString(value.replayTupleHash, 'hex')
    const expiredKeys = new Set()
    for (const [entryKey, entry] of state.entries) {
      if (entry.expiresMonotonicMillis <= now) expiredKeys.add(entryKey)
    }
    if (state.entries.has(key) && !expiredKeys.has(key)) {
      fail('private IPC replay tuple is already durably consumed', 'PRIVATE_IPC_V2_REPLAY')
    }
    const liveCount = state.entries.size - expiredKeys.size
    if (liveCount >= CAPACITY) {
      fail('private IPC replay journal is at live capacity', 'BLIND_STREAM_BUSY')
    }
    const appendCount = expiredKeys.size + 1
    if (state.recordCount + appendCount > state.compactionRecordLimit) {
      if (value.signal && value.signal.aborted) throw abortError()
      await compactJournal(state, now, expiredKeys)
      expiredKeys.clear()
      if (value.signal && value.signal.aborted) throw abortError()
    }
    const durableNow = sampleNow(state)
    if (value.expiresMonotonicMillis <= durableNow) {
      fail('private IPC replay reservation expired before its durable write began',
        'PRIVATE_IPC_V2_EXPIRED')
    }
    const specs = []
    for (const expiredKey of [...expiredKeys].sort()) {
      specs.push({
        type: FRAME_TYPE.EXPIRE,
        replayTupleHash: state.entries.get(expiredKey).replayTupleHash,
        ttlMillis: 0
      })
    }
    specs.push({
      type: FRAME_TYPE.CONSUME,
      replayTupleHash: value.replayTupleHash,
      ttlMillis: Number(value.expiresMonotonicMillis - durableNow)
    })
    if (value.signal && value.signal.aborted) throw abortError()
    await appendFrameSpecs(state, specs, 'reserve')
    for (const expiredKey of expiredKeys) state.entries.delete(expiredKey)
    const entry = Object.freeze({
      replayTupleHash: b4a.from(value.replayTupleHash),
      expiresMonotonicMillis: value.expiresMonotonicMillis,
      generation: state.generation,
      sequence: state.sequence
    })
    state.entries.set(key, entry)
    const committedNow = sampleNow(state)
    if (value.expiresMonotonicMillis <= committedNow) {
      fail('private IPC replay reservation expired before its durable commit could be authorized',
        'PRIVATE_IPC_V2_EXPIRED')
    }
    return mintReceipt(state, entry)
  })
}

export function consumePrivateIpcReplayReservationV2 (authority, receipt, expected = {}) {
  const state = stateFor(authority)
  const binding = expectedReservationBinding(expected)
  if (state.phase !== STATE.OPEN) {
    fail('private IPC replay reservation cannot be consumed from an unavailable journal',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_UNAVAILABLE')
  }
  if (!receipt || typeof receipt !== 'object') {
    fail('private IPC replay reservation receipt is forged or already consumed',
      'PRIVATE_IPC_V2_REPLAY_RESERVATION_INVALID')
  }
  const internal = RECEIPTS.get(receipt)
  if (!internal) {
    fail('private IPC replay reservation receipt is forged, foreign, or already consumed',
      'PRIVATE_IPC_V2_REPLAY_RESERVATION_INVALID')
  }
  RECEIPTS.delete(receipt)
  if (internal.authority !== authority ||
      !sameSecret(internal.replayTupleHash, binding.replayTupleHash) ||
      internal.expiresMonotonicMillis !== binding.expiresMonotonicMillis) {
    fail('private IPC replay reservation receipt does not match its expected tuple and expiry',
      'PRIVATE_IPC_V2_REPLAY_RESERVATION_INVALID')
  }
  const now = sampleNow(state)
  if (state.phase !== STATE.OPEN) {
    fail('private IPC replay reservation became unavailable during consumption',
      'PRIVATE_IPC_V2_REPLAY_JOURNAL_UNAVAILABLE')
  }
  const key = b4a.toString(internal.replayTupleHash, 'hex')
  const entry = state.entries.get(key)
  if (!entry ||
      entry.expiresMonotonicMillis <= now ||
      internal.expiresMonotonicMillis <= now ||
      entry.expiresMonotonicMillis !== internal.expiresMonotonicMillis ||
      entry.generation !== internal.generation ||
      entry.sequence !== internal.sequence ||
      !sameSecret(entry.replayTupleHash, internal.replayTupleHash)) {
    fail('private IPC replay reservation is expired, superseded, or no longer current',
      'PRIVATE_IPC_V2_REPLAY_RESERVATION_INVALID')
  }
  return true
}

export function createPrivateIpcReplayReservationAuthorityV2 (authority) {
  stateFor(authority)
  return Object.freeze({
    async reserve (input) {
      if (!input || typeof input !== 'object' || Array.isArray(input)) {
        throw new TypeError('durable replay reservation input is required')
      }
      const replayTupleHash = ownedBytes(input.replayTupleHash, 32, 'replayTupleHash')
      const expiresMonotonicMillis = asU64(input.expiresMonotonicMillis,
        'expiresMonotonicMillis')
      const receipt = await reservePrivateIpcReplayTupleV2(authority, {
        replayTupleHash,
        expiresMonotonicMillis,
        signal: input.signal
      })
      consumePrivateIpcReplayReservationV2(authority, receipt, {
        replayTupleHash,
        expiresMonotonicMillis
      })
      return Object.freeze({
        kind: 'reserved-new',
        durablyCommitted: true,
        replayTupleHash,
        expiresMonotonicMillis
      })
    }
  })
}

export function closePrivateIpcReplayJournalV2 (authority) {
  const state = stateFor(authority)
  if (state.closePromise) return state.closePromise
  if (state.phase === STATE.CLOSED) return Promise.resolve()
  if (state.phase !== STATE.POISONED) state.phase = STATE.CLOSING
  state.closePromise = serialize(state, async () => {
    let failure = null
    try {
      if (state.handle) await state.handle.close()
    } catch (error) {
      failure = error
    } finally {
      state.handle = null
    }
    if (state.lockHandle) {
      try {
        if (state.lockHeld) releaseExclusiveFileLock(state.lockHandle)
      } catch (error) {
        failure = failure || error
      }
      try {
        await state.lockHandle.close()
      } catch (error) {
        failure = failure || error
      }
    }
    state.lockHandle = null
    state.lockHeld = false
    state.entries.clear()
    if (state.headerKey) state.headerKey.fill(0)
    if (state.recordKey) state.recordKey.fill(0)
    state.phase = STATE.CLOSED
    ACTIVE_ROOTS.delete(state.root)
    if (failure) throw failure
  })
  return state.closePromise
}
