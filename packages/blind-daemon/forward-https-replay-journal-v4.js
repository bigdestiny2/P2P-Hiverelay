import { constants as FS_CONSTANTS } from 'node:fs'
import fs from 'node:fs/promises'
import path from 'node:path'
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import b4a from 'b4a'
import {
  decodeLocalForwardHttpsOriginAuthorityV4,
  decodeLocalForwardHttpsTargetIngressV4,
  localForwardHttpsSourceReplayTupleV4,
  localForwardHttpsTargetReplayTupleV4
} from '@hiverelay/blind-ipc'
import {
  releaseExclusiveFileLock,
  tryExclusiveFileLock
} from '@hiverelay/blind-peercred'
import { blake2b256 } from '@hiverelay/blind-protocol'

const MAX_U64 = (1n << 64n) - 1n
const ZERO32 = b4a.alloc(32)
const SNAPSHOT_MAGIC = b4a.from('FRJ4', 'ascii')
const SNAPSHOT_VERSION = 1
// Exact written snapshot header layout: magic4 + version1 + role1 +
// quarantined1 + reserved1 + capacity u32 + count u32 + lastMonotonic u64 +
// four 32-byte bindings + mapGeneration u64 + two 32-byte fence bindings = 224.
const SNAPSHOT_HEADER_BYTES = 224
const SNAPSHOT_RECORD_BYTES = 49
const SNAPSHOT_MAC_BYTES = 32
const LOCK_FILE = 'writer.lock.v4'
const ACTIVE_ROOTS = new Set()
const REPLAY_AUTHORITIES = new WeakMap()
const REPLAY_RESERVATIONS = new WeakMap()
const REPLAY_CONSUMED = new WeakMap()
const QUOTA_AUTHORITIES = new WeakMap()
const QUOTA_CAPABILITIES = new WeakMap()
const QUOTA_SINKS = new WeakMap()
const QUOTA_CLAIMS = new WeakMap()
const QUOTA_RECOVERY_FINALS = new WeakMap()
const QUOTA_PLANS = new WeakMap()
const QUOTA_RESERVATIONS = new WeakMap()

export const FORWARD_HTTPS_REPLAY_ROLE_V4 = deepFreeze({
  SOURCE_ORIGIN: 'SOURCE_ORIGIN',
  TARGET_INGRESS: 'TARGET_INGRESS'
})

export const FORWARD_HTTPS_REPLAY_JOURNAL_V4_LIMITS = deepFreeze({
  capacityPerRole: 4096,
  maximumDeadlineMillis: 15000,
  sourceRecordBytes: 292,
  targetRecordBytes: 65828,
  sourceStateFile: 'forward-replay-source-origin-v4.json',
  targetStateFile: 'forward-replay-target-ingress-v4.json',
  liveEntryEvictionPermitted: false,
  callbackTimeoutMillis: 15000
})

export const FORWARD_HTTPS_REPLAY_JOURNAL_V4_STATUS = deepFreeze({
  schemaVersion: 4,
  implementationReady: true,
  descriptorOperationBits: 0,
  advertisedOperationBits: 0,
  readinessOperationBits: 0,
  runtimeReady: false,
  releaseReady: false,
  authorizesRelease: false
})

export const FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE = deepFreeze({
  INVALID: 'FORWARD_HTTPS_REPLAY_JOURNAL_V4_INVALID',
  AUTHORITY_INVALID: 'FORWARD_HTTPS_REPLAY_JOURNAL_V4_AUTHORITY_INVALID',
  ROLE_INVALID: 'FORWARD_HTTPS_REPLAY_JOURNAL_V4_ROLE_INVALID',
  RECORD_INVALID: 'FORWARD_HTTPS_REPLAY_JOURNAL_V4_RECORD_INVALID',
  REPLAY: 'FORWARD_HTTPS_REPLAY_JOURNAL_V4_REPLAY',
  CAPACITY: 'FORWARD_HTTPS_REPLAY_JOURNAL_V4_CAPACITY',
  EXPIRED: 'FORWARD_HTTPS_REPLAY_JOURNAL_V4_EXPIRED',
  CLOCK_UNSAFE: 'FORWARD_HTTPS_REPLAY_JOURNAL_V4_CLOCK_UNSAFE',
  QUARANTINED: 'FORWARD_HTTPS_REPLAY_JOURNAL_V4_QUARANTINED',
  RESERVATION_INVALID: 'FORWARD_HTTPS_REPLAY_JOURNAL_V4_RESERVATION_INVALID',
  CONSUMED_INVALID: 'FORWARD_HTTPS_REPLAY_JOURNAL_V4_CONSUMED_INVALID',
  FILESYSTEM_INVALID: 'FORWARD_HTTPS_REPLAY_JOURNAL_V4_FILESYSTEM_INVALID',
  PLATFORM_UNSUPPORTED: 'FORWARD_HTTPS_REPLAY_JOURNAL_V4_PLATFORM_UNSUPPORTED',
  LOCKED: 'FORWARD_HTTPS_REPLAY_JOURNAL_V4_LOCKED',
  CLOSED: 'FORWARD_HTTPS_REPLAY_JOURNAL_V4_CLOSED',
  INTEGRITY: 'FORWARD_HTTPS_REPLAY_JOURNAL_V4_INTEGRITY'
})

export const FORWARD_HTTPS_REPLAY_JOURNAL_V4_FAULT_POINT = deepFreeze({
  OPEN_AFTER_LOCK: 'OPEN_AFTER_LOCK',
  BOOTSTRAP_AFTER_WRITE: 'BOOTSTRAP_AFTER_WRITE',
  BOOTSTRAP_AFTER_FILE_FSYNC: 'BOOTSTRAP_AFTER_FILE_FSYNC',
  BOOTSTRAP_AFTER_RENAME: 'BOOTSTRAP_AFTER_RENAME',
  BOOTSTRAP_AFTER_DIRECTORY_FSYNC: 'BOOTSTRAP_AFTER_DIRECTORY_FSYNC',
  RESERVE_AFTER_WRITE: 'RESERVE_AFTER_WRITE',
  RESERVE_AFTER_FILE_FSYNC: 'RESERVE_AFTER_FILE_FSYNC',
  RESERVE_AFTER_RENAME: 'RESERVE_AFTER_RENAME',
  RESERVE_AFTER_DIRECTORY_FSYNC: 'RESERVE_AFTER_DIRECTORY_FSYNC',
  CONSUME_AFTER_WRITE: 'CONSUME_AFTER_WRITE',
  CONSUME_AFTER_FILE_FSYNC: 'CONSUME_AFTER_FILE_FSYNC',
  CONSUME_AFTER_RENAME: 'CONSUME_AFTER_RENAME',
  CONSUME_AFTER_DIRECTORY_FSYNC: 'CONSUME_AFTER_DIRECTORY_FSYNC',
  QUARANTINE_AFTER_FILE_FSYNC: 'QUARANTINE_AFTER_FILE_FSYNC',
  QUARANTINE_AFTER_DIRECTORY_FSYNC: 'QUARANTINE_AFTER_DIRECTORY_FSYNC',
  PRUNE_AFTER_FILE_FSYNC: 'PRUNE_AFTER_FILE_FSYNC',
  CLOSE_BEFORE_UNLOCK: 'CLOSE_BEFORE_UNLOCK'
})

export class ForwardHttpsReplayJournalV4Error extends Error {
  constructor (message, code = FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.INVALID) {
    super(message)
    this.name = 'ForwardHttpsReplayJournalV4Error'
    this.code = code
  }
}

export const FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE = deepFreeze({
  INVALID: 'FORWARD_HTTPS_AGGREGATE_QUOTA_V3_INVALID',
  AUTHORITY_INVALID: 'FORWARD_HTTPS_AGGREGATE_QUOTA_V3_AUTHORITY_INVALID',
  CAPACITY: 'FORWARD_HTTPS_AGGREGATE_QUOTA_V3_CAPACITY',
  FILESYSTEM_INVALID: 'FORWARD_HTTPS_AGGREGATE_QUOTA_V3_FILESYSTEM_INVALID',
  CLOCK_UNSAFE: 'FORWARD_HTTPS_AGGREGATE_QUOTA_V3_CLOCK_UNSAFE',
  CLOSED: 'FORWARD_HTTPS_AGGREGATE_QUOTA_V3_CLOSED',
  INTEGRITY: 'FORWARD_HTTPS_AGGREGATE_QUOTA_V3_INTEGRITY'
})

export const FORWARD_HTTPS_AGGREGATE_QUOTA_V3_FAULT_POINT = deepFreeze({
  OPEN_AFTER_ROOT_BIND: 'OPEN_AFTER_ROOT_BIND',
  RECOVERY_AFTER_FRAME: 'RECOVERY_AFTER_FRAME',
  RECOVERY_AFTER_FINISH: 'RECOVERY_AFTER_FINISH',
  INITIALIZE_AFTER_MEASURE: 'INITIALIZE_AFTER_MEASURE',
  RESERVE_AFTER_MEASURE: 'RESERVE_AFTER_MEASURE',
  COMMIT_AFTER_MEASURE: 'COMMIT_AFTER_MEASURE',
  RELEASE_BEFORE_UNLOCK: 'RELEASE_BEFORE_UNLOCK',
  ADJUST_AFTER_MEASURE: 'ADJUST_AFTER_MEASURE',
  CLOSE_BEFORE_INVALIDATE: 'CLOSE_BEFORE_INVALIDATE'
})

export const FORWARD_HTTPS_AGGREGATE_QUOTA_V3_LIMITS = deepFreeze({
  perStoreDurableBytes: 8589934592,
  aggregateDurableBytes: 17179869184,
  exactRootCount: 4,
  walFrameOverheadBytes: 224,
  maximumIngressEncryptedRecords: 4,
  maximumOutcomeEncryptedRecords: 144,
  maximumIngressOutboundEventsPerTransition: 1,
  maximumOutcomeEventsPerTransition: 142,
  callbackTimeoutMillis: 15000
})

export const FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3 = deepFreeze({
  SOURCE_REPLAY: 'SOURCE_REPLAY',
  TARGET_REPLAY: 'TARGET_REPLAY',
  SOURCE_STORE: 'SOURCE_STORE',
  TARGET_STORE: 'TARGET_STORE'
})

export class ForwardHttpsAggregateQuotaV3Error extends Error {
  constructor (message, code = FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INVALID) {
    super(message)
    this.name = 'ForwardHttpsAggregateQuotaV3Error'
    this.code = code
  }
}

function deepFreeze (value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item)
    Object.freeze(value)
  }
  return value
}

function replayFail (message, code) {
  throw new ForwardHttpsReplayJournalV4Error(message, code)
}

function quotaFail (message, code) {
  throw new ForwardHttpsAggregateQuotaV3Error(message, code)
}

function closedObject (value, required, optional = [], field = 'options') {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) {
    throw new TypeError(`${field} must be a closed object`)
  }
  const keys = Object.keys(value)
  const allowed = [...required, ...optional]
  for (const key of required) if (!Object.hasOwn(value, key)) throw new TypeError(`${field}.${key} is required`)
  for (const key of keys) if (!allowed.includes(key)) throw new TypeError(`${field} contains unknown field ${key}`)
  return value
}

function bytes (value, length, field, nonzero = false) {
  if (!value || typeof value.byteLength !== 'number') throw new TypeError(`${field} must be bytes`)
  const output = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (length !== null && output.byteLength !== length) throw new TypeError(`${field} must be exactly ${length} bytes`)
  if (nonzero && b4a.equals(output, ZERO32)) throw new TypeError(`${field} must be nonzero`)
  return output
}

function u64 (value, field, nonzero = false) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${field} must be an unsigned integer`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64 || (nonzero && value === 0n)) {
    throw new TypeError(`${field} is outside u64`)
  }
  return value
}

function safeUint (value, field, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${field} is outside ${minimum}..${maximum}`)
  }
  return value
}

function canonicalRoot (value, field = 'root') {
  if (typeof value !== 'string' || !path.isAbsolute(value) || path.normalize(value) !== value || value.includes('\0')) {
    throw new TypeError(`${field} must be a canonical absolute path`)
  }
  return value
}

function writeU32 (output, offset, value) {
  output.writeUInt32BE(value, offset)
  return offset + 4
}

function writeU64 (output, offset, value) {
  value = u64(value, 'u64')
  for (let index = 7; index >= 0; index--) {
    output[offset + index] = Number(value & 0xffn)
    value >>= 8n
  }
  return offset + 8
}

function readU64 (input, offset) {
  let value = 0n
  for (let index = 0; index < 8; index++) value = (value << 8n) | BigInt(input[offset + index])
  return value
}

function roleByte (role) {
  if (role === FORWARD_HTTPS_REPLAY_ROLE_V4.SOURCE_ORIGIN) return 1
  if (role === FORWARD_HTTPS_REPLAY_ROLE_V4.TARGET_INGRESS) return 2
  replayFail('replay role is invalid', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.ROLE_INVALID)
}

function hmac (key, ...inputs) {
  const state = createHmac('sha256', key)
  for (const input of inputs) state.update(input)
  return state.digest()
}

function sameInode (left, right) {
  return left.dev === right.dev && left.ino === right.ino
}

function privateDirectory (stat, field, quota = false) {
  const error = quota
    ? FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.FILESYSTEM_INVALID
    : FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.FILESYSTEM_INVALID
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700 ||
      typeof process.getuid !== 'function' || stat.uid !== process.getuid()) {
    if (quota) quotaFail(`${field} must be an owned mode-0700 directory`, error)
    replayFail(`${field} must be an owned mode-0700 directory`, error)
  }
}

function privateFile (stat, field) {
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 ||
      (stat.mode & 0o777) !== 0o600 || typeof process.getuid !== 'function' || stat.uid !== process.getuid()) {
    replayFail(`${field} must be an owned single-link mode-0600 file`,
      FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.FILESYSTEM_INVALID)
  }
}

async function verifyDirectory (root, expected = null, quota = false) {
  const before = await fs.lstat(root)
  privateDirectory(before, root, quota)
  if (await fs.realpath(root) !== root) {
    if (quota) quotaFail('quota root traverses a symlink', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.FILESYSTEM_INVALID)
    replayFail('replay root traverses a symlink', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.FILESYSTEM_INVALID)
  }
  const after = await fs.lstat(root)
  privateDirectory(after, root, quota)
  if (!sameInode(before, after) || (expected && !sameInode(expected, after))) {
    if (quota) quotaFail('quota root inode changed', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.FILESYSTEM_INVALID)
    replayFail('replay root inode changed', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.FILESYSTEM_INVALID)
  }
  return after
}

async function syncDirectory (root) {
  const handle = await fs.open(root, FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW)
  try {
    await handle.sync()
  } finally {
    await handle.close()
  }
}

async function deadlineCall (callback, point, clock, timeout, ErrorClass, code) {
  if (callback === null) return
  const start = u64(clock(), 'monotonicMillis()')
  let timer
  let result
  try {
    result = await Promise.race([
      Promise.resolve().then(() => callback(point)),
      new Promise((resolve, reject) => {
        timer = setTimeout(() => reject(new Error('callback deadline exceeded')), timeout + 1)
      })
    ])
  } catch (error) {
    throw new ErrorClass(`callback ${point} failed`, code, { cause: error })
  } finally {
    clearTimeout(timer)
  }
  const end = u64(clock(), 'monotonicMillis()')
  if (end < start) throw new ErrorClass('monotonic clock regressed', code)
  if (end - start > BigInt(timeout) || result !== undefined) {
    throw new ErrorClass(`callback ${point} violated its contract`, code)
  }
}

function serialize (state, callback) {
  const previous = state.tail
  let release
  state.tail = new Promise(resolve => { release = resolve })
  return previous.then(async () => {
    try {
      return await callback()
    } finally {
      release()
    }
  })
}

function replayState (authority) {
  const state = authority && REPLAY_AUTHORITIES.get(authority)
  if (!state || state.authority !== authority) {
    replayFail('replay authority is forged', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.AUTHORITY_INVALID)
  }
  if (state.closed) replayFail('replay authority is closed', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.CLOSED)
  return state
}

function encodeSnapshot (state) {
  const records = [...state.records.values()].sort((left, right) => b4a.compare(left.tuple, right.tuple))
  const output = b4a.alloc(SNAPSHOT_HEADER_BYTES + records.length * SNAPSHOT_RECORD_BYTES + SNAPSHOT_MAC_BYTES)
  let offset = 0
  b4a.copy(SNAPSHOT_MAGIC, output, offset); offset += 4
  output[offset++] = SNAPSHOT_VERSION
  output[offset++] = roleByte(state.role)
  output[offset++] = state.quarantined ? 1 : 0
  output[offset++] = 0
  offset = writeU32(output, offset, state.capacity)
  offset = writeU32(output, offset, records.length)
  offset = writeU64(output, offset, state.lastMonotonicMillis)
  for (const field of ['wireV3AbiHash', 'privateIpcV4Hash', 'signedLaunchTopologyHash', 'storeId']) {
    b4a.copy(state[field], output, offset); offset += 32
  }
  offset = writeU64(output, offset, state.mapGeneration)
  for (const field of ['ownerFenceTokenHash', 'durabilityContinuityHash']) {
    b4a.copy(state[field], output, offset); offset += 32
  }
  if (offset !== SNAPSHOT_HEADER_BYTES) throw new Error('replay snapshot header accounting mismatch')
  for (const record of records) {
    b4a.copy(record.tuple, output, offset); offset += 32
    offset = writeU64(output, offset, record.acceptedMonotonicMillis)
    offset = writeU64(output, offset, record.deadlineMonotonicMillis)
    output[offset++] = record.state === 'PENDING' ? 1 : 2
  }
  const mac = hmac(state.key, output.subarray(0, offset))
  b4a.copy(mac, output, offset)
  return output
}

function decodeSnapshot (state, input) {
  if (input.byteLength < SNAPSHOT_HEADER_BYTES + SNAPSHOT_MAC_BYTES ||
      (input.byteLength - SNAPSHOT_HEADER_BYTES - SNAPSHOT_MAC_BYTES) % SNAPSHOT_RECORD_BYTES !== 0) {
    replayFail('replay snapshot length is invalid', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.INTEGRITY)
  }
  const body = input.subarray(0, input.byteLength - SNAPSHOT_MAC_BYTES)
  const actualMac = input.subarray(input.byteLength - SNAPSHOT_MAC_BYTES)
  if (!timingSafeEqual(hmac(state.key, body), actualMac)) {
    replayFail('replay snapshot MAC is invalid', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.INTEGRITY)
  }
  if (!b4a.equals(body.subarray(0, 4), SNAPSHOT_MAGIC) || body[4] !== SNAPSHOT_VERSION ||
      body[5] !== roleByte(state.role) || body[7] !== 0) {
    replayFail('replay snapshot header is invalid', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.INTEGRITY)
  }
  const capacity = body.readUInt32BE(8)
  const count = body.readUInt32BE(12)
  if (capacity !== state.capacity || count > state.capacity ||
      body.byteLength !== SNAPSHOT_HEADER_BYTES + count * SNAPSHOT_RECORD_BYTES) {
    replayFail('replay snapshot capacity is invalid', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.INTEGRITY)
  }
  state.lastMonotonicMillis = readU64(body, 16)
  let offset = 24
  for (const field of ['wireV3AbiHash', 'privateIpcV4Hash', 'signedLaunchTopologyHash', 'storeId']) {
    if (!b4a.equals(body.subarray(offset, offset + 32), state[field])) {
      replayFail(`replay snapshot ${field} binding is invalid`, FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.INTEGRITY)
    }
    offset += 32
  }
  if (readU64(body, offset) !== state.mapGeneration) {
    replayFail('replay snapshot generation is invalid', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.INTEGRITY)
  }
  offset += 8
  for (const field of ['ownerFenceTokenHash', 'durabilityContinuityHash']) {
    if (!b4a.equals(body.subarray(offset, offset + 32), state[field])) {
      replayFail(`replay snapshot ${field} binding is invalid`, FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.INTEGRITY)
    }
    offset += 32
  }
  state.quarantined = body[6] === 1
  state.records.clear()
  let previous = null
  for (let index = 0; index < count; index++) {
    const tuple = b4a.from(body.subarray(offset, offset + 32)); offset += 32
    const acceptedMonotonicMillis = readU64(body, offset); offset += 8
    const deadlineMonotonicMillis = readU64(body, offset); offset += 8
    const status = body[offset++]
    if ((previous && b4a.compare(previous, tuple) >= 0) ||
        (status !== 1 && status !== 2) || deadlineMonotonicMillis <= acceptedMonotonicMillis ||
        deadlineMonotonicMillis - acceptedMonotonicMillis > 15000n) {
      replayFail('replay snapshot record is invalid', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.INTEGRITY)
    }
    state.records.set(b4a.toString(tuple, 'hex'), {
      tuple,
      acceptedMonotonicMillis,
      deadlineMonotonicMillis,
      state: status === 1 ? 'PENDING' : 'CONSUMED'
    })
    previous = tuple
  }
}

async function installSnapshot (state, operation) {
  const bytes = encodeSnapshot(state)
  const point = operation.toUpperCase()
  const temporary = path.join(state.root, `.${path.basename(state.statePath)}.${randomBytes(16).toString('hex')}.tmp`)
  const plan = createForwardHttpsReplayQuotaCostPlanV3(state.replayQuotaCapability, {
    operation,
    encodedWriteBuffers: Object.freeze([bytes]),
    existingDestinationBytes: await fileSizeOrZero(state.statePath),
    temporaryAndDestinationCanCoexist: true
  })
  const { reservation } = await reserveForwardHttpsAggregateQuotaV3(state.replayQuotaCapability, plan)
  let handle
  let mutated = false
  try {
    handle = await fs.open(temporary, FS_CONSTANTS.O_WRONLY | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL | FS_CONSTANTS.O_NOFOLLOW, 0o600)
    await handle.writeFile(bytes)
    mutated = true
    await replayFault(state, FORWARD_HTTPS_REPLAY_JOURNAL_V4_FAULT_POINT[`${point}_AFTER_WRITE`])
    await handle.sync()
    await replayFault(state, FORWARD_HTTPS_REPLAY_JOURNAL_V4_FAULT_POINT[`${point}_AFTER_FILE_FSYNC`])
    privateFile(await handle.stat(), 'replay temporary')
    await handle.close(); handle = null
    await fs.rename(temporary, state.statePath)
    await replayFault(state, FORWARD_HTTPS_REPLAY_JOURNAL_V4_FAULT_POINT[`${point}_AFTER_RENAME`])
    await syncDirectory(state.root)
    await replayFault(state, FORWARD_HTTPS_REPLAY_JOURNAL_V4_FAULT_POINT[`${point}_AFTER_DIRECTORY_FSYNC`])
    await commitForwardHttpsAggregateQuotaV3(state.replayQuotaCapability, reservation, {
      durableWalHeadSequence: 0n,
      durableWalHeadHash: ZERO32
    })
  } catch (error) {
    if (!mutated) await releaseForwardHttpsAggregateQuotaV3(state.replayQuotaCapability, reservation).catch(() => {})
    throw error
  } finally {
    if (handle) await handle.close().catch(() => {})
    await fs.unlink(temporary).catch(error => { if (error.code !== 'ENOENT') throw error })
  }
}

async function replayFault (state, point) {
  if (point === undefined || state.faultInjector === null) return
  await deadlineCall(state.faultInjector, point, state.monotonicMillis, state.callbackTimeoutMillis,
    ForwardHttpsReplayJournalV4Error, FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.INTEGRITY)
}

async function quarantineReplay (state) {
  if (state.quarantined) return
  state.quarantined = true
  await installSnapshot(state, 'QUARANTINE')
}

function decodeReplayRecord (state, record) {
  record = bytes(record, state.role === FORWARD_HTTPS_REPLAY_ROLE_V4.SOURCE_ORIGIN ? 292 : 65828, 'record')
  try {
    const decoded = state.role === FORWARD_HTTPS_REPLAY_ROLE_V4.SOURCE_ORIGIN
      ? decodeLocalForwardHttpsOriginAuthorityV4(record)
      : decodeLocalForwardHttpsTargetIngressV4(record)
    if (!b4a.equals(decoded.wireV3AbiHash, state.wireV3AbiHash) ||
        !b4a.equals(decoded.signedLaunchTopologyHash, state.signedLaunchTopologyHash)) {
      replayFail('replay record binding is invalid', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.RECORD_INVALID)
    }
    const tuple = state.role === FORWARD_HTTPS_REPLAY_ROLE_V4.SOURCE_ORIGIN
      ? localForwardHttpsSourceReplayTupleV4(decoded)
      : localForwardHttpsTargetReplayTupleV4(decoded)
    return { record: b4a.from(record), decoded, tuple }
  } catch (error) {
    if (error instanceof ForwardHttpsReplayJournalV4Error) throw error
    replayFail('replay record is noncanonical', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.RECORD_INVALID)
  }
}

export async function openForwardHttpsReplayJournalV4 (options) {
  const required = ['role', 'root', 'manifestKey', 'replayQuotaCapability', 'wireV3AbiHash', 'privateIpcV4Hash', 'signedLaunchTopologyHash', 'storeId', 'mapGeneration', 'ownerFenceTokenHash', 'durabilityContinuityHash', 'monotonicMillis']
  closedObject(options, required, ['faultInjector', 'limits'])
  if (!FS_CONSTANTS.O_NOFOLLOW) replayFail('O_NOFOLLOW is unavailable', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.PLATFORM_UNSUPPORTED)
  const role = options.role
  roleByte(role)
  const root = canonicalRoot(options.root)
  if (ACTIVE_ROOTS.has(root)) replayFail('replay root is already open', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.LOCKED)
  const quotaCapability = quotaCapabilityState(options.replayQuotaCapability)
  const expectedQuotaRole = role === FORWARD_HTTPS_REPLAY_ROLE_V4.SOURCE_ORIGIN
    ? FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3.SOURCE_REPLAY
    : FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3.TARGET_REPLAY
  if (quotaCapability.role !== expectedQuotaRole || quotaCapability.root !== root) {
    replayFail('replay quota capability has the wrong role or root', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.AUTHORITY_INVALID)
  }
  const limits = normalizeTestLimits(options.limits)
  if (typeof options.monotonicMillis !== 'function') throw new TypeError('monotonicMillis must be a function')
  if (options.faultInjector != null && typeof options.faultInjector !== 'function') throw new TypeError('faultInjector must be a function')
  const manifestKey = b4a.from(bytes(options.manifestKey, 32, 'manifestKey', true))
  const state = {
    role,
    root,
    capacity: limits === null ? 4096 : limits.replayCapacityPerRole,
    replayQuotaCapability: options.replayQuotaCapability,
    wireV3AbiHash: b4a.from(bytes(options.wireV3AbiHash, 32, 'wireV3AbiHash', true)),
    privateIpcV4Hash: b4a.from(bytes(options.privateIpcV4Hash, 32, 'privateIpcV4Hash', true)),
    signedLaunchTopologyHash: b4a.from(bytes(options.signedLaunchTopologyHash, 32, 'signedLaunchTopologyHash', true)),
    storeId: b4a.from(bytes(options.storeId, 32, 'storeId', true)),
    mapGeneration: u64(options.mapGeneration, 'mapGeneration', true),
    ownerFenceTokenHash: b4a.from(bytes(options.ownerFenceTokenHash, 32, 'ownerFenceTokenHash', true)),
    durabilityContinuityHash: b4a.from(bytes(options.durabilityContinuityHash, 32, 'durabilityContinuityHash', true)),
    monotonicMillis: options.monotonicMillis,
    callbackTimeoutMillis: limits === null ? 15000 : limits.callbackTimeoutMillis,
    faultInjector: options.faultInjector || null,
    key: hmac(manifestKey, b4a.from('hiverelay.blind.forward-https-replay-key.v4', 'ascii'), b4a.from(role, 'ascii'), options.wireV3AbiHash, options.privateIpcV4Hash, options.signedLaunchTopologyHash, options.storeId, options.ownerFenceTokenHash, options.durabilityContinuityHash),
    statePath: path.join(root, role === FORWARD_HTTPS_REPLAY_ROLE_V4.SOURCE_ORIGIN
      ? FORWARD_HTTPS_REPLAY_JOURNAL_V4_LIMITS.sourceStateFile
      : FORWARD_HTTPS_REPLAY_JOURNAL_V4_LIMITS.targetStateFile),
    lockPath: path.join(root, LOCK_FILE),
    rootStat: null,
    lockHandle: null,
    records: new Map(),
    lastMonotonicMillis: 0n,
    quarantined: false,
    tail: Promise.resolve(),
    authority: null,
    closed: false,
    closePromise: null
  }
  manifestKey.fill(0)
  ACTIVE_ROOTS.add(root)
  try {
    state.rootStat = await verifyDirectory(root)
    state.lockHandle = await fs.open(state.lockPath, FS_CONSTANTS.O_RDWR | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_NOFOLLOW, 0o600)
    privateFile(await state.lockHandle.stat(), 'replay writer lock')
    if (!tryExclusiveFileLock(state.lockHandle)) replayFail('replay root is locked', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.LOCKED)
    await replayFault(state, FORWARD_HTTPS_REPLAY_JOURNAL_V4_FAULT_POINT.OPEN_AFTER_LOCK)
    const now = u64(state.monotonicMillis(), 'monotonicMillis()')
    state.lastMonotonicMillis = now
    try {
      const handle = await fs.open(state.statePath, FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW)
      try {
        privateFile(await handle.stat(), 'replay state')
        decodeSnapshot(state, await handle.readFile())
      } finally {
        await handle.close()
      }
      if (now < state.lastMonotonicMillis) {
        await quarantineReplay(state)
        replayFail('monotonic clock regressed', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.CLOCK_UNSAFE)
      }
      if (!state.quarantined && [...state.records.values()].some(record => record.state === 'PENDING')) {
        await quarantineReplay(state)
      }
      state.lastMonotonicMillis = now > state.lastMonotonicMillis ? now : state.lastMonotonicMillis
    } catch (error) {
      if (error && error.code === 'ENOENT') await installSnapshot(state, 'BOOTSTRAP')
      else if (error instanceof ForwardHttpsReplayJournalV4Error) throw error
      else replayFail('replay recovery failed', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.INTEGRITY)
    }
    const authority = Object.freeze({})
    state.authority = authority
    REPLAY_AUTHORITIES.set(authority, state)
    return authority
  } catch (error) {
    if (state.lockHandle) {
      try { releaseExclusiveFileLock(state.lockHandle) } catch {}
      await state.lockHandle.close().catch(() => {})
    }
    state.key.fill(0)
    ACTIVE_ROOTS.delete(root)
    throw error
  }
}

export function reserveForwardHttpsReplayV4 (journalAuthority, input) {
  let state
  try {
    state = replayState(journalAuthority)
    closedObject(input, ['record'], [], 'reserve input')
  } catch (error) {
    return Promise.reject(error)
  }
  return serialize(state, async () => {
    const candidate = decodeReplayRecord(state, input.record)
    const now = u64(state.monotonicMillis(), 'monotonicMillis()')
    if (now < state.lastMonotonicMillis) {
      await quarantineReplay(state)
      replayFail('monotonic clock regressed', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.CLOCK_UNSAFE)
    }
    if (state.quarantined) replayFail('replay journal is quarantined', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.QUARANTINED)
    const accepted = candidate.decoded.acceptedMonotonicMillis
    const deadline = candidate.decoded.absoluteDeadlineMonotonicMillis
    if (now < accepted || now > deadline || deadline <= accepted || deadline - accepted > 15000n) {
      replayFail('replay authority is expired', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.EXPIRED)
    }
    const tupleHex = b4a.toString(candidate.tuple, 'hex')
    if (state.records.has(tupleHex)) replayFail('replay tuple is occupied', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.REPLAY)
    if (state.records.size >= state.capacity) replayFail('replay capacity exhausted', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.CAPACITY)
    state.records.set(tupleHex, {
      tuple: b4a.from(candidate.tuple),
      acceptedMonotonicMillis: accepted,
      deadlineMonotonicMillis: deadline,
      state: 'PENDING'
    })
    state.lastMonotonicMillis = now
    await installSnapshot(state, 'RESERVE')
    const reservation = Object.freeze({})
    REPLAY_RESERVATIONS.set(reservation, {
      authority: journalAuthority,
      tuple: b4a.from(candidate.tuple),
      record: candidate.record,
      burned: false
    })
    return reservation
  })
}

export function consumeForwardHttpsReplayV4 (journalAuthority, reservation, input) {
  let state
  try {
    state = replayState(journalAuthority)
    closedObject(input, ['record'], [], 'consume input')
  } catch (error) {
    return Promise.reject(error)
  }
  const internal = reservation && REPLAY_RESERVATIONS.get(reservation)
  if (!internal || internal.burned || internal.authority !== journalAuthority) {
    return Promise.reject(new ForwardHttpsReplayJournalV4Error('replay reservation is forged', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.RESERVATION_INVALID))
  }
  internal.burned = true
  return serialize(state, async () => {
    const candidate = decodeReplayRecord(state, input.record)
    if (!b4a.equals(candidate.record, internal.record) || !b4a.equals(candidate.tuple, internal.tuple)) {
      replayFail('replay reservation record changed', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.RESERVATION_INVALID)
    }
    const now = u64(state.monotonicMillis(), 'monotonicMillis()')
    if (now < state.lastMonotonicMillis) {
      await quarantineReplay(state)
      replayFail('monotonic clock regressed', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.CLOCK_UNSAFE)
    }
    const entry = state.records.get(b4a.toString(candidate.tuple, 'hex'))
    if (!entry || entry.state !== 'PENDING') replayFail('replay reservation is not pending', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.RESERVATION_INVALID)
    if (now > entry.deadlineMonotonicMillis) replayFail('replay reservation expired', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.EXPIRED)
    entry.state = 'CONSUMED'
    state.lastMonotonicMillis = now
    await installSnapshot(state, 'CONSUME')
    const consumed = Object.freeze({})
    REPLAY_CONSUMED.set(consumed, {
      authority: journalAuthority,
      role: state.role,
      tuple: b4a.from(candidate.tuple),
      record: candidate.record,
      burned: false
    })
    return consumed
  })
}

export function verifyForwardHttpsReplayConsumedV4 (consumed, input) {
  closedObject(input, ['journalAuthority', 'role', 'record'], [], 'verify consumed input')
  const internal = consumed && REPLAY_CONSUMED.get(consumed)
  if (!internal || internal.burned) replayFail('consumed authority is forged', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.CONSUMED_INVALID)
  internal.burned = true
  const state = replayState(input.journalAuthority)
  const candidate = decodeReplayRecord(state, input.record)
  if (internal.authority !== input.journalAuthority || internal.role !== input.role ||
      input.role !== state.role || !b4a.equals(internal.record, candidate.record) ||
      !b4a.equals(internal.tuple, candidate.tuple)) {
    replayFail('consumed authority binding is invalid', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.CONSUMED_INVALID)
  }
}

export function forwardHttpsReplayJournalV4Status (journalAuthority) {
  const state = replayState(journalAuthority)
  const records = [...state.records.values()]
  return deepFreeze({
    role: state.role,
    state: state.quarantined ? 'QUARANTINED' : 'OPEN',
    localOperational: !state.quarantined,
    blocker: state.quarantined ? FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.QUARANTINED : null,
    capacity: state.capacity,
    occupied: records.length,
    pending: records.filter(record => record.state === 'PENDING').length,
    consumed: records.filter(record => record.state === 'CONSUMED').length,
    lastMonotonicMillis: state.lastMonotonicMillis,
    descriptorOperationBits: 0,
    advertisedOperationBits: 0,
    readinessOperationBits: 0,
    runtimeReady: false,
    releaseReady: false,
    authorizesRelease: false
  })
}

export function inspectForwardHttpsReplayJournalV4 (journalAuthority) {
  const state = replayState(journalAuthority)
  return Object.freeze([...state.records.values()]
    .sort((left, right) => b4a.compare(left.tuple, right.tuple))
    .map(record => freezeResult({
      replayTuple: b4a.from(record.tuple),
      acceptedMonotonicMillis: record.acceptedMonotonicMillis,
      deadlineMonotonicMillis: record.deadlineMonotonicMillis,
      state: record.state
    })))
}

export function closeForwardHttpsReplayJournalV4 (journalAuthority) {
  const state = journalAuthority && REPLAY_AUTHORITIES.get(journalAuthority)
  if (!state || state.authority !== journalAuthority) {
    return Promise.reject(new ForwardHttpsReplayJournalV4Error('replay authority is forged', FORWARD_HTTPS_REPLAY_JOURNAL_V4_ERROR_CODE.AUTHORITY_INVALID))
  }
  if (state.closePromise) return state.closePromise
  state.closePromise = serialize(state, async () => {
    if (state.closed) return
    await replayFault(state, FORWARD_HTTPS_REPLAY_JOURNAL_V4_FAULT_POINT.CLOSE_BEFORE_UNLOCK)
    state.closed = true
    try { releaseExclusiveFileLock(state.lockHandle) } catch {}
    await state.lockHandle.close()
    state.key.fill(0)
    ACTIVE_ROOTS.delete(state.root)
  })
  return state.closePromise
}

// Aggregate FIFO op-lifecycle mutex. A successful reserve holds the mutex
// through every per-frame composite apply and the closing commit, release or
// adjust; later submissions queue in exact submission order instead of being
// rejected. Failure paths resolve the queue so waiters wake and reject
// against the failed authority.
function acquireOp (state) {
  const acquired = state.opTail
  let release
  state.opTail = new Promise(resolve => { release = resolve })
  return { acquired, release }
}

function releaseOpFor (internal) {
  if (internal && internal.opRelease) {
    const release = internal.opRelease
    internal.opRelease = null
    release()
  }
}

function quotaState (authority) {
  const state = authority && QUOTA_AUTHORITIES.get(authority)
  if (!state || state.authority !== authority) quotaFail('quota authority is forged', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  if (state.closed) quotaFail('quota authority is closed', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.CLOSED)
  if (state.failed) quotaFail('quota authority is failed', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
  if (state.closing && !state.closed) quotaFail('quota authority is closing', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
  return state
}

function quotaCapabilityState (capability) {
  const state = capability && QUOTA_CAPABILITIES.get(capability)
  if (!state || state.burned) quotaFail('quota capability is forged', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  quotaState(state.quotaAuthority)
  return state
}

async function recursiveBytes (root) {
  let total = 0
  const entries = await fs.readdir(root, { withFileTypes: true })
  for (const entry of entries) {
    const item = path.join(root, entry.name)
    const stat = await fs.lstat(item)
    if (stat.isSymbolicLink()) quotaFail('quota traversal encountered an alias', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.FILESYSTEM_INVALID)
    if (stat.isDirectory()) total += await recursiveBytes(item)
    else if (stat.isFile()) {
      if (stat.nlink !== 1) quotaFail('quota traversal encountered an alias', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.FILESYSTEM_INVALID)
      total += stat.size
    } else quotaFail('quota traversal encountered a special file', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.FILESYSTEM_INVALID)
  }
  return total
}

async function measurements (state) {
  const output = {}
  for (const role of Object.values(FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3)) {
    await verifyDirectory(state.roots[role], state.rootStats[role], true)
    output[role] = await recursiveBytes(state.roots[role])
  }
  return output
}

async function quotaFault (state, point) {
  if (state.faultInjector === null) return
  await deadlineCall(state.faultInjector, point, state.monotonicMillis, state.callbackTimeoutMillis,
    ForwardHttpsAggregateQuotaV3Error, FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
}

export async function openForwardHttpsAggregateQuotaV3 (options) {
  const required = ['sourceReplayRoot', 'targetReplayRoot', 'sourceStoreRoot', 'targetStoreRoot', 'maximumDurableBytesPerStore', 'maximumForwardStorageBytesAggregate', 'monotonicMillis', 'callbackTimeoutMillis', 'faultInjector']
  closedObject(options, required)
  if (typeof options.monotonicMillis !== 'function') throw new TypeError('monotonicMillis must be a function')
  if (options.faultInjector !== null && typeof options.faultInjector !== 'function') throw new TypeError('faultInjector must be null or a function')
  const perStore = safeUint(options.maximumDurableBytesPerStore, 'maximumDurableBytesPerStore', 1, 8589934592)
  const aggregate = safeUint(options.maximumForwardStorageBytesAggregate, 'maximumForwardStorageBytesAggregate', 1, 17179869184)
  const roots = {
    SOURCE_REPLAY: canonicalRoot(options.sourceReplayRoot, 'sourceReplayRoot'),
    TARGET_REPLAY: canonicalRoot(options.targetReplayRoot, 'targetReplayRoot'),
    SOURCE_STORE: canonicalRoot(options.sourceStoreRoot, 'sourceStoreRoot'),
    TARGET_STORE: canonicalRoot(options.targetStoreRoot, 'targetStoreRoot')
  }
  if (new Set(Object.values(roots)).size !== 4) quotaFail('quota roots alias', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.FILESYSTEM_INVALID)
  const state = {
    roots,
    rootStats: {},
    perStore,
    aggregate,
    monotonicMillis: options.monotonicMillis,
    callbackTimeoutMillis: safeUint(options.callbackTimeoutMillis, 'callbackTimeoutMillis', 1, 15000),
    faultInjector: options.faultInjector,
    lastMonotonicMillis: u64(options.monotonicMillis(), 'monotonicMillis()'),
    logical: { SOURCE_STORE: 0, TARGET_STORE: 0 },
    physical: {},
    sessions: new Map(),
    openRecoverySinks: { SOURCE_STORE: null, TARGET_STORE: null },
    opTail: Promise.resolve(),
    opRelease: null,
    initialized: false,
    capabilitiesMinted: false,
    capabilityInternals: [],
    pendingReservation: false,
    pendingReservationObject: null,
    tail: Promise.resolve(),
    authority: null,
    failed: false,
    blocker: null,
    closed: false
  }
  for (const role of Object.values(FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3)) {
    state.rootStats[role] = await verifyDirectory(roots[role], null, true)
  }
  const identities = Object.values(state.rootStats).map(stat => `${stat.dev}:${stat.ino}`)
  if (new Set(identities).size !== 4) quotaFail('quota roots share an inode', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.FILESYSTEM_INVALID)
  state.physical = await measurements(state)
  const authority = Object.freeze({})
  state.authority = authority
  QUOTA_AUTHORITIES.set(authority, state)
  await quotaFault(state, FORWARD_HTTPS_AGGREGATE_QUOTA_V3_FAULT_POINT.OPEN_AFTER_ROOT_BIND)
  return authority
}

export function mintForwardHttpsAggregateQuotaCapabilitiesV3 (quotaAuthority) {
  const state = quotaState(quotaAuthority)
  if (state.capabilitiesMinted) quotaFail('quota capabilities were already minted', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  state.capabilitiesMinted = true
  const output = {}
  for (const [key, role] of [['sourceReplayQuotaCapability', 'SOURCE_REPLAY'], ['targetReplayQuotaCapability', 'TARGET_REPLAY'], ['sourceStoreQuotaCapability', 'SOURCE_STORE'], ['targetStoreQuotaCapability', 'TARGET_STORE']]) {
    const capability = Object.freeze({})
    QUOTA_CAPABILITIES.set(capability, { quotaAuthority, role, root: state.roots[role], burned: false })
    state.capabilityInternals.push(QUOTA_CAPABILITIES.get(capability))
    output[key] = capability
  }
  return deepFreeze(output)
}

// ---------------------------------------------------------------------------
// Recovery claim ABI (v16 recovery_claims): recovery claims are quota-minted,
// sink-private, one-use, burned inside absorb and never exposed to any caller.
// Live claims and recovery claims are disjoint classes.
// ---------------------------------------------------------------------------

function mintQuotaClaim (bindings) {
  const claim = Object.freeze({})
  QUOTA_CLAIMS.set(claim, { ...bindings, object: claim, burned: false })
  return claim
}

// Advance the canonical per-session mirror (bounded identity/vector state)
// from one closed derived entry. The payload is needed only for FPR9
// allocation dispositions. An open unpruned type113 run marks the exact
// prefix class: FRESH claims a PREFIX_ALLOCATED identity; EXISTING overlays
// ALLOCATED_WITH_PREFIX on the one ALLOCATED identity. A matching final or a
// flags2 abort closes the prefix record; the latest slot-disposing
// transition governs and no earlier frame reopens a closed disposition.
function applyEntryToSessionMirror (sessions, key, entry, payload) {
  if (entry.scope === 'ROLE_GLOBAL' || entry.stableSessionId === null) return
  const mirror = sessions.get(key) || { present: false, consumed: false, pruned: false, prefix: null, bitmap: 0, commitments: null, priorRevision: 0n }
  if (entry.scope === 'PRUNE_TRANSITION') {
    const pruned = decodeForwardHttpsRetentionPrunedV3(payload)
    mirror.chargeEntryCount = Math.max(0, (mirror.chargeEntryCount || 0) - pruned.chargeEntryCount)
    mirror.chargeSum = (mirror.chargeSum || 0n) - pruned.removedOrdinaryLogicalBytes
    if (mirror.chargeSum < 0n) mirror.chargeSum = 0n
    mirror.orphanCount = 0
    mirror.orphanSum = 0n
    mirror.orphanLastRevision = 0n
    mirror.requestCommitment = null
    if (pruned.flags === 2) {
      // flags2 existing-session prefix-abort: the slot stays ALLOCATED and the
      // authority vector is byte-identically unchanged; only orphan charge is
      // removed. The identity remains PRESENT_ALLOCATED; no PRUNED_RELEASED.
      mirror.present = true
      mirror.consumed = false
      mirror.prefix = null
    } else if (pruned.allocationDisposition === 1) {
      mirror.present = false
      mirror.consumed = false
      mirror.pruned = true
      mirror.prefix = null
      mirror.bitmap = 0
      mirror.commitments = null
    } else {
      mirror.present = true
      mirror.consumed = true
      mirror.pruned = true
      mirror.prefix = null
      mirror.bitmap = 0
      mirror.commitments = null
    }
    sessions.set(key, mirror)
    return
  }
  if (entry.walType === 113) {
    const commitment = payload && payload.byteLength >= 68 ? b4a.from(payload.subarray(36, 68)) : null
    if (!mirror.present) {
      mirror.prefix = 'FRESH'
      mirror.requestCommitment = commitment
    } else if (mirror.prefix === null) {
      mirror.prefix = 'EXISTING'
      mirror.requestCommitment = commitment
    } else if (commitment === null || !b4a.equals(commitment, mirror.requestCommitment || b4a.alloc(0))) {
      storeWalFail('mixed prefix requestCommitment is INTEGRITY')
    }
  } else if (mirror.prefix !== null) {
    // Only a final carrying the exact same requestCommitment closes the open
    // prefix record; a final of any other operation leaves it open.
    const commitment = payload && payload.byteLength >= 68 ? b4a.from(payload.subarray(36, 68)) : null
    if (commitment !== null && b4a.equals(commitment, mirror.requestCommitment || b4a.alloc(0))) {
      mirror.prefix = null
      mirror.requestCommitment = null
      mirror.orphanCount = 0
      mirror.orphanSum = 0n
      mirror.orphanLastRevision = 0n
    }
  }
  if (entry.terminalLogicalCharge > 0) {
    // Terminalization closes the open prefix record: the orphan entries
    // persist as ordinary removable charge in the consumed registry and no
    // flags2 abort is possible after.
    mirror.prefix = null
    mirror.requestCommitment = null
    mirror.orphanCount = 0
    mirror.orphanSum = 0n
    mirror.orphanLastRevision = 0n
  }
  if (entry.ordinaryLogicalCharge > 0) {
    // The 65537th removable charge entry of one identity is INTEGRITY in
    // recovery (or cap+1 terminal conversion live before ordinary WAL).
    if ((mirror.chargeEntryCount || 0) >= 65536) storeWalFail('recovered removable charge entries exceed the cap')
    mirror.chargeEntryCount = (mirror.chargeEntryCount || 0) + 1
    mirror.chargeSum = (mirror.chargeSum || 0n) + BigInt(entry.ordinaryLogicalCharge)
  }
  mirror.present = true
  mirror.priorRevision += 1n
  if (entry.walType === 113 && mirror.prefix !== null) {
    // Orphan bookkeeping for the exact flags1/flags2 match at adjust.
    mirror.orphanCount = (mirror.orphanCount || 0) + 1
    mirror.orphanSum = (mirror.orphanSum || 0n) + BigInt(entry.ordinaryLogicalCharge)
    mirror.orphanLastRevision = mirror.priorRevision
  }
  if (entry.terminalLogicalCharge > 0 && payload && payload.byteLength >= 149 && payload.readUInt16BE(6) === 1) {
    // FTM9 flags1 carries the exact session expiry clock in its minimal tail:
    // expiresAtEpoch at 141 and retainedUntilEpoch at 145. The terminal-only
    // FPR9 waits the full FTM9-carried grace.
    mirror.expiresAtEpoch = payload.readUInt32BE(141)
    mirror.recoveryGraceUntilEpoch = payload.readUInt32BE(145)
  }
  mirror.bitmap = entry.authorityBitmap
  mirror.commitments = entry.authorityCommitments
  mirror.consumed = entry.terminalLogicalCharge > 0 || (entry.authorityBitmap & 512) !== 0
  mirror.pruned = false
  sessions.set(key, mirror)
}

export function beginForwardHttpsAggregateQuotaRecoveryV3 (storeQuotaCapability) {
  const capability = quotaCapabilityState(storeQuotaCapability)
  if (capability.role !== 'SOURCE_STORE' && capability.role !== 'TARGET_STORE') {
    quotaFail('recovery capability role is invalid', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  }
  const state = quotaState(capability.quotaAuthority)
  // Sink exclusivity: exactly one open recovery sink per role root. A second
  // begin while a sink is open is AUTHORITY_INVALID; a crashed or abandoned
  // sink leaves the store non-localOperational until a fresh begin finishes.
  if (state.openRecoverySinks[capability.role] !== null) {
    quotaFail('a recovery sink is already open for this role root', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  }
  const sink = Object.freeze({})
  QUOTA_SINKS.set(sink, {
    quotaAuthority: capability.quotaAuthority,
    capability: storeQuotaCapability,
    role: capability.role,
    logicalBytes: 0,
    lastSequence: 0n,
    lastHash: b4a.from(ZERO32),
    sessions: new Map(),
    finished: false,
    burned: false,
    state
  })
  state.openRecoverySinks[capability.role] = sink
  return sink
}

export async function absorbForwardHttpsAggregateQuotaRecoveryFrameV3 (recoverySink, input) {
  closedObject(input, ['frame'], [], 'recovery frame input')
  const sink = recoverySink && QUOTA_SINKS.get(recoverySink)
  if (!sink || sink.finished || sink.burned) quotaFail('recovery sink is invalid', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  const frame = input.frame
  if (!frame || typeof frame !== 'object' || Array.isArray(frame) ||
      u64(frame.sequence, 'frame.sequence') !== sink.lastSequence + 1n ||
      !b4a.equals(bytes(frame.previousWalHash, 32, 'frame.previousWalHash'), sink.lastHash) ||
      safeUint(frame.frameBytes, 'frame.frameBytes') !== bytes(frame.payload, null, 'frame.payload').byteLength + WAL_FRAME_OVERHEAD_BYTES) {
    quotaFail('recovery frame is out-of-order, duplicate, torn or cross-root', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
  }
  // Mint the one-use recovery-sink claim bound to this ordinal, invoke derive
  // with it and burn it exactly once inside this call.
  const claim = mintQuotaClaim({
    kind: 'recovery',
    state: 'MINTED',
    role: sink.role,
    resolvePredecessor: stableSessionId => sink.sessions.get(b4a.toString(stableSessionId, 'hex')) || null
  })
  const derived = deriveForwardHttpsStoreWalQuotaEntryV3({
    role: sink.role,
    frame: {
      type: safeUint(frame.type, 'frame.type', 1, 255),
      payload: bytes(frame.payload, null, 'frame.payload'),
      payloadHash: bytes(frame.payloadHash, 32, 'frame.payloadHash'),
      sequence: u64(frame.sequence, 'frame.sequence'),
      frameBytes: safeUint(frame.frameBytes, 'frame.frameBytes'),
      walHash: bytes(frame.walHash, 32, 'frame.walHash')
    },
    transitionAuthority: claim
  })
  applyEntryToSessionMirror(sink.sessions, b4a.toString(derived.entry.stableSessionId === null ? ZERO32 : derived.entry.stableSessionId, 'hex'), derived.entry, frame.payload)
  // One charge-unit ledger model end to end: recovery seeds the exact derived
  // charge, the same units commits and adjustments move.
  sink.logicalBytes += derived.entry.ordinaryLogicalCharge + derived.entry.terminalLogicalCharge
  sink.lastSequence = u64(frame.sequence, 'frame.sequence')
  sink.lastHash = b4a.from(bytes(frame.walHash, 32, 'frame.walHash'))
  await quotaFault(sink.state, FORWARD_HTTPS_AGGREGATE_QUOTA_V3_FAULT_POINT.RECOVERY_AFTER_FRAME)
  return freezeResult({ entry: derived.entry })
}

export async function finishForwardHttpsAggregateQuotaRecoveryV3 (recoverySink) {
  const sink = recoverySink && QUOTA_SINKS.get(recoverySink)
  if (!sink || sink.finished || sink.burned) quotaFail('recovery sink is invalid', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  sink.finished = true
  sink.state.openRecoverySinks[sink.role] = null
  // Recovery is complete: merge the recovered canonical identity/vector state
  // into the quota authority so live claims bind exact predecessors, and
  // rebuild the role ledger authoritatively from the complete canonical WAL
  // in the one charge-unit model.
  for (const [key, mirror] of sink.sessions) sink.state.sessions.set(`${sink.role}:${key}`, mirror)
  sink.state.logical[sink.role] = sink.logicalBytes
  const finalState = Object.freeze({})
  QUOTA_RECOVERY_FINALS.set(finalState, {
    quotaAuthority: sink.quotaAuthority,
    role: sink.role,
    logicalBytes: sink.logicalBytes,
    walHeadSequence: sink.lastSequence,
    walHeadHash: b4a.from(sink.lastHash),
    sessionCount: sink.sessions.size,
    burned: false
  })
  await quotaFault(sink.state, FORWARD_HTTPS_AGGREGATE_QUOTA_V3_FAULT_POINT.RECOVERY_AFTER_FINISH)
  return finalState
}

export async function initializeForwardHttpsAggregateQuotaV3 (quotaAuthority, input) {
  const state = quotaState(quotaAuthority)
  closedObject(input, ['sourceRecoveryFinalState', 'targetRecoveryFinalState'], [], 'quota initialize input')
  if (state.initialized) quotaFail('quota is already initialized', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
  const source = input.sourceRecoveryFinalState && QUOTA_RECOVERY_FINALS.get(input.sourceRecoveryFinalState)
  const target = input.targetRecoveryFinalState && QUOTA_RECOVERY_FINALS.get(input.targetRecoveryFinalState)
  if (!source || !target || source.burned || target.burned || source.role !== 'SOURCE_STORE' || target.role !== 'TARGET_STORE' ||
      source.quotaAuthority !== quotaAuthority || target.quotaAuthority !== quotaAuthority) {
    quotaFail('quota recovery final states are invalid', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  }
  source.burned = target.burned = true
  state.logical.SOURCE_STORE = source.logicalBytes
  state.logical.TARGET_STORE = target.logicalBytes
  state.physical = await measurements(state)
  await quotaFault(state, FORWARD_HTTPS_AGGREGATE_QUOTA_V3_FAULT_POINT.INITIALIZE_AFTER_MEASURE)
  ensureQuota(state, null, 0, 0)
  state.initialized = true
}

function planFrom (capability, operation, logicalBytes, physicalBytes, commitments = [], protectedPlan = false, bindLogicalBytes = null, bindPhysicalBytes = null, stableSessionId = null) {
  const plan = Object.freeze({})
  QUOTA_PLANS.set(plan, {
    capability,
    operation,
    logicalBytes,
    physicalBytes,
    bindLogicalBytes: bindLogicalBytes === null ? logicalBytes : bindLogicalBytes,
    bindPhysicalBytes: bindPhysicalBytes === null ? physicalBytes : bindPhysicalBytes,
    commitments,
    protected: protectedPlan,
    stableSessionId,
    burned: false
  })
  return plan
}

function buffersArray (value, field, allowEmpty = true) {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0)) throw new TypeError(`${field} must be an array`)
  return value.map((item, index) => b4a.from(bytes(item, null, `${field}[${index}]`)))
}

export function createForwardHttpsReplayQuotaCostPlanV3 (replayQuotaCapability, input) {
  const capability = quotaCapabilityState(replayQuotaCapability)
  if (capability.role !== 'SOURCE_REPLAY' && capability.role !== 'TARGET_REPLAY') quotaFail('replay cost-plan role is invalid', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  closedObject(input, ['operation', 'encodedWriteBuffers', 'existingDestinationBytes', 'temporaryAndDestinationCanCoexist'], [], 'replay cost plan')
  if (!['BOOTSTRAP', 'RESERVE', 'CONSUME', 'QUARANTINE', 'PRUNE', 'CLOSE'].includes(input.operation)) throw new TypeError('replay operation is invalid')
  const encoded = buffersArray(input.encodedWriteBuffers, 'encodedWriteBuffers', false)
  const existing = safeUint(input.existingDestinationBytes, 'existingDestinationBytes')
  if (typeof input.temporaryAndDestinationCanCoexist !== 'boolean') throw new TypeError('temporaryAndDestinationCanCoexist must be boolean')
  const total = encoded.reduce((sum, item) => sum + item.byteLength, 0)
  return planFrom(replayQuotaCapability, input.operation, 0,
    total + (input.temporaryAndDestinationCanCoexist ? existing : 0), encoded.map(item => hmac(ZERO32, item)))
}

export function createForwardHttpsStoreQuotaCostPlanV3 (storeQuotaCapability, input) {
  const capability = quotaCapabilityState(storeQuotaCapability)
  if (capability.role !== 'SOURCE_STORE' && capability.role !== 'TARGET_STORE') quotaFail('store cost-plan role is invalid', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  closedObject(input, ['operation', 'knownInputBuffers', 'temporaryWriteBuffers', 'existingDestinationBytes'], [], 'store cost plan')
  const row = FORWARD_HTTPS_STORE_OPERATION_ROWS[input.operation]
  if (!row) throw new TypeError('store operation is invalid')
  // Inapplicable role/operation pair is INVALID before plan creation.
  if (row.roles !== 'BOTH' && row.roles !== capability.role) {
    quotaFail('operation is inapplicable for the capability role', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INVALID)
  }
  const known = buffersArray(input.knownInputBuffers, 'knownInputBuffers')
  const temporary = buffersArray(input.temporaryWriteBuffers, 'temporaryWriteBuffers')
  const existing = safeUint(input.existingDestinationBytes, 'existingDestinationBytes')
  const knownBytes = known.reduce((sum, item) => sum + item.byteLength, 0)
  const temporaryBytes = temporary.reduce((sum, item) => sum + item.byteLength, 0)
  if (knownBytes > row.knownInputMaximum) quotaFail('known input exceeds the operation row', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INVALID)
  let pruneNetLogical = null
  let pruneProtected = false
  if (input.operation === 'PRUNE') {
    // The exact already-encoded FPR9 is known before reserve; net admission is
    // exactly removal-then-736, never the conservative row maximum. Only
    // flags0 terminal-existing and terminal-only PRUNE (NONE_CONSUMED) use the
    // protected liability and never return CAPACITY; ordinary, flags1
    // orphan-abort and flags2 existing-session-abort are ordinary net
    // admission evaluated against the exact protected inequalities.
    if (known.length !== 1) throw new TypeError('PRUNE requires exactly one known tombstone buffer')
    const pruned = decodeForwardHttpsRetentionPrunedV3(known[0])
    const roleByteValue = capability.role === 'SOURCE_STORE' ? 1 : 2
    if (pruned.role !== roleByteValue) quotaFail('PRUNE tombstone role mismatch', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    pruneNetLogical = 736 - Number(pruned.removedOrdinaryLogicalBytes)
    pruneProtected = pruned.flags === 0 && pruned.allocationDisposition === 0
  }
  // Every number is the exact conservative admission ceiling of the frozen
  // operation row. Terminal append (608/416) and terminal prune are earmark
  // zero-sum and never return CAPACITY.
  const logical = pruneNetLogical === null ? row.logical : pruneNetLogical
  const physical = row.physical + temporaryBytes + existing
  const planSession = input.operation === 'PRUNE'
    ? (known.length === 1 ? b4a.from(known[0].subarray(8, 40)) : null)
    : (known.length > 0 && known[0].byteLength >= 36 && input.operation !== 'OPEN_RECOVERY' && input.operation !== 'QUARANTINE' ? b4a.from(known[0].subarray(4, 36)) : null)
  return planFrom(storeQuotaCapability, input.operation, logical, physical,
    [...known, ...temporary].map(item => hmac(ZERO32, item)), pruneProtected || input.operation === 'SESSION_TERMINAL',
    // Bind validates gross actual bytes against the exact tombstone frame
    // dimensions; admission uses the net removal-then-736 value, which may be
    // negative once the exact removal exceeds the tombstone charge.
    input.operation === 'PRUNE' ? 736 : null,
    input.operation === 'PRUNE' ? 480 + temporaryBytes + existing : null,
    planSession)
}

export function bindForwardHttpsStoreQuotaActualBuffersV3 (storeQuotaCapability, reservation, input) {
  const capability = quotaCapabilityState(storeQuotaCapability)
  const internal = reservation && QUOTA_RESERVATIONS.get(reservation)
  if (!internal || internal.burned || internal.capability !== storeQuotaCapability || capability.quotaAuthority !== internal.state.authority) {
    quotaFail('quota reservation is invalid', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  }
  closedObject(input, ['logicalRecordBuffers', 'encryptedPlaintextBuffers', 'finalWalMetadataBuffers', 'temporaryWriteBuffers'], [], 'actual buffer binding')
  if (internal.actual !== null) quotaFail('quota reservation is already bound', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
  const arrays = ['logicalRecordBuffers', 'encryptedPlaintextBuffers', 'finalWalMetadataBuffers', 'temporaryWriteBuffers']
    .flatMap(field => buffersArray(input[field], field))
  const logicalBytes = arrays.reduce((sum, item) => sum + item.byteLength, 0) + input.encryptedPlaintextBuffers.length * 218
  const physicalBytes = logicalBytes + input.encryptedPlaintextBuffers.length * 342 + 224
  if (logicalBytes > internal.plan.bindLogicalBytes || physicalBytes > internal.plan.bindPhysicalBytes) {
    quotaFail('actual buffers exceed the conservative plan', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
  }
  // One-time bind freezes the exact actual frame count/order: zero or more
  // type113 prefix frames (bound as encrypted plaintext records) followed by
  // exactly one operation final frame. Actual dimensions above the reserved
  // operation row are INTEGRITY.
  const row = FORWARD_HTTPS_STORE_WAL_QUOTA_FRAME_ROWS[internal.plan.operation]
  if (!row || row.finalTypes.length === 0) quotaFail('operation cannot bind WAL frames', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
  const type113Buffers = buffersArray(input.encryptedPlaintextBuffers, 'encryptedPlaintextBuffers')
  if (type113Buffers.length > row.type113) quotaFail('type113 frame count exceeds the operation row', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
  const finalBuffers = buffersArray(input.finalWalMetadataBuffers, 'finalWalMetadataBuffers')
  if (finalBuffers.length !== 1 || finalBuffers[0].byteLength < 36) quotaFail('exactly one operation final frame buffer is required', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
  for (const prefix of type113Buffers) if (prefix.byteLength !== 118) quotaFail('type113 frame payload must be exactly 118 bytes', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
  const finalPayload = finalBuffers[0]
  // The FTM9 and FPR9 headers place the session id at offset 8; ordinary
  // session payloads place it at offset 4.
  const stableSessionId = (internal.plan.operation === 'PRUNE' || internal.plan.operation === 'SESSION_TERMINAL')
    ? b4a.from(finalPayload.subarray(8, 40))
    : b4a.from(finalPayload.subarray(4, 36))
  if (b4a.equals(stableSessionId, ZERO32)) quotaFail('bound session identity must be nonzero', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
  if (internal.plan.operation === 'PRUNE') {
    // Per-variant clock eligibility and prefix class against the exact
    // recovered state: flags0 ordinary and terminal-existing wait the strict
    // +900 past the recorded recoveryGraceUntilEpoch (zero for unclocked
    // sessions, FTM9-carried for the terminal-only variant); flags1 requires
    // a FRESH recovered prefix; flags2 requires an EXISTING-session prefix.
    // flags1/flags2 prefix variants are the disjoint immediate exception.
    const pruned = decodeForwardHttpsRetentionPrunedV3(finalPayload)
    const mirror = internal.state.sessions.get(`${capability.role}:${b4a.toString(stableSessionId, 'hex')}`) || null
    if (pruned.flags === 0) {
      const grace = mirror ? (mirror.recoveryGraceUntilEpoch || 0) : 0
      if (pruned.pruneEpochSeconds <= grace) quotaFail('FPR9 prune epoch has not passed the exact recovery grace', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
      if (!mirror || !mirror.present) quotaFail('FPR9 tombstone has no recovered session state', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    } else {
      if (!mirror || (pruned.flags === 1 && mirror.prefix !== 'FRESH') || (pruned.flags === 2 && mirror.prefix !== 'EXISTING')) {
        quotaFail('FPR9 prefix variant does not match the recovered prefix class', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
      }
    }
  }
  internal.actual = { logicalBytes, physicalBytes, commitments: arrays.map(item => hmac(ZERO32, item)) }
  internal.totalFrames = 1 + type113Buffers.length
  internal.nextOrdinal = 0
  internal.lastHandoff = null
  internal.stableSessionId = stableSessionId
  // Mint the ordinal0 MINTED_UNBEGUN claim bound to the independently held
  // reservation, role, session, operation, exact total and the quota-private
  // canonical predecessor state. Returned exactly once.
  const state = internal.state
  const claim = mintQuotaClaim({
    kind: 'live',
    state: 'MINTED_UNBEGUN',
    role: capability.role,
    reservation,
    ordinal: 0,
    totalFrames: internal.totalFrames,
    stableSessionId,
    predecessorHead: null,
    resolvePredecessor: sessionId => state.sessions.get(`${capability.role}:${b4a.toString(sessionId, 'hex')}`) || null
  })
  internal.claims.add(claim)
  return Object.freeze({ transitionAuthority: claim })
}

// ---------------------------------------------------------------------------
// Composite per-frame operation (v17 transition_authority_lifecycle). The
// module-private begin step executes only inside this operation; no caller can
// begin, derive or present a handoff outside the atomic append+sync+derive.
// ---------------------------------------------------------------------------

// Module-private begin step: ordinal0 marks the reservation WAL_ATTEMPTED;
// ordinal>0 consumes the sole prior PENDING_DURABILITY handoff once.
function beginForwardHttpsAggregateQuotaWalAttemptV3 (internal, claimInternal) {
  if (claimInternal.ordinal === 0) {
    if (claimInternal.state !== 'MINTED_UNBEGUN') quotaFail('ordinal0 claim is not MINTED_UNBEGUN', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
    internal.walAttempted = true
    internal.mutated = true
  } else {
    if (claimInternal.state !== 'PENDING_DURABILITY' || internal.lastHandoff !== claimInternal.object) {
      quotaFail('ordinal handoff is not the sole prior PENDING_DURABILITY handoff', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
    }
    internal.lastHandoff = null
  }
  claimInternal.state = 'BEGUN'
}

function compositeReject (storeQuotaCapability, token, internal, message, code) {
  if (internal.walAttempted) {
    try { failForwardHttpsAggregateQuotaWalAttemptV3(storeQuotaCapability, token) } catch {}
  }
  quotaFail(message, code)
}

export async function applyForwardHttpsAggregateQuotaWalFrameV3 (storeQuotaCapability, token, claimOrHandoff, frame, appendSync) {
  const capability = quotaCapabilityState(storeQuotaCapability)
  const internal = token && QUOTA_RESERVATIONS.get(token)
  const claimInternal = claimOrHandoff && QUOTA_CLAIMS.get(claimOrHandoff)
  if (!internal || internal.burned || internal.capability !== storeQuotaCapability ||
      !claimInternal || claimInternal.burned || claimInternal.kind !== 'live' || claimInternal.reservation !== token ||
      claimInternal.role !== capability.role || !frame || typeof frame !== 'object' || Array.isArray(frame) ||
      typeof appendSync !== 'function') {
    quotaFail('composite apply presentation is forged', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  }
  if (claimInternal.ordinal !== internal.nextOrdinal || claimInternal.ordinal >= internal.totalFrames) {
    compositeReject(storeQuotaCapability, token, internal, 'composite apply ordinal is early, skipped, reordered or reused', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  }
  const row = FORWARD_HTTPS_STORE_WAL_QUOTA_FRAME_ROWS[internal.plan.operation]
  const frameType = safeUint(frame.type, 'frame.type', 1, 255)
  const prefixOrdinal = claimInternal.ordinal < internal.totalFrames - 1
  if ((prefixOrdinal && frameType !== 113) || (!prefixOrdinal && !row.finalTypes.includes(frameType))) {
    compositeReject(storeQuotaCapability, token, internal, 'composite apply frame type does not match the bound ordinal', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
  }
  try {
    beginForwardHttpsAggregateQuotaWalAttemptV3(internal, claimInternal)
    const payload = bytes(frame.payload, null, 'frame.payload')
    // Per-frame session binding: frames of a different session never share
    // this reservation (session-A prefix with session-B final rejects). The
    // FTM9/FPR9 headers place the session id at offset 8; ordinary session
    // payloads place it at offset 4.
    const frameSession = (frameType === 99 || frameType === 117 || frameType === 100 || frameType === 118)
      ? (payload.byteLength >= 40 ? payload.subarray(8, 40) : null)
      : (payload.byteLength >= 36 ? payload.subarray(4, 36) : null)
    if (frameSession === null || !b4a.equals(frameSession, claimInternal.stableSessionId)) {
      quotaFail('composite apply frame session does not match the bound reservation', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    }
    const durable = await appendSync(frame)
    if (!durable || typeof durable !== 'object') throw new TypeError('appendSync must return the durable frame')
    claimInternal.state = 'SYNCED'
    const derived = deriveForwardHttpsStoreWalQuotaEntryV3({
      role: capability.role,
      frame: {
        type: frameType,
        payload,
        payloadHash: bytes(durable.payloadHash, 32, 'durable.payloadHash'),
        sequence: u64(durable.sequence, 'durable.sequence'),
        frameBytes: payload.byteLength + WAL_FRAME_OVERHEAD_BYTES,
        walHash: bytes(durable.walHash, 32, 'durable.walHash')
      },
      transitionAuthority: claimOrHandoff
    })
    // PRUNE_TRANSITION mirror transitions land at adjust (the prune commit
    // point), never at frame durability: adjust independently matches the
    // tombstone against the exact pre-prune mirror first.
    if (derived.entry.scope !== 'PRUNE_TRANSITION') {
      applyEntryToSessionMirror(internal.state.sessions, `${capability.role}:${b4a.toString(derived.entry.stableSessionId === null ? ZERO32 : derived.entry.stableSessionId, 'hex')}`, derived.entry, payload)
    }
    internal.nextOrdinal++
    internal.lastHandoff = derived.transitionAuthorityHandoff
    internal.lastAppliedHead = { sequence: derived.entry.walSequence, hash: b4a.from(bytes(durable.walHash, 32, 'durable.walHash')) }
    internal.derivedLogical += derived.entry.ordinaryLogicalCharge + derived.entry.terminalLogicalCharge
    if (internal.lastHandoff !== null) internal.claims.add(internal.lastHandoff)
    return freezeResult({ entry: derived.entry, transitionAuthorityHandoff: derived.transitionAuthorityHandoff })
  } catch (error) {
    if (internal.walAttempted) {
      try { failForwardHttpsAggregateQuotaWalAttemptV3(storeQuotaCapability, token) } catch {}
    }
    throw error
  }
}

// Exact protected inequalities of liability_scope (v18): role logical
// current + planned + unconsumed*1344 + consumedUnpruned*736 <= perStore,
// role physical with *896 and *480, and the two aggregate analogues.
// Equality admits; any sum above the ceiling returns CAPACITY before WAL
// with no mutation. Only flags0 terminal-existing and terminal-only PRUNE
// (protected plans) are earmark zero-sum and never return CAPACITY.
function slotLiabilities (state) {
  const counts = {
    SOURCE_STORE: { unconsumed: 0, consumedUnpruned: 0 },
    TARGET_STORE: { unconsumed: 0, consumedUnpruned: 0 }
  }
  for (const [key, mirror] of state.sessions) {
    const role = key.startsWith('SOURCE_STORE:') ? 'SOURCE_STORE' : key.startsWith('TARGET_STORE:') ? 'TARGET_STORE' : null
    if (role === null || !mirror.present) continue
    if (mirror.consumed) { if (!mirror.pruned) counts[role].consumedUnpruned++ } else counts[role].unconsumed++
  }
  return counts
}

function ensureQuota (state, role, logicalIncrease, physicalIncrease, protectedPlan = false) {
  if (protectedPlan) return
  if (role !== 'SOURCE_STORE' && role !== 'TARGET_STORE') {
    // Replay roles keep the plain apparent-bytes ceilings.
    const aggregate = Object.values(state.physical).reduce((sum, item) => sum + item, 0) + physicalIncrease
    if (aggregate > state.aggregate) quotaFail('aggregate physical quota exhausted', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.CAPACITY)
    return
  }
  const counts = slotLiabilities(state)
  const perStore = BigInt(state.perStore)
  const aggregateCeiling = BigInt(state.aggregate)
  const plannedLogical = BigInt(logicalIncrease)
  const plannedPhysical = BigInt(physicalIncrease)
  const sourceLogical = BigInt(state.logical.SOURCE_STORE) + (role === 'SOURCE_STORE' ? plannedLogical : 0n)
  const targetLogical = BigInt(state.logical.TARGET_STORE) + (role === 'TARGET_STORE' ? plannedLogical : 0n)
  if (sourceLogical + BigInt(counts.SOURCE_STORE.unconsumed) * 1344n + BigInt(counts.SOURCE_STORE.consumedUnpruned) * 736n > perStore ||
      targetLogical + BigInt(counts.TARGET_STORE.unconsumed) * 1344n + BigInt(counts.TARGET_STORE.consumedUnpruned) * 736n > perStore) {
    quotaFail('protected role logical inequality violated', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.CAPACITY)
  }
  const sourcePhysical = BigInt(state.physical.SOURCE_STORE || 0) + (role === 'SOURCE_STORE' ? plannedPhysical : 0n) +
    BigInt(counts.SOURCE_STORE.unconsumed) * 896n + BigInt(counts.SOURCE_STORE.consumedUnpruned) * 480n
  const targetPhysical = BigInt(state.physical.TARGET_STORE || 0) + (role === 'TARGET_STORE' ? plannedPhysical : 0n) +
    BigInt(counts.TARGET_STORE.unconsumed) * 896n + BigInt(counts.TARGET_STORE.consumedUnpruned) * 480n
  if (sourcePhysical > perStore || targetPhysical > perStore) {
    quotaFail('protected role physical inequality violated', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.CAPACITY)
  }
  const aggregateLogical = BigInt(state.logical.SOURCE_STORE) + BigInt(state.logical.TARGET_STORE) + plannedLogical +
    BigInt(counts.SOURCE_STORE.unconsumed + counts.TARGET_STORE.unconsumed) * 1344n +
    BigInt(counts.SOURCE_STORE.consumedUnpruned + counts.TARGET_STORE.consumedUnpruned) * 736n
  if (aggregateLogical > aggregateCeiling) {
    quotaFail('protected aggregate logical inequality violated', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.CAPACITY)
  }
  const allRootsPhysical = Object.values(state.physical).reduce((sum, item) => sum + BigInt(item), 0n)
  const aggregatePhysical = allRootsPhysical + plannedPhysical +
    BigInt(counts.SOURCE_STORE.unconsumed + counts.TARGET_STORE.unconsumed) * 896n +
    BigInt(counts.SOURCE_STORE.consumedUnpruned + counts.TARGET_STORE.consumedUnpruned) * 480n
  if (aggregatePhysical > aggregateCeiling) {
    quotaFail('protected aggregate physical inequality violated', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.CAPACITY)
  }
}

export async function reserveForwardHttpsAggregateQuotaV3 (quotaCapability, costPlan) {
  let capability
  let plan
  try {
    capability = quotaCapabilityState(quotaCapability)
    plan = costPlan && QUOTA_PLANS.get(costPlan)
    if (!plan || plan.burned || plan.capability !== quotaCapability) quotaFail('quota cost plan is invalid', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
    plan.burned = true
  } catch (error) {
    return Promise.reject(error)
  }
  const state = quotaState(capability.quotaAuthority)
  // The aggregate FIFO op-lifecycle mutex: a successful reserve holds the
  // mutex through the whole operation; later submissions queue in exact
  // submission order.
  const opTicket = acquireOp(state)
  await opTicket.acquired
  try {
    state.physical = await measurements(state)
    await quotaFault(state, FORWARD_HTTPS_AGGREGATE_QUOTA_V3_FAULT_POINT.RESERVE_AFTER_MEASURE)
    ensureQuota(state, capability.role, plan.logicalBytes, plan.physicalBytes, plan.protected === true)
    // Reserve returns the exact frozen disposition union. The plan is burned
    // in every arm; a rejected ordinary plan in the entry-cap arm mints one
    // terminalReservation bound to the exact rejected operation/count and the
    // flags0 BUDGET_EXHAUSTED expectation.
    let disposition = 'ORDINARY'
    let terminal = null
    let terminalExpectation = null
    if (plan.operation === 'SESSION_TERMINAL') {
      disposition = 'REQUESTED_TERMINAL'
      terminal = 'REQUESTED'
    } else if (plan.stableSessionId !== null) {
      const mirror = state.sessions.get(`${capability.role}:${b4a.toString(plan.stableSessionId, 'hex')}`)
      const row = FORWARD_HTTPS_STORE_OPERATION_ROWS[plan.operation]
      if (mirror && mirror.present && !mirror.consumed && (mirror.chargeEntryCount || 0) + (row ? row.removable : 0) > 65536) {
        disposition = 'ENTRY_CAP_TERMINAL'
        terminal = 'ENTRY_CAP'
        terminalExpectation = Object.freeze({
          operation: 'SESSION_TERMINAL',
          flags: 0,
          reason: 'BUDGET_EXHAUSTED',
          stableSessionId: b4a.from(plan.stableSessionId),
          rejectedOperation: plan.operation,
          rejectedChargeEntryCount: mirror.chargeEntryCount || 0,
          plannedRemovableCount: row.removable
        })
      }
    }
    state.pendingReservation = true
    const reservation = Object.freeze({})
    QUOTA_RESERVATIONS.set(reservation, { state, capability: quotaCapability, plan, actual: null, burned: false, mutated: false, walAttempted: false, totalFrames: 0, nextOrdinal: 0, lastHandoff: null, claims: new Set(), stableSessionId: null, terminal, terminalExpectation, lastAppliedHead: null, derivedLogical: 0, opRelease: opTicket.release })
    state.pendingReservationObject = reservation
    if (disposition === 'ORDINARY') return Object.freeze({ disposition, reservation })
    return Object.freeze({ disposition, terminalReservation: reservation })
  } catch (error) {
    state.pendingReservation = false
    state.pendingReservationObject = null
    opTicket.release()
    throw error
  }
}

export async function commitForwardHttpsAggregateQuotaV3 (quotaCapability, reservation, input) {
  let capability
  let internal
  try {
    capability = quotaCapabilityState(quotaCapability)
    internal = reservation && QUOTA_RESERVATIONS.get(reservation)
    if (!internal || internal.burned || internal.capability !== quotaCapability) quotaFail('quota reservation is invalid', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
    closedObject(input, ['durableWalHeadSequence', 'durableWalHeadHash'], [], 'quota commit')
    u64(input.durableWalHeadSequence, 'durableWalHeadSequence')
    bytes(input.durableWalHeadHash, 32, 'durableWalHeadHash')
  } catch (error) {
    return Promise.reject(error)
  }
  const state = quotaState(capability.quotaAuthority)
  try {
    if (internal.plan.operation === 'PRUNE') quotaFail('commit is forbidden for PRUNE; use adjust', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    // Commit is legal only after the final composite apply, the final derive
    // and with no remaining live claim or outstanding handoff.
    if (internal.actual !== null && (internal.nextOrdinal !== internal.totalFrames || internal.lastHandoff !== null)) {
      quotaFail('quota commit has a remaining claim or outstanding handoff', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    }
    // Exact durable head equality: a fabricated head rejects without mutation.
    if (internal.lastAppliedHead !== null &&
        (u64(input.durableWalHeadSequence, 'durableWalHeadSequence') !== internal.lastAppliedHead.sequence ||
         !b4a.equals(bytes(input.durableWalHeadHash, 32, 'durableWalHeadHash'), internal.lastAppliedHead.hash))) {
      quotaFail('quota commit durable head is not the exact applied head', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    }
    internal.burned = true
    // Commit applies the exact derived logical of the operation's closed
    // entries (never the caller's bind-actual estimate).
    const cost = internal.actual !== null ? { logicalBytes: internal.derivedLogical } : internal.plan
    if (capability.role === 'SOURCE_STORE' || capability.role === 'TARGET_STORE') state.logical[capability.role] += cost.logicalBytes
    state.physical = await measurements(state)
    await quotaFault(state, FORWARD_HTTPS_AGGREGATE_QUOTA_V3_FAULT_POINT.COMMIT_AFTER_MEASURE)
    ensureQuota(state, null, 0, 0)
    state.pendingReservation = false
    state.pendingReservationObject = null
    releaseOpFor(internal)
  } catch (error) {
    if (internal.walAttempted) {
      try { failForwardHttpsAggregateQuotaWalAttemptV3(quotaCapability, reservation) } catch {}
    }
    state.pendingReservation = false
    state.pendingReservationObject = null
    releaseOpFor(internal)
    throw error
  }
}

export async function releaseForwardHttpsAggregateQuotaV3 (quotaCapability, reservation) {
  let capability
  let internal
  try {
    capability = quotaCapabilityState(quotaCapability)
    internal = reservation && QUOTA_RESERVATIONS.get(reservation)
    if (!internal || internal.burned || internal.capability !== quotaCapability) quotaFail('quota reservation is invalid', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  } catch (error) {
    return Promise.reject(error)
  }
  const state = quotaState(capability.quotaAuthority)
  try {
    // Release is forbidden after the first WAL attempt; pre-first-apply
    // release burns the reservation and every minted/unissued claim. A
    // terminal reservation aborted before the first begin is the terminal
    // prewrite abort: quota transitions FAILED_PREWRITE, claims burn, the
    // role bytes stay unchanged and the caller receives INTEGRITY.
    if (internal.walAttempted) quotaFail('release is forbidden after the first WAL attempt', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    await quotaFault(state, FORWARD_HTTPS_AGGREGATE_QUOTA_V3_FAULT_POINT.RELEASE_BEFORE_UNLOCK)
    internal.burned = true
    for (const claim of internal.claims) {
      const claimInternal = QUOTA_CLAIMS.get(claim)
      if (claimInternal) { claimInternal.burned = true; claimInternal.state = 'BURNED' }
    }
    state.pendingReservation = false
    state.pendingReservationObject = null
    releaseOpFor(internal)
    if (internal.plan.operation === 'SESSION_TERMINAL' || internal.terminal !== null) {
      state.failed = true
      state.failureState = 'FAILED_PREWRITE'
      state.blocker = FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY
      quotaFail('terminal prewrite abort; FAILED_PREWRITE', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    }
  } catch (error) {
    if (!internal.burned) {
      state.pendingReservation = false
      state.pendingReservationObject = null
      releaseOpFor(internal)
    }
    throw error
  }
}

export async function adjustForwardHttpsAggregateQuotaV3 (storeQuotaCapability, input) {
  let capability
  let internal
  try {
    capability = quotaCapabilityState(storeQuotaCapability)
    if (capability.role !== 'SOURCE_STORE' && capability.role !== 'TARGET_STORE') quotaFail('adjust role is invalid', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
    closedObject(input, ['durableTombstonePayloadBuffer', 'durableWalHeadSequence', 'durableWalHeadHash'], [], 'quota adjustment')
  } catch (error) {
    return Promise.reject(error)
  }
  const state = quotaState(capability.quotaAuthority)
  let pending = null
  try {
    // PRUNE adjust is the only adjust path: it requires the exact pending
    // bound PRUNE reservation, revalidates the tombstone and applies
    // logical = current - provenRemoval + 736 atomically.
    pending = state.pendingReservationObject
    internal = pending ? QUOTA_RESERVATIONS.get(pending) : null
    if (!internal || internal.burned || internal.capability !== storeQuotaCapability || internal.plan.operation !== 'PRUNE') {
      quotaFail('quota adjustment has no pending PRUNE reservation', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
    }
    // Adjust follows the complete final composite apply of the FPR9 frame:
    // exact final derive, no remaining claim, no outstanding handoff, and the
    // exact durable head of the tombstone frame.
    if (internal.actual === null || internal.nextOrdinal !== internal.totalFrames || internal.lastHandoff !== null) {
      quotaFail('quota adjustment has a remaining claim or outstanding handoff', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    }
    if (internal.lastAppliedHead !== null &&
        (u64(input.durableWalHeadSequence, 'durableWalHeadSequence') !== internal.lastAppliedHead.sequence ||
         !b4a.equals(bytes(input.durableWalHeadHash, 32, 'durableWalHeadHash'), internal.lastAppliedHead.hash))) {
      quotaFail('quota adjustment durable head is not the exact applied head', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    }
    const tombstone = bytes(input.durableTombstonePayloadBuffer, null, 'durableTombstonePayloadBuffer')
    const commitment = hmac(ZERO32, tombstone)
    if (!internal.plan.commitments.some(expected => timingSafeEqual(expected, commitment))) {
      quotaFail('quota adjustment tombstone commitment mismatch', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    }
    const pruned = decodeForwardHttpsRetentionPrunedV3(tombstone)
    const roleByteValue = capability.role === 'SOURCE_STORE' ? 1 : 2
    if (pruned.role !== roleByteValue) quotaFail('quota adjustment tombstone role mismatch', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    // Independent quota match: the tombstone is recomputed against the exact
    // pre-prune recovered mirror — count, sum, revision, vector and slot —
    // before any mutation. A tampered count or commitment is INTEGRITY.
    const mirrorKey = `${capability.role}:${b4a.toString(pruned.stableSessionId, 'hex')}`
    const mirror = state.sessions.get(mirrorKey) || null
    if (!mirror || mirror.present !== true) quotaFail('quota adjustment has no recovered session state', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    if (pruned.flags === 0 && pruned.priorSessionRevision !== mirror.priorRevision) quotaFail('quota adjustment revision mismatch', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    if (pruned.beforeAuthorityBitmap !== mirror.bitmap) quotaFail('quota adjustment vector mismatch', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    const mirrorCommitments = mirror.commitments || Array.from({ length: AUTHORITY_CLASS_COUNT }, () => b4a.from(ZERO32))
    const expectedAuthority = authorityRegistryCommitment(roleByteValue, pruned.stableSessionId, pruned.priorSessionRevision, pruned.beforeAuthorityBitmap, mirrorCommitments)
    if (!b4a.equals(pruned.authorityRegistryCommitment, expectedAuthority)) quotaFail('quota adjustment authority commitment mismatch', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    if (pruned.flags === 0 &&
        (pruned.chargeEntryCount !== (mirror.chargeEntryCount || 0) || pruned.removedOrdinaryLogicalBytes !== (mirror.chargeSum || 0n))) {
      quotaFail('quota adjustment count/sum mismatch', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    }
    if (pruned.flags !== 0 &&
        (pruned.priorSessionRevision !== (mirror.orphanLastRevision || 0n) || pruned.chargeEntryCount !== (mirror.orphanCount || 0) || pruned.removedOrdinaryLogicalBytes !== (mirror.orphanSum || 0n))) {
      quotaFail('quota adjustment orphan count/sum/revision mismatch', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    }
    if (pruned.flags === 0 && ((pruned.allocationDisposition === 1 && mirror.consumed) || (pruned.allocationDisposition === 0 && !mirror.consumed))) {
      quotaFail('quota adjustment slot state mismatch', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    }
    if (pruned.flags === 1 && mirror.prefix !== 'FRESH') quotaFail('quota adjustment prefix class mismatch', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    if (pruned.flags === 2 && mirror.prefix !== 'EXISTING') quotaFail('quota adjustment prefix class mismatch', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    // Matched: apply the exact prune transition to the canonical mirror.
    applyEntryToSessionMirror(state.sessions, mirrorKey, { scope: 'PRUNE_TRANSITION', stableSessionId: pruned.stableSessionId, walType: roleByteValue === 1 ? 100 : 118, authorityBitmap: 0, ordinaryLogicalCharge: 0, terminalLogicalCharge: 0 }, tombstone)
    const removed = pruned.removedOrdinaryLogicalBytes
    const current = BigInt(state.logical[capability.role])
    // Net removal-then-736 in one charge-unit model: the ledger counts the
    // exact derived charge through recovery seeds and commits, so current
    // never underflows a proven removal.
    const next = current - removed + 736n
    if (next < 0n) quotaFail('quota adjustment removal exceeds the exact ledger', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    state.logical[capability.role] = Number(next)
    state.physical = await measurements(state)
    await quotaFault(state, FORWARD_HTTPS_AGGREGATE_QUOTA_V3_FAULT_POINT.ADJUST_AFTER_MEASURE)
    internal.burned = true
    state.pendingReservation = false
    state.pendingReservationObject = null
    releaseOpFor(internal)
  } catch (error) {
    if (internal && internal.walAttempted) {
      try { failForwardHttpsAggregateQuotaWalAttemptV3(storeQuotaCapability, pending) } catch {}
    }
    state.pendingReservation = false
    state.pendingReservationObject = null
    releaseOpFor(internal)
    throw error
  }
}

export function forwardHttpsAggregateQuotaV3Status (quotaAuthority) {
  // Status is an exact-authority exception to the operational gate: it remains
  // callable in FAILED_PREWRITE, FAILED_WAL_OUTCOME_UNKNOWN_PENDING, CLOSING
  // and CLOSED.
  const state = quotaAuthority && QUOTA_AUTHORITIES.get(quotaAuthority)
  if (!state || state.authority !== quotaAuthority) quotaFail('quota authority is forged', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  const physical = state.physical
  return deepFreeze({
    state: state.closed ? 'CLOSED' : state.failed ? (state.failureState || 'FAILED') : state.closing ? 'CLOSING' : state.initialized ? 'OPEN' : 'UNINITIALIZED',
    sourceLogicalChargedBytes: state.logical.SOURCE_STORE,
    targetLogicalChargedBytes: state.logical.TARGET_STORE,
    aggregateLogicalChargedBytes: state.logical.SOURCE_STORE + state.logical.TARGET_STORE,
    sourceReplayPhysicalApparentBytes: physical.SOURCE_REPLAY || 0,
    targetReplayPhysicalApparentBytes: physical.TARGET_REPLAY || 0,
    sourceStorePhysicalApparentBytes: physical.SOURCE_STORE || 0,
    targetStorePhysicalApparentBytes: physical.TARGET_STORE || 0,
    aggregatePhysicalApparentBytes: Object.values(physical).reduce((sum, item) => sum + item, 0),
    perStoreQuotaBytes: state.perStore,
    aggregateQuotaBytes: state.aggregate,
    pendingReservation: state.pendingReservation,
    localOperational: state.initialized && !state.failed,
    blocker: state.blocker
  })
}

export async function closeForwardHttpsAggregateQuotaV3 (quotaAuthority) {
  const state = quotaAuthority && QUOTA_AUTHORITIES.get(quotaAuthority)
  if (!state || state.authority !== quotaAuthority) quotaFail('quota authority is forged', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  if (state.closed) return
  // An ordinary pending reservation before begin-WAL: close returns INTEGRITY
  // and leaves the owning operation responsible for ordinary release.
  if (state.pendingReservation && !state.failed) quotaFail('quota close has a pending ordinary reservation', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
  state.closing = true
  await serialize(state, async () => {
    await quotaFault(state, FORWARD_HTTPS_AGGREGATE_QUOTA_V3_FAULT_POINT.CLOSE_BEFORE_INVALIDATE)
    for (const capability of state.capabilityInternals) capability.burned = true
    state.closed = true
  })
}

// Universal operational gate (adopted v13): succeeds only for an exact OPEN
// localOperational quota authority bound to the role/root; FAILED_PREWRITE,
// FAILED_WAL_OUTCOME_UNKNOWN_PENDING, CLOSING or CLOSED return exact INTEGRITY
// with no token burn and no role mutation.
export function assertForwardHttpsAggregateQuotaOperationalV3 (storeQuotaCapability) {
  const capability = storeQuotaCapability && QUOTA_CAPABILITIES.get(storeQuotaCapability)
  if (!capability || capability.burned) quotaFail('quota capability is forged', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  const state = capability.quotaAuthority && QUOTA_AUTHORITIES.get(capability.quotaAuthority)
  if (!state || state.authority !== capability.quotaAuthority) quotaFail('quota authority is forged', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  if (state.closed || state.closing || state.failed || !state.initialized) {
    quotaFail('quota authority is not operational', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
  }
}

// fail-WAL control (v16 aggregate_quota_failure_state_machine): every catch
// from first append through remeasure transitions atomically to
// FAILED_WAL_OUTCOME_UNKNOWN_PENDING, invalidates transition claims, retains
// the operation token, sets blocker INTEGRITY and rejects all later work.
export function failForwardHttpsAggregateQuotaWalAttemptV3 (storeQuotaCapability, token) {
  const capability = quotaCapabilityState(storeQuotaCapability)
  if (capability.role !== 'SOURCE_STORE' && capability.role !== 'TARGET_STORE') quotaFail('fail-WAL role is invalid', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  const state = quotaState(capability.quotaAuthority)
  if (token !== undefined && token !== null && token !== state.pendingReservationObject) {
    quotaFail('fail-WAL token is not the retained operation token', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  }
  state.failed = true
  state.failureState = 'FAILED_WAL_OUTCOME_UNKNOWN_PENDING'
  state.blocker = FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY
  // Wake queued waiters; every later admission rejects against the failed
  // authority. The token is retained for close-only teardown.
  releaseOpFor(state.pendingReservationObject ? QUOTA_RESERVATIONS.get(state.pendingReservationObject) : null)
}

function normalizeTestLimits (limits) {
  if (limits == null) return null
  const keys = ['replayCapacityPerRole', 'maximumLiveSessionsPerRole', 'maximumTurnsPerSession', 'maximumRetainedTurnsPerRole', 'maximumDurableBytesPerStore', 'maximumForwardStorageBytesAggregate', 'transportBudgetBytesPerSession', 'maximumProcessorRequestBytes', 'maximumProcessorOutcomeBytes', 'maximumResponderStateBytes', 'callbackTimeoutMillis']
  closedObject(limits, keys, [], 'limits')
  for (const key of keys) safeUint(limits[key], `limits.${key}`, 1)
  if (limits.replayCapacityPerRole > 4096 || limits.maximumTurnsPerSession > 512 || limits.maximumTurnsPerSession < 459 ||
      limits.transportBudgetBytesPerSession !== limits.maximumTurnsPerSession * 131072 ||
      limits.maximumDurableBytesPerStore > 8589934592 || limits.maximumForwardStorageBytesAggregate > 17179869184 ||
      limits.maximumProcessorRequestBytes > 4194304 || limits.maximumProcessorOutcomeBytes > 4194304 ||
      limits.maximumResponderStateBytes > 65536 || limits.callbackTimeoutMillis > 15000) {
    throw new TypeError('limits exceed production or cannot reserve the complete 459-turn flow')
  }
  return limits
}

async function fileSizeOrZero (file) {
  try {
    return (await fs.lstat(file)).size
  } catch (error) {
    if (error.code === 'ENOENT') return 0
    throw error
  }
}

// FORWARD HTTPS durability store WAL registry v3 (module-private, deep-frozen).
// This table is reachable only through the closed derive/codec functions below.
// It is never exported and is not source-hash or object-shape authority.
const WAL_FRAME_OVERHEAD_BYTES = 224
const FTM9_PAYLOAD_BYTES = 192
const FTM9_LOGICAL_BYTES = 608
const FPR9_PAYLOAD_BYTES = 256
const FPR9_LOGICAL_BYTES = 736
const TYPE113_LOGICAL_BYTES = 460
const MAXIMUM_WAL_PAYLOAD_BYTES = 16777216
const RECOVERY_GRACE_SECONDS = 900
const U32_MAX = 4294967295
const EXPIRY_HORIZON = U32_MAX - 901 // 4294966394

// 14-type private registry. class: SESSION | SESSION_EMERGENCY | PRUNE_TRANSITION | ROLE_GLOBAL
const FORWARD_HTTPS_STORE_WAL_QUOTA_REGISTRY_V3 = deepFreeze({
  96: { role: 1, name: 'PREPARED_NEW', class: 'SESSION' },
  97: { role: 1, name: 'TRANSPORT_RESERVED', class: 'SESSION' },
  98: { role: 1, name: 'RESULT_PERSISTED', class: 'SESSION' },
  99: { role: 1, name: 'SESSION_TERMINAL', class: 'SESSION_EMERGENCY' },
  100: { role: 1, name: 'RETENTION_PRUNED', class: 'PRUNE_TRANSITION' },
  101: { role: 1, name: 'QUARANTINED', class: 'ROLE_GLOBAL' },
  112: { role: 2, name: 'TURN_FINAL', class: 'SESSION' },
  113: { role: 2, name: 'TRANSPORT_RESERVED', class: 'SESSION' },
  114: { role: 2, name: 'PROCESSOR_PREPARED', class: 'SESSION' },
  115: { role: 2, name: 'PROCESSOR_REQUEST_READY', class: 'SESSION' },
  116: { role: 2, name: 'PROCESSOR_COMPLETED', class: 'SESSION' },
  117: { role: 2, name: 'SESSION_TERMINAL', class: 'SESSION_EMERGENCY' },
  118: { role: 2, name: 'RETENTION_PRUNED', class: 'PRUNE_TRANSITION' },
  119: { role: 2, name: 'QUARANTINED', class: 'ROLE_GLOBAL' }
})

const AUTHORITY_CLASS_COUNT = 10
const MINIMAL_TERMINAL_BITMAP = (1 << 7) | (1 << 9) // 640

const DOMAIN_CHARGE_REGISTRY_INIT = b4a.from('hiverelay.blind.forward-https-quota-charge-registry-init.v4', 'ascii')
const DOMAIN_CHARGE_REGISTRY_STEP = b4a.from('hiverelay.blind.forward-https-quota-charge-registry-step.v4', 'ascii')
const DOMAIN_CHARGE_REGISTRY_FINAL = b4a.from('hiverelay.blind.forward-https-quota-charge-registry-final.v4', 'ascii')
const DOMAIN_AUTHORITY_REGISTRY = b4a.from('hiverelay.blind.forward-https-authority-registry.v3', 'ascii')
const DOMAIN_PRUNE_SESSION_STATE = b4a.from('hiverelay.blind.forward-https-prune-session-state.v3', 'ascii')
const DOMAIN_PREFIX_SESSION_STATE = b4a.from('hiverelay.blind.forward-https-prefix-session-state.v3', 'ascii')
const DOMAIN_MINIMAL_TERMINAL = b4a.from('hiverelay.blind.forward-https-minimal-terminal-authority.v3', 'ascii')
const DOMAIN_RETENTION_LOOKUP = b4a.from('hiverelay.blind.forward-https-retention-lookup.v3', 'ascii')
const DOMAIN_TERMINAL_STATE = b4a.from('hiverelay.blind.forward-https-terminal-state.v3', 'ascii')
const DOMAIN_TERMINAL_STATE_EXISTING = b4a.from('hiverelay.blind.forward-https-terminal-state-existing.v3', 'ascii')

// Exact operation rows of the v18 complete_operation_bound_table: the
// conservative admission ceilings, the planned removable charge-entry count
// (type113 count plus the ordinary final SESSION indicator) and the known
// input maximum. Every number is the exact frozen ceiling.
const FORWARD_HTTPS_STORE_OPERATION_ROWS = deepFreeze({
  OPEN_RECOVERY: { roles: 'BOTH', logical: 0, physical: 0, removable: 0, knownInputMaximum: 16777440 },
  PREPARE: { roles: 'SOURCE_STORE', logical: 33554656, physical: 16777440, removable: 1, knownInputMaximum: 16777216 },
  RESULT: { roles: 'SOURCE_STORE', logical: 33554656, physical: 16777440, removable: 1, knownInputMaximum: 16777216 },
  TURN_FINAL: { roles: 'TARGET_STORE', logical: 33555116, physical: 16777782, removable: 2, knownInputMaximum: 16777216 },
  PROCESSOR_REQUEST_READY: { roles: 'TARGET_STORE', logical: 2362286, physical: 1181591, removable: 4, knownInputMaximum: 16777216 },
  PROCESSOR_PREPARED: { roles: 'TARGET_STORE', logical: 33554656, physical: 16777440, removable: 1, knownInputMaximum: 16777216 },
  PROCESSOR_COMPLETED: { roles: 'TARGET_STORE', logical: 4683994, physical: 2344461, removable: 22, knownInputMaximum: 16777216 },
  SESSION_TERMINAL: { roles: 'BOTH', logical: 608, physical: 416, removable: 0, knownInputMaximum: 65976 },
  QUARANTINE: { roles: 'BOTH', logical: 33554656, physical: 16777440, removable: 0, knownInputMaximum: 16777216 },
  PRUNE: { roles: 'BOTH', logical: 736, physical: 480, removable: 0, knownInputMaximum: 256 }
})

// Exact actual frame order per operation row: zero or more type113 prefix
// frames followed by exactly one operation final frame (v18 bound table).
const FORWARD_HTTPS_STORE_WAL_QUOTA_FRAME_ROWS = deepFreeze({
  OPEN_RECOVERY: { type113: 0, finalTypes: [] },
  PREPARE: { type113: 0, finalTypes: [96, 97] },
  RESULT: { type113: 0, finalTypes: [98] },
  TURN_FINAL: { type113: 1, finalTypes: [112] },
  PROCESSOR_REQUEST_READY: { type113: 3, finalTypes: [115] },
  PROCESSOR_PREPARED: { type113: 0, finalTypes: [114] },
  PROCESSOR_COMPLETED: { type113: 21, finalTypes: [116] },
  SESSION_TERMINAL: { type113: 0, finalTypes: [99, 117] },
  QUARANTINE: { type113: 0, finalTypes: [101, 119] },
  PRUNE: { type113: 0, finalTypes: [100, 118] }
})

function storeWalFail (message) {
  throw new ForwardHttpsAggregateQuotaV3Error(message, FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
}

// Closed frozen output that never freezes ArrayBuffer views (Node forbids
// freezing typed arrays with elements); byte leaves are already copies.
function freezeResult (value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value) && !ArrayBuffer.isView(value)) {
    for (const item of Object.values(value)) freezeResult(item)
    Object.freeze(value)
  }
  return value
}

function quotaRoleByte (role) {
  if (role === FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3.SOURCE_STORE) return 1
  if (role === FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3.TARGET_STORE) return 2
  throw new TypeError('role must be SOURCE_STORE or TARGET_STORE')
}

function u8 (value, field, minimum = 0, maximum = 255) {
  return safeUint(value, field, minimum, maximum)
}

function writeU16 (output, offset, value) {
  output.writeUInt16BE(value, offset)
  return offset + 2
}

function readU16 (input, offset) {
  return input.readUInt16BE(offset)
}

// ---------------------------------------------------------------------------
// FTM9 ForwardHttpsSessionTerminalV3 (private decode; encode lives with the
// storage authority module that constructs terminal deltas)
// ---------------------------------------------------------------------------

function decodeFtm9Payload (payload, expectedWalType) {
  if (payload.byteLength !== FTM9_PAYLOAD_BYTES) storeWalFail('FTM9 payload length is invalid')
  if (b4a.toString(payload.subarray(0, 4), 'ascii') !== 'FTM9') storeWalFail('FTM9 magic is invalid')
  if (payload[4] !== 1) storeWalFail('FTM9 version is invalid')
  const role = payload[5]
  const flags = readU16(payload, 6)
  if ((role === 1 && expectedWalType !== 99) || (role === 2 && expectedWalType !== 117) || (role !== 1 && role !== 2)) {
    storeWalFail('FTM9 role/type binding is invalid')
  }
  if (flags !== 0 && flags !== 1) storeWalFail('FTM9 flags are invalid')
  const stableSessionId = b4a.from(payload.subarray(8, 40))
  const sequence = readU64(payload, 40)
  const buckets = []
  let offset = 48
  for (let index = 0; index < 5; index++) { buckets.push(readU16(payload, offset)); offset += 2 }
  const transportTurnsSpent = readU16(payload, offset); offset += 2
  const transportBytesSpent = payload.readUInt32BE(offset); offset += 4
  const priorSessionRevision = readU64(payload, offset); offset += 8
  const newTrustedEpochHighWatermark = payload.readUInt32BE(offset); offset += 4
  const reasonLength = payload[offset++]
  if (reasonLength < 1 || reasonLength > 64) storeWalFail('FTM9 reason length is invalid')
  const reasonAscii = b4a.from(payload.subarray(offset, offset + 64))
  const reason = b4a.from(reasonAscii.subarray(0, reasonLength))
  for (let index = reasonLength; index < 64; index++) if (reasonAscii[index] !== 0) storeWalFail('FTM9 reason padding is invalid')
  offset += 64
  const tail = payload.subarray(offset, offset + 51)
  let expiresAtEpoch = 0
  let retainedUntilEpoch = 0
  let minimalTerminalAuthorityCommitment = null
  if (flags === 0) {
    if (priorSessionRevision === 0n) storeWalFail('FTM9 existing delta requires nonzero prior revision')
    for (const byte of tail) if (byte !== 0) storeWalFail('FTM9 existing delta tail is invalid')
  } else {
    if (priorSessionRevision !== 0n) storeWalFail('FTM9 minimal terminal requires zero prior revision')
    if (sequence === 0n) storeWalFail('FTM9 minimal terminal requires nonzero sequence')
    const exactReason = role === 1
      ? 'FORWARD_HTTPS_SOURCE_STORE_V3_SEQUENCE_INVALID'
      : 'FORWARD_HTTPS_TARGET_STORE_V3_SEQUENCE_INVALID'
    if (b4a.toString(reason, 'ascii') !== exactReason) storeWalFail('FTM9 minimal terminal reason is invalid')
    for (const value of [...buckets, transportTurnsSpent, transportBytesSpent]) if (value !== 0) storeWalFail('FTM9 minimal terminal counters are invalid')
    expiresAtEpoch = tail.readUInt32BE(0)
    retainedUntilEpoch = tail.readUInt32BE(4)
    if (expiresAtEpoch > EXPIRY_HORIZON) storeWalFail('FTM9 expiry horizon is invalid')
    if (retainedUntilEpoch !== expiresAtEpoch + RECOVERY_GRACE_SECONDS) storeWalFail('FTM9 retainedUntil is invalid')
    // The tail carries the exact request commitment; M is recomputed from
    // the complete payload, never stored or trusted as an input.
    const exactRequestCommitment = b4a.from(tail.subarray(8, 40))
    if (b4a.equals(exactRequestCommitment, ZERO32)) storeWalFail('FTM9 request commitment is invalid')
    for (let index = 40; index < 51; index++) if (tail[index] !== 0) storeWalFail('FTM9 minimal tail padding is invalid')
    const sequenceBytes = b4a.alloc(8)
    writeU64(sequenceBytes, 0, sequence)
    const scalars = b4a.alloc(13)
    scalars.writeUInt32BE(expiresAtEpoch, 0)
    scalars.writeUInt32BE(retainedUntilEpoch, 4)
    scalars.writeUInt32BE(newTrustedEpochHighWatermark, 8)
    scalars[12] = reasonLength
    minimalTerminalAuthorityCommitment = blake2b256(b4a.concat([
      DOMAIN_MINIMAL_TERMINAL, b4a.from([role]), stableSessionId, sequenceBytes, exactRequestCommitment, scalars, reason
    ]))
  }
  return freezeResult({
    role,
    flags,
    stableSessionId,
    sequence,
    buckets: Object.freeze(buckets),
    transportTurnsSpent,
    transportBytesSpent,
    priorSessionRevision,
    newTrustedEpochHighWatermark,
    reason,
    expiresAtEpoch,
    retainedUntilEpoch,
    minimalTerminalAuthorityCommitment
  })
}

// ---------------------------------------------------------------------------
// FPR9 ForwardHttpsRetentionPrunedV3 (exported codec)
// ---------------------------------------------------------------------------

// Adopted V13 streaming charge-registry commitment. E0 over the init domain,
// one step per exact49-byte entry in WAL order, final over count, exact
// removed sum and the chain. O(1) working memory; no raw entry buffering.
function chargeRegistryCommitment (roleByteValue, stableSessionId, chargeEntryCount, removedOrdinaryLogicalBytes, walOrderedEntryBuffers) {
  let chain = blake2b256(b4a.concat([DOMAIN_CHARGE_REGISTRY_INIT, b4a.from([roleByteValue]), stableSessionId]))
  for (const entry of walOrderedEntryBuffers) chain = blake2b256(b4a.concat([DOMAIN_CHARGE_REGISTRY_STEP, chain, entry]))
  const count = b4a.alloc(4)
  count.writeUInt32BE(chargeEntryCount, 0)
  const removed = b4a.alloc(8)
  writeU64(removed, 0, removedOrdinaryLogicalBytes)
  return blake2b256(b4a.concat([DOMAIN_CHARGE_REGISTRY_FINAL, b4a.from([roleByteValue]), stableSessionId, count, removed, chain]))
}

function authorityRegistryCommitment (roleByteValue, stableSessionId, priorSessionRevision, beforeAuthorityBitmap, commitments) {
  const revision = b4a.alloc(8)
  writeU64(revision, 0, priorSessionRevision)
  const bitmap = b4a.alloc(4)
  bitmap.writeUInt32BE(beforeAuthorityBitmap, 0)
  return blake2b256(b4a.concat([DOMAIN_AUTHORITY_REGISTRY, b4a.from([roleByteValue]), stableSessionId, revision, bitmap, ...commitments]))
}

// flags0 uses the prune-session-state.v3 domain; the flags1/flags2 prefix
// variants use the unique prefix-session-state.v3 domain with the identical
// typed field order. flags is the exact u16be variant scalar in both.
function previousSessionStateCommitment (flags, roleByteValue, stableSessionId, priorSessionRevision, chargeCommitment, authorityCommitment, terminalSlotState) {
  const domain = flags === 0 ? DOMAIN_PRUNE_SESSION_STATE : DOMAIN_PREFIX_SESSION_STATE
  const flagsBytes = b4a.alloc(2)
  flagsBytes.writeUInt16BE(flags, 0)
  const revision = b4a.alloc(8)
  writeU64(revision, 0, priorSessionRevision)
  return blake2b256(b4a.concat([domain, flagsBytes, b4a.from([roleByteValue]), stableSessionId, revision, chargeCommitment, authorityCommitment, b4a.from([terminalSlotState])]))
}

export function encodeForwardHttpsRetentionPrunedV3 (input) {
  closedObject(input, ['role', 'stableSessionId', 'priorSessionRevision', 'pruneEpochSeconds', 'trustedEpochHighWatermark', 'expiresAtEpoch', 'recoveryGraceUntilEpoch', 'removedOrdinaryLogicalBytes', 'chargeEntryCount', 'beforeAuthorityBitmap', 'allocationDisposition', 'terminalSlotState', 'chargeEntryBuffers', 'authorityCommitments'], ['flags'], 'FPR9 encode input')
  const roleByteValue = quotaRoleByte(input.role)
  const flags = input.flags === undefined ? 0 : input.flags
  if (flags !== 0 && flags !== 1 && flags !== 2) throw new TypeError('flags must be ORDINARY_OR_TERMINAL=0, RECOVERED_PREFIX_ORPHAN=1 or EXISTING_SESSION_PREFIX_ABORT=2')
  const stableSessionId = b4a.from(bytes(input.stableSessionId, 32, 'stableSessionId', true))
  const priorSessionRevision = u64(input.priorSessionRevision, 'priorSessionRevision', true)
  const pruneEpochSeconds = safeUint(input.pruneEpochSeconds, 'pruneEpochSeconds', 0, U32_MAX)
  const trustedEpochHighWatermark = safeUint(input.trustedEpochHighWatermark, 'trustedEpochHighWatermark', 0, U32_MAX)
  const expiresAtEpoch = safeUint(input.expiresAtEpoch, 'expiresAtEpoch', 0, U32_MAX)
  const recoveryGraceUntilEpoch = safeUint(input.recoveryGraceUntilEpoch, 'recoveryGraceUntilEpoch', 0, U32_MAX)
  if (expiresAtEpoch > EXPIRY_HORIZON) storeWalFail('FPR9 expiry horizon is invalid')
  const removedOrdinaryLogicalBytes = u64(input.removedOrdinaryLogicalBytes, 'removedOrdinaryLogicalBytes')
  const chargeEntryCount = safeUint(input.chargeEntryCount, 'chargeEntryCount', 0, 65536)
  const beforeAuthorityBitmap = safeUint(input.beforeAuthorityBitmap, 'beforeAuthorityBitmap', 0, 1023)
  if (input.allocationDisposition !== 0 && input.allocationDisposition !== 1 && input.allocationDisposition !== 2) throw new TypeError('allocationDisposition must be NONE_CONSUMED=0, RELEASE_ALLOCATED=1 or NONE_RETAINED_ALLOCATED=2')
  if (input.terminalSlotState !== 1 && input.terminalSlotState !== 2 && input.terminalSlotState !== 3) throw new TypeError('terminalSlotState must be ALLOCATED=1, CONSUMED=2 or PREFIX_ALLOCATED=3')
  if (!Array.isArray(input.chargeEntryBuffers) || input.chargeEntryBuffers.length !== chargeEntryCount) throw new TypeError('chargeEntryBuffers must match chargeEntryCount')
  const entries = input.chargeEntryBuffers.map((entry, index) => b4a.from(bytes(entry, 49, `chargeEntryBuffers[${index}]`)))
  if (!Array.isArray(input.authorityCommitments) || input.authorityCommitments.length !== AUTHORITY_CLASS_COUNT) throw new TypeError('authorityCommitments must contain exactly ten entries')
  const commitments = input.authorityCommitments.map((commitment, index) => b4a.from(bytes(commitment, 32, `authorityCommitments[${index}]`)))
  if (chargeEntryCount === 0 && removedOrdinaryLogicalBytes !== 0n) storeWalFail('FPR9 terminal-only variant requires zero removal')
  if (chargeEntryCount > 0 && removedOrdinaryLogicalBytes === 0n) storeWalFail('FPR9 ordinary variant requires positive removal')
  // Exact variant matrix: flags0 RELEASE_ALLOCATED/ALLOCATED or
  // NONE_CONSUMED/CONSUMED; flags1 RELEASE_ALLOCATED/PREFIX_ALLOCATED; flags2
  // NONE_RETAINED_ALLOCATED/ALLOCATED. Every other pair is INTEGRITY. The
  // flags1/flags2 immediate exception zeroes both expiry fields and requires
  // a nonzero trusted prune epoch; prefix variants remove exact positive
  // orphan charge, so count is 1..65536.
  const pairValid =
    (flags === 0 && ((input.allocationDisposition === 1 && input.terminalSlotState === 1) || (input.allocationDisposition === 0 && input.terminalSlotState === 2))) ||
    (flags === 1 && input.allocationDisposition === 1 && input.terminalSlotState === 3) ||
    (flags === 2 && input.allocationDisposition === 2 && input.terminalSlotState === 1)
  if (!pairValid) storeWalFail('FPR9 allocation/slot pairing is invalid for the variant')
  if (flags !== 0) {
    if (expiresAtEpoch !== 0 || recoveryGraceUntilEpoch !== 0) storeWalFail('FPR9 prefix variants require zeroed expiry fields')
    if (pruneEpochSeconds === 0) storeWalFail('FPR9 prefix variants require a nonzero trusted prune epoch')
    if (chargeEntryCount === 0) storeWalFail('FPR9 prefix variants require exact positive orphan entries')
  }
  // The commitment stream independently matches count, sum and chain: the
  // removed sum must equal the exact total of the supplied entry charges.
  let entrySum = 0n
  for (const entry of entries) entrySum += readU64(entry, 41)
  if (entrySum !== removedOrdinaryLogicalBytes) storeWalFail('FPR9 removal does not match the charge entry sum')
  const chargeCommitment = chargeRegistryCommitment(roleByteValue, stableSessionId, chargeEntryCount, removedOrdinaryLogicalBytes, entries)
  const authorityCommitment = authorityRegistryCommitment(roleByteValue, stableSessionId, priorSessionRevision, beforeAuthorityBitmap, commitments)
  const stateCommitment = previousSessionStateCommitment(flags, roleByteValue, stableSessionId, priorSessionRevision, chargeCommitment, authorityCommitment, input.terminalSlotState)
  const output = b4a.alloc(FPR9_PAYLOAD_BYTES)
  let offset = 0
  b4a.copy(b4a.from('FPR9', 'ascii'), output, offset); offset += 4
  output[offset++] = 1
  output[offset++] = roleByteValue
  offset = writeU16(output, offset, flags)
  b4a.copy(stableSessionId, output, offset); offset += 32
  offset = writeU64(output, offset, priorSessionRevision)
  offset = writeU32(output, offset, pruneEpochSeconds)
  offset = writeU32(output, offset, trustedEpochHighWatermark)
  offset = writeU32(output, offset, expiresAtEpoch)
  offset = writeU32(output, offset, recoveryGraceUntilEpoch)
  offset = writeU64(output, offset, removedOrdinaryLogicalBytes)
  offset = writeU32(output, offset, chargeEntryCount)
  offset = writeU32(output, offset, beforeAuthorityBitmap)
  offset = writeU32(output, offset, 0)
  output[offset++] = input.allocationDisposition
  output[offset++] = input.terminalSlotState
  offset = writeU16(output, offset, 0)
  b4a.copy(chargeCommitment, output, offset); offset += 32
  b4a.copy(authorityCommitment, output, offset); offset += 32
  b4a.copy(stateCommitment, output, offset); offset += 32
  if (offset !== 184) throw new Error('FPR9 payload accounting mismatch')
  return output
}

export function decodeForwardHttpsRetentionPrunedV3 (payload) {
  payload = bytes(payload, FPR9_PAYLOAD_BYTES, 'FPR9 payload')
  if (b4a.toString(payload.subarray(0, 4), 'ascii') !== 'FPR9') storeWalFail('FPR9 magic is invalid')
  if (payload[4] !== 1) storeWalFail('FPR9 version is invalid')
  const role = payload[5]
  if (role !== 1 && role !== 2) storeWalFail('FPR9 role is invalid')
  const flags = readU16(payload, 6)
  if (flags !== 0 && flags !== 1 && flags !== 2) storeWalFail('FPR9 flags are invalid')
  const stableSessionId = b4a.from(payload.subarray(8, 40))
  const priorSessionRevision = readU64(payload, 40)
  if (priorSessionRevision === 0n) storeWalFail('FPR9 prior revision is invalid')
  const pruneEpochSeconds = payload.readUInt32BE(48)
  const trustedEpochHighWatermark = payload.readUInt32BE(52)
  const expiresAtEpoch = payload.readUInt32BE(56)
  const recoveryGraceUntilEpoch = payload.readUInt32BE(60)
  if (expiresAtEpoch > EXPIRY_HORIZON) storeWalFail('FPR9 expiry horizon is invalid')
  const removedOrdinaryLogicalBytes = readU64(payload, 64)
  const chargeEntryCount = payload.readUInt32BE(72)
  const beforeAuthorityBitmap = payload.readUInt32BE(76)
  if (payload.readUInt32BE(80) !== 0) storeWalFail('FPR9 after bitmap is invalid')
  const allocationDisposition = payload[84]
  const terminalSlotState = payload[85]
  if (allocationDisposition !== 0 && allocationDisposition !== 1 && allocationDisposition !== 2) storeWalFail('FPR9 allocation disposition is invalid')
  if (terminalSlotState !== 1 && terminalSlotState !== 2 && terminalSlotState !== 3) storeWalFail('FPR9 terminal slot state is invalid')
  if (readU16(payload, 86) !== 0) storeWalFail('FPR9 reserved field is invalid')
  if (beforeAuthorityBitmap > 1023) storeWalFail('FPR9 authority bitmap is invalid')
  if (chargeEntryCount > 65536) storeWalFail('FPR9 charge entry count is invalid')
  if ((chargeEntryCount === 0) !== (removedOrdinaryLogicalBytes === 0n)) storeWalFail('FPR9 count/removal pairing is invalid')
  // Exact variant matrix; every other flags/disposition/slot triple is INTEGRITY.
  const pairValid =
    (flags === 0 && ((allocationDisposition === 1 && terminalSlotState === 1) || (allocationDisposition === 0 && terminalSlotState === 2))) ||
    (flags === 1 && allocationDisposition === 1 && terminalSlotState === 3) ||
    (flags === 2 && allocationDisposition === 2 && terminalSlotState === 1)
  if (!pairValid) storeWalFail('FPR9 allocation/slot pairing is invalid for the variant')
  if (flags !== 0 && (expiresAtEpoch !== 0 || recoveryGraceUntilEpoch !== 0 || pruneEpochSeconds === 0 || chargeEntryCount === 0)) {
    storeWalFail('FPR9 prefix variant fields are invalid')
  }
  const chargeCommitment = b4a.from(payload.subarray(88, 120))
  const authorityCommitment = b4a.from(payload.subarray(120, 152))
  const stateCommitment = b4a.from(payload.subarray(152, 184))
  for (let index = 184; index < FPR9_PAYLOAD_BYTES; index++) if (payload[index] !== 0) storeWalFail('FPR9 padding is invalid')
  return freezeResult({
    role,
    flags,
    stableSessionId,
    priorSessionRevision,
    pruneEpochSeconds,
    trustedEpochHighWatermark,
    expiresAtEpoch,
    recoveryGraceUntilEpoch,
    removedOrdinaryLogicalBytes,
    chargeEntryCount,
    beforeAuthorityBitmap,
    afterAuthorityBitmap: 0,
    allocationDisposition,
    terminalSlotState,
    chargeRegistryCommitment: chargeCommitment,
    authorityRegistryCommitment: authorityCommitment,
    previousSessionStateCommitment: stateCommitment
  })
}

// ---------------------------------------------------------------------------
// deriveForwardHttpsStoreWalQuotaEntryV3
// ---------------------------------------------------------------------------

export function deriveForwardHttpsStoreWalQuotaEntryV3 (input) {
  closedObject(input, ['role', 'frame', 'transitionAuthority'], [], 'derive input')
  const roleByteValue = quotaRoleByte(input.role)
  // Claim fencing: derive burns exactly one claim and only a SYNCED live claim
  // or a recovery-sink claim minted inside absorb. A MINTED_UNBEGUN or BEGUN
  // claim, a caller-constructed value, a static capability, a reused or
  // cross-role value is AUTHORITY_INVALID with no WAL mutation.
  const claim = input.transitionAuthority && QUOTA_CLAIMS.get(input.transitionAuthority)
  if (!claim || claim.burned || claim.role !== input.role ||
      (claim.kind !== 'live' && claim.kind !== 'recovery') ||
      (claim.kind === 'live' && claim.state !== 'SYNCED')) {
    quotaFail('transition authority is forged, reused, cross-role or not SYNCED', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  }
  const frame = input.frame
  if (!frame || typeof frame !== 'object' || Array.isArray(frame)) throw new TypeError('frame must be a verified complete BlindWalFrameV2 object')
  const payload = bytes(frame.payload, null, 'frame.payload')
  const payloadHash = b4a.from(bytes(frame.payloadHash, 32, 'frame.payloadHash'))
  const walSequence = u64(frame.sequence, 'frame.sequence', true)
  const frameBytes = safeUint(frame.frameBytes, 'frame.frameBytes', 1, MAXIMUM_WAL_PAYLOAD_BYTES + WAL_FRAME_OVERHEAD_BYTES)
  if (frameBytes !== payload.byteLength + WAL_FRAME_OVERHEAD_BYTES) storeWalFail('frame byte accounting is invalid')
  if (payload.byteLength > MAXIMUM_WAL_PAYLOAD_BYTES) storeWalFail('frame payload exceeds the profile ceiling')
  if (payload.byteLength < 4) storeWalFail('frame payload is truncated')
  const walType = u8(frame.type, 'frame.type')
  const row = FORWARD_HTTPS_STORE_WAL_QUOTA_REGISTRY_V3[walType]
  if (!row || row.role !== roleByteValue) storeWalFail('frame WAL type is unknown or cross-role')
  let scope
  let stableSessionId = null
  let ordinaryLogicalCharge = 0
  let terminalLogicalCharge = 0
  let authorityBitmap = 0
  let authorityCommitments = Array.from({ length: AUTHORITY_CLASS_COUNT }, () => b4a.from(ZERO32))
  if (row.class === 'SESSION') {
    scope = 'SESSION'
    if (walType === 113) {
      ordinaryLogicalCharge = TYPE113_LOGICAL_BYTES
      if (payload.byteLength !== 118) storeWalFail('type113 payload length is invalid')
      stableSessionId = b4a.from(bytes(payload.subarray(4, 36), 32, 'type113 stableSessionId', true))
    } else {
      ordinaryLogicalCharge = payload.byteLength + frameBytes
      if (payload.byteLength < 36) storeWalFail('session frame payload is truncated')
      stableSessionId = b4a.from(bytes(payload.subarray(4, 36), 32, 'session stableSessionId', true))
    }
  } else if (row.class === 'SESSION_EMERGENCY') {
    scope = 'SESSION'
    const terminal = decodeFtm9Payload(payload, walType)
    terminalLogicalCharge = FTM9_LOGICAL_BYTES
    stableSessionId = terminal.stableSessionId
    const predecessor = claim.resolvePredecessor ? claim.resolvePredecessor(stableSessionId) : null
    if (terminal.flags === 1) {
      // flags1 minimal terminal: NEVER_SEEN predecessor only.
      if (predecessor && predecessor.present) storeWalFail('flags1 minimal terminal requires a NEVER_SEEN predecessor')
      authorityBitmap = MINIMAL_TERMINAL_BITMAP
      authorityCommitments = authorityCommitments.map((commitment, index) => {
        if (index === 7) return blake2b256(b4a.concat([DOMAIN_RETENTION_LOOKUP, terminal.minimalTerminalAuthorityCommitment]))
        if (index === 9) return blake2b256(b4a.concat([DOMAIN_TERMINAL_STATE, terminal.minimalTerminalAuthorityCommitment]))
        return commitment
      })
    } else {
      // flags0 existing terminal: requires PRESENT_ALLOCATED (including
      // ALLOCATED_WITH_PREFIX with the exact current orphan-last revision
      // floor) with class9 absent; preserves bitmap bits and commitments0..8
      // byte-identically and adds the exact C9 over domain
      // hiverelay.blind.forward-https-terminal-state-existing.v3. A FRESH
      // prefix predecessor (PRESENT_PREFIX_ALLOCATED) is never eligible.
      if (!predecessor || !predecessor.present || predecessor.consumed || predecessor.prefix === 'FRESH' || (predecessor.bitmap & 512) !== 0) {
        storeWalFail('flags0 terminal requires a PRESENT_ALLOCATED predecessor')
      }
      if (predecessor.priorRevision !== terminal.priorSessionRevision) storeWalFail('flags0 terminal prior revision mismatch')
      const predecessorCommitments = predecessor.commitments || Array.from({ length: AUTHORITY_CLASS_COUNT }, () => b4a.from(ZERO32))
      const revision = b4a.alloc(8)
      writeU64(revision, 0, terminal.priorSessionRevision)
      const bitmap = b4a.alloc(4)
      bitmap.writeUInt32BE(predecessor.bitmap, 0)
      const sequenceBytes = b4a.alloc(8)
      writeU64(sequenceBytes, 0, walSequence)
      authorityBitmap = predecessor.bitmap | 512
      authorityCommitments = predecessorCommitments.map(commitment => b4a.from(commitment))
      authorityCommitments[9] = blake2b256(b4a.concat([
        DOMAIN_TERMINAL_STATE_EXISTING, b4a.from([roleByteValue]), stableSessionId, revision, bitmap,
        ...predecessorCommitments.slice(0, 9), sequenceBytes, payloadHash
      ]))
    }
  } else if (row.class === 'PRUNE_TRANSITION') {
    scope = 'PRUNE_TRANSITION'
    const pruned = decodeForwardHttpsRetentionPrunedV3(payload)
    if (pruned.role !== roleByteValue) storeWalFail('FPR9 role binding is invalid')
    ordinaryLogicalCharge = FPR9_LOGICAL_BYTES
    stableSessionId = pruned.stableSessionId
    authorityBitmap = pruned.beforeAuthorityBitmap
  } else {
    scope = 'ROLE_GLOBAL'
    ordinaryLogicalCharge = payload.byteLength + frameBytes
  }
  // Burn exactly this one claim and mint the opaque next handoff (or null at
  // the exact final ordinal).
  claim.burned = true
  claim.state = 'BURNED'
  const entry = freezeResult({
    role: input.role,
    scope,
    stableSessionId,
    walType,
    walSequence,
    payloadHash,
    ordinaryLogicalCharge,
    terminalLogicalCharge,
    authorityBitmap,
    authorityCommitments: Object.freeze(authorityCommitments)
  })
  let handoff = null
  if (claim.kind === 'live' && claim.ordinal + 1 < claim.totalFrames) {
    handoff = mintQuotaClaim({
      kind: 'live',
      state: 'PENDING_DURABILITY',
      role: claim.role,
      reservation: claim.reservation,
      ordinal: claim.ordinal + 1,
      totalFrames: claim.totalFrames,
      stableSessionId: claim.stableSessionId,
      predecessorHead: { sequence: walSequence, hash: b4a.from(bytes(frame.walHash, 32, 'frame.walHash')) },
      resolvePredecessor: claim.resolvePredecessor
    })
  }
  return freezeResult({ entry, transitionAuthorityHandoff: handoff })
}
