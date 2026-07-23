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
const SNAPSHOT_HEADER_BYTES = 231
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
  const reservation = await reserveForwardHttpsAggregateQuotaV3(state.replayQuotaCapability, plan)
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
    .map(record => deepFreeze({
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

function quotaState (authority) {
  const state = authority && QUOTA_AUTHORITIES.get(authority)
  if (!state || state.authority !== authority) quotaFail('quota authority is forged', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  if (state.closed) quotaFail('quota authority is closed', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.CLOSED)
  if (state.failed) quotaFail('quota authority is failed', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
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
    initialized: false,
    capabilitiesMinted: false,
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
    output[key] = capability
  }
  return deepFreeze(output)
}

export function beginForwardHttpsAggregateQuotaRecoveryV3 (quotaAuthority, storeQuotaCapability, input) {
  const state = quotaState(quotaAuthority)
  const capability = quotaCapabilityState(storeQuotaCapability)
  if (capability.quotaAuthority !== quotaAuthority || (capability.role !== 'SOURCE_STORE' && capability.role !== 'TARGET_STORE')) {
    quotaFail('recovery capability role is invalid', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  }
  closedObject(input, ['storeId', 'mapGeneration', 'ownerFenceTokenHash', 'durabilityContinuityHash'], [], 'recovery input')
  const sink = Object.freeze({})
  QUOTA_SINKS.set(sink, {
    quotaAuthority,
    capability: storeQuotaCapability,
    role: capability.role,
    storeId: b4a.from(bytes(input.storeId, 32, 'storeId', true)),
    mapGeneration: u64(input.mapGeneration, 'mapGeneration', true),
    ownerFenceTokenHash: b4a.from(bytes(input.ownerFenceTokenHash, 32, 'ownerFenceTokenHash', true)),
    durabilityContinuityHash: b4a.from(bytes(input.durabilityContinuityHash, 32, 'durabilityContinuityHash', true)),
    logicalBytes: 0,
    lastSequence: 0n,
    lastHash: b4a.from(ZERO32),
    finished: false,
    burned: false,
    state
  })
  return sink
}

export async function absorbForwardHttpsAggregateQuotaRecoveryFrameV3 (recoverySink, input) {
  closedObject(input, ['frame'], [], 'recovery frame input')
  const sink = recoverySink && QUOTA_SINKS.get(recoverySink)
  if (!sink || sink.finished || sink.burned) quotaFail('recovery sink is invalid', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  const frame = input.frame
  if (!frame || typeof frame !== 'object' || u64(frame.sequence, 'frame.sequence') !== sink.lastSequence + 1n ||
      !b4a.equals(bytes(frame.previousWalHash, 32, 'frame.previousWalHash'), sink.lastHash) ||
      u64(frame.mapGeneration, 'frame.mapGeneration') !== sink.mapGeneration ||
      !b4a.equals(bytes(frame.ownerFenceTokenHash, 32, 'frame.ownerFenceTokenHash'), sink.ownerFenceTokenHash) ||
      !b4a.equals(bytes(frame.durabilityContinuityHash, 32, 'frame.durabilityContinuityHash'), sink.durabilityContinuityHash) ||
      safeUint(frame.frameBytes, 'frame.frameBytes') !== bytes(frame.payload, null, 'frame.payload').byteLength + 224) {
    quotaFail('recovery frame binding is invalid', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
  }
  sink.logicalBytes += frame.payload.byteLength
  sink.lastSequence = frame.sequence
  sink.lastHash = b4a.from(bytes(frame.walHash, 32, 'frame.walHash'))
  await quotaFault(sink.state, FORWARD_HTTPS_AGGREGATE_QUOTA_V3_FAULT_POINT.RECOVERY_AFTER_FRAME)
}

export async function finishForwardHttpsAggregateQuotaRecoveryV3 (recoverySink, input) {
  closedObject(input, ['walHeadSequence', 'walHeadHash'], [], 'recovery finish input')
  const sink = recoverySink && QUOTA_SINKS.get(recoverySink)
  if (!sink || sink.finished || sink.burned) quotaFail('recovery sink is invalid', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  if (u64(input.walHeadSequence, 'walHeadSequence') !== sink.lastSequence ||
      !b4a.equals(bytes(input.walHeadHash, 32, 'walHeadHash'), sink.lastHash)) {
    quotaFail('recovery head is invalid', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
  }
  sink.finished = true
  const claim = Object.freeze({})
  QUOTA_CLAIMS.set(claim, { sink, burned: false })
  await quotaFault(sink.state, FORWARD_HTTPS_AGGREGATE_QUOTA_V3_FAULT_POINT.RECOVERY_AFTER_FINISH)
  return claim
}

export async function initializeForwardHttpsAggregateQuotaV3 (quotaAuthority, input) {
  const state = quotaState(quotaAuthority)
  closedObject(input, ['sourceRecoveryClaim', 'targetRecoveryClaim'], [], 'quota initialize input')
  if (state.initialized) quotaFail('quota is already initialized', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
  const source = input.sourceRecoveryClaim && QUOTA_CLAIMS.get(input.sourceRecoveryClaim)
  const target = input.targetRecoveryClaim && QUOTA_CLAIMS.get(input.targetRecoveryClaim)
  if (!source || !target || source.burned || target.burned || source.sink.role !== 'SOURCE_STORE' || target.sink.role !== 'TARGET_STORE' ||
      source.sink.quotaAuthority !== quotaAuthority || target.sink.quotaAuthority !== quotaAuthority) {
    quotaFail('quota recovery claims are invalid', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  }
  source.burned = target.burned = true
  state.logical.SOURCE_STORE = source.sink.logicalBytes
  state.logical.TARGET_STORE = target.sink.logicalBytes
  state.physical = await measurements(state)
  await quotaFault(state, FORWARD_HTTPS_AGGREGATE_QUOTA_V3_FAULT_POINT.INITIALIZE_AFTER_MEASURE)
  ensureQuota(state, null, 0, 0)
  state.initialized = true
}

function planFrom (capability, operation, logicalBytes, physicalBytes, commitments = []) {
  const plan = Object.freeze({})
  QUOTA_PLANS.set(plan, {
    capability,
    operation,
    logicalBytes,
    physicalBytes,
    commitments,
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
  const operations = ['OPEN_RECOVERY', 'PREPARE', 'RESULT', 'TURN_FINAL', 'PROCESSOR_REQUEST_READY', 'PROCESSOR_PREPARED', 'PROCESSOR_COMPLETED', 'SESSION_TERMINAL', 'QUARANTINE', 'PRUNE']
  if (!operations.includes(input.operation)) throw new TypeError('store operation is invalid')
  const known = buffersArray(input.knownInputBuffers, 'knownInputBuffers')
  const temporary = buffersArray(input.temporaryWriteBuffers, 'temporaryWriteBuffers')
  const existing = safeUint(input.existingDestinationBytes, 'existingDestinationBytes')
  const knownBytes = known.reduce((sum, item) => sum + item.byteLength, 0)
  const temporaryBytes = temporary.reduce((sum, item) => sum + item.byteLength, 0)
  // Exact fixed rows: SESSION_TERMINAL is 608 logical/416 physical; PRUNE is
  // 736 logical/480 physical before any proven ordinary removal. All other
  // rows reserve their conservative maximum.
  const exactLogical = input.operation === 'SESSION_TERMINAL' ? 608 : null
  const exactPhysical = input.operation === 'SESSION_TERMINAL' ? 416 : input.operation === 'PRUNE' ? 480 : null
  let pruneNetLogical = null
  if (input.operation === 'PRUNE') {
    // The exact already-encoded FPR9 is known before reserve; net admission is
    // exactly removal-then-736, never the conservative row maximum.
    if (known.length !== 1) throw new TypeError('PRUNE requires exactly one known tombstone buffer')
    const pruned = decodeForwardHttpsRetentionPrunedV3(known[0])
    const roleByteValue = capability.role === 'SOURCE_STORE' ? 1 : 2
    if (pruned.role !== roleByteValue) quotaFail('PRUNE tombstone role mismatch', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    pruneNetLogical = 736 - Number(pruned.removedOrdinaryLogicalBytes)
  }
  const maximum = input.operation === 'PROCESSOR_COMPLETED'
    ? 13553338 + 49248 + 65536
    : input.operation === 'PROCESSOR_REQUEST_READY'
      ? 8645538 + 4 * 342 + 65536
      : knownBytes + 224 + 65536
  const logical = pruneNetLogical === null ? (exactLogical === null ? maximum : exactLogical) : pruneNetLogical
  const physical = exactPhysical === null ? maximum + temporaryBytes + existing : exactPhysical + temporaryBytes + existing
  return planFrom(storeQuotaCapability, input.operation, logical, physical,
    [...known, ...temporary].map(item => hmac(ZERO32, item)))
}

export function bindForwardHttpsStoreQuotaActualBuffersV3 (storeQuotaCapability, reservation, input) {
  const capability = quotaCapabilityState(storeQuotaCapability)
  const internal = reservation && QUOTA_RESERVATIONS.get(reservation)
  if (!internal || internal.burned || internal.capability !== storeQuotaCapability || capability.quotaAuthority !== internal.state.authority) {
    quotaFail('quota reservation is invalid', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
  }
  closedObject(input, ['logicalRecordBuffers', 'encryptedPlaintextBuffers', 'finalWalMetadataBuffers', 'temporaryWriteBuffers'], [], 'actual buffer binding')
  const arrays = ['logicalRecordBuffers', 'encryptedPlaintextBuffers', 'finalWalMetadataBuffers', 'temporaryWriteBuffers']
    .flatMap(field => buffersArray(input[field], field))
  const logicalBytes = arrays.reduce((sum, item) => sum + item.byteLength, 0) + input.encryptedPlaintextBuffers.length * 218
  const physicalBytes = logicalBytes + input.encryptedPlaintextBuffers.length * 342 + 224
  if (logicalBytes > internal.plan.logicalBytes || physicalBytes > internal.plan.physicalBytes) {
    quotaFail('actual buffers exceed the conservative plan', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
  }
  internal.actual = { logicalBytes, physicalBytes, commitments: arrays.map(item => hmac(ZERO32, item)) }
}

function ensureQuota (state, role, logicalIncrease, physicalIncrease) {
  const logicalSource = state.logical.SOURCE_STORE + (role === 'SOURCE_STORE' ? logicalIncrease : 0)
  const logicalTarget = state.logical.TARGET_STORE + (role === 'TARGET_STORE' ? logicalIncrease : 0)
  if (logicalSource > state.perStore || logicalTarget > state.perStore || logicalSource + logicalTarget > state.aggregate) {
    quotaFail('logical quota exhausted', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.CAPACITY)
  }
  for (const [itemRole, value] of Object.entries(state.physical)) {
    if (value + (itemRole === role ? physicalIncrease : 0) > state.perStore) quotaFail('physical quota exhausted', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.CAPACITY)
  }
  const aggregate = Object.values(state.physical).reduce((sum, item) => sum + item, 0) + physicalIncrease
  if (aggregate > state.aggregate) quotaFail('aggregate physical quota exhausted', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.CAPACITY)
}

export function reserveForwardHttpsAggregateQuotaV3 (quotaCapability, costPlan) {
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
  return serialize(state, async () => {
    state.physical = await measurements(state)
    await quotaFault(state, FORWARD_HTTPS_AGGREGATE_QUOTA_V3_FAULT_POINT.RESERVE_AFTER_MEASURE)
    ensureQuota(state, capability.role, plan.logicalBytes, plan.physicalBytes)
    if (state.pendingReservation) quotaFail('nested quota reservation', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    state.pendingReservation = true
    const reservation = Object.freeze({})
    QUOTA_RESERVATIONS.set(reservation, { state, capability: quotaCapability, plan, actual: null, burned: false, mutated: false })
    state.pendingReservationObject = reservation
    return reservation
  })
}

export function commitForwardHttpsAggregateQuotaV3 (quotaCapability, reservation, input) {
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
  return serialize(state, async () => {
    if (internal.plan.operation === 'PRUNE') quotaFail('commit is forbidden for PRUNE; use adjust', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    internal.burned = true
    const cost = internal.actual || internal.plan
    if (capability.role === 'SOURCE_STORE' || capability.role === 'TARGET_STORE') state.logical[capability.role] += cost.logicalBytes
    state.physical = await measurements(state)
    await quotaFault(state, FORWARD_HTTPS_AGGREGATE_QUOTA_V3_FAULT_POINT.COMMIT_AFTER_MEASURE)
    ensureQuota(state, null, 0, 0)
    state.pendingReservation = false
    state.pendingReservationObject = null
  })
}

export function releaseForwardHttpsAggregateQuotaV3 (quotaCapability, reservation) {
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
  return serialize(state, async () => {
    await quotaFault(state, FORWARD_HTTPS_AGGREGATE_QUOTA_V3_FAULT_POINT.RELEASE_BEFORE_UNLOCK)
    internal.burned = true
    state.pendingReservation = false
    state.pendingReservationObject = null
  })
}

export function adjustForwardHttpsAggregateQuotaV3 (storeQuotaCapability, input) {
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
  return serialize(state, async () => {
    // PRUNE adjust is the only adjust path: it requires the exact pending
    // bound PRUNE reservation, revalidates the tombstone and applies
    // logical = current - provenRemoval + 736 atomically.
    const pending = state.pendingReservationObject
    internal = pending ? QUOTA_RESERVATIONS.get(pending) : null
    if (!internal || internal.burned || internal.capability !== storeQuotaCapability || internal.plan.operation !== 'PRUNE') {
      quotaFail('quota adjustment has no pending PRUNE reservation', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.AUTHORITY_INVALID)
    }
    const tombstone = bytes(input.durableTombstonePayloadBuffer, null, 'durableTombstonePayloadBuffer')
    const commitment = hmac(ZERO32, tombstone)
    if (!internal.plan.commitments.some(expected => timingSafeEqual(expected, commitment))) {
      quotaFail('quota adjustment tombstone commitment mismatch', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    }
    const pruned = decodeForwardHttpsRetentionPrunedV3(tombstone)
    const roleByteValue = capability.role === 'SOURCE_STORE' ? 1 : 2
    if (pruned.role !== roleByteValue) quotaFail('quota adjustment tombstone role mismatch', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    u64(input.durableWalHeadSequence, 'durableWalHeadSequence')
    bytes(input.durableWalHeadHash, 32, 'durableWalHeadHash')
    const removed = pruned.removedOrdinaryLogicalBytes
    const current = BigInt(state.logical[capability.role])
    const next = current - removed + 736n
    if (next < 0n) quotaFail('quota adjustment underflow', FORWARD_HTTPS_AGGREGATE_QUOTA_V3_ERROR_CODE.INTEGRITY)
    state.logical[capability.role] = Number(next)
    state.physical = await measurements(state)
    await quotaFault(state, FORWARD_HTTPS_AGGREGATE_QUOTA_V3_FAULT_POINT.ADJUST_AFTER_MEASURE)
    internal.burned = true
    state.pendingReservation = false
    state.pendingReservationObject = null
  })
}

export function forwardHttpsAggregateQuotaV3Status (quotaAuthority) {
  const state = quotaState(quotaAuthority)
  const physical = state.physical
  return deepFreeze({
    state: state.failed ? 'FAILED' : state.initialized ? 'OPEN' : 'UNINITIALIZED',
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
  await serialize(state, async () => {
    await quotaFault(state, FORWARD_HTTPS_AGGREGATE_QUOTA_V3_FAULT_POINT.CLOSE_BEFORE_INVALIDATE)
    state.closed = true
    for (const capability of QUOTA_CAPABILITIES.values?.() || []) capability.burned = true
  })
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

const DOMAIN_CHARGE_REGISTRY = b4a.from('hiverelay.blind.forward-https-quota-charge-registry.v3', 'ascii')
const DOMAIN_AUTHORITY_REGISTRY = b4a.from('hiverelay.blind.forward-https-authority-registry.v3', 'ascii')
const DOMAIN_PRUNE_SESSION_STATE = b4a.from('hiverelay.blind.forward-https-prune-session-state.v3', 'ascii')
const DOMAIN_RETENTION_LOOKUP = b4a.from('hiverelay.blind.forward-https-retention-lookup.v3', 'ascii')
const DOMAIN_TERMINAL_STATE = b4a.from('hiverelay.blind.forward-https-terminal-state.v3', 'ascii')

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
    if (b4a.toString(reason, 'ascii') !== 'SEQUENCE_INVALID') storeWalFail('FTM9 minimal terminal reason is invalid')
    for (const value of [...buckets, transportTurnsSpent, transportBytesSpent]) if (value !== 0) storeWalFail('FTM9 minimal terminal counters are invalid')
    expiresAtEpoch = tail.readUInt32BE(0)
    retainedUntilEpoch = tail.readUInt32BE(4)
    if (expiresAtEpoch > EXPIRY_HORIZON) storeWalFail('FTM9 expiry horizon is invalid')
    if (retainedUntilEpoch !== expiresAtEpoch + RECOVERY_GRACE_SECONDS) storeWalFail('FTM9 retainedUntil is invalid')
    minimalTerminalAuthorityCommitment = b4a.from(tail.subarray(8, 40))
    if (b4a.equals(minimalTerminalAuthorityCommitment, ZERO32)) storeWalFail('FTM9 minimal authority commitment is invalid')
    for (let index = 40; index < 51; index++) if (tail[index] !== 0) storeWalFail('FTM9 minimal tail padding is invalid')
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

function chargeRegistryCommitment (roleByteValue, stableSessionId, chargeEntryCount, ascendingEntryBuffers) {
  const parts = [DOMAIN_CHARGE_REGISTRY, b4a.from([roleByteValue]), stableSessionId]
  const count = b4a.alloc(4)
  count.writeUInt32BE(chargeEntryCount, 0)
  parts.push(count)
  for (const entry of ascendingEntryBuffers) parts.push(entry)
  return blake2b256(b4a.concat(parts))
}

function authorityRegistryCommitment (roleByteValue, stableSessionId, priorSessionRevision, beforeAuthorityBitmap, commitments) {
  const revision = b4a.alloc(8)
  writeU64(revision, 0, priorSessionRevision)
  const bitmap = b4a.alloc(4)
  bitmap.writeUInt32BE(beforeAuthorityBitmap, 0)
  return blake2b256(b4a.concat([DOMAIN_AUTHORITY_REGISTRY, b4a.from([roleByteValue]), stableSessionId, revision, bitmap, ...commitments]))
}

function previousSessionStateCommitment (roleByteValue, stableSessionId, priorSessionRevision, chargeCommitment, authorityCommitment, terminalSlotState) {
  const revision = b4a.alloc(8)
  writeU64(revision, 0, priorSessionRevision)
  return blake2b256(b4a.concat([DOMAIN_PRUNE_SESSION_STATE, b4a.from([roleByteValue]), stableSessionId, revision, chargeCommitment, authorityCommitment, b4a.from([terminalSlotState])]))
}

export function encodeForwardHttpsRetentionPrunedV3 (input) {
  closedObject(input, ['role', 'stableSessionId', 'priorSessionRevision', 'pruneEpochSeconds', 'trustedEpochHighWatermark', 'expiresAtEpoch', 'recoveryGraceUntilEpoch', 'removedOrdinaryLogicalBytes', 'chargeEntryCount', 'beforeAuthorityBitmap', 'allocationDisposition', 'terminalSlotState', 'chargeEntryBuffers', 'authorityCommitments'], [], 'FPR9 encode input')
  const roleByteValue = quotaRoleByte(input.role)
  const stableSessionId = b4a.from(bytes(input.stableSessionId, 32, 'stableSessionId', true))
  const priorSessionRevision = u64(input.priorSessionRevision, 'priorSessionRevision', true)
  const pruneEpochSeconds = safeUint(input.pruneEpochSeconds, 'pruneEpochSeconds', 0, U32_MAX)
  const trustedEpochHighWatermark = safeUint(input.trustedEpochHighWatermark, 'trustedEpochHighWatermark', 0, U32_MAX)
  const expiresAtEpoch = safeUint(input.expiresAtEpoch, 'expiresAtEpoch', 0, U32_MAX)
  const recoveryGraceUntilEpoch = safeUint(input.recoveryGraceUntilEpoch, 'recoveryGraceUntilEpoch', 0, U32_MAX)
  const removedOrdinaryLogicalBytes = u64(input.removedOrdinaryLogicalBytes, 'removedOrdinaryLogicalBytes')
  const chargeEntryCount = safeUint(input.chargeEntryCount, 'chargeEntryCount', 0, 65536)
  const beforeAuthorityBitmap = safeUint(input.beforeAuthorityBitmap, 'beforeAuthorityBitmap', 0, 1023)
  if (input.allocationDisposition !== 0 && input.allocationDisposition !== 1) throw new TypeError('allocationDisposition must be NONE_CONSUMED=0 or RELEASE_ALLOCATED=1')
  if (input.terminalSlotState !== 1 && input.terminalSlotState !== 2) throw new TypeError('terminalSlotState must be ALLOCATED=1 or CONSUMED=2')
  if (!Array.isArray(input.chargeEntryBuffers) || input.chargeEntryBuffers.length !== chargeEntryCount) throw new TypeError('chargeEntryBuffers must match chargeEntryCount')
  const entries = input.chargeEntryBuffers.map((entry, index) => b4a.from(bytes(entry, 49, `chargeEntryBuffers[${index}]`)))
  if (!Array.isArray(input.authorityCommitments) || input.authorityCommitments.length !== AUTHORITY_CLASS_COUNT) throw new TypeError('authorityCommitments must contain exactly ten entries')
  const commitments = input.authorityCommitments.map((commitment, index) => b4a.from(bytes(commitment, 32, `authorityCommitments[${index}]`)))
  if (chargeEntryCount === 0 && removedOrdinaryLogicalBytes !== 0n) storeWalFail('FPR9 terminal-only variant requires zero removal')
  if (chargeEntryCount > 0 && removedOrdinaryLogicalBytes === 0n) storeWalFail('FPR9 ordinary variant requires positive removal')
  const chargeCommitment = chargeRegistryCommitment(roleByteValue, stableSessionId, chargeEntryCount, entries)
  const authorityCommitment = authorityRegistryCommitment(roleByteValue, stableSessionId, priorSessionRevision, beforeAuthorityBitmap, commitments)
  const stateCommitment = previousSessionStateCommitment(roleByteValue, stableSessionId, priorSessionRevision, chargeCommitment, authorityCommitment, input.terminalSlotState)
  const output = b4a.alloc(FPR9_PAYLOAD_BYTES)
  let offset = 0
  b4a.copy(b4a.from('FPR9', 'ascii'), output, offset); offset += 4
  output[offset++] = 1
  output[offset++] = roleByteValue
  offset = writeU16(output, offset, 0)
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
  if (readU16(payload, 6) !== 0) storeWalFail('FPR9 flags are invalid')
  const stableSessionId = b4a.from(payload.subarray(8, 40))
  const priorSessionRevision = readU64(payload, 40)
  if (priorSessionRevision === 0n) storeWalFail('FPR9 prior revision is invalid')
  const pruneEpochSeconds = payload.readUInt32BE(48)
  const trustedEpochHighWatermark = payload.readUInt32BE(52)
  const expiresAtEpoch = payload.readUInt32BE(56)
  const recoveryGraceUntilEpoch = payload.readUInt32BE(60)
  const removedOrdinaryLogicalBytes = readU64(payload, 64)
  const chargeEntryCount = payload.readUInt32BE(72)
  const beforeAuthorityBitmap = payload.readUInt32BE(76)
  if (payload.readUInt32BE(80) !== 0) storeWalFail('FPR9 after bitmap is invalid')
  const allocationDisposition = payload[84]
  const terminalSlotState = payload[85]
  if (allocationDisposition !== 0 && allocationDisposition !== 1) storeWalFail('FPR9 allocation disposition is invalid')
  if (terminalSlotState !== 1 && terminalSlotState !== 2) storeWalFail('FPR9 terminal slot state is invalid')
  if (readU16(payload, 86) !== 0) storeWalFail('FPR9 reserved field is invalid')
  if (beforeAuthorityBitmap > 1023) storeWalFail('FPR9 authority bitmap is invalid')
  if (chargeEntryCount > 65536) storeWalFail('FPR9 charge entry count is invalid')
  if ((chargeEntryCount === 0) !== (removedOrdinaryLogicalBytes === 0n)) storeWalFail('FPR9 count/removal pairing is invalid')
  const chargeCommitment = b4a.from(payload.subarray(88, 120))
  const authorityCommitment = b4a.from(payload.subarray(120, 152))
  const stateCommitment = b4a.from(payload.subarray(152, 184))
  for (let index = 184; index < FPR9_PAYLOAD_BYTES; index++) if (payload[index] !== 0) storeWalFail('FPR9 padding is invalid')
  return freezeResult({
    role,
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
  closedObject(input, ['role', 'frame'], [], 'derive input')
  const roleByteValue = quotaRoleByte(input.role)
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
    if (terminal.flags === 1) {
      authorityBitmap = MINIMAL_TERMINAL_BITMAP
      authorityCommitments = authorityCommitments.map((commitment, index) => {
        if (index === 7) return blake2b256(b4a.concat([DOMAIN_RETENTION_LOOKUP, terminal.minimalTerminalAuthorityCommitment]))
        if (index === 9) return blake2b256(b4a.concat([DOMAIN_TERMINAL_STATE, terminal.minimalTerminalAuthorityCommitment]))
        return commitment
      })
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
  return freezeResult({
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
}
