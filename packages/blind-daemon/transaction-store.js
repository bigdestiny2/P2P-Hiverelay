import fs from 'node:fs/promises'
import { constants as FS_CONSTANTS } from 'node:fs'
import path from 'node:path'
import { createHmac, randomBytes } from 'node:crypto'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { FAMILY, blake2b256 } from '@hiverelay/blind-protocol'
import {
  releaseExclusiveFileLock,
  tryExclusiveFileLock
} from '@hiverelay/blind-peercred'
import {
  acquireBlindStoreSessionTransactionLease,
  transferBlindStoreSessionTransactionLease,
  verifyBlindStoreSessionTransactionLease
} from './store-session.js'

const WAL_MAGIC = b4a.from('HRWL', 'ascii')
const WAL_VERSION = 2
const WAL_HEADER_BYTES = 192
const WAL_CHECKSUM_BYTES = 32
const WAL_MIN_FRAME_BYTES = WAL_HEADER_BYTES + WAL_CHECKSUM_BYTES
const ZERO32 = b4a.alloc(32)
const MAX_U64 = (1n << 64n) - 1n

// Segmented WAL (Phase 3). The live segment keeps the historical
// `wal.v2` name — a pre-segmentation store imports unchanged as exactly one
// live segment. Sealing renames the live segment to
// `wal-<firstSequence16>-<lastSequence16>.v2`; the zero-padded hex ranges
// sort lexicographically in sequence order. A commit group never straddles
// a boundary: rollover runs only between groups, after the previous group's
// datasync, so every sealed segment ends on a committed frame boundary and
// holds exactly its named range. The seal is the rename itself (plus a
// directory sync); the frame hash chain crosses segment boundaries, so a
// missing, reordered, truncated, or corrupted sealed segment reads as an
// interior break and fails closed. Torn-tail truncation remains legal only
// at the live segment tail.
const WAL_LIVE_SEGMENT_NAME = 'wal.v2'
const WAL_SEALED_SEGMENT_NAME = /^wal-([0-9a-f]{16})-([0-9a-f]{16})\.v2$/
// Default rollover threshold: 64 MiB bounds per-file recovery scan work and
// prune granularity without creating meaningful directory fan-out (a segment
// holds ~40k reference-size frames; fsync cost is per commit group, not per
// byte, so a larger segment buys no group-commit throughput). The threshold
// is soft: a segment may exceed it by at most one commit group, because a
// group's frames always land together.
const DEFAULT_WAL_SEGMENT_MAX_BYTES = 64 * 1024 * 1024
const MIN_WAL_SEGMENT_MAX_BYTES = 64 * 1024
const MAX_WAL_SEGMENT_MAX_BYTES = 1024 * 1024 * 1024

const WAL_CHECKSUM_DOMAIN = b4a.from('hiverelay.blind.wal-frame-checksum.v1', 'ascii')
const WAL_HASH_DOMAIN = b4a.from('hiverelay.blind.wal-frame-hash.v1', 'ascii')
const OPEN_STORE_ROOTS = new Set()
const TRANSACTION_STORE_SESSION_LEASES = new WeakMap()
const TRANSACTION_STORE_RECOVERY_HANDOFFS = new WeakMap()
const ACTIVE_WAL_BARRIER_AUTHORITIES = new WeakSet()
const WAL_BARRIER_AUTHORITY_STATE = new WeakMap()
const ACTIVE_WAL_ANCHORS = new WeakSet()
const WAL_ANCHOR_STATE = new WeakMap()

export const BLIND_STORE_SERVICE_TAG = Object.freeze({
  CELL: FAMILY.CELL,
  INBOX: FAMILY.INBOX,
  CORE: FAMILY.CORE
})

export const BLIND_TRANSACTION_RECOVERY_HANDOFF_STATUS = Object.freeze({
  preacquiredLeaseTransferReady: true,
  mutationFreeValidationCallbackRequired: true,
  jointRecoveryValidationAuthorityRequired: true,
  productionReady: false,
  blocker: 'ALL_FAMILY_SHADOW_SEMANTIC_AUTHORITY_UNIMPLEMENTED'
})

export class BlindWalIntegrityError extends Error {
  constructor (message, reason = null) {
    super(message)
    this.name = 'BlindWalIntegrityError'
    this.code = 'RECOVERY_GAP_READ_ONLY'
    this.reason = reason
  }
}

export class BlindStoreBoundsError extends Error {
  constructor (message, code = 'TOO_LARGE') {
    super(message)
    this.name = 'BlindStoreBoundsError'
    this.code = code
  }
}

export class BlindOpaqueBodyError extends Error {
  constructor (message, code, terminal) {
    super(message)
    this.name = 'BlindOpaqueBodyError'
    this.code = code
    this.terminal = terminal === true
  }
}

export class BlindWalAnchorError extends Error {
  constructor (message, code = 'BLIND_WAL_ANCHOR_INVALID') {
    super(message)
    this.name = 'BlindWalAnchorError'
    this.code = code
  }
}

export class BlindWalBarrierAuthorityError extends Error {
  constructor (message, code = 'BLIND_WAL_BARRIER_AUTHORITY_INVALID') {
    super(message)
    this.name = 'BlindWalBarrierAuthorityError'
    this.code = code
  }
}

export class BlindRecoveryHandoffError extends Error {
  constructor (message, code = 'BLIND_RECOVERY_HANDOFF_INVALID') {
    super(message)
    this.name = 'BlindRecoveryHandoffError'
    this.code = code
  }
}

function bytes (value, length, field, options = {}) {
  if (!value || typeof value.byteLength !== 'number') throw new TypeError(`${field} must be bytes`)
  value = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (length != null && value.byteLength !== length) throw new TypeError(`${field} must be exactly ${length} bytes`)
  if (options.nonzero === true && isZero(value)) throw new TypeError(`${field} must be nonzero`)
  return value
}

function isZero (value) {
  for (const byte of value) if (byte !== 0) return false
  return true
}

function asU64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${field} must be an unsigned safe integer or bigint`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) throw new TypeError(`${field} is outside u64`)
  return value
}

function boundedInteger (value, minimum, maximum, field) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${field} is outside ${minimum}..${maximum}`)
  }
  return value
}

function writeU16be (buffer, offset, value) {
  buffer[offset] = value >>> 8
  buffer[offset + 1] = value
}

function readU16be (buffer, offset) {
  return buffer[offset] * 0x100 + buffer[offset + 1]
}

function writeU32be (buffer, offset, value) {
  buffer[offset] = value >>> 24
  buffer[offset + 1] = value >>> 16
  buffer[offset + 2] = value >>> 8
  buffer[offset + 3] = value
}

function readU32be (buffer, offset) {
  return buffer[offset] * 0x1000000 + buffer[offset + 1] * 0x10000 +
    buffer[offset + 2] * 0x100 + buffer[offset + 3]
}

function writeU64be (buffer, offset, value) {
  value = asU64(value, 'u64')
  for (let index = 7; index >= 0; index--) {
    buffer[offset + index] = Number(value & 0xffn)
    value >>= 8n
  }
}

function readU64be (buffer, offset) {
  let value = 0n
  for (let index = 0; index < 8; index++) value = (value << 8n) | BigInt(buffer[offset + index])
  return value
}

function hashParts (domain, ...parts) {
  return blake2b256(b4a.concat([domain, ...parts]))
}

function hashStream () {
  const state = b4a.alloc(sodium.crypto_generichash_STATEBYTES)
  sodium.crypto_generichash_init(state, null, 32)
  return {
    update (chunk) { sodium.crypto_generichash_update(state, chunk) },
    digest () {
      const output = b4a.alloc(32)
      sodium.crypto_generichash_final(state, output)
      return output
    }
  }
}

async function writeAll (handle, buffer, position) {
  let written = 0
  while (written < buffer.byteLength) {
    const result = await handle.write(buffer, written, buffer.byteLength - written, position + written)
    if (result.bytesWritten === 0) throw new Error('zero-byte filesystem write')
    written += result.bytesWritten
  }
}

// Settles every not-yet-resolved member of a poisoned commit group. The
// member whose own step failed (failedIndex) sees the raw error, exactly like
// the failing appender does in the serial path; every other member sees the
// standard poison error, exactly like an appender queued behind a poison.
// Members already resolved are untouched because rejecting a settled promise
// is a no-op.
function rejectWalGroupAsPoisoned (frames, failedIndex, failure) {
  for (let index = 0; index < frames.length; index++) {
    if (index === failedIndex) frames[index].member.reject(failure)
    else {
      frames[index].member.reject(
        new BlindWalIntegrityError('transaction store requires recovery after an interrupted WAL append')
      )
    }
  }
}

async function readAtMost (handle, buffer, position) {
  let read = 0
  while (read < buffer.byteLength) {
    const result = await handle.read(buffer, read, buffer.byteLength - read, position + read)
    if (result.bytesRead === 0) break
    read += result.bytesRead
  }
  return read
}

async function syncDirectory (directory) {
  const handle = await fs.open(directory, 'r')
  try {
    await handle.sync()
  } finally {
    await handle.close()
  }
}

function sameInode (left, right) {
  return left.dev === right.dev && left.ino === right.ino
}

function assertOwnedPrivateDirectory (stat, field) {
  if (!stat.isDirectory()) throw new BlindWalIntegrityError(`${field} is not a directory`)
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
    throw new BlindWalIntegrityError(`${field} is not owned by the daemon uid`)
  }
  if ((stat.mode & 0o700) !== 0o700 || (stat.mode & 0o077) !== 0) {
    throw new BlindWalIntegrityError(`${field} must have private owner-only mode`)
  }
}

function assertOwnedPrivateFile (stat, field, expectedLinks = 1) {
  if (!stat.isFile()) throw new BlindWalIntegrityError(`${field} is not a regular file`)
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
    throw new BlindWalIntegrityError(`${field} is not owned by the daemon uid`)
  }
  if ((stat.mode & 0o600) !== 0o600 || (stat.mode & 0o077) !== 0) {
    throw new BlindWalIntegrityError(`${field} must have private owner-only mode`)
  }
  if (expectedLinks != null && stat.nlink !== expectedLinks) {
    throw new BlindWalIntegrityError(`${field} has an unexpected hard-link count`)
  }
}

async function verifyPrivateDirectory (directory, field) {
  const lstat = await fs.lstat(directory)
  if (lstat.isSymbolicLink()) throw new BlindWalIntegrityError(`${field} must not be a symlink`)
  assertOwnedPrivateDirectory(lstat, field)
  const real = await fs.realpath(directory)
  if (real !== directory) throw new BlindWalIntegrityError(`${field} realpath is not its canonical configured path`)
  return lstat
}

async function createPrivateDirectory (directory, parent, field, fault = null) {
  let created = false
  try {
    await fs.mkdir(directory, { mode: 0o700 })
    created = true
  } catch (error) {
    if (!error || error.code !== 'EEXIST') throw error
  }
  const stat = await verifyPrivateDirectory(directory, field)
  if (created && fault) await fault('after-directory-create', { directory, parent, field })
  if (created || fault) await syncDirectory(parent)
  if (fault) await fault('after-parent-directory-sync', { directory, parent, field, created })
  return { created, stat }
}

function canonicalRoot (root) {
  if (typeof root !== 'string' || !path.isAbsolute(root) || path.normalize(root) !== root) {
    throw new TypeError('store root must be an absolute canonical path')
  }
  return root
}

function normalizeRecoveryHandoff (value) {
  if (value == null) return null
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('recoveryHandoff must be an object')
  }
  const allowed = new Set(['lease', 'validationResult', 'validate'])
  const unknown = Object.keys(value).find(key => !allowed.has(key))
  if (unknown) throw new TypeError(`recoveryHandoff contains unknown field ${unknown}`)
  if (!value.lease || typeof value.lease !== 'object') {
    throw new TypeError('recoveryHandoff.lease must be a StoreSession transaction lease')
  }
  if (!value.validationResult || typeof value.validationResult !== 'object' || Array.isArray(value.validationResult)) {
    throw new TypeError('recoveryHandoff.validationResult must be an object')
  }
  if (typeof value.validate !== 'function') {
    throw new TypeError('recoveryHandoff.validate must be an awaited validation callback')
  }
  return Object.freeze({
    lease: value.lease,
    validationResult: value.validationResult,
    validate: value.validate
  })
}

function normalizeWalAnchorValue (value, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${field} must be an object`)
  const sequence = asU64(value.sequence, `${field}.sequence`)
  if (sequence === 0n) throw new TypeError(`${field}.sequence must be nonzero`)
  const hash = bytes(value.hash, 32, `${field}.hash`, { nonzero: true })
  return Object.freeze({ sequence, hash: b4a.from(hash) })
}

// Checkpoint-anchored recovery options (Phase 3). `checkpointAnchor` pins
// (coveredWalSequence, coveredWalHash) from the newest validated checkpoint.
// Recovery verifies the anchor against the retained segment chain and, by
// default, replays only post-anchor frames (the checkpoint snapshot covers
// the prefix). `replayCoveredFrames` instead applies every retained frame:
// the prune-tolerant full replay used by writers that hold no snapshot
// restore path but must still tolerate a floor-respecting prune. An anchor
// that does not validate against the retained segments refuses to open —
// replaying from genesis is impossible once covered segments are pruned, so
// refusal is the only fail-closed fallback (never a silent history skip).
function normalizeOpenRecoveryOptions (options) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('transaction store open options must be an object')
  }
  const allowed = new Set(['checkpointAnchor', 'replayCoveredFrames'])
  const unknown = Object.keys(options).find(key => !allowed.has(key))
  if (unknown) throw new TypeError(`transaction store open options contain unknown field ${unknown}`)
  if (options.replayCoveredFrames != null && typeof options.replayCoveredFrames !== 'boolean') {
    throw new TypeError('replayCoveredFrames must be a boolean')
  }
  const checkpointAnchor = options.checkpointAnchor == null
    ? null
    : normalizeWalAnchorValue(options.checkpointAnchor, 'checkpointAnchor')
  const replayCoveredFrames = options.replayCoveredFrames === true
  if (replayCoveredFrames && checkpointAnchor === null) {
    throw new TypeError('replayCoveredFrames requires a checkpoint anchor')
  }
  return Object.freeze({ checkpointAnchor, replayCoveredFrames })
}

function mintWalBarrierAuthority (store, lease) {
  const state = Object.freeze({ store, root: store.root, lease })
  const authority = Object.freeze({ root: state.root })
  ACTIVE_WAL_BARRIER_AUTHORITIES.add(authority)
  WAL_BARRIER_AUTHORITY_STATE.set(authority, state)
  return authority
}

export async function verifyBlindWalBarrierAuthority (authority, expectedRoot) {
  const root = canonicalRoot(expectedRoot)
  if (!authority || typeof authority !== 'object' || !ACTIVE_WAL_BARRIER_AUTHORITIES.has(authority)) {
    throw new BlindWalBarrierAuthorityError('WAL barrier authority is forged, expired, or unsupported')
  }
  const state = WAL_BARRIER_AUTHORITY_STATE.get(authority)
  if (!state || state.root !== root || authority.root !== root || state.store.root !== root || !state.store.handle ||
      TRANSACTION_STORE_SESSION_LEASES.get(state.store) !== state.lease) {
    throw new BlindWalBarrierAuthorityError('WAL barrier authority binding is invalid')
  }
  if (state.lease) {
    await verifyBlindStoreSessionTransactionLease(state.lease, root)
  } else if (!state.store.storeLockHandle) {
    throw new BlindWalBarrierAuthorityError('standalone WAL barrier has no active writer lock')
  }
  return true
}

function mintWalAnchor (store, barrierAuthority) {
  const state = Object.freeze({
    store,
    root: store.root,
    barrierAuthority,
    sequence: store.walSequence,
    hash: b4a.from(store.walHash)
  })
  const anchor = {}
  Object.defineProperties(anchor, {
    root: { enumerable: true, value: state.root },
    sequence: { enumerable: true, value: state.sequence },
    hash: { enumerable: true, get: () => b4a.from(state.hash) }
  })
  Object.freeze(anchor)
  ACTIVE_WAL_ANCHORS.add(anchor)
  WAL_ANCHOR_STATE.set(anchor, state)
  return anchor
}

export async function verifyBlindWalAnchor (anchor, expectedRoot, barrierAuthority) {
  const root = canonicalRoot(expectedRoot)
  if (!anchor || typeof anchor !== 'object' || !ACTIVE_WAL_ANCHORS.has(anchor)) {
    throw new BlindWalAnchorError('WAL anchor is forged, expired, or unsupported historical authority')
  }
  const state = WAL_ANCHOR_STATE.get(anchor)
  if (!state || state.root !== root || anchor.root !== root || state.barrierAuthority !== barrierAuthority) {
    throw new BlindWalAnchorError('WAL anchor root or barrier-authority binding is invalid')
  }
  await verifyBlindWalBarrierAuthority(barrierAuthority, root)
  if (state.store.root !== root || !state.store.handle || state.store.walSequence !== state.sequence ||
      !b4a.equals(state.store.walHash, state.hash) || anchor.sequence !== state.sequence ||
      !b4a.equals(anchor.hash, state.hash)) {
    throw new BlindWalAnchorError('WAL anchor no longer matches the active serialized WAL state')
  }
  return true
}

function randomNonzero32 () {
  let value
  do value = randomBytes(32)
  while (isZero(value))
  return value
}

function walSealedSegmentName (firstSequence, lastSequence) {
  firstSequence = asU64(firstSequence, 'WAL segment firstSequence')
  lastSequence = asU64(lastSequence, 'WAL segment lastSequence')
  if (firstSequence === 0n || lastSequence < firstSequence) throw new TypeError('WAL segment sequence range is invalid')
  return `wal-${firstSequence.toString(16).padStart(16, '0')}-${lastSequence.toString(16).padStart(16, '0')}.v2`
}

function sourceIterator (source) {
  if (source && typeof source.byteLength === 'number') {
    return (async function * () { yield bytes(source, null, 'opaque body') })()
  }
  if (source && typeof source[Symbol.asyncIterator] === 'function') return source[Symbol.asyncIterator]()
  if (source && typeof source[Symbol.iterator] === 'function') {
    return (async function * () { yield * source })()
  }
  throw new TypeError('opaque body source must be bytes or an iterable of byte chunks')
}

async function nextBeforeDeadline (iterator, deadlineUnixMillis, nowUnixMillis, signal) {
  if (signal && signal.aborted) throw new BlindOpaqueBodyError('opaque body input was aborted', 'BODY_INTERRUPTED', false)
  const remaining = deadlineUnixMillis - asU64(nowUnixMillis(), 'nowUnixMillis')
  if (remaining < 0n) throw new BlindOpaqueBodyError('opaque body deadline expired', 'BODY_DEADLINE_EXPIRED', true)
  let timer = null
  let abort = null
  const contenders = [Promise.resolve().then(() => iterator.next())]
  contenders.push(new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(new BlindOpaqueBodyError(
      'opaque body deadline expired while awaiting input',
      'BODY_DEADLINE_EXPIRED',
      true
    )), Number(remaining > 0x7fffffffn ? 0x7fffffffn : remaining) + 1)
  }))
  if (signal) {
    contenders.push(new Promise((resolve, reject) => {
      abort = () => reject(new BlindOpaqueBodyError('opaque body input was aborted', 'BODY_INTERRUPTED', false))
      signal.addEventListener('abort', abort, { once: true })
    }))
  }
  try {
    return await Promise.race(contenders)
  } catch (error) {
    if (typeof iterator.return === 'function') {
      try {
        Promise.resolve(iterator.return()).catch(() => {})
      } catch {}
    }
    throw error
  } finally {
    if (timer) clearTimeout(timer)
    if (signal && abort) signal.removeEventListener('abort', abort)
  }
}

function frameChecksum (prefixAndPayload) {
  return hashParts(WAL_CHECKSUM_DOMAIN, prefixAndPayload)
}

function frameHash (completeFrame) {
  return hashParts(WAL_HASH_DOMAIN, completeFrame)
}

function encodeWalFrame (value, maximumPayloadBytes) {
  const type = boundedInteger(value.type, 1, 255, 'WAL frame type')
  const sequence = asU64(value.sequence, 'WAL sequence')
  if (sequence === 0n) throw new TypeError('WAL sequence must be nonzero')
  const transactionId = bytes(value.transactionId, 32, 'transactionId', { nonzero: true })
  const virtualBucket = boundedInteger(value.virtualBucket, 0, 0xffff, 'virtualBucket')
  const mapGeneration = asU64(value.mapGeneration, 'mapGeneration')
  const ownerFenceTokenHash = bytes(value.ownerFenceTokenHash, 32, 'ownerFenceTokenHash', { nonzero: true })
  const durabilityContinuityHash = bytes(
    value.durabilityContinuityHash,
    32,
    'durabilityContinuityHash',
    { nonzero: true }
  )
  const previousWalHash = bytes(value.previousWalHash, 32, 'previousWalHash')
  const payload = bytes(value.payload, null, 'WAL payload')
  if (payload.byteLength > maximumPayloadBytes) {
    throw new BlindStoreBoundsError(`WAL payload exceeds ${maximumPayloadBytes} bytes`)
  }
  const totalLength = WAL_MIN_FRAME_BYTES + payload.byteLength
  const frame = b4a.alloc(totalLength)
  b4a.copy(WAL_MAGIC, frame, 0)
  frame[4] = WAL_VERSION
  frame[5] = type
  writeU32be(frame, 6, totalLength)
  writeU64be(frame, 10, sequence)
  b4a.copy(transactionId, frame, 18)
  writeU16be(frame, 50, virtualBucket)
  writeU64be(frame, 52, mapGeneration)
  b4a.copy(ownerFenceTokenHash, frame, 60)
  writeU32be(frame, 92, payload.byteLength)
  b4a.copy(previousWalHash, frame, 96)
  b4a.copy(durabilityContinuityHash, frame, 128)
  b4a.copy(blake2b256(payload), frame, 160)
  b4a.copy(payload, frame, WAL_HEADER_BYTES)
  const checksumOffset = totalLength - WAL_CHECKSUM_BYTES
  b4a.copy(frameChecksum(frame.subarray(0, checksumOffset)), frame, checksumOffset)
  return frame
}

export function inspectBlindWalFrameV2Header (header, maximumPayloadBytes) {
  header = bytes(header, WAL_HEADER_BYTES, 'WAL v2 header')
  boundedInteger(maximumPayloadBytes, 1024, 16 * 1024 * 1024, 'maximumWalPayloadBytes')
  if (!b4a.equals(header.subarray(0, 4), WAL_MAGIC)) throw new BlindWalIntegrityError('WAL frame magic mismatch')
  if (header[4] !== WAL_VERSION) throw new BlindWalIntegrityError('unknown WAL frame version')
  const type = header[5]
  if (type === 0) throw new BlindWalIntegrityError('WAL frame type zero is forbidden')
  const totalLength = readU32be(header, 6)
  const payloadLength = readU32be(header, 92)
  if (totalLength !== WAL_MIN_FRAME_BYTES + payloadLength) {
    throw new BlindWalIntegrityError('WAL frame length fields disagree')
  }
  if (payloadLength > maximumPayloadBytes) throw new BlindWalIntegrityError('WAL payload exceeds the configured recovery bound')
  const sequence = readU64be(header, 10)
  if (sequence === 0n) throw new BlindWalIntegrityError('WAL sequence zero is forbidden')
  const transactionId = b4a.from(header.subarray(18, 50))
  if (isZero(transactionId)) throw new BlindWalIntegrityError('WAL transaction ID must be nonzero')
  const mapGeneration = readU64be(header, 52)
  if (mapGeneration === 0n) throw new BlindWalIntegrityError('WAL map generation must be nonzero')
  const ownerFenceTokenHash = b4a.from(header.subarray(60, 92))
  if (isZero(ownerFenceTokenHash)) throw new BlindWalIntegrityError('WAL writer fence token hash must be nonzero')
  const durabilityContinuityHash = b4a.from(header.subarray(128, 160))
  if (isZero(durabilityContinuityHash)) throw new BlindWalIntegrityError('WAL durability continuity hash must be nonzero')
  return Object.freeze({
    type,
    totalLength,
    payloadLength,
    sequence,
    transactionId,
    virtualBucket: readU16be(header, 50),
    mapGeneration,
    ownerFenceTokenHash,
    previousWalHash: b4a.from(header.subarray(96, 128)),
    durabilityContinuityHash,
    payloadHash: b4a.from(header.subarray(160, 192))
  })
}

export function decodeBlindWalFrameV2 (
  frame,
  expectedSequence,
  expectedPreviousWalHash,
  expectedDurabilityContinuityHash,
  maximumPayloadBytes
) {
  if (frame.byteLength < WAL_MIN_FRAME_BYTES) throw new BlindWalIntegrityError('WAL frame is shorter than its fixed envelope')
  const header = inspectBlindWalFrameV2Header(frame.subarray(0, WAL_HEADER_BYTES), maximumPayloadBytes)
  if (header.totalLength !== frame.byteLength) {
    throw new BlindWalIntegrityError('WAL frame length fields disagree')
  }
  if (header.sequence !== expectedSequence) throw new BlindWalIntegrityError('WAL sequence gap or fork')
  if (!b4a.equals(header.previousWalHash, expectedPreviousWalHash)) throw new BlindWalIntegrityError('WAL predecessor hash fork')
  if (!b4a.equals(header.durabilityContinuityHash, expectedDurabilityContinuityHash)) {
    throw new BlindWalIntegrityError('WAL durability continuity binding mismatch')
  }
  const payload = b4a.from(frame.subarray(WAL_HEADER_BYTES, WAL_HEADER_BYTES + header.payloadLength))
  if (!b4a.equals(blake2b256(payload), header.payloadHash)) {
    throw new BlindWalIntegrityError('WAL payload hash mismatch')
  }
  const checksumOffset = frame.byteLength - WAL_CHECKSUM_BYTES
  if (!b4a.equals(frameChecksum(frame.subarray(0, checksumOffset)), frame.subarray(checksumOffset))) {
    throw new BlindWalIntegrityError('WAL frame checksum mismatch')
  }
  return {
    type: header.type,
    sequence: header.sequence,
    transactionId: header.transactionId,
    virtualBucket: header.virtualBucket,
    mapGeneration: header.mapGeneration,
    ownerFenceTokenHash: header.ownerFenceTokenHash,
    previousWalHash: header.previousWalHash,
    durabilityContinuityHash: header.durabilityContinuityHash,
    payload,
    payloadHash: header.payloadHash,
    walHash: frameHash(frame),
    frameBytes: frame.byteLength
  }
}

class KeyLockTable {
  constructor () {
    this.tails = new Map()
  }

  async with (keys, callback) {
    keys = [...new Set(keys)].sort()
    const held = []
    try {
      for (const key of keys) {
        const previous = this.tails.get(key) || Promise.resolve()
        let release
        const gate = new Promise(resolve => { release = resolve })
        const tail = previous.catch(() => {}).then(() => gate)
        this.tails.set(key, tail)
        await previous.catch(() => {})
        held.push({ key, release, tail })
      }
      return await callback()
    } finally {
      for (let index = held.length - 1; index >= 0; index--) {
        const item = held[index]
        item.release()
        if (this.tails.get(item.key) === item.tail) {
          this.tails.delete(item.key)
        }
      }
    }
  }
}

export class BlindTransactionStore {
  constructor (options = {}) {
    this.root = canonicalRoot(options.root)
    // The runtime loader deliberately wipes its temporary secret buffers after
    // construction. The store must therefore own independent copies for its
    // entire writer lifetime rather than retaining caller-owned aliases.
    this.partitionKey = b4a.from(bytes(options.partitionKey, 32, 'partitionKey', { nonzero: true }))
    this.mapGeneration = asU64(options.mapGeneration == null ? 1n : options.mapGeneration, 'mapGeneration')
    if (this.mapGeneration === 0n) throw new TypeError('mapGeneration must be nonzero')
    this.ownerFenceTokenHash = b4a.from(bytes(
      options.ownerFenceTokenHash,
      32,
      'ownerFenceTokenHash',
      { nonzero: true }
    ))
    this.durabilityContinuityHash = b4a.from(bytes(
      options.durabilityContinuityHash,
      32,
      'durabilityContinuityHash',
      { nonzero: true }
    ))
    this.maximumWalPayloadBytes = boundedInteger(
      options.maximumWalPayloadBytes == null ? 1024 * 1024 : options.maximumWalPayloadBytes,
      1024,
      16 * 1024 * 1024,
      'maximumWalPayloadBytes'
    )
    this.maximumOpaqueBodyBytes = boundedInteger(
      options.maximumOpaqueBodyBytes == null ? 1024 * 1024 : options.maximumOpaqueBodyBytes,
      4096,
      4 * 1024 * 1024,
      'maximumOpaqueBodyBytes'
    )
    this.maximumChunkBytes = boundedInteger(
      options.maximumChunkBytes == null ? 256 * 1024 : options.maximumChunkBytes,
      1024,
      this.maximumOpaqueBodyBytes,
      'maximumChunkBytes'
    )
    this.walSegmentMaxBytes = boundedInteger(
      options.walSegmentMaxBytes == null ? DEFAULT_WAL_SEGMENT_MAX_BYTES : options.walSegmentMaxBytes,
      MIN_WAL_SEGMENT_MAX_BYTES,
      MAX_WAL_SEGMENT_MAX_BYTES,
      'walSegmentMaxBytes'
    )
    if (options.faultInjector != null && typeof options.faultInjector !== 'function') {
      throw new TypeError('faultInjector must be a function')
    }
    this.faultInjector = options.faultInjector || null
    if (options.beforeRecovery != null && typeof options.beforeRecovery !== 'function') {
      throw new TypeError('beforeRecovery must be a function')
    }
    this.beforeRecovery = options.beforeRecovery || null
    this.storeSessionContext = options.storeSessionContext == null ? null : options.storeSessionContext
    const recoveryHandoff = normalizeRecoveryHandoff(options.recoveryHandoff)
    if (recoveryHandoff && this.storeSessionContext !== null) {
      throw new TypeError('recoveryHandoff and storeSessionContext are mutually exclusive')
    }
    if (recoveryHandoff && this.beforeRecovery) {
      throw new TypeError('recoveryHandoff replaces beforeRecovery with its required validation callback')
    }
    this.controlDirectory = path.join(this.root, 'control')
    this.blobDirectory = path.join(this.root, 'blobs')
    this.stagingDirectory = path.join(this.root, 'staging')
    this.walPath = path.join(this.controlDirectory, WAL_LIVE_SEGMENT_NAME)
    this.storeLockPath = path.join(this.controlDirectory, 'writer.lock.v1')
    this.locks = new KeyLockTable()
    this.handle = null
    this.storeLockHandle = null
    TRANSACTION_STORE_SESSION_LEASES.set(this, null)
    TRANSACTION_STORE_RECOVERY_HANDOFFS.set(this, recoveryHandoff)
    this.closing = false
    this.destroyed = false
    this.opened = false
    this.openPromise = null
    this.closePromise = null
    this.activeOpaqueOperations = 0
    this.opaqueDrainWaiters = []
    this.walOffset = 0
    this.walSequence = 0n
    this.walHash = b4a.from(ZERO32)
    this.liveSegmentFirstSequence = 1n
    this.sealedWalSegments = []
    this.poisoned = false
    this.walCommitQueue = []
    this.walCommitDrainActive = false
    this.staged = new Map()
  }

  open (applyRecoveredFrame, options = {}) {
    if (this.destroyed) return Promise.reject(new Error('transaction store secrets were destroyed on close'))
    if (this.handle || this.openPromise) return Promise.reject(new Error('transaction store is already opening or open'))
    if (this.closing || this.closePromise) return Promise.reject(new Error('transaction store is closing'))
    if (typeof applyRecoveredFrame !== 'function') {
      return Promise.reject(new TypeError('applyRecoveredFrame must be a function'))
    }
    let recovery
    try {
      recovery = normalizeOpenRecoveryOptions(options)
    } catch (error) {
      return Promise.reject(error)
    }
    const opening = this._open(applyRecoveredFrame, recovery)
    this.openPromise = opening
    opening.then(
      () => { if (this.openPromise === opening) this.openPromise = null },
      () => { if (this.openPromise === opening) this.openPromise = null }
    )
    return opening
  }

  async _open (applyRecoveredFrame, recovery) {
    if (OPEN_STORE_ROOTS.has(this.root)) throw new BlindWalIntegrityError('store root already has an active writer in this process')
    OPEN_STORE_ROOTS.add(this.root)
    let opened = false
    try {
      if (!FS_CONSTANTS.O_NOFOLLOW) throw new BlindWalIntegrityError('O_NOFOLLOW is required for the blind store')
      const recoveryHandoff = TRANSACTION_STORE_RECOVERY_HANDOFFS.get(this)
      if (recoveryHandoff) {
        await verifyBlindStoreSessionTransactionLease(recoveryHandoff.lease, this.root)
        await verifyPrivateDirectory(this.root, 'store root')
        await verifyPrivateDirectory(this.controlDirectory, 'control directory')
        const validationContext = Object.freeze({
          root: this.root,
          controlDirectory: this.controlDirectory,
          walPath: this.walPath,
          lease: recoveryHandoff.lease,
          validationResult: recoveryHandoff.validationResult,
          mutationAllowed: false,
          authorityStatus: BLIND_TRANSACTION_RECOVERY_HANDOFF_STATUS
        })
        const { verifyBlindRecoveryValidationAuthority } = await import('./recovery-validation-authority.js')
        await verifyBlindRecoveryValidationAuthority(
          recoveryHandoff.validationResult,
          this.root,
          recoveryHandoff.lease
        )
        const validatedResult = await recoveryHandoff.validate(validationContext)
        if (validatedResult !== recoveryHandoff.validationResult) {
          throw new BlindRecoveryHandoffError(
            'recovery handoff validation callback did not return the exact supplied result'
          )
        }
        if (this.closing) throw new Error('transaction store is closing during recovery handoff validation')
        await verifyBlindRecoveryValidationAuthority(
          recoveryHandoff.validationResult,
          this.root,
          recoveryHandoff.lease
        )
        await verifyBlindStoreSessionTransactionLease(recoveryHandoff.lease, this.root)
        if (this.closing) throw new Error('transaction store is closing before recovery lease transfer')
        const transferredLease = await transferBlindStoreSessionTransactionLease(
          recoveryHandoff.lease,
          this.root
        )
        TRANSACTION_STORE_SESSION_LEASES.set(this, transferredLease)
        TRANSACTION_STORE_RECOVERY_HANDOFFS.set(this, null)
        await verifyBlindStoreSessionTransactionLease(transferredLease, this.root)
      } else if (this.storeSessionContext !== null) {
        TRANSACTION_STORE_SESSION_LEASES.set(this, await acquireBlindStoreSessionTransactionLease(
          this.storeSessionContext,
          this.root
        ))
      }
      if (!recoveryHandoff) await verifyPrivateDirectory(this.root, 'store root')
      if (this.closing) throw new Error('transaction store is closing before store mutation')
      if (TRANSACTION_STORE_SESSION_LEASES.get(this)) {
        if (!recoveryHandoff) await verifyPrivateDirectory(this.controlDirectory, 'control directory')
      } else {
        await createPrivateDirectory(this.controlDirectory, this.root, 'control directory')
        this.storeLockHandle = await fs.open(
          this.storeLockPath,
          FS_CONSTANTS.O_RDWR | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_NOFOLLOW,
          0o600
        )
        const [lockFileStat, lockPathStat] = await Promise.all([
          this.storeLockHandle.stat(),
          fs.lstat(this.storeLockPath)
        ])
        if (lockPathStat.isSymbolicLink() || !sameInode(lockFileStat, lockPathStat)) {
          throw new BlindWalIntegrityError('store lock path and opened inode disagree')
        }
        assertOwnedPrivateFile(lockFileStat, 'store lock file')
        if (!tryExclusiveFileLock(this.storeLockHandle)) {
          throw new BlindWalIntegrityError('store root already has an active writer in another process')
        }
      }
      if (this.beforeRecovery) {
        await this.beforeRecovery(Object.freeze({
          root: this.root,
          controlDirectory: this.controlDirectory,
          walPath: this.walPath
        }))
      }
      await createPrivateDirectory(
        this.blobDirectory,
        this.root,
        'blob directory',
        (point, context) => this.#fault(`store:blob:${point}`, context)
      )
      await createPrivateDirectory(
        this.stagingDirectory,
        this.root,
        'staging directory',
        (point, context) => this.#fault(`store:staging:${point}`, context)
      )
      this.handle = await fs.open(
        this.walPath,
        FS_CONSTANTS.O_RDWR | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_APPEND | FS_CONSTANTS.O_NOFOLLOW,
        0o600
      )
      const [fileStat, pathStat] = await Promise.all([this.handle.stat(), fs.lstat(this.walPath)])
      if (pathStat.isSymbolicLink() || !sameInode(fileStat, pathStat)) {
        throw new BlindWalIntegrityError('WAL path and opened inode disagree')
      }
      assertOwnedPrivateFile(fileStat, 'WAL file')
      await this.#fault('wal:after-file-open', { byteLength: fileStat.size })
      await this.handle.sync()
      await this.#fault('wal:after-open-file-sync', { byteLength: fileStat.size })
      await syncDirectory(this.controlDirectory)
      await this.#fault('wal:after-open-directory-sync', { byteLength: fileStat.size })
      await this.#recover(applyRecoveredFrame, recovery)
      await this.#cleanupStaging()
      if (this.closing) throw new Error('transaction store is closing before activation')
      this.opened = true
      opened = true
      return this
    } catch (error) {
      this.opened = false
      if (this.handle) await this.handle.close().catch(() => {})
      this.handle = null
      if (this.storeLockHandle) {
        try { releaseExclusiveFileLock(this.storeLockHandle) } catch {}
        await this.storeLockHandle.close().catch(() => {})
      }
      this.storeLockHandle = null
      const storeSessionTransactionLease = TRANSACTION_STORE_SESSION_LEASES.get(this)
      if (storeSessionTransactionLease) storeSessionTransactionLease.release()
      TRANSACTION_STORE_SESSION_LEASES.set(this, null)
      throw error
    } finally {
      if (!opened) OPEN_STORE_ROOTS.delete(this.root)
    }
  }

  // Recovery enumerates the sealed segments in sequence order, then the live
  // segment, replaying one continuous hash chain. Fail-closed on any interior
  // break: a malformed segment name, a coverage gap or overlap between
  // segments, a checksum/chain/map/fence mismatch, or a torn tail anywhere
  // but the live segment tail. With a checkpoint anchor the retained prefix
  // may start after sequence 1: the first retained frame's predecessor link
  // is unverifiable from retained bytes alone, so the anchor must pin it —
  // either the retained range begins exactly at anchor.sequence + 1 (the
  // first frame's previousWalHash must equal the anchor hash), or the anchor
  // frame itself is still retained and must hash to the anchor value (which
  // transitively pins every retained frame before it, since each frame's
  // hash covers its declared predecessor). Without an anchor the retained
  // range must begin at genesis, exactly as the pre-segmentation store
  // required of the single wal.v2 file.
  async #recover (applyRecoveredFrame, recovery) {
    const anchor = recovery.checkpointAnchor
    const replayCoveredFrames = recovery.replayCoveredFrames
    const segments = await this.#enumerateWalSegments()
    const firstRetainedSequence = segments.length === 0
      ? await this.#peekLiveFirstSequence()
      : segments[0].firstSequence
    if (anchor === null) {
      if (firstRetainedSequence !== 1n) {
        throw new BlindWalIntegrityError('WAL history begins after genesis without a checkpoint anchor')
      }
    } else if (firstRetainedSequence > anchor.sequence + 1n) {
      throw new BlindWalIntegrityError('WAL begins after the checkpoint anchor')
    }
    const chain = {
      expectedSequence: firstRetainedSequence,
      expectedPreviousWalHash: firstRetainedSequence === 1n ? b4a.from(ZERO32) : null
    }
    let anchorVerified = false
    if (anchor !== null && firstRetainedSequence === anchor.sequence + 1n) {
      chain.expectedPreviousWalHash = b4a.from(anchor.hash)
      anchorVerified = true
    }
    const onFrame = async (frame) => {
      if (anchor !== null && !anchorVerified && frame.sequence === anchor.sequence) {
        if (!b4a.equals(frame.walHash, anchor.hash)) {
          throw new BlindWalIntegrityError('WAL checkpoint anchor hash mismatch')
        }
        anchorVerified = true
      }
      if (anchor === null || replayCoveredFrames || frame.sequence > anchor.sequence) {
        await applyRecoveredFrame(frame)
      }
      chain.expectedSequence = frame.sequence + 1n
      chain.expectedPreviousWalHash = frame.walHash
      this.walSequence = frame.sequence
      this.walHash = frame.walHash
    }
    for (const segment of segments) {
      if (segment.firstSequence !== chain.expectedSequence) {
        throw new BlindWalIntegrityError('WAL segment chain has an interior gap')
      }
      await this.#replaySealedWalSegment(segment, chain, onFrame)
      if (chain.expectedSequence !== segment.lastSequence + 1n) {
        throw new BlindWalIntegrityError('sealed WAL segment does not contain its sealed sequence range')
      }
    }
    this.liveSegmentFirstSequence = chain.expectedSequence
    const stat = await this.handle.stat()
    this.walOffset = await this.#scanSegmentFrames(
      this.handle, stat.size, 'live WAL segment', false, chain, onFrame)
    if (anchor !== null && !anchorVerified) {
      throw new BlindWalIntegrityError('WAL does not contain the exact checkpoint anchor')
    }
    this.sealedWalSegments = segments
  }

  // When no sealed segment survives, the live segment's own first frame
  // header declares the first retained sequence (a store pruned down to its
  // live segment starts above 1). The full scan that follows verifies the
  // chain from that frame on, so the peek fixes only the boundary the
  // checkpoint-anchor rule pins. An empty or header-short live segment is
  // the pre-segmentation fresh/torn case and starts at 1.
  async #peekLiveFirstSequence () {
    const stat = await this.handle.stat()
    if (stat.size < WAL_HEADER_BYTES) return 1n
    const header = b4a.alloc(WAL_HEADER_BYTES)
    if (await readAtMost(this.handle, header, 0) !== WAL_HEADER_BYTES) return 1n
    return inspectBlindWalFrameV2Header(header, this.maximumWalPayloadBytes).sequence
  }

  async #enumerateWalSegments () {
    const segments = []
    const directory = await fs.opendir(this.controlDirectory)
    for await (const entry of directory) {
      if (!entry.name.startsWith('wal-')) continue
      const match = WAL_SEALED_SEGMENT_NAME.exec(entry.name)
      if (!match || !entry.isFile()) {
        throw new BlindWalIntegrityError(`unexpected WAL segment entry ${entry.name}`)
      }
      const firstSequence = BigInt(`0x${match[1]}`)
      const lastSequence = BigInt(`0x${match[2]}`)
      if (firstSequence === 0n || lastSequence < firstSequence) {
        throw new BlindWalIntegrityError(`WAL segment entry ${entry.name} carries an invalid sequence range`)
      }
      segments.push({ name: entry.name, firstSequence, lastSequence })
    }
    segments.sort((left, right) => (left.firstSequence < right.firstSequence ? -1 : 1))
    for (let index = 1; index < segments.length; index++) {
      if (segments[index].firstSequence !== segments[index - 1].lastSequence + 1n) {
        throw new BlindWalIntegrityError('WAL segment chain has an interior gap')
      }
    }
    return segments
  }

  async #replaySealedWalSegment (segment, chain, onFrame) {
    const segmentPath = path.join(this.controlDirectory, segment.name)
    const linked = await fs.lstat(segmentPath)
    assertOwnedPrivateFile(linked, 'sealed WAL segment')
    const handle = await fs.open(segmentPath, FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW)
    try {
      const opened = await handle.stat()
      assertOwnedPrivateFile(opened, 'opened sealed WAL segment')
      if (!sameInode(linked, opened)) {
        throw new BlindWalIntegrityError('sealed WAL segment path and opened inode disagree')
      }
      await this.#scanSegmentFrames(
        handle, opened.size, `sealed WAL segment ${segment.name}`, true, chain, onFrame)
    } finally {
      await handle.close()
    }
  }

  // Walks every frame in one segment file, threading sequence and predecessor
  // hash through `chain` across file boundaries. A sealed segment must end
  // exactly on a frame boundary — trailing bytes are an interior break. Only
  // the live segment may end in a torn tail, which is truncated exactly as
  // the pre-segmentation store truncated the wal.v2 tail. Returns the byte
  // length of the valid prefix (the live append offset after recovery).
  async #scanSegmentFrames (handle, size, label, sealed, chain, onFrame) {
    let offset = 0
    while (offset < size) {
      const remaining = size - offset
      if (remaining < WAL_HEADER_BYTES) {
        if (sealed) throw new BlindWalIntegrityError(`${label} ends inside a frame header`)
        await this.#truncateTornTail(offset)
        break
      }
      const header = b4a.alloc(WAL_HEADER_BYTES)
      if (await readAtMost(handle, header, offset) !== WAL_HEADER_BYTES) {
        if (sealed) throw new BlindWalIntegrityError(`${label} frame header changed while it was read`)
        await this.#truncateTornTail(offset)
        break
      }
      const inspected = inspectBlindWalFrameV2Header(header, this.maximumWalPayloadBytes)
      if (remaining < inspected.totalLength) {
        if (sealed) throw new BlindWalIntegrityError(`${label} ends inside a frame`)
        await this.#truncateTornTail(offset)
        break
      }
      const frameBytes = b4a.alloc(inspected.totalLength)
      b4a.copy(header, frameBytes, 0)
      if (await readAtMost(handle, frameBytes.subarray(WAL_HEADER_BYTES), offset + WAL_HEADER_BYTES) !==
          inspected.totalLength - WAL_HEADER_BYTES) {
        if (sealed) throw new BlindWalIntegrityError(`${label} frame changed while it was read`)
        await this.#truncateTornTail(offset)
        break
      }
      const frame = decodeBlindWalFrameV2(
        frameBytes,
        chain.expectedSequence,
        // At a pruned boundary the first retained frame's predecessor is not
        // retained; the checkpoint anchor pins that link instead (see
        // #recover), so the decode check passes the frame's own declared
        // predecessor for exactly this one frame.
        chain.expectedPreviousWalHash === null ? inspected.previousWalHash : chain.expectedPreviousWalHash,
        this.durabilityContinuityHash,
        this.maximumWalPayloadBytes
      )
      if (frame.mapGeneration !== this.mapGeneration || !b4a.equals(frame.ownerFenceTokenHash, this.ownerFenceTokenHash)) {
        throw new BlindWalIntegrityError('WAL bucket-map generation or writer fence does not match this writer')
      }
      await onFrame(frame)
      offset += inspected.totalLength
    }
    return offset
  }

  async #truncateTornTail (offset) {
    await this.handle.truncate(offset)
    await this.handle.sync()
    await syncDirectory(this.controlDirectory)
  }

  async append (value) {
    if (!this.handle || !this.opened) throw new Error('transaction store is not open')
    if (this.closing) throw new Error('transaction store is closing')
    if (this.poisoned) throw new BlindWalIntegrityError('transaction store requires recovery after an interrupted WAL append')
    return this.#enqueueWalCommit(value, null, null)
  }

  async appendAndApply (value, applyFrame, options = {}) {
    if (!this.handle || !this.opened) throw new Error('transaction store is not open')
    if (this.closing) throw new Error('transaction store is closing')
    if (this.poisoned) throw new BlindWalIntegrityError('transaction store requires recovery after an interrupted WAL append')
    if (typeof applyFrame !== 'function') throw new TypeError('applyFrame must be a function')
    const prewriteFence = options.prewriteFence == null ? null : options.prewriteFence
    if (prewriteFence != null && typeof prewriteFence !== 'function') {
      throw new TypeError('prewriteFence must be a synchronous function')
    }
    return this.#enqueueWalCommit(value, applyFrame, prewriteFence)
  }

  // WAL group commit (Phase 1). Admission rule: a commit group is the exact
  // set of append requests queued on `walCommitQueue` at the moment a drain
  // turn begins. The first queued request schedules the drain on a microtask
  // (so callers in the same event-loop turn are admitted together); each turn
  // snapshots the queue with splice(0) and commits that snapshot under one
  // 'wal' stripe hold (the same KeyLockTable key serializes withWalBarrier
  // and close). There is deliberately no timer and no wait-for-more
  // window: batching emerges because new requests pile up while the previous
  // group's datasync is in flight. A lone appender therefore always forms a
  // one-member group — one write plus one datasync, with frame bytes
  // identical to the pre-group-commit store.
  #enqueueWalCommit (value, applyFrame, prewriteFence) {
    const commit = new Promise((resolve, reject) => {
      this.walCommitQueue.push({ value, applyFrame, prewriteFence, resolve, reject })
    })
    this.#scheduleWalCommitDrain()
    return commit
  }

  #scheduleWalCommitDrain () {
    if (this.walCommitDrainActive) return
    this.walCommitDrainActive = true
    Promise.resolve().then(() => this.#drainWalCommits())
  }

  async #drainWalCommits () {
    try {
      while (this.walCommitQueue.length > 0) {
        const group = this.walCommitQueue.splice(0)
        try {
          await this.locks.with(['\u0000wal'], () => this.#commitWalGroup(group))
        } catch (error) {
          // #commitWalGroup settles every member itself and never throws; this
          // guard only covers a stripe-level failure, which poisons the store
          // identically to a commit-phase failure.
          this.poisoned = true
          for (const member of group) member.reject(error)
        }
      }
    } finally {
      // The flag flips synchronously with the final queue check: an enqueue
      // racing this turn either was admitted by the loop above or observes
      // the cleared flag and schedules a fresh drain. The re-check covers an
      // enqueue that slipped in after the last admission but before this
      // finally ran.
      this.walCommitDrainActive = false
      if (this.walCommitQueue.length > 0) this.#scheduleWalCommitDrain()
    }
  }

  // One group per stripe hold:
  //   1. per member, in admission order: synchronous prewriteFence, then
  //      encode, chaining sequence/previousWalHash locally so the group's
  //      frames are contiguous and hash-chained in the order they were
  //      admitted. A fence or bounds failure ejects only that member —
  //      pre-write failures never poison, exactly as in the serial path.
  //   2. segment rollover when the group would cross walSegmentMaxBytes:
  //      seal the live segment (rename + directory sync), open a fresh live
  //      segment, re-base the group's write offsets. Never splits a group.
  //   3. per frame, in order: positional write plus the per-frame
  //      `wal:after-write` fault with that frame's own sequence.
  //   4. ONE datasync for the whole group. fsync-before-ack is load-bearing:
  //      no member resolves before this completes.
  //   5. per frame, in order: `wal:after-sync` fault, decode-verify
  //      self-check, walOffset/walSequence/walHash advance, applyFrame,
  //      resolve — the same per-frame completion order a serial appender
  //      observes today.
  // Poison semantics: any seal/write/sync/fault/apply failure poisons the
  // store.
  async #commitWalGroup (group) {
    if (!this.handle || !this.opened) {
      for (const member of group) member.reject(new Error('transaction store is not open'))
      return
    }
    if (this.closing) {
      for (const member of group) member.reject(new Error('transaction store is closing'))
      return
    }
    if (this.poisoned) {
      for (const member of group) {
        member.reject(new BlindWalIntegrityError('transaction store requires recovery after an interrupted WAL append'))
      }
      return
    }
    const frames = []
    let sequence = this.walSequence
    let previousWalHash = this.walHash
    let offset = this.walOffset
    for (const member of group) {
      let completeFrame = null
      const memberSequence = sequence + 1n
      try {
        if (member.prewriteFence) {
          const fence = member.prewriteFence()
          if (fence && typeof fence.then === 'function') {
            throw new TypeError('prewriteFence must not return a promise')
          }
        }
        completeFrame = encodeWalFrame({
          type: member.value.type,
          sequence: memberSequence,
          transactionId: member.value.transactionId,
          virtualBucket: member.value.virtualBucket,
          mapGeneration: this.mapGeneration,
          ownerFenceTokenHash: this.ownerFenceTokenHash,
          durabilityContinuityHash: this.durabilityContinuityHash,
          previousWalHash,
          payload: member.value.payload
        }, this.maximumWalPayloadBytes)
      } catch (error) {
        member.reject(error)
        continue
      }
      frames.push({ member, completeFrame, sequence: memberSequence, offset })
      sequence = memberSequence
      previousWalHash = frameHash(completeFrame)
      offset += completeFrame.byteLength
    }
    if (frames.length === 0) return
    // Segment rollover (Phase 3): evaluated only between groups, after every
    // earlier group's datasync, so a group never straddles a segment
    // boundary. An empty live segment never rolls.
    if (this.walOffset > 0 && offset - this.walOffset > 0 &&
        this.walOffset + (offset - this.walOffset) > this.walSegmentMaxBytes) {
      try {
        await this.#sealLiveSegment()
      } catch (error) {
        // A seal failure leaves the WAL handle state unknown; poison exactly
        // like a commit-phase failure and settle every member.
        this.poisoned = true
        rejectWalGroupAsPoisoned(frames, -1, error)
        return
      }
      let rebased = 0
      for (const entry of frames) {
        entry.offset = rebased
        rebased += entry.completeFrame.byteLength
      }
    }
    let failedIndex = -1
    let failure = null
    for (let index = 0; index < frames.length; index++) {
      const entry = frames[index]
      try {
        await writeAll(this.handle, entry.completeFrame, entry.offset)
        await this.#fault('wal:after-write', { sequence: entry.sequence, byteLength: entry.completeFrame.byteLength })
      } catch (error) {
        failedIndex = index
        failure = error
        break
      }
    }
    if (failure) {
      this.poisoned = true
      rejectWalGroupAsPoisoned(frames, failedIndex, failure)
      return
    }
    try {
      await this.#syncWal()
    } catch (error) {
      // The one sync genuinely belongs to every member of the group.
      this.poisoned = true
      for (const entry of frames) entry.member.reject(error)
      return
    }
    for (let index = 0; index < frames.length; index++) {
      const entry = frames[index]
      let decoded = null
      try {
        await this.#fault('wal:after-sync', { sequence: entry.sequence, byteLength: entry.completeFrame.byteLength })
        decoded = decodeBlindWalFrameV2(
          entry.completeFrame,
          entry.sequence,
          this.walHash,
          this.durabilityContinuityHash,
          this.maximumWalPayloadBytes
        )
      } catch (error) {
        this.poisoned = true
        rejectWalGroupAsPoisoned(frames, index, error)
        return
      }
      this.walOffset += entry.completeFrame.byteLength
      this.walSequence = entry.sequence
      this.walHash = decoded.walHash
      if (entry.member.applyFrame) {
        try {
          await entry.member.applyFrame(decoded)
        } catch (error) {
          this.poisoned = true
          rejectWalGroupAsPoisoned(frames, index, error)
          return
        }
      }
      entry.member.resolve(decoded)
    }
  }

  // fdatasync-class durability for WAL frames (Phase 1). POSIX requires
  // fdatasync to flush every metadata item needed to retrieve the data
  // afterwards, and an extending append's st_size update is exactly such
  // metadata (per the fdatasync man page a change to st_size requires a
  // metadata flush), so recovery after a crash still observes every
  // acknowledged byte — the same guarantee LevelDB/RocksDB rely on for their
  // WALs on Linux. Size-changing WAL preallocation (truncate to fixed extents
  // with a full sync on extension) is deliberately NOT used here: recovery is
  // fail-closed and size-authoritative, so a preallocated zero tail would
  // read as an interior break and refuse to open, and block-level
  // preallocation that keeps st_size (fallocate KEEP_SIZE / F_PREALLOCATE) is
  // not exposed by node:fs. Extent preallocation remains a Phase 3 fleet task
  // alongside the store-format authority.
  async #syncWal () {
    if (typeof this.handle.datasync === 'function') return this.handle.datasync()
    return this.handle.sync()
  }

  // Seals the live segment and opens a fresh one. The previous group commit
  // already datasynced every byte of the live segment, so the seal itself is
  // name metadata: close, atomic same-directory rename to the sealed name,
  // directory sync, then create the replacement live segment (O_EXCL — a
  // pre-existing wal.v2 at this point is an interior anomaly) and sync file
  // plus directory so the new live name is durable before any frame lands in
  // it. Every crash window is recoverable: before the rename the old live
  // segment is intact; after it the sealed segment is intact and recovery
  // recreates the missing live segment; the frame hash chain never observes
  // the boundary.
  async #sealLiveSegment () {
    const firstSequence = this.liveSegmentFirstSequence
    const lastSequence = this.walSequence
    if (lastSequence < firstSequence) return
    const name = walSealedSegmentName(firstSequence, lastSequence)
    const sealedPath = path.join(this.controlDirectory, name)
    const sealedBytes = this.walOffset
    await this.handle.close()
    this.handle = null
    await fs.rename(this.walPath, sealedPath)
    await syncDirectory(this.controlDirectory)
    await this.#fault('wal:after-segment-seal', { firstSequence, lastSequence, byteLength: sealedBytes })
    this.handle = await fs.open(
      this.walPath,
      FS_CONSTANTS.O_RDWR | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL | FS_CONSTANTS.O_APPEND | FS_CONSTANTS.O_NOFOLLOW,
      0o600
    )
    const [fileStat, pathStat] = await Promise.all([this.handle.stat(), fs.lstat(this.walPath)])
    if (pathStat.isSymbolicLink() || !sameInode(fileStat, pathStat)) {
      throw new BlindWalIntegrityError('WAL path and opened inode disagree')
    }
    assertOwnedPrivateFile(fileStat, 'WAL file')
    await this.handle.sync()
    await syncDirectory(this.controlDirectory)
    await this.#fault('wal:after-segment-rollover', { firstSequence: lastSequence + 1n })
    this.sealedWalSegments.push(Object.freeze({ name, firstSequence, lastSequence }))
    this.liveSegmentFirstSequence = lastSequence + 1n
    this.walOffset = 0
  }

  // Checkpoint-anchored WAL pruning (Phase 3). A sealed segment is prunable
  // only when BOTH bounds hold: its last sequence is covered by the
  // checkpoint anchor (lastSequence <= anchor.sequence, with the anchor
  // frame itself verified against the retained chain before anything is
  // deleted) and every frame in it is older than the spent-marker horizon
  // (lastSequence < retainFromSequence, the oldest WAL sequence a still-
  // needed spend/terminal marker may live at). Deletion is write-then-
  // delete ordered by construction — the checkpoint and its manifest CAS
  // are durable before prune is called — and proceeds oldest-first with a
  // directory sync per segment, so a crash mid-prune leaves a contiguous
  // retained prefix whose anchor still validates at the next open. Pruning
  // never touches the live segment.
  async pruneWalSegments (options = {}) {
    if (!this.handle || !this.opened) throw new Error('transaction store is not open')
    if (this.closing) throw new Error('transaction store is closing')
    if (this.poisoned) throw new BlindWalIntegrityError('transaction store requires recovery before WAL pruning')
    if (!options || typeof options !== 'object' || Array.isArray(options)) {
      throw new TypeError('WAL prune options must be an object')
    }
    const allowed = new Set(['checkpointAnchor', 'retainFromSequence'])
    const unknown = Object.keys(options).find(key => !allowed.has(key))
    if (unknown) throw new TypeError(`WAL prune options contain unknown field ${unknown}`)
    const anchor = normalizeWalAnchorValue(options.checkpointAnchor, 'checkpointAnchor')
    const retainFromSequence = asU64(options.retainFromSequence, 'retainFromSequence')
    if (retainFromSequence === 0n) throw new TypeError('retainFromSequence must be nonzero')
    return this.locks.with(['\u0000wal'], async () => {
      if (!this.handle || !this.opened) throw new Error('transaction store is not open')
      if (this.closing) throw new Error('transaction store is closing')
      if (this.poisoned) throw new BlindWalIntegrityError('transaction store requires recovery before WAL pruning')
      if (anchor.sequence > this.walSequence) {
        throw new BlindWalIntegrityError('WAL prune checkpoint anchor is ahead of the WAL head')
      }
      await this.#verifyWalPruneAnchor(anchor)
      const pruned = []
      for (const segment of this.sealedWalSegments) {
        if (segment.lastSequence > anchor.sequence || segment.lastSequence >= retainFromSequence) continue
        try {
          await fs.unlink(path.join(this.controlDirectory, segment.name))
        } catch (error) {
          // A crash mid-prune may already have deleted the file; a retried
          // prune treats the missing segment as already pruned.
          if (!error || error.code !== 'ENOENT') throw error
        }
        await syncDirectory(this.controlDirectory)
        await this.#fault('wal:after-segment-prune', {
          name: segment.name,
          firstSequence: segment.firstSequence,
          lastSequence: segment.lastSequence
        })
        pruned.push(segment)
      }
      if (pruned.length > 0) {
        this.sealedWalSegments = this.sealedWalSegments.filter(segment => !pruned.includes(segment))
      }
      return Object.freeze({
        checkpointSequence: anchor.sequence,
        retainFromSequence,
        prunedSegments: Object.freeze(pruned.map(segment => Object.freeze({
          name: segment.name,
          firstSequence: segment.firstSequence,
          lastSequence: segment.lastSequence
        })))
      })
    })
  }

  // Verifies the prune anchor frame against the retained chain: the frame at
  // anchor.sequence must still be retained and must hash to anchor.hash.
  // O(1) when the anchor is the current head; otherwise one bounded scan of
  // exactly the segment that contains the anchor frame.
  async #verifyWalPruneAnchor (anchor) {
    if (anchor.sequence === this.walSequence) {
      if (!b4a.equals(this.walHash, anchor.hash)) {
        throw new BlindWalIntegrityError('WAL prune checkpoint anchor hash mismatch')
      }
      return
    }
    let target
    if (anchor.sequence >= this.liveSegmentFirstSequence) {
      target = Object.freeze({ name: WAL_LIVE_SEGMENT_NAME, firstSequence: this.liveSegmentFirstSequence })
    } else {
      target = this.sealedWalSegments.find(segment =>
        segment.firstSequence <= anchor.sequence && anchor.sequence <= segment.lastSequence)
    }
    if (!target) {
      throw new BlindWalIntegrityError('WAL prune checkpoint anchor frame is not retained')
    }
    const chain = {
      expectedSequence: target.firstSequence,
      expectedPreviousWalHash: null
    }
    let verified = false
    const onFrame = async (frame) => {
      if (frame.sequence === anchor.sequence) {
        if (!b4a.equals(frame.walHash, anchor.hash)) {
          throw new BlindWalIntegrityError('WAL prune checkpoint anchor hash mismatch')
        }
        verified = true
      }
      chain.expectedSequence = frame.sequence + 1n
      chain.expectedPreviousWalHash = frame.walHash
    }
    if (anchor.sequence >= this.liveSegmentFirstSequence) {
      await this.#scanSegmentFrames(
        this.handle, this.walOffset, 'live WAL segment', true, chain, onFrame)
    } else {
      await this.#replaySealedWalSegment(target, chain, onFrame)
    }
    if (!verified) throw new BlindWalIntegrityError('WAL prune checkpoint anchor frame is not retained')
  }

  async withLocks (keys, callback) {
    if (!Array.isArray(keys) || keys.length === 0 || keys.some(key => typeof key !== 'string' || key.length === 0)) {
      throw new TypeError('lock keys must be a non-empty string array')
    }
    return this.locks.with(keys, callback)
  }

  async withWalBarrier (callback) {
    if (!this.handle || !this.opened) throw new Error('transaction store is not open')
    if (this.closing) throw new Error('transaction store is closing')
    if (this.poisoned) throw new BlindWalIntegrityError('transaction store requires recovery before a WAL barrier')
    if (typeof callback !== 'function') throw new TypeError('WAL barrier callback must be a function')
    return this.locks.with(['\u0000wal'], async () => {
      if (!this.handle || !this.opened) throw new Error('transaction store is not open')
      if (this.closing) throw new Error('transaction store is closing')
      if (this.poisoned) throw new BlindWalIntegrityError('transaction store requires recovery before a WAL barrier')
      const lease = TRANSACTION_STORE_SESSION_LEASES.get(this)
      if (lease) await verifyBlindStoreSessionTransactionLease(lease, this.root)
      const barrierAuthority = mintWalBarrierAuthority(this, lease)
      const anchor = mintWalAnchor(this, barrierAuthority)
      try {
        return await callback(barrierAuthority, anchor)
      } finally {
        ACTIVE_WAL_ANCHORS.delete(anchor)
        ACTIVE_WAL_BARRIER_AUTHORITIES.delete(barrierAuthority)
      }
    })
  }

  virtualBucket (serviceTag, primaryLocator) {
    boundedInteger(serviceTag, 1, 255, 'serviceTag')
    primaryLocator = bytes(primaryLocator, 32, 'primaryLocator')
    const digest = createHmac('sha256', this.partitionKey)
      .update(b4a.from([serviceTag]))
      .update(primaryLocator)
      .digest()
    return digest[0] * 0x100 + digest[1]
  }

  async stageOpaque (options = {}) {
    const finish = this.#beginOpaqueOperation()
    try {
      const expectedLength = boundedInteger(options.expectedLength, 1, this.maximumOpaqueBodyBytes, 'expectedLength')
      const expectedHash = bytes(options.expectedHash, 32, 'expectedHash', { nonzero: true })
      const deadlineUnixMillis = asU64(options.deadlineUnixMillis, 'deadlineUnixMillis')
      const nowUnixMillis = typeof options.nowUnixMillis === 'function' ? options.nowUnixMillis : () => BigInt(Date.now())
      const signal = options.signal || null
      const temporaryId = randomNonzero32()
      const objectId = randomNonzero32()
      const token = randomNonzero32()
      const temporaryPath = path.join(this.stagingDirectory, `${b4a.toString(temporaryId, 'hex')}.part`)
      const handle = await fs.open(
        temporaryPath,
        FS_CONSTANTS.O_WRONLY | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL | FS_CONSTANTS.O_NOFOLLOW,
        0o600
      )
      const openedStat = await handle.stat()
      assertOwnedPrivateFile(openedStat, 'staging file')
      const hasher = hashStream()
      let total = 0
      let completed = false
      try {
        const iterator = sourceIterator(options.source)
        while (true) {
          const next = await nextBeforeDeadline(iterator, deadlineUnixMillis, nowUnixMillis, signal)
          if (!next || next.done) break
          const inputChunk = next.value
          const chunk = bytes(inputChunk, null, 'opaque body chunk')
          if (chunk.byteLength === 0) continue
          if (total + chunk.byteLength > expectedLength) {
            throw new BlindOpaqueBodyError('opaque body exceeds its declared length', 'BODY_LENGTH_MISMATCH', true)
          }
          for (let offset = 0; offset < chunk.byteLength; offset += this.maximumChunkBytes) {
            if (signal && signal.aborted) throw new BlindOpaqueBodyError('opaque body input was aborted', 'BODY_INTERRUPTED', false)
            if (asU64(nowUnixMillis(), 'nowUnixMillis') > deadlineUnixMillis) {
              throw new BlindOpaqueBodyError('opaque body deadline expired', 'BODY_DEADLINE_EXPIRED', true)
            }
            const piece = chunk.subarray(offset, Math.min(offset + this.maximumChunkBytes, chunk.byteLength))
            await writeAll(handle, piece, total)
            hasher.update(piece)
            total += piece.byteLength
          }
        }
        completed = true
        if (total !== expectedLength) {
          throw new BlindOpaqueBodyError('opaque body is shorter than its declared length', 'BODY_LENGTH_MISMATCH', true)
        }
        const digest = hasher.digest()
        if (!b4a.equals(digest, expectedHash)) {
          throw new BlindOpaqueBodyError('opaque body hash does not match its declaration', 'BODY_HASH_MISMATCH', true)
        }
        if (signal && signal.aborted) {
          throw new BlindOpaqueBodyError('opaque body input was aborted before final staging fsync',
            'BODY_INTERRUPTED', false)
        }
        await handle.sync()
        if (signal && signal.aborted) {
          throw new BlindOpaqueBodyError('opaque body input was aborted after final staging fsync',
            'BODY_INTERRUPTED', false)
        }
        await this.#fault('body:after-fsync', { temporaryPath, objectId, byteLength: total })
        if (signal && signal.aborted) {
          throw new BlindOpaqueBodyError('opaque body input was aborted before staging authority release',
            'BODY_INTERRUPTED', false)
        }
        const staged = {
          token: b4a.from(token),
          temporaryPath,
          objectId: b4a.from(objectId),
          byteLength: total,
          hash: b4a.from(digest),
          dev: openedStat.dev,
          ino: openedStat.ino
        }
        this.staged.set(b4a.toString(token, 'hex'), staged)
        return Object.freeze({ token: b4a.from(token) })
      } catch (error) {
        let failure = error
        if (!completed && !(failure instanceof BlindOpaqueBodyError)) {
          const interrupted = new BlindOpaqueBodyError('opaque body source failed before completion', 'BODY_INTERRUPTED', false)
          interrupted.cause = failure
          failure = interrupted
        }
        await handle.close().catch(() => {})
        await fs.unlink(temporaryPath).catch(() => {})
        throw failure
      } finally {
        await handle.close().catch(() => {})
      }
    } finally {
      finish()
    }
  }

  async publishOpaque (staged, virtualBucket) {
    const finish = this.#beginOpaqueOperation()
    try {
      if (!staged || typeof staged !== 'object') throw new TypeError('staged opaque body is invalid')
      const token = bytes(staged.token, 32, 'staging token', { nonzero: true })
      const internal = this.staged.get(b4a.toString(token, 'hex'))
      if (!internal) throw new BlindWalIntegrityError('staging token is unknown, forged, or already consumed')
      boundedInteger(virtualBucket, 0, 0xffff, 'virtualBucket')
      const objectId = internal.objectId
      const bucketName = virtualBucket.toString(16).padStart(4, '0')
      const directory = path.join(this.blobDirectory, bucketName)
      await createPrivateDirectory(directory, this.blobDirectory, 'blob bucket directory')
      const stagingStat = await fs.lstat(internal.temporaryPath)
      if (stagingStat.isSymbolicLink() || stagingStat.dev !== internal.dev || stagingStat.ino !== internal.ino) {
        throw new BlindWalIntegrityError('staging inode changed before publication')
      }
      assertOwnedPrivateFile(stagingStat, 'staging file')
      const objectName = `${b4a.toString(objectId, 'hex')}.blob`
      const destination = path.join(directory, objectName)
      try {
        await fs.link(internal.temporaryPath, destination)
      } catch (error) {
        if (error && error.code === 'EEXIST') throw new BlindWalIntegrityError('random opaque object ID collision refused overwrite')
        throw error
      }
      await syncDirectory(directory)
      await this.#fault('body:after-publish', { destination, objectId, virtualBucket })
      await fs.unlink(internal.temporaryPath)
      await syncDirectory(this.stagingDirectory)
      this.staged.delete(b4a.toString(token, 'hex'))
      return { objectId: b4a.from(objectId), virtualBucket, byteLength: internal.byteLength, hash: b4a.from(internal.hash) }
    } finally {
      finish()
    }
  }

  async discardStaged (staged) {
    const finish = this.#beginOpaqueOperation()
    try {
      if (!staged || typeof staged !== 'object') return false
      const token = bytes(staged.token, 32, 'staging token', { nonzero: true })
      const key = b4a.toString(token, 'hex')
      const internal = this.staged.get(key)
      if (!internal) return false
      this.staged.delete(key)
      await fs.unlink(internal.temporaryPath).catch(() => {})
      await syncDirectory(this.stagingDirectory)
      return true
    } finally {
      finish()
    }
  }

  opaquePath (reference) {
    if (!reference || typeof reference !== 'object') throw new TypeError('blob reference must be an object')
    const virtualBucket = boundedInteger(reference.virtualBucket, 0, 0xffff, 'blob virtualBucket')
    const objectId = bytes(reference.objectId, 32, 'blob objectId', { nonzero: true })
    return path.join(
      this.blobDirectory,
      virtualBucket.toString(16).padStart(4, '0'),
      `${b4a.toString(objectId, 'hex')}.blob`
    )
  }

  async inspectOpaque (reference, expectedLength, expectedHash, options = {}) {
    const finish = this.#beginOpaqueOperation()
    try {
      expectedLength = boundedInteger(expectedLength, 1, this.maximumOpaqueBodyBytes, 'expectedLength')
      expectedHash = bytes(expectedHash, 32, 'expectedHash', { nonzero: true })
      const objectPath = this.opaquePath(reference)
      let handle
      try {
        handle = await fs.open(objectPath, FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW)
      } catch (error) {
        if (error && (error.code === 'ENOENT' || error.code === 'ELOOP')) return { ok: false, reason: 'MISSING' }
        throw error
      }
      try {
        const before = await handle.stat()
        try {
          assertOwnedPrivateFile(before, 'opaque blob')
        } catch {
          return { ok: false, reason: 'INODE' }
        }
        if (before.size !== expectedLength) return { ok: false, reason: 'LENGTH' }
        if (options.hash === false) return { ok: true, reason: null }
        const hasher = hashStream()
        const output = options.returnBytes === true ? b4a.alloc(expectedLength) : null
        const chunk = output || b4a.alloc(Math.min(this.maximumChunkBytes, expectedLength))
        let offset = 0
        while (offset < expectedLength) {
          const length = Math.min(this.maximumChunkBytes, expectedLength - offset)
          const view = output ? output.subarray(offset, offset + length) : chunk.subarray(0, length)
          const count = await readAtMost(handle, view, offset)
          if (count !== length) return { ok: false, reason: 'LENGTH' }
          hasher.update(view)
          offset += count
        }
        const after = await handle.stat()
        if (!sameInode(before, after) || after.size !== expectedLength) return { ok: false, reason: 'INODE' }
        const observedHash = hasher.digest()
        return b4a.equals(observedHash, expectedHash)
          ? { ok: true, reason: null, observedHash, bytes: output }
          : { ok: false, reason: 'HASH', observedHash }
      } finally {
        await handle.close()
      }
    } finally {
      finish()
    }
  }

  async readOpaque (reference, expectedLength, expectedHash) {
    const inspection = await this.inspectOpaque(reference, expectedLength, expectedHash, { returnBytes: true })
    if (!inspection.ok) {
      throw new BlindWalIntegrityError(`opaque body integrity failure: ${inspection.reason}`, inspection.reason)
    }
    return inspection.bytes
  }

  async removeOpaque (reference) {
    const finish = this.#beginOpaqueOperation()
    try {
      const objectPath = this.opaquePath(reference)
      try {
        await fs.unlink(objectPath)
        await syncDirectory(path.dirname(objectPath))
        return true
      } catch (error) {
        if (error && error.code === 'ENOENT') return false
        throw error
      }
    } finally {
      finish()
    }
  }

  async cleanupStaging (maximumEntries = 10000) {
    const finish = this.#beginOpaqueOperation()
    try {
      return await this.#cleanupStaging(maximumEntries)
    } finally {
      finish()
    }
  }

  async #cleanupStaging (maximumEntries = 10000) {
    boundedInteger(maximumEntries, 1, 100000, 'maximum staging cleanup entries')
    let removed = 0
    const directory = await fs.opendir(this.stagingDirectory)
    for await (const entry of directory) {
      if (removed >= maximumEntries) throw new BlindStoreBoundsError('staging orphan count exceeds the recovery bound', 'BUSY')
      if (!entry.isFile() || !/^[0-9a-f]{64}\.part$/.test(entry.name)) {
        throw new BlindWalIntegrityError('unexpected entry in the opaque staging directory')
      }
      await fs.unlink(path.join(this.stagingDirectory, entry.name))
      removed++
    }
    if (removed > 0) await syncDirectory(this.stagingDirectory)
    return removed
  }

  async cleanupOrphans (liveReferences, maximumEntries = 100000) {
    const finish = this.#beginOpaqueOperation()
    try {
      if (!(liveReferences instanceof Set)) throw new TypeError('liveReferences must be a Set')
      boundedInteger(maximumEntries, 1, 1000000, 'maximum orphan scan entries')
      let scanned = 0
      let removed = 0
      const bucketDirectory = await fs.opendir(this.blobDirectory)
      for await (const bucket of bucketDirectory) {
        if (!bucket.isDirectory() || !/^[0-9a-f]{4}$/.test(bucket.name)) {
          throw new BlindWalIntegrityError('unexpected entry in the opaque blob directory')
        }
        const directory = path.join(this.blobDirectory, bucket.name)
        await verifyPrivateDirectory(directory, 'blob bucket directory')
        let bucketRemoved = 0
        const entries = await fs.opendir(directory)
        for await (const entry of entries) {
          scanned++
          if (scanned > maximumEntries) throw new BlindStoreBoundsError('blob orphan scan exceeds its recovery bound', 'BUSY')
          if (!entry.isFile() || !/^[0-9a-f]{64}\.blob$/.test(entry.name)) {
            throw new BlindWalIntegrityError('unexpected object in the opaque blob directory')
          }
          const key = `${bucket.name}/${entry.name.slice(0, 64)}`
          if (!liveReferences.has(key)) {
            await fs.unlink(path.join(directory, entry.name))
            removed++
            bucketRemoved++
          }
        }
        if (bucketRemoved > 0) await syncDirectory(directory)
      }
      return { scanned, removed }
    } finally {
      finish()
    }
  }

  referenceKey (reference) {
    const objectPath = this.opaquePath(reference)
    return `${path.basename(path.dirname(objectPath))}/${path.basename(objectPath, '.blob')}`
  }

  newTransactionId () {
    return randomNonzero32()
  }

  async #fault (point, context) {
    if (this.faultInjector) await this.faultInjector(point, context)
  }

  #beginOpaqueOperation () {
    if (this.destroyed) throw new Error('transaction store secrets were destroyed on close')
    if (this.closing) throw new Error('transaction store is closing')
    if (!this.opened || !this.handle) throw new Error('transaction store is not open')
    this.activeOpaqueOperations++
    let active = true
    return () => {
      if (!active) return
      active = false
      this.activeOpaqueOperations--
      if (this.activeOpaqueOperations === 0) {
        for (const resolve of this.opaqueDrainWaiters.splice(0)) resolve()
      }
    }
  }

  async #waitForOpaqueDrain () {
    if (this.activeOpaqueOperations === 0) return
    await new Promise(resolve => this.opaqueDrainWaiters.push(resolve))
  }

  close () {
    if (this.closePromise) return this.closePromise
    this.closing = true
    const opening = this.openPromise
    const closing = (async () => {
      try {
        if (opening) await opening.catch(() => {})
        await this.#waitForOpaqueDrain()
        return await this.locks.with(['\u0000wal'], async () => {
          const activeStoreSessionLease = TRANSACTION_STORE_SESSION_LEASES.get(this)
          this.opened = false
          if (!this.handle && !this.storeLockHandle && !activeStoreSessionLease) {
            OPEN_STORE_ROOTS.delete(this.root)
            return
          }
          const handle = this.handle
          const storeLockHandle = this.storeLockHandle
          const storeSessionTransactionLease = activeStoreSessionLease
          this.handle = null
          this.storeLockHandle = null
          TRANSACTION_STORE_SESSION_LEASES.set(this, null)
          try {
            if (handle) await handle.close()
          } finally {
            try {
              if (storeLockHandle) releaseExclusiveFileLock(storeLockHandle)
            } finally {
              if (storeLockHandle) await storeLockHandle.close().catch(() => {})
              if (storeSessionTransactionLease) storeSessionTransactionLease.release()
              OPEN_STORE_ROOTS.delete(this.root)
            }
          }
        })
      } finally {
        this.partitionKey.fill(0)
        this.ownerFenceTokenHash.fill(0)
        this.durabilityContinuityHash.fill(0)
        for (const value of this.staged.values()) {
          value.token.fill(0)
          value.objectId.fill(0)
          value.hash.fill(0)
        }
        this.staged.clear()
        this.destroyed = true
      }
    })()
    this.closePromise = closing.finally(() => {
      this.closing = false
      this.closePromise = null
    })
    return this.closePromise
  }
}

export const BLIND_WAL_LAYOUT = Object.freeze({
  magic: 'HRWL',
  version: WAL_VERSION,
  fileName: WAL_LIVE_SEGMENT_NAME,
  liveSegmentFileName: WAL_LIVE_SEGMENT_NAME,
  sealedSegmentFileName: WAL_SEALED_SEGMENT_NAME.source,
  sealedSegmentNameExample: 'wal-0000000000000001-00000000000000f0.v2',
  segmented: true,
  defaultSegmentMaxBytes: DEFAULT_WAL_SEGMENT_MAX_BYTES,
  minimumSegmentMaxBytes: MIN_WAL_SEGMENT_MAX_BYTES,
  maximumSegmentMaxBytes: MAX_WAL_SEGMENT_MAX_BYTES,
  checkpointAnchoredRecovery: true,
  pruningSupported: true,
  headerBytes: WAL_HEADER_BYTES,
  checksumBytes: WAL_CHECKSUM_BYTES,
  minimumFrameBytes: WAL_MIN_FRAME_BYTES,
  checksumDomain: b4a.toString(WAL_CHECKSUM_DOMAIN, 'ascii'),
  frameHashDomain: b4a.toString(WAL_HASH_DOMAIN, 'ascii'),
  authority: 'hiverelay-blind-store-format-authority-v1.draft.cenc'
})
