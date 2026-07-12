import fs from 'node:fs/promises'
import { constants as FS_CONSTANTS } from 'node:fs'
import path from 'node:path'
import { randomBytes } from 'node:crypto'
import b4a from 'b4a'
import {
  blindLocalCheckpointV1,
  blindStoreManifestV1,
  decodeCanonical,
  encodeCanonical,
  localCheckpointHash
} from '@hiverelay/blind-protocol'
import {
  renameFileNoReplace,
  renameFileNoReplacePlatformSupported
} from '@hiverelay/blind-peercred'
import { verifyBlindControlStateSnapshotFile } from './control-snapshot-stream.js'
import {
  advanceBlindManifestSnapshot,
  blindStoreManifestHash,
  verifyBlindManifestSnapshot
} from './manifest-store.js'
import {
  verifyBlindWalAnchor,
  verifyBlindWalBarrierAuthority
} from './transaction-store.js'
import { verifyBlindStoreSessionTransactionLease } from './store-session.js'
import { verifyBlindCellControlSnapshotSemanticResult } from './cell-control-snapshot.js'
import {
  verifyBlindCellInboxCoreControlSnapshotSemanticResult,
  verifyBlindCellInboxCoreControlSnapshotSemanticVerifier
} from './cell-inbox-core-control-snapshot.js'

const CHECKPOINT_FINAL = /^checkpoint-([0-9a-f]{64})\.v1$/
const SNAPSHOT_FINAL = /^snapshot-([0-9a-f]{64})\.v1$/
const CHECKPOINT_TEMP = /^\.checkpoint-([0-9a-f]{64})\.v1\.([0-9a-f]{32})\.tmp$/
const SNAPSHOT_TEMP = /^\.snapshot-([0-9a-f]{64})\.v1\.([0-9a-f]{32})\.tmp$/
const MAX_CHECKPOINT_HEADER_BYTES = 4096
const MAX_U64 = (1n << 64n) - 1n
const ZERO32 = b4a.alloc(32)
const ACTIVE_CHECKPOINT_DIRECTORIES = new Set()
const UNSAFE_TEST_SEMANTIC_VERIFIER = Symbol('unsafe test-only checkpoint semantic verifier')
const ACTIVE_RECOVERY_VALIDATIONS = new WeakSet()
const RECOVERY_VALIDATION_STATE = new WeakMap()
const ACTIVE_SNAPSHOT_SEMANTIC_AUTHORITIES = new WeakSet()
const SNAPSHOT_SEMANTIC_AUTHORITY_STATE = new WeakMap()

const CURRENT_BINDING_FIELDS = Object.freeze([
  'relayPublicKey',
  'storeId',
  'durabilityProfileId',
  'durabilityContinuityHash',
  'durabilityProfileHash',
  'formatMajor',
  'formatMinor',
  'storeFormatHash',
  'specHash',
  'abiHash',
  'mapGeneration',
  'bucketMapHash',
  'writerEpoch',
  'writerFenceTokenHash'
])

// Migration, profile rotation, map transition, and writer-fence rotation do not
// yet have a closed transition authority in this draft. Until they do, every
// persisted binding remains byte-for-byte fixed across the checkpoint chain.
const IMMUTABLE_PREDECESSOR_FIELDS = CURRENT_BINDING_FIELDS

const MANIFEST_CAS_OWNED_FIELDS = new Set([
  'checkpointWalSequence',
  'checkpointHash',
  'epochFloor',
  'descriptorSequenceFloor',
  'descriptorHashFloor',
  'previousManifestHash',
  'manifestRevision',
  'mac'
])

export class BlindLocalCheckpointIntegrityError extends Error {
  constructor (message, code = 'RECOVERY_GAP_READ_ONLY') {
    super(message)
    this.name = 'BlindLocalCheckpointIntegrityError'
    this.code = code
  }
}

function canonicalDirectory (value) {
  if (typeof value !== 'string' || value.includes('\0') || !path.isAbsolute(value) || path.normalize(value) !== value) {
    throw new TypeError('controlDirectory must be a canonical absolute path')
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

function sameValue (left, right) {
  if (left && typeof left.byteLength === 'number') {
    return right && typeof right.byteLength === 'number' && b4a.equals(left, right)
  }
  return left === right
}

function copyValue (value, field) {
  if (value && typeof value.byteLength === 'number') return b4a.from(asBytes(value, null, field))
  if (typeof value === 'number' || typeof value === 'bigint') return value
  throw new TypeError(`${field} has an unsupported binding type`)
}

function checkpointName (hash) {
  return `checkpoint-${b4a.toString(asBytes(hash, 32, 'checkpoint hash', true), 'hex')}.v1`
}

function snapshotName (hash) {
  return `snapshot-${b4a.toString(asBytes(hash, 32, 'snapshot hash', true), 'hex')}.v1`
}

function assertPrivateDirectory (stat, field) {
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new BlindLocalCheckpointIntegrityError(`${field} is not a directory`)
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
    throw new BlindLocalCheckpointIntegrityError(`${field} is not owned by the daemon uid`)
  }
  if ((stat.mode & 0o700) !== 0o700 || (stat.mode & 0o077) !== 0) {
    throw new BlindLocalCheckpointIntegrityError(`${field} permissions are not private`)
  }
}

function assertPrivateFile (stat, field, expectedLinks = 1) {
  if (!stat.isFile() || stat.isSymbolicLink() || (expectedLinks != null && stat.nlink !== expectedLinks)) {
    throw new BlindLocalCheckpointIntegrityError(`${field} is not a private regular file with the expected link count`)
  }
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
    throw new BlindLocalCheckpointIntegrityError(`${field} is not owned by the daemon uid`)
  }
  if ((stat.mode & 0o600) !== 0o600 || (stat.mode & 0o077) !== 0) {
    throw new BlindLocalCheckpointIntegrityError(`${field} permissions are not private`)
  }
}

function sameInode (left, right) {
  return left.dev === right.dev && left.ino === right.ino
}

function immutableFileState (stat) {
  return Object.freeze({
    dev: stat.dev,
    ino: stat.ino,
    size: stat.size,
    mode: stat.mode,
    uid: stat.uid,
    gid: stat.gid,
    nlink: stat.nlink,
    mtimeMs: stat.mtimeMs,
    ctimeMs: stat.ctimeMs
  })
}

function sameFileState (left, right) {
  return sameInode(left, right) && left.size === right.size && left.mode === right.mode &&
    left.uid === right.uid && left.gid === right.gid && left.nlink === right.nlink &&
    left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs
}

async function syncDirectory (directory) {
  const handle = await fs.open(directory, FS_CONSTANTS.O_RDONLY)
  try {
    await handle.sync()
  } finally {
    await handle.close()
  }
}

async function readAll (handle, size, field) {
  const output = b4a.alloc(size)
  let offset = 0
  while (offset < size) {
    const { bytesRead } = await handle.read(output, offset, size - offset, offset)
    if (bytesRead === 0) throw new BlindLocalCheckpointIntegrityError(`${field} ended before its opened size`)
    offset += bytesRead
  }
  return output
}

async function comparePrivateFiles (leftPath, rightPath, expectedLength, field) {
  let left
  let right
  try {
    left = await fs.open(leftPath, FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW)
    right = await fs.open(rightPath, FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW)
    const [leftBefore, rightBefore, leftLinked, rightLinked] = await Promise.all([
      left.stat(), right.stat(), fs.lstat(leftPath), fs.lstat(rightPath)
    ])
    for (const [stat, label] of [[leftBefore, `${field} source`], [rightBefore, `${field} target`],
      [leftLinked, `${field} linked source`], [rightLinked, `${field} linked target`]]) {
      assertPrivateFile(stat, label)
    }
    if (!sameInode(leftBefore, leftLinked) || !sameInode(rightBefore, rightLinked) ||
        leftBefore.size !== expectedLength || rightBefore.size !== expectedLength) {
      throw new BlindLocalCheckpointIntegrityError(`${field} file identity or length differs`)
    }
    const leftChunk = b4a.alloc(64 * 1024)
    const rightChunk = b4a.alloc(64 * 1024)
    let offset = 0
    while (offset < expectedLength) {
      const length = Math.min(leftChunk.byteLength, expectedLength - offset)
      const [leftRead, rightRead] = await Promise.all([
        left.read(leftChunk, 0, length, offset),
        right.read(rightChunk, 0, length, offset)
      ])
      if (leftRead.bytesRead !== length || rightRead.bytesRead !== length ||
          !b4a.equals(leftChunk.subarray(0, length), rightChunk.subarray(0, length))) {
        throw new BlindLocalCheckpointIntegrityError(`${field} has conflicting bytes`)
      }
      offset += length
    }
    const [leftAfter, rightAfter] = await Promise.all([left.stat(), right.stat()])
    if (!sameInode(leftBefore, leftAfter) || !sameInode(rightBefore, rightAfter) ||
        leftAfter.size !== expectedLength || rightAfter.size !== expectedLength) {
      throw new BlindLocalCheckpointIntegrityError(`${field} changed while it was compared`)
    }
    return true
  } finally {
    if (left) await left.close().catch(() => {})
    if (right) await right.close().catch(() => {})
  }
}

function sourceIterator (source) {
  if (source && typeof source.byteLength === 'number') {
    return (async function * () { yield asBytes(source, null, 'snapshotBytes') })()
  }
  if (source && typeof source[Symbol.asyncIterator] === 'function') return source[Symbol.asyncIterator]()
  if (source && typeof source[Symbol.iterator] === 'function') {
    return (async function * () { yield * source })()
  }
  throw new TypeError('snapshotBytes must be bytes or an iterable of byte chunks')
}

async function nextSourceChunk (iterator, deadlineUnixMillis, signal, field) {
  if (signal && signal.aborted) {
    throw new BlindLocalCheckpointIntegrityError(`${field} was aborted`, 'BLIND_CHECKPOINT_SOURCE_ABORTED')
  }
  const remaining = deadlineUnixMillis - Date.now()
  if (remaining <= 0) {
    throw new BlindLocalCheckpointIntegrityError(`${field} deadline expired`, 'BLIND_CHECKPOINT_SOURCE_DEADLINE')
  }
  let timer = null
  let abort = null
  const contenders = [Promise.resolve().then(() => iterator.next())]
  contenders.push(new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(new BlindLocalCheckpointIntegrityError(
      `${field} deadline expired while awaiting a chunk`,
      'BLIND_CHECKPOINT_SOURCE_DEADLINE'
    )), Math.min(remaining, 0x7fffffff))
  }))
  if (signal) {
    contenders.push(new Promise((resolve, reject) => {
      abort = () => reject(new BlindLocalCheckpointIntegrityError(
        `${field} was aborted while awaiting a chunk`,
        'BLIND_CHECKPOINT_SOURCE_ABORTED'
      ))
      signal.addEventListener('abort', abort, { once: true })
    }))
  }
  try {
    return await Promise.race(contenders)
  } finally {
    if (timer) clearTimeout(timer)
    if (signal && abort) signal.removeEventListener('abort', abort)
  }
}

function requireManifestSnapshot (value, controlDirectory) {
  if (!value || typeof value !== 'object' || !value.manifest) throw new TypeError('manifestSnapshot is required')
  verifyBlindManifestSnapshot(value, controlDirectory)
  const bytes = b4a.from(asBytes(value.bytes, null, 'manifestSnapshot.bytes'))
  const hash = b4a.from(asBytes(value.hash, 32, 'manifestSnapshot.hash', true))
  let decoded
  try {
    decoded = decodeCanonical(blindStoreManifestV1, bytes, { copyBytes: true })
    if (!b4a.equals(encodeCanonical(blindStoreManifestV1, decoded), bytes) ||
        !b4a.equals(encodeCanonical(blindStoreManifestV1, value.manifest), bytes)) {
      throw new Error('canonical bytes and manifest object differ')
    }
  } catch (error) {
    throw new BlindLocalCheckpointIntegrityError(`manifest snapshot is not canonical: ${error.message}`)
  }
  if (!b4a.equals(blindStoreManifestHash(bytes), hash)) {
    throw new BlindLocalCheckpointIntegrityError('manifest snapshot hash does not match its canonical bytes')
  }
  return {
    bytes,
    hash,
    manifest: decoded
  }
}

function verifiedAnchorValue (value, label) {
  if (!value || typeof value !== 'object') throw new TypeError(`${label} is required`)
  const sequence = asU64(value.sequence, `${label}.sequence`)
  const hash = asBytes(value.hash, 32, `${label}.hash`, true)
  if (sequence === 0n) throw new TypeError(`${label}.sequence must be nonzero`)
  return Object.freeze({ sequence, hash: b4a.from(hash) })
}

function assertFieldEquality (left, right, fields, label) {
  for (const field of fields) {
    if (!sameValue(left[field], right[field])) {
      throw new BlindLocalCheckpointIntegrityError(`${label} ${field} does not match`)
    }
  }
}

function manifestCheckpointUpdates (header, headerHash) {
  return Object.freeze({
    checkpointWalSequence: header.coveredWalSequence,
    checkpointHash: b4a.from(headerHash),
    epochFloor: header.epochFloor,
    descriptorSequenceFloor: header.descriptorSequenceFloor,
    descriptorHashFloor: b4a.from(header.descriptorHashFloor)
  })
}

function copyCheckpointHeader (header) {
  return decodeCanonical(blindLocalCheckpointV1,
    encodeCanonical(blindLocalCheckpointV1, header), { copyBytes: true })
}

function mintRecoveryValidation (
  store,
  lease,
  manifestSnapshot,
  current,
  snapshot,
  predecessors,
  checkpointFileState,
  snapshotFileState,
  predecessorFileStates
) {
  const snapshotSemanticAuthority = Object.freeze({ root: store.root })
  const state = Object.freeze({
    store,
    generation: store.generation,
    root: store.root,
    lease,
    manifestSnapshot,
    manifestHash: b4a.from(manifestSnapshot.hash),
    checkpointHeaderHash: b4a.from(current.hash),
    checkpointSequence: current.header.coveredWalSequence,
    checkpointWalHash: b4a.from(current.header.coveredWalHash),
    mapGeneration: current.header.mapGeneration,
    writerFenceTokenHash: b4a.from(current.header.writerFenceTokenHash),
    durabilityContinuityHash: b4a.from(current.header.durabilityContinuityHash),
    snapshotValidation: snapshot,
    snapshotSemanticAuthority,
    predecessorCount: predecessors.length,
    checkpointPath: current.target,
    checkpointFileState,
    snapshotPath: snapshot.filePath,
    snapshotFileState,
    predecessorFileStates
  })
  const validation = {}
  Object.defineProperties(validation, {
    root: { enumerable: true, value: state.root },
    manifestSnapshot: { enumerable: true, value: state.manifestSnapshot },
    manifestHash: { enumerable: true, get: () => b4a.from(state.manifestHash) },
    checkpointHeaderHash: { enumerable: true, get: () => b4a.from(state.checkpointHeaderHash) },
    checkpointSequence: { enumerable: true, value: state.checkpointSequence },
    checkpointWalHash: { enumerable: true, get: () => b4a.from(state.checkpointWalHash) },
    mapGeneration: { enumerable: true, value: state.mapGeneration },
    writerFenceTokenHash: { enumerable: true, get: () => b4a.from(state.writerFenceTokenHash) },
    durabilityContinuityHash: { enumerable: true, get: () => b4a.from(state.durabilityContinuityHash) },
    snapshotSemanticAuthority: { enumerable: true, value: state.snapshotSemanticAuthority },
    predecessorCount: { enumerable: true, value: state.predecessorCount }
  })
  Object.freeze(validation)
  ACTIVE_RECOVERY_VALIDATIONS.add(validation)
  RECOVERY_VALIDATION_STATE.set(validation, state)
  ACTIVE_SNAPSHOT_SEMANTIC_AUTHORITIES.add(snapshotSemanticAuthority)
  SNAPSHOT_SEMANTIC_AUTHORITY_STATE.set(snapshotSemanticAuthority, Object.freeze({
    store,
    generation: store.generation,
    root: store.root,
    lease,
    validation,
    snapshotValidation: snapshot
  }))
  return validation
}

export async function verifyBlindLocalCheckpointRecoveryValidation (
  validation,
  expectedRoot,
  lease,
  manifestSnapshot
) {
  const root = canonicalDirectory(expectedRoot)
  if (!validation || typeof validation !== 'object' || !ACTIVE_RECOVERY_VALIDATIONS.has(validation)) {
    throw new BlindLocalCheckpointIntegrityError(
      'checkpoint recovery validation is forged, expired, or unsupported',
      'BLIND_CHECKPOINT_RECOVERY_VALIDATION_INVALID'
    )
  }
  const state = RECOVERY_VALIDATION_STATE.get(validation)
  if (!state || state.root !== root || state.lease !== lease || state.manifestSnapshot !== manifestSnapshot ||
      state.store.root !== root || !state.store.opened || !state.store.validationOnly || state.store.closing ||
      state.store.closed || state.store.generation !== state.generation ||
      validation.root !== root || validation.manifestSnapshot !== manifestSnapshot ||
      !b4a.equals(validation.manifestHash, state.manifestHash) ||
      !b4a.equals(validation.checkpointHeaderHash, state.checkpointHeaderHash) ||
      validation.checkpointSequence !== state.checkpointSequence ||
      !b4a.equals(validation.checkpointWalHash, state.checkpointWalHash) ||
      validation.mapGeneration !== state.mapGeneration ||
      !b4a.equals(validation.writerFenceTokenHash, state.writerFenceTokenHash) ||
      !b4a.equals(validation.durabilityContinuityHash, state.durabilityContinuityHash) ||
      validation.snapshotSemanticAuthority !== state.snapshotSemanticAuthority ||
      validation.predecessorCount !== state.predecessorCount) {
    throw new BlindLocalCheckpointIntegrityError(
      'checkpoint recovery validation binding is stale or invalid',
      'BLIND_CHECKPOINT_RECOVERY_VALIDATION_INVALID'
    )
  }
  verifyBlindManifestSnapshot(manifestSnapshot, state.store.controlDirectory)
  await verifyBlindStoreSessionTransactionLease(lease, root)
  const [checkpointLinked, snapshotLinked] = await Promise.all([
    fs.lstat(state.checkpointPath),
    fs.lstat(state.snapshotPath)
  ])
  assertPrivateFile(checkpointLinked, 'checkpoint recovery validation header')
  assertPrivateFile(snapshotLinked, 'checkpoint recovery validation snapshot')
  if (!sameFileState(checkpointLinked, state.checkpointFileState) ||
      !sameFileState(snapshotLinked, state.snapshotFileState)) {
    throw new BlindLocalCheckpointIntegrityError(
      'checkpoint or snapshot changed after recovery validation',
      'BLIND_CHECKPOINT_RECOVERY_VALIDATION_INVALID'
    )
  }
  for (const predecessor of state.predecessorFileStates) {
    const linked = await fs.lstat(predecessor.path)
    assertPrivateFile(linked, 'checkpoint recovery validation predecessor')
    if (!sameFileState(linked, predecessor.fileState)) {
      throw new BlindLocalCheckpointIntegrityError(
        'checkpoint predecessor changed after recovery validation',
        'BLIND_CHECKPOINT_RECOVERY_VALIDATION_INVALID'
      )
    }
  }
  return true
}

export async function verifyBlindLocalCheckpointSnapshotSemanticAuthority (
  authority,
  recoveryValidation,
  expectedRoot,
  lease
) {
  const root = canonicalDirectory(expectedRoot)
  if (!authority || typeof authority !== 'object' || !ACTIVE_SNAPSHOT_SEMANTIC_AUTHORITIES.has(authority)) {
    throw new BlindLocalCheckpointIntegrityError(
      'snapshot semantic authority is forged, expired, or unsupported',
      'BLIND_CHECKPOINT_SNAPSHOT_SEMANTIC_AUTHORITY_INVALID'
    )
  }
  const state = SNAPSHOT_SEMANTIC_AUTHORITY_STATE.get(authority)
  const validationState = RECOVERY_VALIDATION_STATE.get(recoveryValidation)
  if (!state || !validationState || state.validation !== recoveryValidation ||
      validationState.snapshotSemanticAuthority !== authority || state.root !== root || state.lease !== lease ||
      authority.root !== root || state.store !== validationState.store || state.generation !== validationState.generation ||
      state.snapshotValidation !== validationState.snapshotValidation) {
    throw new BlindLocalCheckpointIntegrityError(
      'snapshot semantic authority binding is invalid',
      'BLIND_CHECKPOINT_SNAPSHOT_SEMANTIC_AUTHORITY_INVALID'
    )
  }
  await verifyBlindLocalCheckpointRecoveryValidation(
    recoveryValidation,
    root,
    lease,
    validationState.manifestSnapshot
  )
  const snapshotValidation = state.snapshotValidation
  const expected = {
    relayPublicKey: snapshotValidation.header.relayPublicKey,
    storeId: snapshotValidation.header.storeId,
    durabilityContinuityHash: snapshotValidation.header.durabilityContinuityHash,
    walSequence: snapshotValidation.header.walSequence,
    walHash: snapshotValidation.header.walHash,
    entryCount: snapshotValidation.entryCount
  }
  const semanticResult = state.store.semanticVerifierKind === 'cell-inbox-core'
    ? verifyBlindCellInboxCoreControlSnapshotSemanticResult(snapshotValidation.semanticEcho, expected)
    : verifyBlindCellControlSnapshotSemanticResult(snapshotValidation.semanticEcho, expected)
  const expectedComplete = state.store.semanticVerifierKind === 'cell-inbox-core'
    ? semanticResult.cellInboxCoreRetryComplete === true && semanticResult.coreComplete === false &&
      semanticResult.allFamilyComplete === false
    : semanticResult.cellComplete === true
  if (semanticResult !== snapshotValidation.semanticEcho || !expectedComplete ||
      semanticResult.recoveryVerified !== true || semanticResult.publicationAuthorized !== false ||
      semanticResult.productionComplete !== false) {
    throw new BlindLocalCheckpointIntegrityError(
      'snapshot semantic authority is not a recovery-only complete Cell result',
      'BLIND_CHECKPOINT_SNAPSHOT_SEMANTIC_AUTHORITY_INVALID'
    )
  }
  return true
}

export class BlindLocalCheckpointStore {
  constructor (options = {}) {
    this.controlDirectory = canonicalDirectory(options.controlDirectory)
    this.root = path.dirname(this.controlDirectory)
    if (path.basename(this.controlDirectory) !== 'control' ||
        path.join(this.root, 'control') !== this.controlDirectory) {
      throw new TypeError('controlDirectory must be the exact control child of its StoreSession root')
    }
    if (!renameFileNoReplacePlatformSupported()) {
      throw new BlindLocalCheckpointIntegrityError(
        'this platform has no atomic rename-no-replace primitive',
        'BLIND_RENAME_NOREPLACE_UNSUPPORTED'
      )
    }
    this.maximumSnapshotBytes = boundedInteger(
      options.maximumSnapshotBytes == null ? 256 * 1024 * 1024 : options.maximumSnapshotBytes,
      1024,
      0x7fffffff,
      'maximumSnapshotBytes'
    )
    this.maximumEntries = boundedInteger(
      options.maximumEntries == null ? 0x1000000 : options.maximumEntries,
      0,
      0x1000000,
      'maximumEntries'
    )
    this.maximumArtifacts = boundedInteger(
      options.maximumArtifacts == null ? 4096 : options.maximumArtifacts,
      4,
      100000,
      'maximumArtifacts'
    )
    this.maximumSnapshotSourceChunks = boundedInteger(
      options.maximumSnapshotSourceChunks == null ? 65536 : options.maximumSnapshotSourceChunks,
      1,
      1000000,
      'maximumSnapshotSourceChunks'
    )
    this.maximumSnapshotPublicationMillis = boundedInteger(
      options.maximumSnapshotPublicationMillis == null ? 120000 : options.maximumSnapshotPublicationMillis,
      1000,
      3600000,
      'maximumSnapshotPublicationMillis'
    )
    if (!options.expectedBindings || typeof options.expectedBindings !== 'object' || Array.isArray(options.expectedBindings)) {
      throw new TypeError('expectedBindings must be an object')
    }
    for (const field of CURRENT_BINDING_FIELDS) {
      if (!Object.prototype.hasOwnProperty.call(options.expectedBindings, field)) {
        throw new TypeError(`expectedBindings.${field} is required`)
      }
    }
    this.expectedBindings = Object.freeze(Object.fromEntries(CURRENT_BINDING_FIELDS.map(field => [
      field,
      copyValue(options.expectedBindings[field], `expectedBindings.${field}`)
    ])))
    if (options.snapshotSemanticVerifier != null) {
      this.semanticVerifier = verifyBlindCellInboxCoreControlSnapshotSemanticVerifier(
        options.snapshotSemanticVerifier
      )
      this.semanticVerifierKind = 'cell-inbox-core'
      this.unsafeTestOnlySemanticVerifier = false
    } else if (typeof options[UNSAFE_TEST_SEMANTIC_VERIFIER] !== 'function') {
      throw new BlindLocalCheckpointIntegrityError(
        'a branded Cell+Inbox+Core snapshot semantic authority is required',
        'BLIND_CHECKPOINT_SEMANTIC_AUTHORITY_UNIMPLEMENTED'
      )
    } else {
      this.semanticVerifier = options[UNSAFE_TEST_SEMANTIC_VERIFIER]
      this.semanticVerifierKind = 'cell-test-only'
      this.unsafeTestOnlySemanticVerifier = true
    }
    if (options.faultInjector != null && typeof options.faultInjector !== 'function') {
      throw new TypeError('faultInjector must be a function')
    }
    this.faultInjector = options.faultInjector || null
    this.opened = false
    this.validationOnly = false
    this.closing = false
    this.closed = false
    this.generation = 0
    this.openPromise = null
    this.closePromise = null
    this.serial = Promise.resolve()
    this.validatedCurrent = null
  }

  async _fault (point, context = {}) {
    if (this.faultInjector) await this.faultInjector(point, Object.freeze({ controlDirectory: this.controlDirectory, ...context }))
  }

  open (options = {}) {
    if (this.closed) return Promise.reject(new Error('local checkpoint store is closed'))
    if (this.opened || this.openPromise) return Promise.reject(new Error('local checkpoint store is already opening or open'))
    if (!options || typeof options !== 'object' || Array.isArray(options) ||
        Object.keys(options).some(key => key !== 'validationOnly') ||
        (options.validationOnly != null && typeof options.validationOnly !== 'boolean')) {
      return Promise.reject(new TypeError('checkpoint open options may contain only validationOnly'))
    }
    const opening = this._open(options)
    this.openPromise = opening
    opening.catch(() => {
      if (this.openPromise === opening && !this.closed) this.openPromise = null
    })
    return opening
  }

  async _open (options) {
    if (ACTIVE_CHECKPOINT_DIRECTORIES.has(this.controlDirectory)) {
      throw new BlindLocalCheckpointIntegrityError('checkpoint control directory already has an active in-process owner')
    }
    ACTIVE_CHECKPOINT_DIRECTORIES.add(this.controlDirectory)
    let opened = false
    try {
      const stat = await fs.lstat(this.controlDirectory)
      assertPrivateDirectory(stat, 'checkpoint control directory')
      if (await fs.realpath(this.controlDirectory) !== this.controlDirectory) {
        throw new BlindLocalCheckpointIntegrityError('checkpoint control directory is not its canonical realpath')
      }
      let artifacts = 0
      const directory = await fs.opendir(this.controlDirectory)
      for await (const entry of directory) {
        const name = entry.name
        const recognized = CHECKPOINT_FINAL.test(name) || SNAPSHOT_FINAL.test(name) ||
          CHECKPOINT_TEMP.test(name) || SNAPSHOT_TEMP.test(name)
        const reservedPrefix = name.startsWith('checkpoint-') || name.startsWith('snapshot-') ||
          name.startsWith('.checkpoint-') || name.startsWith('.snapshot-')
        if (reservedPrefix && !recognized) {
          throw new BlindLocalCheckpointIntegrityError(`malformed checkpoint artifact name ${name}`)
        }
        if (!recognized) continue
        artifacts++
        if (artifacts > this.maximumArtifacts) {
          throw new BlindLocalCheckpointIntegrityError('checkpoint artifact bound exceeded')
        }
        assertPrivateFile(await fs.lstat(path.join(this.controlDirectory, name)), `checkpoint artifact ${name}`)
      }
      await this._fault('checkpoint:open:after-directory-inspection', { artifacts })
      if (this.closing || this.closed) throw new Error('local checkpoint store closed while opening')
      this.opened = true
      this.validationOnly = options.validationOnly === true
      this.generation++
      this.closePromise = null
      opened = true
      return this
    } finally {
      if (!opened) ACTIVE_CHECKPOINT_DIRECTORIES.delete(this.controlDirectory)
    }
  }

  _serialized (operation) {
    const result = this.serial.then(operation)
    this.serial = result.catch(() => {})
    return result
  }

  _assertAccepting () {
    if (!this.opened) throw new Error('local checkpoint store is not open')
    if (this.closing) throw new Error('local checkpoint store is closing')
  }

  _assertMutable () {
    this._assertAccepting()
    if (this.validationOnly) {
      const error = new Error('local checkpoint store was opened in validation-only mode')
      error.code = 'BLIND_CHECKPOINT_VALIDATION_ONLY'
      throw error
    }
  }

  async _verifyBarrierAuthority (authority) {
    await verifyBlindWalBarrierAuthority(authority, this.root)
  }

  async _readHeader (expectedHash) {
    expectedHash = asBytes(expectedHash, 32, 'expected checkpoint hash', true)
    const target = path.join(this.controlDirectory, checkpointName(expectedHash))
    const linked = await fs.lstat(target)
    assertPrivateFile(linked, 'local checkpoint header')
    let handle
    try {
      handle = await fs.open(target, FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW)
      const opened = await handle.stat()
      assertPrivateFile(opened, 'opened local checkpoint header')
      if (!sameInode(linked, opened)) throw new BlindLocalCheckpointIntegrityError('checkpoint header path and opened inode disagree')
      if (opened.size < 256 || opened.size > MAX_CHECKPOINT_HEADER_BYTES) {
        throw new BlindLocalCheckpointIntegrityError('checkpoint header size is outside its closed bound')
      }
      const bytes = await readAll(handle, opened.size, 'checkpoint header')
      let header
      try {
        header = decodeCanonical(blindLocalCheckpointV1, bytes, { copyBytes: true })
        if (!b4a.equals(encodeCanonical(blindLocalCheckpointV1, header), bytes)) throw new Error('round trip differs')
      } catch (error) {
        throw new BlindLocalCheckpointIntegrityError(`checkpoint header is not canonical: ${error.message}`)
      }
      const hash = localCheckpointHash(bytes)
      if (!b4a.equals(hash, expectedHash)) throw new BlindLocalCheckpointIntegrityError('checkpoint header hash does not match its filename/reference')
      const [openedAfter, linkedAfter] = await Promise.all([handle.stat(), fs.lstat(target)])
      assertPrivateFile(openedAfter, 'opened local checkpoint header')
      assertPrivateFile(linkedAfter, 'local checkpoint header')
      if (!sameInode(openedAfter, linkedAfter) || openedAfter.size !== opened.size ||
          openedAfter.mtimeMs !== opened.mtimeMs || openedAfter.ctimeMs !== opened.ctimeMs) {
        throw new BlindLocalCheckpointIntegrityError('checkpoint header changed while it was read')
      }
      return Object.freeze({ target, bytes, hash, header: Object.freeze(header) })
    } finally {
      if (handle) await handle.close().catch(() => {})
    }
  }

  _assertCurrentBindings (manifest, header, headerHash) {
    if (manifest.checkpointWalSequence === 0n || manifest.mapGeneration === 0n || manifest.writerEpoch === 0n ||
        isZero(manifest.checkpointHash)) {
      throw new BlindLocalCheckpointIntegrityError('manifest checkpoint, map generation, and writer epoch must be nonzero')
    }
    assertFieldEquality(manifest, header, CURRENT_BINDING_FIELDS, 'manifest/checkpoint')
    assertFieldEquality(header, this.expectedBindings, CURRENT_BINDING_FIELDS, 'launch/checkpoint')
    if (manifest.checkpointWalSequence !== header.coveredWalSequence || !b4a.equals(manifest.checkpointHash, headerHash)) {
      throw new BlindLocalCheckpointIntegrityError('manifest checkpoint anchor does not match the checkpoint header')
    }
    if (manifest.epochFloor !== header.epochFloor ||
        manifest.descriptorSequenceFloor !== header.descriptorSequenceFloor ||
        !b4a.equals(manifest.descriptorHashFloor, header.descriptorHashFloor)) {
      throw new BlindLocalCheckpointIntegrityError('manifest floors do not match the checkpoint header')
    }
  }

  async _validatePredecessors (current) {
    const output = []
    let child = current
    while (child.header.checkpointRevision > 1n) {
      if (output.length + 1 >= this.maximumArtifacts) {
        throw new BlindLocalCheckpointIntegrityError('checkpoint predecessor chain exceeds its configured artifact bound')
      }
      const previousHash = asBytes(child.header.previousCheckpointHash, 32, 'previousCheckpointHash', true)
      const predecessor = await this._readHeader(previousHash)
      if (predecessor.header.checkpointRevision + 1n !== child.header.checkpointRevision) {
        throw new BlindLocalCheckpointIntegrityError('checkpoint predecessor revision is not exactly adjacent')
      }
      assertFieldEquality(predecessor.header, child.header, IMMUTABLE_PREDECESSOR_FIELDS, 'checkpoint predecessor identity')
      if (predecessor.header.coveredWalSequence >= child.header.coveredWalSequence) {
        throw new BlindLocalCheckpointIntegrityError('checkpoint predecessor WAL sequence did not strictly advance')
      }
      if (predecessor.header.epochFloor > child.header.epochFloor ||
          predecessor.header.descriptorSequenceFloor > child.header.descriptorSequenceFloor) {
        throw new BlindLocalCheckpointIntegrityError('checkpoint predecessor floors roll back')
      }
      if (predecessor.header.descriptorSequenceFloor === child.header.descriptorSequenceFloor &&
          !b4a.equals(predecessor.header.descriptorHashFloor, child.header.descriptorHashFloor)) {
        throw new BlindLocalCheckpointIntegrityError('equal descriptor floors carry different descriptor hashes')
      }
      output.push(predecessor)
      child = predecessor
    }
    if (child.header.previousCheckpointHash != null) {
      throw new BlindLocalCheckpointIntegrityError('checkpoint revision 1 unexpectedly has a predecessor')
    }
    return Object.freeze(output)
  }

  async _validateSnapshotFile (target, header) {
    return verifyBlindControlStateSnapshotFile({
      filePath: target,
      maximumSnapshotBytes: this.maximumSnapshotBytes,
      maximumEntries: this.maximumEntries,
      expectedByteLength: header.snapshotByteLength,
      expectedHash: header.snapshotHash,
      expected: {
        relayPublicKey: header.relayPublicKey,
        storeId: header.storeId,
        durabilityContinuityHash: header.durabilityContinuityHash,
        walSequence: header.coveredWalSequence,
        walHash: header.coveredWalHash
      },
      semanticVerifier: input => this.semanticVerifier(Object.freeze({
        checkpointHeader: Object.freeze(copyCheckpointHeader(header)),
        ...input
      }))
    })
  }

  async _validateSnapshot (header) {
    return this._validateSnapshotFile(
      path.join(this.controlDirectory, snapshotName(header.snapshotHash)),
      header
    )
  }

  validateManifestCheckpoint (options = {}) {
    this._assertAccepting()
    return this._serialized(async () => {
      await this._verifyBarrierAuthority(options.walBarrierAuthority)
      await verifyBlindWalAnchor(options.verifiedWalAnchor, this.root, options.walBarrierAuthority)
      const manifestSnapshot = requireManifestSnapshot(options.manifestSnapshot, this.controlDirectory)
      const walAnchor = verifiedAnchorValue(options.verifiedWalAnchor, 'verifiedWalAnchor')
      const current = await this._readHeader(manifestSnapshot.manifest.checkpointHash)
      this._assertCurrentBindings(manifestSnapshot.manifest, current.header, current.hash)
      if (current.header.coveredWalSequence !== walAnchor.sequence ||
          !b4a.equals(current.header.coveredWalHash, walAnchor.hash)) {
        throw new BlindLocalCheckpointIntegrityError('checkpoint header does not match the WAL anchor verified under the writer lock')
      }
      const predecessors = await this._validatePredecessors(current)
      const snapshot = await this._validateSnapshot(current.header)
      await verifyBlindWalAnchor(options.verifiedWalAnchor, this.root, options.walBarrierAuthority)
      const validated = Object.freeze({
        manifestSnapshot,
        header: current.header,
        headerBytes: b4a.from(current.bytes),
        headerHash: b4a.from(current.hash),
        snapshot,
        predecessors,
        historicalSnapshotsValidated: false,
        walAnchor
      })
      this.validatedCurrent = Object.freeze({
        manifestHash: b4a.from(manifestSnapshot.hash),
        headerHash: b4a.from(current.hash),
        headerRevision: current.header.checkpointRevision,
        walSequence: current.header.coveredWalSequence,
        walHash: b4a.from(current.header.coveredWalHash)
      })
      return validated
    })
  }

  validateManifestCheckpointForRecovery (options = {}) {
    this._assertAccepting()
    if (!this.validationOnly) {
      throw new BlindLocalCheckpointIntegrityError(
        'checkpoint recovery validation requires a validation-only store',
        'BLIND_CHECKPOINT_RECOVERY_REQUIRES_VALIDATION_ONLY'
      )
    }
    return this._serialized(async () => {
      const lease = options.lease
      await verifyBlindStoreSessionTransactionLease(lease, this.root)
      const publicManifestSnapshot = options.manifestSnapshot
      const manifestSnapshot = requireManifestSnapshot(publicManifestSnapshot, this.controlDirectory)
      const current = await this._readHeader(manifestSnapshot.manifest.checkpointHash)
      this._assertCurrentBindings(manifestSnapshot.manifest, current.header, current.hash)
      const predecessors = await this._validatePredecessors(current)
      const snapshot = await this._validateSnapshot(current.header)
      const [checkpointLinked, snapshotLinked] = await Promise.all([
        fs.lstat(current.target),
        fs.lstat(snapshot.filePath)
      ])
      assertPrivateFile(checkpointLinked, 'checkpoint recovery validation header')
      assertPrivateFile(snapshotLinked, 'checkpoint recovery validation snapshot')
      const predecessorFileStates = await Promise.all(predecessors.map(async predecessor => {
        const linked = await fs.lstat(predecessor.target)
        assertPrivateFile(linked, 'checkpoint recovery validation predecessor')
        return Object.freeze({
          path: predecessor.target,
          fileState: immutableFileState(linked)
        })
      }))
      await verifyBlindStoreSessionTransactionLease(lease, this.root)
      return mintRecoveryValidation(
        this,
        lease,
        publicManifestSnapshot,
        current,
        snapshot,
        predecessors,
        immutableFileState(checkpointLinked),
        immutableFileState(snapshotLinked),
        Object.freeze(predecessorFileStates)
      )
    })
  }

  async _readExactFinal (target, expectedBytes, field) {
    const stat = await fs.lstat(target)
    assertPrivateFile(stat, field)
    if (stat.size !== expectedBytes.byteLength) throw new BlindLocalCheckpointIntegrityError(`${field} has conflicting bytes`)
    let handle
    try {
      handle = await fs.open(target, FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW)
      const opened = await handle.stat()
      assertPrivateFile(opened, field)
      if (!sameInode(stat, opened)) throw new BlindLocalCheckpointIntegrityError(`${field} path and opened inode disagree`)
      const chunk = b4a.alloc(Math.min(64 * 1024, expectedBytes.byteLength || 1))
      let offset = 0
      while (offset < expectedBytes.byteLength) {
        const length = Math.min(chunk.byteLength, expectedBytes.byteLength - offset)
        const { bytesRead } = await handle.read(chunk, 0, length, offset)
        if (bytesRead !== length ||
            !b4a.equals(chunk.subarray(0, length), expectedBytes.subarray(offset, offset + length))) {
          throw new BlindLocalCheckpointIntegrityError(`${field} has conflicting bytes`)
        }
        offset += length
      }
      const openedAfter = await handle.stat()
      if (!sameInode(opened, openedAfter) || openedAfter.size !== opened.size) {
        throw new BlindLocalCheckpointIntegrityError(`${field} changed while it was compared`)
      }
      return true
    } finally {
      if (handle) await handle.close().catch(() => {})
    }
  }

  async _installBytesNoReplace (kind, hash, source, expectedLength, publication = {}) {
    const finalName = kind === 'snapshot' ? snapshotName(hash) : checkpointName(hash)
    const target = path.join(this.controlDirectory, finalName)
    const temporary = path.join(this.controlDirectory, `.${finalName}.${randomBytes(16).toString('hex')}.tmp`)
    let handle
    let installed = false
    let written = 0
    let iterator = null
    let iteratorCompleted = false
    let sourceChunks = 0
    try {
      handle = await fs.open(temporary,
        FS_CONSTANTS.O_WRONLY | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL | FS_CONSTANTS.O_NOFOLLOW,
        0o600)
      iterator = sourceIterator(source)
      for (;;) {
        const next = await nextSourceChunk(
          iterator,
          publication.deadlineUnixMillis,
          publication.signal,
          `${kind} source`
        )
        if (next.done) {
          iteratorCompleted = true
          break
        }
        sourceChunks++
        if (sourceChunks > this.maximumSnapshotSourceChunks) {
          throw new BlindLocalCheckpointIntegrityError(`${kind} source exceeds its configured chunk bound`)
        }
        const chunk = asBytes(next.value, null, `${kind} source chunk`)
        if (chunk.byteLength === 0) continue
        if (written + chunk.byteLength > expectedLength) {
          throw new BlindLocalCheckpointIntegrityError(`${kind} source exceeds its declared length`)
        }
        let offset = 0
        while (offset < chunk.byteLength) {
          const { bytesWritten } = await handle.write(chunk, offset, chunk.byteLength - offset, written + offset)
          if (bytesWritten === 0) throw new BlindLocalCheckpointIntegrityError(`${kind} temporary write made no progress`)
          offset += bytesWritten
        }
        written += chunk.byteLength
      }
      if (written !== expectedLength) throw new BlindLocalCheckpointIntegrityError(`${kind} source does not match its declared length`)
      await this._fault(`checkpoint:${kind}:after-temp-write`, { finalName, byteLength: written })
      await handle.sync()
      const [openedTemporary, linkedTemporary] = await Promise.all([handle.stat(), fs.lstat(temporary)])
      assertPrivateFile(openedTemporary, `${kind} opened temporary`)
      assertPrivateFile(linkedTemporary, `${kind} temporary`)
      if (!sameInode(openedTemporary, linkedTemporary)) {
        throw new BlindLocalCheckpointIntegrityError(`${kind} temporary path and opened inode disagree`)
      }
      await this._fault(`checkpoint:${kind}:after-temp-sync`, { finalName, byteLength: written })
      if (typeof publication.validateTemporary === 'function') {
        await publication.validateTemporary(temporary)
        const [openedAfterValidation, linkedAfterValidation] = await Promise.all([
          handle.stat(), fs.lstat(temporary)
        ])
        assertPrivateFile(openedAfterValidation, `${kind} opened temporary`)
        assertPrivateFile(linkedAfterValidation, `${kind} temporary`)
        if (!sameInode(openedTemporary, openedAfterValidation) ||
            !sameInode(openedAfterValidation, linkedAfterValidation) ||
            openedAfterValidation.size !== openedTemporary.size) {
          throw new BlindLocalCheckpointIntegrityError(`${kind} temporary changed during pre-install validation`)
        }
      }
      installed = renameFileNoReplace(temporary, target)
      if (!installed) {
        const linkedAfterRefusal = await fs.lstat(temporary)
        assertPrivateFile(linkedAfterRefusal, `${kind} temporary`)
        if (!sameInode(openedTemporary, linkedAfterRefusal)) {
          throw new BlindLocalCheckpointIntegrityError(`${kind} temporary changed during no-replace install`)
        }
        if (source && typeof source.byteLength === 'number') {
          await this._readExactFinal(target, asBytes(source, null, `${kind} source`), `${kind} final`)
        } else {
          await comparePrivateFiles(temporary, target, expectedLength, `${kind} final`)
        }
      } else {
        const [openedAfterRename, linkedFinal] = await Promise.all([handle.stat(), fs.lstat(target)])
        assertPrivateFile(openedAfterRename, `${kind} opened final`)
        assertPrivateFile(linkedFinal, `${kind} final`)
        if (!sameInode(openedTemporary, openedAfterRename) || !sameInode(openedAfterRename, linkedFinal)) {
          throw new BlindLocalCheckpointIntegrityError(`${kind} no-replace rename did not preserve the opened inode`)
        }
      }
      await this._fault(`checkpoint:${kind}:after-no-replace-rename`, { finalName, installed })
      await syncDirectory(this.controlDirectory)
      await this._fault(`checkpoint:${kind}:after-install-directory-sync`, { finalName, installed })
      await handle.close()
      handle = null
      if (!installed) {
        await fs.unlink(temporary)
        await syncDirectory(this.controlDirectory)
        await this._fault(`checkpoint:${kind}:after-idempotent-temp-unlink-directory-sync`, { finalName })
      }
      if (source && typeof source.byteLength === 'number') {
        await this._readExactFinal(target, asBytes(source, null, `${kind} source`), `${kind} final`)
      } else {
        const finalStat = await fs.lstat(target)
        assertPrivateFile(finalStat, `${kind} final`)
        if (finalStat.size !== expectedLength) {
          throw new BlindLocalCheckpointIntegrityError(`${kind} final length changed after installation`)
        }
      }
      await this._fault(`checkpoint:${kind}:after-reopen-verify`, { finalName, installed })
      return target
    } finally {
      if (handle) await handle.close().catch(() => {})
      if (iterator && !iteratorCompleted && typeof iterator.return === 'function') {
        await Promise.resolve(iterator.return()).catch(() => {})
      }
    }
  }

  async _assertGenesisArtifactSet (expectedCheckpointHash, expectedSnapshotHash) {
    const expectedCheckpoint = checkpointName(expectedCheckpointHash)
    const expectedSnapshot = snapshotName(expectedSnapshotHash)
    for (const name of await fs.readdir(this.controlDirectory)) {
      if (CHECKPOINT_FINAL.test(name) && name !== expectedCheckpoint) {
        throw new BlindLocalCheckpointIntegrityError(
          'genesis found an unreferenced checkpoint final with a different hash'
        )
      }
      if (SNAPSHOT_FINAL.test(name) && name !== expectedSnapshot) {
        throw new BlindLocalCheckpointIntegrityError(
          'genesis found an unreferenced control snapshot final with a different hash'
        )
      }
    }
  }

  initializeGenesis (options = {}) {
    this._assertMutable()
    return this._serialized(async () => {
      await this._verifyBarrierAuthority(options.walBarrierAuthority)
      await verifyBlindWalAnchor(options.verifiedWalAnchor, this.root, options.walBarrierAuthority)
      const walAnchor = verifiedAnchorValue(options.verifiedWalAnchor, 'verifiedWalAnchor')
      let checkpointBytes
      let checkpoint
      try {
        checkpointBytes = encodeCanonical(blindLocalCheckpointV1, options.checkpoint)
        checkpoint = decodeCanonical(blindLocalCheckpointV1, checkpointBytes, { copyBytes: true })
      } catch (error) {
        throw new BlindLocalCheckpointIntegrityError(`genesis checkpoint header is not canonical: ${error.message}`)
      }
      const checkpointHash = localCheckpointHash(checkpointBytes)
      if (checkpoint.checkpointRevision !== 1n || checkpoint.previousCheckpointHash != null) {
        throw new BlindLocalCheckpointIntegrityError(
          'genesis checkpoint must be revision 1 without a predecessor'
        )
      }
      assertFieldEquality(checkpoint, this.expectedBindings, CURRENT_BINDING_FIELDS, 'genesis checkpoint/launch')
      if (checkpoint.coveredWalSequence !== walAnchor.sequence ||
          !b4a.equals(checkpoint.coveredWalHash, walAnchor.hash)) {
        throw new BlindLocalCheckpointIntegrityError(
          'genesis checkpoint does not equal the verified WAL anchor'
        )
      }
      const snapshotLength = asU64(checkpoint.snapshotByteLength, 'checkpoint.snapshotByteLength')
      if (snapshotLength > BigInt(this.maximumSnapshotBytes) || snapshotLength > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new BlindLocalCheckpointIntegrityError('genesis checkpoint snapshot length exceeds its configured bound')
      }
      await this._assertGenesisArtifactSet(checkpointHash, checkpoint.snapshotHash)
      const publication = {
        deadlineUnixMillis: Date.now() + this.maximumSnapshotPublicationMillis,
        signal: options.signal == null ? null : options.signal
      }
      let validatedSnapshot = null
      await this._installBytesNoReplace(
        'snapshot',
        checkpoint.snapshotHash,
        options.snapshotBytes,
        Number(snapshotLength),
        {
          ...publication,
          validateTemporary: async temporary => {
            validatedSnapshot = await this._validateSnapshotFile(temporary, checkpoint)
          }
        }
      )
      if (!validatedSnapshot) {
        throw new BlindLocalCheckpointIntegrityError(
          'genesis snapshot temporary was not semantically validated before installation'
        )
      }
      await this._installBytesNoReplace(
        'checkpoint', checkpointHash, checkpointBytes, checkpointBytes.byteLength, publication)
      await verifyBlindWalAnchor(options.verifiedWalAnchor, this.root, options.walBarrierAuthority)
      const installed = await this._readHeader(checkpointHash)
      if (!b4a.equals(installed.bytes, checkpointBytes)) {
        throw new BlindLocalCheckpointIntegrityError('installed genesis checkpoint differs from its canonical bytes')
      }
      return Object.freeze({
        header: Object.freeze(copyCheckpointHeader(installed.header)),
        headerBytes: b4a.from(installed.bytes),
        headerHash: b4a.from(installed.hash),
        snapshot: validatedSnapshot,
        walAnchor
      })
    })
  }

  publish (options = {}) {
    this._assertMutable()
    return this._serialized(async () => {
      await this._verifyBarrierAuthority(options.walBarrierAuthority)
      await verifyBlindWalAnchor(options.verifiedWalAnchor, this.root, options.walBarrierAuthority)
      const manifestSnapshot = requireManifestSnapshot(options.manifestSnapshot, this.controlDirectory)
      const nextWalAnchor = verifiedAnchorValue(options.verifiedWalAnchor, 'verifiedWalAnchor')
      if (!this.validatedCurrent ||
          !b4a.equals(this.validatedCurrent.manifestHash, manifestSnapshot.hash) ||
          !b4a.equals(this.validatedCurrent.headerHash, manifestSnapshot.manifest.checkpointHash)) {
        throw new BlindLocalCheckpointIntegrityError(
          'current manifest/checkpoint has not been validated under this StoreSession before publication',
          'BLIND_CHECKPOINT_STARTUP_VALIDATION_REQUIRED'
        )
      }
      const current = await this._readHeader(manifestSnapshot.manifest.checkpointHash)
      this._assertCurrentBindings(manifestSnapshot.manifest, current.header, current.hash)
      if (current.header.checkpointRevision !== this.validatedCurrent.headerRevision ||
          current.header.coveredWalSequence !== this.validatedCurrent.walSequence ||
          !b4a.equals(current.header.coveredWalHash, this.validatedCurrent.walHash)) {
        throw new BlindLocalCheckpointIntegrityError('current checkpoint changed after startup validation')
      }

      let checkpointBytes
      let checkpoint
      try {
        checkpointBytes = encodeCanonical(blindLocalCheckpointV1, options.checkpoint)
        checkpoint = decodeCanonical(blindLocalCheckpointV1, checkpointBytes, { copyBytes: true })
      } catch (error) {
        throw new BlindLocalCheckpointIntegrityError(`new checkpoint header is not canonical: ${error.message}`)
      }
      const checkpointHash = localCheckpointHash(checkpointBytes)
      if (checkpoint.checkpointRevision !== current.header.checkpointRevision + 1n ||
          checkpoint.checkpointRevision <= 1n ||
          checkpoint.previousCheckpointHash == null ||
          !b4a.equals(checkpoint.previousCheckpointHash, current.hash)) {
        throw new BlindLocalCheckpointIntegrityError('new checkpoint is not the exact adjacent successor')
      }
      assertFieldEquality(checkpoint, manifestSnapshot.manifest, CURRENT_BINDING_FIELDS, 'new checkpoint/manifest')
      assertFieldEquality(checkpoint, this.expectedBindings, CURRENT_BINDING_FIELDS, 'new checkpoint/launch')
      if (checkpoint.coveredWalSequence !== nextWalAnchor.sequence || !b4a.equals(checkpoint.coveredWalHash, nextWalAnchor.hash) ||
          checkpoint.coveredWalSequence <= current.header.coveredWalSequence) {
        throw new BlindLocalCheckpointIntegrityError('new checkpoint does not strictly advance to its verified WAL anchor')
      }
      if (checkpoint.epochFloor < current.header.epochFloor ||
          checkpoint.descriptorSequenceFloor < current.header.descriptorSequenceFloor) {
        throw new BlindLocalCheckpointIntegrityError('new checkpoint floors roll back')
      }
      if (checkpoint.descriptorSequenceFloor === current.header.descriptorSequenceFloor &&
          !b4a.equals(checkpoint.descriptorHashFloor, current.header.descriptorHashFloor)) {
        throw new BlindLocalCheckpointIntegrityError('equal descriptor floor sequence changed hash')
      }
      const snapshotLength = asU64(checkpoint.snapshotByteLength, 'checkpoint.snapshotByteLength')
      if (snapshotLength > BigInt(this.maximumSnapshotBytes) || snapshotLength > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new BlindLocalCheckpointIntegrityError('new checkpoint snapshot length exceeds its configured bound')
      }

      const publication = {
        deadlineUnixMillis: Date.now() + this.maximumSnapshotPublicationMillis,
        signal: options.signal == null ? null : options.signal
      }
      if (publication.signal != null &&
          (typeof publication.signal !== 'object' || typeof publication.signal.aborted !== 'boolean' ||
           typeof publication.signal.addEventListener !== 'function')) {
        throw new TypeError('signal must be an AbortSignal')
      }

      let validatedSnapshot = null
      await this._installBytesNoReplace(
        'snapshot',
        checkpoint.snapshotHash,
        options.snapshotBytes,
        Number(snapshotLength),
        {
          ...publication,
          validateTemporary: async temporary => {
            validatedSnapshot = await this._validateSnapshotFile(temporary, checkpoint)
          }
        }
      )
      if (!validatedSnapshot) {
        throw new BlindLocalCheckpointIntegrityError('snapshot temporary was not semantically validated before installation')
      }
      if (!b4a.equals(encodeCanonical(blindLocalCheckpointV1, checkpoint), checkpointBytes)) {
        throw new BlindLocalCheckpointIntegrityError('new checkpoint was mutated during snapshot semantic verification')
      }
      await this._installBytesNoReplace(
        'checkpoint', checkpointHash, checkpointBytes, checkpointBytes.byteLength, publication)
      const installedHeader = await this._readHeader(checkpointHash)
      if (!b4a.equals(installedHeader.bytes, checkpointBytes)) {
        throw new BlindLocalCheckpointIntegrityError('installed checkpoint header differs from the published bytes')
      }
      await verifyBlindWalAnchor(options.verifiedWalAnchor, this.root, options.walBarrierAuthority)
      await this._fault('checkpoint:before-manifest-cas', { checkpointHash })
      const updates = manifestCheckpointUpdates(installedHeader.header, checkpointHash)
      const nextManifest = await advanceBlindManifestSnapshot(
        options.manifestSnapshot,
        this.controlDirectory,
        manifestSnapshot.hash,
        updates
      )
      await verifyBlindWalAnchor(options.verifiedWalAnchor, this.root, options.walBarrierAuthority)
      await this._fault('checkpoint:after-manifest-cas', { checkpointHash })
      const verifiedManifest = requireManifestSnapshot(nextManifest, this.controlDirectory)
      this._assertCurrentBindings(verifiedManifest.manifest, installedHeader.header, checkpointHash)
      for (const field of Object.keys(manifestSnapshot.manifest)) {
        if (!MANIFEST_CAS_OWNED_FIELDS.has(field) &&
            !sameValue(verifiedManifest.manifest[field], manifestSnapshot.manifest[field])) {
          throw new BlindLocalCheckpointIntegrityError(`manifest CAS changed unrelated field ${field}`)
        }
      }
      if (verifiedManifest.manifest.manifestRevision !== manifestSnapshot.manifest.manifestRevision + 1n ||
          verifiedManifest.manifest.previousManifestHash == null ||
          !b4a.equals(verifiedManifest.manifest.previousManifestHash, manifestSnapshot.hash)) {
        throw new BlindLocalCheckpointIntegrityError('manifest CAS did not return the exact linked successor')
      }
      this.validatedCurrent = Object.freeze({
        manifestHash: b4a.from(verifiedManifest.hash),
        headerHash: b4a.from(checkpointHash),
        headerRevision: installedHeader.header.checkpointRevision,
        walSequence: installedHeader.header.coveredWalSequence,
        walHash: b4a.from(installedHeader.header.coveredWalHash)
      })
      return Object.freeze({
        manifestSnapshot: verifiedManifest,
        header: Object.freeze(copyCheckpointHeader(installedHeader.header)),
        headerBytes: b4a.from(checkpointBytes),
        headerHash: b4a.from(checkpointHash),
        walAnchor: nextWalAnchor,
        walPruned: false,
        checkpointGcPerformed: false
      })
    })
  }

  close () {
    if (this.closePromise) return this.closePromise
    this.closing = true
    this.closed = true
    this.closePromise = (async () => {
      if (this.openPromise) await this.openPromise.catch(() => {})
      await this._serialized(async () => {
        this.opened = false
        this.validationOnly = false
        this.validatedCurrent = null
        ACTIVE_CHECKPOINT_DIRECTORIES.delete(this.controlDirectory)
      })
    })()
    return this.closePromise
  }
}

// Deliberately omitted from the package root export. Focused daemon tests import
// this file directly so publication mechanics can be exercised before the real
// storage-engine semantic authority exists; production construction cannot opt
// into the bypass through ordinary constructor fields.
export function createUnsafeTestOnlyBlindLocalCheckpointStore (options, semanticVerifier) {
  if (typeof semanticVerifier !== 'function') throw new TypeError('test semanticVerifier must be a function')
  return new BlindLocalCheckpointStore({
    ...options,
    [UNSAFE_TEST_SEMANTIC_VERIFIER]: semanticVerifier
  })
}

export const BLIND_LOCAL_CHECKPOINT_LAYOUT = Object.freeze({
  checkpointFinal: CHECKPOINT_FINAL.source,
  snapshotFinal: SNAPSHOT_FINAL.source,
  checkpointTemporary: CHECKPOINT_TEMP.source,
  snapshotTemporary: SNAPSHOT_TEMP.source,
  maximumCheckpointHeaderBytes: MAX_CHECKPOINT_HEADER_BYTES,
  defaultMaximumSnapshotBytes: 256 * 1024 * 1024,
  publicationOrder: Object.freeze([
    'snapshot-temp-sync',
    'snapshot-stream-semantic-verify',
    'snapshot-no-replace-install',
    'snapshot-directory-sync',
    'snapshot-reopen-verify',
    'checkpoint-temp-sync',
    'checkpoint-no-replace-install',
    'checkpoint-directory-sync',
    'checkpoint-reopen-verify',
    'manifest-cas'
  ]),
  walPruningSupported: false,
  checkpointGarbageCollectionSupported: false,
  genesisPublicationSupported: false,
  zeroHash: b4a.from(ZERO32)
})

export const BLIND_LOCAL_CHECKPOINT_INTEGRATION_STATUS = Object.freeze({
  productionRuntimeReady: false,
  mechanicalPublicationImplemented: true,
  storageEngineSemanticAuthorityImplemented: false,
  currentHeadValidationImplemented: true,
  historicalCheckpointAnchoredReplayImplemented: true,
  singleLeaseRecoveryHandoffImplemented: true,
  jointCheckpointWalShadowAuthorityImplemented: true,
  allFamilyShadowSemanticAuthorityImplemented: false,
  blocker: 'ALL_FAMILY_SHADOW_SEMANTIC_AUTHORITY_UNIMPLEMENTED'
})
