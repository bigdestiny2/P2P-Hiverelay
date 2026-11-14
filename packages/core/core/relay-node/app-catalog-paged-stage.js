import b4a from 'b4a'
import sodium from 'sodium-universal'
import { constants } from 'fs'
import { lstat, mkdir, open, opendir, realpath, rename, rmdir, unlink } from 'fs/promises'
import { basename, dirname, isAbsolute, join, resolve } from 'path'
import {
  APP_CATALOG_LIMITS,
  AppCatalogProtocolError,
  decodeAppCatalogFrame,
  validateCanonicalCatalogRow
} from './app-catalog-paged.js'

const HEX_64 = /^[0-9a-f]{64}$/
const HEX_32 = /^[0-9a-f]{32}$/
const POINTER_FIELDS = Object.freeze([
  'version',
  'peerPubkey',
  'snapshotId',
  'highWater',
  'rootDigest',
  'entryCount',
  'directory'
])
const MANIFEST_FIELDS = Object.freeze([
  'version',
  'peerPubkey',
  'snapshotId',
  'highWater',
  'rootDigest',
  'entryCount',
  'encodedRecordBytes'
])
const CATALOG_METADATA_MAX_BYTES = 4_096
const CATALOG_INDEX_RECORD_BYTES = 72
const CATALOG_RECONCILE_MAX_ENTRIES = 2_048
const OWNED_CATALOG_DIRECTORY = /^([0-9a-f]{64})\.([0-9a-f]{64})\.([0-9a-f]{32})$/
const OWNED_PEER_POINTER = /^([0-9a-f]{64})\.json$/
const OWNED_TEMPORARY_POINTER = /^\.([0-9a-f]{64})\.([0-9a-f]{32})\.tmp$/
const OWNED_CATALOG_FILES = new Set(['index.bin', 'manifest.json', 'rows.bin'])
const PRIVATE_MODE_MASK = 0o077n
const OPEN_COMMITTED_MAX_ATTEMPTS = 4
const COMMITTED_HANDLE_STATE = new WeakMap()
const LSTAT_SUPPORTS_OPTIONS = lstat.length < 2

function fail (code, message) {
  throw new AppCatalogProtocolError(code, message)
}

function assertHex64 (value, field) {
  if (typeof value !== 'string' || !HEX_64.test(value)) fail('PROTOCOL_ERROR', `${field} must be lowercase 64-hex`)
  return value
}

function assertExactObject (value, fields, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('SNAPSHOT_MISMATCH', `${field} must be an object`)
  }
  const keys = Object.keys(value)
  if (keys.length !== fields.length || keys.some(key => !fields.includes(key)) || fields.some(key => !Object.prototype.hasOwnProperty.call(value, key))) {
    fail('SNAPSHOT_MISMATCH', `${field} has an unknown or missing field`)
  }
  return value
}

function assertSafeInteger (value, field, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < 0 || value > max || Object.is(value, -0)) {
    fail('SNAPSHOT_MISMATCH', `${field} is outside its allowed integer range`)
  }
  return value
}

function validatePointer (input, expectedPeer = null) {
  const pointer = assertExactObject(input, POINTER_FIELDS, 'catalog committed pointer')
  if (pointer.version !== 1) fail('SNAPSHOT_MISMATCH', 'catalog committed pointer version is invalid')
  const peerPubkey = assertHex64(pointer.peerPubkey, 'pointer peerPubkey')
  const snapshotId = assertHex64(pointer.snapshotId, 'pointer snapshotId')
  const rootDigest = assertHex64(pointer.rootDigest, 'pointer rootDigest')
  const highWater = assertSafeInteger(pointer.highWater, 'pointer highWater')
  const entryCount = assertSafeInteger(pointer.entryCount, 'pointer entryCount', APP_CATALOG_LIMITS.maxSnapshotEntries)
  if (expectedPeer !== null && peerPubkey !== expectedPeer) {
    fail('SNAPSHOT_MISMATCH', 'catalog committed pointer peer does not match its filename')
  }
  if (typeof pointer.directory !== 'string' || basename(pointer.directory) !== pointer.directory) {
    fail('SNAPSHOT_MISMATCH', 'catalog committed pointer directory is invalid')
  }
  const directoryParts = pointer.directory.split('.')
  if (directoryParts.length !== 3 || directoryParts[0] !== peerPubkey || directoryParts[1] !== snapshotId || !HEX_32.test(directoryParts[2])) {
    fail('SNAPSHOT_MISMATCH', 'catalog committed pointer directory tuple is invalid')
  }
  return Object.freeze({
    version: 1,
    peerPubkey,
    snapshotId,
    highWater,
    rootDigest,
    entryCount,
    directory: pointer.directory
  })
}

function samePointer (left, right) {
  return left !== null && right !== null && POINTER_FIELDS.every(field => left[field] === right[field])
}

function samePointerState (left, right) {
  return left === null ? right === null : samePointer(left, right)
}

function validateManifest (input, pointer) {
  const manifest = assertExactObject(input, MANIFEST_FIELDS, 'catalog committed manifest')
  if (manifest.version !== 1) fail('SNAPSHOT_MISMATCH', 'catalog committed manifest version is invalid')
  const validated = Object.freeze({
    version: 1,
    peerPubkey: assertHex64(manifest.peerPubkey, 'manifest peerPubkey'),
    snapshotId: assertHex64(manifest.snapshotId, 'manifest snapshotId'),
    highWater: assertSafeInteger(manifest.highWater, 'manifest highWater'),
    rootDigest: assertHex64(manifest.rootDigest, 'manifest rootDigest'),
    entryCount: assertSafeInteger(manifest.entryCount, 'manifest entryCount', APP_CATALOG_LIMITS.maxSnapshotEntries),
    encodedRecordBytes: assertSafeInteger(
      manifest.encodedRecordBytes,
      'manifest encodedRecordBytes',
      APP_CATALOG_LIMITS.maxInboundSessionBytes
    )
  })
  for (const field of ['peerPubkey', 'snapshotId', 'highWater', 'rootDigest', 'entryCount']) {
    if (validated[field] !== pointer[field]) fail('SNAPSHOT_MISMATCH', `catalog committed manifest ${field} mismatch`)
  }
  return validated
}

function randomHex () {
  const bytes = b4a.alloc(16)
  sodium.randombytes_buf(bytes)
  return b4a.toString(bytes, 'hex')
}

function statIdentity (stat) {
  const normalize = (value, field) => {
    if (typeof value === 'bigint') return value.toString()
    if (Number.isSafeInteger(value) && value >= 0) return String(value)
    fail('RESOURCE_LIMIT', `catalog ${field} identity is not an exact integer`)
  }
  return Object.freeze({
    dev: normalize(stat.dev, 'device'),
    ino: normalize(stat.ino, 'inode'),
    uid: normalize(stat.uid, 'owner')
  })
}

function statSizeEquals (value, expected) {
  if (!Number.isSafeInteger(expected) || expected < 0) return false
  if (typeof value === 'bigint') return value === BigInt(expected)
  return Number.isSafeInteger(value) && value === expected
}

function lstatExact (path) {
  return LSTAT_SUPPORTS_OPTIONS ? lstat(path, { bigint: true }) : lstat(path)
}

function sameIdentity (left, right) {
  return left !== null && right !== null && left.dev === right.dev && left.ino === right.ino && left.uid === right.uid
}

function assertOwnedStat (stat, expected, field, ownerUid = null) {
  const validType = expected === 'directory' ? stat.isDirectory() : stat.isFile()
  if (!validType || stat.isSymbolicLink()) fail('RESOURCE_LIMIT', `${field} is not an owned ${expected}`)
  if (ownerUid !== null && String(stat.uid) !== ownerUid) fail('RESOURCE_LIMIT', `${field} does not match the pinned catalog owner`)
  if ((BigInt(stat.mode) & PRIVATE_MODE_MASK) !== 0n) {
    fail('RESOURCE_LIMIT', `${field} must have private owner-only permissions`)
  }
  return statIdentity(stat)
}

function closeOwnedResource (closeOwner, resource, field) {
  if (closeOwner === null) return resource.close()
  return closeOwner._closeRetainedResource(resource, field)
}

async function closeOwnedResources (closeOwner, resources) {
  const results = await Promise.allSettled(resources.map(({ resource, field }) => {
    return resource === null ? Promise.resolve() : closeOwnedResource(closeOwner, resource, field)
  }))
  const failure = results.find(result => result.status === 'rejected')
  if (failure) throw failure.reason
}

async function inspectOwnedPath (path, expected, field, pinnedIdentity = null, ownerUid = null, closeOwner = null) {
  let handle = null
  try {
    handle = await openReadNoFollow(path)
    const expectedOwner = ownerUid === null && pinnedIdentity !== null ? pinnedIdentity.uid : ownerUid
    const handleIdentity = assertOwnedStat(await handle.stat({ bigint: true }), expected, field, expectedOwner)
    const pathIdentity = assertOwnedStat(await lstatExact(path), expected, field, expectedOwner)
    if (!sameIdentity(handleIdentity, pathIdentity)) fail('RESOURCE_LIMIT', `${field} changed identity while it was verified`)
    if (pinnedIdentity !== null && !sameIdentity(pathIdentity, pinnedIdentity)) {
      fail('RESOURCE_LIMIT', `${field} no longer matches its pinned identity`)
    }
    if (await realpath(path) !== path) fail('RESOURCE_LIMIT', `${field} must not traverse a symlink`)
    return pathIdentity
  } catch (err) {
    if (err && err.code === 'ENOENT') throw err
    if (err instanceof AppCatalogProtocolError) throw err
    fail('RESOURCE_LIMIT', `${field} could not be verified without following links`)
  } finally {
    if (handle !== null) await closeOwnedResource(closeOwner, handle, `${field} verification handle`)
  }
}

async function assertOwnedDirectory (path, field, pinnedIdentity = null, ownerUid = null, closeOwner = null) {
  return inspectOwnedPath(path, 'directory', field, pinnedIdentity, ownerUid, closeOwner)
}

async function writeAll (handle, bytes) {
  let offset = 0
  while (offset < bytes.byteLength) {
    const result = await handle.write(bytes, offset, bytes.byteLength - offset, null)
    if (!result || !Number.isSafeInteger(result.bytesWritten) || result.bytesWritten <= 0) {
      fail('RESOURCE_LIMIT', 'catalog staging write made no progress')
    }
    offset += result.bytesWritten
  }
}

async function openExclusiveNoFollow (path) {
  const noFollow = Number.isSafeInteger(constants.O_NOFOLLOW) ? constants.O_NOFOLLOW : 0
  // O_CREAT | O_EXCL refuses an existing final-component symlink even on
  // Bare platforms that do not expose O_NOFOLLOW. The opened-vs-linked
  // identity checks still run before the handle is used.
  return open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | noFollow, 0o600)
}

async function openReadNoFollow (path) {
  const noFollow = Number.isSafeInteger(constants.O_NOFOLLOW) ? constants.O_NOFOLLOW : 0
  // When Bare omits O_NOFOLLOW, callers validate the opened handle against a
  // fresh lstat/realpath identity before reading, syncing, or deleting.
  return open(path, constants.O_RDONLY | noFollow)
}

async function openOwnedRead (path, expected, field, ownerUid, pinnedIdentity = null, closeOwner = null) {
  const identity = await inspectOwnedPath(path, expected, field, pinnedIdentity, ownerUid, closeOwner)
  let handle = null
  try {
    handle = await openReadNoFollow(path)
    const openedIdentity = assertOwnedStat(await handle.stat({ bigint: true }), expected, field, ownerUid)
    const linkedIdentity = assertOwnedStat(await lstatExact(path), expected, field, ownerUid)
    if (!sameIdentity(identity, openedIdentity) || !sameIdentity(identity, linkedIdentity)) {
      fail('RESOURCE_LIMIT', `${field} changed while its owned handle was acquired`)
    }
    return { handle, identity }
  } catch (err) {
    if (handle !== null) await closeOwnedResource(closeOwner, handle, `${field} failed acquisition handle`)
    throw err
  }
}

async function syncOwnedDirectory (path, field, pinnedIdentity = null, ownerUid = null, closeOwner = null) {
  const handle = await openReadNoFollow(path)
  try {
    const expectedOwner = ownerUid === null && pinnedIdentity !== null ? pinnedIdentity.uid : ownerUid
    const identity = assertOwnedStat(await handle.stat({ bigint: true }), 'directory', field, expectedOwner)
    const pathIdentity = assertOwnedStat(await lstatExact(path), 'directory', field, expectedOwner)
    if (!sameIdentity(identity, pathIdentity) || (pinnedIdentity !== null && !sameIdentity(identity, pinnedIdentity))) {
      fail('RESOURCE_LIMIT', `${field} changed before it could be synchronized`)
    }
    if (typeof handle.sync !== 'function') fail('RESOURCE_LIMIT', `${field} cannot be synchronized`)
    await handle.sync()
  } finally {
    await closeOwnedResource(closeOwner, handle, `${field} synchronization handle`)
  }
}

function uint64Bytes (value) {
  if (!Number.isSafeInteger(value) || value < 0) fail('RESOURCE_LIMIT', 'catalog file offset is invalid')
  const bytes = b4a.alloc(8)
  const high = Math.floor(value / 0x100000000)
  const low = value - (high * 0x100000000)
  bytes.writeUInt32BE(high, 0)
  bytes.writeUInt32BE(low, 4)
  return bytes
}

function decodeUint64 (bytes) {
  const value = (bytes.readUInt32BE(0) * 0x100000000) + bytes.readUInt32BE(4)
  if (!Number.isSafeInteger(value)) fail('RESOURCE_LIMIT', 'catalog file offset exceeds safe integer range')
  return value
}

async function readExact (handle, bytes, position) {
  let offset = 0
  while (offset < bytes.byteLength) {
    const result = await handle.read(bytes, offset, bytes.byteLength - offset, position + offset)
    if (!result || !Number.isSafeInteger(result.bytesRead) || result.bytesRead <= 0) {
      fail('SNAPSHOT_MISMATCH', 'catalog committed file is truncated')
    }
    offset += result.bytesRead
  }
  return bytes
}

async function readOwnedJson (path, field, ownerUid = null, closeOwner = null) {
  let handle = null
  let identity = null
  try {
    const opened = await openOwnedRead(path, 'file', field, ownerUid, null, closeOwner)
    handle = opened.handle
    identity = opened.identity
    const stat = await handle.stat({ bigint: true })
    assertOwnedStat(stat, 'file', field, ownerUid)
    const size = Number(stat.size)
    if (!Number.isSafeInteger(size) || size < 2 || size > CATALOG_METADATA_MAX_BYTES) {
      fail('SNAPSHOT_MISMATCH', `${field} is not a bounded owned file`)
    }
    const frame = b4a.alloc(4 + size)
    frame.writeUInt32BE(size, 0)
    await readExact(handle, frame.subarray(4), 0)
    const finalIdentity = assertOwnedStat(await lstatExact(path), 'file', field, ownerUid)
    if (!sameIdentity(identity, finalIdentity)) fail('RESOURCE_LIMIT', `${field} changed while it was read`)
    if (await realpath(path) !== path) fail('RESOURCE_LIMIT', `${field} must remain in its owned ancestry`)
    return decodeAppCatalogFrame(frame)
  } catch (err) {
    if (err && err.code === 'ENOENT') throw err
    if (err instanceof AppCatalogProtocolError) throw err
    fail('SNAPSHOT_MISMATCH', `${field} could not be read`)
  } finally {
    if (handle !== null) await closeOwnedResource(closeOwner, handle, `${field} read handle`)
  }
}

async function existingPointer (pointerPath, expectedPeer = null, ownerUid = null, closeOwner = null) {
  try {
    return validatePointer(await readOwnedJson(pointerPath, 'catalog peer pointer', ownerUid, closeOwner), expectedPeer)
  } catch (err) {
    if (err && err.code === 'ENOENT') return null
    throw err
  }
}

async function scanReconciliationDirectory (path, state, visit, closeOwner = null) {
  const directory = await opendir(path)
  try {
    while (true) {
      const entry = await directory.read()
      if (entry === null) break
      state.examined++
      if (state.examined > CATALOG_RECONCILE_MAX_ENTRIES) {
        fail('RESOURCE_LIMIT', 'catalog startup reconciliation entry cap exceeded')
      }
      await visit(entry)
    }
  } finally {
    await closeOwnedResource(closeOwner, directory, 'catalog reconciliation directory handle')
  }
}

async function assertOwnedEntry (path, expected, field, ownerUid = null, closeOwner = null) {
  return inspectOwnedPath(path, expected, field, null, ownerUid, closeOwner)
}

export class AppCatalogDiskStageFactory {
  constructor (opts) {
    if (!opts || typeof opts.rootDir !== 'string' || !isAbsolute(opts.rootDir)) {
      fail('PROTOCOL_ERROR', 'catalog stage rootDir must be absolute')
    }
    this.rootDir = resolve(opts.rootDir)
    this.stagingDir = join(this.rootDir, 'staging')
    this.snapshotsDir = join(this.rootDir, 'snapshots')
    this.peersDir = join(this.rootDir, 'peers')
    this._beforePointerRename = typeof opts.beforePointerRename === 'function'
      ? opts.beforePointerRename
      : null
    this._onDurabilityBarrier = typeof opts.onDurabilityBarrier === 'function'
      ? opts.onDurabilityBarrier
      : null
    this._beforeCommittedValidation = typeof opts.beforeCommittedValidation === 'function'
      ? opts.beforeCommittedValidation
      : null
    this._ready = null
    this._stop = null
    this._lifecycleEpoch = 0
    this._ownerUid = null
    this._ownedDirectoryIdentities = new Map()
    this._operations = new Set()
    this._failedHandleClosures = new Set()
    this._retainedHandleOwners = new WeakMap()
    this._failedOpenCleanups = new Set()
    this._failedReclaims = new Map()
    this._failedPeerRemovals = new Map()
    this._active = new Set()
    this._activePeers = new Set()
    this._reservedPeers = new Set()
    this._retainedPeers = new Set()
    this._committedLeases = new Map()
    this._pendingReclaims = new Map()
    this._reclaimingSnapshots = new Map()
    this._reclaimTail = Promise.resolve()
    this._peerAdmissionTail = Promise.resolve()
    this._storageFault = false
    this.stopped = false
  }

  async ready () {
    if (this.stopped) fail('RESOURCE_LIMIT', 'catalog disk stage factory is stopped')
    const epoch = this._lifecycleEpoch
    if (this._ready === null) this._ready = this._initialize(epoch)
    await this._ready
    if (this.stopped || epoch !== this._lifecycleEpoch) fail('RESOURCE_LIMIT', 'catalog disk stage factory is stopped')
  }

  open (metadata) {
    if (this.stopped) fail('RESOURCE_LIMIT', 'catalog disk stage factory is stopped')
    const epoch = this._lifecycleEpoch
    return this._trackOperation(this._openNow(metadata, epoch))
  }

  async _openNow (metadata, epoch) {
    await this.ready()
    this._assertRunning(epoch)
    await this._assertOwnedLayout()
    this._assertRunning(epoch)
    const peerPubkey = assertHex64(metadata.peerPubkey, 'peerPubkey')
    const snapshotId = assertHex64(metadata.snapshotId, 'snapshotId')
    assertHex64(metadata.rootDigest, 'rootDigest')
    if (!Number.isSafeInteger(metadata.highWater) || metadata.highWater < 0 ||
        !Number.isSafeInteger(metadata.entryCount) || metadata.entryCount < 0 ||
        metadata.entryCount > APP_CATALOG_LIMITS.maxSnapshotEntries) {
      fail('PROTOCOL_ERROR', 'catalog stage metadata integers are invalid')
    }
    let reserved = false
    let path = null
    let pathIdentity = null
    let rowsHandle = null
    let indexHandle = null
    try {
      await this._reservePeer(peerPubkey)
      reserved = true
      this._assertRunning(epoch)
      for (let attempt = 0; attempt < 4; attempt++) {
        const candidate = join(this.stagingDir, `${peerPubkey}.${snapshotId}.${randomHex()}`)
        try {
          await mkdir(candidate, { mode: 0o700 })
          path = candidate
          pathIdentity = await assertOwnedDirectory(path, 'catalog staging directory', null, this._ownerUid, this)
          this._assertRunning(epoch)
          break
        } catch (err) {
          if (!err || err.code !== 'EEXIST') throw err
        }
      }
      if (path === null) fail('RESOURCE_LIMIT', 'catalog staging name collision limit reached')
      rowsHandle = await this._openExclusive(join(path, 'rows.bin'))
      this._assertRunning(epoch)
      await this._assertOwnedLayout()
      await assertOwnedDirectory(path, 'catalog staging directory', pathIdentity, this._ownerUid, this)
      const rowsIdentity = await inspectOwnedPath(join(path, 'rows.bin'), 'file', 'catalog staged rows file', null, this._ownerUid, this)
      const openedRowsIdentity = assertOwnedStat(await rowsHandle.stat({ bigint: true }), 'file', 'catalog staged rows file', this._ownerUid)
      if (!sameIdentity(rowsIdentity, openedRowsIdentity)) fail('RESOURCE_LIMIT', 'catalog staged rows file changed while it was opened')
      this._assertRunning(epoch)
      indexHandle = await this._openExclusive(join(path, 'index.bin'))
      this._assertRunning(epoch)
      await this._assertOwnedLayout()
      await assertOwnedDirectory(path, 'catalog staging directory', pathIdentity, this._ownerUid, this)
      const indexIdentity = await inspectOwnedPath(join(path, 'index.bin'), 'file', 'catalog staged index file', null, this._ownerUid, this)
      const openedIndexIdentity = assertOwnedStat(await indexHandle.stat({ bigint: true }), 'file', 'catalog staged index file', this._ownerUid)
      if (!sameIdentity(indexIdentity, openedIndexIdentity)) fail('RESOURCE_LIMIT', 'catalog staged index file changed while it was opened')
      this._assertRunning(epoch)
      const stage = new AppCatalogDiskStage(this, {
        ...metadata,
        peerPubkey,
        snapshotId,
        path,
        pathIdentity,
        rowsHandle,
        indexHandle
      })
      this._active.add(stage)
      return stage
    } catch (err) {
      const cleanup = {
        peerPubkey,
        reserved,
        path,
        pathIdentity,
        rowsHandle,
        indexHandle,
        directoryRemoved: path === null,
        directorySynced: path === null,
        syncBarrierPassed: path === null
      }
      this._failedOpenCleanups.add(cleanup)
      await this._retryOpenCleanup(cleanup)
      if (!(err instanceof AppCatalogProtocolError)) {
        fail('RESOURCE_LIMIT', 'catalog staging store could not be opened safely')
      }
      throw err
    }
  }

  stop () {
    if (this._stop !== null) return this._stop
    if (!this.stopped) {
      this.stopped = true
      this._lifecycleEpoch++
    }
    const stop = this._stopNow()
    this._stop = stop
    stop.catch(() => {
      if (this._stop === stop) this._stop = null
    })
    return stop
  }

  async _stopNow () {
    if (this._ready !== null) {
      try { await this._ready } catch {}
    }
    while (this._operations.size !== 0) {
      await Promise.allSettled([...this._operations])
    }
    try { await this._peerAdmissionTail } catch {}
    try { await this._reclaimTail } catch {}
    for (const pending of [...this._failedHandleClosures]) {
      await this._closeRetainedResource(pending.resource, pending.field)
    }
    for (const cleanup of [...this._failedOpenCleanups]) {
      await this._retryOpenCleanup(cleanup)
    }
    await this._drainSnapshotReclaims()
    for (const pending of [...this._failedPeerRemovals.values()]) {
      await this._retryPeerRemoval(pending)
    }
    const discardResults = await Promise.allSettled([...this._active].map(stage => stage.discard()))
    const failedDiscard = discardResults.find(result => result.status === 'rejected')
    if (failedDiscard) throw failedDiscard.reason
    // Settling an already-published replacement during discard transfers its
    // superseded snapshot here while the factory is stopped. Drain that newly
    // retained owner before certifying terminal storage ownership.
    await this._drainSnapshotReclaims()
    if (this._failedHandleClosures.size !== 0 || this._failedOpenCleanups.size !== 0 ||
        this._failedReclaims.size !== 0 || this._failedPeerRemovals.size !== 0 ||
        this._hasReleasedPendingReclaim() ||
        this._active.size !== 0 || this._activePeers.size !== 0 || this._reservedPeers.size !== 0) {
      fail('RESOURCE_LIMIT', 'catalog disk stage factory stop retained unresolved storage ownership')
    }
  }

  async _drainSnapshotReclaims () {
    for (const pending of [...this._failedReclaims.values()]) {
      await this._reclaimSnapshot(pending)
    }
    for (const [directory, pending] of [...this._pendingReclaims]) {
      const lease = this._committedLeases.get(directory)
      if (lease && lease.count > 0) continue
      this._pendingReclaims.delete(directory)
      this._failedReclaims.set(directory, pending)
      await this._reclaimSnapshot(pending)
    }
  }

  _assertRunning (epoch = this._lifecycleEpoch) {
    if (this.stopped || epoch !== this._lifecycleEpoch) fail('RESOURCE_LIMIT', 'catalog disk stage factory is stopped')
  }

  _trackOperation (operation) {
    this._operations.add(operation)
    Promise.resolve(operation).then(
      () => this._operations.delete(operation),
      () => this._operations.delete(operation)
    )
    return operation
  }

  _closeRetainedResource (resource, field) {
    let pending = this._retainedHandleOwners.get(resource)
    if (pending === undefined) {
      pending = { resource, field, attempt: null }
      this._retainedHandleOwners.set(resource, pending)
      this._failedHandleClosures.add(pending)
    }
    if (pending.attempt !== null) return pending.attempt
    const attempt = (async () => {
      try {
        await resource.close()
        if (pending.resource === resource) pending.resource = null
        this._retainedHandleOwners.delete(resource)
        this._failedHandleClosures.delete(pending)
      } catch (err) {
        this._storageFault = true
        throw err
      }
    })()
    pending.attempt = attempt
    attempt.catch(() => {
      if (pending.attempt === attempt) pending.attempt = null
    })
    return attempt
  }

  _openOwnedRead (path, expected, field, pinnedIdentity = null) {
    return openOwnedRead(path, expected, field, this._ownerUid, pinnedIdentity, this)
  }

  _openExclusive (path) {
    return openExclusiveNoFollow(path)
  }

  async _retryOpenCleanup (cleanup) {
    let closeError = null
    for (const field of ['rowsHandle', 'indexHandle']) {
      const handle = cleanup[field]
      if (handle === null) continue
      try {
        await handle.close()
        if (cleanup[field] === handle) cleanup[field] = null
      } catch (err) {
        if (closeError === null) closeError = err
      }
    }
    if (closeError !== null) {
      this._storageFault = true
      throw closeError
    }
    if (!cleanup.directoryRemoved && cleanup.path !== null && cleanup.pathIdentity === null) {
      try {
        cleanup.pathIdentity = await assertOwnedDirectory(
          cleanup.path,
          'catalog failed staging directory',
          null,
          this._ownerUid,
          this
        )
      } catch (err) {
        this._storageFault = true
        throw err
      }
    }
    if (!cleanup.directoryRemoved && cleanup.path !== null) {
      try {
        await this._removeOwnedCatalogDirectory(
          cleanup.path,
          this.stagingDir,
          'catalog failed staging directory',
          cleanup.pathIdentity,
          true
        )
        cleanup.directoryRemoved = true
      } catch (err) {
        this._storageFault = true
        throw err
      }
    }
    if (!cleanup.directorySynced) {
      try {
        await this._syncOwnedDirectory(this.stagingDir, 'catalog failed staging parent')
        cleanup.directorySynced = true
      } catch (err) {
        this._storageFault = true
        throw err
      }
    }
    if (!cleanup.syncBarrierPassed) {
      try {
        await this._durabilityBarrier('failed-open-staging-directory-synced', {
          peerPubkey: cleanup.peerPubkey
        })
        cleanup.syncBarrierPassed = true
      } catch (err) {
        this._storageFault = true
        throw err
      }
    }
    if (cleanup.reserved) {
      this._releasePeer(cleanup.peerPubkey, false)
      cleanup.reserved = false
    }
    this._failedOpenCleanups.delete(cleanup)
  }

  get storageFault () {
    return this._storageFault
  }

  removeCommittedPeer (peerPubkey) {
    if (this.stopped) fail('RESOURCE_LIMIT', 'catalog disk stage factory is stopped')
    const epoch = this._lifecycleEpoch
    return this._trackOperation(this._removeCommittedPeer(peerPubkey, epoch))
  }

  async _removeCommittedPeer (peerPubkey, epoch) {
    await this.ready()
    this._assertRunning(epoch)
    const peer = assertHex64(peerPubkey, 'peerPubkey')
    const operation = this._peerAdmissionTail.then(() => this._removeCommittedPeerNow(peer))
    this._peerAdmissionTail = operation.catch(() => {})
    return operation
  }

  async _removeCommittedPeerNow (peer) {
    const retained = this._failedPeerRemovals.get(peer)
    if (retained !== undefined) return this._retryPeerRemoval(retained)
    if (this.stopped) fail('RESOURCE_LIMIT', 'catalog disk stage factory is stopped')
    if (this._activePeers.has(peer)) fail('RESOURCE_LIMIT', 'catalog peer still has an active staging session')
    if (this._hasPeerLease(peer)) fail('RESOURCE_LIMIT', 'catalog peer still has an acquired committed handle')
    await this._assertOwnedLayout()
    const pointerPath = join(this.peersDir, `${peer}.json`)
    const pointer = await existingPointer(pointerPath, peer, this._ownerUid, this)
    if (pointer === null) {
      this._retainedPeers.delete(peer)
      return false
    }
    try {
      const snapshotPath = join(this.snapshotsDir, pointer.directory)
      const snapshotIdentity = await assertOwnedDirectory(snapshotPath, 'catalog retained snapshot', null, this._ownerUid, this)
      const pending = {
        peerPubkey: peer,
        pointer,
        pointerPath,
        snapshotPath,
        snapshotIdentity,
        pointerRemoved: false,
        peersDirectorySynced: false,
        peersBarrierPassed: false,
        snapshotRemoved: false,
        snapshotsDirectorySynced: false,
        snapshotsBarrierPassed: false
      }
      this._failedPeerRemovals.set(peer, pending)
      return this._retryPeerRemoval(pending)
    } catch (err) {
      this._storageFault = true
      throw err
    }
  }

  async _retryPeerRemoval (pending) {
    try {
      await this._assertOwnedLayout()
      if (!pending.pointerRemoved) {
        await this._removeOwnedFile(pending.pointerPath, this.peersDir, 'catalog retained peer pointer')
        pending.pointerRemoved = true
      }
      if (!pending.peersDirectorySynced) {
        await this._syncOwnedDirectory(this.peersDir, 'catalog peers directory')
        pending.peersDirectorySynced = true
      }
      if (!pending.peersBarrierPassed) {
        await this._durabilityBarrier('removed-peer-directory-synced', {
          peerPubkey: pending.peerPubkey,
          snapshotId: pending.pointer.snapshotId
        })
        pending.peersBarrierPassed = true
      }
      if (!pending.snapshotRemoved) {
        await this._removeOwnedCatalogDirectory(
          pending.snapshotPath,
          this.snapshotsDir,
          'catalog retained snapshot',
          pending.snapshotIdentity
        )
        pending.snapshotRemoved = true
      }
      if (!pending.snapshotsDirectorySynced) {
        await this._syncOwnedDirectory(this.snapshotsDir, 'catalog snapshots directory')
        pending.snapshotsDirectorySynced = true
      }
      if (!pending.snapshotsBarrierPassed) {
        await this._durabilityBarrier('removed-snapshot-directory-synced', {
          peerPubkey: pending.peerPubkey,
          snapshotId: pending.pointer.snapshotId
        })
        pending.snapshotsBarrierPassed = true
      }
      this._failedPeerRemovals.delete(pending.peerPubkey)
      this._retainedPeers.delete(pending.peerPubkey)
      return true
    } catch (err) {
      this._storageFault = true
      this._failedPeerRemovals.set(pending.peerPubkey, pending)
      throw err
    }
  }

  openCommittedPeer (peerPubkey) {
    if (this.stopped) fail('RESOURCE_LIMIT', 'catalog disk stage factory is stopped')
    const epoch = this._lifecycleEpoch
    return this._trackOperation(this._openCommittedPeer(peerPubkey, epoch))
  }

  async _openCommittedPeer (peerPubkey, epoch) {
    await this.ready()
    this._assertRunning(epoch)
    const peer = assertHex64(peerPubkey, 'peerPubkey')
    const operation = this._peerAdmissionTail.then(() => this._openCommittedPeerNow(peer, epoch))
    this._peerAdmissionTail = operation.catch(() => {})
    return operation
  }

  async _openCommittedPeerNow (peer, epoch) {
    this._assertRunning(epoch)
    const pointerPath = join(this.peersDir, `${peer}.json`)
    for (let attempt = 0; attempt < OPEN_COMMITTED_MAX_ATTEMPTS; attempt++) {
      if (this.stopped) fail('RESOURCE_LIMIT', 'catalog disk stage factory is stopped')
      await this._assertOwnedLayout()
      this._assertRunning(epoch)
      const pointer = await existingPointer(pointerPath, peer, this._ownerUid, this)
      this._assertRunning(epoch)
      if (!pointer) return null
      if (this._reclaimingSnapshots.has(pointer.directory)) {
        await this._reclaimTail
        continue
      }

      // The handle is deliberately provisional: its lease is installed before
      // any manifest or file validation can yield to superseded-snapshot
      // reclamation. It is published only after the peer pointer is reread and
      // still names this exact tuple.
      const committed = this._committed(pointer, peer)
      let released = false
      try {
        if (this._beforeCommittedValidation !== null) await this._beforeCommittedValidation(pointer)
        this._assertRunning(epoch)
        const committedPath = join(this.snapshotsDir, pointer.directory)
        const committedIdentity = await assertOwnedDirectory(committedPath, 'committed catalog directory', null, this._ownerUid, this)
        this._assertRunning(epoch)
        const manifest = validateManifest(
          await readOwnedJson(join(committedPath, 'manifest.json'), 'catalog committed manifest', this._ownerUid, this),
          pointer
        )
        this._assertRunning(epoch)
        await assertOwnedDirectory(committedPath, 'committed catalog directory', committedIdentity, this._ownerUid, this)
        let indexHandle = null
        let rowsHandle = null
        try {
          indexHandle = (await this._openOwnedRead(
            join(committedPath, 'index.bin'),
            'file',
            'catalog committed index'
          )).handle
          this._assertRunning(epoch)
          await assertOwnedDirectory(committedPath, 'committed catalog directory', committedIdentity, this._ownerUid, this)
          rowsHandle = (await this._openOwnedRead(
            join(committedPath, 'rows.bin'),
            'file',
            'catalog committed rows'
          )).handle
          this._assertRunning(epoch)
          const [indexStat, rowsStat] = await Promise.all([
            indexHandle.stat({ bigint: true }),
            rowsHandle.stat({ bigint: true })
          ])
          this._assertRunning(epoch)
          assertOwnedStat(indexStat, 'file', 'catalog committed index', this._ownerUid)
          assertOwnedStat(rowsStat, 'file', 'catalog committed rows', this._ownerUid)
          if (!statSizeEquals(indexStat.size, manifest.entryCount * CATALOG_INDEX_RECORD_BYTES)) {
            fail('SNAPSHOT_MISMATCH', 'catalog committed index size does not match its manifest')
          }
          if (!statSizeEquals(rowsStat.size, manifest.encodedRecordBytes)) {
            fail('SNAPSHOT_MISMATCH', 'catalog committed rows size does not match its manifest')
          }
        } finally {
          await closeOwnedResources(this, [
            { resource: indexHandle, field: 'catalog committed validation index handle' },
            { resource: rowsHandle, field: 'catalog committed validation rows handle' }
          ])
        }
        await assertOwnedDirectory(committedPath, 'committed catalog directory', committedIdentity, this._ownerUid, this)
        this._assertRunning(epoch)
        const authoritative = await existingPointer(pointerPath, peer, this._ownerUid, this)
        this._assertRunning(epoch)
        if (!samePointer(authoritative, pointer)) {
          released = true
          await committed.release()
          continue
        }
        return committed
      } catch (err) {
        if (!released) {
          try {
            await committed.release()
          } catch (releaseError) {
            this._storageFault = true
            throw releaseError
          }
        }
        throw err
      }
    }
    fail('RESOURCE_LIMIT', 'catalog committed pointer changed during every bounded acquisition attempt')
  }

  _committed (input, expectedPeer = null) {
    this._assertRunning()
    const pointer = validatePointer(input, expectedPeer)
    if (this._reclaimingSnapshots.has(pointer.directory)) {
      fail('RESOURCE_LIMIT', 'catalog committed snapshot is being reclaimed')
    }
    const committed = new AppCatalogCommittedCatalog({
      ...pointer,
      factory: this,
      path: join(this.snapshotsDir, pointer.directory)
    })
    const lease = this._committedLeases.get(pointer.directory) || { peerPubkey: pointer.peerPubkey, count: 0 }
    if (lease.peerPubkey !== pointer.peerPubkey) fail('SNAPSHOT_MISMATCH', 'catalog committed lease owner mismatch')
    lease.count++
    this._committedLeases.set(pointer.directory, lease)
    COMMITTED_HANDLE_STATE.set(committed, { factory: this, ownerUid: this._ownerUid, released: false })
    return committed
  }

  _reservePeer (peer) {
    const operation = this._peerAdmissionTail.then(() => this._reservePeerNow(peer))
    this._peerAdmissionTail = operation.catch(() => {})
    return operation
  }

  async _reservePeerNow (peer) {
    if (this.stopped) fail('RESOURCE_LIMIT', 'catalog disk stage factory is stopped')
    if (this._storageFault) fail('RESOURCE_LIMIT', 'catalog stage storage is fail-closed after a cleanup fault')
    if (this._activePeers.has(peer)) fail('RESOURCE_LIMIT', 'catalog peer already has an active staging session')
    for (const pending of this._pendingReclaims.values()) {
      if (pending.peerPubkey === peer) fail('RESOURCE_LIMIT', 'catalog peer has an acquired superseded snapshot')
    }
    const isNewPeer = !this._retainedPeers.has(peer)
    if (isNewPeer && this._retainedPeers.size + this._reservedPeers.size >= APP_CATALOG_LIMITS.maxInboundPeers) {
      await this._evictInactivePeer(peer)
    }
    if (this.stopped) fail('RESOURCE_LIMIT', 'catalog disk stage factory is stopped')
    if (isNewPeer && this._retainedPeers.size + this._reservedPeers.size >= APP_CATALOG_LIMITS.maxInboundPeers) {
      fail('RESOURCE_LIMIT', 'catalog retained peer cap reached with no inactive peer available for eviction')
    }
    this._activePeers.add(peer)
    if (isNewPeer) this._reservedPeers.add(peer)
  }

  async _evictInactivePeer (incomingPeer) {
    for (const peer of [...this._retainedPeers].sort()) {
      if (peer === incomingPeer || this._activePeers.has(peer) || this._reservedPeers.has(peer) || this._hasPeerLease(peer)) continue
      await this._removeCommittedPeerNow(peer)
      return true
    }
    return false
  }

  _releasePeer (peer, committed) {
    this._activePeers.delete(peer)
    this._reservedPeers.delete(peer)
    if (committed) this._retainedPeers.add(peer)
  }

  _hasPeerLease (peer) {
    for (const lease of this._committedLeases.values()) {
      if (lease.peerPubkey === peer && lease.count > 0) return true
    }
    for (const pending of this._pendingReclaims.values()) {
      if (pending.peerPubkey === peer) return true
    }
    for (const reclaimingPeer of this._reclaimingSnapshots.values()) {
      if (reclaimingPeer === peer) return true
    }
    return false
  }

  _hasReleasedPendingReclaim () {
    for (const directory of this._pendingReclaims.keys()) {
      const lease = this._committedLeases.get(directory)
      if (!lease || lease.count === 0) return true
    }
    return false
  }

  async _durabilityBarrier (name, details) {
    if (this._onDurabilityBarrier !== null) await this._onDurabilityBarrier(name, details)
  }

  _releaseCommitted (catalog) {
    const state = COMMITTED_HANDLE_STATE.get(catalog)
    if (!state || state.factory !== this || state.released) return Promise.resolve(false)
    state.released = true
    const lease = this._committedLeases.get(catalog.directory)
    if (!lease || lease.count < 1) return Promise.reject(new AppCatalogProtocolError('RESOURCE_LIMIT', 'catalog committed lease accounting mismatch'))
    lease.count--
    if (lease.count > 0) return Promise.resolve(true)
    this._committedLeases.delete(catalog.directory)
    const pending = this._pendingReclaims.get(catalog.directory)
    if (!pending) return Promise.resolve(true)
    if (this.stopped) return Promise.resolve(true)
    this._pendingReclaims.delete(catalog.directory)
    return this._queueSnapshotReclaim(pending).then(() => true)
  }

  _retireSnapshot (pointer, replacement) {
    const lease = this._committedLeases.get(pointer.directory)
    const pending = {
      peerPubkey: pointer.peerPubkey,
      pointer,
      replacement
    }
    if (lease && lease.count > 0) {
      if (this._pendingReclaims.has(pointer.directory)) fail('RESOURCE_LIMIT', 'catalog snapshot already awaits bounded reclamation')
      this._pendingReclaims.set(pointer.directory, pending)
      return Promise.resolve(false)
    }
    if (this.stopped) {
      this._failedReclaims.set(pointer.directory, pending)
      return Promise.resolve(false)
    }
    return this._queueSnapshotReclaim(pending)
  }

  _queueSnapshotReclaim (pending) {
    if (this.stopped) {
      this._failedReclaims.set(pending.pointer.directory, pending)
      return Promise.resolve(false)
    }
    const operation = this._reclaimTail.then(() => this._reclaimSnapshot(pending))
    this._reclaimTail = operation.catch(() => {})
    return operation
  }

  async _reclaimSnapshot (pending) {
    const oldPath = join(this.snapshotsDir, pending.pointer.directory)
    const lease = this._committedLeases.get(pending.pointer.directory)
    if (lease && lease.count > 0) {
      if (!this._pendingReclaims.has(pending.pointer.directory)) {
        this._pendingReclaims.set(pending.pointer.directory, pending)
      }
      return false
    }
    if (this._reclaimingSnapshots.has(pending.pointer.directory)) {
      fail('RESOURCE_LIMIT', 'catalog snapshot already has an active reclamation')
    }
    this._reclaimingSnapshots.set(pending.pointer.directory, pending.peerPubkey)
    try {
      await this._assertOwnedLayout()
      if (!pending.directoryRemoved) {
        if (!pending.pathIdentity) {
          pending.pathIdentity = await assertOwnedDirectory(oldPath, 'prior catalog snapshot', null, this._ownerUid, this)
        }
        await this._removeOwnedCatalogDirectory(
          oldPath,
          this.snapshotsDir,
          'prior catalog snapshot',
          pending.pathIdentity
        )
        pending.directoryRemoved = true
      }
      if (!pending.removalBarrierPassed) {
        await this._durabilityBarrier('prior-snapshot-removed', {
          peerPubkey: pending.peerPubkey,
          snapshotId: pending.replacement.snapshotId,
          priorSnapshotId: pending.pointer.snapshotId
        })
        pending.removalBarrierPassed = true
      }
      if (!pending.directorySynced) {
        await this._syncOwnedDirectory(this.snapshotsDir, 'catalog snapshots directory')
        pending.directorySynced = true
      }
      if (!pending.syncBarrierPassed) {
        await this._durabilityBarrier('snapshots-directory-resynced', {
          peerPubkey: pending.peerPubkey,
          snapshotId: pending.replacement.snapshotId,
          priorSnapshotId: pending.pointer.snapshotId
        })
        pending.syncBarrierPassed = true
      }
      this._failedReclaims.delete(pending.pointer.directory)
      return true
    } catch (err) {
      this._storageFault = true
      this._failedReclaims.set(pending.pointer.directory, pending)
      throw err
    } finally {
      this._reclaimingSnapshots.delete(pending.pointer.directory)
    }
  }

  async _assertOwnedLayout () {
    try {
      for (const [path, field] of [
        [this.rootDir, 'catalog stage root'],
        [this.stagingDir, 'catalog staging parent'],
        [this.snapshotsDir, 'catalog snapshots parent'],
        [this.peersDir, 'catalog peers parent']
      ]) {
        const identity = this._ownedDirectoryIdentities.get(path)
        if (identity === undefined) fail('RESOURCE_LIMIT', `${field} has no pinned identity`)
        await assertOwnedDirectory(path, field, identity, this._ownerUid, this)
      }
    } catch (err) {
      this._storageFault = true
      throw err
    }
  }

  async _assertOwnedParent (parent, field) {
    try {
      const rootIdentity = this._ownedDirectoryIdentities.get(this.rootDir)
      const parentIdentity = this._ownedDirectoryIdentities.get(parent)
      if (rootIdentity === undefined || parentIdentity === undefined) {
        fail('RESOURCE_LIMIT', `${field} is outside the pinned catalog layout`)
      }
      await assertOwnedDirectory(this.rootDir, 'catalog stage root', rootIdentity, this._ownerUid, this)
      if (parent !== this.rootDir) await assertOwnedDirectory(parent, field, parentIdentity, this._ownerUid, this)
    } catch (err) {
      this._storageFault = true
      throw err
    }
  }

  async _syncOwnedDirectory (path, field) {
    const identity = this._ownedDirectoryIdentities.get(path)
    if (identity === undefined) fail('RESOURCE_LIMIT', `${field} has no pinned identity`)
    const parent = dirname(path)
    if (path !== this.rootDir) await this._assertOwnedParent(parent, `${field} parent`)
    await syncOwnedDirectory(path, field, identity, this._ownerUid, this)
    if (path !== this.rootDir) await this._assertOwnedParent(parent, `${field} parent`)
  }

  async _removeOwnedFile (path, parent, field, allowMissing = false) {
    try {
      if (dirname(path) !== parent) fail('RESOURCE_LIMIT', `${field} escaped its owned parent`)
      await this._assertOwnedParent(parent, `${field} parent`)
      const identity = await inspectOwnedPath(path, 'file', field, null, this._ownerUid, this)
      await this._assertOwnedParent(parent, `${field} parent`)
      await inspectOwnedPath(path, 'file', field, identity, this._ownerUid, this)
      await unlink(path)
      return true
    } catch (err) {
      if (allowMissing && err && err.code === 'ENOENT') return false
      throw err
    }
  }

  async _removeOwnedCatalogDirectory (path, parent, field, pinnedIdentity = null, allowMissing = false) {
    let pinHandle = null
    let directory = null
    try {
      if (dirname(path) !== parent) fail('RESOURCE_LIMIT', `${field} escaped its owned parent`)
      await this._assertOwnedParent(parent, `${field} parent`)
      const identity = await assertOwnedDirectory(path, field, pinnedIdentity, this._ownerUid, this)
      pinHandle = await openReadNoFollow(path)
      const openedIdentity = assertOwnedStat(await pinHandle.stat({ bigint: true }), 'directory', field, this._ownerUid)
      if (!sameIdentity(identity, openedIdentity)) fail('RESOURCE_LIMIT', `${field} changed before cleanup was pinned`)

      directory = await opendir(path)
      while (true) {
        const entry = await directory.read()
        if (entry === null) break
        if (!OWNED_CATALOG_FILES.has(entry.name)) {
          fail('RESOURCE_LIMIT', `${field} contains an unowned cleanup entry`)
        }
        const entryPath = join(path, entry.name)
        const entryIdentity = await inspectOwnedPath(entryPath, 'file', `${field} file`, null, this._ownerUid, this)
        await this._assertOwnedParent(parent, `${field} parent`)
        await assertOwnedDirectory(path, field, identity, this._ownerUid, this)
        await inspectOwnedPath(entryPath, 'file', `${field} file`, entryIdentity, this._ownerUid, this)
        await unlink(entryPath)
      }
      await closeOwnedResource(this, directory, `${field} directory enumeration handle`)
      directory = null
      await this._assertOwnedParent(parent, `${field} parent`)
      await assertOwnedDirectory(path, field, identity, this._ownerUid, this)
      await closeOwnedResource(this, pinHandle, `${field} pinned directory handle`)
      pinHandle = null
      await rmdir(path)
      return true
    } catch (err) {
      if (allowMissing && err && err.code === 'ENOENT') return false
      throw err
    } finally {
      await closeOwnedResources(this, [
        { resource: directory, field: `${field} directory enumeration handle` },
        { resource: pinHandle, field: `${field} pinned directory handle` }
      ])
    }
  }

  async _initialize (epoch) {
    await mkdir(this.rootDir, { recursive: true, mode: 0o700 })
    this._assertRunning(epoch)
    const rootIdentity = await assertOwnedDirectory(this.rootDir, 'catalog stage root', null, null, this)
    this._assertRunning(epoch)
    this._ownerUid = rootIdentity.uid
    this._ownedDirectoryIdentities.set(this.rootDir, rootIdentity)
    for (const path of [this.stagingDir, this.snapshotsDir, this.peersDir]) {
      await mkdir(path, { recursive: true, mode: 0o700 })
      this._assertRunning(epoch)
      const identity = await assertOwnedDirectory(path, 'catalog owned directory', null, this._ownerUid, this)
      this._assertRunning(epoch)
      this._ownedDirectoryIdentities.set(path, identity)
    }
    await this._reconcileOwnedState(epoch)
    this._assertRunning(epoch)
  }

  async _reconcileOwnedState (epoch = this._lifecycleEpoch) {
    this._assertRunning(epoch)
    await this._assertOwnedLayout()
    this._assertRunning(epoch)
    const state = { examined: 0 }
    let stagingChanged = false
    try {
      await scanReconciliationDirectory(this.stagingDir, state, async entry => {
        this._assertRunning(epoch)
        if (!OWNED_CATALOG_DIRECTORY.test(entry.name)) {
          fail('RESOURCE_LIMIT', 'catalog staging directory contains an unowned entry')
        }
        const path = join(this.stagingDir, entry.name)
        const identity = await assertOwnedEntry(path, 'directory', 'catalog stale staging entry', this._ownerUid, this)
        this._assertRunning(epoch)
        await this._removeOwnedCatalogDirectory(
          path,
          this.stagingDir,
          'catalog stale staging entry',
          identity
        )
        this._assertRunning(epoch)
        stagingChanged = true
      }, this)
    } finally {
      if (stagingChanged) {
        await this._syncOwnedDirectory(this.stagingDir, 'catalog staging directory')
        await this._durabilityBarrier('reconciled-staging-directory-synced', {})
        this._assertRunning(epoch)
      }
    }

    const referencedSnapshots = new Set()
    let peerPointers = 0
    let peersChanged = false
    try {
      await scanReconciliationDirectory(this.peersDir, state, async entry => {
        this._assertRunning(epoch)
        const path = join(this.peersDir, entry.name)
        if (OWNED_TEMPORARY_POINTER.test(entry.name)) {
          await assertOwnedEntry(path, 'file', 'catalog temporary pointer', this._ownerUid, this)
          this._assertRunning(epoch)
          await this._removeOwnedFile(path, this.peersDir, 'catalog temporary pointer')
          this._assertRunning(epoch)
          peersChanged = true
          return
        }
        const match = OWNED_PEER_POINTER.exec(entry.name)
        if (!match) fail('RESOURCE_LIMIT', 'catalog peer directory contains an unowned entry')
        peerPointers++
        if (peerPointers > APP_CATALOG_LIMITS.maxInboundPeers) {
          fail('RESOURCE_LIMIT', 'catalog committed peer pointer cap exceeded')
        }
        await assertOwnedEntry(path, 'file', 'catalog peer pointer', this._ownerUid, this)
        const pointer = await existingPointer(path, match[1], this._ownerUid, this)
        this._assertRunning(epoch)
        if (pointer === null) fail('SNAPSHOT_MISMATCH', 'catalog peer pointer disappeared during reconciliation')
        referencedSnapshots.add(pointer.directory)
        this._retainedPeers.add(pointer.peerPubkey)
      }, this)
    } finally {
      if (peersChanged) {
        await this._syncOwnedDirectory(this.peersDir, 'catalog peers directory')
        await this._durabilityBarrier('reconciled-peers-directory-synced', {})
        this._assertRunning(epoch)
      }
    }

    const missingSnapshots = new Set(referencedSnapshots)
    let snapshotsChanged = false
    try {
      await scanReconciliationDirectory(this.snapshotsDir, state, async entry => {
        this._assertRunning(epoch)
        if (!OWNED_CATALOG_DIRECTORY.test(entry.name)) {
          fail('RESOURCE_LIMIT', 'catalog snapshot directory contains an unowned entry')
        }
        const path = join(this.snapshotsDir, entry.name)
        const identity = await assertOwnedEntry(path, 'directory', 'catalog snapshot entry', this._ownerUid, this)
        this._assertRunning(epoch)
        if (referencedSnapshots.has(entry.name)) {
          missingSnapshots.delete(entry.name)
          return
        }
        await this._removeOwnedCatalogDirectory(
          path,
          this.snapshotsDir,
          'catalog unreferenced snapshot entry',
          identity
        )
        this._assertRunning(epoch)
        snapshotsChanged = true
      }, this)
    } finally {
      if (snapshotsChanged) {
        await this._syncOwnedDirectory(this.snapshotsDir, 'catalog snapshots directory')
        await this._durabilityBarrier('reconciled-snapshots-directory-synced', {})
        this._assertRunning(epoch)
      }
    }
    if (missingSnapshots.size !== 0) {
      fail('SNAPSHOT_MISMATCH', 'catalog peer pointer references a missing snapshot directory')
    }
  }
}

export class AppCatalogDiskStage {
  constructor (factory, opts) {
    this.factory = factory
    this.peerPubkey = opts.peerPubkey
    this.snapshotId = opts.snapshotId
    this.highWater = opts.highWater
    this.rootDigest = opts.rootDigest
    this.entryCount = opts.entryCount
    this.path = opts.path
    this.pathIdentity = opts.pathIdentity
    this.rowsHandle = opts.rowsHandle
    this.indexHandle = opts.indexHandle
    this.manifestHandle = null
    this.pointerHandle = null
    this.temporaryPointer = null
    this.publishedPointer = null
    this.priorPointer = null
    this.peersDirectorySynced = false
    this.peersBarrierPassed = false
    this.rows = 0
    this.bytes = 0
    this.rowsFileOffset = 0
    this.lastRowKey = null
    this.closed = false
    this.committed = false
    this.discardRequested = false
    this._mutationTail = Promise.resolve()
    this._discard = null
  }

  append (row, recordBytes) {
    this.factory._assertRunning()
    if (this.discardRequested) fail('RESOURCE_LIMIT', 'catalog stage discard is in progress')
    const epoch = this.factory._lifecycleEpoch
    return this._queueMutation(() => this._append(row, recordBytes, epoch))
  }

  async _append (row, recordBytes, epoch) {
    if (this.closed) fail('RESOURCE_LIMIT', 'catalog stage is closed')
    if (!Array.isArray(row) || !recordBytes || !b4a.isBuffer(recordBytes)) fail('PROTOCOL_ERROR', 'catalog stage append is invalid')
    const canonical = validateCanonicalCatalogRow(row)
    if (this.lastRowKey !== null && canonical[0] <= this.lastRowKey) {
      fail('SNAPSHOT_MISMATCH', 'catalog stage rows are not strictly ordered')
    }
    const expected = b4a.from(JSON.stringify(canonical), 'utf8')
    if (!b4a.equals(expected, recordBytes)) fail('PROTOCOL_ERROR', 'catalog stage record bytes are not canonical')
    const length = b4a.alloc(4)
    length.writeUInt32BE(recordBytes.byteLength, 0)
    const indexRecord = b4a.concat([
      b4a.from(canonical[0], 'ascii'),
      uint64Bytes(this.rowsFileOffset)
    ])
    await writeAll(this.indexHandle, indexRecord)
    this.factory._assertRunning(epoch)
    await writeAll(this.rowsHandle, length)
    this.factory._assertRunning(epoch)
    await writeAll(this.rowsHandle, recordBytes)
    this.factory._assertRunning(epoch)
    this.rows++
    this.bytes += 4 + recordBytes.byteLength
    this.rowsFileOffset += 4 + recordBytes.byteLength
    this.lastRowKey = canonical[0]
  }

  commit (snapshot) {
    this.factory._assertRunning()
    if (this.discardRequested) fail('RESOURCE_LIMIT', 'catalog stage discard is in progress')
    const epoch = this.factory._lifecycleEpoch
    return this._queueMutation(() => this._commit(snapshot, epoch))
  }

  async _commit (snapshot, epoch) {
    if (this.closed) fail('RESOURCE_LIMIT', 'catalog stage is closed')
    this.factory._assertRunning(epoch)
    if (this.publishedPointer !== null) {
      await this._settlePublishedCommit(epoch)
      await this._retirePriorPointer()
      this.factory._assertRunning(epoch)
      return this.factory._committed(this.publishedPointer, this.peerPubkey)
    }
    if (!snapshot || snapshot.snapshotId !== this.snapshotId || snapshot.highWater !== this.highWater ||
        snapshot.rootDigest !== this.rootDigest || snapshot.entryCount !== this.entryCount ||
        this.rows !== this.entryCount) {
      fail('SNAPSHOT_MISMATCH', 'catalog stage commit tuple mismatch')
    }
    const manifest = Object.freeze({
      version: 1,
      peerPubkey: this.peerPubkey,
      snapshotId: this.snapshotId,
      highWater: this.highWater,
      rootDigest: this.rootDigest,
      entryCount: this.entryCount,
      encodedRecordBytes: this.bytes
    })
    await this.factory._assertOwnedLayout()
    this.factory._assertRunning(epoch)
    await assertOwnedDirectory(this.path, 'catalog staging directory', this.pathIdentity, this.factory._ownerUid, this.factory)
    this.factory._assertRunning(epoch)
    this.manifestHandle = await this.factory._openExclusive(join(this.path, 'manifest.json'))
    try {
      this.factory._assertRunning(epoch)
      const manifestIdentity = await inspectOwnedPath(
        join(this.path, 'manifest.json'),
        'file',
        'catalog staged manifest',
        null,
        this.factory._ownerUid,
        this.factory
      )
      const openedManifestIdentity = assertOwnedStat(
        await this.manifestHandle.stat({ bigint: true }),
        'file',
        'catalog staged manifest',
        this.factory._ownerUid
      )
      if (!sameIdentity(manifestIdentity, openedManifestIdentity)) fail('RESOURCE_LIMIT', 'catalog staged manifest changed while it was opened')
      this.factory._assertRunning(epoch)
      await writeAll(this.manifestHandle, b4a.from(JSON.stringify(manifest), 'utf8'))
      this.factory._assertRunning(epoch)
      if (typeof this.manifestHandle.sync !== 'function') fail('RESOURCE_LIMIT', 'catalog manifest cannot be synchronized')
      await this.manifestHandle.sync()
      this.factory._assertRunning(epoch)
    } finally {
      await this._closeOwnedHandle('manifestHandle')
    }
    this.factory._assertRunning(epoch)
    if (typeof this.rowsHandle.sync !== 'function' || typeof this.indexHandle.sync !== 'function') {
      fail('RESOURCE_LIMIT', 'catalog staged files cannot be synchronized')
    }
    await this.rowsHandle.sync()
    this.factory._assertRunning(epoch)
    await this.indexHandle.sync()
    this.factory._assertRunning(epoch)
    await this.factory._durabilityBarrier('staged-files-synced', {
      peerPubkey: this.peerPubkey,
      snapshotId: this.snapshotId
    })
    this.factory._assertRunning(epoch)
    await this._closeOwnedHandle('rowsHandle')
    this.factory._assertRunning(epoch)
    await this._closeOwnedHandle('indexHandle')

    const finalName = `${this.peerPubkey}.${this.snapshotId}.${randomHex()}`
    const finalPath = join(this.factory.snapshotsDir, finalName)
    await this.factory._assertOwnedLayout()
    this.factory._assertRunning(epoch)
    await assertOwnedDirectory(this.path, 'catalog staging directory', this.pathIdentity, this.factory._ownerUid, this.factory)
    this.factory._assertRunning(epoch)
    await rename(this.path, finalPath)
    this.path = finalPath
    await assertOwnedDirectory(this.path, 'catalog snapshot directory', this.pathIdentity, this.factory._ownerUid, this.factory)
    this.factory._assertRunning(epoch)
    try {
      await this.factory._syncOwnedDirectory(this.factory.snapshotsDir, 'catalog snapshots directory')
      this.factory._assertRunning(epoch)
      await this.factory._durabilityBarrier('snapshots-directory-synced', {
        peerPubkey: this.peerPubkey,
        snapshotId: this.snapshotId
      })
      this.factory._assertRunning(epoch)
    } catch (err) {
      this.factory._storageFault = true
      throw err
    }

    const pointerPath = join(this.factory.peersDir, `${this.peerPubkey}.json`)
    const prior = await existingPointer(pointerPath, this.peerPubkey, this.factory._ownerUid, this.factory)
    this.factory._assertRunning(epoch)
    const pointer = Object.freeze({
      version: 1,
      peerPubkey: this.peerPubkey,
      snapshotId: this.snapshotId,
      highWater: this.highWater,
      rootDigest: this.rootDigest,
      entryCount: this.entryCount,
      directory: basename(finalPath)
    })
    this.temporaryPointer = join(this.factory.peersDir, `.${this.peerPubkey}.${randomHex()}.tmp`)
    let pointerRenamed = false
    try {
      try {
        await this.factory._assertOwnedLayout()
        this.factory._assertRunning(epoch)
        this.pointerHandle = await this.factory._openExclusive(this.temporaryPointer)
        this.factory._assertRunning(epoch)
        const temporaryIdentity = await inspectOwnedPath(
          this.temporaryPointer,
          'file',
          'catalog temporary pointer',
          null,
          this.factory._ownerUid,
          this.factory
        )
        const openedTemporaryIdentity = assertOwnedStat(
          await this.pointerHandle.stat({ bigint: true }),
          'file',
          'catalog temporary pointer',
          this.factory._ownerUid
        )
        if (!sameIdentity(temporaryIdentity, openedTemporaryIdentity)) fail('RESOURCE_LIMIT', 'catalog temporary pointer changed while it was opened')
        this.factory._assertRunning(epoch)
        await writeAll(this.pointerHandle, b4a.from(JSON.stringify(pointer), 'utf8'))
        this.factory._assertRunning(epoch)
        if (typeof this.pointerHandle.sync !== 'function') fail('RESOURCE_LIMIT', 'catalog temporary pointer cannot be synchronized')
        await this.pointerHandle.sync()
        this.factory._assertRunning(epoch)
      } finally {
        await this._closeOwnedHandle('pointerHandle')
      }
      this.factory._assertRunning(epoch)
      await this.factory._durabilityBarrier('temporary-pointer-synced', {
        peerPubkey: this.peerPubkey,
        snapshotId: this.snapshotId
      })
      this.factory._assertRunning(epoch)
      if (this.factory._beforePointerRename !== null) {
        await this.factory._beforePointerRename({ temporaryPointer: this.temporaryPointer, pointerPath, pointer })
        this.factory._assertRunning(epoch)
      }
      await this.factory._assertOwnedLayout()
      this.factory._assertRunning(epoch)
      await inspectOwnedPath(this.temporaryPointer, 'file', 'catalog temporary pointer', null, this.factory._ownerUid, this.factory)
      const authoritativePrior = await existingPointer(pointerPath, this.peerPubkey, this.factory._ownerUid, this.factory)
      if (!samePointerState(authoritativePrior, prior)) fail('RESOURCE_LIMIT', 'catalog peer pointer changed during commit')
      await this.factory._assertOwnedLayout()
      await inspectOwnedPath(this.temporaryPointer, 'file', 'catalog temporary pointer', null, this.factory._ownerUid, this.factory)
      if (authoritativePrior !== null) await inspectOwnedPath(pointerPath, 'file', 'catalog prior peer pointer', null, this.factory._ownerUid, this.factory)
      this.factory._assertRunning(epoch)
      await rename(this.temporaryPointer, pointerPath)
      pointerRenamed = true
      this.temporaryPointer = null
      this.publishedPointer = pointer
      this.priorPointer = prior
      await this._settlePublishedCommit(epoch)
    } catch (err) {
      if (pointerRenamed) {
        this.factory._storageFault = true
      } else {
        if (this.pointerHandle === null && this.temporaryPointer !== null) {
          try {
            await this.factory._removeOwnedFile(
              this.temporaryPointer,
              this.factory.peersDir,
              'catalog temporary pointer',
              true
            )
            this.temporaryPointer = null
          } catch (cleanupError) {
            this.factory._storageFault = true
            throw cleanupError
          }
        }
      }
      throw err
    }

    // The pointer transaction has committed the new complete catalog. A prior
    // owned snapshot is now unreachable and can be reclaimed without ever
    // touching a caller-supplied path or following a symlink.
    await this._retirePriorPointer()
    this.factory._assertRunning(epoch)
    return this.factory._committed(pointer, this.peerPubkey)
  }

  async _settlePublishedCommit (epoch = null) {
    if (this.publishedPointer === null) fail('RESOURCE_LIMIT', 'catalog commit has no published pointer to settle')
    if (!this.peersDirectorySynced) {
      await this.factory._syncOwnedDirectory(this.factory.peersDir, 'catalog peers directory')
      this.peersDirectorySynced = true
      if (epoch !== null) this.factory._assertRunning(epoch)
    }
    if (!this.peersBarrierPassed) {
      await this.factory._durabilityBarrier('peers-directory-synced', {
        peerPubkey: this.peerPubkey,
        snapshotId: this.snapshotId
      })
      this.peersBarrierPassed = true
      if (epoch !== null) this.factory._assertRunning(epoch)
    }
    this._finishCommitted()
  }

  async _retirePriorPointer () {
    const prior = this.priorPointer
    const pointer = this.publishedPointer
    if (prior === null || pointer === null) return
    this.priorPointer = null
    if (prior.directory !== pointer.directory && basename(prior.directory) === prior.directory) {
      await this.factory._retireSnapshot(prior, pointer)
    }
  }

  _finishCommitted () {
    if (this.closed) return
    if (this.rowsHandle !== null || this.indexHandle !== null || this.manifestHandle !== null ||
        this.pointerHandle !== null || this.temporaryPointer !== null) {
      this.factory._storageFault = true
      fail('RESOURCE_LIMIT', 'catalog commit retained unresolved file ownership')
    }
    this.committed = true
    this.closed = true
    this.factory._active.delete(this)
    this.factory._releasePeer(this.peerPubkey, true)
  }

  _queueMutation (mutate) {
    const operation = this._mutationTail.then(mutate)
    this._mutationTail = operation.catch(() => {})
    return this.factory._trackOperation(operation)
  }

  async _closeOwnedHandle (field) {
    const handle = this[field]
    if (handle === null) return false
    await handle.close()
    if (this[field] === handle) this[field] = null
    return true
  }

  discard () {
    if (this._discard !== null) return this._discard
    this.discardRequested = true
    const drain = this._mutationTail
    const discard = this._discardAfterMutations(drain)
    this._discard = discard
    discard.catch(() => {
      if (this._discard === discard) this._discard = null
    })
    return discard
  }

  async _discardAfterMutations (drain) {
    await drain
    if (this.publishedPointer !== null && !this.committed) {
      await this._settlePublishedCommit()
      await this._retirePriorPointer()
      return
    }
    if (this.committed) return
    let closeError = null
    for (const field of ['rowsHandle', 'indexHandle', 'manifestHandle', 'pointerHandle']) {
      try {
        await this._closeOwnedHandle(field)
      } catch (err) {
        if (closeError === null) closeError = err
      }
    }
    if (closeError !== null) {
      this.factory._storageFault = true
      throw closeError
    }
    try {
      if (this.temporaryPointer !== null) {
        await this.factory._removeOwnedFile(
          this.temporaryPointer,
          this.factory.peersDir,
          'catalog discarded temporary pointer',
          true
        )
        this.temporaryPointer = null
      }
      const parent = dirname(this.path)
      if (parent !== this.factory.stagingDir && parent !== this.factory.snapshotsDir) {
        fail('RESOURCE_LIMIT', 'catalog discarded stage escaped its owned parent')
      }
      await this.factory._removeOwnedCatalogDirectory(
        this.path,
        parent,
        'catalog discarded stage',
        this.pathIdentity,
        true
      )
      await this.factory._syncOwnedDirectory(parent, 'catalog discarded stage parent')
      await this.factory._durabilityBarrier('discarded-stage-directory-synced', {
        peerPubkey: this.peerPubkey,
        snapshotId: this.snapshotId
      })
      this.closed = true
      this.factory._active.delete(this)
      this.factory._releasePeer(this.peerPubkey, false)
    } catch (err) {
      this.factory._storageFault = true
      throw err
    }
  }
}

export class AppCatalogCommittedCatalog {
  constructor (opts) {
    this.version = 1
    this.peerPubkey = opts.peerPubkey
    this.snapshotId = opts.snapshotId
    this.highWater = opts.highWater
    this.rootDigest = opts.rootDigest
    this.entryCount = opts.entryCount
    this.directory = opts.directory
    this.path = opts.path
    Object.freeze(this)
  }

  get released () {
    const state = COMMITTED_HANDLE_STATE.get(this)
    return !state || state.released
  }

  acquire () {
    const state = COMMITTED_HANDLE_STATE.get(this)
    if (!state || state.released) fail('RESOURCE_LIMIT', 'catalog committed handle is released')
    state.factory._assertRunning()
    return state.factory._committed({
      version: 1,
      peerPubkey: this.peerPubkey,
      snapshotId: this.snapshotId,
      highWater: this.highWater,
      rootDigest: this.rootDigest,
      entryCount: this.entryCount,
      directory: this.directory
    }, this.peerPubkey)
  }

  release () {
    const state = COMMITTED_HANDLE_STATE.get(this)
    if (!state) return Promise.resolve(false)
    return state.factory._releaseCommitted(this)
  }

  readPage (opts = {}) {
    const state = COMMITTED_HANDLE_STATE.get(this)
    if (!state || state.released) fail('RESOURCE_LIMIT', 'catalog committed handle is released')
    state.factory._assertRunning()
    const epoch = state.factory._lifecycleEpoch
    const readLease = this.acquire()
    const operation = this._readPage(opts, state.factory, state.ownerUid, epoch).finally(() => readLease.release())
    return state.factory._trackOperation(operation)
  }

  async _readPage (opts, factory, ownerUid, epoch) {
    const cursor = opts.cursor === undefined ? null : opts.cursor
    const limit = opts.limit === undefined ? APP_CATALOG_LIMITS.maxPageEntries : opts.limit
    if (cursor !== null) assertHex64(cursor, 'committed catalog cursor')
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > APP_CATALOG_LIMITS.externalApiMaxPageEntries) {
      fail('RESOURCE_LIMIT', 'committed catalog page limit is outside 1..500')
    }
    await factory._assertOwnedLayout()
    factory._assertRunning(epoch)
    const committedIdentity = await assertOwnedDirectory(
      this.path,
      'committed catalog directory',
      null,
      ownerUid,
      factory
    )
    factory._assertRunning(epoch)
    let indexHandle = null
    let rowsHandle = null
    try {
      indexHandle = (await factory._openOwnedRead(
        join(this.path, 'index.bin'),
        'file',
        'catalog committed index'
      )).handle
      factory._assertRunning(epoch)
      await assertOwnedDirectory(this.path, 'committed catalog directory', committedIdentity, ownerUid, factory)
      rowsHandle = (await factory._openOwnedRead(
        join(this.path, 'rows.bin'),
        'file',
        'catalog committed rows'
      )).handle
      factory._assertRunning(epoch)
      const indexStat = await indexHandle.stat({ bigint: true })
      factory._assertRunning(epoch)
      assertOwnedStat(indexStat, 'file', 'catalog committed index', ownerUid)
      if (!statSizeEquals(indexStat.size, this.entryCount * CATALOG_INDEX_RECORD_BYTES)) {
        fail('SNAPSHOT_MISMATCH', 'committed catalog index size mismatch')
      }
      let low = 0
      let high = this.entryCount
      while (low < high) {
        const middle = (low + high) >>> 1
        const index = await this._readIndex(indexHandle, middle)
        factory._assertRunning(epoch)
        if (cursor !== null && index.rowKey <= cursor) low = middle + 1
        else high = middle
      }
      const entries = []
      let lastRowKey = cursor
      let position = low
      while (position < this.entryCount && entries.length < limit) {
        const index = await this._readIndex(indexHandle, position)
        factory._assertRunning(epoch)
        const length = await readExact(rowsHandle, b4a.alloc(4), index.offset)
        factory._assertRunning(epoch)
        const recordBytes = length.readUInt32BE(0)
        if (recordBytes > APP_CATALOG_LIMITS.maxPayloadBytes) {
          fail('CATALOG_ENTRY_TOO_LARGE', 'committed catalog record exceeds wire limit')
        }
        const frame = b4a.alloc(4 + recordBytes)
        length.copy(frame, 0)
        await readExact(rowsHandle, frame.subarray(4), index.offset + 4)
        factory._assertRunning(epoch)
        const row = validateCanonicalCatalogRow(decodeAppCatalogFrame(frame))
        if (row[0] !== index.rowKey || (lastRowKey !== null && row[0] <= lastRowKey)) {
          fail('SNAPSHOT_MISMATCH', 'committed catalog index ordering mismatch')
        }
        entries.push(row)
        lastRowKey = row[0]
        position++
      }
      const complete = position === this.entryCount
      await assertOwnedDirectory(this.path, 'committed catalog directory', committedIdentity, ownerUid, factory)
      factory._assertRunning(epoch)
      return Object.freeze({
        entries: Object.freeze(entries),
        complete,
        cursor: complete ? null : lastRowKey,
        highWater: this.highWater,
        rootDigest: this.rootDigest,
        entryCount: this.entryCount
      })
    } finally {
      await closeOwnedResources(factory, [
        { resource: indexHandle, field: 'catalog committed page index handle' },
        { resource: rowsHandle, field: 'catalog committed page rows handle' }
      ])
    }
  }

  async _readIndex (handle, position) {
    const record = await readExact(handle, b4a.alloc(72), position * 72)
    const rowKey = b4a.toString(record.subarray(0, 64), 'ascii')
    assertHex64(rowKey, 'committed catalog index rowKey')
    return { rowKey, offset: decodeUint64(record.subarray(64)) }
  }
}
