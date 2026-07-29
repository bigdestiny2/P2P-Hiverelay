import fs from 'node:fs/promises'
import { constants as FS_CONSTANTS } from 'node:fs'
import path from 'node:path'
import { randomBytes } from 'node:crypto'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  blindStoreManifestV1,
  decodeCanonical,
  encodeCanonical
} from '@hiverelay/blind-protocol'

const SLOT_NAMES = Object.freeze({ a: 'manifest-a.v1', b: 'manifest-b.v1' })
const MAX_MANIFEST_BYTES = 4096
const MAX_TEMP_FILES = 16
const ZERO32 = b4a.alloc(32)
const MAC_DOMAIN = b4a.from('hiverelay.blind.store-manifest-mac.v1', 'ascii')
const HASH_DOMAIN = b4a.from('hiverelay.blind.store-manifest-hash.v1', 'ascii')
const MANIFEST_SNAPSHOT_STATE = new WeakMap()
const MANIFEST_STORE_STATE = new WeakMap()
const ACTIVE_MANIFEST_DIRECTORIES = new Set()
const REQUIRED_BINDINGS = Object.freeze([
  'storeId',
  'relayPublicKey',
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
  'writerFenceTokenHash'
])

export class BlindManifestIntegrityError extends Error {
  constructor (message) {
    super(message)
    this.name = 'BlindManifestIntegrityError'
    this.code = 'RECOVERY_GAP_READ_ONLY'
  }
}

function asBytes (value, length, field, nonzero = false) {
  if (!value || typeof value.byteLength !== 'number') throw new TypeError(`${field} must be bytes`)
  value = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (length != null && value.byteLength !== length) throw new TypeError(`${field} must be exactly ${length} bytes`)
  if (nonzero && b4a.equals(value, ZERO32)) throw new TypeError(`${field} must be nonzero`)
  return value
}

function u64bytes (value) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) throw new TypeError('u64 value is invalid')
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > ((1n << 64n) - 1n)) {
    throw new TypeError('u64 value is invalid')
  }
  const output = b4a.alloc(8)
  for (let index = 7; index >= 0; index--) {
    output[index] = Number(value & 0xffn)
    value >>= 8n
  }
  return output
}

function hashParts (domain, bytes, key = null) {
  const input = b4a.concat([domain, u64bytes(bytes.byteLength), bytes])
  const output = b4a.alloc(32)
  if (key == null) sodium.crypto_generichash(output, input)
  else sodium.crypto_generichash(output, input, key)
  return output
}

function manifestWithoutMac (value) {
  const placeholder = b4a.alloc(32, 1)
  const complete = encodeCanonical(blindStoreManifestV1, { ...value, mac: placeholder })
  return complete.subarray(0, complete.byteLength - 32)
}

export function sealBlindStoreManifest (value, manifestKey) {
  manifestKey = asBytes(manifestKey, 32, 'manifestKey', true)
  const unsigned = manifestWithoutMac(value)
  const mac = hashParts(MAC_DOMAIN, unsigned, manifestKey)
  return encodeCanonical(blindStoreManifestV1, { ...value, mac })
}

export function blindStoreManifestHash (canonicalBytes) {
  canonicalBytes = asBytes(canonicalBytes, null, 'canonical manifest bytes')
  return hashParts(HASH_DOMAIN, canonicalBytes)
}

function verifyManifest (canonicalBytes, manifestKey) {
  canonicalBytes = asBytes(canonicalBytes, null, 'canonical manifest bytes')
  if (canonicalBytes.byteLength < 64 || canonicalBytes.byteLength > MAX_MANIFEST_BYTES) {
    throw new BlindManifestIntegrityError('manifest size is outside its closed bound')
  }
  let value
  try {
    value = decodeCanonical(blindStoreManifestV1, canonicalBytes, { copyBytes: true })
    if (!b4a.equals(encodeCanonical(blindStoreManifestV1, value), canonicalBytes)) {
      throw new Error('non-canonical')
    }
  } catch (error) {
    throw new BlindManifestIntegrityError(`manifest is not canonical: ${error.message}`)
  }
  const expectedMac = hashParts(MAC_DOMAIN, manifestWithoutMac(value), manifestKey)
  if (!b4a.equals(expectedMac, value.mac)) {
    throw new BlindManifestIntegrityError('manifest MAC verification failed')
  }
  return {
    bytes: b4a.from(canonicalBytes),
    hash: blindStoreManifestHash(canonicalBytes),
    value
  }
}

function sameInode (left, right) {
  return left.dev === right.dev && left.ino === right.ino
}

function assertPrivateFile (stat, field) {
  if (!stat.isFile() || stat.nlink !== 1) throw new BlindManifestIntegrityError(`${field} is not a single-link regular file`)
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
    throw new BlindManifestIntegrityError(`${field} is not owned by the daemon UID`)
  }
  if ((stat.mode & 0o600) !== 0o600 || (stat.mode & 0o077) !== 0) {
    throw new BlindManifestIntegrityError(`${field} permissions are not private`)
  }
}

async function syncDirectory (directory) {
  const handle = await fs.open(directory, FS_CONSTANTS.O_RDONLY)
  try {
    await handle.sync()
  } finally {
    await handle.close()
  }
}

async function readAll (handle, size) {
  const output = b4a.alloc(size)
  let offset = 0
  while (offset < size) {
    const { bytesRead } = await handle.read(output, offset, size - offset, offset)
    if (bytesRead === 0) throw new BlindManifestIntegrityError('manifest file ended before its declared size')
    offset += bytesRead
  }
  return output
}

function bindingCopy (value, field) {
  if (value && typeof value.byteLength === 'number') return b4a.from(asBytes(value, null, field))
  if (typeof value === 'bigint' || typeof value === 'number') return value
  throw new TypeError(`expectedBindings.${field} has an unsupported type`)
}

function sameBinding (left, right) {
  if (left && typeof left.byteLength === 'number') {
    return right && typeof right.byteLength === 'number' && b4a.equals(left, right)
  }
  return left === right
}

function manifestPrivate (store) {
  const state = MANIFEST_STORE_STATE.get(store)
  if (!state) throw new BlindManifestIntegrityError('manifest store identity is invalid')
  return state
}

function publicSnapshot (store, record) {
  const privateState = manifestPrivate(store)
  const value = decodeCanonical(blindStoreManifestV1, record.bytes, { copyBytes: true })
  const snapshot = Object.freeze({
    slot: record.slot,
    needsRepair: record.needsRepair,
    revision: value.manifestRevision,
    bytes: b4a.from(record.bytes),
    hash: b4a.from(record.hash),
    manifest: Object.freeze(value)
  })
  MANIFEST_SNAPSHOT_STATE.set(snapshot, Object.freeze({
    store,
    generation: privateState.generation,
    controlDirectory: store.controlDirectory,
    bytes: b4a.from(record.bytes),
    hash: b4a.from(record.hash)
  }))
  return snapshot
}

export function verifyBlindManifestSnapshot (snapshot, expectedControlDirectory) {
  if (!snapshot || typeof snapshot !== 'object') {
    throw new BlindManifestIntegrityError('manifest snapshot is missing or forged')
  }
  const state = MANIFEST_SNAPSHOT_STATE.get(snapshot)
  const storeState = state && MANIFEST_STORE_STATE.get(state.store)
  if (!state || state.controlDirectory !== expectedControlDirectory ||
      !storeState || !storeState.opened || storeState.closing ||
      state.store.controlDirectory !== expectedControlDirectory ||
      storeState.generation !== state.generation || storeState.currentSelectedHash == null ||
      !b4a.equals(storeState.currentSelectedHash, state.hash) ||
      !b4a.equals(state.bytes, snapshot.bytes) || !b4a.equals(state.hash, snapshot.hash)) {
    throw new BlindManifestIntegrityError('manifest snapshot is forged, stale-lifetime, or belongs to another store')
  }
  return true
}

export function advanceBlindManifestSnapshot (snapshot, expectedControlDirectory, expectedHash, updates) {
  verifyBlindManifestSnapshot(snapshot, expectedControlDirectory)
  const state = MANIFEST_SNAPSHOT_STATE.get(snapshot)
  expectedHash = asBytes(expectedHash, 32, 'expected manifest hash')
  if (!b4a.equals(state.hash, expectedHash)) {
    throw new BlindManifestIntegrityError('branded manifest CAS expected hash differs from its snapshot')
  }
  return state.store.advance(expectedHash, updates)
}

export class TwoSlotManifestStore {
  constructor (options = {}) {
    if (typeof options.controlDirectory !== 'string' || !path.isAbsolute(options.controlDirectory) ||
        path.normalize(options.controlDirectory) !== options.controlDirectory || options.controlDirectory.includes('\0')) {
      throw new TypeError('controlDirectory must be a canonical absolute path')
    }
    if (!options.expectedBindings || typeof options.expectedBindings !== 'object' ||
        Array.isArray(options.expectedBindings) || Object.keys(options.expectedBindings).length === 0) {
      throw new TypeError('expectedBindings must be a non-empty object')
    }
    for (const field of REQUIRED_BINDINGS) {
      if (!Object.prototype.hasOwnProperty.call(options.expectedBindings, field)) {
        throw new TypeError(`expectedBindings.${field} is required`)
      }
    }
    this.controlDirectory = options.controlDirectory
    this.manifestKey = b4a.from(asBytes(options.manifestKey, 32, 'manifestKey', true))
    this.expectedBindings = Object.freeze(Object.fromEntries(Object.entries(options.expectedBindings)
      .map(([field, value]) => [field, bindingCopy(value, field)])))
    this.faultInjector = options.faultInjector == null ? null : options.faultInjector
    if (this.faultInjector != null && typeof this.faultInjector !== 'function') {
      throw new TypeError('faultInjector must be a function')
    }
    this.opened = false
    this.validationOnly = false
    this.closing = false
    this.closePromise = null
    this.serial = Promise.resolve()
    this.generation = 0
    this.currentSelectedHash = null
    MANIFEST_STORE_STATE.set(this, {
      generation: 0,
      currentSelectedHash: null,
      opened: false,
      closing: false
    })
  }

  async open (options = {}) {
    if (this.opened) throw new Error('manifest store is already open')
    if (ACTIVE_MANIFEST_DIRECTORIES.has(this.controlDirectory)) {
      throw new BlindManifestIntegrityError('manifest control directory already has an active in-process owner')
    }
    if (!options || typeof options !== 'object' || Array.isArray(options) ||
        Object.keys(options).some(key => key !== 'validationOnly') ||
        (options.validationOnly != null && typeof options.validationOnly !== 'boolean')) {
      throw new TypeError('manifest open options may contain only validationOnly')
    }
    const validationOnly = options.validationOnly === true
    ACTIVE_MANIFEST_DIRECTORIES.add(this.controlDirectory)
    let opened = false
    try {
      const stat = await fs.lstat(this.controlDirectory)
      if (!stat.isDirectory() || stat.isSymbolicLink()) {
        throw new BlindManifestIntegrityError('manifest control root is not a directory')
      }
      if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
        throw new BlindManifestIntegrityError('manifest control root is not owned by the daemon UID')
      }
      if ((stat.mode & 0o700) !== 0o700 || (stat.mode & 0o077) !== 0) {
        throw new BlindManifestIntegrityError('manifest control root permissions are not private')
      }
      if (await fs.realpath(this.controlDirectory) !== this.controlDirectory) {
        throw new BlindManifestIntegrityError('manifest control root is not its canonical realpath')
      }
      const temporaryFiles = await this._inspectTemps()
      if (!validationOnly) await this._cleanupTemps(temporaryFiles)
      this.generation++
      this.currentSelectedHash = null
      this.opened = true
      this.validationOnly = validationOnly
      this.closing = false
      this.closePromise = null
      const privateState = manifestPrivate(this)
      privateState.generation++
      privateState.currentSelectedHash = null
      privateState.opened = true
      privateState.closing = false
      opened = true
      return this
    } finally {
      if (!opened) ACTIVE_MANIFEST_DIRECTORIES.delete(this.controlDirectory)
    }
  }

  _serialized (operation) {
    const result = this.serial.then(operation)
    this.serial = result.catch(() => {})
    return result
  }

  _assertOpen () {
    if (!this.opened) throw new Error('manifest store is not open')
  }

  _assertAccepting () {
    this._assertOpen()
    if (this.closing) throw new Error('manifest store is closing')
  }

  _assertMutable () {
    this._assertAccepting()
    if (this.validationOnly) {
      const error = new Error('manifest store was opened in validation-only mode')
      error.code = 'BLIND_MANIFEST_VALIDATION_ONLY'
      throw error
    }
  }

  _assertBindings (manifest) {
    for (const [field, expected] of Object.entries(this.expectedBindings)) {
      if (!(field in manifest) || !sameBinding(expected, manifest[field])) {
        throw new BlindManifestIntegrityError(`manifest ${field} does not match its launch binding`)
      }
    }
  }

  async _fault (point, context) {
    if (this.faultInjector) await this.faultInjector(point, context)
  }

  async _inspectTemps () {
    const names = (await fs.readdir(this.controlDirectory))
      .filter(name => /^\.manifest-[ab]\.v1\.[0-9a-f]{32}\.tmp$/.test(name))
    if (names.length > MAX_TEMP_FILES) throw new BlindManifestIntegrityError('manifest temporary-file bound exceeded')
    for (const name of names) {
      const target = path.join(this.controlDirectory, name)
      const stat = await fs.lstat(target)
      assertPrivateFile(stat, 'manifest temporary file')
    }
    return names
  }

  async _cleanupTemps (names) {
    for (const name of names) {
      const target = path.join(this.controlDirectory, name)
      await fs.unlink(target)
    }
    if (names.length > 0) await syncDirectory(this.controlDirectory)
  }

  async _readSlot (slot) {
    const target = path.join(this.controlDirectory, SLOT_NAMES[slot])
    let pathStat
    try {
      pathStat = await fs.lstat(target)
    } catch (error) {
      if (error && error.code === 'ENOENT') return { slot, exists: false, valid: false, error: null }
      return { slot, exists: true, valid: false, error }
    }
    let handle
    try {
      if (pathStat.isSymbolicLink()) throw new BlindManifestIntegrityError(`manifest slot ${slot} is a symlink`)
      assertPrivateFile(pathStat, `manifest slot ${slot}`)
      handle = await fs.open(target, FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW)
      const opened = await handle.stat()
      if (!sameInode(pathStat, opened)) throw new BlindManifestIntegrityError(`manifest slot ${slot} changed inode`)
      assertPrivateFile(opened, `manifest slot ${slot}`)
      if (opened.size < 64 || opened.size > MAX_MANIFEST_BYTES) {
        throw new BlindManifestIntegrityError(`manifest slot ${slot} size is invalid`)
      }
      const verified = verifyManifest(await readAll(handle, opened.size), this.manifestKey)
      this._assertBindings(verified.value)
      return { slot, exists: true, valid: true, error: null, ...verified }
    } catch (error) {
      return { slot, exists: true, valid: false, error }
    } finally {
      if (handle) await handle.close().catch(() => {})
    }
  }

  async _states () {
    return Promise.all([this._readSlot('a'), this._readSlot('b')])
  }

  _select (states, allowAbsent = false) {
    const valid = states.filter(state => state.valid)
    if (valid.length === 0) {
      if (allowAbsent && states.every(state => !state.exists)) return null
      const details = states.map(state => state.error && state.error.message).filter(Boolean).join('; ')
      throw new BlindManifestIntegrityError(`no valid manifest slot${details ? `: ${details}` : ''}`)
    }
    if (valid.length === 1) return { ...valid[0], needsRepair: true }
    const [left, right] = valid
    const leftRevision = left.value.manifestRevision
    const rightRevision = right.value.manifestRevision
    if (leftRevision === rightRevision) {
      if (!b4a.equals(left.hash, right.hash) || !b4a.equals(left.bytes, right.bytes)) {
        throw new BlindManifestIntegrityError('equal-revision manifest fork detected')
      }
      return { ...left, slot: 'both', needsRepair: false }
    }
    const high = leftRevision > rightRevision ? left : right
    const low = high === left ? right : left
    if (high.value.manifestRevision !== low.value.manifestRevision + 1n ||
        high.value.previousManifestHash == null ||
        !b4a.equals(high.value.previousManifestHash, low.hash)) {
      throw new BlindManifestIntegrityError('manifest slots do not form one adjacent predecessor chain')
    }
    return { ...high, needsRepair: true }
  }

  async _loadInternal (allowAbsent = false) {
    return this._select(await this._states(), allowAbsent)
  }

  load () {
    this._assertAccepting()
    return this._serialized(async () => {
      this._assertOpen()
      const snapshot = publicSnapshot(this, await this._loadInternal())
      this.currentSelectedHash = b4a.from(snapshot.hash)
      manifestPrivate(this).currentSelectedHash = b4a.from(snapshot.hash)
      return snapshot
    })
  }

  initialize (value) {
    this._assertMutable()
    return this._serialized(async () => {
      this._assertOpen()
      const states = await this._states()
      if (BigInt(value.manifestRevision) !== 0n || value.previousManifestHash != null) {
        throw new TypeError('manifest genesis must be revision zero without a predecessor')
      }
      this._assertBindings(value)
      const bytes = sealBlindStoreManifest(value, this.manifestKey)
      for (const state of states) {
        if (!state.exists) continue
        if (!state.valid || !b4a.equals(state.bytes, bytes)) {
          throw new BlindManifestIntegrityError(
            'manifest initialization refuses any existing slot unless it is the exact authenticated genesis'
          )
        }
      }
      await this._install('a', bytes)
      await this._fault('manifest:after-first-install', { slot: 'a', revision: 0n })
      await this._install('b', bytes)
      await this._fault('manifest:after-second-install', { slot: 'b', revision: 0n })
      const snapshot = publicSnapshot(this, await this._loadInternal())
      this.currentSelectedHash = b4a.from(snapshot.hash)
      manifestPrivate(this).currentSelectedHash = b4a.from(snapshot.hash)
      return snapshot
    })
  }

  advance (expectedHash, updates = {}) {
    this._assertMutable()
    return this._serialized(async () => {
      this._assertOpen()
      expectedHash = asBytes(expectedHash, 32, 'expected manifest hash')
      for (const forbidden of ['manifestRevision', 'previousManifestHash', 'mac']) {
        if (Object.prototype.hasOwnProperty.call(updates, forbidden)) {
          throw new TypeError(`manifest advance owns ${forbidden}`)
        }
      }
      const current = await this._loadInternal()
      if (!b4a.equals(current.hash, expectedHash)) {
        throw new BlindManifestIntegrityError('manifest advance expected hash is stale')
      }
      const next = {
        ...current.value,
        ...updates,
        previousManifestHash: b4a.from(current.hash),
        manifestRevision: current.value.manifestRevision + 1n
      }
      this._assertBindings(next)
      const bytes = sealBlindStoreManifest(next, this.manifestKey)
      const first = current.slot === 'a' ? 'b' : 'a'
      const second = first === 'a' ? 'b' : 'a'
      await this._install(first, bytes)
      await this._fault('manifest:after-first-install', { slot: first, revision: next.manifestRevision })
      await this._install(second, bytes)
      await this._fault('manifest:after-second-install', { slot: second, revision: next.manifestRevision })
      const snapshot = publicSnapshot(this, await this._loadInternal())
      this.currentSelectedHash = b4a.from(snapshot.hash)
      manifestPrivate(this).currentSelectedHash = b4a.from(snapshot.hash)
      return snapshot
    })
  }

  repair (expectedHash) {
    this._assertMutable()
    return this._serialized(async () => {
      this._assertOpen()
      expectedHash = asBytes(expectedHash, 32, 'expected manifest hash')
      const current = await this._loadInternal()
      if (!b4a.equals(current.hash, expectedHash)) {
        throw new BlindManifestIntegrityError('manifest repair expected hash is stale')
      }
      await this._install('a', current.bytes)
      await this._install('b', current.bytes)
      const snapshot = publicSnapshot(this, await this._loadInternal())
      this.currentSelectedHash = b4a.from(snapshot.hash)
      manifestPrivate(this).currentSelectedHash = b4a.from(snapshot.hash)
      return snapshot
    })
  }

  async _install (slot, bytes) {
    const target = path.join(this.controlDirectory, SLOT_NAMES[slot])
    const temporary = path.join(this.controlDirectory,
      `.${SLOT_NAMES[slot]}.${randomBytes(16).toString('hex')}.tmp`)
    let handle
    try {
      handle = await fs.open(temporary,
        FS_CONSTANTS.O_WRONLY | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL | FS_CONSTANTS.O_NOFOLLOW,
        0o600)
      let offset = 0
      while (offset < bytes.byteLength) {
        const { bytesWritten } = await handle.write(bytes, offset, bytes.byteLength - offset, offset)
        if (bytesWritten === 0) throw new BlindManifestIntegrityError('manifest temporary write made no progress')
        offset += bytesWritten
      }
      await this._fault('manifest:after-temp-write', { slot })
      await handle.sync()
      await this._fault('manifest:after-temp-sync', { slot })
      await handle.close()
      handle = null
      await fs.rename(temporary, target)
      await this._fault('manifest:after-rename', { slot })
      await syncDirectory(this.controlDirectory)
      await this._fault('manifest:after-directory-sync', { slot })
      const installed = await this._readSlot(slot)
      if (!installed.valid || !b4a.equals(installed.bytes, bytes)) {
        const reason = installed.error && installed.error.message
        throw new BlindManifestIntegrityError(`manifest slot ${slot} failed post-install verification${reason ? `: ${reason}` : ''}`)
      }
    } finally {
      if (handle) await handle.close().catch(() => {})
      await fs.unlink(temporary).catch(error => {
        if (!error || error.code !== 'ENOENT') throw error
      })
    }
  }

  close () {
    if (this.closePromise) return this.closePromise
    if (!this.opened) {
      this.validationOnly = false
      this.currentSelectedHash = null
      const privateState = manifestPrivate(this)
      privateState.currentSelectedHash = null
      privateState.opened = false
      privateState.closing = false
      ACTIVE_MANIFEST_DIRECTORIES.delete(this.controlDirectory)
      this.manifestKey.fill(0)
      return Promise.resolve()
    }
    this.closing = true
    manifestPrivate(this).closing = true
    this.closePromise = this._serialized(async () => {
      this.opened = false
      this.validationOnly = false
      this.currentSelectedHash = null
      const privateState = manifestPrivate(this)
      privateState.currentSelectedHash = null
      privateState.opened = false
      privateState.closing = false
      ACTIVE_MANIFEST_DIRECTORIES.delete(this.controlDirectory)
      this.manifestKey.fill(0)
    })
    return this.closePromise
  }
}

export const BLIND_MANIFEST_STORE_LIMITS = Object.freeze({
  maxManifestBytes: MAX_MANIFEST_BYTES,
  maxTemporaryFiles: MAX_TEMP_FILES,
  requiredBindings: REQUIRED_BINDINGS,
  slotNames: SLOT_NAMES
})
