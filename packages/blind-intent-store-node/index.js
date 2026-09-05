import { constants, openSync, closeSync, fstatSync, fsyncSync } from 'node:fs'
import { lstat, mkdir, open, opendir, rename, unlink } from 'node:fs/promises'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto'
import FDLock from 'fd-lock'

const MAGIC = Buffer.from('HRINDB01')
const HEADER_BYTES = 84
const MAX_U64 = (1n << 64n) - 1n
const LOCK_NAME = '.writer-lock'
const TEMP_NAME = '.pending'
const KEY = /^intent:([0-9a-f]{64})$/
const RECORD_NAME = /^([0-9a-f]{64})\.intent$/
const READ_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW
const DIRECTORY_FLAGS = READ_FLAGS | constants.O_DIRECTORY

export const NODE_INTENT_BACKEND_LIMITS = Object.freeze({
  maxCiphertextBytes: 8 * 1024 * 1024 + 264 + 28,
  maxPendingOperations: 8,
  maxPageSize: 256,
  maxOpenScans: 4
})

function failure (code, message, cause) {
  return Object.assign(new Error(message, cause ? { cause } : undefined), { code })
}

function keyName (key) {
  const match = typeof key === 'string' && KEY.exec(key)
  if (!match) throw failure('INTENT_STORE_INPUT', 'key must be intent: followed by 64 lowercase hex characters')
  return match[1] + '.intent'
}

function revisionValue (value) {
  if (typeof value === 'number' && Number.isSafeInteger(value)) value = BigInt(value)
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
    throw failure('INTENT_STORE_INPUT', 'expected revision must be a nonnegative u64')
  }
  return value
}

function sameInode (left, right) {
  return left.dev === right.dev && left.ino === right.ino
}

function assertOwned (stat, directory = false) {
  if (stat.uid !== process.getuid() || (stat.mode & 0o777) !== (directory ? 0o700 : 0o600) ||
      !(directory ? stat.isDirectory() : stat.isFile()) || (!directory && stat.nlink !== 1)) {
    throw failure('INTENT_STORE_CUSTODY', 'intent storage requires an owned private directory and single-link private files')
  }
}

async function assertParents (path) {
  for (let parent = dirname(path); ; parent = dirname(parent)) {
    const stat = await lstat(parent)
    const trustedOwner = stat.uid === 0 || stat.uid === process.getuid()
    const protectedWritableParent = (stat.mode & 0o1000) !== 0
    if (!stat.isDirectory() || !trustedOwner || ((stat.mode & 0o022) !== 0 && !protectedWritableParent)) {
      throw failure('INTENT_STORE_CUSTODY', 'intent directory ancestors must have trusted custody and contain no symlinks')
    }
    if (parent === dirname(parent)) return
  }
}

function encodeRecord (key, revision, ciphertext) {
  const output = Buffer.alloc(HEADER_BYTES + ciphertext.length)
  MAGIC.copy(output)
  output.writeBigUInt64BE(revision, 8)
  output.writeUInt32BE(ciphertext.length, 16)
  Buffer.from(KEY.exec(key)[1], 'hex').copy(output, 20)
  ciphertext.copy(output, HEADER_BYTES)
  createHash('sha256').update(output.subarray(0, 52)).update(ciphertext).digest().copy(output, 52)
  return output
}

function decodeRecord (key, bytes) {
  if (bytes.length < HEADER_BYTES || !bytes.subarray(0, 8).equals(MAGIC) ||
      bytes.readBigUInt64BE(8) === 0n || bytes.readUInt32BE(16) < 1 ||
      bytes.length !== HEADER_BYTES + bytes.readUInt32BE(16) ||
      bytes.subarray(20, 52).toString('hex') !== KEY.exec(key)[1]) {
    throw failure('INTENT_CORRUPT', 'invalid intent record header, key or length')
  }
  const ciphertext = bytes.subarray(HEADER_BYTES)
  const digest = createHash('sha256').update(bytes.subarray(0, 52)).update(ciphertext).digest()
  if (!timingSafeEqual(digest, bytes.subarray(52, 84))) {
    throw failure('INTENT_CORRUPT', 'intent record checksum mismatch')
  }
  return { revision: bytes.readBigUInt64BE(8), ciphertext: Buffer.from(ciphertext) }
}

export class NodeIntentBackend {
  constructor (directory, options = {}) {
    if (!['linux', 'darwin'].includes(process.platform)) {
      throw failure('INTENT_STORE_PLATFORM', 'this backend requires qualified Node Linux or macOS file semantics')
    }
    if (typeof directory !== 'string' || !isAbsolute(directory) || resolve(directory) !== directory) {
      throw failure('INTENT_STORE_INPUT', 'directory must be a canonical absolute path')
    }
    if (options.onCommitPhase !== undefined && typeof options.onCommitPhase !== 'function') {
      throw failure('INTENT_STORE_INPUT', 'onCommitPhase must be a function')
    }
    this.directory = directory
    this._onCommitPhase = options.onCommitPhase || (() => {})
    this._opening = null
    this._directory = null
    this._directoryStat = null
    this._lock = null
    this._lockFd = -1
    this._lockStat = null
    this._failed = null
    this._closing = false
    this._closePromise = null
    this._tail = Promise.resolve()
    this._pending = 0
    this._scans = new Map()
  }

  ready () {
    if (this._closing) return Promise.reject(failure('INTENT_STORE_CLOSED', 'intent backend is closing'))
    if (this._failed) return Promise.reject(failure('INTENT_STORE_FAILED', 'intent backend requires close and recovery', this._failed))
    return this._ready()
  }

  _ready () {
    if (!this._opening) {
      this._opening = this._open().catch(async error => {
        this._failed = error
        await this._release()
        throw error
      })
    }
    return this._opening
  }

  async _open () {
    await assertParents(this.directory)
    try {
      await mkdir(this.directory, { mode: 0o700 })
    } catch (error) {
      if (error.code !== 'EEXIST') throw error
    }
    const before = await lstat(this.directory)
    assertOwned(before, true)
    this._directory = await open(this.directory, DIRECTORY_FLAGS)
    this._directoryStat = await this._directory.stat()
    if (!sameInode(before, this._directoryStat)) throw failure('INTENT_STORE_CUSTODY', 'intent directory changed during open')
    const lockPath = join(this.directory, LOCK_NAME)
    try { assertOwned(await lstat(lockPath)) } catch (error) {
      if (error.code !== 'ENOENT') throw error
    }
    let fd = openSync(lockPath, constants.O_RDWR | constants.O_CREAT | constants.O_NOFOLLOW | constants.O_NONBLOCK, 0o600)
    try {
      this._lockStat = fstatSync(fd)
      assertOwned(this._lockStat)
      if (!sameInode(this._lockStat, await lstat(lockPath)) || this._lockStat.size !== 0) {
        throw failure('INTENT_STORE_CUSTODY', 'intent writer lock inode is invalid')
      }
      this._lockFd = fd
      this._lock = new FDLock(fd)
      fd = -1 // FDLock now owns the descriptor, including failed acquisition.
      try { await this._lock.ready() } catch (error) {
        throw failure('INTENT_STORE_LOCKED', 'intent directory already has a writer or cannot be locked', error)
      }
    } finally {
      if (fd !== -1) closeSync(fd)
    }
    await this._assertCustody()
    fsyncSync(this._lockFd)
    // Repeat this even for an existing root: an earlier opener may have died
    // between mkdir and its parent-directory synchronization.
    const parent = await open(dirname(this.directory), DIRECTORY_FLAGS)
    try { await parent.sync() } finally { await parent.close() }
    const pending = join(this.directory, TEMP_NAME)
    try {
      const stat = await lstat(pending)
      assertOwned(stat)
      if (stat.size > HEADER_BYTES + NODE_INTENT_BACKEND_LIMITS.maxCiphertextBytes) {
        throw failure('INTENT_CORRUPT', 'unpublished intent record exceeds its bound')
      }
      // Only this reserved unpublished slot may be discarded. Committed files
      // are never repaired, truncated or interpreted as absence on read failure.
      await unlink(pending)
    } catch (error) {
      if (error.code !== 'ENOENT') throw error
    }
    await this._directory.sync()
    await this._assertCustody()
  }

  async _assertCustody () {
    const [directory, lock] = await Promise.all([
      lstat(this.directory), lstat(join(this.directory, LOCK_NAME))
    ])
    assertOwned(directory, true)
    assertOwned(lock)
    if (!sameInode(directory, this._directoryStat) || !sameInode(lock, this._lockStat) || lock.size !== 0 ||
        !this._lock.locked || !sameInode(fstatSync(this._lockFd), this._lockStat)) {
      throw failure('INTENT_STORE_CUSTODY', 'intent directory or writer lease was substituted')
    }
  }

  _checkAdmission () {
    if (this._closing) throw failure('INTENT_STORE_CLOSED', 'intent backend is closing')
    if (this._failed) throw failure('INTENT_STORE_FAILED', 'intent backend requires close and recovery', this._failed)
    if (this._pending >= NODE_INTENT_BACKEND_LIMITS.maxPendingOperations) {
      throw failure('INTENT_STORE_BUSY', 'intent backend operation admission is full')
    }
  }

  _enqueue (operation) {
    this._checkAdmission()
    this._pending++
    const result = this._tail.then(async () => {
      await this._ready()
      if (this._failed) throw failure('INTENT_STORE_FAILED', 'intent backend requires close and recovery', this._failed)
      await this._assertCustody()
      return operation()
    })
    this._tail = result.catch(() => {})
    return result.finally(() => { this._pending-- })
  }

  async read (key) {
    keyName(key)
    return this._enqueue(() => this._read(key))
  }

  async _read (key) {
    const path = join(this.directory, keyName(key))
    let before
    try { before = await lstat(path) } catch (error) {
      if (error.code === 'ENOENT') {
        await this._assertCustody()
        return { revision: 0n, ciphertext: null }
      }
      throw error
    }
    assertOwned(before)
    const handle = await open(path, READ_FLAGS | constants.O_NONBLOCK)
    try {
      const stat = await handle.stat()
      assertOwned(stat)
      if (!sameInode(before, stat)) throw failure('INTENT_STORE_CUSTODY', 'intent record changed during open')
      if (stat.size < HEADER_BYTES || stat.size > HEADER_BYTES + NODE_INTENT_BACKEND_LIMITS.maxCiphertextBytes) {
        throw failure('INTENT_CORRUPT', 'intent record size is outside its bound')
      }
      const bytes = Buffer.alloc(stat.size)
      let offset = 0
      while (offset < bytes.length) {
        const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset)
        if (!bytesRead) throw failure('INTENT_CORRUPT', 'intent record was truncated during read')
        offset += bytesRead
      }
      const after = await lstat(path)
      assertOwned(after)
      if (!sameInode(stat, after) || stat.size !== after.size) throw failure('INTENT_STORE_CUSTODY', 'intent record changed during read')
      await this._assertCustody()
      return decodeRecord(key, bytes)
    } finally { await handle.close() }
  }

  async compareAndSwap (key, expectedRevision, ciphertext) {
    keyName(key)
    expectedRevision = revisionValue(expectedRevision)
    if (!(ciphertext instanceof Uint8Array) || ciphertext.length < 1 ||
        ciphertext.length > NODE_INTENT_BACKEND_LIMITS.maxCiphertextBytes ||
        (typeof SharedArrayBuffer !== 'undefined' && ciphertext.buffer instanceof SharedArrayBuffer)) {
      throw failure('INTENT_STORE_INPUT', 'ciphertext must be bounded unshared opaque bytes')
    }
    this._checkAdmission() // Bound retained ciphertext before copying it.
    const copied = Buffer.from(ciphertext)
    return this._enqueue(async () => {
      if (this._scans.size) throw failure('INTENT_STORE_BUSY', 'close or exhaust key scans before mutating intents')
      const current = await this._read(key)
      if (current.revision !== expectedRevision) return false
      if (expectedRevision === MAX_U64) throw failure('INTENT_STORE_REVISION', 'intent revision is exhausted')
      const pending = join(this.directory, TEMP_NAME)
      let handle
      try {
        await this._onCommitPhase('before-write')
        await this._assertCustody()
        handle = await open(pending, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
        const record = encodeRecord(key, expectedRevision + 1n, copied)
        await handle.writeFile(record)
        await handle.sync()
        await this._onCommitPhase('after-file-sync')
        await this._assertCustody()
        const pendingStat = await lstat(pending)
        assertOwned(pendingStat)
        if (!sameInode(await handle.stat(), pendingStat)) throw failure('INTENT_STORE_CUSTODY', 'unpublished intent record was substituted')
        await rename(pending, join(this.directory, keyName(key)))
        await this._onCommitPhase('after-publication')
        await this._onCommitPhase('before-directory-sync')
        await this._assertCustody()
        await this._directory.sync()
        await this._onCommitPhase('after-directory-sync')
        const committed = await lstat(join(this.directory, keyName(key)))
        assertOwned(committed)
        if (!sameInode(await handle.stat(), committed)) throw failure('INTENT_STORE_CUSTODY', 'published intent record was substituted')
        await handle.close()
        handle = null
        await this._assertCustody()
        return true
      } catch (error) {
        this._failed = error
        throw failure('INTENT_STORE_COMMIT_UNKNOWN', 'CAS did not prove durable completion; close and reopen before reconciling', error)
      } finally {
        if (handle) await handle.close()
      }
    })
  }

  async keysPage ({ cursor = null, limit = 64 } = {}) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > NODE_INTENT_BACKEND_LIMITS.maxPageSize) {
      throw failure('INTENT_STORE_INPUT', 'page limit must be within 1..256')
    }
    return this._enqueue(async () => {
      let scan = cursor === null ? null : this._scans.get(cursor)
      if (cursor !== null && !scan) throw failure('INTENT_STORE_CURSOR', 'scan cursor is unknown or expired')
      if (!scan) {
        if (this._scans.size >= NODE_INTENT_BACKEND_LIMITS.maxOpenScans) {
          throw failure('INTENT_STORE_BUSY', 'intent backend scan admission is full')
        }
        scan = await opendir(this.directory, { bufferSize: 1 })
        cursor = randomUUID()
        this._scans.set(cursor, scan)
      }
      const keys = []
      try {
        // Limit directory reads as well as returned rows. Internal entries can
        // produce an empty page with a non-null continuation cursor.
        for (let scanned = 0; scanned < limit; scanned++) {
          const entry = await scan.read()
          if (!entry) {
            await this._closeScan(cursor, scan)
            await this._assertCustody()
            return { keys, cursor: null }
          }
          if (entry.name === LOCK_NAME) continue
          const match = RECORD_NAME.exec(entry.name)
          if (!match || !entry.isFile()) throw failure('INTENT_STORE_CUSTODY', 'unexpected entry in intent directory')
          assertOwned(await lstat(join(this.directory, entry.name)))
          keys.push('intent:' + match[1])
        }
        await this._assertCustody()
        return { keys, cursor }
      } catch (error) {
        await this._closeScan(cursor, scan)
        throw error
      }
    })
  }

  async closeScan (cursor) {
    return this._enqueue(async () => {
      const scan = this._scans.get(cursor)
      if (!scan) throw failure('INTENT_STORE_CURSOR', 'scan cursor is unknown or expired')
      await this._closeScan(cursor, scan)
    })
  }

  async _closeScan (cursor, scan) {
    try { await scan.close() } catch (error) {
      if (error.code !== 'ERR_DIR_CLOSED') {
        this._failed = error
        throw error
      }
    }
    this._scans.delete(cursor)
  }

  close () {
    if (!this._closePromise) {
      this._closing = true
      this._closePromise = this._tail.then(async () => {
        if (this._opening) await this._opening.catch(() => {})
        await this._release()
      })
    }
    return this._closePromise
  }

  async _release () {
    for (const [cursor, scan] of this._scans) await this._closeScan(cursor, scan)
    try {
      if (this._directory) await this._directory.close()
    } finally {
      this._directory = null
      if (this._lock) await this._lock.close()
      this._lock = null
      this._lockFd = -1
    }
  }
}
