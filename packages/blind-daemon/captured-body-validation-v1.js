import fs from 'node:fs/promises'
import { constants as C } from 'node:fs'
import path from 'node:path'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { readBlindCellWalCapture } from './storage-engine-checkpoint-v1.js'
import { readBlindInboxWalCapture } from './inbox-storage-engine-checkpoint-v1.js'
import { readBlindCoreWalCapture } from './core-storage-engine-checkpoint-v1.js'
import { verifyBlindStoreSessionTransactionLease } from './store-session.js'
import { capturedBodyReferences } from './captured-body-references-v1.js'

const READERS = Object.freeze({ cell: readBlindCellWalCapture, inbox: readBlindInboxWalCapture, core: readBlindCoreWalCapture })
const VALIDATIONS = new WeakMap()
const FILE_FIELDS = ['dev', 'ino', 'size', 'mode', 'uid', 'gid', 'nlink', 'mtimeNs', 'ctimeNs']
const DIRECTORY_FIELDS = ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'mtimeNs', 'ctimeNs']

export class CapturedBodyValidationError extends Error {
  constructor (message, code = 'CAPTURED_BODY_INVALID') { super(message); this.name = 'CapturedBodyValidationError'; this.code = code }
}
const fail = message => { throw new CapturedBodyValidationError(message) }
function checkSignal (signal) { if (signal?.aborted) throw new CapturedBodyValidationError('captured body validation cancelled', 'CAPTURED_BODY_ABORTED') }
function limitsOf (input = {}) {
  const defaults = { maximumBodies: 65536, maximumReferences: 262144, maximumBodyBytes: 64 * 1024 * 1024, maximumTotalBytes: 256 * 1024 * 1024, maximumChunkBytes: 64 * 1024 }
  const ceilings = { maximumBodies: 65536, maximumReferences: 1048576, maximumBodyBytes: 64 * 1024 * 1024, maximumTotalBytes: 64 * 1024 * 1024 * 1024, maximumChunkBytes: 1024 * 1024 }
  for (const name of Object.keys(input)) if (!Object.hasOwn(defaults, name)) throw new TypeError('unknown captured body limit')
  const result = { ...defaults, ...input }
  for (const [name, value] of Object.entries(result)) if (!Number.isSafeInteger(value) || value < 1 || value > ceilings[name]) throw new TypeError(`invalid ${name}`)
  return Object.freeze(result)
}
function privateStat (stat, directory) {
  if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile()) || (!directory && stat.nlink !== 1n)) fail('captured body path is not an ordinary owned inode')
  if (typeof process.getuid === 'function' && stat.uid !== BigInt(process.getuid())) fail('captured body path has another owner')
  if ((stat.mode & 0o077n) !== 0n || (stat.mode & (directory ? 0o700n : 0o600n)) !== (directory ? 0o700n : 0o600n)) fail('captured body path permissions are not private')
}
function sameStat (a, b, directory = false) {
  if (!(directory ? DIRECTORY_FIELDS : FILE_FIELDS).every(key => a[key] === b[key])) fail('captured body path or bytes changed')
}
async function checkedDirectory (directory, signal) {
  checkSignal(signal)
  const stat = await fs.lstat(directory, { bigint: true })
  privateStat(stat, true)
  if (await fs.realpath(directory) !== directory) fail('captured body directory is not canonical')
  checkSignal(signal)
  return stat
}
async function checkDirectories (directories, signal) {
  for (const [directory, expected] of directories) sameStat(expected, await checkedDirectory(directory, signal), true)
}
function copySummary (state) {
  return {
    role: state.role,
    root: state.root,
    coveredWal: { sequence: state.value.coveredWal.sequence, hash: b4a.from(state.value.coveredWal.hash) },
    hasIrreversibleHistory: state.value.hasIrreversibleHistory,
    bodyCount: state.references.bodies.length,
    bodyBytes: state.references.totalBytes,
    ownerReferences: state.references.references,
    bodies: state.references.bodies.map(body => ({ virtualBucket: body.virtualBucket, objectId: b4a.from(body.objectId), byteLength: body.byteLength, hash: b4a.from(body.hash), owners: body.owners }))
  }
}

async function hashBody (file, body, chunkBytes, directories, signal) {
  checkSignal(signal)
  // Check every parent, then compare the opened inode with the named inode.
  // O_NOFOLLOW covers the final path component; canonical parent checks are
  // repeated after reading and when the branded result is consumed.
  await checkDirectories(directories, signal)
  const named = await fs.lstat(file, { bigint: true })
  privateStat(named, false)
  if (named.size !== BigInt(body.byteLength)) fail('captured body length differs')
  const handle = await fs.open(file, C.O_RDONLY | C.O_NOFOLLOW)
  let stable
  try {
    const before = await handle.stat({ bigint: true })
    privateStat(before, false); sameStat(named, before)
    const state = b4a.alloc(sodium.crypto_generichash_STATEBYTES)
    sodium.crypto_generichash_init(state, null, 32)
    const chunk = b4a.alloc(Math.min(chunkBytes, body.byteLength))
    let offset = 0
    while (offset < body.byteLength) {
      checkSignal(signal)
      const length = Math.min(chunk.byteLength, body.byteLength - offset)
      const { bytesRead } = await handle.read(chunk, 0, length, offset)
      if (bytesRead < 1 || bytesRead > length) fail('captured body became short')
      sodium.crypto_generichash_update(state, chunk.subarray(0, bytesRead))
      offset += bytesRead
    }
    checkSignal(signal)
    const hash = b4a.alloc(32)
    sodium.crypto_generichash_final(state, hash)
    if (!b4a.equals(hash, body.hash)) fail('captured body hash differs')
    stable = await handle.stat({ bigint: true })
    sameStat(before, stable)
    const after = await fs.lstat(file, { bigint: true })
    privateStat(after, false); sameStat(stable, after)
  } finally {
    // No result or lease release is implied until this real handle closes.
    await handle.close()
  }
  await checkDirectories(directories, signal)
  const closed = await fs.lstat(file, { bigint: true })
  privateStat(closed, false); sameStat(stable, closed)
  checkSignal(signal)
  return closed
}

async function revalidate (state, signal) {
  checkSignal(signal)
  // Capture validation checks the unchanged full WAL and exact retained lease.
  await READERS[state.role](state.capture, state.root, state.lease)
  for (const [file, expected] of state.files) {
    checkSignal(signal)
    const actual = await fs.lstat(file, { bigint: true })
    privateStat(actual, false); sameStat(expected, actual)
  }
  await checkDirectories(state.directories, signal)
  await READERS[state.role](state.capture, state.root, state.lease)
  // Earlier capture/file checks contain awaits. Check native ownership last,
  // after all file handles closed, before minting or returning copied evidence.
  await verifyBlindStoreSessionTransactionLease(state.lease, state.root)
  checkSignal(signal)
}

export async function validateCapturedBodies ({ role, capture, root, lease, limits = {}, signal } = {}) {
  if (!Object.hasOwn(READERS, role)) throw new TypeError('known CELL, INBOX or CORE role required')
  if (typeof root !== 'string' || !path.isAbsolute(root) || path.normalize(root) !== root || root.includes('\0')) throw new TypeError('canonical absolute capture root required')
  const bound = limitsOf(limits)
  checkSignal(signal)
  const value = await READERS[role](capture, root, lease)
  if (value.role !== role) fail('capture role differs')
  const references = capturedBodyReferences(value, bound)
  const directories = new Map([[root, await checkedDirectory(root, signal)]])
  const files = new Map()
  const state = { role, root, capture, lease, value, references, directories, files }
  if (references.bodies.length) {
    const blobs = path.join(root, 'blobs')
    directories.set(blobs, await checkedDirectory(blobs, signal))
    for (const body of references.bodies) {
      const bucket = path.join(blobs, body.key.slice(0, 4))
      if (!directories.has(bucket)) directories.set(bucket, await checkedDirectory(bucket, signal))
    }
    for (const body of references.bodies) {
      checkSignal(signal)
      await verifyBlindStoreSessionTransactionLease(lease, root)
      const file = path.join(blobs, body.key + '.blob')
      const parents = new Map([root, blobs, path.dirname(file)].map(directory => [directory, directories.get(directory)]))
      files.set(file, await hashBody(file, body, bound.maximumChunkBytes, parents, signal))
    }
  }
  await revalidate(state, signal)
  const result = Object.freeze({ kind: 'CAPTURED_OPAQUE_BODIES_V1', role, root })
  VALIDATIONS.set(result, state)
  return result
}

export async function readCapturedBodyValidation (validation, root, lease, { signal } = {}) {
  const state = VALIDATIONS.get(validation)
  if (!state || state.root !== root || state.lease !== lease) throw new TypeError('original body validation and retained root lease required')
  await revalidate(state, signal)
  return copySummary(state)
}
