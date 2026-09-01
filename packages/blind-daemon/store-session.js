import fs from 'node:fs/promises'
import { constants as FS_CONSTANTS } from 'node:fs'
import path from 'node:path'
import {
  releaseExclusiveFileLock,
  tryExclusiveFileLock
} from '@hiverelay/blind-peercred'

const CONTROL_DIRECTORY = 'control'
const WRITER_LOCK_FILE = 'writer.lock.v1'
const RUNTIME_BINDING_FILE = 'runtime-binding.v1'
const GENESIS_INTENT_FILE = 'genesis-intent.v1'
const STORE_GENERATION_HEAD_FILE = 'blind-store-generation-head-v2.json'
const STORE_GENERATION_RECORD = /^blind-store-generation-record-[0-9]{16}-v2\.json$/
const STORE_GENERATION_TEMP = /^\.blind-store-generation-(?:record|head)\.tmp-[0-9a-f]{32}$/
const STORE_GENERATION_RECORD_TEMP = /^\.blind-store-generation-record\.tmp-[0-9a-f]{32}$/
const MANIFEST_SLOT_FILES = Object.freeze(['manifest-a.v1', 'manifest-b.v1'])
const ROOT_NAMES = new Set([CONTROL_DIRECTORY, RUNTIME_BINDING_FILE, 'blobs', 'staging'])
const CONTROL_NAMES = new Set([
  WRITER_LOCK_FILE, 'wal.v2', GENESIS_INTENT_FILE, STORE_GENERATION_HEAD_FILE, ...MANIFEST_SLOT_FILES
])
const MANIFEST_TEMP = /^\.manifest-[ab]\.v1\.[0-9a-f]{32}\.tmp$/
const GENESIS_INTENT_TEMP = /^\.genesis-intent\.v1\.[0-9a-f]{32}\.tmp$/
const CHECKPOINT_FINAL = /^(checkpoint|snapshot)-([0-9a-f]{64})\.v1$/
const CHECKPOINT_TEMP = /^\.(checkpoint|snapshot)-([0-9a-f]{64})\.v1\.([0-9a-f]{32})\.tmp$/
const WAL_SEGMENT_FINAL = /^wal-([0-9a-f]{16})-([0-9a-f]{16})\.v2$/
const ACTIVE_SESSION_ROOTS = new Set()
const STORE_SESSION_PRIVATE = new WeakMap()
const STORE_SESSION_CONTEXTS = new WeakMap()
const STORE_SESSION_TRANSACTION_LEASES = new WeakSet()
const STORE_SESSION_TRANSACTION_LEASE_STATE = new WeakMap()

export const BLIND_STORE_ROOT_CLASSIFICATION = Object.freeze({
  PRISTINE: 'pristine',
  GENESIS_INCOMPLETE: 'genesis-incomplete',
  CURRENT_MANIFESTED: 'current-manifested',
  LEGACY_AMBIGUOUS: 'legacy-ambiguous'
})

export const BLIND_STORE_SESSION_INTEGRATION_STATUS = Object.freeze({
  productionRuntimeReady: false,
  transactionStoreLockOwnership: 'STORE_SESSION_TRANSACTION_LEASE',
  blocker: 'TWO_SLOT_MANIFEST_RUNTIME_INTEGRATION_UNASSEMBLED'
})

export class BlindStoreSessionError extends Error {
  constructor (message, code = 'BLIND_STORE_SESSION_INVALID') {
    super(message)
    this.name = 'BlindStoreSessionError'
    this.code = code
  }
}

function canonicalRoot (root) {
  if (typeof root !== 'string' || root.includes('\0') || !path.isAbsolute(root) || path.normalize(root) !== root) {
    throw new TypeError('store session root must be a canonical absolute path')
  }
  return root
}

function sameNames (left, right) {
  return left.length === right.length && left.every((name, index) => name === right[index])
}

function stateFor (stat) {
  return Object.freeze({
    dev: stat.dev,
    ino: stat.ino,
    mode: stat.mode,
    uid: stat.uid,
    gid: stat.gid,
    nlink: stat.nlink,
    size: stat.size,
    mtimeMs: stat.mtimeMs,
    ctimeMs: stat.ctimeMs,
    kind: stat.isDirectory() ? 'directory' : stat.isFile() ? 'file' : stat.isSymbolicLink() ? 'symlink' : 'other'
  })
}

function sameState (left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode &&
    left.uid === right.uid && left.gid === right.gid && left.nlink === right.nlink &&
    left.size === right.size && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs &&
    left.kind === right.kind
}

function privateDirectory (stat) {
  return stat.isDirectory() && !stat.isSymbolicLink() &&
    (typeof process.getuid !== 'function' || stat.uid === process.getuid()) &&
    (stat.mode & 0o700) === 0o700 && (stat.mode & 0o077) === 0
}

function privateFile (stat, expectedLinks = 1) {
  return stat.isFile() && !stat.isSymbolicLink() && (expectedLinks == null || stat.nlink === expectedLinks) &&
    (typeof process.getuid !== 'function' || stat.uid === process.getuid()) &&
    (stat.mode & 0o600) === 0o600 && (stat.mode & 0o077) === 0
}

async function inspectRootDirectory (root) {
  const before = await fs.lstat(root)
  if (!privateDirectory(before) || await fs.realpath(root) !== root) {
    throw new BlindStoreSessionError(
      'store root must be a canonical daemon-owned private directory',
      'BLIND_STORE_ROOT_INVALID'
    )
  }
  const names = (await fs.readdir(root)).sort()
  const after = await fs.lstat(root)
  const namesAfter = (await fs.readdir(root)).sort()
  if (!sameState(stateFor(before), stateFor(after)) || !sameNames(names, namesAfter)) {
    throw new BlindStoreSessionError('store root changed while it was classified', 'BLIND_STORE_LAYOUT_CHANGED')
  }
  return { state: stateFor(after), names }
}

async function inspectPrivateDirectory (directory, label) {
  let before
  try {
    before = await fs.lstat(directory)
  } catch (error) {
    return { ok: false, reason: `${label} is missing`, error }
  }
  if (!privateDirectory(before)) return { ok: false, reason: `${label} is not a private regular directory` }
  let real
  try {
    real = await fs.realpath(directory)
  } catch (error) {
    return { ok: false, reason: `${label} realpath failed`, error }
  }
  if (real !== directory) return { ok: false, reason: `${label} traverses a symlinked path` }
  let names
  let namesAfter
  let after
  try {
    names = (await fs.readdir(directory)).sort()
    after = await fs.lstat(directory)
    namesAfter = (await fs.readdir(directory)).sort()
  } catch (error) {
    return { ok: false, reason: `${label} changed while it was inspected`, error }
  }
  if (!sameState(stateFor(before), stateFor(after)) || !sameNames(names, namesAfter)) {
    throw new BlindStoreSessionError(`${label} changed while it was classified`, 'BLIND_STORE_LAYOUT_CHANGED')
  }
  return { ok: true, state: stateFor(after), names }
}

async function inspectEntry (target, expectedKind, label, options = {}) {
  let before
  let after
  try {
    before = await fs.lstat(target)
    after = await fs.lstat(target)
  } catch (error) {
    return { ok: false, reason: `${label} is missing or unstable`, error }
  }
  const beforeState = stateFor(before)
  const afterState = stateFor(after)
  if (!sameState(beforeState, afterState)) {
    throw new BlindStoreSessionError(`${label} changed while it was classified`, 'BLIND_STORE_LAYOUT_CHANGED')
  }
  const ok = expectedKind === 'directory'
    ? privateDirectory(after)
    : privateFile(after, options.expectedLinks === undefined ? 1 : options.expectedLinks)
  if (ok && options.expectedSize != null && after.size !== options.expectedSize) {
    return { ok: false, state: afterState, reason: `${label} does not have its exact required byte length` }
  }
  return ok
    ? { ok: true, state: afterState }
    : { ok: false, state: afterState, reason: `${label} is not a private single-link ${expectedKind}` }
}

async function generationRecordPublicationLinks (controlDirectory, names) {
  const candidates = names.filter(name =>
    STORE_GENERATION_RECORD.test(name) || STORE_GENERATION_TEMP.test(name)
  )
  const linked = new Map()
  for (const name of candidates) {
    const inspected = await inspectEntry(
      path.join(controlDirectory, name),
      'file',
      `store control entry ${name}`,
      { expectedLinks: null }
    )
    if (!inspected.ok) return { ok: false, reason: inspected.reason }
    if (inspected.state.nlink === 1) continue
    if (inspected.state.nlink !== 2 ||
        (!STORE_GENERATION_RECORD.test(name) && !STORE_GENERATION_RECORD_TEMP.test(name))) {
      return { ok: false, reason: `store control entry ${name} has an unsupported hard-link topology` }
    }
    const inode = `${inspected.state.dev}:${inspected.state.ino}`
    const group = linked.get(inode) || []
    group.push({ name, state: inspected.state })
    linked.set(inode, group)
  }

  const accepted = new Set()
  for (const group of linked.values()) {
    const finals = group.filter(entry => STORE_GENERATION_RECORD.test(entry.name))
    const temporaries = group.filter(entry => STORE_GENERATION_RECORD_TEMP.test(entry.name))
    if (group.length !== 2 || finals.length !== 1 || temporaries.length !== 1 ||
        !sameState(finals[0].state, temporaries[0].state)) {
      return { ok: false, reason: 'store generation record publication has an incomplete or ambiguous hard-link pair' }
    }
    accepted.add(finals[0].name)
    accepted.add(temporaries[0].name)
  }
  return { ok: true, accepted }
}

function checkpointArtifact (name) {
  let match = CHECKPOINT_FINAL.exec(name)
  if (match) return Object.freeze({ kind: match[1], hash: match[2], role: 'final' })
  match = CHECKPOINT_TEMP.exec(name)
  if (match) return Object.freeze({ kind: match[1], hash: match[2], role: 'temporary' })
  return null
}

function walSegmentArtifact (name) {
  const match = WAL_SEGMENT_FINAL.exec(name)
  if (!match) return null
  return Object.freeze({ kind: 'wal-segment', firstSequence: match[1], lastSequence: match[2], role: 'final' })
}

function classification (kind, root, rootState, rootNames, details = {}) {
  return Object.freeze({
    kind,
    root,
    rootState,
    rootNames: Object.freeze([...rootNames]),
    reason: details.reason || null,
    controlState: details.controlState || null,
    controlNames: Object.freeze([...(details.controlNames || [])]),
    entryStates: Object.freeze([...(details.entryStates || [])])
  })
}

function classificationFingerprint (value) {
  const state = item => item == null
    ? '-'
    : [item.dev, item.ino, item.mode, item.uid, item.gid, item.nlink, item.size,
        item.mtimeMs, item.ctimeMs, item.kind].join(':')
  return [
    value.kind,
    state(value.rootState),
    value.rootNames.join(','),
    state(value.controlState),
    value.controlNames.join(','),
    value.entryStates.map(entry => `${entry.name}:${state(entry.state)}`).join(',')
  ].join('|')
}

export async function classifyBlindStoreRoot (configuredRoot) {
  const root = canonicalRoot(configuredRoot)
  const inspectedRoot = await inspectRootDirectory(root)
  if (inspectedRoot.names.length === 0) {
    return classification(BLIND_STORE_ROOT_CLASSIFICATION.PRISTINE,
      root, inspectedRoot.state, inspectedRoot.names)
  }
  const unknownRootName = inspectedRoot.names.find(name => !ROOT_NAMES.has(name))
  if (unknownRootName) {
    return classification(BLIND_STORE_ROOT_CLASSIFICATION.LEGACY_AMBIGUOUS,
      root, inspectedRoot.state, inspectedRoot.names, { reason: `unrecognized root entry ${unknownRootName}` })
  }
  if (!inspectedRoot.names.includes(CONTROL_DIRECTORY)) {
    if (sameNames(inspectedRoot.names, [RUNTIME_BINDING_FILE])) {
      const runtimeBinding = await inspectEntry(
        path.join(root, RUNTIME_BINDING_FILE),
        'file',
        'store runtime binding',
        { expectedSize: 213 }
      )
      if (runtimeBinding.ok) {
        return classification(BLIND_STORE_ROOT_CLASSIFICATION.PRISTINE,
          root, inspectedRoot.state, inspectedRoot.names, {
            entryStates: [Object.freeze({ name: RUNTIME_BINDING_FILE, state: runtimeBinding.state })]
          })
      }
    }
    return classification(BLIND_STORE_ROOT_CLASSIFICATION.LEGACY_AMBIGUOUS,
      root, inspectedRoot.state, inspectedRoot.names, { reason: 'nonempty store has no control directory' })
  }

  const entryStates = []
  for (const name of inspectedRoot.names) {
    if (name === CONTROL_DIRECTORY) continue
    const expectedKind = name === RUNTIME_BINDING_FILE ? 'file' : 'directory'
    const inspected = await inspectEntry(
      path.join(root, name),
      expectedKind,
      `store root entry ${name}`,
      name === RUNTIME_BINDING_FILE ? { expectedSize: 213 } : {}
    )
    if (!inspected.ok) {
      return classification(BLIND_STORE_ROOT_CLASSIFICATION.LEGACY_AMBIGUOUS,
        root, inspectedRoot.state, inspectedRoot.names, { reason: inspected.reason, entryStates })
    }
    entryStates.push(Object.freeze({ name, state: inspected.state }))
  }

  const controlDirectory = path.join(root, CONTROL_DIRECTORY)
  const control = await inspectPrivateDirectory(controlDirectory, 'store control directory')
  if (!control.ok) {
    return classification(BLIND_STORE_ROOT_CLASSIFICATION.LEGACY_AMBIGUOUS,
      root, inspectedRoot.state, inspectedRoot.names, { reason: control.reason, entryStates })
  }
  const unknownControlName = control.names.find(name =>
    !CONTROL_NAMES.has(name) && !STORE_GENERATION_RECORD.test(name) && !STORE_GENERATION_TEMP.test(name) &&
    !MANIFEST_TEMP.test(name) &&
    !GENESIS_INTENT_TEMP.test(name) && !checkpointArtifact(name) && !walSegmentArtifact(name))
  if (unknownControlName) {
    return classification(BLIND_STORE_ROOT_CLASSIFICATION.LEGACY_AMBIGUOUS,
      root, inspectedRoot.state, inspectedRoot.names, {
        reason: `unrecognized control entry ${unknownControlName}`,
        controlState: control.state,
        controlNames: control.names,
        entryStates
      })
  }
  const generationPublicationLinks = await generationRecordPublicationLinks(controlDirectory, control.names)
  if (!generationPublicationLinks.ok) {
    return classification(BLIND_STORE_ROOT_CLASSIFICATION.LEGACY_AMBIGUOUS,
      root, inspectedRoot.state, inspectedRoot.names, {
        reason: generationPublicationLinks.reason,
        controlState: control.state,
        controlNames: control.names,
        entryStates
      })
  }
  for (const name of control.names) {
    const inspected = await inspectEntry(
      path.join(controlDirectory, name),
      'file',
      `store control entry ${name}`,
      generationPublicationLinks.accepted.has(name) ? { expectedLinks: 2 } : {}
    )
    if (!inspected.ok) {
      return classification(BLIND_STORE_ROOT_CLASSIFICATION.LEGACY_AMBIGUOUS,
        root, inspectedRoot.state, inspectedRoot.names, {
          reason: inspected.reason,
          controlState: control.state,
          controlNames: control.names,
          entryStates
        })
    }
    entryStates.push(Object.freeze({ name: `${CONTROL_DIRECTORY}/${name}`, state: inspected.state }))
  }
  if (!control.names.includes(WRITER_LOCK_FILE)) {
    if (control.names.length === 0) {
      return classification(BLIND_STORE_ROOT_CLASSIFICATION.GENESIS_INCOMPLETE,
        root, inspectedRoot.state, inspectedRoot.names, {
          reason: 'pristine bootstrap created its control directory but not its writer lock',
          controlState: control.state,
          controlNames: control.names,
          entryStates
        })
    }
    return classification(BLIND_STORE_ROOT_CLASSIFICATION.LEGACY_AMBIGUOUS,
      root, inspectedRoot.state, inspectedRoot.names, {
        reason: 'manifested store has no existing writer lock',
        controlState: control.state,
        controlNames: control.names,
        entryStates
      })
  }
  if (!MANIFEST_SLOT_FILES.some(name => control.names.includes(name))) {
    const hasGenesisIntent = control.names.includes(GENESIS_INTENT_FILE)
    const hasGenesisIntentTemporary = control.names.some(name => GENESIS_INTENT_TEMP.test(name))
    const hasBootstrapData = control.names.some(name =>
      name === 'wal.v2' || walSegmentArtifact(name) != null || checkpointArtifact(name) != null
    ) || inspectedRoot.names.some(name => name === 'blobs' || name === 'staging')
    if (!hasBootstrapData || hasGenesisIntent || hasGenesisIntentTemporary) {
      return classification(BLIND_STORE_ROOT_CLASSIFICATION.GENESIS_INCOMPLETE,
        root, inspectedRoot.state, inspectedRoot.names, {
          reason: 'authorized crash-resumable genesis has not installed a manifest slot',
          controlState: control.state,
          controlNames: control.names,
          entryStates
        })
    }
    return classification(BLIND_STORE_ROOT_CLASSIFICATION.LEGACY_AMBIGUOUS,
      root, inspectedRoot.state, inspectedRoot.names, {
        reason: 'control directory has no manifest slot',
        controlState: control.state,
        controlNames: control.names,
        entryStates
      })
  }
  return classification(BLIND_STORE_ROOT_CLASSIFICATION.CURRENT_MANIFESTED,
    root, inspectedRoot.state, inspectedRoot.names, {
      controlState: control.state,
      controlNames: control.names,
      entryStates
    })
}

async function syncDirectory (directory) {
  const handle = await fs.open(directory, FS_CONSTANTS.O_RDONLY)
  try {
    await handle.sync()
  } finally {
    await handle.close()
  }
}

async function assertOpenedLock (handle, lockPath) {
  const [opened, linked] = await Promise.all([handle.stat(), fs.lstat(lockPath)])
  if (!privateFile(opened) || !privateFile(linked) || opened.dev !== linked.dev || opened.ino !== linked.ino) {
    throw new BlindStoreSessionError('writer lock path and opened inode disagree', 'BLIND_STORE_LOCK_INVALID')
  }
  return stateFor(opened)
}

function sessionPrivate (session) {
  const state = STORE_SESSION_PRIVATE.get(session)
  if (!state) throw new BlindStoreSessionError('store session identity is invalid', 'BLIND_STORE_SESSION_INVALID')
  return state
}

function releaseTransactionLease (lease) {
  if (!STORE_SESSION_TRANSACTION_LEASES.has(lease)) return
  const leaseState = STORE_SESSION_TRANSACTION_LEASE_STATE.get(lease)
  if (leaseState.released) return
  leaseState.released = true
  STORE_SESSION_TRANSACTION_LEASES.delete(lease)
  const state = sessionPrivate(leaseState.session)
  if (state.activeTransactionLease === leaseState) state.activeTransactionLease = null
  leaseState.resolveReleased()
}

function mintTransactionLease (leaseState) {
  const lease = Object.freeze({
    root: leaseState.root,
    generation: leaseState.generation,
    release: () => releaseTransactionLease(lease)
  })
  STORE_SESSION_TRANSACTION_LEASES.add(lease)
  STORE_SESSION_TRANSACTION_LEASE_STATE.set(lease, leaseState)
  leaseState.lease = lease
  return lease
}

export async function verifyBlindStoreSessionTransactionLease (lease, expectedRoot) {
  const root = canonicalRoot(expectedRoot)
  if (!lease || typeof lease !== 'object' || !STORE_SESSION_TRANSACTION_LEASES.has(lease)) {
    throw new BlindStoreSessionError('store session transaction lease is forged or inactive', 'BLIND_STORE_TRANSACTION_LEASE_INVALID')
  }
  const leaseState = STORE_SESSION_TRANSACTION_LEASE_STATE.get(lease)
  if (!leaseState || leaseState.released || lease.root !== root || leaseState.root !== root) {
    throw new BlindStoreSessionError('store session transaction lease root or lifetime is invalid', 'BLIND_STORE_TRANSACTION_LEASE_INVALID')
  }
  const session = leaseState.session
  const state = sessionPrivate(session)
  if (session.root !== root || session.writerLockPath !== leaseState.writerLockPath) {
    throw new BlindStoreSessionError('store session transaction lease identity no longer matches its root', 'BLIND_STORE_TRANSACTION_LEASE_INVALID')
  }
  if (state.activeTransactionLease !== leaseState || state.generation !== leaseState.generation ||
      lease.generation !== leaseState.generation) {
    throw new BlindStoreSessionError('store session transaction lease generation is stale', 'BLIND_STORE_TRANSACTION_LEASE_INVALID')
  }
  if (state.closing || state.closed || !state.opened || !state.lockHeld || !state.writerLockHandle) {
    throw new BlindStoreSessionError('store session transaction lease has no open writer authority', 'BLIND_STORE_SESSION_CLOSING')
  }
  const observed = await assertOpenedLock(state.writerLockHandle, leaseState.writerLockPath)
  if (observed.dev !== leaseState.lockState.dev || observed.ino !== leaseState.lockState.ino) {
    throw new BlindStoreSessionError('writer lock inode changed during transaction lease verification', 'BLIND_STORE_LOCK_INVALID')
  }
  if (state.activeTransactionLease !== leaseState || state.generation !== leaseState.generation ||
      state.closing || state.closed || !state.opened || !state.lockHeld) {
    throw new BlindStoreSessionError('store session changed while its transaction lease was verified', 'BLIND_STORE_SESSION_CLOSING')
  }
  return true
}

/**
 * Atomically replace a caller-held transaction lease with a successor lease.
 * The old object becomes unverifiable and its release closure becomes inert;
 * the StoreSession continues waiting on the same underlying lease lifetime.
 */
export async function transferBlindStoreSessionTransactionLease (lease, expectedRoot) {
  const root = canonicalRoot(expectedRoot)
  await verifyBlindStoreSessionTransactionLease(lease, root)
  const leaseState = STORE_SESSION_TRANSACTION_LEASE_STATE.get(lease)
  const state = sessionPrivate(leaseState.session)
  if (!leaseState.transferable || leaseState.lease !== lease || leaseState.released ||
      state.activeTransactionLease !== leaseState || !STORE_SESSION_TRANSACTION_LEASES.has(lease)) {
    throw new BlindStoreSessionError(
      'store session transaction lease cannot be transferred again',
      'BLIND_STORE_TRANSACTION_LEASE_TRANSFER_INVALID'
    )
  }
  leaseState.transferable = false
  STORE_SESSION_TRANSACTION_LEASES.delete(lease)
  return mintTransactionLease(leaseState)
}

/**
 * Borrow the writer authority already held by a StoreSession. The returned
 * lease is branded inside this module; callers cannot manufacture either the
 * context or a second concurrent lease by copying their visible fields.
 */
export async function acquireBlindStoreSessionTransactionLease (context, expectedRoot) {
  const root = canonicalRoot(expectedRoot)
  if (!context || typeof context !== 'object') {
    throw new BlindStoreSessionError('store session lock context is invalid', 'BLIND_STORE_SESSION_CONTEXT_INVALID')
  }
  const contextState = STORE_SESSION_CONTEXTS.get(context)
  if (!contextState || contextState.context !== context) {
    throw new BlindStoreSessionError('store session lock context is forged or unknown', 'BLIND_STORE_SESSION_CONTEXT_INVALID')
  }
  if (contextState.root !== root || context.root !== root) {
    throw new BlindStoreSessionError('store session lock context belongs to a different root', 'BLIND_STORE_SESSION_ROOT_MISMATCH')
  }
  const session = contextState.session
  const state = sessionPrivate(session)
  if (state.context !== context || state.generation !== contextState.generation ||
      context.generation !== contextState.generation) {
    throw new BlindStoreSessionError('store session lock context generation is stale', 'BLIND_STORE_SESSION_CONTEXT_STALE')
  }
  if (state.closing || state.closed || session.closing || session.closed) {
    throw new BlindStoreSessionError('store session is closing or closed', 'BLIND_STORE_SESSION_CLOSING')
  }
  if (!state.opened || !session.opened || !state.lockHeld || !state.writerLockHandle) {
    throw new BlindStoreSessionError('store session is not open with its writer lock', 'BLIND_STORE_SESSION_NOT_OPEN')
  }
  if (session.root !== root || session.writerLockPath !== contextState.writerLockPath) {
    throw new BlindStoreSessionError('store session identity no longer matches its context', 'BLIND_STORE_SESSION_CONTEXT_STALE')
  }
  if (state.activeTransactionLease) {
    throw new BlindStoreSessionError('store session already has an active transaction lease', 'BLIND_STORE_TRANSACTION_LEASE_ACTIVE')
  }

  let resolveReleased
  const released = new Promise(resolve => { resolveReleased = resolve })
  const leaseState = {
    session,
    root,
    generation: state.generation,
    writerLockPath: contextState.writerLockPath,
    lockState: contextState.lockState,
    transferable: true,
    released: false,
    releasedPromise: released,
    resolveReleased
  }
  const lease = mintTransactionLease(leaseState)
  state.activeTransactionLease = leaseState

  try {
    await verifyBlindStoreSessionTransactionLease(lease, root)
    if (state.context !== context) {
      throw new BlindStoreSessionError(
        'store session changed while its transaction lease was acquired',
        'BLIND_STORE_SESSION_CONTEXT_STALE'
      )
    }
    return lease
  } catch (error) {
    releaseTransactionLease(lease)
    throw error
  }
}

export class BlindStoreSession {
  constructor (options = {}) {
    this.root = canonicalRoot(options.root)
    this.controlDirectory = path.join(this.root, CONTROL_DIRECTORY)
    this.writerLockPath = path.join(this.controlDirectory, WRITER_LOCK_FILE)
    this.allowPristineBootstrap = options.allowPristineBootstrap === true
    if (options.faultInjector != null && typeof options.faultInjector !== 'function') {
      throw new TypeError('faultInjector must be a function')
    }
    this.faultInjector = options.faultInjector || null
    this.writerLockHandle = null
    this.lockHeld = false
    this.opened = false
    this.closing = false
    this.closed = false
    this.openPromise = null
    this.closePromise = null
    this.rootClassification = null
    this.bootstrapCreated = false
    STORE_SESSION_PRIVATE.set(this, {
      generation: 0,
      context: null,
      writerLockHandle: null,
      lockHeld: false,
      lockState: null,
      opened: false,
      closing: false,
      closed: false,
      activeTransactionLease: null
    })
  }

  async _fault (point, context = {}) {
    if (this.faultInjector) await this.faultInjector(point, Object.freeze({ root: this.root, ...context }))
  }

  open () {
    if (this.closed) return Promise.reject(new Error('store session is closed'))
    if (this.openPromise) return this.openPromise
    this.openPromise = this._open()
    return this.openPromise
  }

  async _open () {
    if (this.opened || this.writerLockHandle) throw new Error('store session is already open')
    if (ACTIVE_SESSION_ROOTS.has(this.root)) {
      throw new BlindStoreSessionError('store root already has a StoreSession in this process', 'BLIND_STORE_LOCKED')
    }
    if (!FS_CONSTANTS.O_NOFOLLOW) {
      throw new BlindStoreSessionError('O_NOFOLLOW is required for StoreSession', 'BLIND_STORE_LOCK_UNAVAILABLE')
    }
    ACTIVE_SESSION_ROOTS.add(this.root)
    try {
      const initial = await classifyBlindStoreRoot(this.root)
      await this._fault('store-session:after-classification', { classification: initial.kind })
      if (initial.kind === BLIND_STORE_ROOT_CLASSIFICATION.LEGACY_AMBIGUOUS) {
        throw new BlindStoreSessionError(
          `store layout is legacy or ambiguous: ${initial.reason}`,
          'BLIND_STORE_LAYOUT_AMBIGUOUS'
        )
      }
      if (initial.kind === BLIND_STORE_ROOT_CLASSIFICATION.PRISTINE) {
        await this._openPristine(initial)
      } else if (initial.kind === BLIND_STORE_ROOT_CLASSIFICATION.GENESIS_INCOMPLETE) {
        if (!this.allowPristineBootstrap) {
          throw new BlindStoreSessionError(
            'incomplete genesis resume was not explicitly authorized',
            'BLIND_STORE_BOOTSTRAP_NOT_AUTHORIZED'
          )
        }
        if (initial.controlNames.includes(WRITER_LOCK_FILE)) {
          await this._openExisting(initial, BLIND_STORE_ROOT_CLASSIFICATION.GENESIS_INCOMPLETE)
        } else {
          await this._openGenesisControlShell(initial)
        }
      } else {
        await this._openExisting(initial)
      }
      this.rootClassification = initial
      this.opened = true
      const state = sessionPrivate(this)
      state.generation++
      state.opened = true
      const context = Object.freeze({
        root: this.root,
        controlDirectory: this.controlDirectory,
        writerLockPath: this.writerLockPath,
        generation: state.generation,
        classification: this.rootClassification.kind,
        bootstrapCreated: this.bootstrapCreated,
        ownsWriterLock: true,
        transactionStoreLockOwnership: BLIND_STORE_SESSION_INTEGRATION_STATUS.transactionStoreLockOwnership,
        integrationBlocker: BLIND_STORE_SESSION_INTEGRATION_STATUS.blocker
      })
      state.context = context
      STORE_SESSION_CONTEXTS.set(context, Object.freeze({
        context,
        session: this,
        root: this.root,
        writerLockPath: this.writerLockPath,
        generation: state.generation,
        lockState: state.lockState
      }))
      return this
    } catch (error) {
      await this._release().catch(() => {})
      ACTIVE_SESSION_ROOTS.delete(this.root)
      throw error
    }
  }

  async _openExisting (initial, expectedClassification = BLIND_STORE_ROOT_CLASSIFICATION.CURRENT_MANIFESTED) {
    this.writerLockHandle = await fs.open(
      this.writerLockPath,
      FS_CONSTANTS.O_RDWR | FS_CONSTANTS.O_NOFOLLOW
    )
    const state = sessionPrivate(this)
    state.writerLockHandle = this.writerLockHandle
    state.lockState = await assertOpenedLock(this.writerLockHandle, this.writerLockPath)
    await this._fault('store-session:after-lock-open', { classification: initial.kind })
    if (!tryExclusiveFileLock(this.writerLockHandle)) {
      throw new BlindStoreSessionError('store root already has an active writer', 'BLIND_STORE_LOCKED')
    }
    this.lockHeld = true
    state.lockHeld = true
    await this._fault('store-session:after-lock-acquired', { classification: initial.kind })
    const rechecked = await classifyBlindStoreRoot(this.root)
    if (rechecked.kind !== expectedClassification ||
        classificationFingerprint(rechecked) !== classificationFingerprint(initial)) {
      throw new BlindStoreSessionError(
        'store layout changed between classification and writer-lock acquisition',
        'BLIND_STORE_LAYOUT_CHANGED'
      )
    }
  }

  async _openPristine (initial) {
    if (!this.allowPristineBootstrap) {
      throw new BlindStoreSessionError(
        'pristine store bootstrap was not explicitly authorized',
        'BLIND_STORE_BOOTSTRAP_NOT_AUTHORIZED'
      )
    }
    const rechecked = await classifyBlindStoreRoot(this.root)
    if (rechecked.kind !== BLIND_STORE_ROOT_CLASSIFICATION.PRISTINE ||
        classificationFingerprint(rechecked) !== classificationFingerprint(initial)) {
      throw new BlindStoreSessionError(
        'pristine store changed before bootstrap lock creation',
        'BLIND_STORE_LAYOUT_CHANGED'
      )
    }
    await this._fault('store-session:after-pristine-recheck', { classification: initial.kind })
    await fs.mkdir(this.controlDirectory, { mode: 0o700 })
    await this._fault('store-session:after-control-mkdir', { classification: initial.kind })
    this.writerLockHandle = await fs.open(
      this.writerLockPath,
      FS_CONSTANTS.O_RDWR | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL | FS_CONSTANTS.O_NOFOLLOW,
      0o600
    )
    await this._fault('store-session:after-lock-create', { classification: initial.kind })
    const state = sessionPrivate(this)
    state.writerLockHandle = this.writerLockHandle
    const lockState = await assertOpenedLock(this.writerLockHandle, this.writerLockPath)
    state.lockState = lockState
    if (!tryExclusiveFileLock(this.writerLockHandle)) {
      throw new BlindStoreSessionError('new bootstrap writer lock could not be acquired', 'BLIND_STORE_LOCKED')
    }
    this.lockHeld = true
    state.lockHeld = true
    await this.writerLockHandle.sync()
    await this._fault('store-session:after-lock-file-sync', { classification: initial.kind })
    await syncDirectory(this.controlDirectory)
    await this._fault('store-session:after-control-directory-sync', { classification: initial.kind })
    await syncDirectory(this.root)
    await this._fault('store-session:after-root-directory-sync', { classification: initial.kind })
    const root = await inspectRootDirectory(this.root)
    const control = await inspectPrivateDirectory(this.controlDirectory, 'store control directory')
    const expectedRootNames = [...initial.rootNames, CONTROL_DIRECTORY].sort()
    if (!control.ok || !sameNames(root.names, expectedRootNames) ||
        !sameNames(control.names, [WRITER_LOCK_FILE])) {
      throw new BlindStoreSessionError('pristine bootstrap layout changed during lock creation', 'BLIND_STORE_LAYOUT_CHANGED')
    }
    const installed = await fs.lstat(this.writerLockPath)
    if (!sameState(lockState, stateFor(installed))) {
      throw new BlindStoreSessionError('bootstrap writer lock changed during creation', 'BLIND_STORE_LAYOUT_CHANGED')
    }
    this.bootstrapCreated = true
  }

  async _openGenesisControlShell (initial) {
    const rechecked = await classifyBlindStoreRoot(this.root)
    if (rechecked.kind !== BLIND_STORE_ROOT_CLASSIFICATION.GENESIS_INCOMPLETE ||
        rechecked.controlNames.length !== 0 ||
        classificationFingerprint(rechecked) !== classificationFingerprint(initial)) {
      throw new BlindStoreSessionError(
        'incomplete genesis control shell changed before writer-lock creation',
        'BLIND_STORE_LAYOUT_CHANGED'
      )
    }
    this.writerLockHandle = await fs.open(
      this.writerLockPath,
      FS_CONSTANTS.O_RDWR | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL | FS_CONSTANTS.O_NOFOLLOW,
      0o600
    )
    await this._fault('store-session:after-lock-create', { classification: initial.kind })
    const state = sessionPrivate(this)
    state.writerLockHandle = this.writerLockHandle
    const lockState = await assertOpenedLock(this.writerLockHandle, this.writerLockPath)
    state.lockState = lockState
    if (!tryExclusiveFileLock(this.writerLockHandle)) {
      throw new BlindStoreSessionError('resumed bootstrap writer lock could not be acquired', 'BLIND_STORE_LOCKED')
    }
    this.lockHeld = true
    state.lockHeld = true
    await this.writerLockHandle.sync()
    await this._fault('store-session:after-lock-file-sync', { classification: initial.kind })
    await syncDirectory(this.controlDirectory)
    await this._fault('store-session:after-control-directory-sync', { classification: initial.kind })
    await syncDirectory(this.root)
    await this._fault('store-session:after-root-directory-sync', { classification: initial.kind })
    const installed = await fs.lstat(this.writerLockPath)
    if (!sameState(lockState, stateFor(installed))) {
      throw new BlindStoreSessionError('resumed bootstrap writer lock changed during creation', 'BLIND_STORE_LAYOUT_CHANGED')
    }
    this.bootstrapCreated = true
  }

  lockContext () {
    const state = sessionPrivate(this)
    if (!state.opened || state.closing || !state.lockHeld || !state.context) {
      throw new Error('store session does not hold its writer lock')
    }
    return state.context
  }

  async _release () {
    const state = sessionPrivate(this)
    const handle = this.writerLockHandle
    const held = this.lockHeld
    this.writerLockHandle = null
    this.lockHeld = false
    state.writerLockHandle = null
    state.lockHeld = false
    state.lockState = null
    if (!handle) return
    try {
      if (held) releaseExclusiveFileLock(handle)
    } finally {
      await handle.close()
    }
  }

  close () {
    const state = sessionPrivate(this)
    if (this.closePromise) return this.closePromise
    if (!this.opened && !this.writerLockHandle && !this.openPromise) {
      this.closed = true
      state.closed = true
      return Promise.resolve()
    }
    this.closing = true
    this.closed = true
    state.closing = true
    state.closed = true
    this.closePromise = (async () => {
      try {
        if (this.openPromise) await this.openPromise.catch(() => {})
        while (state.activeTransactionLease) {
          await state.activeTransactionLease.releasedPromise
        }
        await this._release()
      } finally {
        this.opened = false
        state.opened = false
        ACTIVE_SESSION_ROOTS.delete(this.root)
      }
    })()
    return this.closePromise
  }
}
