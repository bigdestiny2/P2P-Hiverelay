import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import b4a from 'b4a'
import test from 'brittle'
import {
  releaseExclusiveFileLock,
  tryExclusiveFileLock
} from '@hiverelay/blind-peercred'
import {
  BLIND_STORE_ROOT_CLASSIFICATION,
  BLIND_STORE_SESSION_INTEGRATION_STATUS,
  BlindStoreSession,
  acquireBlindStoreSessionTransactionLease,
  classifyBlindStoreRoot,
  transferBlindStoreSessionTransactionLease,
  verifyBlindStoreSessionTransactionLease
} from '../store-session.js'

async function temporaryRoot (t, name = 'hiverelay-blind-store-session-') {
  const created = await fs.mkdtemp(path.join(os.tmpdir(), name))
  const root = await fs.realpath(created)
  await fs.chmod(root, 0o700)
  t.teardown(() => fs.rm(root, { recursive: true, force: true }))
  return root
}

async function createManifestedLayout (t) {
  const root = await temporaryRoot(t)
  const control = path.join(root, 'control')
  await fs.mkdir(control, { mode: 0o700 })
  await fs.writeFile(path.join(control, 'writer.lock.v1'), b4a.alloc(0), { mode: 0o600 })
  await fs.writeFile(path.join(control, 'wal.v2'), b4a.alloc(0), { mode: 0o600 })
  await fs.writeFile(path.join(control, 'manifest-a.v1'), b4a.alloc(64, 0x31), { mode: 0o600 })
  return { root, control, lock: path.join(control, 'writer.lock.v1') }
}

async function treeSnapshot (root, relative = '') {
  const directory = path.join(root, relative)
  const output = []
  for (const name of (await fs.readdir(directory)).sort()) {
    const childRelative = relative ? path.join(relative, name) : name
    const child = path.join(root, childRelative)
    const stat = await fs.lstat(child)
    const record = {
      path: childRelative,
      mode: stat.mode & 0o777,
      nlink: stat.nlink,
      type: stat.isDirectory() ? 'directory' : stat.isFile() ? 'file' : stat.isSymbolicLink() ? 'symlink' : 'other'
    }
    if (stat.isFile()) record.bytes = (await fs.readFile(child)).toString('hex')
    if (stat.isSymbolicLink()) record.target = await fs.readlink(child)
    output.push(record)
    if (stat.isDirectory()) output.push(...await treeSnapshot(root, childRelative))
  }
  return output
}

async function rejectsCode (t, promise, code) {
  try {
    await promise
    t.fail(`expected ${code}`)
  } catch (error) {
    t.is(error.code, code)
  }
}

test('store classifier accepts only exact runtime binding placement and still refuses ambiguous legacy roots', async t => {
  const root = await temporaryRoot(t)
  await fs.writeFile(path.join(root, 'runtime-binding.v1'), b4a.alloc(213, 0x42), { mode: 0o600 })
  const before = await treeSnapshot(root)
  const classified = await classifyBlindStoreRoot(root)
  t.is(classified.kind, BLIND_STORE_ROOT_CLASSIFICATION.PRISTINE)

  const session = new BlindStoreSession({ root })
  await t.exception(session.open(), /not explicitly authorized/)
  t.alike(await treeSnapshot(root), before)
  t.is(BLIND_STORE_SESSION_INTEGRATION_STATUS.transactionStoreLockOwnership, 'STORE_SESSION_TRANSACTION_LEASE')
  t.is(BLIND_STORE_SESSION_INTEGRATION_STATUS.blocker,
    'TWO_SLOT_MANIFEST_RUNTIME_INTEGRATION_UNASSEMBLED')

  const walV1Root = await temporaryRoot(t, 'hiverelay-blind-wal-v1-')
  const control = path.join(walV1Root, 'control')
  await fs.mkdir(control, { mode: 0o700 })
  await fs.writeFile(path.join(control, 'writer.lock.v1'), b4a.alloc(0), { mode: 0o600 })
  await fs.writeFile(path.join(control, 'manifest-a.v1'), b4a.alloc(64, 0x51), { mode: 0o600 })
  await fs.writeFile(path.join(control, 'wal.v1'), b4a.alloc(0), { mode: 0o600 })
  const walV1Before = await treeSnapshot(walV1Root)
  const walV1 = await classifyBlindStoreRoot(walV1Root)
  t.is(walV1.kind, BLIND_STORE_ROOT_CLASSIFICATION.LEGACY_AMBIGUOUS)
  t.ok(walV1.reason.includes('wal.v1'))
  await t.exception(new BlindStoreSession({ root: walV1Root }).open(), /legacy or ambiguous/)
  t.alike(await treeSnapshot(walV1Root), walV1Before)

  const mixed = await createManifestedLayout(t)
  await fs.writeFile(path.join(mixed.root, 'runtime-binding.v1'), b4a.alloc(213, 0x61), { mode: 0o600 })
  const mixedBefore = await treeSnapshot(mixed.root)
  const mixedClassification = await classifyBlindStoreRoot(mixed.root)
  t.is(mixedClassification.kind, BLIND_STORE_ROOT_CLASSIFICATION.CURRENT_MANIFESTED)
  const mixedSession = new BlindStoreSession({ root: mixed.root })
  await mixedSession.open()
  await mixedSession.close()
  t.alike(await treeSnapshot(mixed.root), mixedBefore)
})

test('StoreSession opens only an existing manifested lock and owns it until close', async t => {
  const state = await createManifestedLayout(t)
  const classified = await classifyBlindStoreRoot(state.root)
  t.is(classified.kind, BLIND_STORE_ROOT_CLASSIFICATION.CURRENT_MANIFESTED)

  const competing = await fs.open(state.lock, 'r+')
  t.teardown(() => competing.close())
  t.is(tryExclusiveFileLock(competing), true)
  const blocked = new BlindStoreSession({ root: state.root })
  await t.exception(blocked.open(), /active writer/)
  releaseExclusiveFileLock(competing)

  const session = new BlindStoreSession({ root: state.root })
  await session.open()
  const context = session.lockContext()
  t.is(context.classification, BLIND_STORE_ROOT_CLASSIFICATION.CURRENT_MANIFESTED)
  t.is(context.ownsWriterLock, true)
  t.is(context.transactionStoreLockOwnership, 'STORE_SESSION_TRANSACTION_LEASE')
  t.is(tryExclusiveFileLock(competing), false)
  await session.close()
  t.is(tryExclusiveFileLock(competing), true)
  releaseExclusiveFileLock(competing)
})

test('StoreSession detects a parent-directory path swap after opening the old lock inode', async t => {
  const state = await createManifestedLayout(t)
  const displaced = path.join(state.root, 'control-displaced')
  let swapped = false
  const session = new BlindStoreSession({
    root: state.root,
    faultInjector: async point => {
      if (!swapped && point === 'store-session:after-classification') {
        swapped = true
        await fs.rename(state.control, displaced)
        await fs.symlink(displaced, state.control)
      }
    }
  })
  await t.exception(session.open(), /layout changed/)
  t.is(swapped, true)

  const oldLock = await fs.open(path.join(displaced, 'writer.lock.v1'), 'r+')
  t.is(tryExclusiveFileLock(oldLock), true)
  releaseExclusiveFileLock(oldLock)
  await oldLock.close()
})

test('root symlinks and symlinked manifest recovery artifacts fail without cleanup', async t => {
  const state = await createManifestedLayout(t)
  const linkedRoot = `${state.root}-link`
  await fs.symlink(state.root, linkedRoot)
  t.teardown(() => fs.unlink(linkedRoot).catch(() => {}))
  await t.exception(classifyBlindStoreRoot(linkedRoot), /canonical daemon-owned private directory/)

  await fs.unlink(path.join(state.control, 'manifest-a.v1'))
  await fs.symlink('writer.lock.v1', path.join(state.control, 'manifest-a.v1'))
  const temporary = path.join(state.control, `.manifest-b.v1.${'4'.repeat(32)}.tmp`)
  await fs.symlink('writer.lock.v1', temporary)
  const before = await treeSnapshot(state.root)
  const classified = await classifyBlindStoreRoot(state.root)
  t.is(classified.kind, BLIND_STORE_ROOT_CLASSIFICATION.LEGACY_AMBIGUOUS)
  const session = new BlindStoreSession({ root: state.root })
  await t.exception(session.open(), /legacy or ambiguous/)
  t.alike(await treeSnapshot(state.root), before)
})

test('pristine lock creation requires explicit authority and a stable empty-root recheck', async t => {
  const root = await temporaryRoot(t)
  const refused = new BlindStoreSession({ root })
  await t.exception(refused.open(), /not explicitly authorized/)
  t.alike(await fs.readdir(root), [])

  let injected = false
  const raced = new BlindStoreSession({
    root,
    allowPristineBootstrap: true,
    faultInjector: async point => {
      if (!injected && point === 'store-session:after-classification') {
        injected = true
        await fs.writeFile(path.join(root, 'legacy-state'), b4a.from('legacy'), { mode: 0o600 })
      }
    }
  })
  await t.exception(raced.open(), /changed before bootstrap lock creation/)
  t.alike(await treeSnapshot(root), [{
    path: 'legacy-state',
    mode: 0o600,
    nlink: 1,
    type: 'file',
    bytes: b4a.from('legacy').toString('hex')
  }])

  const fresh = await temporaryRoot(t, 'hiverelay-blind-store-bootstrap-')
  const session = new BlindStoreSession({ root: fresh, allowPristineBootstrap: true })
  await session.open()
  const context = session.lockContext()
  t.is(context.classification, BLIND_STORE_ROOT_CLASSIFICATION.PRISTINE)
  t.is(context.bootstrapCreated, true)
  const competing = await fs.open(context.writerLockPath, 'r+')
  t.is(tryExclusiveFileLock(competing), false)
  await session.close()
  t.is(tryExclusiveFileLock(competing), true)
  releaseExclusiveFileLock(competing)
  await competing.close()
})

test('close racing open cannot leave a StoreSession writer lock behind', async t => {
  const state = await createManifestedLayout(t)
  let unblock
  const blocked = new Promise(resolve => { unblock = resolve })
  let markReached
  const reached = new Promise(resolve => { markReached = resolve })
  const session = new BlindStoreSession({
    root: state.root,
    faultInjector: async point => {
      if (point === 'store-session:after-classification') {
        markReached()
        await blocked
      }
    }
  })
  const opening = session.open()
  await reached
  const closing = session.close()
  unblock()
  await opening
  await closing

  const competing = await fs.open(state.lock, 'r+')
  t.is(tryExclusiveFileLock(competing), true)
  releaseExclusiveFileLock(competing)
  await competing.close()
  await t.exception(session.open(), /closed/)
})

test('transaction leases are branded, root-bound, singular, and keep the OS lock until release', async t => {
  const unopenedState = await createManifestedLayout(t)
  const unopened = new BlindStoreSession({ root: unopenedState.root })
  await t.exception(Promise.resolve().then(() => unopened.lockContext()), /does not hold its writer lock/)
  await unopened.close()

  const state = await createManifestedLayout(t)
  const session = new BlindStoreSession({ root: state.root })
  await session.open()
  const context = session.lockContext()
  t.is(Object.isFrozen(context), true)

  await rejectsCode(t,
    acquireBlindStoreSessionTransactionLease(Object.freeze({ ...context }), state.root),
    'BLIND_STORE_SESSION_CONTEXT_INVALID')
  await rejectsCode(t,
    acquireBlindStoreSessionTransactionLease(context, `${state.root}-wrong`),
    'BLIND_STORE_SESSION_ROOT_MISMATCH')

  const lease = await acquireBlindStoreSessionTransactionLease(context, state.root)
  t.is(Object.isFrozen(lease), true)
  await rejectsCode(t,
    acquireBlindStoreSessionTransactionLease(context, state.root),
    'BLIND_STORE_TRANSACTION_LEASE_ACTIVE')

  const competing = await fs.open(state.lock, 'r+')
  t.teardown(() => competing.close())
  let closed = false
  const closing = session.close().then(() => { closed = true })
  await Promise.resolve()
  t.is(closed, false)
  t.is(tryExclusiveFileLock(competing), false)
  lease.release()
  await closing
  t.is(closed, true)
  t.is(tryExclusiveFileLock(competing), true)
  releaseExclusiveFileLock(competing)
  await rejectsCode(t,
    acquireBlindStoreSessionTransactionLease(context, state.root),
    'BLIND_STORE_SESSION_CLOSING')
})

test('transaction lease acquisition rejects a substituted writer-lock inode without mutation', async t => {
  const state = await createManifestedLayout(t)
  const session = new BlindStoreSession({ root: state.root })
  await session.open()
  const context = session.lockContext()
  const displaced = `${state.lock}.displaced`
  await fs.rename(state.lock, displaced)
  await fs.writeFile(state.lock, b4a.alloc(0), { mode: 0o600 })
  const before = await treeSnapshot(state.root)

  await rejectsCode(t,
    acquireBlindStoreSessionTransactionLease(context, state.root),
    'BLIND_STORE_LOCK_INVALID')
  t.alike(await treeSnapshot(state.root), before)
  await session.close()
})

test('transaction lease transfer is singular and invalidates caller release authority', async t => {
  const state = await createManifestedLayout(t)
  const session = new BlindStoreSession({ root: state.root })
  await session.open()
  const original = await acquireBlindStoreSessionTransactionLease(session.lockContext(), state.root)
  const transferred = await transferBlindStoreSessionTransactionLease(original, state.root)

  await rejectsCode(t,
    verifyBlindStoreSessionTransactionLease(original, state.root),
    'BLIND_STORE_TRANSACTION_LEASE_INVALID')
  original.release()
  t.is(await verifyBlindStoreSessionTransactionLease(transferred, state.root), true)
  await rejectsCode(t,
    transferBlindStoreSessionTransactionLease(original, state.root),
    'BLIND_STORE_TRANSACTION_LEASE_INVALID')
  await rejectsCode(t,
    transferBlindStoreSessionTransactionLease(transferred, state.root),
    'BLIND_STORE_TRANSACTION_LEASE_TRANSFER_INVALID')

  const competing = await fs.open(state.lock, 'r+')
  t.teardown(() => competing.close())
  t.is(tryExclusiveFileLock(competing), false)
  let closed = false
  const closing = session.close().then(() => { closed = true })
  await Promise.resolve()
  t.is(closed, false)
  t.is(tryExclusiveFileLock(competing), false)
  transferred.release()
  await closing
  t.is(closed, true)
  t.is(tryExclusiveFileLock(competing), true)
  releaseExclusiveFileLock(competing)
})

test('classifier recognizes checkpoint names but rejects every hard-linked store artifact', async t => {
  const paired = await createManifestedLayout(t)
  const hash = 'a'.repeat(64)
  const checkpoint = path.join(paired.control, `checkpoint-${hash}.v1`)
  const temporary = path.join(paired.control, `.checkpoint-${hash}.v1.${'b'.repeat(32)}.tmp`)
  await fs.writeFile(checkpoint, b4a.alloc(256, 0x71), { mode: 0o600 })
  await fs.link(checkpoint, temporary)
  t.is((await fs.lstat(checkpoint)).nlink, 2)
  const pairedClassification = await classifyBlindStoreRoot(paired.root)
  t.is(pairedClassification.kind, BLIND_STORE_ROOT_CLASSIFICATION.LEGACY_AMBIGUOUS)
  await t.exception(new BlindStoreSession({ root: paired.root }).open(), /legacy or ambiguous/)

  const wrongHash = await createManifestedLayout(t)
  const first = path.join(wrongHash.control, `snapshot-${'c'.repeat(64)}.v1`)
  const mismatched = path.join(wrongHash.control, `.snapshot-${'d'.repeat(64)}.v1.${'e'.repeat(32)}.tmp`)
  await fs.writeFile(first, b4a.alloc(256, 0x72), { mode: 0o600 })
  await fs.link(first, mismatched)
  const rejected = await classifyBlindStoreRoot(wrongHash.root)
  t.is(rejected.kind, BLIND_STORE_ROOT_CLASSIFICATION.LEGACY_AMBIGUOUS)
  t.ok(rejected.reason.includes('single-link'))

  const external = await createManifestedLayout(t)
  const final = path.join(external.control, `checkpoint-${'f'.repeat(64)}.v1`)
  const outside = path.join(external.root, 'outside-hardlink')
  await fs.writeFile(final, b4a.alloc(256, 0x73), { mode: 0o600 })
  await fs.link(final, outside)
  const externallyLinked = await classifyBlindStoreRoot(external.root)
  t.is(externallyLinked.kind, BLIND_STORE_ROOT_CLASSIFICATION.LEGACY_AMBIGUOUS)
})
