import fs from 'node:fs/promises'
import path from 'node:path'
import b4a from 'b4a'
import test from 'brittle'
import {
  releaseExclusiveFileLock,
  tryExclusiveFileLock
} from '@hiverelay/blind-peercred'
import {
  BlindStoreSession,
  acquireBlindStoreSessionTransactionLease,
  verifyBlindStoreSessionTransactionLease
} from '../store-session.js'
import {
  BLIND_TRANSACTION_RECOVERY_HANDOFF_STATUS,
  BlindTransactionStore,
  verifyBlindWalAnchor,
  verifyBlindWalBarrierAuthority
} from '../transaction-store.js'
import {
  scanBlindWalV2ForAnchoredRecovery
} from '../wal-recovery-scan.js'
import {
  createBlindBoundaryScratch,
  removeBlindBoundaryScratch
} from '../../../test/blind-boundary-scratch.js'

async function temporaryRoot (t, name) {
  const root = await createBlindBoundaryScratch(name)
  await fs.chmod(root, 0o700)
  t.teardown(() => removeBlindBoundaryScratch(root))
  return root
}

async function manifestedRoot (t, name = 'hiverelay-blind-session-lock-') {
  const root = await temporaryRoot(t, name)
  const control = path.join(root, 'control')
  await fs.mkdir(control, { mode: 0o700 })
  await fs.writeFile(path.join(control, 'writer.lock.v1'), b4a.alloc(0), { mode: 0o600 })
  await fs.writeFile(path.join(control, 'manifest-a.v1'), b4a.alloc(64, 0x51), { mode: 0o600 })
  return { root, control, lock: path.join(control, 'writer.lock.v1') }
}

function storeOptions (root, extra = {}) {
  return {
    root,
    partitionKey: b4a.alloc(32, 0x31),
    mapGeneration: 1n,
    ownerFenceTokenHash: b4a.alloc(32, 0x32),
    durabilityContinuityHash: b4a.alloc(32, 0x33),
    ...extra
  }
}

async function rejectsCode (t, promise, code) {
  try {
    await promise
    t.fail(`expected ${code}`)
  } catch (error) {
    t.is(error.code, code)
  }
}

test('transaction store holds an exclusive OS lock for its complete writer lifetime', async t => {
  const root = await temporaryRoot(t, 'hiverelay-blind-os-lock-')
  const store = new BlindTransactionStore(storeOptions(root))
  await store.open(async () => {})
  const competing = await fs.open(path.join(root, 'control', 'writer.lock.v1'), 'r+')
  t.teardown(() => competing.close())
  t.is(tryExclusiveFileLock(competing), false)

  await store.close()
  t.is(tryExclusiveFileLock(competing), true)
  releaseExclusiveFileLock(competing)
})

test('pre-recovery validation runs under the writer lock and before WAL or blob mutation', async t => {
  const root = await temporaryRoot(t, 'hiverelay-blind-pre-recovery-')
  let hookObserved = false
  const store = new BlindTransactionStore(storeOptions(root, {
    beforeRecovery: async context => {
      hookObserved = true
      await t.exception(fs.lstat(context.walPath))
      await t.exception(fs.lstat(path.join(root, 'blobs')))
      await t.exception(fs.lstat(path.join(root, 'staging')))
      const competing = await fs.open(path.join(context.controlDirectory, 'writer.lock.v1'), 'r+')
      try {
        t.is(tryExclusiveFileLock(competing), false)
      } finally {
        await competing.close()
      }
      throw new Error('manifest validation refused the store')
    }
  }))
  await t.exception(store.open(async () => {}), /manifest validation refused/)
  t.is(hookObserved, true)
  await t.exception(fs.lstat(path.join(root, 'control', 'wal.v2')))
  await t.exception(fs.lstat(path.join(root, 'blobs')))
  await t.exception(fs.lstat(path.join(root, 'staging')))

  const competing = await fs.open(path.join(root, 'control', 'writer.lock.v1'), 'r+')
  t.is(tryExclusiveFileLock(competing), true)
  releaseExclusiveFileLock(competing)
  await competing.close()
})

test('external StoreSession contexts fail closed before transaction-store mutation', async t => {
  const forgedRoot = await temporaryRoot(t, 'hiverelay-blind-forged-context-')
  const forged = new BlindTransactionStore(storeOptions(forgedRoot, {
    storeSessionContext: Object.freeze({ root: forgedRoot })
  }))
  await rejectsCode(t, forged.open(async () => {}), 'BLIND_STORE_SESSION_CONTEXT_INVALID')
  t.alike(await fs.readdir(forgedRoot), [])

  const state = await manifestedRoot(t)
  const session = new BlindStoreSession({ root: state.root })
  await session.open()
  const context = session.lockContext()
  const wrongRoot = await temporaryRoot(t, 'hiverelay-blind-wrong-context-root-')
  const wrong = new BlindTransactionStore(storeOptions(wrongRoot, { storeSessionContext: context }))
  await rejectsCode(t, wrong.open(async () => {}), 'BLIND_STORE_SESSION_ROOT_MISMATCH')
  t.alike(await fs.readdir(wrongRoot), [])

  const lease = await acquireBlindStoreSessionTransactionLease(context, state.root)
  const second = new BlindTransactionStore(storeOptions(state.root, { storeSessionContext: context }))
  await rejectsCode(t, second.open(async () => {}), 'BLIND_STORE_TRANSACTION_LEASE_ACTIVE')
  t.alike((await fs.readdir(state.root)).sort(), ['control'])
  t.alike((await fs.readdir(state.control)).sort(), ['manifest-a.v1', 'writer.lock.v1'])
  lease.release()

  await session.close()
  const closed = new BlindTransactionStore(storeOptions(state.root, { storeSessionContext: context }))
  await rejectsCode(t, closed.open(async () => {}), 'BLIND_STORE_SESSION_CLOSING')
  t.alike((await fs.readdir(state.root)).sort(), ['control'])
  t.alike((await fs.readdir(state.control)).sort(), ['manifest-a.v1', 'writer.lock.v1'])
})

test('external transaction lease never relocks writer.lock and StoreSession closes last', async t => {
  const state = await manifestedRoot(t)
  const session = new BlindStoreSession({ root: state.root })
  await session.open()
  const store = new BlindTransactionStore(storeOptions(state.root, {
    storeSessionContext: session.lockContext()
  }))
  await store.open(async () => {})
  t.is(store.storeLockHandle, null)
  t.is(store.storeSessionTransactionLease, undefined)

  const competing = await fs.open(state.lock, 'r+')
  t.teardown(() => competing.close())
  t.is(tryExclusiveFileLock(competing), false)
  let expiredAnchor
  let expiredAuthority
  await store.withWalBarrier(async (barrierAuthority, anchor) => {
    t.ok(barrierAuthority)
    t.ok(anchor)
    t.is(barrierAuthority.release, undefined)
    t.is(await verifyBlindWalBarrierAuthority(barrierAuthority, state.root), true)
    t.is(await verifyBlindWalAnchor(anchor, state.root, barrierAuthority), true)
    const exposedHash = anchor.hash
    exposedHash.fill(0)
    t.is(await verifyBlindWalAnchor(anchor, state.root, barrierAuthority), true)
    await rejectsCode(t,
      verifyBlindWalBarrierAuthority(Object.freeze({ ...barrierAuthority }), state.root),
      'BLIND_WAL_BARRIER_AUTHORITY_INVALID')
    await rejectsCode(t,
      verifyBlindWalAnchor(Object.freeze({ ...anchor }), state.root, barrierAuthority),
      'BLIND_WAL_ANCHOR_INVALID')
    expiredAnchor = anchor
    expiredAuthority = barrierAuthority
  })
  await rejectsCode(t,
    verifyBlindWalBarrierAuthority(expiredAuthority, state.root),
    'BLIND_WAL_BARRIER_AUTHORITY_INVALID')
  await rejectsCode(t,
    verifyBlindWalAnchor(expiredAnchor, state.root, expiredAuthority),
    'BLIND_WAL_ANCHOR_INVALID')
  let sessionClosed = false
  const closing = session.close().then(() => { sessionClosed = true })
  await Promise.resolve()
  t.is(sessionClosed, false)
  t.is(tryExclusiveFileLock(competing), false)
  await store.close()
  await closing
  t.is(sessionClosed, true)
  t.is(tryExclusiveFileLock(competing), true)
  releaseExclusiveFileLock(competing)
})

test('external beforeRecovery failure releases only the transaction lease', async t => {
  const state = await manifestedRoot(t)
  const session = new BlindStoreSession({ root: state.root })
  await session.open()
  const context = session.lockContext()
  let hookObserved = false
  const store = new BlindTransactionStore(storeOptions(state.root, {
    storeSessionContext: context,
    beforeRecovery: async recovery => {
      hookObserved = true
      await t.exception(fs.lstat(recovery.walPath))
      await t.exception(fs.lstat(path.join(state.root, 'blobs')))
      await t.exception(fs.lstat(path.join(state.root, 'staging')))
      throw new Error('checkpoint validation refused the store')
    }
  }))
  await t.exception(store.open(async () => {}), /checkpoint validation refused/)
  t.is(hookObserved, true)
  t.alike((await fs.readdir(state.root)).sort(), ['control'])
  t.alike((await fs.readdir(state.control)).sort(), ['manifest-a.v1', 'writer.lock.v1'])

  const competing = await fs.open(state.lock, 'r+')
  t.is(tryExclusiveFileLock(competing), false)
  const replacementLease = await acquireBlindStoreSessionTransactionLease(context, state.root)
  replacementLease.release()
  t.is(tryExclusiveFileLock(competing), false)
  await session.close()
  t.is(tryExclusiveFileLock(competing), true)
  releaseExclusiveFileLock(competing)
  await competing.close()
})

test('external transaction open rejects writer-lock inode substitution before creating WAL state', async t => {
  const state = await manifestedRoot(t)
  const session = new BlindStoreSession({ root: state.root })
  await session.open()
  const context = session.lockContext()
  const displaced = path.join(state.root, 'displaced-writer-lock')
  await fs.rename(state.lock, displaced)
  await fs.writeFile(state.lock, b4a.alloc(0), { mode: 0o600 })
  const rootBefore = (await fs.readdir(state.root)).sort()
  const controlBefore = (await fs.readdir(state.control)).sort()

  const store = new BlindTransactionStore(storeOptions(state.root, { storeSessionContext: context }))
  await rejectsCode(t, store.open(async () => {}), 'BLIND_STORE_LOCK_INVALID')
  t.alike((await fs.readdir(state.root)).sort(), rootBefore)
  t.alike((await fs.readdir(state.control)).sort(), controlBefore)
  await t.exception(fs.lstat(path.join(state.root, 'blobs')))
  await t.exception(fs.lstat(path.join(state.root, 'staging')))
  await t.exception(fs.lstat(path.join(state.control, 'wal.v2')))
  await session.close()
})

test('appendAndApply excludes a concurrent WAL checkpoint barrier until state catches up', async t => {
  const root = await temporaryRoot(t, 'hiverelay-blind-wal-barrier-')
  const store = new BlindTransactionStore(storeOptions(root))
  await store.open(async () => {})
  let stateSequence = 0n
  let releaseApply
  const applyBlocked = new Promise(resolve => { releaseApply = resolve })
  let applyStarted
  const applyReached = new Promise(resolve => { applyStarted = resolve })
  const appending = store.appendAndApply({
    type: 201,
    transactionId: b4a.alloc(32, 0x61),
    virtualBucket: 7,
    payload: b4a.from('barrier-state')
  }, async frame => {
    applyStarted()
    await applyBlocked
    stateSequence = frame.sequence
  })
  await applyReached
  t.is(store.walSequence, 1n)
  t.is(stateSequence, 0n)

  let barrierRan = false
  const barrier = store.withWalBarrier(async (barrierAuthority, anchor) => {
    barrierRan = true
    t.ok(barrierAuthority)
    t.is(barrierAuthority.release, undefined)
    t.is(await verifyBlindWalBarrierAuthority(barrierAuthority, root), true)
    t.ok(anchor)
    t.is(anchor.sequence, 1n)
    t.is(store.walSequence, stateSequence)
  })
  await Promise.resolve()
  t.is(barrierRan, false)
  releaseApply()
  await appending
  await barrier
  t.is(barrierRan, true)
  t.is(stateSequence, 1n)

  let rejectApply
  const rejectApplyGate = new Promise(resolve => { rejectApply = resolve })
  let failedApplyStarted
  const failedApplyReached = new Promise(resolve => { failedApplyStarted = resolve })
  const failingApply = store.appendAndApply({
    type: 202,
    transactionId: b4a.alloc(32, 0x62),
    virtualBucket: 7,
    payload: b4a.from('apply-failure')
  }, async () => {
    failedApplyStarted()
    await rejectApplyGate
    throw new Error('apply refused')
  })
  await failedApplyReached
  const queuedAppend = store.append({
    type: 203,
    transactionId: b4a.alloc(32, 0x63),
    virtualBucket: 7,
    payload: b4a.from('must-not-append')
  })
  rejectApply()
  await t.exception(failingApply, /apply refused/)
  await t.exception(queuedAppend, /requires recovery/)
  t.is(store.walSequence, 2n)
  t.is(stateSequence, 1n)
  await t.exception(store.withWalBarrier(() => {}), /requires recovery/)
  await store.close()
})

test('close waits for an active WAL barrier and its opaque authority expires afterward', async t => {
  const root = await temporaryRoot(t, 'hiverelay-blind-wal-barrier-close-')
  const store = new BlindTransactionStore(storeOptions(root))
  await store.open(async () => {})
  let releaseBarrier
  const blocked = new Promise(resolve => { releaseBarrier = resolve })
  let entered
  const reached = new Promise(resolve => { entered = resolve })
  let capturedAuthority
  let capturedAnchor
  const active = store.withWalBarrier(async (barrierAuthority, anchor) => {
    capturedAuthority = barrierAuthority
    capturedAnchor = anchor
    entered()
    await blocked
    t.is(await verifyBlindWalBarrierAuthority(barrierAuthority, root), true)
    t.is(await verifyBlindWalAnchor(anchor, root, barrierAuthority), true)
  })
  await reached

  let closed = false
  const closing = store.close().then(() => { closed = true })
  await Promise.resolve()
  t.is(closed, false)
  t.ok(store.handle)
  t.is(capturedAuthority.release, undefined)
  t.is(await verifyBlindWalBarrierAuthority(capturedAuthority, root), true)
  await t.exception(store.append({
    type: 204,
    transactionId: b4a.alloc(32, 0x64),
    virtualBucket: 7,
    payload: b4a.from('closing-must-reject')
  }), /closing/)

  releaseBarrier()
  await active
  await closing
  t.is(closed, true)
  t.is(store.handle, null)
  await rejectsCode(t,
    verifyBlindWalBarrierAuthority(capturedAuthority, root),
    'BLIND_WAL_BARRIER_AUTHORITY_INVALID')
  await rejectsCode(t,
    verifyBlindWalAnchor(capturedAnchor, root, capturedAuthority),
    'BLIND_WAL_ANCHOR_INVALID')
})

test('recovery handoff rejects an unbranded result before callback, transfer, or mutation', async t => {
  const state = await manifestedRoot(t, 'hiverelay-blind-handoff-refused-')
  const session = new BlindStoreSession({ root: state.root })
  await session.open()
  const lease = await acquireBlindStoreSessionTransactionLease(session.lockContext(), state.root)
  const validationResult = Object.freeze({ kind: 'refused-test-result' })
  const rootBefore = (await fs.readdir(state.root)).sort()
  const controlBefore = (await fs.readdir(state.control)).sort()
  const manifestBefore = await fs.readFile(path.join(state.control, 'manifest-a.v1'))

  const refused = new BlindTransactionStore(storeOptions(state.root, {
    recoveryHandoff: {
      lease,
      validationResult,
      validate: async () => { throw new Error('unbranded result reached callback') }
    }
  }))
  await rejectsCode(t, refused.open(async () => {}), 'BLIND_RECOVERY_VALIDATION_AUTHORITY_INVALID')
  t.is(await verifyBlindStoreSessionTransactionLease(lease, state.root), true)
  t.alike((await fs.readdir(state.root)).sort(), rootBefore)
  t.alike((await fs.readdir(state.control)).sort(), controlBefore)
  t.alike(await fs.readFile(path.join(state.control, 'manifest-a.v1')), manifestBefore)

  const competing = await fs.open(state.lock, 'r+')
  t.is(tryExclusiveFileLock(competing), false)
  lease.release()
  await session.close()
  t.is(tryExclusiveFileLock(competing), true)
  releaseExclusiveFileLock(competing)
  await competing.close()
})

test('a branded WAL scan alone cannot authorize recovery handoff', async t => {
  const root = await temporaryRoot(t, 'hiverelay-blind-handoff-success-')
  const seed = new BlindTransactionStore(storeOptions(root))
  await seed.open(async () => {})
  const frames = []
  for (let index = 1; index <= 2; index++) {
    frames.push(await seed.append({
      type: 210 + index,
      transactionId: b4a.alloc(32, 0x70 + index),
      virtualBucket: index,
      payload: b4a.from(`recovery-${index}`)
    }))
  }
  await seed.close()
  const control = path.join(root, 'control')
  const walPath = path.join(control, 'wal.v2')
  await fs.writeFile(path.join(control, 'manifest-a.v1'), b4a.alloc(64, 0x79), { mode: 0o600 })
  const completeWalBytes = (await fs.stat(walPath)).size
  await fs.appendFile(walPath, b4a.alloc(31, 0xff))
  const tornWalBefore = await fs.readFile(walPath)

  const session = new BlindStoreSession({ root })
  await session.open()
  const callerLease = await acquireBlindStoreSessionTransactionLease(session.lockContext(), root)
  const shadowSequences = []
  const scanResult = await scanBlindWalV2ForAnchoredRecovery({
    root,
    lease: callerLease,
    checkpoint: { sequence: frames[0].sequence, hash: frames[0].walHash },
    mapGeneration: 1n,
    writerFenceTokenHash: b4a.alloc(32, 0x32),
    durabilityContinuityHash: b4a.alloc(32, 0x33),
    maximumWalBytes: 1024 * 1024,
    maximumWalFrames: 1024,
    maximumWalPayloadBytes: 1024 * 1024,
    applyShadowFrame: async frame => { shadowSequences.push(frame.sequence) }
  })
  t.alike(shadowSequences, [2n])
  t.is(scanResult.tornTailBytes, 31)
  t.alike(await fs.readFile(walPath), tornWalBefore)

  const store = new BlindTransactionStore(storeOptions(root, {
    recoveryHandoff: {
      lease: callerLease,
      validationResult: scanResult,
      validate: async () => { throw new Error('bare scan reached callback') }
    }
  }))
  await rejectsCode(t, store.open(async () => {}), 'BLIND_RECOVERY_VALIDATION_AUTHORITY_INVALID')
  t.is((await fs.stat(walPath)).size, completeWalBytes + 31)
  t.alike(await fs.readFile(walPath), tornWalBefore)
  t.is(await verifyBlindStoreSessionTransactionLease(callerLease, root), true)
  t.is(BLIND_TRANSACTION_RECOVERY_HANDOFF_STATUS.productionReady, false)
  callerLease.release()
  await session.close()
})
