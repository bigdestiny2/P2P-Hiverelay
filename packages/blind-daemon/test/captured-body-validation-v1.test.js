import fs from 'node:fs/promises'
import path from 'node:path'
import test from 'brittle'
import b4a from 'b4a'
import { OPERATION } from '@hiverelay/blind-protocol'
import { BlindCellStorageEngine } from '../storage-engine-checkpoint-v1.js'
import { BlindInboxStorageEngine } from '../inbox-storage-engine-checkpoint-v1.js'
import { BlindCoreStorageEngine } from '../core-storage-engine-checkpoint-v1.js'
import { BlindStoreSession, acquireBlindStoreSessionTransactionLease } from '../store-session.js'
import { validateCapturedBodies, readCapturedBodyValidation } from '../captured-body-validation-v1.js'
import { clock, options, putFixture, profile1ResultBindingBytes } from './generation-history-fixture.js'
import * as inbox from './captured-body-inbox-fixture-v1.js'
import * as core from './captured-body-core-fixture-v1.js'
import { createBlindBoundaryScratch, removeBlindBoundaryScratch } from '../../../test/blind-boundary-scratch.js'

async function rootOf (t) {
  const root = await createBlindBoundaryScratch('captured-body-')
  t.teardown(() => removeBlindBoundaryScratch(root))
  return root
}
async function captureOf (Engine, input, role) {
  const owner = new BlindStoreSession({ root: input.root, validationOnly: true, allowUnmanifestedWal: true })
  await owner.open()
  const lease = await acquireBlindStoreSessionTransactionLease(owner.lockContext(), input.root)
  try {
    const capture = await Engine.captureFullWal(input, { lease })
    return { role, root: input.root, capture, lease, async close () { lease.release(); await owner.close() } }
  } catch (error) { lease.release(); await owner.close(); throw error }
}
async function bodyPaths (root) {
  const base = path.join(root, 'blobs')
  const result = []
  for (const bucket of await fs.readdir(base)) for (const name of await fs.readdir(path.join(base, bucket))) result.push(path.join(base, bucket, name))
  return result.sort()
}
async function cellFixture (t, { charged = false, retired = false, empty = false } = {}) {
  const root = await rootOf(t); const time = clock(); const input = options(root, time)
  const engine = new BlindCellStorageEngine(input)
  await engine.open()
  try {
    if (!empty) {
      const put = putFixture()
      await engine.putCell({ ...put, resultBinding: profile1ResultBindingBytes() })
      if (charged) {
        const commitment = b4a.alloc(32, 0xe1)
        await engine.chargedCellRead({ operationId: OPERATION.CELL.GET, request: { storageSlot: put.request.storageSlot }, requestCommitment: commitment, resultBinding: profile1ResultBindingBytes(), preparedAdmission: { ...put.preparedAdmission, spendTag: b4a.alloc(32, 0xe2), requestCommitment: commitment, costClass: { resourceClass: 1, leaseClass: 0, costUnits: 1n } } })
      }
      if (retired) { time.epoch = 1040; await engine.confirmClock(time.epoch); await engine.gc() }
    }
  } finally { await engine.close() }
  const captured = await captureOf(BlindCellStorageEngine, input, 'cell')
  t.teardown(() => captured.close())
  return captured
}
async function summary (captured, limits) {
  const token = await validateCapturedBodies({ ...captured, limits })
  return readCapturedBodyValidation(token, captured.root, captured.lease)
}

test('body validation checks actual CELL bytes, deduplicates paid read ownership, and copies evidence', async t => {
  const c = await cellFixture(t, { charged: true })
  const wal = path.join(c.root, 'control', 'wal.v2'); const before = await fs.readFile(wal)
  const token = await validateCapturedBodies({ ...c, limits: { maximumChunkBytes: 17 } })
  const value = await readCapturedBodyValidation(token, c.root, c.lease)
  t.is(value.bodyCount, 1); t.is(value.bodyBytes, 4096); t.is(value.ownerReferences, 2); t.is(value.bodies[0].owners, 2)
  const hash = b4a.from(value.bodies[0].hash); value.bodies[0].hash.fill(0); value.coveredWal.hash.fill(0)
  t.alike((await readCapturedBodyValidation(token, c.root, c.lease)).bodies[0].hash, hash)
  await t.exception.all(readCapturedBodyValidation({ ...token }, c.root, c.lease), /original/)
  await t.exception.all(readCapturedBodyValidation(token, c.root, { ...c.lease }), /original/)
  await t.exception.all(validateCapturedBodies({ ...c, capture: { ...c.capture } }), /original/)
  await t.exception.all(validateCapturedBodies({ ...c, role: 'inbox' }), /original/)
  t.alike(await fs.readFile(wal), before, 'no WAL mutation or repair')
})

test('body validation preserves paid history after legitimate CELL retirement', async t => {
  const c = await cellFixture(t, { retired: true })
  const value = await summary(c)
  t.is(value.bodyCount, 0); t.is(value.bodyBytes, 0); t.ok(value.hasIrreversibleHistory)
  t.is((await bodyPaths(c.root)).length, 0)
})

test('pristine capture has no invented body or irreversible history', async t => {
  const c = await cellFixture(t, { empty: true }); const value = await summary(c)
  t.is(value.bodyCount, 0); t.absent(value.hasIrreversibleHistory)
})

test('body validation checks retained INBOX frame bytes and charged page pins', async t => {
  const root = await rootOf(t); const time = inbox.clock(); const input = inbox.engineOptions(root, time)
  const engine = new BlindInboxStorageEngine(input)
  await engine.open()
  try {
    const created = inbox.createFixture()
    await engine.createInbox({ ...created, resultBinding: inbox.binding() })
    await inbox.appendAndFinalize(engine, { ...inbox.appendFixture(created, 0xd3), resultBinding: inbox.binding() })
    const read = inbox.readFixture(created)
    await engine.pinChargedPage({ operationId: OPERATION.INBOX.READ, ...read, resultBinding: inbox.binding() })
    await engine.finalizeChargedPage({ spendTag: read.preparedAdmission.spendTag, requestCommitment: read.requestCommitment, resultCommitment: b4a.alloc(32, 0xf1) })
  } finally { await engine.close() }
  const c = await captureOf(BlindInboxStorageEngine, input, 'inbox')
  try {
    const value = await summary(c)
    t.is(value.bodyCount, 1); t.is(value.bodyBytes, 4096); t.ok(value.hasIrreversibleHistory)
    const file = (await bodyPaths(root))[0]; const original = await fs.readFile(file)
    await fs.writeFile(file, b4a.alloc(original.length, 0x91))
    await t.exception.all(summary(c), /hash differs/)
    t.alike(await fs.readFile(file), b4a.alloc(original.length, 0x91), 'no implicit body repair')
  } finally { await c.close() }
})

test('body validation retains replaced CORE paid proof corpus and releases only retired owners', async t => {
  const root = await rootOf(t); const time = core.clock(); const keys = core.signingAuthority()
  const input = core.storageOptions(root, time, keys.publicKey)
  const storage = new BlindCoreStorageEngine(input)
  await storage.open()
  let expiry
  try {
    const adapter = core.adapterHarness(storage, keys, core.descriptorAuthority(keys.publicKey), core.upstreamAuthority())
    const first = core.mirrorRequest(keys.publicKey)
    await adapter.execute(core.executionInput(OPERATION.CORE.MIRROR, first.request, first.requestCommitment, core.admission(first.requestCommitment, 0xa1, 1)))
    const proof = core.proveRequest(keys.publicKey, first)
    await adapter.execute(core.executionInput(OPERATION.CORE.PROVE, proof.request, proof.requestCommitment, core.admission(proof.requestCommitment, 0xb1, 0)))
    expiry = [...storage.proofPins.values()][0].expiresAtUnixMillis
    const next = core.mirrorRequest(keys.publicKey, { length: 5n, signedHeadHash: b4a.alloc(32, 0x42), clientNonce: b4a.alloc(32, 0x52) })
    await adapter.execute(core.executionInput(OPERATION.CORE.MIRROR, next.request, next.requestCommitment, core.admission(next.requestCommitment, 0xa2, 1)))
  } finally { await storage.close() }
  const c = await captureOf(BlindCoreStorageEngine, input, 'core')
  try { const value = await summary(c); t.is(value.bodyCount, 2); t.is(value.bodyBytes, 8192); t.is(value.ownerReferences, 2) } finally { await c.close() }
  const retired = new BlindCoreStorageEngine(input)
  await retired.open()
  try {
    time.millis = expiry + 1n; t.is(await retired.sweepProofPins(), 1)
    time.epoch = 1005; time.millis = BigInt(time.epoch) * 21600000n
    t.is(await retired.sweepExpiredCores(), 1)
  } finally { await retired.close() }
  const after = await captureOf(BlindCoreStorageEngine, input, 'core')
  try { const value = await summary(after); t.is(value.bodyCount, 0); t.ok(value.hasIrreversibleHistory); t.is((await bodyPaths(root)).length, 0) } finally { await after.close() }
})

for (const damage of ['missing', 'short', 'changed', 'symlink', 'hardlink', 'permissions', 'bucket-symlink']) {
  test(`body validation refuses ${damage} without changing the journal`, async t => {
    const c = await cellFixture(t); const file = (await bodyPaths(c.root))[0]
    const wal = path.join(c.root, 'control', 'wal.v2'); const before = await fs.readFile(wal)
    if (damage === 'missing') await fs.unlink(file)
    if (damage === 'short') await fs.truncate(file, 3)
    if (damage === 'changed') await fs.writeFile(file, b4a.alloc(4096, 0xa2))
    if (damage === 'symlink') { await fs.rename(file, file + '.target'); await fs.symlink(file + '.target', file) }
    if (damage === 'hardlink') await fs.link(file, file + '.link')
    if (damage === 'permissions') await fs.chmod(file, 0o644)
    if (damage === 'bucket-symlink') { const bucket = path.dirname(file); await fs.rename(bucket, bucket + '.target'); await fs.symlink(bucket + '.target', bucket) }
    await t.exception.all(summary(c))
    t.alike(await fs.readFile(wal), before)
  })
}

test('body validation refuses configured work limits before reading any body', async t => {
  const c = await cellFixture(t, { charged: true })
  for (const limits of [{ maximumBodyBytes: 4095 }, { maximumTotalBytes: 4095 }, { maximumReferences: 1 }, { maximumChunkBytes: 1048577 }, { maximumBodies: 0 }, { madeUp: 1 }]) await t.exception.all(summary(c, limits))
  t.is((await summary(c, { maximumBodies: 1, maximumTotalBytes: 4096, maximumReferences: 2 })).bodyCount, 1)
})

test('body validation refuses late body or WAL changes on consumption', async t => {
  const c = await cellFixture(t); const token = await validateCapturedBodies(c)
  const file = (await bodyPaths(c.root))[0]
  await fs.writeFile(file, b4a.alloc(4096, 0xa1))
  await t.exception.all(readCapturedBodyValidation(token, c.root, c.lease), /changed/)
  const fresh = await validateCapturedBodies(c)
  await fs.appendFile(path.join(c.root, 'control', 'wal.v2'), b4a.from([1]))
  await t.exception.all(readCapturedBodyValidation(fresh, c.root, c.lease))
})

for (const action of ['cancel', 'release', 'mutate']) {
  test(`body validation ${action} during actual streaming closes its body handle`, async t => {
    const c = await cellFixture(t); const file = (await bodyPaths(c.root))[0]; const controller = new AbortController()
    const original = fs.open; let opened = 0; let closed = 0; let fired = false
    fs.open = async function (name, ...args) {
      const handle = await original.call(this, name, ...args)
      if (name === file) {
        opened++
        const read = handle.read.bind(handle); const close = handle.close.bind(handle)
        handle.read = async (...readArgs) => {
          const result = await read(...readArgs)
          if (!fired) {
            fired = true
            if (action === 'cancel') controller.abort()
            if (action === 'release') c.lease.release()
            if (action === 'mutate') await fs.writeFile(file, b4a.alloc(4096, 0x13))
          }
          return result
        }
        handle.close = async () => { await close(); closed++ }
      }
      return handle
    }
    try { await t.exception.all(validateCapturedBodies({ ...c, limits: { maximumChunkBytes: 17 }, signal: controller.signal })); t.ok(fired); t.is(opened, closed); t.is(opened, 1) } finally { fs.open = original }
  })
}

test('body validation refuses pre-cancellation and released native lease', async t => {
  const c = await cellFixture(t); const controller = new AbortController(); controller.abort()
  await t.exception.all(validateCapturedBodies({ ...c, signal: controller.signal }), /cancelled/)
  const token = await validateCapturedBodies(c); c.lease.release()
  await t.exception.all(readCapturedBodyValidation(token, c.root, c.lease), /lease/)
})

test('body validation refuses a parent replacement and closes after a read failure', async t => {
  const c = await cellFixture(t); const file = (await bodyPaths(c.root))[0]
  const original = fs.open; let closed = false
  fs.open = async function (name, ...args) {
    const handle = await original.call(this, name, ...args)
    if (name === file) {
      const close = handle.close.bind(handle)
      handle.read = async () => { throw new Error('injected body read failure') }
      handle.close = async () => { await close(); closed = true }
    }
    return handle
  }
  try { await t.exception.all(validateCapturedBodies(c), /injected body read failure/); t.ok(closed) } finally { fs.open = original }
  const token = await validateCapturedBodies(c)
  const bucket = path.dirname(file); await fs.rename(bucket, bucket + '.old'); await fs.mkdir(bucket, { mode: 0o700 })
  await fs.copyFile(path.join(bucket + '.old', path.basename(file)), file); await fs.chmod(file, 0o600)
  await t.exception.all(readCapturedBodyValidation(token, c.root, c.lease), /changed/)
})

test('body validation rejects noncanonical roots and caller-created descriptive values', async t => {
  const c = await cellFixture(t)
  for (const root of [path.relative(process.cwd(), c.root), c.root + '/', c.root + '/x/..', c.root + '\0', c.root + '-other']) await t.exception.all(validateCapturedBodies({ ...c, root }))
  await t.exception.all(readCapturedBodyValidation({ kind: 'CAPTURED_OPAQUE_BODIES_V1', role: 'cell', root: c.root }, c.root, c.lease), /original/)
})
