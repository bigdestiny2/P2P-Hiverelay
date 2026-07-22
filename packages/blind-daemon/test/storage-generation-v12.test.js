import b4a from 'b4a'
import test from 'brittle'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { mkdtemp, readFile, readdir, rm, stat, unlink, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { BLIND_STORE_READER_MODE, openBlindStoreGenerationFloor } from '../storage-generation-v12.js'

const KEY = b4a.alloc(32, 0xa1)
const IDENTITY = b4a.from('authenticated-runtime-store-binding')
const first = { walSequence: 1n, walHash: b4a.alloc(32, 1) }
const second = { walSequence: 2n, walHash: b4a.alloc(32, 2) }
const third = { walSequence: 3n, walHash: b4a.alloc(32, 3) }
const fourth = { walSequence: 4n, walHash: b4a.alloc(32, 4) }

test('fresh 1.2 floor advances only after a newer acknowledged blind write', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'blind-store-generation-'))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const options = { manifestKey: KEY, storeIdentity: IDENTITY, storeEvidence: first }
  const floor = await openBlindStoreGenerationFloor(root, { ...options, allowCreate: true })
  t.is(floor.firstBlindOnlyWriteAcknowledged, false)
  t.ok(floor.assertReaderMode(BLIND_STORE_READER_MODE.BLIND_ONLY))
  t.exception(() => floor.assertReaderMode('legacy-only'), /fresh|replacement|blind-only/)
  await t.exception.all(() => floor.acknowledgeBlindOnlyWrite(first), /newer durable WAL write/)
  t.is(await floor.acknowledgeBlindOnlyWrite(second), true)
  const restarted = await openBlindStoreGenerationFloor(root, { ...options, storeEvidence: second })
  t.is(restarted.firstBlindOnlyWriteAcknowledged, true)
})

test('missing, tampered, replayed-false, transplanted, and partial evidence fail closed', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'blind-store-generation-'))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const options = { manifestKey: KEY, storeIdentity: IDENTITY, storeEvidence: first }
  const floor = await openBlindStoreGenerationFloor(root, { ...options, allowCreate: true })
  const oldHead = await readFile(path.join(root, 'blind-store-generation-head-v1.json'))
  await floor.acknowledgeBlindOnlyWrite(second)

  const record1 = (await readdir(root)).find(name => name.includes('0000000000000001'))
  await unlink(path.join(root, record1))
  await writeFile(path.join(root, 'blind-store-generation-head-v1.json'), oldHead)
  await t.exception.all(() => openBlindStoreGenerationFloor(root, { ...options, storeEvidence: second }), /rolled back|replayed/)

  const fresh = await mkdtemp(path.join(os.tmpdir(), 'blind-store-generation-'))
  t.teardown(() => rm(fresh, { recursive: true, force: true }))
  await openBlindStoreGenerationFloor(fresh, { ...options, allowCreate: true })
  const head = path.join(fresh, 'blind-store-generation-head-v1.json')
  const tampered = JSON.parse(await readFile(head))
  tampered.sequence = 9
  await writeFile(head, JSON.stringify(tampered))
  await t.exception.all(() => openBlindStoreGenerationFloor(fresh, options), /invalid/)
  await unlink(head)
  await t.exception.all(() => openBlindStoreGenerationFloor(fresh, options), /missing/)

  const partial = path.join(fresh, '.blind-store-generation-head.tmp-999')
  await writeFile(partial, '{')
  await t.exception.all(() => openBlindStoreGenerationFloor(fresh, options), /missing/)
  t.absent((await readdir(fresh)).includes(path.basename(partial)))

  const other = await mkdtemp(path.join(os.tmpdir(), 'blind-store-generation-'))
  t.teardown(() => rm(other, { recursive: true, force: true }))
  await openBlindStoreGenerationFloor(other, { ...options, storeIdentity: b4a.from('other'), allowCreate: true })
  await t.exception.all(() => openBlindStoreGenerationFloor(other, options), /another store|invalid/)
})

test('process kill between append-only record and head rename recovers monotonically', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'blind-store-generation-kill-'))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  await openBlindStoreGenerationFloor(root, {
    manifestKey: KEY, storeIdentity: IDENTITY, storeEvidence: first, allowCreate: true
  })
  const child = spawn(process.execPath, [
    new URL('storage-generation-kill-fixture.mjs', import.meta.url).pathname, root
  ], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'] })
  await once(child, 'message')
  const exited = once(child, 'exit')
  child.kill('SIGKILL')
  await exited
  const recovered = await openBlindStoreGenerationFloor(root, {
    manifestKey: KEY, storeIdentity: IDENTITY, storeEvidence: second
  })
  t.is(recovered.firstBlindOnlyWriteAcknowledged, true)
})

test('concurrent first commits serialize and retain the highest durable WAL evidence', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'blind-store-generation-concurrent-'))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const floor = await openBlindStoreGenerationFloor(root, {
    manifestKey: KEY, storeIdentity: IDENTITY, storeEvidence: first, allowCreate: true
  })
  t.alike(await Promise.all([
    floor.acknowledgeBlindOnlyWrite(second),
    floor.acknowledgeBlindOnlyWrite(third)
  ]), [true, true])
  const records = (await readdir(root)).filter(name => name.includes('generation-record')).sort()
  t.is(records.length, 2)
  const headPath = path.join(root, 'blind-store-generation-head-v1.json')
  const head = JSON.parse(await readFile(headPath))
  t.is(head.sequence, 1)
  const highest = JSON.parse(await readFile(path.join(root, records.at(-1))))
  t.is(highest.storeEvidence.walSequence, '3')
  const beforeNames = await readdir(root)
  const beforeHead = await readFile(headPath)
  const beforeHeadStat = await stat(headPath)
  t.is(await floor.acknowledgeBlindOnlyWrite(fourth), false)
  t.alike(await readdir(root), beforeNames)
  t.alike(await readFile(headPath), beforeHead)
  t.is((await stat(headPath)).mtimeMs, beforeHeadStat.mtimeMs)
  const restarted = await openBlindStoreGenerationFloor(root, {
    manifestKey: KEY, storeIdentity: IDENTITY, storeEvidence: fourth
  })
  t.is(restarted.firstBlindOnlyWriteAcknowledged, true)
  t.is(await restarted.acknowledgeBlindOnlyWrite(second), false)
})

test('record fsync linearizes the floor before recoverable head publication', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'blind-store-generation-linearization-'))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  let follower = null
  let floor = null
  floor = await openBlindStoreGenerationFloor(root, {
    manifestKey: KEY,
    storeIdentity: IDENTITY,
    storeEvidence: first,
    allowCreate: true,
    async faultInjector (phase) {
      if (phase === 'after-record-sync') follower = await floor.acknowledgeBlindOnlyWrite(third)
    }
  })
  t.is(await floor.acknowledgeBlindOnlyWrite(second), true)
  t.is(follower, false)
  const records = (await readdir(root)).filter(name => name.includes('generation-record')).sort()
  t.is(records.length, 2)
  const trueRecord = JSON.parse(await readFile(path.join(root, records.at(-1))))
  t.is(trueRecord.storeEvidence.walSequence, '2')
  const names = await readdir(root)
  t.is(names.filter(name => name.includes('generation-record')).length, 2)
  const restarted = await openBlindStoreGenerationFloor(root, {
    manifestKey: KEY, storeIdentity: IDENTITY, storeEvidence: third
  })
  t.is(restarted.firstBlindOnlyWriteAcknowledged, true)
})
