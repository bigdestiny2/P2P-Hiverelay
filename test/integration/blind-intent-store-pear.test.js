import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { createRequire } from 'node:module'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { NodeIntentBackend } from '../../packages/blind-intent-pear-consumer/test/baseline/packages/blind-intent-store-node/index.js'
import { EncryptedIntentStore, INTENT_STATE, createAesGcmIntentSealer, createClientIntent } from '../../packages/blind-intent-pear-consumer/test/baseline/packages/blind-client/intent.js'
import { createNodeCryptoRuntime } from '../../packages/blind-intent-pear-consumer/test/baseline/packages/blind-client/runtime/node.js'

const require = createRequire(import.meta.url)
const consumer = process.env.PEAR_CONSUMER_PACKAGE || fileURLToPath(new URL('../../packages/blind-intent-pear-consumer', import.meta.url))
const { PearIntentBackend } = require(consumer)
const key = n => 'intent:' + BigInt(n).toString(16).padStart(64, '0')
const filename = n => key(n).slice(7) + '.intent'
const digest = bytes => createHash('sha256').update(bytes).digest('hex')
const gate = () => { let release; const promise = new Promise(resolve => { release = resolve }); return { promise, resolve: release } }

async function setup (t) {
  const base = await mkdtemp(join(await realpath(process.env.PEAR_TEST_STORAGE || tmpdir()), 'hiverelay-intent-pear-'))
  const backends = []
  t.after(async () => {
    for (const backend of backends) await backend.close().catch(() => {})
    await rm(base, { recursive: true, force: true })
  })
  return {
    base,
    path: join(base, 'store'),
    pear (name = 'store', options) { const backend = new PearIntentBackend(join(base, name), options); backends.push(backend); return backend },
    node (name = 'store') { const backend = new NodeIntentBackend(join(base, name)); backends.push(backend); return backend }
  }
}

function recordBytes (intentKey, revision, ciphertext) {
  const bytes = Buffer.alloc(84 + ciphertext.length)
  bytes.write('HRINDB01')
  bytes.writeBigUInt64BE(revision, 8)
  bytes.writeUInt32BE(ciphertext.length, 16)
  Buffer.from(intentKey.slice(7), 'hex').copy(bytes, 20)
  ciphertext.copy(bytes, 84)
  createHash('sha256').update(bytes.subarray(0, 52)).update(ciphertext).digest().copy(bytes, 52)
  return bytes
}

test('fixed packaged Pear worker observes its actual runtime and exits only after backend drain', async t => {
  const c = await setup(t)
  const backend = c.pear()
  const runtime = await backend.ready()
  assert.equal(runtime.runtime, 'v1.29.4')
  assert.equal(runtime.platform, process.platform)
  assert.equal(runtime.arch, process.arch)
  assert.equal(runtime.executableSha256, digest(await readFile(runtime.executable)))
  assert.equal(await backend.compareAndSwap(key(1), 0n, Buffer.from('first')), true)
  await backend.close()
  await assert.rejects(backend.ready(), { code: 'INTENT_STORE_CLOSED' })
  assert.deepEqual(backend.lifecycle.exit, { code: 0, signal: null })
  assert.deepEqual(backend.lifecycle.events, ['drained', 'exit', 'close'])
  assert.throws(() => process.kill(runtime.pid, 0), { code: 'ESRCH' })
  t.diagnostic(JSON.stringify({ runtime, lifecycle: backend.lifecycle, storage: c.base }))
})

test('Pear and Node retain common opaque bytes, exact u64 revisions and CAS conflicts', async t => {
  const c = await setup(t)
  const bytes = Buffer.from('00112233445566778899aabbccddeeff', 'hex')
  let pear = c.pear()
  assert.equal(await pear.compareAndSwap(key(1), 0n, bytes), true)
  await pear.close()
  const expected = recordBytes(key(1), 1n, bytes)
  assert.deepEqual(await readFile(join(c.path, filename(1))), expected)
  const node = c.node()
  assert.deepEqual(await node.read(key(1)), { revision: 1n, ciphertext: bytes })
  assert.equal(await node.compareAndSwap(key(1), 1n, Buffer.from('node-next')), true)
  await node.close()
  pear = c.pear()
  assert.equal(await pear.compareAndSwap(key(1), 1n, bytes), false)
  assert.equal(await pear.compareAndSwap(key(1), 2n, bytes), true)
  await pear.close()
  const high = (1n << 64n) - 2n
  await writeFile(join(c.path, filename(2)), recordBytes(key(2), high, bytes), { mode: 0o600 })
  pear = c.pear()
  assert.equal(await pear.compareAndSwap(key(2), high, Buffer.from('last')), true)
  assert.equal((await pear.read(key(2))).revision, high + 1n)
  await assert.rejects(pear.compareAndSwap(key(2), high + 1n, bytes), { code: 'INTENT_STORE_REVISION' })
  t.diagnostic('common-vector=' + expected.toString('hex'))
})

test('real worker and Node process contend on the same permanent writer inode', async t => {
  const c = await setup(t)
  const first = c.pear()
  await first.ready()
  const inode = (await stat(join(c.path, '.writer-lock'))).ino
  await assert.rejects(c.pear().ready(), { code: 'INTENT_STORE_LOCKED' })
  await assert.rejects(c.node().ready(), { code: 'INTENT_STORE_LOCKED' })
  await first.close()
  const next = c.node()
  await next.ready()
  assert.equal((await stat(join(c.path, '.writer-lock'))).ino, inode)
  await next.close()
  await c.pear().ready()
})

test('worker admission is bounded before startup and ciphertext copying; graceful close drains accepted work', async t => {
  const c = await setup(t)
  const reached = gate(); const release = gate()
  const backend = c.pear('store', { pauseAtPhase: 'after-file-sync', onPhase: () => { reached.resolve(); return release.promise } })
  const operations = Array.from({ length: 8 }, (_, i) => backend.compareAndSwap(key(i + 1), 0n, Buffer.from('queued')))
  await assert.rejects(backend.compareAndSwap(key(9), 0n, Buffer.from('overflow')), { code: 'INTENT_STORE_BUSY' })
  await reached.promise
  let closed = false
  const closing = backend.close().then(() => { closed = true })
  await assert.rejects(backend.read(key(1)), { code: 'INTENT_STORE_CLOSED' })
  assert.equal(closed, false)
  release.resolve()
  assert.deepEqual(await Promise.all(operations), Array(8).fill(true))
  await closing
  assert.equal(backend.lifecycle.drained, true)
  const node = c.node()
  for (let i = 1; i <= 8; i++) assert.equal((await node.read(key(i))).revision, 1n)
})

test('four bounded scans block mutation and are released by real worker close', async t => {
  const c = await setup(t)
  const backend = c.pear()
  for (let i = 1; i <= 6; i++) await backend.compareAndSwap(key(i), 0n, Buffer.from('data'))
  const cursors = []
  for (let i = 0; i < 4; i++) { const page = await backend.keysPage({ limit: 1 }); assert.ok(page.keys.length <= 1); assert.ok(page.cursor); cursors.push(page.cursor) }
  await assert.rejects(backend.keysPage({ limit: 1 }), { code: 'INTENT_STORE_BUSY' })
  await assert.rejects(backend.compareAndSwap(key(1), 1n, Buffer.from('blocked')), { code: 'INTENT_STORE_BUSY' })
  await backend.closeScan(cursors[0])
  await backend.close()
  const reopen = c.pear()
  assert.equal(await reopen.compareAndSwap(key(1), 1n, Buffer.from('resumed')), true)
  const names = []; let cursor = null
  do { const page = await reopen.keysPage({ cursor, limit: 2 }); assert.ok(page.keys.length <= 2); names.push(...page.keys); cursor = page.cursor } while (cursor)
  assert.equal(new Set(names).size, 6)
})

for (const phase of ['before-write', 'after-file-sync', 'after-publication', 'after-directory-sync']) {
  test('worker SIGKILL at ' + phase + ' reports unknown and recovers exact committed state', async t => {
    const c = await setup(t)
    const node = c.node()
    await node.compareAndSwap(key(1), 0n, Buffer.from('previous'))
    await node.close()
    const backend = c.pear('store', { pauseAtPhase: phase, onPhase: () => { backend._process.kill('SIGKILL'); return new Promise(() => {}) } })
    await assert.rejects(backend.compareAndSwap(key(1), 1n, Buffer.from('next')), { code: 'INTENT_STORE_WORKER_UNKNOWN' })
    await assert.rejects(backend.close(), { code: 'INTENT_STORE_WORKER_UNKNOWN' })
    assert.equal(backend.lifecycle, undefined)
    const recover = c.pear()
    const record = await recover.read(key(1))
    const published = phase === 'after-publication' || phase === 'after-directory-sync'
    assert.equal(record.revision, published ? 2n : 1n)
    assert.deepEqual(record.ciphertext, Buffer.from(published ? 'next' : 'previous'))
    assert.equal((await readdir(c.path)).includes('.pending'), false)
    t.diagnostic(JSON.stringify({ phase, killedExit: await backend._exit, revision: String(record.revision), ciphertext: record.ciphertext.toString('hex') }))
  })
}

test('caller keys seal before worker IPC; SENT recovery preserves the original operation identity', async t => {
  const c = await setup(t)
  const runtime = createNodeCryptoRuntime()
  const callerKey = Buffer.alloc(32, 91)
  const id = Buffer.alloc(32, 1)
  const operation = Buffer.from('PEAR_SIGNED_OPERATION_SENTINEL_20260905')
  const sealer = createAesGcmIntentSealer(runtime, callerKey)
  let backend = c.pear()
  let store = new EncryptedIntentStore({ backend, sealer })
  await store.create(createClientIntent({ runtime, intentId: id, logicalId: Buffer.alloc(32, 2), continuityRoot: Buffer.alloc(32, 3), storeId: Buffer.alloc(32, 4), descriptorHash: Buffer.alloc(32, 5), descriptorSequence: 7n, endpointId: 1, transportId: 1, transportSupportBit: 1, privacyProfileBit: 1, familyId: 2, operationId: 1, requestCommitment: Buffer.alloc(32, 6), clientNonce: Buffer.alloc(32, 7), operationBytes: operation }))
  await store.update(id, value => ({ ...value, state: INTENT_STATE.TARGET_PREPARED }))
  await store.update(id, value => ({ ...value, state: INTENT_STATE.SENT, mayHaveCommitted: true, attemptCount: 1 }))
  const sent = await store.read(id)
  await backend.close()
  const persisted = await readFile(join(c.path, id.toString('hex') + '.intent'))
  assert.equal(persisted.includes(operation), false)
  assert.equal(persisted.includes(callerKey), false)
  backend = c.pear()
  store = new EncryptedIntentStore({ backend, sealer })
  assert.equal((await store.read(id)).value.state, INTENT_STATE.SENT)
  await store.update(id, value => ({ ...value, state: INTENT_STATE.PENDING_UNKNOWN }))
  const recovered = await store.read(id)
  assert.equal(recovered.value.state, INTENT_STATE.PENDING_UNKNOWN)
  for (const field of ['logicalId', 'operationBytes', 'requestCommitment', 'clientNonce']) assert.deepEqual(recovered.value[field], sent.value[field])
  assert.equal(recovered.value.mayHaveCommitted, true)
  assert.equal(recovered.value.attemptCount, 1)
  const wrong = new EncryptedIntentStore({ backend, sealer: createAesGcmIntentSealer(runtime, Buffer.alloc(32, 92)) })
  await assert.rejects(wrong.read(id))
  t.diagnostic(JSON.stringify({ beforeRevision: String(sent.revision), afterRevision: String(recovered.revision), operationSha256: digest(operation), plaintextAbsent: true, wrongCallerKeyRejected: true }))
})

test('twelve packaged worker restarts leave no process or writer lock behind', async t => {
  const c = await setup(t)
  const pids = []
  for (let i = 0; i < 12; i++) {
    const backend = c.pear()
    pids.push((await backend.ready()).pid)
    assert.equal(await backend.compareAndSwap(key(1), BigInt(i), Buffer.from(String(i))), true)
    await backend.close()
    assert.equal(backend.lifecycle.drained, true)
    assert.throws(() => process.kill(pids.at(-1), 0), { code: 'ESRCH' })
  }
  const node = c.node()
  assert.equal((await node.read(key(1))).revision, 12n)
  t.diagnostic(JSON.stringify({ starts: pids.length, exits: pids.length, lockReacquired: true }))
})

test('parent SIGKILL cannot acknowledge success; orphaned worker closes and committed state reopens', async t => {
  const c = await setup(t)
  const fixture = fileURLToPath(new URL('../../packages/blind-intent-pear-consumer/test/parent-fixture.cjs', import.meta.url))
  const parent = spawn(process.execPath, [fixture, consumer, c.path], { stdio: ['ignore', 'pipe', 'pipe'] })
  t.after(async () => {
    if (parent.exitCode === null && parent.signalCode === null) { const ended = once(parent, 'exit'); parent.kill('SIGKILL'); await ended }
  })
  const phase = await new Promise((resolve, reject) => {
    let buffer = ''
    const timer = setTimeout(() => reject(new Error('parent did not reach publication')), 15000)
    parent.stdout.on('data', bytes => {
      buffer += bytes
      if (buffer.includes('\n')) { clearTimeout(timer); resolve(JSON.parse(buffer.split('\n')[0])) }
    })
    parent.once('error', error => { clearTimeout(timer); reject(error) })
    parent.once('exit', () => { clearTimeout(timer); if (!buffer.includes('\n')) reject(new Error('parent exited before publication')) })
  })
  assert.equal(phase.phase, 'after-publication')
  const exited = once(parent, 'exit')
  parent.kill('SIGKILL')
  assert.deepEqual(await exited, [null, 'SIGKILL'])
  let gone = false
  for (let attempt = 0; attempt < 300; attempt++) {
    try { process.kill(phase.workerPid, 0) } catch (error) { assert.equal(error.code, 'ESRCH'); gone = true; break }
    await new Promise(resolve => setTimeout(resolve, 50))
  }
  assert.equal(gone, true, 'task-owned worker exited after parent IPC loss')
  const recovered = await c.pear().read(key(1))
  assert.deepEqual(recovered, { revision: 1n, ciphertext: Buffer.from('parent-lost') })
  t.diagnostic(JSON.stringify({ parentSignal: 'SIGKILL', workerExited: gone, acknowledgedSuccess: false, recoveredRevision: String(recovered.revision) }))
})

test('operation deadline reaps an unresponsive worker and preserves an unknown outcome', async t => {
  const c = await setup(t)
  const backend = c.pear('store', { timeoutMs: 2000, pauseAtPhase: 'after-publication', onPhase: () => new Promise(() => {}) })
  await assert.rejects(backend.compareAndSwap(key(1), 0n, Buffer.from('deadline')), { code: 'INTENT_STORE_WORKER_UNKNOWN' })
  await assert.rejects(backend.ready(), { code: 'INTENT_STORE_WORKER_UNKNOWN' })
  let copied = false
  await assert.rejects(backend._operation('cas', () => { copied = true; return {} }), { code: 'INTENT_STORE_WORKER_UNKNOWN' })
  assert.equal(copied, false)
  await assert.rejects(backend.close(), { code: 'INTENT_STORE_WORKER_UNKNOWN' })
  assert.equal(backend.lifecycle, undefined)
  assert.deepEqual(await backend._exit, { code: null, signal: 'SIGKILL' })
  const recovered = await c.pear().read(key(1))
  assert.deepEqual(recovered, { revision: 1n, ciphertext: Buffer.from('deadline') })
})

test('streaming pipe decoding preserves fragmented UTF-8 and real caller Unicode storage paths', async t => {
  const c = await setup(t)
  const TextDecoder = require(require.resolve('text-decoder', { paths: [consumer] }))
  const wire = Buffer.from(JSON.stringify({ directory: '/private/保存/é/🚀' }) + '\n')
  for (let boundary = 0; boundary <= wire.length; boundary++) {
    const decoder = new TextDecoder()
    assert.equal(decoder.push(wire.subarray(0, boundary)) + decoder.push(wire.subarray(boundary)), wire.toString())
  }
  const backend = c.pear('保存-é-🚀')
  assert.equal(await backend.compareAndSwap(key(1), 0n, Buffer.from('unicode-root')), true)
  await backend.close()
  const node = c.node('保存-é-🚀')
  assert.deepEqual(await node.read(key(1)), { revision: 1n, ciphertext: Buffer.from('unicode-root') })
})
