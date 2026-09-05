import test from 'brittle'
import fs from 'node:fs/promises'
import path from 'node:path'
import b4a from 'b4a'
import { createHash } from 'node:crypto'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { BlindStoreSession, acquireBlindStoreSessionTransactionLease } from '../store-session.js'
import { prepareBlindGenerationStartup } from '../generation-startup.js'
import { createBlindBoundaryScratch, removeBlindBoundaryScratch } from '../../../test/blind-boundary-scratch.js'
import { clock, options, putFixture, atomicPut, profile1ResultBindingBytes, BlindCellStorageEngine, openHistory, retireCells, generationBytes, startupOptions } from './generation-history-fixture.js'

const digest = bytes => createHash('sha256').update(bytes).digest('hex')
async function scratch (t) {
  const root = await createBlindBoundaryScratch('ghistory-')
  t.teardown(() => removeBlindBoundaryScratch(root))
  return root
}

async function inventory (root, relative = '') {
  const output = []
  for (const name of (await fs.readdir(path.join(root, relative))).sort()) {
    const file = path.join(relative, name)
    const stat = await fs.lstat(path.join(root, file))
    output.push({ path: file, mode: stat.mode & 0o777, nlink: stat.nlink, bytes: stat.isFile() ? stat.size : null, sha256: stat.isFile() ? digest(await fs.readFile(path.join(root, file))) : null })
    if (stat.isDirectory()) output.push(...await inventory(root, file))
  }
  return output
}

async function inspect (root, time, limits) {
  const session = new BlindStoreSession({ root, validationOnly: true, allowUnmanifestedWal: true })
  await session.open()
  const lease = await acquireBlindStoreSessionTransactionLease(session.lockContext(), root)
  try { return await BlindCellStorageEngine.inspectGeneration(options(root, time), { lease, limits }) } finally { lease.release(); await session.close() }
}

async function unchanged (t, root, operation) {
  const before = await inventory(root)
  await operation()
  const after = await inventory(root)
  t.alike(after, before, 'validation leaves every persisted byte and namespace entry unchanged')
  t.comment(JSON.stringify({ before, after, beforeHash: digest(JSON.stringify(before)), afterHash: digest(JSON.stringify(after)) }))
}

for (const atomic of [false, true]) {
  test(`CELL ${atomic ? 'atomic' : 'staged'} history survives empty live rows, full replay and copied-root startup`, async t => {
    const root = await scratch(t)
    const time = clock()
    let owned = await openHistory(root, time, { allowFreshGenesis: true })
    const { engine, startup } = owned
    t.is(engine.storageGenerationEvidence().hasIrreversibleState, false)
    const input = putFixture()
    if (atomic) await atomicPut(engine, input)
    else await engine.putCell({ ...input, resultBinding: profile1ResultBindingBytes() })
    const trigger = startup.floor.triggerReceipt()
    const authority = await generationBytes(root)
    t.ok(trigger, 'real acknowledged write publishes the installation floor')
    t.ok(await retireCells(engine, time) >= 2, 'legal horizon compaction removes CELL and spend rows')
    t.is(engine.cells.size, 0)
    t.is(engine.spends.size, 0)
    t.is(engine.requestResults.size, 0)
    t.is(engine.storageGenerationEvidence().hasIrreversibleState, true, 'retired live state is not the history authority')
    t.alike(await generationBytes(root), authority, 'compaction does not rewrite the signed first trigger')
    await owned.close()
    await unchanged(t, root, async () => t.is((await inspect(root, time)).hasIrreversibleState, true))
    const copy = await scratch(t)
    await fs.cp(root, copy, { recursive: true, preserveTimestamps: true })
    t.alike(await inventory(copy), await inventory(root), 'closed full-root copy retains exact control/WAL/identity bytes')
    for (const target of [root, copy]) {
      owned = await openHistory(target, time)
      t.is(owned.startup.currentStores[0].hasIrreversibleState, true, 'G01b consumes historical semantic evidence')
      t.is(owned.engine.storageGenerationEvidence().hasIrreversibleState, true)
      t.alike(owned.startup.floor.triggerReceipt(), trigger)
      t.is(owned.engine.cells.size, 0)
      await owned.close()
    }
  })
}

test('partial authority restore over retired full WAL conservatively preserves history', async t => {
  const root = await scratch(t)
  const time = clock()
  const owned = await openHistory(root, time, { allowFreshGenesis: true })
  const beforeTrigger = await generationBytes(root)
  await atomicPut(owned.engine, putFixture())
  await retireCells(owned.engine, time)
  await owned.close()
  const control = path.join(root, 'control')
  for (const record of await generationBytes(root)) await fs.unlink(path.join(control, record.name))
  for (const record of beforeTrigger) await fs.writeFile(path.join(control, record.name), record.bytes, { mode: 0o600 })
  await unchanged(t, root, async () => t.is((await inspect(root, time)).hasIrreversibleState, true))
  const reopened = await openHistory(root, time)
  t.is(reopened.startup.floor.firstIrreversibleWriteAcknowledged, true)
  t.is(reopened.startup.floor.trigger.recoveryConservative, true)
  t.is(reopened.engine.cells.size, 0)
  await reopened.close()
})

test('fresh, reserved and terminal failed CELL writes never invent irreversible history', async t => {
  const root = await scratch(t)
  const time = clock()
  const owned = await openHistory(root, time, { allowFreshGenesis: true })
  const cancelled = putFixture({ spendByte: 0xe1, nonceByte: 0xe2 })
  const staged = await owned.engine.stageAtomicCellPut({ request: cancelled.request, source: cancelled.cellBlob, admissionProfileId: cancelled.preparedAdmission.profileId, resultBinding: profile1ResultBindingBytes() })
  await t.exception(owned.engine.commitAtomicCellPut({ authority: staged, preparedAdmission: cancelled.preparedAdmission, preCommitFence () { throw new Error('cancelled before commit') } }), /cancelled before commit/)
  t.is(owned.engine.storageGenerationEvidence().hasIrreversibleState, false, 'aborted staging creates no historical commit')
  const invalid = putFixture({ declaredBlobHash: b4a.alloc(32, 0xed) })
  let entered
  let release
  const entering = new Promise(resolve => { entered = resolve })
  const held = new Promise(resolve => { release = resolve })
  const source = (async function * () { entered(); await held; yield invalid.cellBlob })()
  const pending = owned.engine.putCell({ ...invalid, source, resultBinding: profile1ResultBindingBytes() }).catch(error => error)
  await entering
  t.is(owned.engine.spends.size, 1, 'a real reservation exists while the body is pending')
  t.is(owned.engine.storageGenerationEvidence().hasIrreversibleState, false)
  release()
  t.is((await pending).code, 'RETRY_TERMINAL')
  t.is(owned.engine.storageGenerationEvidence().hasIrreversibleState, false)
  t.is(owned.startup.floor.firstIrreversibleWriteAcknowledged, false)
  await owned.close()
  await unchanged(t, root, async () => t.is((await inspect(root, time)).hasIrreversibleState, false))
  const reopened = await openHistory(root, time)
  t.is(reopened.startup.floor.firstIrreversibleWriteAcknowledged, false)
  await reopened.close()
})

for (const kind of ['missing', 'partial', 'oversized', 'pruned']) {
  test(`historical ${kind} evidence refuses before startup mutation`, async t => {
    const root = await scratch(t)
    const time = clock()
    const owned = await openHistory(root, time, { allowFreshGenesis: true })
    for (let n = 0; n < (kind === 'pruned' ? 80 : 1); n++) await atomicPut(owned.engine, putFixture({ spendByte: 1 + n, nonceByte: 1 + n }))
    await retireCells(owned.engine, time)
    if (kind === 'pruned') {
      const anchor = { sequence: owned.engine.transactionStore.walSequence, hash: owned.engine.transactionStore.walHash }
      const pruned = await owned.engine.transactionStore.pruneWalSegments({ checkpointAnchor: anchor, retainFromSequence: owned.engine.spendRetentionWalFloorSequence() })
      t.ok(pruned.prunedSegments.length > 0, 'real sealed WAL segments were pruned')
    }
    await owned.close()
    if (kind === 'missing') for (const record of await generationBytes(root)) await fs.unlink(path.join(root, 'control', record.name))
    if (kind === 'partial') await fs.writeFile(path.join(root, 'control', (await generationBytes(root))[0].name), '{', { mode: 0o600 })
    const extra = kind === 'oversized' ? { limits: { maximumWalBytes: 224 } } : {}
    await unchanged(t, root, () => t.exception(prepareBlindGenerationStartup(startupOptions(root, time, extra)), /generation|WAL|genesis|sequence|bounds|maximum/i))
  })
}

for (const phase of ['compaction-wal-synced', 'compaction-applied']) {
  test(`real process death at ${phase} retains irreversible history`, async t => {
    const root = await scratch(t)
    const child = spawn(process.execPath, [new URL('./generation-history-worker.mjs', import.meta.url).pathname, root, phase], { stdio: ['ignore', 'pipe', 'pipe', 'ipc'] })
    let stderr = ''
    child.stderr.on('data', bytes => { stderr += bytes })
    const watchdog = setTimeout(() => child.kill('SIGKILL'), 15000)
    t.teardown(() => { clearTimeout(watchdog); if (child.exitCode == null) child.kill('SIGKILL') })
    const reached = await Promise.race([once(child, 'message').then(([value]) => value), once(child, 'exit').then(([code, signal]) => { throw new Error(`child ended before barrier: ${code}/${signal}: ${stderr}`) })])
    const closed = once(child, 'close')
    child.kill('SIGKILL')
    await closed
    clearTimeout(watchdog)
    t.is(reached.phase, phase)
    const owned = await openHistory(root, clock(2502))
    t.is(owned.startup.currentStores[0].hasIrreversibleState, true)
    t.is(owned.engine.storageGenerationEvidence().hasIrreversibleState, true)
    t.alike(owned.startup.floor.triggerReceipt(), reached.trigger)
    if (phase === 'compaction-applied') t.is(owned.engine.cells.size, 0)
    t.comment(JSON.stringify({ phase, trigger: reached.trigger, signal: child.signalCode, stderr }))
    await owned.close()
  })
}
