import test from 'brittle'
import b4a from 'b4a'
import fs from 'node:fs/promises'
import path from 'node:path'
import { createHash } from 'node:crypto'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { blake2b256 } from '@hiverelay/blind-protocol'
import { loadDaemonBootstrapConfig } from '../bootstrap-config.js'
import { assembleProductionBlindDaemon, loadProductionRuntimeConfig } from '../production-runtime.js'
import { prepareBlindGenerationStartup } from '../generation-startup.js'
import { BlindStoreSession, acquireBlindStoreSessionTransactionLease } from '../store-session.js'
import { BlindCellStorageEngine } from '../storage-engine.js'
import { BlindInboxStorageEngine } from '../inbox-storage-engine.js'
import { BlindCoreStorageEngine } from '../core-storage-engine.js'
import { BlindTransactionStore } from '../transaction-store.js'
import { BLIND_STORE_READER_MODE } from '../storage-generation-v12.js'
import { runtimeCoreFixture } from './production-runtime-core-fixture.js'
import { createBlindBoundaryScratch, removeBlindBoundaryScratch } from '../../../test/blind-boundary-scratch.js'

const digest = bytes => createHash('sha256').update(bytes).digest('hex')
const KEY = b4a.alloc(32, 0x91)
const ID = b4a.from('generation-startup-functional-fixture')
const engines = { cell: BlindCellStorageEngine, inbox: BlindInboxStorageEngine, core: BlindCoreStorageEngine }

async function inventory (root, relative = '') {
  const output = []
  for (const name of (await fs.readdir(path.join(root, relative))).sort()) {
    const target = path.join(relative, name)
    const stat = await fs.lstat(path.join(root, target))
    output.push({
      path: target,
      kind: stat.isDirectory() ? 'directory' : 'file',
      mode: stat.mode & 0o777,
      nlink: stat.nlink,
      bytes: stat.isFile() ? stat.size : null,
      sha256: stat.isFile() ? digest(await fs.readFile(path.join(root, target))) : null
    })
    if (stat.isDirectory()) output.push(...await inventory(root, target))
  }
  return output
}

async function rootsInventory (roots) {
  return Promise.all(roots.map(async root => ({ root: path.basename(root), entries: await inventory(root) })))
}

function recordInventory (t, label, before, after) {
  t.comment(JSON.stringify({ label, before, after, beforeHash: digest(JSON.stringify(before)), afterHash: digest(JSON.stringify(after)) }))
  t.alike(after, before, 'all store bytes and directory entries remain exact')
}

function admissionAdapter () {
  const preflights = new WeakSet()
  const prepared = input => Object.freeze({ spendTag: blake2b256(input.admission.token), requestCommitment: b4a.from(input.requestCommitment), costClass: { ...input.costClass }, walCommitRecord: b4a.from(input.admission.token), profileId: input.admission.profileId, schemeId: input.admission.schemeId, parameterHash: b4a.from(input.admission.parameterHash) })
  return {
    async prepare (input) { return prepared(input) },
    async preparePreflight () { const token = {}; preflights.add(token); return token },
    async confirmAfterEof (input) {
      if (!preflights.delete(input.adapterPreflight)) throw new Error('unknown test admission preflight')
      return prepared(input)
    }
  }
}

async function assemble (fixture) {
  // These tests assemble the daemon without listening. Keep the unused socket
  // addresses portable even when the owned worktree path is very long.
  const socketRoot = `/tmp/gq-${digest(fixture.directory).slice(0, 12)}`
  const environment = {
    ...fixture.environment,
    HIVERELAY_BLIND_UNARY_SOCKET: `${socketRoot}/unary.sock`,
    HIVERELAY_BLIND_STREAM_SOCKET: `${socketRoot}/stream.sock`
  }
  const bootstrap = loadDaemonBootstrapConfig(environment)
  return assembleProductionBlindDaemon({
    bootstrap: { ...bootstrap, expectedPeerUid: process.getuid() },
    runtimeConfig: loadProductionRuntimeConfig(environment, bootstrap.endpointIds),
    enableCellRuntime: true,
    enableInboxRuntime: true,
    enableCoreRuntime: true,
    resolveAdmissionAdapter: async () => admissionAdapter(),
    releaseGate: async () => {}
  })
}

function runtimeRoots (fixture) {
  return ['HIVERELAY_BLIND_STORE_ROOT', 'HIVERELAY_BLIND_INBOX_STORE_ROOT', 'HIVERELAY_BLIND_CORE_STORE_ROOT'].map(key => fixture.environment[key])
}

async function addRecoveryCandidates (roots) {
  for (const root of roots) {
    await fs.appendFile(path.join(root, 'control', 'wal.v2'), b4a.alloc(19, 0xff))
    await fs.writeFile(path.join(root, 'staging', 'interrupted-startup.tmp'), b4a.from('retained recovery candidate'), { mode: 0o600 })
  }
}

for (const kind of ['missing', 'malformed', 'foreign', 'rolled-back']) {
  test(`real three-family serving rejects ${kind} generation before recovery or cleanup`, async t => {
    const fixture = await runtimeCoreFixture()
    t.teardown(() => removeBlindBoundaryScratch(fixture.directory))
    const runtime = await assemble(fixture)
    await runtime.close()
    const roots = runtimeRoots(fixture)
    const control = path.join(roots[0], 'control')
    if (kind === 'missing') {
      for (const name of await fs.readdir(control)) if (name.startsWith('blind-store-generation')) await fs.unlink(path.join(control, name))
    } else if (kind === 'malformed') {
      const record = (await fs.readdir(control)).find(name => name.includes('generation-record-'))
      await fs.writeFile(path.join(control, record), '{invalid')
    } else if (kind === 'foreign') {
      const other = await runtimeCoreFixture()
      t.teardown(() => removeBlindBoundaryScratch(other.directory))
      const second = await assemble(other)
      await second.close()
      const otherControl = path.join(runtimeRoots(other)[0], 'control')
      for (const name of await fs.readdir(control)) if (name.startsWith('blind-store-generation')) await fs.unlink(path.join(control, name))
      for (const name of await fs.readdir(otherControl)) if (name.startsWith('blind-store-generation')) await fs.copyFile(path.join(otherControl, name), path.join(control, name))
    } else {
      await fs.writeFile(path.join(roots[1], 'control', 'wal.v2'), b4a.alloc(0))
    }
    await addRecoveryCandidates(roots)
    const before = await rootsInventory(roots)
    await t.exception(assemble(fixture), /generation|rolled back|another installation/)
    recordInventory(t, kind, before, await rootsInventory(roots))
    for (const root of roots) {
      const session = new BlindStoreSession({ root, validationOnly: true, allowUnmanifestedWal: true, allowPristineBootstrap: true })
      await session.open()
      await session.close()
      t.pass('failed startup releases root and writer ownership')
    }
  })
}

async function plainFixture (t) {
  const directory = await createBlindBoundaryScratch('gstart-')
  t.teardown(() => removeBlindBoundaryScratch(directory))
  const stores = []
  for (const role of ['cell', 'inbox', 'core']) {
    const root = path.join(directory, role)
    await fs.mkdir(root, { mode: 0o700 })
    const engineOptions = {
      root,
      relayPublicKey: b4a.alloc(32, 1),
      storeId: b4a.alloc(32, 2),
      ownerFenceTokenHash: b4a.alloc(32, 3),
      durabilityContinuityHash: b4a.alloc(32, 4),
      cursorKey: b4a.alloc(32, 5),
      nowEpoch: () => 20,
      nowUnixMillis: () => 20n * 21600000n,
      autoClock: false
    }
    stores.push({ role, root, engineOptions })
  }
  const options = { stores, manifestKey: KEY, installationIdentity: ID, readerMode: BLIND_STORE_READER_MODE.BLIND_ONLY, allowFreshGenesis: true }
  return { directory, stores, options }
}

async function openPlain (options) {
  const startup = await prepareBlindGenerationStartup(options)
  const opened = []
  try {
    for (const store of options.stores) {
      const engine = new engines[store.role]({ ...store.engineOptions, generationStartupHandoff: startup.handoffs.get(store.role) })
      await engine.open()
      opened.push(engine)
    }
    return { startup, opened, async close () { for (const engine of [...opened].reverse()) await engine.close(); await startup.close() } }
  } catch (error) {
    for (const engine of opened) await engine.close()
    await startup.close()
    throw error
  }
}

test('fresh three-root ownership is mutation-free until validation succeeds and remains singular after transfer', async t => {
  const fixture = await plainFixture(t)
  const before = await rootsInventory(fixture.stores.map(store => store.root))
  await t.exception(prepareBlindGenerationStartup({
    ...fixture.options,
    faultInjector (point) {
      if (point === 'generation-startup:after-inspection') throw new Error('reject final validation')
    }
  }), /reject final validation/)
  recordInventory(t, 'fresh rejected', before, await rootsInventory(fixture.stores.map(store => store.root)))
  const state = await openPlain(fixture.options)
  t.is(state.opened.length, 3)
  for (const store of fixture.stores) {
    const competitor = new BlindTransactionStore(store.engineOptions)
    await t.exception(competitor.open(() => {}), /active writer/)
    await competitor.close()
  }
  await state.close()
  const restarted = await openPlain(fixture.options)
  t.alike(restarted.opened.map(engine => engine.transactionStore.walSequence), [1n, 1n, 0n])
  await restarted.close()
})

test('partial root ownership failure never mutates an earlier pristine family', async t => {
  const fixture = await plainFixture(t)
  const held = new BlindStoreSession({ root: fixture.stores[1].root, validationOnly: true, allowPristineBootstrap: true })
  await held.open()
  const before = await rootsInventory(fixture.stores.map(store => store.root))
  await t.exception(prepareBlindGenerationStartup(fixture.options), /StoreSession|startup owner/)
  recordInventory(t, 'partial acquisition', before, await rootsInventory(fixture.stores.map(store => store.root)))
  await held.close()
  const state = await openPlain(fixture.options)
  await state.close()
  t.pass('retry acquires every released lease')
})

for (const drift of ['generation', 'wal', 'segment']) {
  test(`last validation catches ${drift} drift before mutable recovery`, async t => {
    const fixture = await plainFixture(t)
    const initial = await openPlain(fixture.options)
    await initial.close()
    let changed
    await t.exception(prepareBlindGenerationStartup({
      ...fixture.options,
      async faultInjector (point) {
        if (point !== 'generation-startup:after-inspection') return
        const control = path.join(fixture.stores[0].root, 'control')
        if (drift === 'generation') {
          const record = (await fs.readdir(control)).find(name => name.includes('generation-record-'))
          await fs.appendFile(path.join(control, record), ' ')
        } else if (drift === 'wal') await fs.appendFile(path.join(control, 'wal.v2'), b4a.alloc(7))
        else await fs.writeFile(path.join(control, 'wal-0000000000000001-0000000000000001.v2'), 'bad', { mode: 0o600 })
        changed = await rootsInventory(fixture.stores.map(store => store.root))
      }
    }), /changed/)
    recordInventory(t, drift + ' drift', changed, await rootsInventory(fixture.stores.map(store => store.root)))
  })
}

test('semantic recovery rejects a complete unknown CORE frame without touching CELL torn tail or staging', async t => {
  const fixture = await plainFixture(t)
  const initial = await openPlain(fixture.options)
  await initial.close()
  const writer = new BlindTransactionStore(fixture.stores[2].engineOptions)
  await writer.open(() => {})
  await writer.append({ type: 240, virtualBucket: 0, transactionId: b4a.alloc(32, 7), payload: b4a.from('not a Core operation') })
  await writer.close()
  await addRecoveryCandidates(fixture.stores.map(store => store.root))
  const before = await rootsInventory(fixture.stores.map(store => store.root))
  await t.exception(prepareBlindGenerationStartup(fixture.options), /unknown Core WAL/)
  recordInventory(t, 'semantic rejection', before, await rootsInventory(fixture.stores.map(store => store.root)))
})

test('forged startup handoff cannot reach control or WAL creation', async t => {
  const fixture = await plainFixture(t)
  const store = fixture.stores[0]
  const writer = new BlindTransactionStore({ ...store.engineOptions, generationStartupHandoff: { root: store.root } })
  await t.exception(writer.open(() => {}), /invalid or expired/)
  t.alike(await fs.readdir(store.root), [])
  await writer.close()
})

test('native root-directory ownership survives process contention and releases on SIGKILL', async t => {
  const fixture = await plainFixture(t)
  const root = fixture.stores[0].root
  const child = spawn(process.execPath, [new URL('./generation-startup-worker.mjs', import.meta.url).pathname, root], { stdio: ['ignore', 'pipe', 'pipe', 'ipc'] })
  t.teardown(() => child.kill('SIGKILL'))
  const [message] = await once(child, 'message')
  t.is(message, 'locked')
  const before = await inventory(root)
  const competitor = new BlindStoreSession({ root, validationOnly: true, allowPristineBootstrap: true })
  await t.exception(competitor.open(), /startup owner/)
  await competitor.close()
  child.kill('SIGKILL')
  const [code, signal] = await once(child, 'exit')
  t.is(signal, 'SIGKILL')
  t.is(code, null)
  t.alike(await inventory(root), before)
  const session = new BlindStoreSession({ root, validationOnly: true, allowPristineBootstrap: true })
  await session.open()
  const lease = await acquireBlindStoreSessionTransactionLease(session.lockContext(), root)
  lease.release()
  await session.close()
  t.pass('kernel releases real directory ownership after process death')
})

for (const phase of ['before-record-publication', 'after-record-temp-partial', 'before-record-file-sync', 'after-record-temp-sync']) {
  test(`fresh first-floor interruption at ${phase} resumes with no lost root ownership`, async t => {
    const fixture = await plainFixture(t)
    await t.exception(prepareBlindGenerationStartup({
      ...fixture.options,
      faultInjector (point, context) {
        if (point === phase && context.sequence === 0) throw new Error('interrupted first floor')
      }
    }), /interrupted first floor/)
    const state = await openPlain(fixture.options)
    t.is(state.opened.length, 3)
    t.is(state.startup.floor.firstBlindOnlyWriteAcknowledged, false)
    await state.close()
  })
}

test('a fresh sealed WAL substitution fails at the handoff before recovery', async t => {
  const fixture = await plainFixture(t)
  const state = await prepareBlindGenerationStartup(fixture.options)
  const store = fixture.stores[2]
  await fs.writeFile(path.join(store.root, 'control', 'wal-0000000000000001-0000000000000001.v2'), 'unvalidated', { mode: 0o600 })
  const before = await rootsInventory(fixture.stores.map(item => item.root))
  const engine = new BlindCoreStorageEngine({ ...store.engineOptions, generationStartupHandoff: state.handoffs.get('core') })
  await t.exception(engine.open(), /WAL appeared/)
  recordInventory(t, 'fresh sealed substitution', before, await rootsInventory(fixture.stores.map(item => item.root)))
  await state.close()
})

test('bounded semantic replay rejects excess frames without truncating recovery tails', async t => {
  const fixture = await plainFixture(t)
  const initial = await openPlain(fixture.options)
  const inbox = initial.opened[1]
  await inbox.advanceEpochFloor(21)
  await initial.close()
  await addRecoveryCandidates(fixture.stores.map(store => store.root))
  const before = await rootsInventory(fixture.stores.map(store => store.root))
  await t.exception(prepareBlindGenerationStartup({ ...fixture.options, limits: { maximumWalFrames: 1 } }), /frame count exceeds/)
  recordInventory(t, 'bounded replay', before, await rootsInventory(fixture.stores.map(store => store.root)))
})

test('failed read-handle close rejects validation and releases every root', async t => {
  const fixture = await plainFixture(t)
  const initial = await openPlain(fixture.options)
  await initial.close()
  const roots = fixture.stores.map(store => store.root)
  const before = await rootsInventory(roots)
  const open = fs.open
  let injected = false
  fs.open = async (...args) => {
    const handle = await open(...args)
    if (!injected && args[0] === path.join(roots[0], 'control', 'wal.v2')) {
      injected = true
      const close = handle.close.bind(handle)
      handle.close = async () => { await close(); throw new Error('read close failed') }
    }
    return handle
  }
  try { await t.exception(prepareBlindGenerationStartup(fixture.options), /read close failed/) } finally { fs.open = open }
  recordInventory(t, 'read close failure', before, await rootsInventory(roots))
  const restarted = await openPlain(fixture.options)
  await restarted.close()
  t.pass('all ownership released after reader-close failure')
})

test('repeated rejected inspection has bounded descriptors and exact persistent inventory', async t => {
  const fixture = await plainFixture(t)
  const initial = await openPlain(fixture.options)
  await initial.close()
  const roots = fixture.stores.map(store => store.root)
  const before = await rootsInventory(roots)
  const fdDirectory = process.platform === 'linux' ? '/proc/self/fd' : '/dev/fd'
  const beforeFd = (await fs.readdir(fdDirectory)).length
  const open = fs.open
  let active = 0
  let peak = 0
  fs.open = async (...args) => {
    const handle = await open(...args)
    active++
    peak = Math.max(peak, active)
    const close = handle.close.bind(handle)
    handle.close = async () => { try { await close() } finally { active-- } }
    return handle
  }
  try {
    for (let index = 0; index < 20; index++) {
      await t.exception(prepareBlindGenerationStartup({
        ...fixture.options,
        faultInjector (point) {
          if (point === 'generation-startup:after-inspection') throw new Error('bounded validation stop')
        }
      }), /bounded validation stop/)
    }
  } finally { fs.open = open }
  const afterFd = (await fs.readdir(fdDirectory)).length
  t.is(active, 0)
  t.ok(peak <= 7, 'three root/writer lock pairs and one single-file reader')
  t.is(afterFd, beforeFd)
  t.comment(JSON.stringify({ iterations: 20, beforeFd, afterFd, peak, active }))
  recordInventory(t, 'bounded repeated inspection', before, await rootsInventory(roots))
})

test('missing head repairs only after valid owned replay and clock reconciliation uses the recovered head', async t => {
  const fixture = await plainFixture(t)
  const initial = await openPlain(fixture.options)
  await initial.close()
  const head = path.join(fixture.stores[0].root, 'control', 'blind-store-generation-head-v2.json')
  await fs.unlink(head)
  const options = {
    ...fixture.options,
    stores: fixture.stores.map(store => ({
      ...store,
      engineOptions: { ...store.engineOptions, nowUnixMillis: () => 21n * 21600000n }
    }))
  }
  const state = await openPlain(options)
  t.ok(state.startup.inspection.requiredRecoveryActions.some(action => action.kind === 'repair-head'))
  t.is(state.opened[0].transactionStore.walSequence, 2n, 'CELL recovery appends its clock reconciliation after validation')
  t.ok((await fs.stat(head)).size > 0)
  await state.close()
  const restarted = await openPlain(options)
  t.is(restarted.opened[0].transactionStore.walSequence, 2n, 'restart does not append duplicate reconciliation')
  await restarted.close()
})

test('preparatory root ownership cannot bypass writer acquisition through the ordinary session API', async t => {
  const fixture = await plainFixture(t)
  const store = fixture.stores[0]
  await fs.mkdir(path.join(store.root, 'control'), { mode: 0o700 })
  const session = new BlindStoreSession({ root: store.root, validationOnly: true, allowPristineBootstrap: true })
  await session.open()
  t.is(session.lockContext().ownsWriterLock, false)
  const before = await inventory(store.root)
  const writer = new BlindTransactionStore({ ...store.engineOptions, storeSessionContext: session.lockContext() })
  await t.exception(writer.open(() => {}), /has not acquired its writer inode/)
  t.alike(await inventory(store.root), before)
  await writer.close()
  await session.close()
})
