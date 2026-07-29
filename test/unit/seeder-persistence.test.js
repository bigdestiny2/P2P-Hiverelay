/**
 * Seeder bare-core persistence (v0.18.x).
 *
 * /seed-core pins (catalog bees + any plain Hypercore) must survive a relay
 * restart. These pin the contract: seedCore persists, unseedCore removes,
 * stop() (teardown) does NOT wipe the list, and a fresh Seeder.start()
 * re-seeds exactly what was pinned. The last two are the load-bearing ones —
 * a persisting unseed in stop() would empty the file on every clean shutdown.
 */

import test from 'brittle'
import b4a from 'b4a'
import { mkdtemp, readFile, rm, writeFile } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { Seeder } from 'p2p-hiverelay/core/relay-node/seeder.js'

const K1 = 'a'.repeat(64)
const K2 = 'b'.repeat(64)
const B1 = 1024 * 1024
const B2 = 2 * 1024 * 1024

function fakeCore (keyHex) {
  const key = b4a.from(keyHex, 'hex')
  const discoveryKey = b4a.alloc(32)
  discoveryKey[0] = key[0] // distinct per key; content irrelevant to the fakes
  return {
    key,
    discoveryKey,
    fork: 0,
    length: 0,
    byteLength: 0,
    async ready () {},
    async update () { return true },
    snapshot () {
      return {
        fork: this.fork,
        length: this.length,
        byteLength: this.byteLength,
        async ready () {},
        download: (...args) => this.download(...args),
        async close () {}
      }
    },
    download () { return { async done () {}, destroy () {} } },
    on () {},
    removeListener () {},
    async close () {}
  }
}

function fakeAdmission () {
  const records = new Map()
  return {
    records,
    recoveryReady: [],
    reserve (key, bytes, opts = {}) {
      const previous = records.get(key) || null
      if (previous && previous.state !== 'unknown-recovery') return { allowed: false, reason: 'already-reserved' }
      if (previous && opts.authoritativeSizeBytes == null) return { allowed: false, reason: 'storage-commitment-unknown' }
      const token = { allowed: true, key, bytes, state: 'reserved', previous }
      records.set(key, token)
      return token
    },
    owns (token) {
      return records.get(token.key) === token && token.state === 'reserved'
    },
    commit (token) {
      if (!this.owns(token)) return false
      token.state = 'committed'
      return true
    },
    rollback (token) {
      if (!this.owns(token)) return false
      if (token.previous) records.set(token.key, token.previous)
      else records.delete(token.key)
      token.state = 'rolled-back'
      return true
    },
    release (key) { return records.delete(key) },
    adoptRecovery (key, bytes) {
      const record = { key, bytes, state: bytes === null ? 'unknown-recovery' : 'committed' }
      records.set(key, record)
      return record
    },
    markRecoveryReady (source) { this.recoveryReady.push(source) },
    admission () { return { allowed: true } },
    failClosed () {}
  }
}

function fakeDeps () {
  const requested = []
  const store = {
    get ({ key }) {
      const hex = b4a.toString(key, 'hex')
      requested.push(hex)
      return fakeCore(hex)
    }
  }
  const swarm = { join () {}, async leave () {} }
  return { store, swarm, requested }
}

async function readCores (path) {
  try { return JSON.parse(await readFile(path, 'utf8')).cores } catch { return null }
}

test('seedCore persists; unseedCore removes', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'seeder-'))
  const path = join(dir, 'seeded-cores.json')
  const { store, swarm } = fakeDeps()
  const admission = fakeAdmission()
  const s = new Seeder(store, swarm, { storagePath: path, storageAdmission: admission })
  await s.start()

  await s.seedCore(K1, { maxStorageBytes: B1 })
  await s.seedCore(K2, { maxStorageBytes: B2 })
  await s._persistTail // drain the serialized writer
  t.alike(await readCores(path), [
    { key: K1, maxStorageBytes: B1, state: 'bounded' },
    { key: K2, maxStorageBytes: B2, state: 'bounded' }
  ], 'both keys and their bounds persisted')

  await s.unseedCore(K1)
  await s._persistTail
  t.alike(await readCores(path), [{ key: K2, maxStorageBytes: B2, state: 'bounded' }], 'unseed removed K1 from the persisted set')
  t.absent(admission.records.get(`core:${K1}`), 'durable unseed releases the commitment')

  await s.stop()
})

test('cross-key seed transactions persist only the committed inventory under opposite outcomes', async (t) => {
  for (const failure of ['second', 'first']) {
    const dir = await mkdtemp(join(tmpdir(), `seeder-cross-key-${failure}-`))
    const path = join(dir, 'seeded-cores.json')
    t.teardown(() => rm(dir, { recursive: true, force: true }))
    const { store, swarm, requested } = fakeDeps()
    const admission = fakeAdmission()
    const seeder = new Seeder(store, swarm, { storagePath: path, storageAdmission: admission })
    await seeder.start()

    const originalWrite = seeder._writePersisted.bind(seeder)
    let writeCount = 0
    let releaseFirst = null
    let firstWriteStarted = null
    const firstWriteGate = new Promise(resolve => { releaseFirst = resolve })
    const firstStarted = new Promise(resolve => { firstWriteStarted = resolve })
    seeder._writePersisted = async () => {
      writeCount++
      if (writeCount === 1) {
        firstWriteStarted()
        await firstWriteGate
      }
      if ((failure === 'first' && writeCount === 1) ||
          (failure === 'second' && writeCount === 2)) {
        throw new Error(`injected ${failure} persistence failure`)
      }
      return originalWrite()
    }

    const first = seeder.seedCore(K1, { maxStorageBytes: B1 })
    await firstStarted
    const second = seeder.seedCore(K2, { maxStorageBytes: B2 })
    await new Promise(resolve => setTimeout(resolve, 0))
    t.alike(requested, [K1], `${failure}: second key cannot enter the inventory transaction early`)
    releaseFirst()
    const results = await Promise.allSettled([first, second])
    const committedKey = failure === 'second' ? K1 : K2
    const rejectedIndex = failure === 'second' ? 1 : 0
    t.is(results[rejectedIndex].status, 'rejected', `${failure}: injected transaction rejects`)
    t.alike([...seeder.cores.keys()], [committedKey], `${failure}: live map equals committed outcome`)
    t.alike((await readCores(path)).map(row => row.key), [committedKey], `${failure}: durable file excludes rejected key`)
    t.alike([...admission.records.keys()], [`core:${committedKey}`], `${failure}: authority equals durable inventory`)

    await seeder.stop()
    const restoredDeps = fakeDeps()
    const restored = new Seeder(restoredDeps.store, restoredDeps.swarm, {
      storagePath: path,
      storageAdmission: fakeAdmission()
    })
    await restored.start()
    t.alike([...restored.cores.keys()], [committedKey], `${failure}: restart load equals durable inventory`)
    await restored.stop()
  }
})

test('bounded-download replacement and release retain failed dependency owners for retry', async (t) => {
  const events = []
  let rejectOldRange = true
  const oldRange = {
    destroy () {
      events.push('old-range-destroy')
      if (rejectOldRange) throw new Error('injected old range failure')
    }
  }
  const oldSnapshot = { async close () { events.push('old-snapshot-close') } }
  const nextRange = { done: async () => {}, destroy () { events.push('next-range-destroy') } }
  const nextSnapshot = {
    fork: 0,
    length: 1,
    byteLength: 10,
    download () { return nextRange },
    async close () { events.push('next-snapshot-close') }
  }
  const seeder = new Seeder({}, { async leave () { events.push('swarm-leave') } })
  const entry = {
    publicKeyHex: K1,
    retiring: false,
    retiringDownloads: [],
    range: oldRange,
    rangeSnapshot: oldSnapshot
  }
  const proof = { coreSnapshot: nextSnapshot, fork: 0, length: 1, byteLength: 10 }

  await t.exception(seeder._installBoundedDownload(entry, proof), /injected old range failure/)
  t.is(entry.range, nextRange, 'new proved owner remains installed')
  t.is(entry.retiringDownloads[0]?.range, oldRange, 'failed predecessor remains reachable')
  t.absent(events.includes('old-snapshot-close'), 'snapshot parent remains while its range child failed')
  rejectOldRange = false
  await seeder._drainRetiringDownloads(entry)
  t.alike(events.slice(-2), ['old-range-destroy', 'old-snapshot-close'])
  t.is(entry.retiringDownloads.length, 0)

  let rejectCurrentRange = true
  let coreCloses = 0
  entry.range = {
    destroy () {
      events.push('current-range-destroy')
      if (rejectCurrentRange) throw new Error('injected current range failure')
    }
  }
  entry.rangeSnapshot = { async close () { events.push('current-snapshot-close') } }
  entry.interval = null
  entry.refreshing = null
  entry.downloadListenerAttached = false
  entry.uploadListenerAttached = false
  entry.appendListenerAttached = false
  entry.topic = Buffer.alloc(32)
  entry.core = { async close () { coreCloses++ } }
  await t.exception(seeder._releaseEntry(entry), /teardown did not settle/)
  t.absent(events.includes('current-snapshot-close'), 'release stops before downstream snapshot close')
  t.absent(events.includes('swarm-leave'), 'release stops before leaving swarm')
  t.is(coreCloses, 0)
  rejectCurrentRange = false
  await seeder._releaseEntry(entry)
  t.ok(events.indexOf('current-range-destroy') < events.indexOf('current-snapshot-close'))
  t.ok(events.indexOf('current-snapshot-close') < events.indexOf('swarm-leave'))
  t.is(coreCloses, 1)
})

test('authority-owned announce is serialized against stop and settles tentative session', async (t) => {
  const admission = fakeAdmission()
  const handoff = {}
  admission.validateOwnedHandoff = candidate => candidate === handoff
  admission.runMutation = run => run()
  let releaseSession = null
  let sessionReadyStarted = null
  const sessionGate = new Promise(resolve => { releaseSession = resolve })
  const sessionStarted = new Promise(resolve => { sessionReadyStarted = resolve })
  let sessionCloses = 0
  let joins = 0
  let leaves = 0
  const session = {
    discoveryKey: Buffer.alloc(32, 4),
    async ready () { sessionReadyStarted(); await sessionGate },
    async close () { sessionCloses++ }
  }
  const core = {
    key: Buffer.alloc(32, 5),
    discoveryKey: session.discoveryKey,
    writable: true,
    length: 0,
    async ready () {},
    session () { return session }
  }
  const swarm = {
    join () { joins++ },
    async flush () {},
    async leave () { leaves++ }
  }
  const seeder = new Seeder({}, swarm, { storageAdmission: admission })
  await seeder.start()

  const announcing = seeder.announceAuthorityOwnedCore(core, handoff)
  await sessionStarted
  const stopping = seeder.stop()
  releaseSession()
  const [announceResult, stopResult] = await Promise.allSettled([announcing, stopping])
  t.is(announceResult.reason?.code, 'SEEDER_STOPPING')
  t.is(stopResult.status, 'fulfilled')
  t.is(sessionCloses, 1, 'tentative exact session settles once')
  t.is(joins, 0, 'stop intent prevents a late announcement')
  t.is(leaves, 0)
  t.is(seeder._ownedAnnouncements.size, 0)
})

test('inventory-only recovery adopts debt without opening or announcing cores', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'seeder-inventory-only-'))
  const path = join(dir, 'seeded-cores.json')
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  await writeFile(path, JSON.stringify({
    schemaVersion: 3,
    cores: [
      { key: K1, maxStorageBytes: B1, state: 'bounded' },
      { key: K2, maxStorageBytes: null, state: 'unknown-recovery' }
    ]
  }))

  let gets = 0
  let joins = 0
  const admission = fakeAdmission()
  const seeder = new Seeder({
    get () {
      gets++
      throw new Error('inventory-only recovery must not open a core')
    }
  }, {
    join () {
      joins++
      throw new Error('inventory-only recovery must not announce a core')
    }
  }, { storagePath: path, storageAdmission: admission })

  t.ok(await seeder.recoverInventoryOnly())
  t.is(gets, 0, 'no core sessions opened')
  t.is(joins, 0, 'no swarm topics joined')
  t.is(seeder.running, false, 'no serving or timer lifecycle started')
  t.is(seeder.cores.size, 0, 'no live listeners or ranges attached')
  t.is(admission.records.get(`core:${K1}`).bytes, B1, 'bounded debt adopted')
  t.is(admission.records.get(`core:${K2}`).state, 'unknown-recovery', 'legacy unknown debt adopted')
  t.alike(admission.recoveryReady, ['cores'], 'seal follows the complete scan')
})

test('inventory-only recovery keeps the seal pending on a corrupt tail', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'seeder-inventory-corrupt-'))
  const path = join(dir, 'seeded-cores.json')
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  await writeFile(path, JSON.stringify({
    schemaVersion: 3,
    cores: [
      { key: K1, maxStorageBytes: B1, state: 'bounded' },
      { key: K1, maxStorageBytes: B1, state: 'bounded' }
    ]
  }))

  const admission = fakeAdmission()
  const seeder = new Seeder({
    get () { throw new Error('must not open a core') }
  }, {
    join () { throw new Error('must not join a topic') }
  }, { storagePath: path, storageAdmission: admission })

  t.is(await seeder.recoverInventoryOnly(), false)
  t.is(admission.records.size, 0, 'validated scan adopts no partial prefix')
  t.alike(admission.recoveryReady, [], 'corrupt inventory leaves the seal pending')
  t.is(seeder.cores.size, 0)
})

test('unseedCore retains authority until live teardown settles and retries failed close', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'seeder-release-last-'))
  const path = join(dir, 'seeded-cores.json')
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const core = fakeCore(K1)
  const events = []
  let closeStartedResolve
  let closeResolve
  const closeStarted = new Promise(resolve => { closeStartedResolve = resolve })
  const closeGate = new Promise(resolve => { closeResolve = resolve })
  core.close = async () => {
    events.push('core-close-start')
    closeStartedResolve()
    await closeGate
    events.push('core-close-done')
  }
  const admission = fakeAdmission()
  const originalRelease = admission.release.bind(admission)
  admission.release = key => {
    events.push('authority-release')
    return originalRelease(key)
  }
  const swarm = {
    join () {},
    async leave () { events.push('swarm-leave') }
  }
  const seeder = new Seeder({ get: () => core }, swarm, { storagePath: path, storageAdmission: admission })
  await seeder.start()
  await seeder.seedCore(K1, { maxStorageBytes: B1 })

  const removing = seeder.unseedCore(K1)
  await closeStarted
  t.ok(admission.records.has(`core:${K1}`), 'commitment remains while core.close is pending')
  t.alike(await readCores(path), [], 'durable retirement intent precedes live teardown')
  closeResolve()
  await removing
  t.absent(admission.records.has(`core:${K1}`), 'commitment releases only after close settles')
  t.alike(events, ['swarm-leave', 'core-close-start', 'core-close-done', 'authority-release'])

  // A failed close keeps both the debt and a retryable retiring entry.
  const core2 = fakeCore(K2)
  let failClose = true
  core2.close = async () => {
    events.push('core2-close')
    if (failClose) throw new Error('injected close failure')
  }
  seeder.store = { get: () => core2 }
  await seeder.seedCore(K2, { maxStorageBytes: B2 })
  await t.exception(seeder.unseedCore(K2), /teardown did not settle/)
  t.ok(admission.records.has(`core:${K2}`), 'failed teardown retains commitment')
  t.ok(seeder._retiringCores.has(K2), 'failed teardown remains retryable')
  failClose = false
  await seeder.unseedCore(K2)
  t.absent(admission.records.has(`core:${K2}`))
  t.absent(seeder._retiringCores.has(K2))
  await seeder.stop()
})

test('attached core listener without removal authority retains retirement debt', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'seeder-listener-retirement-'))
  const path = join(dir, 'seeded-cores.json')
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const core = fakeCore(K1)
  core.on = () => core // production EventEmitter contract: attachment succeeded
  core.removeListener = undefined
  const admission = fakeAdmission()
  const seeder = new Seeder({ get: () => core }, { join () {}, async leave () {} }, {
    storagePath: path,
    storageAdmission: admission
  })
  await seeder.start()
  await seeder.seedCore(K1, { maxStorageBytes: B1 })
  await t.exception(seeder.unseedCore(K1), /teardown did not settle/)
  t.ok(admission.records.has(`core:${K1}`))
  t.ok(seeder._retiringCores.has(K1))

  core.removeListener = () => {}
  await seeder.unseedCore(K1)
  t.absent(admission.records.has(`core:${K1}`))
  await seeder.stop()
})

test('seeded-core inventory proves target plus tmp at maximum cardinality', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'seeder-cardinality-'))
  const path = join(dir, 'seeded-cores.json')
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const seeder = new Seeder({}, {}, { storagePath: path })
  for (let i = 0; i < 4096; i++) {
    const key = i.toString(16).padStart(64, '0')
    seeder.cores.set(key, {
      publicKeyHex: key,
      maxStorageBytes: B1
    })
  }
  await seeder._writePersisted()
  const raw = await readFile(path, 'utf8')
  t.is(JSON.parse(raw).cores.length, 4096)
  t.ok(2 * b4a.byteLength(raw) <= 4096 * 64 * 1024,
    'simultaneous target and tmp fit aggregate per-core metadata slots')

  const overflowKey = (4096).toString(16).padStart(64, '0')
  seeder.cores.set(overflowKey, { publicKeyHex: overflowKey, maxStorageBytes: B1 })
  await t.exception(seeder._writePersisted(), /CARDINALITY_EXCEEDED/)
})

test('stop() does NOT wipe the persisted list (restart-safety guard)', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'seeder-'))
  const path = join(dir, 'seeded-cores.json')
  const { store, swarm } = fakeDeps()
  const s = new Seeder(store, swarm, { storagePath: path, storageAdmission: fakeAdmission() })
  await s.start()
  await s.seedCore(K1, { maxStorageBytes: B1 })
  await s.seedCore(K2, { maxStorageBytes: B2 })
  await s._persistTail

  await s.stop() // teardown — must release resources but keep the list
  t.is(s.cores.size, 0, 'in-memory cores cleared on stop')
  t.alike(await readCores(path), [
    { key: K1, maxStorageBytes: B1, state: 'bounded' },
    { key: K2, maxStorageBytes: B2, state: 'bounded' }
  ], 'persisted list survives a clean shutdown')
})

test('start() re-seeds the persisted cores', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'seeder-'))
  const path = join(dir, 'seeded-cores.json')

  // First run: pin two, then shut down.
  const a = fakeDeps()
  const s1 = new Seeder(a.store, a.swarm, { storagePath: path, storageAdmission: fakeAdmission() })
  await s1.start()
  await s1.seedCore(K1, { maxStorageBytes: B1 })
  await s1.seedCore(K2, { maxStorageBytes: B2 })
  await s1._persistTail
  await s1.stop()

  // Restart: a fresh Seeder over the same storagePath must re-seed both.
  const b = fakeDeps()
  const admission = fakeAdmission()
  const s2 = new Seeder(b.store, b.swarm, { storagePath: path, storageAdmission: admission })
  await s2.start()
  t.alike(b.requested.sort(), [K1, K2].sort(), 'store.get called for each persisted key on start')
  t.is(s2.cores.size, 2, 'both cores re-seeded into memory')
  // Re-seeding did not corrupt the persisted set.
  await s2._persistTail
  t.alike(await readCores(path), [
    { key: K1, maxStorageBytes: B1, state: 'bounded' },
    { key: K2, maxStorageBytes: B2, state: 'bounded' }
  ])
  t.is(admission.records.get(`core:${K1}`).bytes, B1)
  t.is(admission.records.get(`core:${K2}`).bytes, B2)
  t.alike(admission.recoveryReady, ['cores'], 'core inventory independently seals recovery')
  await s2.stop()
})

test('throwing reseed observers cannot truncate core recovery inventory', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'seeder-observer-'))
  const path = join(dir, 'seeded-cores.json')
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  await writeFile(path, JSON.stringify({
    schemaVersion: 3,
    cores: [
      { key: K1, maxStorageBytes: B1, state: 'bounded' },
      { key: K2, maxStorageBytes: B2, state: 'bounded' }
    ]
  }))
  const admission = fakeAdmission()
  const store = {
    get ({ key }) {
      const hex = b4a.toString(key, 'hex')
      const core = fakeCore(hex)
      if (hex === K1) core.ready = async () => { throw new Error('injected open failure') }
      return core
    }
  }
  const swarm = { join () {}, async leave () {} }
  const seeder = new Seeder(store, swarm, { storagePath: path, storageAdmission: admission })
  seeder.on('reseed-error', () => { throw new Error('observer must not abort inventory') })
  await seeder.start()
  t.ok(seeder.cores.has(K2), 'later durable rows are still scanned and restored')
  t.ok(admission.records.has(`core:${K1}`), 'failed row debt remains adopted')
  t.ok(admission.records.has(`core:${K2}`), 'later row debt is adopted')
  t.alike(admission.recoveryReady, ['cores'], 'seal is emitted only after the complete scan')
  await seeder.stop()
})

test('schema v1 cores restore serve-only as unknown recovery debt', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'seeder-'))
  const path = join(dir, 'seeded-cores.json')
  await writeFile(path, JSON.stringify({ schemaVersion: 1, cores: [K1] }))
  const { store, swarm } = fakeDeps()
  const admission = fakeAdmission()
  const s = new Seeder(store, swarm, { storagePath: path, storageAdmission: admission })

  await s.start()

  const entry = s.cores.get(K1)
  t.ok(entry, 'legacy core is reopened for serving')
  t.is(entry.recoveryOnly, true, 'legacy core does not pull new blocks')
  t.is(entry.maxStorageBytes, null)
  t.is(admission.records.get(`core:${K1}`).state, 'unknown-recovery')

  const rebound = await s.seedCore(K1, { maxStorageBytes: B1 })
  t.is(rebound.recoveryOnly, false, 'authoritatively measured re-pin can resume bounded pulls')
  t.is(rebound.maxStorageBytes, B1)
  t.is(admission.records.get(`core:${K1}`).state, 'committed')
  t.alike(JSON.parse(await readFile(path, 'utf8')), {
    schemaVersion: 3,
    cores: [{ key: K1, maxStorageBytes: B1, state: 'bounded' }]
  }, 'the rebound is durable before it becomes writable')
  await s.stop()
})

test('legacy core stays serve-only when authoritative sizing fails', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'seeder-'))
  const path = join(dir, 'seeded-cores.json')
  await writeFile(path, JSON.stringify({ schemaVersion: 1, cores: [K1] }))
  const core = fakeCore(K1)
  core.update = async () => { throw new Error('no signed size proof') }
  const admission = fakeAdmission()
  const s = new Seeder({ get: () => core }, { join () {}, async leave () {} }, {
    storagePath: path,
    storageAdmission: admission
  })
  await s.start()

  await t.exception(s.seedCore(K1, { maxStorageBytes: B1 }), /no signed size proof/)
  t.is(s.cores.get(K1).recoveryOnly, true)
  t.is(admission.records.get(`core:${K1}`).state, 'unknown-recovery')
  t.alike(JSON.parse(await readFile(path, 'utf8')), { schemaVersion: 1, cores: [K1] })
  await s.stop()
})

test('v1 unknown recovery survives an unrelated unseed rewrite and restart', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'seeder-v1-rewrite-'))
  const path = join(dir, 'seeded-cores.json')
  await writeFile(path, JSON.stringify({ schemaVersion: 1, cores: [K1, K2] }))

  const firstDeps = fakeDeps()
  const first = new Seeder(firstDeps.store, firstDeps.swarm, { storagePath: path, storageAdmission: fakeAdmission() })
  await first.start()
  await first.unseedCore(K2)
  t.alike(JSON.parse(await readFile(path, 'utf8')), {
    schemaVersion: 3,
    cores: [{ key: K1, maxStorageBytes: null, state: 'unknown-recovery' }]
  })
  await first.stop()

  const secondDeps = fakeDeps()
  const admission = fakeAdmission()
  const second = new Seeder(secondDeps.store, secondDeps.swarm, { storagePath: path, storageAdmission: admission })
  await second.start()
  t.ok(second.cores.get(K1)?.recoveryOnly, 'unknown recovery remains serve-only after rewrite')
  t.is(admission.records.get(`core:${K1}`).state, 'unknown-recovery')
  t.alike(admission.recoveryReady, ['cores'])
  await second.stop()
  await rm(dir, { recursive: true, force: true })
})

test('invalid or duplicate v2 inventory tails hydrate nothing and keep the core seal pending', async (t) => {
  const cases = [
    {
      name: 'invalid bound',
      cores: [{ key: K1, maxStorageBytes: B1 }, { key: K2, maxStorageBytes: 0 }]
    },
    {
      name: 'duplicate key',
      cores: [{ key: K1, maxStorageBytes: B1 }, { key: K1, maxStorageBytes: B2 }]
    },
    {
      name: 'noncanonical key',
      cores: [{ key: K1, maxStorageBytes: B1 }, { key: K2.toUpperCase(), maxStorageBytes: B2 }]
    }
  ]

  for (const fixture of cases) {
    const dir = await mkdtemp(join(tmpdir(), 'seeder-invalid-tail-'))
    const path = join(dir, 'seeded-cores.json')
    await writeFile(path, JSON.stringify({ schemaVersion: 2, cores: fixture.cores }))
    const deps = fakeDeps()
    const admission = fakeAdmission()
    const seeder = new Seeder(deps.store, deps.swarm, { storagePath: path, storageAdmission: admission })
    const errors = []
    seeder.on('recovery-error', event => errors.push(event))
    await seeder.start()
    t.alike(deps.requested, [], fixture.name + ': no valid prefix opened')
    t.is(seeder.cores.size, 0, fixture.name + ': no partial core map')
    t.alike(admission.recoveryReady, [], fixture.name + ': recovery seal remains pending')
    t.is(errors.length, 1, fixture.name + ': failure is observable')
    await seeder.stop()
    await rm(dir, { recursive: true, force: true })
  }
})

test('start() tolerates a missing/corrupt persist file', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'seeder-'))
  const path = join(dir, 'seeded-cores.json')
  const { store, swarm } = fakeDeps()
  const admission = fakeAdmission()
  const s = new Seeder(store, swarm, { storagePath: path, storageAdmission: admission }) // file doesn't exist
  await s.start() // must not throw
  t.is(s.cores.size, 0)
  t.alike(admission.recoveryReady, ['cores'])
  await s.stop()
})

test('no storagePath -> a fresh pin fails closed and rolls back its reservation', async (t) => {
  const { store, swarm } = fakeDeps()
  const admission = fakeAdmission()
  const s = new Seeder(store, swarm, { storageAdmission: admission }) // null storagePath
  await s.start()
  await t.exception(s.seedCore(K1, { maxStorageBytes: B1 }), /persistence unavailable/)
  t.is(s.cores.size, 0)
  t.absent(admission.records.get(`core:${K1}`))
  await s.stop()
})
