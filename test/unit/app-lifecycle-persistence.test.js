import test from 'brittle'
import { tmpdir } from 'os'
import { join } from 'path'
import { randomBytes } from 'crypto'
import { mkdir, rm } from 'fs/promises'
import Hyperdrive from 'hyperdrive'
import { AppRegistry } from 'p2p-hiverelay/core/app-registry.js'
import { AppLifecycle } from 'p2p-hiverelay/core/relay-node/app-lifecycle.js'
import { LifecycleScope } from 'p2p-hiverelay/core/relay-node/lifecycle-scope.js'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import { measureStorageTreeBytes } from '../../packages/core/config/storage-cap.js'

function tmpStorage () {
  return join(tmpdir(), 'hiverelay-lifecycle-persist-' + randomBytes(8).toString('hex'))
}

function testPhysicalEnforcer (storage) {
  let generation = 0
  return {
    schemaVersion: 1,
    async installAbsoluteCeiling (request) {
      return {
        providerId: 'test-provider',
        scopeId: 'test-root',
        leaseId: 'test-lease',
        operationId: request.operationId,
        requestedAt: request.requestedAt,
        rootIdentity: { ...request.storageIdentity },
        hardLimitBytes: request.ceilingAllocatedBytes,
        generation: ++generation
      }
    },
    async inspectAbsoluteCeiling (lease) {
      return {
        schemaVersion: 1,
        active: true,
        exclusive: true,
        providerId: lease.providerId,
        scopeId: lease.scopeId,
        leaseId: lease.leaseId,
        operationId: lease.operationId,
        rootIdentity: { ...lease.rootIdentity },
        usedAllocatedBytes: measureStorageTreeBytes(storage),
        hardLimitBytes: lease.hardLimitBytes,
        generation: lease.generation,
        checkedAt: Math.max(Date.now(), lease.requestedAt)
      }
    }
  }
}

test('AppLifecycle: failed durable unseed retains retry debt after ordered live teardown', async (t) => {
  const appKey = 'a'.repeat(64)
  const registry = new AppRegistry(null)
  let destroyed = 0
  let closed = 0
  let left = 0
  let unregistered = 0

  registry.set(appKey, {
    type: 'app',
    appId: 'durable-delete',
    discoveryKey: Buffer.alloc(32, 1),
    drive: {
      close: async () => { closed++ }
    },
    downloadRanges: [
      { destroy: () => { destroyed++ } }
    ]
  }, { persist: false })
  registry.persistDelete = async () => {
    throw new Error('disk full')
  }

  const lifecycle = new AppLifecycle({
    appRegistry: registry,
    swarm: {
      leave: async () => { left++ }
    },
    distributedDriveBridge: {
      unregisterDrive: () => { unregistered++ }
    }
  })

  await t.exception(
    lifecycle.unseedApp(appKey),
    /disk full/,
    'unseed rejects when the durable delete fails'
  )

  t.ok(registry.has(appKey), 'closed retiring entry is restored in memory for retry')
  t.is(destroyed, 1, 'download ranges settle before durable delete')
  t.is(closed, 1, 'drive settles before durable delete')
  t.is(left, 0, 'swarm topic was not left')
  t.is(unregistered, 1, 'drive bridge settles before durable delete')
  t.ok(lifecycle._retiringDrives.has(appKey), 'retirement owner remains reachable')

  registry.persistDelete = async () => {}
  await lifecycle.unseedApp(appKey)
  t.absent(registry.has(appKey), 'retry completes the durable retirement')
  t.is(destroyed, 1, 'settled range is not destroyed twice')
  t.is(closed, 1, 'settled drive is not closed twice')
  t.absent(lifecycle._retiringDrives.has(appKey))
})

test('AppLifecycle: persistent drive pulls are finite ranges on one proved snapshot', async (t) => {
  const appKey = 'b'.repeat(64)
  const registry = new AppRegistry(null)
  const downloads = []
  let mutationKey = null

  const makeCore = (name, length, byteLength, fork) => ({
    length,
    byteLength,
    fork,
    async update () { return true },
    snapshot () {
      return {
        length,
        byteLength,
        fork,
        async ready () {},
        download (range) {
          downloads.push({ name, range })
          return { destroy () {} }
        },
        async close () {}
      }
    }
  })
  const metaCore = makeCore('meta', 7, 700, 2)
  const blobCore = makeCore('blob', 11, 1100, 3)
  const drive = {
    version: 5,
    closed: false,
    closing: false,
    db: { core: metaCore },
    blobs: { core: blobCore }
  }
  registry.set(appKey, {
    type: 'app',
    maxStorage: 4096,
    discoveryKey: Buffer.alloc(32, 2),
    drive
  }, { persist: false })

  const lifecycle = new AppLifecycle({
    appRegistry: registry,
    storageAdmission: {
      runKeyMutation (key, operation) {
        mutationKey = key
        return operation()
      }
    }
  })
  await lifecycle._registerPersistentDownloads(appKey, drive)

  const entry = registry.get(appKey)
  t.is(mutationKey, `drive:${appKey}`, 'registration serializes on the drive storage key')
  t.alike(downloads, [
    { name: 'meta', range: { start: 0, end: 7 } },
    { name: 'blob', range: { start: 0, end: 11 } }
  ], 'only the proved metadata/blob lengths become persistent wants')
  t.is(entry.downloadRanges.length, 2, 'the finite range owners stay reachable for retirement')
  t.is(entry.downloadSnapshotCores.length, 2, 'the exact snapshot owners stay reachable for retirement')
  t.absent(entry.downloadRegistration, 'the registration settlement barrier is released')
})

test('RelayNode: seedApp rolls back registry when explicit registry persist fails', async (t) => {
  const storage = tmpStorage()
  await mkdir(storage, { recursive: true })
  const node = new RelayNode({
    storage,
    enableAPI: false,
    enableNetworkDiscovery: false,
    enableHolesail: false,
    physicalEnforcer: testPhysicalEnforcer(storage)
  })
  t.teardown(async () => {
    try { await node.stop() } catch (_) {}
    try { await node.store.close() } catch (_) {}
    await rm(storage, { recursive: true, force: true })
  })
  await node.start()

  const writer = new Hyperdrive(node.store.session())
  await writer.ready()
  await writer.put('/persist-fixture.txt', Buffer.from('durable rollback fixture'))
  const appKey = writer.key.toString('hex')
  await writer.close()
  const placeholder = { discoveryKey: null, maxStorage: 1024 * 1024, type: 'app' }
  node.appRegistry.set(appKey, placeholder, { persist: false })
  const previous = node.appRegistry.get(appKey)
  node.storageAdmission.adoptRecovery(`drive:${appKey}`, 1024 * 1024, { kind: 'drive' })
  node.appRegistry.persistEntry = async () => {
    throw new Error('disk full')
  }

  await t.exception(
    node.seedApp(appKey, { maxStorage: 1024 * 1024 }),
    /disk full/,
    'seedApp rejects when the durable registry write fails'
  )

  t.alike(node.appRegistry.get(appKey), previous, 'failed seed restores only the pre-existing key placeholder')
})

test('AppLifecycle: stale live entry cannot fast-path ACK and mixed-case calls share one mutation key', async (t) => {
  const lower = 'a'.repeat(64)
  const upper = lower.toUpperCase()
  const registry = new AppRegistry(null)
  registry.on('change', () => { throw new Error('observer boom') })
  registry.set(upper, {
    type: 'drive',
    appId: 'stale-live',
    discoveryKey: Buffer.alloc(32, 7),
    maxStorage: 1024 * 1024
  }, { persist: false })

  let tail = Promise.resolve()
  let active = 0
  let maxActive = 0
  const mutationKeys = []
  const storageAdmission = {
    fatalReason: null,
    canAcknowledge: () => false,
    runKeyMutation (key, run) {
      mutationKeys.push(key)
      const operation = tail.then(async () => {
        active++
        maxActive = Math.max(maxActive, active)
        try { return await run() } finally { active-- }
      })
      tail = operation.catch(() => {})
      return operation
    }
  }
  const lifecycle = new AppLifecycle({
    appRegistry: registry,
    seeder: {},
    storageAdmission,
    config: { strictSeedingPrivacy: true },
    policyGuard: { check: () => ({ allowed: true }) }
  })

  const results = await Promise.allSettled([
    lifecycle.seedApp(upper, { maxStorage: 1024 * 1024 }),
    lifecycle.seedApp(lower, { maxStorage: 1024 * 1024 })
  ])
  t.ok(results.every(result => result.status === 'rejected'))
  t.ok(results.every(result => result.reason.code === 'STORAGE_RECONCILIATION_REQUIRED'), 'neither retry can ACK without authority')
  t.alike(mutationKeys, [`drive:${lower}`, `drive:${lower}`])
  t.is(maxActive, 1, 'case-colliding calls serialize on the canonical key')
})

test('AppLifecycle: manifest read is local-only on the pinned proof checkout', async (t) => {
  const appKey = '6'.repeat(64)
  const registry = new AppRegistry(null)
  registry.set(appKey, { type: 'app', blind: false }, { persist: false })
  let materializingGets = 0
  let checkoutClosed = 0
  const checkout = {
    version: 1,
    db: { core: { fork: 0, length: 2, byteLength: 10 } },
    async ready () {},
    async get (_path, opts) {
      if (opts?.wait !== false) {
        materializingGets++
        return new Promise(() => {})
      }
      return null
    },
    async close () { checkoutClosed++ }
  }
  const drive = { checkout: () => checkout }
  const proof = {
    driveVersion: 1,
    metaLength: 2,
    blobLength: 1,
    totalBytes: 30,
    metaFork: 0,
    blobFork: 0,
    metaCoreSnapshot: { fork: 0, length: 2, byteLength: 10 },
    blobCoreSnapshot: { fork: 0, length: 1, byteLength: 20 }
  }
  const lifecycle = new AppLifecycle({ appRegistry: registry })
  await lifecycle._indexAppManifest(appKey, drive, proof)
  t.is(materializingGets, 0, 'manifest lookup cannot open a post-timeout network request')
  t.is(checkoutClosed, 1, 'the pinned checkout is always closed')
})

test('AppLifecycle: shutdown destroys exact drive discovery before closing drive', async (t) => {
  const appKey = '7'.repeat(64)
  const events = []
  const handle = { async destroy () { events.push('discovery-destroy') } }
  const registry = new AppRegistry(null)
  registry.set(appKey, {
    discoveryKey: Buffer.alloc(32, 7),
    discoveryHandles: new Set([handle]),
    drive: { async close () { events.push('drive-close') } }
  }, { persist: false })
  const lifecycle = new AppLifecycle({ appRegistry: registry, swarm: {} })

  await lifecycle.unseedApp(appKey, { forget: false })
  t.alike(events, ['discovery-destroy', 'drive-close'])
  t.is(registry.get(appKey).drive, null)
  t.is(registry.get(appKey).discoveryHandles, null)
})

test('AppLifecycle: rejected discovery destroy retains drive owner for retry', async (t) => {
  const appKey = '8'.repeat(64)
  let rejectDestroy = true
  let closes = 0
  const handle = {
    async destroy () {
      if (rejectDestroy) throw new Error('injected discovery failure')
    }
  }
  const registry = new AppRegistry(null)
  registry.set(appKey, {
    discoveryKey: Buffer.alloc(32, 8),
    discoveryHandles: new Set([handle]),
    drive: { async close () { closes++ } }
  }, { persist: false })
  const lifecycle = new AppLifecycle({ appRegistry: registry, swarm: {} })

  await t.exception(lifecycle.unseedApp(appKey, { forget: false }), /injected discovery failure/)
  t.is(closes, 0, 'drive stays open while discovery teardown is unsettled')
  t.ok(registry.get(appKey).discoveryHandles.has(handle), 'exact failed handle retained')

  rejectDestroy = false
  await lifecycle.unseedApp(appKey, { forget: false })
  t.is(closes, 1)
  t.is(registry.get(appKey).drive, null)
})

test('AppLifecycle: auxiliary share-bundle owner destroys session before core and store', async (t) => {
  const events = []
  const lifecycle = new AppLifecycle({ swarm: { removeListener () { events.push('listener-remove') } } })
  const resource = {
    appKey: '9'.repeat(64),
    discovery: { async destroy () { events.push('discovery-destroy') } },
    core: { async close () { events.push('core-close') } },
    auxStore: { async close () { events.push('store-close') } },
    onConnection: () => {},
    auxPath: null
  }
  lifecycle._auxShareBundleResources.add(resource)

  await lifecycle._releaseAuxShareBundleResource(resource)
  t.alike(events, ['listener-remove', 'discovery-destroy', 'core-close', 'store-close'])
  t.is(lifecycle._auxShareBundleResources.size, 0)
})

test('AppLifecycle: concurrent shutdown and forget share one retirement and upgrade durable intent', async (t) => {
  const appKey = 'b'.repeat(64)
  const registry = new AppRegistry(null)
  let releaseClose = null
  let closeStarted = null
  const closeGate = new Promise(resolve => { releaseClose = resolve })
  const started = new Promise(resolve => { closeStarted = resolve })
  let closes = 0
  let deletes = 0
  let releases = 0
  registry.set(appKey, {
    discoveryHandles: new Set(),
    drive: {
      async close () {
        closes++
        closeStarted()
        await closeGate
      }
    }
  }, { persist: false })
  registry.persistDelete = async () => { deletes++ }
  const lifecycle = new AppLifecycle({
    appRegistry: registry,
    swarm: {},
    storageAdmission: { release () { releases++; return true } }
  })

  const shutdown = lifecycle.unseedApp(appKey, { forget: false })
  await started
  const forget = lifecycle.unseedApp(appKey, { forget: true, evictedAt: 10 })
  releaseClose()
  await Promise.all([shutdown, forget])
  t.is(closes, 1, 'exact drive closes once')
  t.is(deletes, 1, 'forget upgrade persists once')
  t.is(releases, 1, 'commitment releases once')
  t.absent(registry.has(appKey))
  t.absent(lifecycle._retiringDrives.has(appKey))
})

test('AppLifecycle: failed auxiliary core close preserves store and path owners', async (t) => {
  const events = []
  let rejectCore = true
  const lifecycle = new AppLifecycle({ swarm: { removeListener () { events.push('listener') } } })
  const resource = {
    appKey: 'c'.repeat(64),
    discovery: { async destroy () { events.push('discovery') } },
    tracker: { destroy () { events.push('tracker') } },
    snapshotCore: { async close () { events.push('snapshot') } },
    core: {
      async close () {
        events.push('core')
        if (rejectCore) throw new Error('injected core close failure')
      }
    },
    auxStore: { async close () { events.push('store') } },
    auxPath: null,
    onConnection: () => {}
  }
  lifecycle._auxShareBundleResources.add(resource)
  await t.exception(lifecycle._releaseAuxShareBundleResource(resource), /injected core close failure/)
  t.alike(events, ['listener', 'discovery', 'tracker', 'snapshot', 'core'])
  t.ok(resource.auxStore, 'backing store remains owned')
  t.ok(lifecycle._auxShareBundleResources.has(resource))
  rejectCore = false
  await lifecycle._releaseAuxShareBundleResource(resource)
  t.alike(events.slice(-2), ['core', 'store'])
  t.absent(lifecycle._auxShareBundleResources.has(resource))
})

test('AppLifecycle: failed range retirement preserves every downstream drive owner', async (t) => {
  const appKey = 'd'.repeat(64)
  const registry = new AppRegistry(null)
  let rejectRange = true
  let snapshots = 0
  let discoveries = 0
  let closes = 0
  const handle = { async destroy () { discoveries++ } }
  registry.set(appKey, {
    downloadRanges: [{ destroy () { if (rejectRange) throw new Error('injected range failure') } }],
    downloadSnapshotCores: [{ async close () { snapshots++ } }],
    discoveryHandles: new Set([handle]),
    drive: { async close () { closes++ } }
  }, { persist: false })
  const lifecycle = new AppLifecycle({ appRegistry: registry, swarm: {} })
  await t.exception(lifecycle.unseedApp(appKey, { forget: false }), /injected range failure/)
  t.is(snapshots, 0)
  t.is(discoveries, 0)
  t.is(closes, 0)
  t.ok(lifecycle._retiringDrives.has(appKey))
  rejectRange = false
  await lifecycle.unseedApp(appKey, { forget: false })
  t.is(snapshots, 1)
  t.is(discoveries, 1)
  t.is(closes, 1)
})

test('AppLifecycle: queued seed admission times out or aborts without later execution', async (t) => {
  for (const mode of ['timeout', 'abort']) {
    const scope = new LifecycleScope()
    const lifecycle = new AppLifecycle({
      _scope: scope,
      config: { seedAdmissionTimeoutMs: 5 }
    })
    let releaseFirst = null
    let firstEntered = null
    const firstGate = new Promise(resolve => { releaseFirst = resolve })
    const entered = new Promise(resolve => { firstEntered = resolve })
    let runs = 0
    const first = lifecycle._queueSeedAdmission(async () => {
      runs++
      firstEntered()
      await firstGate
    })
    await entered
    const second = lifecycle._queueSeedAdmission(async () => { runs++ })
    if (mode === 'abort') scope.abort()
    const failure = await Promise.allSettled([second])
    t.is(
      failure[0].reason?.code,
      mode === 'timeout' ? 'STORAGE_SEED_ADMISSION_TIMEOUT' : 'ABORT_ERR',
      `${mode}: queued caller fails with exact admission cause`
    )
    releaseFirst()
    await first
    await lifecycle._seedTail
    t.is(runs, 1, `${mode}: cancelled queued closure never runs later`)
  }
})

async function admissionNode (t) {
  const storage = tmpStorage()
  await mkdir(storage, { recursive: true })
  const node = new RelayNode({
    storage,
    enableAPI: false,
    enableNetworkDiscovery: false,
    enableHolesail: false,
    physicalEnforcer: testPhysicalEnforcer(storage)
  })
  t.teardown(async () => {
    try { await node.stop() } catch (_) {}
    try { await node.store.close() } catch (_) {}
    await rm(storage, { recursive: true, force: true })
  })
  await node.start()
  return node
}

async function authorAdmissionDrive (node, label) {
  const writer = new Hyperdrive(node.store.session())
  await writer.ready()
  await writer.put('/fixture.txt', Buffer.from(label))
  const appKey = writer.key.toString('hex')
  await writer.close()
  return appKey
}

test('AppLifecycle: successful seed commits its storage admission reservation', async (t) => {
  const node = await admissionNode(t)
  const appKey = await authorAdmissionDrive(node, 'successful admission')
  const cap = 1024 * 1024

  await node.seedApp(appKey, { maxStorage: cap })

  const record = node.storageAdmission.get(`drive:${appKey}`)
  t.is(record.state, 'committed', 'seed commits the reservation instead of abandoning it in `reserved`')
  t.is(record.boundBytes, cap, 'the committed bound is the requested cap')
  t.ok(node.storageAdmission.canAcknowledge(`drive:${appKey}`), 'the drive can be acknowledged from durable state')

  // An abandoned `reserved` record makes canAcknowledge() false, which turns
  // every re-pin into STORAGE_RECONCILIATION_REQUIRED.
  const repin = await node.seedApp(appKey, { maxStorage: cap })
  t.ok(repin.alreadySeeded, 're-pin ACKs from the committed ledger record')

  // ...and makes reserve() fail with `storage-reservation-in-progress`, which
  // surfaces as STORAGE_CAP_REPIN_BLOCKED on any cap raise.
  await node.seedApp(appKey, { maxStorage: cap * 2 })
  t.is(node.storageAdmission.get(`drive:${appKey}`).boundBytes, cap * 2, 'a later cap raise can still reserve this key')
  t.absent(node.storageAdmission.fatalReason, 'no invariant violation was tripped')
})

test('AppLifecycle: failed seed rolls its reservation back to the adopted commitment', async (t) => {
  const node = await admissionNode(t)
  const appKey = await authorAdmissionDrive(node, 'failed admission rollback')
  const cap = 1024 * 1024

  node.appRegistry.set(appKey, { discoveryKey: null, maxStorage: cap, type: 'app' }, { persist: false })
  const adopted = node.storageAdmission.adoptRecovery(`drive:${appKey}`, cap, { kind: 'drive' })

  const persistEntry = node.appRegistry.persistEntry.bind(node.appRegistry)
  node.appRegistry.persistEntry = async () => { throw new Error('disk full') }

  await t.exception(node.seedApp(appKey, { maxStorage: cap }), /disk full/)

  // rollback() restores the startup adoptRecovery() commitment. release() would
  // have deleted it, silently dropping this drive's durable debt from the ledger.
  t.alike(node.storageAdmission.get(`drive:${appKey}`), adopted, 'the failed seed restores the adopted commitment exactly')
  t.ok(node.storageAdmission.canAcknowledge(`drive:${appKey}`), 'the recovered drive is still acknowledgeable')

  node.appRegistry.persistEntry = persistEntry
  const retry = await node.seedApp(appKey, { maxStorage: cap })
  t.ok(retry.discoveryKey, 'a failed seed does not wedge the key in `reserved` against every retry')
  t.is(node.storageAdmission.get(`drive:${appKey}`).state, 'committed')
  t.absent(node.storageAdmission.fatalReason)
})

test('AppLifecycle: seed failure before the drive exists still rolls the reservation back', async (t) => {
  const node = await admissionNode(t)
  const appKey = await authorAdmissionDrive(node, 'constructor failure rollback')

  // Throws from the Hyperdrive construction — earlier than the drive-close
  // catch that used to be _seedAppInner's only failure handler.
  const session = node.store.session.bind(node.store)
  node.store.session = () => { throw new Error('store wedged') }

  await t.exception(node.seedApp(appKey, { maxStorage: 1024 * 1024 }), /store wedged/)
  t.absent(node.storageAdmission.get(`drive:${appKey}`), 'a reservation with no prior record is removed, not left reserved')

  node.store.session = session
  const retry = await node.seedApp(appKey, { maxStorage: 1024 * 1024 })
  t.ok(retry.discoveryKey, 'the key is reservable again after the pre-drive failure')
  t.absent(node.storageAdmission.fatalReason)
})
