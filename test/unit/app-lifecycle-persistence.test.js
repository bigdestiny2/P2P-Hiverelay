import test from 'brittle'
import { tmpdir } from 'os'
import { join } from 'path'
import { randomBytes } from 'crypto'
import { mkdir, rm } from 'fs/promises'
import { AppRegistry, APP_RETIREMENT_STATE } from 'p2p-hiverelay/core/app-registry.js'
import { AppLifecycle } from 'p2p-hiverelay/core/relay-node/app-lifecycle.js'
import { LifecycleScope } from 'p2p-hiverelay/core/relay-node/lifecycle-scope.js'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import createTestnet from '@hyperswarm/testnet'
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

test('RelayNode: seedApp rolls back registry when explicit registry persist fails', async (t) => {
  const testnet = await createTestnet(2, t)
  const storage = tmpStorage()
  await mkdir(storage, { recursive: true })
  const node = new RelayNode({
    storage,
    bootstrapNodes: testnet.bootstrap,
    enableAPI: false,
    enableNetworkDiscovery: false,
    enableHolesail: false,
    physicalEnforcer: testPhysicalEnforcer(storage)
  })
  t.teardown(async () => {
    await node.stop()
    await rm(storage, { recursive: true, force: true })
  })
  await node.start()

  const appKey = randomBytes(32).toString('hex')
  const placeholder = { discoveryKey: null, maxStorage: 1024 * 1024, type: 'app' }
  node.appRegistry.set(appKey, placeholder, { persist: false })
  const previous = node.appRegistry.get(appKey)
  node.storageAdmission.adoptRecovery(`drive:${appKey}`, 1024 * 1024, { kind: 'drive' })
  const persistEntry = node.appRegistry.persistEntry
  node.appRegistry.persistEntry = async () => {
    throw new Error('disk full')
  }

  try {
    await t.exception(
      node.seedApp(appKey, { maxStorage: 1024 * 1024 }),
      /disk full/,
      'seedApp rejects when the durable registry write fails'
    )
  } finally {
    node.appRegistry.persistEntry = persistEntry
  }

  t.alike(node.appRegistry.get(appKey), previous, 'failed seed restores only the pre-existing key placeholder')
  await node.stop()
  t.is(node.running, false, 'relay shuts down after the scoped persistence failure')
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

test('AppLifecycle: forget drains repair before entering the durable key lane', async (t) => {
  const appKey = 'e'.repeat(64)
  const events = []
  const registry = new AppRegistry(null)
  registry.set(appKey, {
    maxStorage: 4096,
    drive: { async close () { events.push('drive-close') } },
    discoveryHandles: new Set()
  }, { persist: false })
  registry.persistDelete = async (_key, opts) => {
    events.push(`delete:${opts.retirementId}`)
  }

  let finishRepair = null
  const repairGate = new Promise(resolve => { finishRepair = resolve })
  const storageAdmission = {
    runKeyMutation: async (_key, run) => {
      events.push('key-lane')
      return run()
    },
    releaseRetirement: () => { events.push('release'); return true }
  }
  const lifecycle = new AppLifecycle({ appRegistry: registry, storageAdmission, swarm: {} })
  lifecycle._repairUnanchoredOwned = async () => {
    events.push('repair-start')
    await repairGate
    events.push('repair-end')
    return false
  }

  const repair = lifecycle.repairUnanchored(appKey)
  const forget = lifecycle.unseedApp(appKey)
  await Promise.resolve()
  t.alike(events, ['repair-start'], 'phase two cannot take the key lane while repair is live')
  finishRepair()
  await Promise.allSettled([repair, forget])
  t.alike(events.slice(0, 4), ['repair-start', 'repair-end', 'drive-close', 'key-lane'])
  t.ok(events[4].startsWith('delete:'))
  t.is(events[5], 'release')
})

test('AppLifecycle: release failure retains tombstone and retries the same retirement id', async (t) => {
  const appKey = 'f'.repeat(64)
  const registry = new AppRegistry(null)
  let closes = 0
  let deletes = 0
  const releaseIds = []
  registry.set(appKey, {
    maxStorage: 8192,
    drive: { async close () { closes++ } },
    discoveryHandles: new Set()
  }, { persist: false })
  registry.persistDelete = async () => { deletes++ }
  const lifecycle = new AppLifecycle({
    appRegistry: registry,
    swarm: {},
    storageAdmission: {
      releaseRetirement (_key, retirementId) {
        releaseIds.push(retirementId)
        return releaseIds.length > 1
      }
    }
  })

  const first = await Promise.allSettled([lifecycle.unseedApp(appKey)])
  t.is(first[0].reason?.code, 'APP_RETIREMENT_RELEASE_PENDING')
  t.absent(registry.has(appKey), 'a committed delete is never resurrected')
  const retained = lifecycle._retiringDrives.get(appKey)
  t.is(retained.state, APP_RETIREMENT_STATE.RELEASE_PENDING)
  t.is(registry.retirementTombstones(APP_RETIREMENT_STATE.FORGOTTEN).length, 0)

  await lifecycle.unseedApp(appKey)
  t.is(closes, 1, 'terminal close is exact-once')
  t.is(deletes, 1, 'durable deletion is exact-once')
  t.is(releaseIds.length, 2)
  t.is(releaseIds[0], releaseIds[1], 'release retry is bound to one stable retirement id')
  t.is(registry.retirementTombstone(appKey).state, APP_RETIREMENT_STATE.FORGOTTEN)
})

test('AppLifecycle: final tombstone failure repeats only idempotent release', async (t) => {
  const appKey = '1'.repeat(64)
  const registry = new AppRegistry(null)
  let closes = 0
  let deletes = 0
  let finalWrites = 0
  const releaseIds = []
  registry.set(appKey, {
    maxStorage: 4096,
    drive: { async close () { closes++ } },
    discoveryHandles: new Set()
  }, { persist: false })
  registry.persistDelete = async () => { deletes++ }
  registry.persistRetirementState = async () => {
    finalWrites++
    if (finalWrites === 1) throw new Error('final tombstone write failed')
  }
  const lifecycle = new AppLifecycle({
    appRegistry: registry,
    swarm: {},
    storageAdmission: {
      releaseRetirement (_key, retirementId) {
        releaseIds.push(retirementId)
        return releaseIds.every(id => id === retirementId)
      }
    }
  })

  await t.exception(lifecycle.unseedApp(appKey), /final tombstone write failed/)
  t.absent(registry.has(appKey))
  await lifecycle.unseedApp(appKey)
  t.is(closes, 1)
  t.is(deletes, 1)
  t.is(finalWrites, 2)
  t.is(releaseIds.length, 2)
  t.is(releaseIds[0], releaseIds[1])
})

test('AppLifecycle: a post-append delete failure advances only to release-pending', async (t) => {
  const appKey = '6'.repeat(64)
  const registry = new AppRegistry(null)
  let deletes = 0
  let releases = 0
  registry.set(appKey, {
    maxStorage: 4096,
    drive: { async close () {} },
    discoveryHandles: new Set()
  }, { persist: false })
  registry.persistDelete = async (key, opts) => {
    deletes++
    registry.delete(key, { persist: false })
    await registry.persistRetirementState(key, opts)
    const err = new Error('journal authority settlement failed')
    err.durableDeleteCommitted = true
    err.retirementId = opts.retirementId
    throw err
  }
  const lifecycle = new AppLifecycle({
    appRegistry: registry,
    swarm: {},
    storageAdmission: {
      releaseRetirement () { releases++; return true }
    }
  })

  await t.exception(lifecycle.unseedApp(appKey), /journal authority settlement failed/)
  t.absent(registry.has(appKey))
  t.is(lifecycle._retiringDrives.get(appKey).state, APP_RETIREMENT_STATE.RELEASE_PENDING)
  await lifecycle.unseedApp(appKey)
  t.is(deletes, 1, 'retry never repeats the already committed delete')
  t.is(releases, 1)
  t.is(registry.retirementTombstone(appKey).state, APP_RETIREMENT_STATE.FORGOTTEN)
})

test('AppLifecycle: shutdown joins a forget accepted before the global fence', async (t) => {
  const appKey = '7'.repeat(64)
  const registry = new AppRegistry(null)
  let finishDelete
  const deleteGate = new Promise(resolve => { finishDelete = resolve })
  registry.set(appKey, {
    maxStorage: 4096,
    drive: { async close () {} },
    discoveryHandles: new Set()
  }, { persist: false })
  registry.persistDelete = async () => { await deleteGate }
  const lifecycle = new AppLifecycle({
    appRegistry: registry,
    swarm: {},
    storageAdmission: { releaseRetirement: () => true }
  })

  const forget = lifecycle.unseedApp(appKey)
  await Promise.resolve()
  lifecycle.beginShutdown()
  const shutdownJoin = lifecycle.unseedApp(appKey, { forget: false })
  finishDelete()
  await Promise.all([forget, shutdownJoin])
  t.absent(registry.has(appKey), 'shutdown never downgrades an already accepted durable forget')
  t.absent(lifecycle._retiringDrives.has(appKey))
})

test('AppLifecycle: shutdown fence rejects later forget but permits preserving teardown', async (t) => {
  const appKey = '2'.repeat(64)
  const registry = new AppRegistry(null)
  registry.set(appKey, {
    drive: { async close () {} },
    discoveryHandles: new Set()
  }, { persist: false })
  const lifecycle = new AppLifecycle({ appRegistry: registry, swarm: {} })
  lifecycle.beginShutdown()
  const result = await Promise.allSettled([lifecycle.unseedApp(appKey)])
  t.is(result[0].reason?.code, 'SHUTTING_DOWN')
  t.ok(registry.has(appKey), 'post-fence forget cannot remove durable state')
  await lifecycle.unseedApp(appKey, { forget: false })
  t.ok(registry.has(appKey), 'shutdown teardown preserves the durable row')
})

test('AppLifecycle: unresolved terminal close is retained and never double-invoked', async (t) => {
  const appKey = '3'.repeat(64)
  const registry = new AppRegistry(null)
  let closes = 0
  registry.set(appKey, {
    maxStorage: 4096,
    drive: { close () { closes++; return new Promise(() => {}) } },
    discoveryHandles: new Set()
  }, { persist: false })
  const lifecycle = new AppLifecycle({
    appRegistry: registry,
    swarm: {},
    config: { driveCloseTimeoutMs: 5 },
    storageAdmission: { releaseRetirement: () => true }
  })
  await t.exception(lifecycle.unseedApp(appKey), /drive close timed out/)
  await t.exception(lifecycle.unseedApp(appKey), /drive close timed out/)
  t.is(closes, 1, 'retry waits on the exact unresolved close')
  t.ok(registry.has(appKey), 'pre-delete failure preserves the row')
  t.is(lifecycle._retiringDrives.get(appKey).state, APP_RETIREMENT_STATE.LIVE)
})

test('AppLifecycle: an unresolved owned operation is bounded and retains its exact owner', async (t) => {
  const appKey = '8'.repeat(64)
  const registry = new AppRegistry(null)
  let closes = 0
  registry.set(appKey, {
    maxStorage: 4096,
    drive: { async close () { closes++ } },
    discoveryHandles: new Set()
  }, { persist: false })
  const lifecycle = new AppLifecycle({
    appRegistry: registry,
    swarm: {},
    config: { driveCloseTimeoutMs: 5 },
    storageAdmission: { releaseRetirement: () => true }
  })
  const entry = registry.get(appKey)
  const driveOwner = lifecycle._driveOwner(entry, appKey)
  const pending = new Promise(() => {})
  driveOwner.operations.add(pending)

  await t.exception(lifecycle.unseedApp(appKey), /drive owner operations timed out/)
  t.is(closes, 1, 'terminal close still runs after the bounded operation drain')
  t.ok(registry.has(appKey), 'operator forget preserves the row when quiescence cannot be proved')
  t.is(lifecycle._retiringDrives.get(appKey).driveOwner, driveOwner)
  t.ok(driveOwner.operations.has(pending), 'the unresolved operation owner remains reachable for retry')
})

test('AppLifecycle: an unresolved persistent registration cannot block terminal close', async (t) => {
  const appKey = '9'.repeat(64)
  const registry = new AppRegistry(null)
  const registration = { settled: new Promise(() => {}) }
  let closes = 0
  let deletes = 0
  let releases = 0
  registry.set(appKey, {
    maxStorage: 4096,
    downloadRegistration: registration,
    drive: { async close () { closes++ } },
    discoveryHandles: new Set()
  }, { persist: false })
  registry.persistDelete = async () => { deletes++ }
  const lifecycle = new AppLifecycle({
    appRegistry: registry,
    swarm: {},
    config: { driveCloseTimeoutMs: 5 },
    storageAdmission: {
      releaseRetirement () { releases++; return true }
    }
  })

  await t.exception(lifecycle.unseedApp(appKey), /persistent download registration timed out/)
  t.is(closes, 1, 'terminal close starts exactly once after the registration deadline')
  t.is(deletes, 0, 'durable row is retained while registration ownership is unresolved')
  t.is(releases, 0, 'storage commitment is retained while registration ownership is unresolved')
  t.is(registry.get(appKey).downloadRegistration, registration, 'exact registration owner remains reachable')
  t.is(lifecycle._retiringDrives.get(appKey).state, APP_RETIREMENT_STATE.LIVE)
})

test('AppLifecycle: fencing during anchor persistence restores the prior durable tuple', async (t) => {
  const appKey = 'a'.repeat(64)
  const registry = new AppRegistry(null)
  const drive = { closed: false, closing: false }
  registry.set(appKey, {
    anchored: false,
    drive,
    maxStorage: 4096
  }, { persist: false })
  let releasePersist = null
  let persistStarted = null
  const persistGate = new Promise(resolve => { releasePersist = resolve })
  const started = new Promise(resolve => { persistStarted = resolve })
  const persisted = []
  registry.persistEntry = async () => {
    persisted.push({
      anchored: registry.get(appKey).anchored,
      storageProvedDriveVersion: registry.get(appKey).storageProvedDriveVersion
    })
    if (persisted.length === 1) {
      persistStarted()
      await persistGate
    }
  }
  const lifecycle = new AppLifecycle({
    appRegistry: registry,
    storageAdmission: { canAcknowledge: () => true }
  })
  const proof = {
    driveVersion: 3,
    metaLength: 1,
    blobLength: 1,
    totalBytes: 2,
    metaFork: 0,
    blobFork: 0
  }

  const commit = lifecycle._commitAnchoredProof(appKey, drive, proof)
  await started
  lifecycle._fenceDriveOwner(registry.get(appKey), appKey)
  releasePersist()

  t.is(await commit, false, 'fenced owner cannot complete an anchor commit')
  t.alike(persisted, [
    { anchored: true, storageProvedDriveVersion: 3 },
    { anchored: false, storageProvedDriveVersion: null }
  ], 'the pre-fence tuple is persisted after the raced write')
  t.is(registry.get(appKey).anchored, false)
  t.is(registry.get(appKey).storageProvedDriveVersion, null)
})

test('AppLifecycle: fencing during share read prevents custody receipt publication', async (t) => {
  const appKey = 'b'.repeat(64)
  const registry = new AppRegistry(null)
  registry.set(appKey, { drive: {}, maxStorage: 4096 }, { persist: false })
  let releaseRead = null
  let readStarted = null
  const readGate = new Promise(resolve => { releaseRead = resolve })
  const started = new Promise(resolve => { readStarted = resolve })
  let receiptCalls = 0
  let receiptEvents = 0
  const lifecycle = new AppLifecycle({
    appRegistry: registry,
    config: { region: 'test' },
    swarm: { keyPair: { publicKey: Buffer.alloc(32), secretKey: Buffer.alloc(64) } },
    seedingRegistry: {
      getCustodyIntent: () => ({
        shareScheme: 'pvss-test',
        shareBundleKey: 'c'.repeat(64)
      }),
      async recordCustodyReceipt () { receiptCalls++ }
    }
  })
  lifecycle._readShareBundle = async () => {
    readStarted()
    await readGate
    return {}
  }
  lifecycle.on('custody-receipt', () => { receiptEvents++ })
  const entry = registry.get(appKey)
  const operation = lifecycle._trackDriveOperation(
    entry,
    appKey,
    'custody receipt race',
    (_owner, ownerToken) => lifecycle._recordCustodyReceipt(appKey, {
      blind: true,
      custodyIntentId: 'intent-1',
      shareScheme: 'pvss-test'
    }, 1, ownerToken)
  )
  await started
  lifecycle._fenceDriveOwner(entry, appKey)
  releaseRead()
  const [result] = await Promise.allSettled([operation])

  t.is(result.reason?.code, 'APP_LIFECYCLE_OWNER_RETIRED')
  t.is(receiptCalls, 0, 'no receipt append starts after the owner fence')
  t.is(receiptEvents, 0, 'no custody receipt event is published after the owner fence')
})

test('AppLifecycle: startup resumes a release-pending tombstone', async (t) => {
  const appKey = '4'.repeat(64)
  const retirementId = '5'.repeat(32)
  const registry = new AppRegistry(null)
  await registry.persistRetirementState(appKey, {
    retirementId,
    retirementState: APP_RETIREMENT_STATE.RELEASE_PENDING,
    retiredAt: 1_700_000_000_000,
    retirementBoundBytes: 4096
  })
  const adopted = []
  const released = []
  const lifecycle = new AppLifecycle({
    appRegistry: registry,
    config: { storage: join(tmpdir(), 'hiverelay-no-legacy-registry') },
    swarm: {},
    storageAdmission: {
      adoptRecovery (key, bound) { adopted.push([key, bound]); return {} },
      runKeyMutation: async (_key, run) => run(),
      releaseRetirement (key, id) { released.push([key, id]); return true },
      markRecoveryReady () {}
    }
  })
  await lifecycle.loadRegistry()
  t.alike(adopted, [[`drive:${appKey}`, 4096]])
  t.alike(released, [[`drive:${appKey}`, retirementId]])
  t.is(registry.retirementTombstone(appKey).state, APP_RETIREMENT_STATE.FORGOTTEN)
  t.is(lifecycle._retiringDrives.size, 0)
})
