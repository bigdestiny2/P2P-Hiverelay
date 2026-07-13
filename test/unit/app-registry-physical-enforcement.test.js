import test from 'brittle'
import Corestore from 'corestore'
import { access, mkdtemp, readFile, rm, writeFile } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { AppRegistry } from 'p2p-hiverelay/core/app-registry.js'
import { AppLifecycle } from 'p2p-hiverelay/core/relay-node/app-lifecycle.js'
import { StorageAdmissionAuthority } from '../../packages/core/config/storage-admission-authority.js'

const GiB = 1024 ** 3
const CAP = 10 * GiB
const KEY_A = 'a'.repeat(64)
const KEY_B = 'b'.repeat(64)
const PHYSICAL_ERROR = 'APP_REGISTRY_PHYSICAL_ENFORCEMENT_UNAVAILABLE'

async function freshTmp () {
  return mkdtemp(join(tmpdir(), 'hiverelay-app-reg-physical-'))
}

async function exists (path) {
  try {
    await access(path)
    return true
  } catch {
    return false
  }
}

function filesystemSample () {
  return {
    ok: true,
    checkedAt: Date.now(),
    storagePath: '/verified/storage',
    realpath: '/verified/storage',
    device: '42',
    inode: '84',
    totalBytes: 100 * GiB,
    freeBytes: 80 * GiB,
    reserveBytes: 0
  }
}

function inactiveAuthority () {
  return new StorageAdmissionAuthority({
    storage: '/verified/storage',
    maxStorageBytes: CAP
  }, {
    getUsedBytes: () => 0,
    sampleFilesystem: filesystemSample,
    recoveryKinds: []
  })
}

class FakePhysicalEnforcer {
  constructor (getUsedBytes = () => 0) {
    this.schemaVersion = 1
    this.providerId = 'fake-project-quota-v1'
    this.scopeId = 'fake-exclusive-root'
    this.leaseId = 'fake-root-lease'
    this.getUsedBytes = getUsedBytes
    this.calls = []
    this.generation = 0
    this.inspectCount = 0
    this.invalidOnInspect = null
  }

  async installAbsoluteCeiling (request, priorLease) {
    this.calls.push({
      type: 'install',
      purpose: request.purpose,
      priorGeneration: priorLease?.generation || null
    })
    const lease = {
      generation: ++this.generation,
      hardLimitBytes: request.ceilingAllocatedBytes,
      rootIdentity: { ...request.storageIdentity },
      providerId: this.providerId,
      scopeId: this.scopeId,
      leaseId: this.leaseId,
      operationId: request.operationId,
      requestedAt: request.requestedAt
    }
    return lease
  }

  async inspectAbsoluteCeiling (lease) {
    const count = ++this.inspectCount
    this.calls.push({ type: 'inspect', generation: lease.generation, count })
    return {
      schemaVersion: 1,
      active: count !== this.invalidOnInspect,
      exclusive: true,
      providerId: lease.providerId,
      scopeId: lease.scopeId,
      leaseId: lease.leaseId,
      operationId: lease.operationId,
      rootIdentity: { ...lease.rootIdentity },
      usedAllocatedBytes: this.getUsedBytes(),
      hardLimitBytes: lease.hardLimitBytes,
      generation: lease.generation,
      checkedAt: Math.max(Date.now(), lease.requestedAt)
    }
  }
}

function activeAuthority (enforcer) {
  return new StorageAdmissionAuthority({
    storage: '/verified/storage',
    maxStorageBytes: CAP
  }, {
    getUsedBytes: enforcer.getUsedBytes,
    getActualBytes: () => 0,
    sampleFilesystem: filesystemSample,
    physicalEnforcer: enforcer,
    recoveryKinds: []
  })
}

function persistedEntry (appKey = KEY_A, overrides = {}) {
  return {
    appKey,
    type: 'app',
    appId: 'physical-test-app',
    version: '1.0.0',
    maxStorage: 4096,
    ...overrides
  }
}

function registryState (registry) {
  const snapshot = registry.snapshot()
  return {
    apps: [...snapshot.apps].map(([key, value]) => [key, { ...value }]),
    byAppId: [...snapshot.byAppId],
    evicted: [...snapshot.evicted],
    metadataBudgets: [...snapshot.metadataBudgets].map(([key, value]) => [key, { ...value }]),
    metadataTombstones: [...snapshot.metadataTombstones],
    metadataTombstoneEntries: [...snapshot.metadataTombstoneEntries].map(([key, value]) => [key, { ...value }]),
    durableEntries: [...snapshot.durableEntries].map(([key, value]) => [key, { ...value }]),
    entryGenerations: [...snapshot.entryGenerations]
  }
}

function physicalMetrics (registry) {
  return {
    byteLength: registry._bee.core.byteLength,
    length: registry._bee.core.length
  }
}

function captureSync (run) {
  try {
    return { value: run(), error: null }
  } catch (error) {
    return { value: undefined, error }
  }
}

async function captureAsync (run) {
  try {
    return { value: await run(), error: null }
  } catch (error) {
    return { value: undefined, error }
  }
}

test('physical fallback: inactive provider leaves an empty Bee byte-for-byte empty', async (t) => {
  const dir = await freshTmp()
  const store = new Corestore(dir)
  try {
    await store.ready()
    const registry = new AppRegistry(dir, {
      store,
      storageAdmission: inactiveAuthority()
    })
    const entries = await registry.load()

    t.alike(entries, [])
    t.is(registry._physicalReadOnly, true)
    t.alike(physicalMetrics(registry), { byteLength: 0, length: 0 }, 'load did not materialize the Hyperbee header')
    await registry.flush({ throwOnError: true })
    t.alike(physicalMetrics(registry), { byteLength: 0, length: 0 }, 'shutdown flush also remains read-only')
  } finally {
    await store.close()
    await rm(dir, { recursive: true, force: true })
  }
})

test('physical enforcement scope: ordinary logical-cap registries remain writable', async (t) => {
  const dir = await freshTmp()
  const store = new Corestore(dir)
  try {
    await store.ready()
    const registry = new AppRegistry(dir, {
      store,
      storageAdmission: inactiveAuthority(),
      requirePhysicalEnforcement: false
    })
    await registry.load()
    t.is(registry.physicalReadOnly, false)
    registry.set(KEY_A, persistedEntry(), { persist: false })
    await registry.persistEntry(KEY_A, { throwOnError: true })
    t.ok(registry.has(KEY_A))
    t.ok(registry._bee.core.byteLength > 0)
  } finally {
    await store.close()
    await rm(dir, { recursive: true, force: true })
  }
})

test('physical enforcement scope: required-without-authority and late attachment fail closed', async (t) => {
  const dir = await freshTmp()
  const store = new Corestore(dir)
  try {
    await store.ready()
    const required = new AppRegistry(dir, { store, requirePhysicalEnforcement: true })
    await required.load()
    t.is(required.physicalReadOnly, true)
    t.is(captureSync(() => required.set(KEY_A, persistedEntry())).error?.code, PHYSICAL_ERROR)
    t.alike(physicalMetrics(required), { byteLength: 0, length: 0 })

    const late = new AppRegistry(null)
    late.setStorageAdmission(inactiveAuthority())
    t.is(late._requirePhysicalEnforcement, true, 'late direct authority attachment defaults hard enforcement on')
    t.is(captureSync(() => late.set(KEY_A, persistedEntry())).error?.code, PHYSICAL_ERROR)
    late.setStorageAdmission(null, { requirePhysicalEnforcement: false })
    late.set(KEY_A, persistedEntry(), { persist: false })
    t.ok(late.has(KEY_A), 'an explicit logical-only override remains available to compatibility embedders')
  } finally {
    await store.close()
    await rm(dir, { recursive: true, force: true })
  }
})

test('physical fallback: inactive provider hydrates legacy JSON without migration or Bee writes', async (t) => {
  const dir = await freshTmp()
  const jsonPath = join(dir, 'app-registry.json')
  const store = new Corestore(dir)
  try {
    const raw = JSON.stringify([persistedEntry()], null, 2)
    await writeFile(jsonPath, raw)
    await store.ready()
    const registry = new AppRegistry(dir, {
      store,
      storageAdmission: inactiveAuthority()
    })
    const entries = await registry.load()

    t.is(entries.length, 1)
    t.is(registry.get(KEY_A).appId, 'physical-test-app')
    t.is(await readFile(jsonPath, 'utf8'), raw, 'legacy authority is not rewritten')
    t.is(await exists(jsonPath + '.bak'), false, 'legacy authority is not renamed')
    t.alike(physicalMetrics(registry), { byteLength: 0, length: 0 }, 'legacy hydration does not create a Bee authority')
  } finally {
    await store.close()
    await rm(dir, { recursive: true, force: true })
  }
})

test('physical fallback: legacy evicted sidecar suppresses its row without Bee, header, or rename', async (t) => {
  const dir = await freshTmp()
  const jsonPath = join(dir, 'app-registry.json')
  const evictedPath = join(dir, 'evicted.json')
  const store = new Corestore(dir)
  try {
    const registryRaw = JSON.stringify([
      persistedEntry(KEY_A),
      persistedEntry(KEY_B, { appId: 'evicted-app' })
    ], null, 2)
    const evictedRaw = JSON.stringify({ [KEY_B]: 1_700_000_000_000 }, null, 2)
    await writeFile(jsonPath, registryRaw)
    await writeFile(evictedPath, evictedRaw)
    await store.ready()

    const registry = new AppRegistry(dir, {
      store,
      storageAdmission: inactiveAuthority()
    })
    const entries = await registry.load()

    t.alike(entries.map(entry => entry.appKey), [KEY_A])
    t.ok(registry.has(KEY_A), 'non-evicted legacy row hydrates')
    t.is(registry.has(KEY_B), false, 'sidecar tombstone suppresses the legacy row')
    t.is(registry.isEvicted(KEY_B), true, 'tombstone remains available to recovery policy')
    t.alike(physicalMetrics(registry), { byteLength: 0, length: 0 }, 'fallback does not materialize the Bee header')
    t.is(await readFile(jsonPath, 'utf8'), registryRaw, 'legacy inventory remains byte-for-byte unchanged')
    t.is(await readFile(evictedPath, 'utf8'), evictedRaw, 'evicted authority remains byte-for-byte unchanged')
    t.is(await exists(jsonPath + '.bak'), false, 'legacy inventory is not renamed')
    t.is(await exists(evictedPath + '.bak'), false, 'evicted sidecar is not renamed')
  } finally {
    await store.close()
    await rm(dir, { recursive: true, force: true })
  }
})

test('physical fallback: corrected eviction authority atomically replaces prior tombstones', async (t) => {
  const dir = await freshTmp()
  const jsonPath = join(dir, 'app-registry.json')
  const evictedPath = join(dir, 'evicted.json')
  const store = new Corestore(dir)
  try {
    await writeFile(jsonPath, JSON.stringify([persistedEntry()]))
    await writeFile(evictedPath, JSON.stringify({ [KEY_A]: 1_700_000_000_000 }))
    await store.ready()
    const registry = new AppRegistry(dir, { store, storageAdmission: inactiveAuthority() })
    t.alike(await registry.load(), [])
    t.ok(registry.isEvicted(KEY_A))

    await writeFile(evictedPath, '{}')
    const entries = await registry.load()
    t.is(entries.length, 1, 'a retry adopts the complete corrected sidecar authority')
    t.is(registry.isEvicted(KEY_A), false, 'removed tombstones do not leak across loads')

    await writeFile(evictedPath, '{broken')
    const failed = await captureAsync(() => registry.load())
    t.is(failed.error?.code, 'APP_REGISTRY_INVENTORY_FAILED')
    t.is(failed.error?.reason, 'evicted-json-corrupt')
  } finally {
    await store.close()
    await rm(dir, { recursive: true, force: true })
  }
})

test('physical fallback: a header-only Bee defers to validated legacy authority', async (t) => {
  const dir = await freshTmp()
  const jsonPath = join(dir, 'app-registry.json')
  try {
    {
      const store = new Corestore(dir)
      await store.ready()
      const registry = new AppRegistry(dir, { store })
      await registry.load()
      t.is(registry._bee.core.length, 1, 'fixture materializes only the protocol header')
      await store.close()
    }
    const raw = JSON.stringify([persistedEntry()], null, 2)
    await writeFile(jsonPath, raw)
    const store = new Corestore(dir)
    await store.ready()
    try {
      const registry = new AppRegistry(dir, { store, storageAdmission: inactiveAuthority() })
      const entries = await registry.load()
      t.is(entries.length, 1)
      t.ok(registry.has(KEY_A), 'legacy row remains authoritative in the header-before-migration crash window')
      t.is(registry._bee.core.length, 1)
      t.is(await readFile(jsonPath, 'utf8'), raw)
      t.is(await exists(jsonPath + '.bak'), false)
    } finally {
      await store.close()
    }
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('physical fallback: attachRuntime changes only volatile fields on an existing hydrated row', async (t) => {
  const dir = await freshTmp()
  const jsonPath = join(dir, 'app-registry.json')
  const store = new Corestore(dir)
  try {
    const raw = JSON.stringify([persistedEntry(KEY_A, {
      appId: 'durable-app',
      version: '4.5.6',
      maxStorage: 8192
    })], null, 2)
    await writeFile(jsonPath, raw)
    await store.ready()
    const registry = new AppRegistry(dir, {
      store,
      storageAdmission: inactiveAuthority()
    })
    await registry.load()

    const drive = { name: 'volatile-drive-handle' }
    const discoveryKey = Buffer.alloc(32, 7)
    const handles = new Set([{ destroy () {} }])
    t.is(registry.attachRuntime(KEY_A, {
      drive,
      discoveryKey,
      discoveryHandles: handles,
      bytesServed: 27,
      retiring: false
    }), true)
    const attached = registry.get(KEY_A)
    t.is(attached.drive, drive)
    t.is(attached.discoveryKey, discoveryKey)
    t.is(attached.discoveryHandles, handles)
    t.is(attached.bytesServed, 27)
    t.is(attached.retiring, false)
    t.is(attached.appId, 'durable-app', 'durable app identity is unchanged')
    t.is(attached.version, '4.5.6', 'durable version is unchanged')
    t.is(attached.maxStorage, 8192, 'durable storage commitment is unchanged')

    t.exception(
      () => registry.attachRuntime(KEY_A, { version: '9.9.9' }),
      /APP_REGISTRY_RUNTIME_FIELD_INVALID: version/,
      'durable fields are outside the runtime attachment allowlist'
    )
    t.is(registry.get(KEY_A).version, '4.5.6', 'rejected durable change has no effect')
    t.is(registry.attachRuntime(KEY_B, { drive: {} }), false, 'runtime attachment cannot create a row')
    t.is(registry.has(KEY_B), false)
    t.is(await readFile(jsonPath, 'utf8'), raw, 'runtime attachment does not rewrite durable authority')
    t.alike(physicalMetrics(registry), { byteLength: 0, length: 0 }, 'runtime attachment appends no Bee bytes')
  } finally {
    await store.close()
    await rm(dir, { recursive: true, force: true })
  }
})

test('physical fallback: lifecycle recovery reopens hydrated row serve-only while external ingress stays closed', async (t) => {
  const dir = await freshTmp()
  const jsonPath = join(dir, 'app-registry.json')
  const store = new Corestore(dir)
  let registry = null
  try {
    const raw = JSON.stringify([persistedEntry(KEY_A, {
      appId: 'serve-only-app',
      version: '7.8.9',
      maxStorage: 8192
    })], null, 2)
    await writeFile(jsonPath, raw)
    await store.ready()
    const storageAdmission = inactiveAuthority()
    registry = new AppRegistry(dir, { store, storageAdmission })
    const entries = await registry.load()
    t.is(registry.physicalReadOnly, true)

    let persistCalls = 0
    let eagerReplications = 0
    let persistentDownloads = 0
    let discoveryJoins = 0
    registry.persistEntry = async () => {
      persistCalls++
      throw new Error('serve-only recovery must not persist')
    }
    const lifecycle = new AppLifecycle({
      appRegistry: registry,
      storageAdmission,
      store,
      seeder: {},
      swarm: {
        join () {
          discoveryJoins++
          return { async destroy () {} }
        },
        async flush () {}
      },
      config: { strictSeedingPrivacy: true },
      _storageIngressReady: false
    })
    lifecycle._trackEagerReplicate = () => { eagerReplications++ }
    lifecycle._registerPersistentDownloads = async () => { persistentDownloads++ }
    const reseeded = []
    const errors = []
    lifecycle.on('reseeded', event => reseeded.push(event))
    lifecycle.on('reseed-error', event => errors.push(event))

    await lifecycle.reseedDrives(entries)

    const recovered = registry.get(KEY_A)
    t.is(errors.length, 0, 'recovery ingress reopens the hydrated row successfully')
    t.alike(reseeded.map(event => event.appKey), [KEY_A])
    t.ok(recovered.drive, 'process-local drive handle is attached')
    t.ok(Buffer.isBuffer(recovered.discoveryKey), 'process-local discovery key is attached')
    t.ok(recovered.discoveryHandles instanceof Set)
    t.ok(discoveryJoins > 0, 'serve-only recovery still joins discovery for serving')
    t.is(recovered.appId, 'serve-only-app', 'durable app identity remains hydrated authority')
    t.is(recovered.version, '7.8.9', 'durable version is not rebuilt from reseed options')
    t.is(recovered.maxStorage, 8192, 'durable storage commitment is unchanged')
    t.is(persistCalls, 0, 'serve-only recovery skips persistEntry')
    t.is(eagerReplications, 0, 'serve-only recovery does not eagerly replicate')
    t.is(persistentDownloads, 0, 'serve-only recovery registers no persistent downloads')
    t.is(await readFile(jsonPath, 'utf8'), raw, 'recovery does not rewrite legacy durable authority')
    t.alike(physicalMetrics(registry), { byteLength: 0, length: 0 }, 'recovery appends no Bee bytes')

    const external = await captureAsync(() => lifecycle.seedApp(KEY_B, { maxStorage: 8192 }))
    t.is(external.error?.code, 'STORAGE_RECOVERY_INVENTORY_PENDING', 'external seed remains rejected while recovery ingress alone is open')
    t.is(registry.has(KEY_B), false)
  } finally {
    const recovered = registry?.get(KEY_A)
    if (recovered?.discoveryHandles instanceof Set) {
      for (const handle of recovered.discoveryHandles) {
        try { await handle.destroy() } catch {}
      }
    }
    try { await recovered?.drive?.close() } catch {}
    await store.close()
    await rm(dir, { recursive: true, force: true })
  }
})

test('physical fallback: durable forget preflights before any live teardown', async (t) => {
  const dir = await freshTmp()
  const jsonPath = join(dir, 'app-registry.json')
  const store = new Corestore(dir)
  let closes = 0
  try {
    await writeFile(jsonPath, JSON.stringify([persistedEntry()]))
    await store.ready()
    const registry = new AppRegistry(dir, { store, storageAdmission: inactiveAuthority() })
    await registry.load()
    registry.attachRuntime(KEY_A, {
      drive: { async close () { closes++ } },
      discoveryHandles: new Set()
    })
    const lifecycle = new AppLifecycle({ appRegistry: registry, swarm: {} })
    const failed = await captureAsync(() => lifecycle.unseedApp(KEY_A, { forget: true }))
    t.is(failed.error?.code, PHYSICAL_ERROR)
    t.is(closes, 0, 'drive remains online when durable retirement cannot begin')
    t.ok(registry.has(KEY_A))
    t.is(registry.get(KEY_A).retiring, undefined)
    t.is(lifecycle._retiringDrives.size, 0)
  } finally {
    await store.close()
    await rm(dir, { recursive: true, force: true })
  }
})

test('physical fallback: fresh ingress and repair stop before storage-producing work', async (t) => {
  const dir = await freshTmp()
  const jsonPath = join(dir, 'app-registry.json')
  const store = new Corestore(dir)
  let keyMutations = 0
  let storeSessions = 0
  let driveUpdates = 0
  let swarmFlushes = 0
  try {
    await writeFile(jsonPath, JSON.stringify([persistedEntry()]))
    await store.ready()
    const registry = new AppRegistry(dir, { store, storageAdmission: inactiveAuthority() })
    await registry.load()
    registry.attachRuntime(KEY_A, {
      drive: {
        closed: false,
        closing: false,
        discoveryKey: Buffer.alloc(32),
        async update () { driveUpdates++ }
      }
    })
    const lifecycle = new AppLifecycle({
      _storageIngressReady: true,
      appRegistry: registry,
      store: { session () { storeSessions++; return {} } },
      seeder: {},
      swarm: { async flush () { swarmFlushes++ } },
      storageAdmission: {
        runKeyMutation (_key, run) { keyMutations++; return Promise.resolve().then(run) }
      },
      config: {}
    })

    const seedFailure = await captureAsync(() => lifecycle.seedApp(KEY_B, { maxStorage: 4096 }))
    t.is(seedFailure.error?.code, PHYSICAL_ERROR)
    t.is(keyMutations, 1, 'fresh ingress is serialized but fails inside the lane before storage adoption')
    t.is(storeSessions, 0, 'fresh ingress fails before Corestore/Hyperdrive adoption')

    t.is(await lifecycle.repairUnanchored(KEY_A), false)
    t.alike(await lifecycle.runRepairPass(), { checked: 0, repaired: 0, stillUnanchored: 0 })
    t.is(driveUpdates, 0, 'serve-only repair never updates or downloads the drive')
    t.is(swarmFlushes, 0)
  } finally {
    await store.close()
    await rm(dir, { recursive: true, force: true })
  }
})

test('physical fallback: inactive provider also locks legacy no-store JSON writers', async (t) => {
  const dir = await freshTmp()
  const jsonPath = join(dir, 'app-registry.json')
  try {
    const raw = JSON.stringify([persistedEntry()], null, 2)
    await writeFile(jsonPath, raw)
    const registry = new AppRegistry(dir, { storageAdmission: inactiveAuthority() })
    const entries = await registry.load()
    t.is(entries.length, 1)

    const setResult = captureSync(() => registry.set(KEY_B, persistedEntry(KEY_B)))
    t.is(setResult.error?.code, PHYSICAL_ERROR)
    const saveResult = await captureAsync(() => registry.save({ throwOnError: true }))
    t.is(saveResult.error?.code, PHYSICAL_ERROR)
    t.is(await readFile(jsonPath, 'utf8'), raw, 'legacy JSON remains byte-for-byte read-only')
    t.is(await exists(jsonPath + '.tmp'), false)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('physical fallback: inactive provider hydrates an existing proved Bee without bytes or migration', async (t) => {
  const dir = await freshTmp()
  const jsonPath = join(dir, 'app-registry.json')
  try {
    let durableMetrics
    {
      const store = new Corestore(dir)
      await store.ready()
      const registry = new AppRegistry(dir, { store })
      await registry.load()
      registry.set(KEY_A, persistedEntry(KEY_A), { persist: false })
      await registry.persistEntry(KEY_A, { throwOnError: true })
      durableMetrics = physicalMetrics(registry)
      await store.close()
    }

    const legacyRaw = JSON.stringify([persistedEntry(KEY_B, { appId: 'must-not-migrate' })])
    await writeFile(jsonPath, legacyRaw)
    const store = new Corestore(dir)
    await store.ready()
    try {
      const registry = new AppRegistry(dir, {
        store,
        storageAdmission: inactiveAuthority()
      })
      const entries = await registry.load()

      t.is(entries.length, 1)
      t.ok(registry.has(KEY_A), 'proved Bee row hydrates')
      t.is(registry.has(KEY_B), false, 'legacy row is not merged into an existing Bee')
      t.alike(physicalMetrics(registry), durableMetrics, 'read-only recovery appends no Bee blocks')
      t.is(await readFile(jsonPath, 'utf8'), legacyRaw)
      t.is(await exists(jsonPath + '.bak'), false, 'read-only recovery does not claim migration')
    } finally {
      await store.close()
    }
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('physical fallback: public durable mutators reject exactly before state, events, or bytes change', async (t) => {
  const dir = await freshTmp()
  try {
    {
      const store = new Corestore(dir)
      await store.ready()
      const registry = new AppRegistry(dir, { store })
      await registry.load()
      registry.set(KEY_A, persistedEntry(KEY_A, {
        anchored: true,
        anchoredLength: 1,
        storageProvedDriveVersion: 1,
        storageProvedMetaLength: 0,
        storageProvedBlobLength: 0,
        storageProvedTotalBytes: 0,
        storageProvedMetaFork: 0,
        storageProvedBlobFork: 0
      }), { persist: false })
      await registry.persistEntry(KEY_A, { throwOnError: true })
      await store.close()
    }

    const store = new Corestore(dir)
    await store.ready()
    try {
      const registry = new AppRegistry(dir, {
        store,
        storageAdmission: inactiveAuthority()
      })
      await registry.load()
      const changes = []
      const errors = []
      registry.on('change', event => changes.push(event))
      registry.on('error', event => errors.push(event))

      const syncCases = [
        ['set', () => registry.set(KEY_B, persistedEntry(KEY_B))],
        ['update', () => registry.update(KEY_A, { version: '2.0.0' })],
        ['delete', () => registry.delete(KEY_A)],
        ['setAnchored', () => registry.setAnchored(KEY_A, 2)],
        ['clearAnchored', () => registry.clearAnchored(KEY_A, 'test')]
      ]
      for (const [name, run] of syncCases) {
        const beforeState = registry.snapshot()
        const before = registryState(registry)
        const beforeMetrics = physicalMetrics(registry)
        const result = captureSync(run)
        await Promise.resolve()
        t.is(result.error?.code, PHYSICAL_ERROR, `${name} rejects with the exact physical-enforcement code`)
        t.alike(registryState(registry), before, `${name} leaves all registry state unchanged`)
        t.alike(physicalMetrics(registry), beforeMetrics, `${name} appends no bytes`)
        t.is(changes.length, 0, `${name} emits no false change acknowledgement`)
        t.is(errors.length, 0, `${name} emits no background persistence error`)
        registry.restoreSnapshot(beforeState)
        changes.length = 0
        errors.length = 0
      }

      registry.evicted.set(KEY_B, 123)
      const asyncCases = [
        ['markEvicted', () => registry.markEvicted(KEY_B, 456)],
        ['clearEvicted', () => registry.clearEvicted(KEY_B)],
        ['persistEntry', () => registry.persistEntry(KEY_A, { throwOnError: true })],
        ['persistDelete', () => registry.persistDelete(KEY_A, { throwOnError: true })],
        ['save', () => registry.save({ throwOnError: true })]
      ]
      for (const [name, run] of asyncCases) {
        const beforeState = registry.snapshot()
        const before = registryState(registry)
        const beforeMetrics = physicalMetrics(registry)
        const result = await captureAsync(run)
        t.is(result.error?.code, PHYSICAL_ERROR, `${name} rejects with the exact physical-enforcement code`)
        t.alike(registryState(registry), before, `${name} leaves all registry state unchanged`)
        t.alike(physicalMetrics(registry), beforeMetrics, `${name} appends no bytes`)
        t.is(changes.length, 0, `${name} emits no false change acknowledgement`)
        t.is(errors.length, 0, `${name} emits no background persistence error`)
        registry.restoreSnapshot(beforeState)
      }
    } finally {
      await store.close()
    }
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('physical provider: header and runtime append each install, inspect, mutate, inspect in order', async (t) => {
  const dir = await freshTmp()
  const enforcer = new FakePhysicalEnforcer()
  const authority = activeAuthority(enforcer)
  const store = new Corestore(dir)
  try {
    await store.ready()
    const activation = await authority.activatePhysicalEnforcement({ purpose: 'startup' })
    t.is(activation.active, true)
    const registry = new AppRegistry(dir, { store, storageAdmission: authority })

    const beforeHeader = enforcer.calls.length
    await registry.load()
    const headerCalls = enforcer.calls.slice(beforeHeader)
    t.alike(headerCalls.map(call => call.type), ['install', 'inspect', 'inspect'], 'header write is enclosed by pre/post proof')
    t.is(headerCalls[0].purpose, 'app-registry-bee-header')

    registry.set(KEY_A, persistedEntry(), { persist: false })
    const beforeAppend = enforcer.calls.length
    await registry.persistEntry(KEY_A, { throwOnError: true })
    const appendCalls = enforcer.calls.slice(beforeAppend)
    t.alike(appendCalls.map(call => call.type), ['install', 'inspect', 'inspect'], 'runtime append is enclosed by pre/post proof')
    t.ok(appendCalls[0].purpose.includes('app-registry'), 'runtime proof is purpose-bound')
    t.ok(registry.has(KEY_A))
  } finally {
    await store.close()
    await rm(dir, { recursive: true, force: true })
  }
})

test('physical provider: recovery append and authority rename are separate proved mutations', async (t) => {
  const dir = await freshTmp()
  const jsonPath = join(dir, 'app-registry.json')
  const enforcer = new FakePhysicalEnforcer()
  const authority = activeAuthority(enforcer)
  const store = new Corestore(dir)
  try {
    await writeFile(jsonPath, JSON.stringify([persistedEntry()]))
    await store.ready()
    await authority.activatePhysicalEnforcement({ purpose: 'startup' })
    const registry = new AppRegistry(dir, { store, storageAdmission: authority })
    await registry.load()
    const purposes = enforcer.calls
      .filter(call => call.type === 'install')
      .map(call => call.purpose)
    t.ok(purposes.includes('app-registry-bee-header'))
    t.ok(purposes.includes('app-registry-bee-append:recovery'))
    t.ok(purposes.includes('app-registry-json-migration-rename'))
    t.is(await exists(jsonPath), false)
    t.is(await exists(jsonPath + '.bak'), true)
  } finally {
    await store.close()
    await rm(dir, { recursive: true, force: true })
  }
})

test('physical provider: failed pre-inspection rejects before the Bee append', async (t) => {
  const dir = await freshTmp()
  const enforcer = new FakePhysicalEnforcer()
  const authority = activeAuthority(enforcer)
  const store = new Corestore(dir)
  try {
    await store.ready()
    await authority.activatePhysicalEnforcement({ purpose: 'startup' })
    const registry = new AppRegistry(dir, { store, storageAdmission: authority })
    await registry.load()
    const beforeMetrics = physicalMetrics(registry)
    registry.set(KEY_A, persistedEntry(), { persist: false })
    enforcer.invalidOnInspect = enforcer.inspectCount + 1

    const result = await captureAsync(() => registry.persistEntry(KEY_A, { throwOnError: true }))
    t.is(result.error?.code, PHYSICAL_ERROR)
    t.alike(physicalMetrics(registry), beforeMetrics, 'failed pre-proof allows no durable append')
    t.is(registry.has(KEY_A), false, 'unacknowledged in-memory row rolls back')
  } finally {
    await store.close()
    await rm(dir, { recursive: true, force: true })
  }
})

test('physical provider: failed post-inspection rejects the ACK and fail-closes authority', async (t) => {
  const dir = await freshTmp()
  const enforcer = new FakePhysicalEnforcer()
  const authority = activeAuthority(enforcer)
  const store = new Corestore(dir)
  try {
    await store.ready()
    await authority.activatePhysicalEnforcement({ purpose: 'startup' })
    const registry = new AppRegistry(dir, { store, storageAdmission: authority })
    await registry.load()
    const beforeMetrics = physicalMetrics(registry)
    registry.set(KEY_A, persistedEntry(), { persist: false })
    enforcer.invalidOnInspect = enforcer.inspectCount + 2

    const result = await captureAsync(() => registry.persistEntry(KEY_A, { throwOnError: true }))
    t.is(result.error?.code, PHYSICAL_ERROR)
    t.ok(physicalMetrics(registry).byteLength > beforeMetrics.byteLength, 'post-proof failure is conservatively treated as a durable ambiguous write')
    t.is(registry.has(KEY_A), false, 'ambiguous write is never acknowledged in memory')
    t.is(authority.fatalReason, 'storage-physical-enforcement-ambiguous')
    t.is(authority.mutationAdmission().allowed, false, 'all later storage mutation admission is closed')
  } finally {
    await store.close()
    await rm(dir, { recursive: true, force: true })
  }
})

test('physical provider: a runtime-fatal authority dynamically blocks seed, repair, and forget', async (t) => {
  const dir = await freshTmp()
  const enforcer = new FakePhysicalEnforcer()
  const authority = activeAuthority(enforcer)
  const store = new Corestore(dir)
  let closes = 0
  let updates = 0
  let sessions = 0
  try {
    await store.ready()
    await authority.activatePhysicalEnforcement({ purpose: 'startup' })
    const registry = new AppRegistry(dir, { store, storageAdmission: authority })
    await registry.load()
    registry.set(KEY_A, persistedEntry(), { persist: false })
    await registry.persistEntry(KEY_A, { throwOnError: true })
    registry.attachRuntime(KEY_A, {
      drive: {
        closed: false,
        closing: false,
        discoveryKey: Buffer.alloc(32),
        async update () { updates++ },
        async close () { closes++ }
      },
      discoveryHandles: new Set()
    })
    authority.failClosed('injected-runtime-fatal')
    t.is(registry.physicalReadOnly, true)

    const lifecycle = new AppLifecycle({
      _storageIngressReady: true,
      appRegistry: registry,
      store: { session () { sessions++; return {} } },
      seeder: {},
      swarm: {},
      storageAdmission: authority,
      config: {}
    })
    t.is((await captureAsync(() => lifecycle.seedApp(KEY_B, { maxStorage: 4096 }))).error?.code, PHYSICAL_ERROR)
    t.is((await captureAsync(() => lifecycle.unseedApp(KEY_A, { forget: true }))).error?.code, PHYSICAL_ERROR)
    t.is(await lifecycle.repairUnanchored(KEY_A), false)
    t.is(sessions, 0)
    t.is(closes, 0)
    t.is(updates, 0)
    t.ok(registry.has(KEY_A))
  } finally {
    await store.close()
    await rm(dir, { recursive: true, force: true })
  }
})

test('physical provider: mutations serialize and a queued mutation observes stop', async (t) => {
  const enforcer = new FakePhysicalEnforcer()
  const authority = activeAuthority(enforcer)
  await authority.activatePhysicalEnforcement({ purpose: 'startup' })

  let releaseFirst
  const firstGate = new Promise(resolve => { releaseFirst = resolve })
  const order = []
  const first = authority.runPhysicalMutation({ purpose: 'first', phase: 'runtime' }, async () => {
    order.push('first-start')
    await firstGate
    order.push('first-end')
    return 'first-ok'
  })
  const second = authority.runPhysicalMutation({ purpose: 'second', phase: 'runtime' }, async () => {
    order.push('second-ran')
    return 'second-ok'
  })
  const observedSecond = captureAsync(() => second)

  await new Promise(resolve => setImmediate(resolve))
  authority.closeMutations('operator-stop')
  releaseFirst()
  t.is(await first, 'first-ok', 'in-flight mutation is allowed to settle under proof')
  const secondResult = await observedSecond
  t.is(secondResult.error?.code, 'STORAGE_PHYSICAL_ENFORCEMENT_UNAVAILABLE')
  t.alike(order, ['first-start', 'first-end'], 'queued callback never overlaps or runs after stop')
  await authority.drainMutations({ timeoutMs: 1000 })
  t.is(authority._physicalMutations.size, 0, 'no physical mutation token leaks across stop')
})
