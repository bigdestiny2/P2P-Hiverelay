import test from 'brittle'
import b4a from 'b4a'
import { openCorestore } from '../../packages/core/core/persistence/storage-root-restore.js'
import { access, mkdir, mkdtemp, rm, writeFile } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { AppRegistry } from 'p2p-hiverelay/core/app-registry.js'
import { StorageAdmissionAuthority } from '../../packages/core/config/storage-admission-authority.js'

const KEY = 'a'.repeat(64)
const BOUND = 1024 * 1024

async function openRegistry (dir, opts = {}) {
  const store = openCorestore(dir)
  await store.ready()
  if (typeof opts.storageAdmission?.activatePhysicalEnforcement === 'function') {
    await opts.storageAdmission.activatePhysicalEnforcement({ purpose: 'test-startup' })
  }
  const registry = new AppRegistry(dir, { store, ...opts })
  await registry.load()
  return { store, registry }
}

function staticAdmission (dir) {
  let generation = 0
  const physicalEnforcer = {
    schemaVersion: 1,
    async installAbsoluteCeiling (request) {
      return {
        providerId: 'test-provider',
        scopeId: 'test-root',
        leaseId: 'test-lease',
        operationId: request.operationId,
        requestedAt: request.requestedAt,
        generation: ++generation,
        hardLimitBytes: request.ceilingAllocatedBytes,
        rootIdentity: { ...request.storageIdentity }
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
        generation: lease.generation,
        hardLimitBytes: lease.hardLimitBytes,
        usedAllocatedBytes: 0,
        checkedAt: Math.max(Date.now(), lease.requestedAt),
        rootIdentity: { ...lease.rootIdentity }
      }
    }
  }
  const sample = () => ({
    ok: true,
    storagePath: dir,
    realpath: dir,
    device: '1',
    inode: '1',
    freeBytes: 80 * 1024 * 1024 * 1024,
    reserveBytes: 0,
    totalBytes: 100 * 1024 * 1024 * 1024,
    checkedAt: Date.now()
  })
  const admission = new StorageAdmissionAuthority({ storage: dir, maxStorageBytes: 512 * 1024 * 1024 }, {
    recoveryKinds: [],
    getUsedBytes: () => 0,
    sampleFilesystem: sample,
    physicalEnforcer
  })
  admission.refreshFilesystem()
  return admission
}

function rejectAdmission () {
  return {
    fatalReason: null,
    physicalEnforcementActive: true,
    physicalEnforcementSnapshot () {
      return { usedAllocatedBytes: 0, hardLimitBytes: 1024 * 1024 * 1024 }
    },
    runPhysicalMutation (_opts, run) { return Promise.resolve().then(run) },
    runKeyMutation (_key, run) { return Promise.resolve().then(run) },
    get () { return null },
    reserve () { return { allowed: false, reason: 'injected-capacity-denial' } },
    failClosed (reason) { this.fatalReason = reason }
  }
}

test('AppRegistry journal: aggregate reserve denial writes zero bytes and rolls memory back', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'registry-reserve-denial-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const admission = rejectAdmission()
  const { store, registry } = await openRegistry(dir, { storageAdmission: admission })
  const before = registry._bee.core.byteLength
  registry.set(KEY, { type: 'drive', maxStorage: BOUND }, { persist: false })
  const failure = await Promise.allSettled([registry.persistEntry(KEY, { throwOnError: true })])
  t.is(failure[0].reason.code, 'APP_REGISTRY_STORAGE_ADMISSION_BLOCKED')
  t.is(registry._bee.core.byteLength, before)
  t.absent(registry.has(KEY), 'failed first put cannot remain live in memory')
  t.is(admission.fatalReason, null, 'ordinary capacity denial is not an authority invariant failure')
  await store.close()
})

test('AppRegistry journal: planned-block cardinality mismatch fails before append', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'registry-plan-mismatch-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const { store, registry } = await openRegistry(dir)
  const originalBatch = registry._bee.batch.bind(registry._bee)
  registry._bee.batch = (...args) => {
    const batch = originalBatch(...args)
    batch.toBlocks = () => []
    return batch
  }
  const before = registry._bee.core.byteLength
  registry.set(KEY, { type: 'drive', maxStorage: BOUND }, { persist: false })
  await t.exception(registry.persistEntry(KEY, { throwOnError: true }), /plan-cardinality-invalid/)
  t.is(registry._bee.core.byteLength, before)
  t.absent(registry.has(KEY))
  registry._bee.batch = originalBatch
  await store.close()
})

test('AppRegistry journal: rejected tombstone flush restores the durable active row', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'registry-flush-reject-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const { store, registry } = await openRegistry(dir)
  registry.set(KEY, { type: 'drive', appId: 'keep', maxStorage: BOUND }, { persist: false })
  await registry.persistEntry(KEY, { throwOnError: true })
  const before = registry._bee.core.byteLength
  const originalBatch = registry._bee.batch.bind(registry._bee)
  registry._bee.batch = (...args) => {
    const batch = originalBatch(...args)
    batch.flush = async () => {
      await batch.close()
      throw new Error('injected flush rejection')
    }
    return batch
  }
  registry.delete(KEY, { persist: false })
  await t.exception(registry.persistDelete(KEY, { throwOnError: true }), /append-rejected/)
  t.is(registry._bee.core.byteLength, before)
  t.is(registry.get(KEY).appId, 'keep', 'memory rolls back to the durable active row')
  registry._bee.batch = originalBatch
  await store.close()
})

test('AppRegistry journal: post-flush feed tuple drift is terminal and retains debt', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'registry-ambiguous-settlement-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const admission = staticAdmission(dir)
  const { store, registry } = await openRegistry(dir, { storageAdmission: admission })
  const originalBatch = registry._bee.batch.bind(registry._bee)
  registry._bee.batch = (...args) => {
    const batch = originalBatch(...args)
    const flush = batch.flush.bind(batch)
    batch.flush = async () => {
      await flush()
      await registry._bee.core.append(b4a.from([0]))
    }
    return batch
  }
  const before = registry._bee.core.byteLength
  registry.set(KEY, { type: 'drive', maxStorage: BOUND }, { persist: false })
  await t.exception(registry.persistEntry(KEY, { throwOnError: true }), /settlement-ambiguous/)
  t.ok(registry._bee.core.byteLength > before, 'late bytes are observed rather than rolled back')
  t.is(admission.fatalReason, 'app-registry-journal-settlement-ambiguous')
  t.absent(registry.has(KEY), 'ambiguous first put is never exposed as live')
  registry._bee.batch = originalBatch
  await store.close()
})

test('AppRegistry journal: post-append migration crash is idempotent on retry', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'registry-migration-crash-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const jsonPath = join(dir, 'app-registry.json')
  const bakPath = jsonPath + '.bak'
  await writeFile(jsonPath, JSON.stringify([{ appKey: KEY, type: 'drive', maxStorage: BOUND }]))
  await mkdir(bakPath)

  let appendedBytes = 0
  {
    const store = openCorestore(dir)
    await store.ready()
    const registry = new AppRegistry(dir, { store })
    const failed = await Promise.allSettled([registry.load()])
    t.is(failed[0].status, 'rejected')
    t.is(failed[0].reason.cause?.reason, 'migration-rename-failed')
    appendedBytes = registry._bee.core.byteLength
    t.ok(appendedBytes > registry._registryJournal.baselineBytes, 'the atomic Bee append landed before rename failed')
    await store.close()
  }

  await rm(bakPath, { recursive: true, force: true })
  {
    const store = openCorestore(dir)
    await store.ready()
    const registry = new AppRegistry(dir, { store })
    const entries = await registry.load()
    t.is(entries.length, 1)
    t.is(registry._bee.core.byteLength, appendedBytes, 'digest marker prevents a second migration append')
    await t.exception(access(jsonPath), /ENOENT/)
    await access(bakPath)
    await store.close()
  }
})

test('AppRegistry journal: legacy eviction sidecar becomes a measured Bee tombstone', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'registry-eviction-migration-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const sidecar = join(dir, 'evicted.json')
  const evictedAt = 1_700_000_000_000
  await writeFile(sidecar, JSON.stringify({ [KEY]: evictedAt }))
  let debt = 0
  let feedBytes = 0
  {
    const { store, registry } = await openRegistry(dir)
    t.is(registry.size, 0)
    t.ok(registry.isEvicted(KEY))
    debt = registry._metadataBudgets.get(KEY).bytes
    feedBytes = registry._bee.core.byteLength
    t.ok(debt > 0)
    await t.exception(access(sidecar), /ENOENT/)
    await access(sidecar + '.bak')
    await store.close()
  }
  {
    const { store, registry } = await openRegistry(dir)
    t.is(registry._metadataBudgets.get(KEY).bytes, debt)
    t.is(registry._bee.core.byteLength, feedBytes)
    t.ok(registry.isEvicted(KEY))
    await store.close()
  }
})
