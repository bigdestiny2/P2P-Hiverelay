import test from 'brittle'
import {
  evaluateStorageAdmission,
  getStorageCapProvenance,
  LEGACY_DEFAULT_MAX_STORAGE_BYTES,
  markStorageCapDefault,
  markStorageCapExplicit,
  resolveStorageCap,
  storageReserveBytes
} from '../../packages/core/config/storage-cap.js'
import { RelayNode } from '../../packages/core/core/relay-node/index.js'
import { AppLifecycle } from '../../packages/core/core/relay-node/app-lifecycle.js'
import { Seeder } from '../../packages/core/core/relay-node/seeder.js'

const GiB = 1024 ** 3
const STORAGE = '/verified/storage'

function filesystem ({ totalBytes, availableBytes, currentStorageBytes = 0, device = 42, realpath = STORAGE } = {}) {
  const calls = { stat: [], realpath: [], statfs: [], measureStorageBytes: [] }
  return {
    calls,
    opts: {
      stat (path) {
        calls.stat.push(path)
        return { dev: device, isDirectory: () => true }
      },
      realpath (path) {
        calls.realpath.push(path)
        return realpath
      },
      statfs (path) {
        calls.statfs.push(path)
        return { blocks: totalBytes, bavail: availableBytes, bsize: 1 }
      },
      measureStorageBytes (path) {
        calls.measureStorageBytes.push(path)
        return currentStorageBytes
      }
    }
  }
}

test('storage cap: explicit 50 GiB is provenance, not an unset default', (t) => {
  const config = { storage: STORAGE, maxStorageBytes: LEGACY_DEFAULT_MAX_STORAGE_BYTES }
  markStorageCapExplicit(config, 'cli')
  const fs = filesystem({ totalBytes: 1024 * GiB, availableBytes: 900 * GiB })

  resolveStorageCap(config, fs.opts)

  t.is(config.maxStorageBytes, 50 * GiB, 'explicit value remains byte-for-byte unchanged')
  t.is(getStorageCapProvenance(config).explicit, true)
  t.is(getStorageCapProvenance(config).source, 'cli')
  t.alike(fs.calls.statfs, [STORAGE], 'measures the exact resolved storage path')
})

test('storage cap: unset default never grows beyond legacy 50 GiB', (t) => {
  const config = { storage: STORAGE, maxStorageBytes: LEGACY_DEFAULT_MAX_STORAGE_BYTES }
  markStorageCapDefault(config)
  const fs = filesystem({ totalBytes: 1024 * GiB, availableBytes: 900 * GiB })

  resolveStorageCap(config, fs.opts)

  t.is(config.maxStorageBytes, 50 * GiB)
  t.is(getStorageCapProvenance(config).explicit, false)
})

test('storage cap: low available space and a pre-used volume preserve the reserve without restart ratchet', (t) => {
  const config = { storage: STORAGE, maxStorageBytes: LEGACY_DEFAULT_MAX_STORAGE_BYTES }
  markStorageCapDefault(config)
  const fs = filesystem({
    totalBytes: 100 * GiB,
    availableBytes: 18 * GiB,
    currentStorageBytes: 7 * GiB
  })

  resolveStorageCap(config, fs.opts)

  t.is(storageReserveBytes(100 * GiB), 10 * GiB)
  t.is(config.maxStorageBytes, 15 * GiB, 'existing 7 GiB + 8 GiB safe new-adoption budget')
  t.is(getStorageCapProvenance(config).availableBytes, 18 * GiB)
  t.is(getStorageCapProvenance(config).reserveBytes, 10 * GiB)
  t.is(getStorageCapProvenance(config).currentStorageBytes, 7 * GiB)
})

test('storage cap: exhausted reserve resolves unset cap to fail-closed zero', (t) => {
  const config = { storage: STORAGE, maxStorageBytes: LEGACY_DEFAULT_MAX_STORAGE_BYTES }
  markStorageCapDefault(config)
  const fs = filesystem({ totalBytes: 100 * GiB, availableBytes: 5 * GiB })

  resolveStorageCap(config, fs.opts)

  t.is(config.maxStorageBytes, 0)
  const admission = evaluateStorageAdmission(config, { usedBytes: 0 })
  t.is(admission.allowed, false)
  t.is(admission.reason, 'storage-cap-reached')
})

test('storage cap: missing future mount never falls back to an existing ancestor', (t) => {
  const config = { storage: '/future/mount/data', maxStorageBytes: LEGACY_DEFAULT_MAX_STORAGE_BYTES }
  markStorageCapDefault(config)
  let statfsCalls = 0
  const err = Object.assign(new Error('missing'), { code: 'ENOENT' })

  resolveStorageCap(config, {
    stat () { throw err },
    realpath () { throw new Error('must not resolve an ancestor') },
    statfs () { statfsCalls++; throw new Error('must not statfs an ancestor') },
    measureStorageBytes () { throw new Error('must not measure an ancestor') }
  })

  t.is(statfsCalls, 0)
  t.is(config.maxStorageBytes, 0)
  t.is(getStorageCapProvenance(config).reason, 'storage-filesystem-enoent')
})

test('storage cap: wrong backing device fails closed without rewriting explicit cap', (t) => {
  const config = { storage: STORAGE, maxStorageBytes: 50 * GiB }
  markStorageCapExplicit(config, 'persisted')
  const fs = filesystem({ totalBytes: 100 * GiB, availableBytes: 90 * GiB, device: 7 })

  resolveStorageCap(config, {
    ...fs.opts,
    expectedFilesystem: { realpath: STORAGE, device: '8' }
  })

  t.is(config.maxStorageBytes, 50 * GiB, 'operator designation is retained')
  t.is(getStorageCapProvenance(config).status, 'unresolved')
  t.is(getStorageCapProvenance(config).reason, 'storage-filesystem-device-mismatch')
  t.is(evaluateStorageAdmission(config, { usedBytes: 0 }).allowed, false, 'new adoption fails closed')
})

test('storage admission: already-over-cap blocks adoption but keeps management non-destructive', async (t) => {
  const config = {
    maxStorageBytes: 20 * GiB,
    eviction: { enabled: false }
  }
  markStorageCapExplicit(config, 'management-api')
  // A direct/programmatic config has no filesystem proof; mark a resolved
  // physical snapshot so this test isolates over-cap semantics.
  const fs = filesystem({ totalBytes: 100 * GiB, availableBytes: 80 * GiB })
  resolveStorageCap({ ...config, storage: STORAGE }, fs.opts)

  const node = {
    config,
    seeder: { maxStorageBytes: 20 * GiB },
    _storageUsedBytes: () => 25 * GiB,
    _storageAdmission: RelayNode.prototype._storageAdmission,
    diskMonitor: null,
    storageAccounting: null
  }
  // Carry the resolved proof to the object used by the prototype method.
  resolveStorageCap(node.config, { ...fs.opts, storagePath: STORAGE })

  const result = await RelayNode.prototype.applyStorageDesignation.call(node, 20 * GiB)

  t.is(result.ok, true, 'management update remains available')
  t.is(result.overCap, true)
  t.is(result.adoptionBlocked, true)
  t.is(result.evictionEnabled, false, 'eviction remains opt-in')
  t.is(result.sweeping, false, 'no implicit destructive recovery starts')
  t.is(node.config.eviction.enabled, false)
})

test('storage admission: a genuinely new drive is rejected before Corestore adoption', async (t) => {
  const lifecycle = new AppLifecycle({
    appRegistry: { apps: new Map() },
    config: { maxStorageBytes: 10 * GiB },
    seeder: { totalBytesStored: 12 * GiB },
    _storageAdmission: () => ({ allowed: false, reason: 'storage-cap-reached' })
  })

  let error = null
  try {
    await lifecycle._seedAppInner('a'.repeat(64), {}, 'app', null, null, 'public')
  } catch (err) {
    error = err
  }

  t.ok(error)
  t.is(error.code, 'STORAGE_ADMISSION_BLOCKED')
  t.is(error.storageAdmission.reason, 'storage-cap-reached')
})

test('storage admission: persisted bare-core recovery bypasses new-adoption gate', async (t) => {
  const joins = []
  const core = {
    discoveryKey: Buffer.alloc(32, 1),
    length: 0,
    async ready () {},
    download () { return { done: async () => {}, destroy () {} } },
    on () {},
    async close () {}
  }
  const seeder = new Seeder({ get: () => core }, {
    join (topic) { joins.push(topic) },
    async leave () {}
  }, {
    maxStorageBytes: 0,
    canAdopt: () => ({ allowed: false, reason: 'storage-cap-reached' })
  })
  seeder._restoring = true
  const entry = await seeder.seedCore('a'.repeat(64))
  seeder._restoring = false

  t.is(entry.core, core, 'existing persisted core can reopen for recovery')
  t.is(joins.length, 1)
  await seeder.stop()
})
