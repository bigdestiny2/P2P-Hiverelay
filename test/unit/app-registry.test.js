import test from 'brittle'
import { AppRegistry } from 'p2p-hiverelay/core/app-registry.js'
import Corestore from 'corestore'
import { mkdtemp, readdir, rm, stat } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'

async function physicalTreeBytes (path) {
  let total = 0
  for (const dirent of await readdir(path, { withFileTypes: true })) {
    const child = join(path, dirent.name)
    if (dirent.isDirectory()) {
      total += await physicalTreeBytes(child)
    } else if (dirent.isFile()) {
      const info = await stat(child)
      total += Number.isSafeInteger(info.blocks) && info.blocks >= 0
        ? info.blocks * 512
        : info.size
    }
  }
  return total
}

test('AppRegistry: snapshot restore preserves map identity and indexes', (t) => {
  const registry = new AppRegistry(null)
  const appsRef = registry.apps
  const byAppIdRef = registry.byAppId
  const keyA = 'a'.repeat(64)
  const keyB = 'b'.repeat(64)

  registry.set(keyA, { type: 'app', appId: 'keep-me' }, { persist: false })
  const snapshot = registry.snapshot()
  registry.set(keyB, { type: 'app', appId: 'new-entry' }, { persist: false })
  registry.delete(keyA, { persist: false })

  registry.restoreSnapshot(snapshot)

  t.is(registry.apps, appsRef, 'apps map identity is stable')
  t.is(registry.byAppId, byAppIdRef, 'dedup index map identity is stable')
  t.ok(registry.has(keyA), 'original entry restored')
  t.absent(registry.has(keyB), 'new entry rolled back')
  t.is(registry.byAppId.get('keep-me'), keyA, 'dedup index restored')
  t.absent(registry.byAppId.get('new-entry'), 'dedup index rollback removed new appId')
})

test('AppRegistry: explicit JSON persistence rejects write failures', async (t) => {
  const registry = new AppRegistry('/dev/null')
  const key = 'c'.repeat(64)
  registry.on('error', () => {})
  registry.set(key, { type: 'app', appId: 'cannot-write' }, { persist: false })

  await t.exception(
    registry.persistEntry(key, { throwOnError: true }),
    /ENOTDIR|not a directory/,
    'explicit persist surfaces the write failure'
  )
})

test('AppRegistry: runtime uppercase key persists canonically and reloads cleanly', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'app-registry-canonical-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const upper = 'A'.repeat(64)
  const lower = upper.toLowerCase()
  const first = new AppRegistry(dir)
  first.set(upper, { type: 'drive', appId: 'canonical', maxStorage: 4096 }, { persist: false })
  await first.persistEntry(upper, { throwOnError: true })

  t.ok(first.has(lower))
  t.ok(first.has(upper), 'runtime lookup canonicalizes too')
  t.alike([...first.keys()], [lower])

  const restarted = new AppRegistry(dir)
  const entries = await restarted.load()
  t.is(entries[0].appKey, lower)
  t.is(restarted.get(lower).maxStorage, 4096)
})

test('AppRegistry: throwing observers cannot interrupt set, update, or delete', (t) => {
  const registry = new AppRegistry(null)
  const key = 'e'.repeat(64)
  const observed = []
  registry.on('change', () => { throw new Error('observer boom') })
  registry.on('change', event => observed.push(event.type))

  registry.set(key, { type: 'app', appId: 'observer-safe' }, { persist: false })
  t.ok(registry.has(key), 'set remains committed in memory')
  t.is(registry.update(key, { description: 'updated' }, { persist: false }), true)
  t.is(registry.get(key).description, 'updated')
  t.is(registry.delete(key, { persist: false }), true)
  t.absent(registry.has(key))
  t.alike(observed, ['set', 'update', 'delete'], 'later observers are independently delivered')
})

test('AppRegistry: encoded metadata cannot silently exceed its per-pin commitment', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'app-registry-overhead-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const registry = new AppRegistry(dir)
  const key = '9'.repeat(64)
  registry.set(key, { type: 'drive', description: 'x'.repeat(70 * 1024), maxStorage: 1 }, { persist: false })
  await t.exception(
    registry.persistEntry(key, { throwOnError: true }),
    /APP_REGISTRY_ENTRY_EXCEEDS_METADATA_COMMITMENT/
  )
})

test('AppRegistry: partial in-memory proof cannot poison durable inventory', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'app-registry-partial-proof-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const registry = new AppRegistry(dir)
  const key = '8'.repeat(64)
  registry.set(key, {
    type: 'drive',
    maxStorage: 4096,
    anchored: true,
    anchoredLength: 2,
    storageProvedDriveVersion: 2
  }, { persist: false })
  await t.exception(
    registry.persistEntry(key, { throwOnError: true }),
    /invalid-storage-proof-tuple/
  )
})

test('AppRegistry: measured Bee debt survives delete, re-add denial, and restart', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'app-registry-journal-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const key = '7'.repeat(64)
  let tombstoneDebt = 0
  let feedBytes = 0
  let feedFork = 0
  let journalBound = 0

  {
    const store = new Corestore(dir)
    await store.ready()
    const registry = new AppRegistry(dir, { store })
    await registry.load()
    registry.set(key, { type: 'drive', maxStorage: 4096, description: 'bounded-history' }, { persist: false })

    let failure = null
    let beforeDenied = 0
    for (let i = 0; i < 500; i++) {
      registry.update(key, { version: `1.0.${i}` }, { persist: false })
      beforeDenied = registry._bee.core.byteLength
      try {
        await registry.persistEntry(key, { throwOnError: true })
      } catch (err) {
        failure = err
        break
      }
    }
    t.is(failure?.code, 'APP_REGISTRY_METADATA_BUDGET_EXCEEDED')
    t.is(registry._bee.core.byteLength, beforeDenied, 'denied put appends no feed bytes')

    const activeDebt = registry._metadataBudgets.get(key).bytes
    registry.delete(key, { persist: false })
    await registry.persistDelete(key, { throwOnError: true, evictedAt: 1_700_000_000_000 })
    tombstoneDebt = registry._metadataBudgets.get(key).bytes
    t.ok(tombstoneDebt > activeDebt, 'retirement tombstone is charged to the same key')

    // Exercise awaited tombstone updates until the historical debt crosses
    // the 48 KiB active threshold while remaining inside the 64 KiB total.
    let tick = 1_700_000_000_001
    while (tombstoneDebt <= 48 * 1024) {
      await registry.markEvicted(key, tick++)
      await registry.clearEvicted(key)
      tombstoneDebt = registry._metadataBudgets.get(key).bytes
    }
    t.ok(tombstoneDebt <= 64 * 1024, 'retirement state remains inside the total allowance')

    const beforeReadd = registry._bee.core.byteLength
    registry.set(key, { type: 'drive', maxStorage: 4096, description: 'must-not-go-live' }, { persist: false })
    await t.exception(
      registry.persistEntry(key, { throwOnError: true }),
      /APP_REGISTRY_KEY_RETIRED_METADATA_EXHAUSTED/
    )
    t.absent(registry.has(key), 'failed re-add rolls memory back to the durable tombstone')
    t.is(registry._bee.core.byteLength, beforeReadd, 'failed re-add appends no feed bytes')

    feedBytes = registry._bee.core.byteLength
    feedFork = registry._bee.core.fork
    journalBound = registry._registryJournal.baselineBytes + 64 * 1024
    t.ok(feedBytes <= journalBound, 'feed remains within baseline plus one historical-key allowance')
    await store.close()
  }

  const physicalBytes = await physicalTreeBytes(dir)
  t.ok(physicalBytes > 0, 'fixture observes real Corestore filesystem bytes')
  t.ok(physicalBytes < 8 * 1024 * 1024, 'bounded journal fixture has a finite physical footprint')

  {
    const store = new Corestore(dir)
    await store.ready()
    const restarted = new AppRegistry(dir, { store })
    const entries = await restarted.load()
    t.is(entries.length, 0, 'durable tombstone is not replayed as an app')
    t.absent(restarted.has(key))
    t.is(restarted._metadataBudgets.get(key).bytes, tombstoneDebt, 'exact debt survives restart')
    t.is(restarted._bee.core.byteLength, feedBytes)
    t.is(restarted._bee.core.fork, feedFork)
    t.ok(restarted._bee.core.byteLength <= journalBound)
    await store.close()
  }
})

test('AppRegistry: catalog keeps drive entries while deduplicating apps by appId', (t) => {
  const registry = new AppRegistry(null)

  registry.set('a'.repeat(64), {
    type: 'app',
    appId: 'peer-chat',
    version: '1.0.0',
    name: 'Peer Chat'
  })

  registry.set('b'.repeat(64), {
    type: 'app',
    appId: 'peer-chat',
    version: '1.1.0',
    name: 'Peer Chat'
  })

  registry.set('c'.repeat(64), {
    type: 'drive',
    appId: 'peer-chat',
    version: '2026.04',
    name: 'Peer Chat Attachments',
    storageClass: 'persistent',
    availabilityClass: 'always-on'
  })

  const catalog = registry.catalog()
  const apps = catalog.filter(entry => entry.type === 'app')
  const drives = catalog.filter(entry => entry.type === 'drive')

  t.is(apps.length, 1, 'only latest app version remains')
  t.is(apps[0].appKey, 'b'.repeat(64), 'latest app version kept')
  t.is(drives.length, 1, 'drive entry is retained')
  t.is(drives[0].appKey, 'c'.repeat(64), 'drive entry key is preserved')
  t.is(drives[0].storageClass, 'persistent', 'storage class is exposed')
  t.is(drives[0].availabilityClass, 'always-on', 'availability class is exposed')
})

test('AppRegistry: catalogByType and catalogForBroadcast include content metadata', (t) => {
  const registry = new AppRegistry(null)
  registry.set('d'.repeat(64), {
    type: 'drive',
    parentKey: 'e'.repeat(64),
    mountPath: '/data',
    appId: 'ghost-drive-demo',
    maxStorage: 4096
  })

  const driveCatalog = registry.catalogByType('drive')
  t.is(driveCatalog.length, 1, 'catalogByType returns drive entry')
  t.is(driveCatalog[0].parentKey, 'e'.repeat(64), 'parentKey preserved in catalog')
  t.is(driveCatalog[0].mountPath, '/data', 'mountPath preserved in catalog')

  const broadcast = registry.catalogForBroadcast()
  t.is(broadcast.length, 1, 'broadcast includes entry')
  t.is(broadcast[0].type, 'drive', 'broadcast includes content type')
  t.is(broadcast[0].parentKey, 'e'.repeat(64), 'broadcast includes parentKey')
  t.is(broadcast[0].mountPath, '/data', 'broadcast includes mountPath')
  t.is(broadcast[0].maxStorageBytes, 4096, 'broadcast carries the durable capacity commitment')
})

test('AppRegistry: redacted catalog hides blind/private metadata', (t) => {
  const registry = new AppRegistry(null)
  registry.set('f'.repeat(64), {
    type: 'drive',
    appId: 'ghost-drive-tax-docs',
    name: 'Alice Tax Docs',
    description: 'Sensitive receipts and invoices',
    author: 'alice',
    categories: ['ghost-drive', 'tax'],
    privacyTier: 'p2p-only',
    blind: true,
    storageClass: 'temporary',
    availabilityClass: 'atomic-handoff',
    parentKey: 'a'.repeat(64),
    mountPath: '/private',
    discoveryKey: 'b'.repeat(64),
    maxStorage: 8192
  })

  // Audit 2026-05-19 (Path 3): blind entries are ALWAYS redacted via
  // catalog(), regardless of whether the caller passes redactPrivate.
  // The blind flag is the publisher's privacy commitment — operator
  // config and caller opts cannot override it. Internal code paths
  // that legitimately need unredacted access use appRegistry.get()
  // directly, not the catalog() projection.
  const rawNoOpts = registry.catalog()[0]
  t.is(rawNoOpts.redacted, true, 'catalog() no-opts redacts blind entry (Path 3 contract)')
  t.is(rawNoOpts.name, 'Private Content', 'no-opts call scrubs name')
  t.is(rawNoOpts.driveKey, null, 'no-opts call scrubs drive key')

  const optOut = registry.catalog({ redactPrivate: false })[0]
  t.is(optOut.redacted, true, 'redactPrivate:false STILL redacts blind (audit fix)')
  t.is(optOut.name, 'Private Content', 'opt-out cannot override blind commitment')

  const redacted = registry.catalog({ redactPrivate: true })[0]
  t.is(redacted.redacted, true, 'redacted flag is set')
  t.is(redacted.name, 'Private Content', 'name is redacted')
  t.is(redacted.description, '', 'description is redacted')
  t.is(redacted.author, 'redacted', 'author is redacted')
  t.alike(redacted.categories, ['private'], 'categories are redacted')
  t.is(redacted.appKey, null, 'address key is hidden')
  t.is(redacted.driveKey, null, 'drive key is hidden from public catalog field')
  t.is(redacted.discoveryKey, null, 'discovery key is hidden')
  t.is(redacted.parentKey, null, 'parent key is hidden')
  t.is(redacted.mountPath, null, 'mount path is hidden')
  t.is(redacted.storageClass, 'temporary', 'redacted catalog preserves storage class')
  t.is(redacted.availabilityClass, 'atomic-handoff', 'redacted catalog preserves availability class')

  const broadcast = registry.catalogForBroadcast()[0]
  t.is(broadcast.maxStorageBytes, 8192, 'blind broadcast keeps the capacity commitment while redacting content metadata')
  t.is(broadcast.redacted, true, 'broadcast marks blind entries redacted')
  t.is(broadcast.appKey, null, 'broadcast hides address key for blind entries')
  t.is(broadcast.appId, null, 'broadcast appId is redacted')
  t.is(broadcast.discoveryKey, null, 'broadcast discovery key is redacted')
  t.is(broadcast.storageClass, 'temporary', 'broadcast includes storage class')
  t.is(broadcast.availabilityClass, 'atomic-handoff', 'broadcast includes availability class')
})

test('AppRegistry: blind entries default to temporary atomic custody', (t) => {
  const registry = new AppRegistry(null)
  registry.set('1'.repeat(64), {
    type: 'drive',
    blind: true
  })

  const entry = registry.get('1'.repeat(64))
  t.is(entry.storageClass, 'temporary', 'blind storage defaults to temporary')
  t.is(entry.availabilityClass, 'atomic-handoff', 'blind availability defaults to atomic handoff')

  const catalog = registry.catalog()[0]
  t.is(catalog.storageClass, 'temporary', 'catalog exposes default storage class')
  t.is(catalog.availabilityClass, 'atomic-handoff', 'catalog exposes default availability class')
})
