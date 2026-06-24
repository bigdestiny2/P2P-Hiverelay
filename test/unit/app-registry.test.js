import test from 'brittle'
import { AppRegistry } from 'p2p-hiverelay/core/app-registry.js'

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
    appId: 'ghost-drive-demo'
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
    discoveryKey: 'b'.repeat(64)
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
