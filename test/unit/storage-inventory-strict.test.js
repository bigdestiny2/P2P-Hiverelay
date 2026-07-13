import test from 'brittle'
import { mkdtemp, rm, writeFile } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { AppRegistry } from '../../packages/core/core/app-registry.js'
import { AppLifecycle } from '../../packages/core/core/relay-node/app-lifecycle.js'

const K1 = 'a'.repeat(64)

test('AppRegistry JSON rejects an invalid tail without partial hydration', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'registry-strict-json-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  await writeFile(join(dir, 'app-registry.json'), JSON.stringify([
    { appKey: K1, maxStorage: 1024 },
    { appKey: 'B'.repeat(64), maxStorage: 2048 }
  ]))
  const registry = new AppRegistry(dir)
  await t.exception(registry.load(), /invalid-app-key/)
  t.is(registry.size, 0, 'valid prefix is not hydrated before the complete scan passes')

  await writeFile(join(dir, 'app-registry.json'), JSON.stringify([
    { appKey: K1, maxStorage: 1024 },
    { appKey: 'b'.repeat(64), maxStorage: 0 }
  ]))
  await t.exception(registry.load(), /invalid-max-storage/)
  t.is(registry.size, 0)
})

test('AppRegistry Bee rejects a corrupt tail without partial hydration', async (t) => {
  const registry = new AppRegistry(null)
  registry._openBee = async () => ({
    async * createReadStream () {
      yield { key: K1, value: { appKey: K1, maxStorage: 1024 } }
      yield { key: 'not-a-hyperdrive-key', value: { appKey: 'not-a-hyperdrive-key', maxStorage: 1024 } }
    }
  })
  await t.exception(registry.load(), /bee-read-failed/)
  t.is(registry.size, 0)
})

test('drive recovery seal remains pending when inventory validation fails', async (t) => {
  const sealed = []
  const lifecycle = new AppLifecycle({
    appRegistry: {
      async load () { throw new Error('APP_REGISTRY_INVENTORY_FAILED') }
    },
    storageAdmission: {
      markRecoveryReady (kind) { sealed.push(kind) }
    }
  })
  await t.exception(lifecycle.loadRegistry(), /APP_REGISTRY_INVENTORY_FAILED/)
  t.alike(sealed, [])
})

test('AppRegistry restores only a complete durable drive proof tuple', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'registry-proof-tuple-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const row = {
    appKey: K1,
    maxStorage: 4096,
    anchored: true,
    anchoredLength: 3,
    storageProvedDriveVersion: 3,
    storageProvedMetaLength: 3,
    storageProvedBlobLength: 2,
    storageProvedTotalBytes: 1024,
    storageProvedMetaFork: 0,
    storageProvedBlobFork: 1
  }
  await writeFile(join(dir, 'app-registry.json'), JSON.stringify([row]))
  const registry = new AppRegistry(dir)
  await registry.load()
  const restored = registry.get(K1)
  t.is(restored.anchored, true)
  t.is(restored.storageProvedDriveVersion, 3)
  t.is(restored.storageProvedBlobFork, 1)
})

test('AppRegistry demotes a legacy anchor without proof and rejects partial proof inventory', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'registry-proof-legacy-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const path = join(dir, 'app-registry.json')
  await writeFile(path, JSON.stringify([{ appKey: K1, maxStorage: 4096, anchored: true, anchoredLength: 3 }]))
  const legacy = new AppRegistry(dir)
  await legacy.load()
  t.is(legacy.get(K1).anchored, false, 'legacy anchor is never ACK-eligible after restart')
  t.is(legacy.get(K1).storageProvedDriveVersion, null)

  await writeFile(path, JSON.stringify([{
    appKey: K1,
    maxStorage: 4096,
    anchored: true,
    anchoredLength: 3,
    storageProvedDriveVersion: 3
  }]))
  const partial = new AppRegistry(dir)
  await t.exception(partial.load(), /invalid-storage-proof-tuple/)
  t.is(partial.size, 0)
})

test('throwing drive-recovery observers cannot truncate later reseed entries', async (t) => {
  const lifecycle = new AppLifecycle({})
  const processed = []
  const delivered = []
  lifecycle.seedApp = async (appKey) => {
    processed.push(appKey)
    if (appKey === K1) throw new Error('injected first-row failure')
  }
  lifecycle.on('reseed-error', () => { throw new Error('throwing error observer') })
  lifecycle.on('reseed-error', event => delivered.push(['error', event.appKey]))
  lifecycle.on('reseeded', () => { throw new Error('throwing success observer') })
  lifecycle.on('reseeded', event => delivered.push(['ok', event.appKey]))
  const k2 = 'b'.repeat(64)
  const k3 = 'c'.repeat(64)
  await lifecycle.reseedDrives([
    { appKey: K1, maxStorage: 1024 },
    { appKey: k2, maxStorage: 1024 },
    { appKey: k3, maxStorage: 1024 }
  ])
  t.alike(processed, [K1, k2, k3], 'the complete durable drive inventory is attempted')
  t.alike(delivered, [['error', K1], ['ok', k2], ['ok', k3]], 'later observers still receive each result')
})
