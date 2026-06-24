import test from 'brittle'
import { tmpdir } from 'os'
import { join } from 'path'
import { randomBytes } from 'crypto'
import { AppRegistry } from 'p2p-hiverelay/core/app-registry.js'
import { AppLifecycle } from 'p2p-hiverelay/core/relay-node/app-lifecycle.js'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'

function tmpStorage () {
  return join(tmpdir(), 'hiverelay-lifecycle-persist-' + randomBytes(8).toString('hex'))
}

test('AppLifecycle: failed unseed registry delete keeps live resources intact', async (t) => {
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

  t.ok(registry.has(appKey), 'registry entry restored in memory')
  t.is(destroyed, 0, 'download ranges were not destroyed')
  t.is(closed, 0, 'drive was not closed')
  t.is(left, 0, 'swarm topic was not left')
  t.is(unregistered, 0, 'drive bridge was not unregistered')
})

test('RelayNode: seedApp rolls back registry when explicit registry persist fails', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  t.teardown(async () => {
    try { await node.stop() } catch (_) {}
    try { await node.store.close() } catch (_) {}
  })
  await node.start()

  const appKey = randomBytes(32).toString('hex')
  node.appRegistry.persistEntry = async () => {
    throw new Error('disk full')
  }

  await t.exception(
    node.seedApp(appKey),
    /disk full/,
    'seedApp rejects when the durable registry write fails'
  )

  t.absent(node.appRegistry.has(appKey), 'failed seed is rolled back from memory')
})
