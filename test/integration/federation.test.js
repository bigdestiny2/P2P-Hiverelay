/**
 * End-to-end federation tests against a real testnet.
 *
 * Verifies the full follow → /catalog.json fetch → accept-mode gate path
 * with two real RelayNodes communicating over a Hyperswarm testnet.
 */

import test from 'brittle'
import createTestnet from '@hyperswarm/testnet'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import { Federation } from 'p2p-hiverelay/core/federation.js'
import { EventEmitter } from 'events'
import http from 'http'
import path from 'path'
import { tmpdir } from 'os'
import { randomBytes } from 'crypto'
import { mkdirSync } from 'fs'

const FEDERATED_APP_MAX_STORAGE_BYTES = 16 * 1024 * 1024

function tmpStorage () {
  const storage = path.join(tmpdir(), 'hiverelay-fed-test-' + randomBytes(8).toString('hex'))
  mkdirSync(storage, { recursive: true })
  return storage
}

function createNode (testnet, overrides = {}) {
  return new RelayNode({
    storage: tmpStorage(),
    bootstrapNodes: testnet.bootstrap,
    enableMetrics: false,
    ...overrides
  })
}

async function waitFor (fn, timeoutMs = 10000, intervalMs = 200) {
  const start = Date.now()
  while ((Date.now() - start) < timeoutMs) {
    if (await fn()) return true
    await new Promise((resolve) => setTimeout(resolve, intervalMs))
  }
  return false
}

test('e2e federation: follow real peer in review mode → app lands in pending queue', async (t) => {
  const testnet = await createTestnet(3, t.teardown)

  // Source relay: serves a /catalog.json over HTTP. Open accept mode so it
  // accepts a self-seed quickly.
  const src = createNode(testnet, { enableAPI: true, apiPort: 0, apiHost: '127.0.0.1', acceptMode: 'open' })
  // Subscriber: in review mode, follows src.
  const sub = createNode(testnet, { acceptMode: 'review', enableAPI: false })

  t.teardown(async () => {
    await src.stop()
    await sub.stop()
    await testnet.destroy()
  })

  await src.start()
  const srcPort = src.api.server.address().port
  await sub.start()

  // Have src publish a fake app entry into its catalog by adding to appRegistry
  // directly. We don't need a real Hyperdrive here — federation only reads the
  // /catalog.json shape.
  const fakeAppKey = randomBytes(32).toString('hex')
  src.appRegistry.set(fakeAppKey, {
    appId: 'federated-test-app',
    name: 'Federation Test App',
    type: 'app',
    version: '1.0.0',
    privacyTier: 'public',
    maxStorage: FEDERATED_APP_MAX_STORAGE_BYTES,
    seededAt: Date.now()
  })

  // Stub seedApp on subscriber so 'review' mode purely queues (no real seed).
  sub.appRegistry.has = () => false
  sub.seededApps.has = () => false

  // sub follows src
  sub.federation.follow(`http://127.0.0.1:${srcPort}`)

  // Trigger an immediate poll instead of waiting for the 5-min interval.
  await sub.federation._pollAll()

  const queued = sub._pendingRequests.has(fakeAppKey)
  t.ok(queued, 'review mode queued the discovered app')

  const entry = sub._pendingRequests.get(fakeAppKey)
  t.is(entry.source, 'federation', 'pending entry tagged with source=federation')
  t.is(entry.sourceRelay, `http://127.0.0.1:${srcPort}`, 'source relay URL recorded')
  t.is(entry.maxStorageBytes, FEDERATED_APP_MAX_STORAGE_BYTES, 'finite catalog bound reaches the review queue exactly')

  // The same signed/catalogued commitment must reach an auto-accept seed
  // without widening, truncation, or fallback to the subscriber default.
  let accepted = null
  sub._pendingRequests.delete(fakeAppKey)
  sub._resolveAcceptMode = () => 'open'
  sub.seedApp = async (appKey, opts) => { accepted = { appKey, opts } }
  await sub.federation._pollAll()
  t.ok(accepted, 'open-mode federation calls seedApp')
  t.is(accepted.appKey, fakeAppKey)
  t.is(accepted.opts.maxStorage, FEDERATED_APP_MAX_STORAGE_BYTES, 'finite catalog bound reaches seedApp exactly')
})

test('e2e federation: follow real peer in closed mode → app rejected, never queues', async (t) => {
  const testnet = await createTestnet(3, t.teardown)

  const src = createNode(testnet, { enableAPI: true, apiPort: 0, apiHost: '127.0.0.1', acceptMode: 'open' })
  const sub = createNode(testnet, { acceptMode: 'closed', enableAPI: false })

  t.teardown(async () => {
    await src.stop()
    await sub.stop()
    await testnet.destroy()
  })

  await src.start()
  const srcPort = src.api.server.address().port
  await sub.start()

  const fakeAppKey = randomBytes(32).toString('hex')
  src.appRegistry.set(fakeAppKey, {
    appId: 'closed-mode-test-app',
    name: 'Closed Mode Test',
    type: 'app',
    version: '1.0.0',
    privacyTier: 'public',
    maxStorage: FEDERATED_APP_MAX_STORAGE_BYTES,
    seededAt: Date.now()
  })

  sub.appRegistry.has = () => false
  sub.seededApps.has = () => false

  const rejected = []
  sub.federation.on('federation-rejected', info => rejected.push(info))

  sub.federation.follow(`http://127.0.0.1:${srcPort}`)
  await sub.federation._pollAll()

  t.is(sub._pendingRequests.size, 0, 'closed mode never queues anything')
  t.is(rejected.length, 1, 'rejection event emitted for the discovered app')
  t.is(rejected[0].mode, 'closed', 'positive bounded app reaches the closed-mode policy gate')
})

test('federation rejects missing, zero, and unsafe catalog storage bounds', async (t) => {
  const apps = [
    { appKey: randomBytes(32).toString('hex'), type: 'app' },
    { appKey: randomBytes(32).toString('hex'), type: 'app', maxStorageBytes: 0 },
    { appKey: randomBytes(32).toString('hex'), type: 'app', maxStorageBytes: Number.MAX_SAFE_INTEGER + 1 }
  ]
  const server = http.createServer((_req, res) => {
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ apps }))
  })
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  t.teardown(() => new Promise(resolve => server.close(resolve)))

  const node = new EventEmitter()
  node.seededApps = new Set()
  node.appRegistry = new Map()
  node._pendingRequests = new Map()
  node._resolveAcceptMode = () => 'review'
  node._decideAcceptance = () => 'queue'
  const federation = new Federation({ node })
  const rejected = []
  federation.on('federation-rejected', info => rejected.push(info))
  federation.follow(`http://127.0.0.1:${server.address().port}`)

  await federation._pollAll()

  t.is(node._pendingRequests.size, 0, 'invalid bounds never enter the review queue')
  t.is(rejected.length, apps.length)
  t.alike(rejected.map(info => info.reason), [
    'storage-bound-invalid',
    'storage-bound-invalid',
    'storage-bound-invalid'
  ])
})

test('e2e federation: /catalog.json from a real RelayNode advertises federation field', async (t) => {
  const testnet = await createTestnet(2, t.teardown)
  const node = createNode(testnet, { enableAPI: true, apiPort: 0, apiHost: '127.0.0.1', acceptMode: 'review' })
  t.teardown(async () => {
    await node.stop()
    await testnet.destroy()
  })

  await node.start()
  const port = node.api.server.address().port
  // Prime federation state so /catalog.json has something to advertise
  node.federation.follow('http://upstream-a.example')
  node.federation.mirror('http://trusted-b.example', { pubkey: 'b'.repeat(64) })

  // Hit the real HTTP endpoint
  const ok = await waitFor(async () => {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/catalog.json`)
      return res.status === 200
    } catch { return false }
  }, 5000)
  t.ok(ok, 'API came up')

  const data = await fetch(`http://127.0.0.1:${port}/catalog.json`).then(r => r.json())
  t.is(data.acceptMode, 'review', 'catalog.json advertises acceptMode')
  t.ok(data.federation, 'catalog.json carries federation field')
  t.is(data.federation.followed.length, 1, 'follow shows up in catalog.json')
  t.is(data.federation.mirrored.length, 1, 'mirror shows up in catalog.json')
  t.is(data.federation.followed[0].url, 'http://upstream-a.example')
})
