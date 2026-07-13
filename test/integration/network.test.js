import test from 'brittle'
import createTestnet from '@hyperswarm/testnet'
import Hyperdrive from 'hyperdrive'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import b4a from 'b4a'
import path from 'path'
import { tmpdir } from 'os'
import { randomBytes } from 'crypto'
import { mkdirSync } from 'fs'

const TEST_MAX_STORAGE_BYTES = 64 * 1024 * 1024

function tmpStorage () {
  const storage = path.join(tmpdir(), 'hiverelay-integ-' + randomBytes(8).toString('hex'))
  mkdirSync(storage, { recursive: true })
  return storage
}

function createNode (testnet, overrides = {}) {
  return new RelayNode({
    storage: tmpStorage(),
    bootstrapNodes: testnet.bootstrap,
    enableAPI: false,
    enableMetrics: false,
    ...overrides
  })
}

async function waitFor (fn, timeoutMs = 15000, intervalMs = 200) {
  const start = Date.now()
  while ((Date.now() - start) < timeoutMs) {
    if (await fn()) return true
    await new Promise(resolve => setTimeout(resolve, intervalMs))
  }
  return false
}

async function authorLocalDrive (node, files) {
  const writer = new Hyperdrive(node.store.session())
  let keyHex = null
  try {
    await writer.ready()
    for (const [filePath, content] of Object.entries(files)) {
      await writer.put(filePath, content)
    }
    keyHex = b4a.toString(writer.key, 'hex')
  } finally {
    await writer.close()
  }

  const probe = new Hyperdrive(node.store.session(), b4a.from(keyHex, 'hex'))
  try {
    await probe.ready()
    if (probe.version <= 0) throw new Error('authored drive did not reopen by key')
  } finally {
    await probe.close()
  }
  return keyHex
}

// ─── Two-node discovery ────────────────────────────────────────────

test('integration: two nodes discover each other via DHT', async (t) => {
  const testnet = await createTestnet(3)
  const nodeA = createNode(testnet)
  const nodeB = createNode(testnet)

  t.teardown(async () => {
    await nodeA.stop()
    await nodeB.stop()
    await testnet.destroy()
  })

  await nodeA.start()
  await nodeB.start()

  t.ok(nodeA.running, 'node A running')
  t.ok(nodeB.running, 'node B running')

  const keyA = b4a.toString(nodeA.swarm.keyPair.publicKey, 'hex')
  const keyB = b4a.toString(nodeB.swarm.keyPair.publicKey, 'hex')
  t.not(keyA, keyB, 'nodes have different public keys')
})

// ─── Hypercore replication between nodes ───────────────────────────

test('integration: node A writes Hypercore, node B replicates it', async (t) => {
  const testnet = await createTestnet(3)
  const nodeA = createNode(testnet)
  const nodeB = createNode(testnet)

  t.teardown(async () => {
    await nodeA.stop()
    await nodeB.stop()
    await testnet.destroy()
  })

  await nodeA.start()
  await nodeB.start()

  // Node A creates a Hypercore and writes data
  const coreA = nodeA.store.get({ name: 'test-core' })
  await coreA.ready()
  await coreA.append(b4a.from('hello'))
  await coreA.append(b4a.from('world'))

  // Node A joins the topic so others can find it
  const topic = coreA.discoveryKey
  nodeA.swarm.join(topic, { server: true, client: true })
  await nodeA.swarm.flush()

  // Node B gets the same core by key and joins the topic
  const coreB = nodeB.store.get({ key: coreA.key })
  nodeB.swarm.join(topic, { server: true, client: true })
  await nodeB.swarm.flush()

  // Wait for replication
  await coreB.ready()
  await coreB.update({ wait: true })

  t.is(coreB.length, 2, 'node B has both blocks')

  const block0 = await coreB.get(0)
  const block1 = await coreB.get(1)
  t.ok(b4a.equals(block0, b4a.from('hello')), 'block 0 matches')
  t.ok(b4a.equals(block1, b4a.from('world')), 'block 1 matches')
})

// ─── seedApp replication ───────────────────────────────────────────

test('integration: seedApp makes Hyperdrive available to other nodes', async (t) => {
  const testnet = await createTestnet(3)
  const publisher = createNode(testnet)
  const seeder = createNode(testnet)

  t.teardown(async () => {
    await publisher.stop()
    await seeder.stop()
    await testnet.destroy()
  })

  await publisher.start()

  // Publisher creates a Hyperdrive and writes a file
  const drive = new Hyperdrive(publisher.store)
  await drive.ready()
  await drive.put('/readme.txt', b4a.from('HiveRelay test file'))

  const appKeyHex = b4a.toString(drive.key, 'hex')

  // Announce the drive
  publisher.swarm.join(drive.discoveryKey, { server: true, client: true })
  await publisher.swarm.flush()

  // Seeder starts and seeds the app by key
  await seeder.start()
  const result = await seeder.seedApp(appKeyHex, { maxStorage: TEST_MAX_STORAGE_BYTES })
  t.ok(result.discoveryKey, 'seedApp returns discoveryKey')
  t.is(seeder.seededApps.size, 1, 'seeder tracks seeded app')

  // Wait for drive replication — the seeder should eventually have the data
  const seederDrive = seeder.seededApps.get(appKeyHex).drive
  await seederDrive.update({ wait: true })

  // Wait for eager download to pull file content
  let content = null
  for (let i = 0; i < 20 && !content; i++) {
    content = await seederDrive.get('/readme.txt')
    if (!content) await new Promise(resolve => setTimeout(resolve, 250))
  }
  t.ok(content, 'seeder downloaded the file')
  t.ok(b4a.equals(content, b4a.from('HiveRelay test file')), 'file content matches')
})

test('integration: seeding registry requests replicate across relays', async (t) => {
  const testnet = await createTestnet(3)
  const nodeA = createNode(testnet, { enableAPI: false, enableServices: false })
  const nodeB = createNode(testnet, { enableAPI: false, enableServices: false })

  t.teardown(async () => {
    await nodeA.stop()
    await nodeB.stop()
    await testnet.destroy()
  })

  await nodeA.start()
  await nodeB.start()

  // Force at least one direct swarm connection by sharing a temporary topic.
  const topicCore = nodeA.store.get({ name: 'registry-sync-topic' })
  await topicCore.ready()
  await topicCore.append(b4a.from('sync'))
  nodeA.swarm.join(topicCore.discoveryKey, { server: true, client: true })
  nodeB.swarm.join(topicCore.discoveryKey, { server: true, client: true })
  await nodeA.swarm.flush()
  await nodeB.swarm.flush()

  const appKey = randomBytes(32)
  const appKeyHex = appKey.toString('hex')
  await nodeA.seedingRegistry.publishRequest({
    appKey,
    discoveryKeys: [randomBytes(32)],
    replicationFactor: 1,
    geoPreference: [],
    maxStorageBytes: TEST_MAX_STORAGE_BYTES,
    bountyRate: 0,
    ttlSeconds: 3600,
    privacyTier: 'public',
    publisherPubkey: nodeA.swarm.keyPair.publicKey
  })

  let replicatedEntry = null
  const replicated = await waitFor(async () => {
    const requests = await nodeB.seedingRegistry.getActiveRequests()
    replicatedEntry = requests.find(r => r.appKey === appKeyHex) || null
    return replicatedEntry !== null
  }, 20000, 250)

  t.is(replicated, true, 'node B indexed node A registry request')
  t.is(replicatedEntry?.maxStorageBytes, TEST_MAX_STORAGE_BYTES, 'finite storage bound replicates exactly')
})

// ─── unseedApp cleanup ─────────────────────────────────────────────

test('integration: unseedApp cleans up drive and topic', async (t) => {
  const testnet = await createTestnet(3)
  const node = createNode(testnet)

  t.teardown(async () => {
    await node.stop()
    await testnet.destroy()
  })

  await node.start()

  const appKey = await authorLocalDrive(node, {
    '/unseed.txt': b4a.from('production unseed fixture')
  })
  await node.seedApp(appKey, { maxStorage: TEST_MAX_STORAGE_BYTES })
  t.is(node.seededApps.size, 1, 'app seeded')
  t.ok(node.storageAdmission.canAcknowledge(`drive:${appKey}`), 'seeded app has committed storage authority')

  await node.unseedApp(appKey)
  t.is(node.seededApps.size, 0, 'app removed after unseed')
  t.is(node.storageAdmission.canAcknowledge(`drive:${appKey}`), false, 'unseed retires storage authority ACK')
})

test('integration: peerless drive without a blob proof fails before durable admission', async (t) => {
  const testnet = await createTestnet(3)
  const node = createNode(testnet)

  t.teardown(async () => {
    await node.stop()
    await testnet.destroy()
  })

  await node.start()
  const fakeKey = randomBytes(32).toString('hex')
  const error = await node.seedApp(fakeKey, { maxStorage: TEST_MAX_STORAGE_BYTES }).then(
    () => null,
    err => err
  )

  t.ok(error, 'peerless drive is rejected')
  t.ok(
    /DRIVE_SIZE_UNRESOLVED|timeout/i.test(error?.message || '') ||
      error?.code === 'STORAGE_SIZE_PROOF_UNAVAILABLE',
    'rejection identifies unresolved authoritative drive size'
  )
  t.is(node.appRegistry.has(fakeKey), false, 'failed proof creates no durable registry entry')
  t.is(node.storageAdmission.canAcknowledge(`drive:${fakeKey}`), false, 'failed proof creates no authority ACK')
})

// ─── Connection events ─────────────────────────────────────────────

test('integration: connection events fire when peers meet', async (t) => {
  const testnet = await createTestnet(3)
  const nodeA = createNode(testnet)
  const nodeB = createNode(testnet)

  t.teardown(async () => {
    await nodeA.stop()
    await nodeB.stop()
    await testnet.destroy()
  })

  // Listen on the RelayNode event emitter
  let gotConnectionEvent = false
  nodeA.on('connection', () => { gotConnectionEvent = true })

  await nodeA.start()
  await nodeB.start()

  // Use a Hypercore to force a real connection (more reliable than raw topic join)
  const core = nodeA.store.get({ name: 'conn-test' })
  await core.ready()
  await core.append(b4a.from('test'))

  nodeA.swarm.join(core.discoveryKey, { server: true, client: true })
  await nodeA.swarm.flush()

  const coreB = nodeB.store.get({ key: core.key })
  nodeB.swarm.join(core.discoveryKey, { server: true, client: true })
  await nodeB.swarm.flush()

  await coreB.ready()
  await coreB.update({ wait: true })

  await waitFor(() => gotConnectionEvent, 1000, 25)
  t.ok(gotConnectionEvent, 'node A emitted connection event')
  t.ok(nodeA.getStats().connections >= 1, 'node A has at least 1 connection')
})

// ─── Circuit relay between streams ─────────────────────────────────

test('integration: circuit relay forwards data between two peers', async (t) => {
  const testnet = await createTestnet(3)
  const relayNode = createNode(testnet)

  t.teardown(async () => {
    await relayNode.stop()
    await testnet.destroy()
  })

  await relayNode.start()

  // Use mock stream objects that the relay's forward() function can attach to.
  // Each mock captures the data callback registered by forward() so we can
  // simulate sending data without creating feedback loops.
  let sourceDataCb = null
  const source = {
    on (event, cb) { if (event === 'data') sourceDataCb = cb },
    write () { return true },
    pause () {},
    resume () {},
    destroy () {}
  }

  const destReceived = []
  const dest = {
    on (event, cb) {},
    write (chunk) { destReceived.push(Buffer.from(chunk)); return true },
    pause () {},
    resume () {},
    destroy () {}
  }

  const circuit = relayNode.relay.createCircuit('test-circuit-1', source, dest)
  t.ok(circuit, 'circuit created')

  // Simulate source sending data — invoke the data callback the relay registered
  sourceDataCb(b4a.from('ping from source'))

  t.is(destReceived.length, 1, 'dest received one chunk')
  t.ok(b4a.equals(destReceived[0], b4a.from('ping from source')), 'data forwarded correctly')

  const stats = relayNode.relay.getStats()
  t.is(stats.activeCircuits, 1, 'one active circuit')
  t.ok(stats.totalBytesRelayed > 0, 'bytes relayed tracked')

  relayNode.relay._closeCircuit('test-circuit-1', 'TEST_DONE')
  t.is(relayNode.relay.getStats().activeCircuits, 0, 'circuit closed')
})

// ─── API integration ───────────────────────────────────────────────

test('integration: HTTP API returns health and status', async (t) => {
  const testnet = await createTestnet(3)
  const port = 9200 + Math.floor(Math.random() * 800)
  const node = createNode(testnet, { enableAPI: true, apiPort: port })

  t.teardown(async () => {
    await node.stop()
    await testnet.destroy()
  })

  await node.start()

  // Health endpoint
  const healthRes = await fetch(`http://127.0.0.1:${port}/health`)
  t.is(healthRes.status, 200, 'health returns 200')
  const health = await healthRes.json()
  t.is(health.ok, true, 'health.ok is true')
  t.is(health.running, true, 'health.running is true')

  // Status endpoint
  const statusRes = await fetch(`http://127.0.0.1:${port}/status`)
  t.is(statusRes.status, 200, 'status returns 200')
  const status = await statusRes.json()
  t.ok(status.publicKey, 'status has publicKey')
  t.is(status.seededApps, 0, 'no seeded apps')
  t.is(typeof status.connections, 'number', 'connections is number')

  // Peers endpoint
  const peersRes = await fetch(`http://127.0.0.1:${port}/peers`)
  const peers = await peersRes.json()
  t.is(typeof peers.count, 'number', 'peers.count is number')
  t.ok(Array.isArray(peers.peers), 'peers.peers is array')
})

// ─── API seed/unseed via HTTP ──────────────────────────────────────

test('integration: HTTP API seed and unseed', async (t) => {
  const testnet = await createTestnet(3)
  const port = 9200 + Math.floor(Math.random() * 800)
  const apiKey = 'test-api-key-' + randomBytes(8).toString('hex')
  const node = createNode(testnet, { enableAPI: true, apiPort: port, apiKey })

  t.teardown(async () => {
    await node.stop()
    await testnet.destroy()
  })

  await node.start()

  const appKey = await authorLocalDrive(node, {
    '/api-seed.txt': b4a.from('production API seed fixture')
  })
  const authHeaders = { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` }

  // Seed via API
  const seedRes = await fetch(`http://127.0.0.1:${port}/seed`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ appKey, maxStorageBytes: TEST_MAX_STORAGE_BYTES })
  })
  t.is(seedRes.status, 200, 'seed returns 200')
  const seedData = await seedRes.json()
  t.is(seedData.ok, true, 'seed response ok')
  t.ok(seedData.discoveryKey, 'seed returns discoveryKey')

  // Check status reflects the seeded app
  const statusRes = await fetch(`http://127.0.0.1:${port}/status`)
  const status = await statusRes.json()
  t.is(status.seededApps, 1, 'status shows 1 seeded app')

  // Unseed via API
  const unseedRes = await fetch(`http://127.0.0.1:${port}/unseed`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ appKey })
  })
  t.is(unseedRes.status, 200, 'unseed returns 200')

  const status2Res = await fetch(`http://127.0.0.1:${port}/status`)
  const status2 = await status2Res.json()
  t.is(status2.seededApps, 0, 'status shows 0 seeded apps after unseed')
})

// ─── Three-node network ────────────────────────────────────────────

test('integration: three nodes form a mesh and replicate data', async (t) => {
  const testnet = await createTestnet(3)
  const nodeA = createNode(testnet)
  const nodeB = createNode(testnet)
  const nodeC = createNode(testnet)

  t.teardown(async () => {
    await nodeA.stop()
    await nodeB.stop()
    await nodeC.stop()
    await testnet.destroy()
  })

  await nodeA.start()
  await nodeB.start()
  await nodeC.start()

  // Node A creates a core and writes data
  const core = nodeA.store.get({ name: 'mesh-test' })
  await core.ready()
  await core.append(b4a.from('block-0'))
  await core.append(b4a.from('block-1'))
  await core.append(b4a.from('block-2'))

  const topic = core.discoveryKey
  nodeA.swarm.join(topic, { server: true, client: true })
  await nodeA.swarm.flush()

  // Both B and C join the topic and get the core
  const coreB = nodeB.store.get({ key: core.key })
  const coreC = nodeC.store.get({ key: core.key })

  nodeB.swarm.join(topic, { server: true, client: true })
  nodeC.swarm.join(topic, { server: true, client: true })
  await nodeB.swarm.flush()
  await nodeC.swarm.flush()

  await coreB.ready()
  await coreC.ready()

  await coreB.update({ wait: true })
  await coreC.update({ wait: true })

  t.is(coreB.length, 3, 'node B replicated all 3 blocks')
  t.is(coreC.length, 3, 'node C replicated all 3 blocks')

  const b2 = await coreC.get(2)
  t.ok(b4a.equals(b2, b4a.from('block-2')), 'node C has correct data')
})

// ─── getStats shape after activity ─────────────────────────────────

test('integration: getStats reflects real activity', async (t) => {
  const testnet = await createTestnet(3)
  const node = createNode(testnet)

  t.teardown(async () => {
    await node.stop()
    await testnet.destroy()
  })

  await node.start()

  const stats = node.getStats()
  t.is(stats.running, true, 'running is true')
  t.ok(stats.publicKey, 'has publicKey')
  t.is(stats.seededApps, 0, 'seededApps starts at 0')
  t.is(stats.connections, 0, 'connections starts at 0')
  t.ok(stats.relay, 'relay stats present')
  t.is(stats.relay.activeCircuits, 0, 'no active circuits')
  t.ok(stats.seeder, 'seeder stats present')
  t.is(stats.seeder.coresSeeded, 0, 'no cores seeded')
})

// ─── Start/stop lifecycle ──────────────────────────────────────────

test('integration: node start/stop/restart lifecycle', async (t) => {
  const testnet = await createTestnet(3)
  const storage = tmpStorage()
  const node = createNode(testnet, { storage })

  t.teardown(async () => {
    if (node.running) await node.stop()
    await testnet.destroy()
  })

  // Start
  await node.start()
  t.is(node.running, true, 'running after start')
  t.ok(node.getStats().publicKey, 'has key after start')

  // Stop
  await node.stop()
  t.is(node.running, false, 'stopped')

  // Restart (new node instance, same storage)
  const node2 = createNode(testnet, { storage })
  await node2.start()
  t.is(node2.running, true, 'restarted')
  t.ok(node2.getStats().publicKey, 'has key after restart')

  await node2.stop()
})
