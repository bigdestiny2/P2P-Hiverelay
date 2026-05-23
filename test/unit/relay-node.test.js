import test from 'brittle'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import { ServiceProvider, ServiceRegistry } from 'p2p-hiverelay/core/services/index.js'
import path from 'path'
import { tmpdir } from 'os'
import { randomBytes } from 'crypto'
import { EventEmitter } from 'events'

function tmpStorage () {
  return path.join(tmpdir(), 'hiverelay-test-' + randomBytes(8).toString('hex'))
}

test('RelayNode - defaults custody to blind mode', (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })

  t.is(node.config.custody.enabled, true, 'custody enabled by default')
  t.is(node.config.custody.defaultMode, 'blind', 'blind custody is the default')
  t.is(node.config.custody.allowTransparent, false, 'transparent custody requires explicit opt-in')
  t.is(node.config.custody.requireEncryptedPayload, true, 'custody requires encrypted payloads')
  t.is(node.config.custody.metadataVisibility, 'redacted', 'blind custody redacts metadata by default')
  t.is(node.config.custody.proofTarget, 'ciphertext', 'proofs target ciphertext')
})

test('RelayNode - creates and starts', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  t.ok(node, 'node created')
  t.is(node.running, false, 'not running initially')

  await node.start()
  t.is(node.running, true, 'running after start')

  const stats = node.getStats()
  t.ok(stats.publicKey, 'has public key')
  t.is(stats.seededApps, 0, 'no seeded apps initially')
  t.is(stats.connections, 0, 'no connections initially')

  await node.stop()
  t.is(node.running, false, 'stopped')
})

test('RelayNode - getStats returns expected shape', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  await node.start()

  const stats = node.getStats()
  t.ok(typeof stats.publicKey === 'string')
  t.ok(typeof stats.seededApps === 'number')
  t.ok(typeof stats.connections === 'number')
  t.ok(stats.relay !== null)
  t.ok(stats.seeder !== null)
  t.ok(stats.payment && stats.payment.experimental === true)
  t.ok(stats.distributedDrive && typeof stats.distributedDrive.enabled === 'boolean')

  await node.stop()
})

test('RelayNode - _onConnection attaches distributed-drive peer bridge', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  const remotePub = randomBytes(32)
  const fakeConn = new EventEmitter()
  fakeConn.remotePublicKey = remotePub
  fakeConn.destroy = () => {}

  const calls = []
  node.distributedDriveBridge = {
    addPeer (conn, meta) {
      calls.push({ conn, meta })
      return {}
    }
  }

  const origReplicate = node.store.replicate
  node.store.replicate = () => {}

  node._onConnection(fakeConn, { publicKey: remotePub })

  t.is(calls.length, 1, 'bridge addPeer called once')
  t.is(calls[0].meta.remotePubKey, remotePub.toString('hex'), 'remote key forwarded')
  t.is(node.connections.size, 1, 'connection tracked')

  fakeConn.emit('close')
  t.is(node.connections.size, 0, 'connection removed on close')

  node.store.replicate = origReplicate
})

test('RelayNode - _onConnection assigns relay-admin service role from allowlist', (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  const remotePub = randomBytes(32)
  const remotePubHex = remotePub.toString('hex')
  const fakeConn = new EventEmitter()
  fakeConn.remotePublicKey = remotePub
  fakeConn.destroy = () => {}

  const assigned = []
  node.config.serviceAdminAllowlist = [remotePubHex]
  node.serviceProtocol = {
    attach () {},
    setPeerRole (pubkey, role) {
      assigned.push({ pubkey, role })
    }
  }

  const origReplicate = node.store.replicate
  node.store.replicate = () => {}

  node._onConnection(fakeConn, { publicKey: remotePub })

  t.is(assigned.length, 1, 'service role assigned once')
  t.is(assigned[0].pubkey, remotePubHex, 'role assigned to remote pubkey')
  t.is(assigned[0].role, 'relay-admin', 'allowlisted peer promoted to relay-admin')

  node.store.replicate = origReplicate
})

test('RelayNode - emits started event with publicKey', async (t) => {
  t.plan(1)
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })

  node.on('started', ({ publicKey }) => {
    t.ok(publicKey, 'publicKey emitted')
  })

  await node.start()
  await node.stop()
})

test('RelayNode - applyMode updates mode profile config', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  // Default mode is 'relay-core' (the productProfile default since the
  // mode/productProfile unification). The legacy 'public' name was the
  // pre-unification default and is no longer used as a mode identifier
  // — privacyTier='public' is still a thing on individual entries.
  t.is(node.mode, 'relay-core')

  await node.applyMode('homehive')
  t.is(node.mode, 'homehive')
  t.is(node.config.access.open, false)
  t.is(node.config.pairing.enabled, true)
  t.is(node.config.maxConnections, 32)
})

test('RelayNode - replication health monitor attempts local repair', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false, enableServices: false })
  const appKey = 'a'.repeat(64)
  const accepted = []
  const seeded = []

  node.swarm = { keyPair: { publicKey: randomBytes(32) } }
  node.seeder = { totalBytesStored: 0 }
  node.config.enableSeeding = true
  node.config.registryAutoAccept = true
  node.config.replicationRepairEnabled = true
  node.config.targetReplicaFloor = 2

  node.seedingRegistry = {
    async getActiveRequests () {
      return [{
        appKey,
        replicationFactor: 2,
        maxStorageBytes: 0,
        publisherPubkey: 'b'.repeat(64),
        privacyTier: 'public'
      }]
    },
    async getRelaysForApp () { return [] },
    async recordAcceptance (key, relayPubkey, region) {
      accepted.push({ key, relayPubkey, region })
    }
  }

  node.seedApp = async (key, opts) => {
    seeded.push({ key, opts })
    node.seededApps.set(key, { startedAt: Date.now() })
    return { discoveryKey: 'd'.repeat(64) }
  }

  await node._checkReplicationHealth()

  t.is(seeded.length, 1, 'under-replicated app seeded locally')
  t.is(accepted.length, 1, 'acceptance recorded after repair')
  t.ok(node._replicationHealth.has(appKey), 'replication health entry recorded')
})

test('RelayNode - seed protocol request queues in review mode', (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  const appKeyBuf = randomBytes(32)
  const publisherBuf = randomBytes(32)
  const appKeyHex = appKeyBuf.toString('hex')

  node.seeder = { totalBytesStored: 0 }
  node.config.maxStorageBytes = 1024 * 1024
  node.config.acceptMode = 'review'
  node._seedProtocol = {
    acceptSeedRequest () {
      t.fail('should not accept request in review mode')
    }
  }

  node.seedApp = async () => {
    t.fail('should not auto-seed request in review mode')
  }

  node._onSeedRequest({
    appKey: appKeyBuf,
    publisherPubkey: publisherBuf,
    discoveryKeys: [],
    replicationFactor: 2,
    maxStorageBytes: 0,
    ttlSeconds: 3600,
    bountyRate: 0,
    revocable: true,
    unseedFreezeMs: 0,
    durability: 0
  })

  t.ok(node._pendingRequests.has(appKeyHex), 'request is queued for operator review')
  t.is(node._pendingRequests.get(appKeyHex).source, 'seed-protocol', 'queue entry tracks source')
})

test('RelayNode - replication repair respects closed accept mode', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false, enableServices: false })

  node.swarm = { keyPair: { publicKey: randomBytes(32) } }
  node.seeder = { totalBytesStored: 0 }
  node.seedingRegistry = { async recordAcceptance () {} }
  node.config.enableSeeding = true
  node.config.strictSeedingPrivacy = true
  node.config.acceptMode = 'closed'

  let attemptedSeed = 0
  node.seedApp = async () => {
    attemptedSeed++
  }

  const ok = await node._attemptReplicationRepair({
    appKey: 'a'.repeat(64),
    replicationFactor: 2,
    maxStorageBytes: 0,
    publisherPubkey: 'b'.repeat(64),
    privacyTier: 'public'
  }, {
    relays: [],
    current: 0,
    target: 2,
    missing: 2
  })

  t.is(ok, false, 'repair aborted by closed accept mode')
  t.is(attemptedSeed, 0, 'no local seed attempt made')
})

test('RelayNode - seedApp enforces strict replicate-user-data policy by default', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  node.seeder = { totalBytesStored: 0 }

  let operation = null
  node.policyGuard = {
    check (_appKey, _tier, op) {
      operation = op
      return { allowed: false, reason: 'blocked by test policy' }
    }
  }

  try {
    await node.seedApp('c'.repeat(64), { privacyTier: 'local-first' })
    t.fail('expected policy violation')
  } catch (err) {
    t.ok(err.message.includes('POLICY_VIOLATION'))
  }
  t.is(operation, 'replicate-user-data')
})

test('RelayNode - seedApp can use serve-code policy when strict mode disabled', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  node.seeder = { totalBytesStored: 0 }
  node.config.strictSeedingPrivacy = false

  let operation = null
  node.policyGuard = {
    check (_appKey, _tier, op) {
      operation = op
      return { allowed: false, reason: 'blocked by test policy' }
    }
  }

  try {
    await node.seedApp('d'.repeat(64), { privacyTier: 'local-first' })
    t.fail('expected policy violation')
  } catch (err) {
    t.ok(err.message.includes('POLICY_VIOLATION'))
  }
  t.is(operation, 'serve-code')
})

test('RelayNode - seedApp keeps replicate-user-data policy for drive type when strict mode disabled', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  node.seeder = { totalBytesStored: 0 }
  node.config.strictSeedingPrivacy = false

  let operation = null
  node.policyGuard = {
    check (_appKey, _tier, op) {
      operation = op
      return { allowed: false, reason: 'blocked by test policy' }
    }
  }

  try {
    await node.seedApp('f'.repeat(64), { type: 'drive', privacyTier: 'local-first' })
    t.fail('expected policy violation')
  } catch (err) {
    t.ok(err.message.includes('POLICY_VIOLATION'))
  }
  t.is(operation, 'replicate-user-data')
})

test('RelayNode - seedApp uses encrypted policy operation for blind custody', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  node.seeder = { totalBytesStored: 0 }

  let operation = null
  node.policyGuard = {
    check (_appKey, _tier, op) {
      operation = op
      return { allowed: false, reason: 'blocked by test policy' }
    }
  }

  try {
    await node.seedApp('b'.repeat(64), {
      type: 'drive',
      privacyTier: 'p2p-only',
      blind: true
    })
    t.fail('expected policy violation')
  } catch (err) {
    t.ok(err.message.includes('POLICY_VIOLATION'))
  }
  t.is(operation, 'replicate-encrypted-data')
})

test('RelayNode - custody expiry removes expired temporary atomic entries only', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  const now = Date.now()
  const expiredKey = '1'.repeat(64)
  const activeKey = '2'.repeat(64)
  const persistentKey = '3'.repeat(64)
  const closed = []
  const expiredEvents = []

  node.appRegistry._filePath = null
  node.swarm = {
    async leave () {}
  }
  node.on('custody-expired', event => expiredEvents.push(event))

  node.appRegistry.apps.set(expiredKey, {
    storageClass: 'temporary',
    availabilityClass: 'atomic-handoff',
    blind: true,
    retainUntil: now - 1,
    discoveryKey: randomBytes(32),
    drive: { async close () { closed.push(expiredKey) } }
  })
  node.appRegistry.apps.set(activeKey, {
    storageClass: 'temporary',
    availabilityClass: 'atomic-handoff',
    blind: true,
    retainUntil: now + 60_000,
    discoveryKey: randomBytes(32),
    drive: { async close () { closed.push(activeKey) } }
  })
  node.appRegistry.apps.set(persistentKey, {
    storageClass: 'persistent',
    availabilityClass: 'always-on',
    blind: false,
    retainUntil: now - 1,
    discoveryKey: randomBytes(32),
    drive: { async close () { closed.push(persistentKey) } }
  })

  const result = await node._runCustodyExpiryPass(now)

  t.is(result.checked, 2, 'temporary entries checked')
  t.is(result.expired, 1, 'one expired temporary entry removed')
  t.is(node.appRegistry.has(expiredKey), false, 'expired temporary entry removed from registry')
  t.is(node.appRegistry.has(activeKey), true, 'active temporary entry remains')
  t.is(node.appRegistry.has(persistentKey), true, 'persistent availability entry remains')
  t.alike(closed, [expiredKey], 'expired drive closed')
  t.is(expiredEvents.length, 1, 'expiry event emitted')
  t.is(expiredEvents[0].appKey, expiredKey, 'expiry event names content key')

  await node.appRegistry.flush()
})

test('RelayNode - service supervision restarts failed persistent services', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  let starts = 0
  let stops = 0

  class WatchedService extends ServiceProvider {
    constructor () {
      super()
      this.healthy = true
    }

    manifest () { return { name: 'watched', version: '1.0.0', capabilities: [] } }
    async start () { starts++; this.healthy = true }
    async stop () { stops++ }
    async healthCheck () { return this.healthy }
  }

  const provider = new WatchedService()
  node.serviceRegistry = new ServiceRegistry()
  node.serviceRegistry.register(provider)
  node._serviceContext = { node, store: node.store, config: node.config }
  await node.serviceRegistry.startAll(node._serviceContext)

  provider.healthy = false
  const result = await node._runServiceSupervisionPass()

  t.is(result.checked, 1, 'one service checked')
  t.is(result.restarted, 1, 'failed service restarted')
  t.is(result.failed, 0, 'restart succeeded')
  t.is(starts, 2, 'service start called again')
  t.is(stops, 1, 'service stopped before restart')
  t.is(node.serviceRegistry.services.get('watched').status, 'running', 'service is running after restart')
})

test('RelayNode - replication repair skips non-public tiers in strict privacy mode', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false, enableServices: false })
  const appKey = 'e'.repeat(64)
  const seeded = []

  node.swarm = { keyPair: { publicKey: randomBytes(32) } }
  node.seeder = { totalBytesStored: 0 }
  node.config.enableSeeding = true
  node.config.registryAutoAccept = true
  node.config.replicationRepairEnabled = true
  node.config.strictSeedingPrivacy = true

  node.seedingRegistry = {
    async getActiveRequests () {
      return [{
        appKey,
        replicationFactor: 2,
        maxStorageBytes: 0,
        publisherPubkey: 'f'.repeat(64),
        privacyTier: 'local-first'
      }]
    },
    async getRelaysForApp () { return [] },
    async recordAcceptance () {}
  }

  node.seedApp = async (key) => {
    seeded.push(key)
    return { discoveryKey: 'a'.repeat(64) }
  }

  await node._checkReplicationHealth()

  t.is(seeded.length, 0, 'non-public tier request not auto-repaired in strict mode')
  t.ok(node._replicationHealth.has(appKey), 'health still tracked for skipped request')
})
