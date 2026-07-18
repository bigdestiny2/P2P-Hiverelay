import test from 'brittle'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import { ServiceProvider, ServiceRegistry } from 'p2p-hiverelay/core/services/index.js'
import path from 'path'
import { tmpdir } from 'os'
import { randomBytes } from 'crypto'
import { EventEmitter } from 'events'
import { mkdir, readFile, rm, stat, writeFile } from 'fs/promises'
import { mkdirSync } from 'fs'
import { createServer } from 'net'

const STORAGE_BOUND = 1024 * 1024

function tmpStorage () {
  const storage = path.join(tmpdir(), 'hiverelay-test-' + randomBytes(8).toString('hex'))
  mkdirSync(storage, { recursive: true })
  return storage
}

async function freeLoopbackPort () {
  const server = createServer()
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  const port = server.address().port
  await new Promise((resolve, reject) => {
    server.close((err) => err ? reject(err) : resolve())
  })
  return port
}

function deferred () {
  let resolvePromise
  let rejectPromise
  const promise = new Promise((resolve, reject) => {
    resolvePromise = resolve
    rejectPromise = reject
  })
  return { promise, resolve: resolvePromise, reject: rejectPromise }
}

function permitFixtureStorageRelease (node) {
  node.storageAdmission = {
    runKeyMutation: (_key, run) => run(),
    release: () => true,
    failClosed: () => {}
  }
  node.appRegistry.setStorageAdmission(null, { requirePhysicalEnforcement: false })
}

test('RelayNode - concurrent start callers share one exact completion authority', async (t) => {
  const gate = deferred()
  const node = Object.create(RelayNode.prototype)
  Object.assign(node, {
    running: false,
    _starting: false,
    _stopping: null,
    _startCompletion: null,
    async _startLifecycle () {
      await gate.promise
      this.running = true
      return this
    }
  })

  const first = node.start()
  const concurrent = node.start()
  t.is(concurrent, first, 'concurrent caller receives the exact first promise')

  gate.resolve()
  t.is(await first, node, 'shared completion resolves to the exact node')
  t.is(node.start(), first, 'already-running start returns the completed authority')

  const failureGate = deferred()
  const failure = new Error('injected relay startup failure')
  const failing = Object.create(RelayNode.prototype)
  Object.assign(failing, {
    running: false,
    _starting: false,
    _stopping: null,
    _startCompletion: null,
    async _startLifecycle () {
      await failureGate.promise
      throw failure
    }
  })
  const rejectedFirst = failing.start()
  const rejectedConcurrent = failing.start()
  t.is(rejectedConcurrent, rejectedFirst, 'rejected concurrent caller shares exact promise')
  failureGate.resolve()
  let observed = null
  try { await rejectedConcurrent } catch (err) { observed = err }
  t.is(observed, failure, 'shared rejection preserves the exact startup error')
})

test('RelayNode - defaults custody to blind mode', (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })

  t.is(node.config.custody.enabled, true, 'custody enabled by default')
  t.is(node.config.custody.defaultMode, 'blind', 'blind custody is the default')
  t.is(node.config.custody.allowTransparent, false, 'transparent custody requires explicit opt-in')
  t.is(node.config.custody.requireEncryptedPayload, true, 'custody requires encrypted payloads')
  t.is(node.config.custody.metadataVisibility, 'redacted', 'blind custody redacts metadata by default')
  t.is(node.config.custody.proofTarget, 'ciphertext', 'proofs target ciphertext')
})

test('RelayNode - hard physical enforcement is explicit or provider-enabled', (t) => {
  const ordinary = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  t.is(ordinary.appRegistry._requirePhysicalEnforcement, false, 'relay-core preserves logical-cap operation')

  const required = new RelayNode({
    storage: tmpStorage(),
    enableAPI: false,
    requirePhysicalEnforcement: true
  })
  t.is(required.appRegistry._requirePhysicalEnforcement, true)

  const provider = {
    schemaVersion: 1,
    async installAbsoluteCeiling () {},
    async inspectAbsoluteCeiling () {}
  }
  const providerEnabled = new RelayNode({
    storage: tmpStorage(),
    enableAPI: false,
    physicalEnforcer: provider
  })
  t.is(providerEnabled.appRegistry._requirePhysicalEnforcement, true)
})

test('RelayNode - applyMode keeps physical enforcement restart-only', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  const originalConfig = node.config

  await t.exception(
    node.applyMode('relay-core', { requirePhysicalEnforcement: true }),
    /physical storage enforcement changes require restart/
  )
  t.is(node.config, originalConfig, 'rejected requirement change leaves config authority untouched')
  t.is(node.appRegistry._requirePhysicalEnforcement, false, 'registry remains in its original logical-only scope')

  const provider = {
    schemaVersion: 1,
    async installAbsoluteCeiling () {},
    async inspectAbsoluteCeiling () {}
  }
  await t.exception(
    node.applyMode('relay-core', { physicalEnforcer: provider }),
    /physical storage enforcement changes require restart/
  )
  t.is(node.storageAdmission.physicalEnforcer, null, 'rejected provider change cannot reach admission authority')

  const enforced = new RelayNode({
    storage: tmpStorage(),
    enableAPI: false,
    requirePhysicalEnforcement: true
  })
  await t.exception(
    enforced.applyMode('relay-core', { requirePhysicalEnforcement: false }),
    /physical storage enforcement changes require restart/
  )
  t.is(enforced.appRegistry._requirePhysicalEnforcement, true, 'rejected downgrade cannot disable registry enforcement')
})

test('RelayNode - relaykernel mode narrows to seed/proof/circuit core', async (t) => {
  const node = new RelayNode({ mode: 'relaykernel', storage: tmpStorage() })
  t.teardown(async () => {
    try { await node.store.close() } catch (_) {}
  })

  t.is(node.mode, 'relaykernel')
  t.is(node.config.productProfile, 'relaykernel')
  t.is(node.config.enableRelay, true, 'circuit relay stays enabled')
  t.is(node.config.enableSeeding, true, 'availability seeding stays enabled')
  t.is(node.config.enableAPI, true, 'HTTP compatibility/API stays enabled')
  t.is(node.config.enableServices, false, 'service plugins disabled')
  t.alike(node.config.plugins, [], 'no service plugins selected')
  t.is(node.config.custody.enabled, false, 'custody is not in the kernel profile')
  t.is(node.config.signedDirectory.enabled, false, 'global signed directory disabled')
  t.is(node.config.federation.enabled, false, 'federation disabled')
  t.alike(node.config.federation.followed, [], 'no followed relays')
  t.alike(node.config.federation.mirrored, [], 'no mirrored relays')
  t.is(node.config.lease.enabled, false, 'lease economy disabled')
  t.is(node.config.payment.enabled, false, 'payment settlement disabled')
  t.is(node.config.subsidy.enabled, false, 'subsidy claims disabled')
  t.is(node.config.acceptMode, 'review', 'operator review remains the seed ingress default')
  t.is(node.config.requireSignedCatalog, true, 'catalog signatures required in the narrowed profile')
})

test('RelayNode - applyMode resets non-kernel surfaces for relaykernel profile', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  t.teardown(async () => {
    try { await node.store.close() } catch (_) {}
  })

  node.config.enableServices = true
  node.config.plugins = ['identity']
  node.config.custody = { ...node.config.custody, enabled: true }
  node.config.signedDirectory = { ...node.config.signedDirectory, enabled: true }
  node.config.federation = { enabled: true, followed: [{ url: 'https://relay.example' }], mirrored: [] }
  node.config.lease = { ...node.config.lease, enabled: true }
  node.config.payment = { ...node.config.payment, enabled: true }
  node.config.subsidy = { ...node.config.subsidy, enabled: true, payoutDestination: 'operator@example.com' }

  await node.applyMode('relaykernel')
  t.is(node.config.enableServices, false)
  t.alike(node.config.plugins, [])
  t.is(node.config.custody.enabled, false)
  t.is(node.config.signedDirectory.enabled, false)
  t.is(node.config.federation.enabled, false)
  t.alike(node.config.federation.followed, [])
  t.is(node.config.lease.enabled, false)
  t.is(node.config.payment.enabled, false)
  t.is(node.config.subsidy.enabled, false)
  t.is(node.config.subsidy.payoutDestination, null)

  await node.applyMode('relay-core')
  t.is(node.config.custody.enabled, true, 'switching back restores relay-core custody default')
  t.is(node.config.enableServices, false, 'relay-core keeps services off')
  t.is(node.config.lease.enabled, false, 'lease defaults remain present after switching back')
})

test('RelayNode - relaykernel constructor ignores non-kernel module overrides', async (t) => {
  const node = new RelayNode({
    mode: 'relaykernel',
    storage: tmpStorage(),
    enableAPI: false,
    enableServices: true,
    plugins: ['identity'],
    custody: { enabled: true, allowTransparent: true, requireEncryptedPayload: false },
    signedDirectory: { enabled: true },
    federation: { enabled: true, followed: [{ url: 'https://relay.example' }], mirrored: [{ url: 'https://mirror.example' }] },
    lease: { enabled: true },
    payment: { enabled: true },
    subsidy: { enabled: true, payoutDestination: 'operator@example.com' }
  })
  t.teardown(async () => {
    try { await node.store.close() } catch (_) {}
  })

  t.is(node.config.productProfile, 'relaykernel')
  t.is(node.config.enableServices, false, 'services remain excluded')
  t.alike(node.config.plugins, [], 'plugins remain excluded')
  t.is(node.config.custody.enabled, false, 'custody remains excluded')
  t.is(node.config.custody.allowTransparent, false, 'transparent custody cannot be smuggled into kernel mode')
  t.is(node.config.custody.requireEncryptedPayload, true, 'encrypted-payload posture preserved')
  t.is(node.config.signedDirectory.enabled, false, 'signed directory remains opt-in outside kernel mode')
  t.is(node.config.federation.enabled, false, 'federation remains excluded')
  t.alike(node.config.federation.followed, [], 'followed relays cleared')
  t.alike(node.config.federation.mirrored, [], 'mirrored relays cleared')
  t.is(node.config.lease.enabled, false)
  t.is(node.config.payment.enabled, false)
  t.is(node.config.subsidy.enabled, false)
  t.is(node.config.subsidy.payoutDestination, null)
})

test('RelayNode - relaykernel locks persisted services overrides off', async (t) => {
  const storage = tmpStorage()
  await mkdir(storage, { recursive: true })
  await writeFile(path.join(storage, 'services.json'), JSON.stringify({
    enabled: true,
    plugins: ['identity']
  }))

  const node = new RelayNode({ mode: 'relaykernel', storage, enableAPI: false })
  t.teardown(async () => {
    try { await node.store.close() } catch (_) {}
    await rm(storage, { recursive: true, force: true })
  })

  await node._loadServicesOverride()
  t.is(node.config.enableServices, false, 'stored services opt-in is ignored')
  t.alike(node.config.plugins, [], 'stored service plugins are cleared')

  const payload = await node.setServicesConfig({ enabled: true, plugins: ['identity'] })
  t.is(payload.enabled, false, 'direct service opt-in remains locked off')
  t.alike(payload.plugins, [], 'direct service plugin selection is cleared')
  t.is(payload.locked, true, 'payload reports the profile lock')

  const persisted = JSON.parse(await readFile(path.join(storage, 'services.json'), 'utf8'))
  t.is(persisted.enabled, false, 'persisted services config is rewritten off')
  t.alike(persisted.plugins, [], 'persisted service plugins are cleared')
  t.is(persisted.lockReason, 'relaykernel-profile')
})

test('RelayNode - startup DHT flush is bounded', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false, dhtFlushTimeoutMs: 5 })
  t.teardown(async () => {
    try { await node.store.close() } catch (_) {}
  })

  node.swarm = { flush: () => new Promise(() => {}) }
  let timeoutEvent = null
  node.on('dht-flush-timeout', (event) => { timeoutEvent = event })

  const started = Date.now()
  const ok = await node._flushDhtForStartup()
  const elapsed = Date.now() - started

  t.is(ok, false, 'timed-out flush is not treated as successful')
  t.ok(timeoutEvent, 'timeout event emitted')
  t.is(timeoutEvent.timeoutMs, 5)
  t.ok(elapsed < 250, 'startup flush returned without waiting on a stuck DHT flush')
})

test('RelayNode - identity file is created owner-only and reloads', async (t) => {
  const storage = tmpStorage()
  const node = new RelayNode({ storage, enableAPI: false })
  t.teardown(async () => {
    try { await node.store.close() } catch (_) {}
    await rm(storage, { recursive: true, force: true })
  })

  const first = await node._loadOrCreateKeyPair()
  const keyPath = path.join(storage, 'relay-identity.json')
  const mode = (await stat(keyPath)).mode & 0o777
  const second = await node._loadOrCreateKeyPair()

  t.is(mode, 0o600, 'relay identity is owner-read/write only')
  t.alike(second.publicKey, first.publicKey, 'public key reloads from disk')
  t.alike(second.secretKey, first.secretKey, 'secret key reloads from disk')
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

test('RelayNode - starts a dedicated gateway once after storage recovery seals', async (t) => {
  const storage = tmpStorage()
  const gatewayPort = await freeLoopbackPort()
  const node = new RelayNode({
    storage,
    enableAPI: true,
    apiHost: '127.0.0.1',
    apiPort: 0,
    gatewayHost: '127.0.0.1',
    gatewayPort,
    enableRelay: false,
    enableServices: false
  })
  t.teardown(async () => {
    if (node.running) await node.stop()
    await rm(storage, { recursive: true, force: true })
  })

  await node.start()
  t.is(node._storageIngressReady, true)
  t.ok(node.gatewayServer && node.gatewayServer.server.listening, 'dedicated gateway starts after recovery')

  await node.stop()
  t.absent(node.gatewayServer)
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

  node.store = { replicate () {} }
  node._storageIngressReady = true

  node._onConnection(fakeConn, { publicKey: remotePub })

  t.is(calls.length, 1, 'bridge addPeer called once')
  t.is(calls[0].meta.remotePubKey, remotePub.toString('hex'), 'remote key forwarded')
  t.is(node.connections.size, 1, 'connection tracked')

  fakeConn.emit('close')
  t.is(node.connections.size, 0, 'connection removed on close')
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

  node.store = { replicate () {} }
  node._storageIngressReady = true

  node._onConnection(fakeConn, { publicKey: remotePub })

  t.is(assigned.length, 1, 'service role assigned once')
  t.is(assigned[0].pubkey, remotePubHex, 'role assigned to remote pubkey')
  t.is(assigned[0].role, 'relay-admin', 'allowlisted peer promoted to relay-admin')
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
  node._storageAdmission = () => ({ allowed: true, availableBytes: STORAGE_BOUND })

  node.seedingRegistry = {
    async getActiveRequests () {
      return [{
        appKey,
        replicationFactor: 2,
        maxStorageBytes: STORAGE_BOUND,
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

test('RelayNode - seed protocol request queues in review mode', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  const appKeyBuf = randomBytes(32)
  const publisherBuf = randomBytes(32)
  const appKeyHex = appKeyBuf.toString('hex')

  node.seeder = { totalBytesStored: 0 }
  node.config.maxStorageBytes = 1024 * 1024
  node.config.acceptMode = 'review'
  node._storageAdmission = () => ({ allowed: true, availableBytes: STORAGE_BOUND })
  node._seedProtocol = {
    acceptSeedRequest () {
      t.fail('should not accept request in review mode')
    }
  }

  node.seedApp = async () => {
    t.fail('should not auto-seed request in review mode')
  }

  await node._onSeedRequest({
    appKey: appKeyBuf,
    publisherPubkey: publisherBuf,
    discoveryKeys: [],
    replicationFactor: 2,
    maxStorageBytes: STORAGE_BOUND,
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
    maxStorageBytes: STORAGE_BOUND,
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
  node._storageIngressReady = true
  node.seeder = { totalBytesStored: 0 }

  let operation = null
  node.policyGuard = {
    check (_appKey, _tier, op) {
      operation = op
      return { allowed: false, reason: 'blocked by test policy' }
    }
  }

  try {
    await node.seedApp('c'.repeat(64), { privacyTier: 'local-first', maxStorage: 1024 * 1024 })
    t.fail('expected policy violation')
  } catch (err) {
    t.ok(err.message.includes('POLICY_VIOLATION'))
  }
  t.is(operation, 'replicate-user-data')
})

test('RelayNode - seedApp can use serve-code policy when strict mode disabled', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  node._storageIngressReady = true
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
    await node.seedApp('d'.repeat(64), { privacyTier: 'local-first', maxStorage: 1024 * 1024 })
    t.fail('expected policy violation')
  } catch (err) {
    t.ok(err.message.includes('POLICY_VIOLATION'))
  }
  t.is(operation, 'serve-code')
})

test('RelayNode - seedApp keeps replicate-user-data policy for drive type when strict mode disabled', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  node._storageIngressReady = true
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
    await node.seedApp('f'.repeat(64), { type: 'drive', privacyTier: 'local-first', maxStorage: 1024 * 1024 })
    t.fail('expected policy violation')
  } catch (err) {
    t.ok(err.message.includes('POLICY_VIOLATION'))
  }
  t.is(operation, 'replicate-user-data')
})

test('RelayNode - seedApp uses encrypted policy operation for blind custody', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  node._storageIngressReady = true
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
      blind: true,
      maxStorage: 1024 * 1024
    })
    t.fail('expected policy violation')
  } catch (err) {
    t.ok(err.message.includes('POLICY_VIOLATION'))
  }
  t.is(operation, 'replicate-encrypted-data')
})

test('RelayNode - custody expiry removes expired temporary atomic entries only', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  permitFixtureStorageRelease(node)
  const now = Date.now()
  const expiredKey = '1'.repeat(64)
  const activeKey = '2'.repeat(64)
  const persistentKey = '3'.repeat(64)
  const closed = []
  const expiredEvents = []

  node.appRegistry._filePath = null
  node.appRegistry.persistDelete = async () => {}
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

test('RelayNode - custody expiry auto-emits non-serving-proof for blind handoffs with intent', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  permitFixtureStorageRelease(node)
  const now = Date.now()
  const appKey = 'a'.repeat(64)
  const intentId = 'b'.repeat(64)
  const blindContentId = 'c'.repeat(64)
  const closed = []
  const attestedEvents = []
  const recordedProofs = []

  node.appRegistry._filePath = null
  node.appRegistry.persistDelete = async () => {}
  node.swarm = {
    keyPair: { publicKey: Buffer.alloc(32, 1), secretKey: Buffer.alloc(64, 2) },
    async leave () {}
  }
  // Minimal fake seedingRegistry — captures the proof the expiry pass
  // tries to record. getCustodyIntent must return a matching intent or
  // createCustodyNonServingProof will throw 'Custody intent not found'.
  node.seedingRegistry = {
    getCustodyIntent: (id) => id === intentId
      ? { intentId, addressKey: appKey, blindContentId, retainUntil: now - 1, publisherPubkey: 'd'.repeat(64) }
      : null,
    recordCustodyNonServingProof: async (entry) => {
      recordedProofs.push(entry)
      return entry
    }
  }
  node.on('custody-non-serving-attested', e => attestedEvents.push(e))

  node.appRegistry.apps.set(appKey, {
    storageClass: 'temporary',
    availabilityClass: 'atomic-handoff',
    blind: true,
    retainUntil: now - 1,
    custodyIntentId: intentId,
    blindContentId,
    discoveryKey: randomBytes(32),
    drive: { async close () { closed.push(appKey) } }
  })

  const result = await node._runCustodyExpiryPass(now)

  t.is(result.expired, 1, 'entry expired')
  t.is(result.attested, 1, 'non-serving-proof auto-emitted')
  t.is(recordedProofs.length, 1, 'recordCustodyNonServingProof called once')
  t.is(recordedProofs[0].intentId, intentId, 'proof references the custody intent')
  t.is(recordedProofs[0].addressKey, appKey, 'proof references the appKey')
  t.is(recordedProofs[0].blindContentId, blindContentId, 'proof carries the blindContentId')
  t.is(recordedProofs[0].notServing, true, 'notServing flag set')
  t.is(recordedProofs[0].notServingReason, 'expired-unseeded', 'reason captured')
  t.is(attestedEvents.length, 1, 'custody-non-serving-attested event emitted')
  t.is(attestedEvents[0].custodyIntentId, intentId)

  await node.appRegistry.flush()
})

test('RelayNode - custody expiry without custodyIntentId expires but does not attest', async (t) => {
  // Older blind entries (pre-custody-pipeline) have retainUntil set but no
  // custodyIntentId. They should still self-remove at expiry; no proof
  // can be signed without an intent to bind against.
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  permitFixtureStorageRelease(node)
  const now = Date.now()
  const appKey = 'e'.repeat(64)
  const expiredEvents = []
  const attestedEvents = []
  const errorEvents = []

  node.appRegistry._filePath = null
  node.appRegistry.persistDelete = async () => {}
  node.swarm = { keyPair: { publicKey: Buffer.alloc(32), secretKey: Buffer.alloc(64) }, async leave () {} }
  let proofCalls = 0
  node.seedingRegistry = {
    getCustodyIntent: () => null,
    recordCustodyNonServingProof: async () => { proofCalls++ }
  }
  node.on('custody-expired', e => expiredEvents.push(e))
  node.on('custody-non-serving-attested', e => attestedEvents.push(e))
  node.on('custody-non-serving-attest-error', e => errorEvents.push(e))

  node.appRegistry.apps.set(appKey, {
    storageClass: 'temporary',
    availabilityClass: 'atomic-handoff',
    blind: true,
    retainUntil: now - 1,
    // custodyIntentId intentionally absent
    discoveryKey: randomBytes(32),
    drive: { async close () {} }
  })

  const result = await node._runCustodyExpiryPass(now)

  t.is(result.expired, 1, 'entry still expires')
  t.is(result.attested, 0, 'no proof attempted without intent linkage')
  t.is(proofCalls, 0, 'recordCustodyNonServingProof not called')
  t.is(attestedEvents.length, 0)
  t.is(errorEvents.length, 0, 'no error event for absent intent (silent skip)')

  await node.appRegistry.flush()
})

test('RelayNode - custody expiry surfaces attest errors but keeps unseed clean', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  permitFixtureStorageRelease(node)
  const now = Date.now()
  const appKey = 'f'.repeat(64)
  const intentId = '0'.repeat(64)
  const errorEvents = []
  const expiredEvents = []

  node.appRegistry._filePath = null
  node.appRegistry.persistDelete = async () => {}
  node.swarm = { keyPair: { publicKey: Buffer.alloc(32, 1), secretKey: Buffer.alloc(64, 2) }, async leave () {} }
  // Intent missing from this relay's registry (federation hasn't gossiped
  // it back yet) — createCustodyNonServingProof throws inside the call.
  node.seedingRegistry = {
    getCustodyIntent: () => null,
    recordCustodyNonServingProof: async () => { throw new Error('should not reach') }
  }
  node.on('custody-expired', e => expiredEvents.push(e))
  node.on('custody-non-serving-attest-error', e => errorEvents.push(e))

  node.appRegistry.apps.set(appKey, {
    storageClass: 'temporary',
    availabilityClass: 'atomic-handoff',
    blind: true,
    retainUntil: now - 1,
    custodyIntentId: intentId,
    discoveryKey: randomBytes(32),
    drive: { async close () {} }
  })

  const result = await node._runCustodyExpiryPass(now)

  t.is(result.expired, 1, 'unseed still succeeds')
  t.is(result.attested, 0, 'no proof when intent missing')
  t.is(expiredEvents.length, 1, 'custody-expired still emitted')
  t.is(errorEvents.length, 1, 'attest error surfaced for observability')
  t.is(errorEvents[0].custodyIntentId, intentId)

  await node.appRegistry.flush()
})

test('RelayNode - witness pass signs expiry-witness for peer relay non-serving-proofs', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  const now = Date.now()
  const intentId = 'a'.repeat(64)
  const appKey = 'b'.repeat(64)
  const peerRelayPubkey = '1'.repeat(64)
  const peerProof = {
    type: 'custody-non-serving-proof',
    intentId,
    addressKey: appKey,
    relayPubkey: peerRelayPubkey,
    notServing: true,
    notServingReason: 'expired-unseeded',
    timestamp: now - 1000,
    signature: 'a'.repeat(128)
  }
  const recordedWitnesses = []
  const attestedEvents = []

  node.appRegistry._filePath = null
  node.swarm = {
    keyPair: { publicKey: Buffer.alloc(32, 9), secretKey: Buffer.alloc(64, 8) },
    async leave () {}
  }
  node.seedingRegistry = {
    _custodyIntents: new Map([[intentId, { intentId, addressKey: appKey, retainUntil: now - 5000, blindContentId: 'c'.repeat(64), publisherPubkey: 'd'.repeat(64) }]]),
    getCustodyIntent: (id) => id === intentId
      ? { intentId, addressKey: appKey, retainUntil: now - 5000, blindContentId: 'c'.repeat(64), publisherPubkey: 'd'.repeat(64) }
      : null,
    getCustodyStatus: () => ({
      intent: { intentId, addressKey: appKey, retainUntil: now - 5000, blindContentId: 'c'.repeat(64), publisherPubkey: 'd'.repeat(64) },
      nonServingProofs: [peerProof],
      expiryWitnesses: []
    }),
    recordCustodyExpiryWitness: async (witness) => {
      recordedWitnesses.push(witness)
      return witness
    }
  }
  node.on('custody-witness-attested', e => attestedEvents.push(e))

  const result = await node._runCustodyExpiryWitnessPass(now)

  t.is(result.checked, 1, 'one expired intent scanned')
  t.is(result.witnessed, 1, 'one witness signed')
  t.is(result.errors, 0)
  t.is(recordedWitnesses.length, 1, 'recordCustodyExpiryWitness invoked')
  t.is(recordedWitnesses[0].intentId, intentId)
  t.is(recordedWitnesses[0].relayPubkey, peerRelayPubkey, 'witness names the subject relay')
  t.ok(recordedWitnesses[0].nonServingProofHash, 'proof-hash carried for verifier')
  t.is(recordedWitnesses[0].catalogPresent, false)
  t.is(attestedEvents.length, 1, 'event emitted')

  await node.appRegistry.flush()
})

test('RelayNode - witness pass skips own non-serving-proofs', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  const now = Date.now()
  const intentId = '2'.repeat(64)
  const myPubkey = Buffer.alloc(32, 7).toString('hex')
  const ownProof = {
    type: 'custody-non-serving-proof',
    intentId,
    relayPubkey: myPubkey,
    notServing: true,
    signature: 'a'.repeat(128)
  }
  let recordCalls = 0

  node.appRegistry._filePath = null
  node.swarm = {
    keyPair: { publicKey: Buffer.alloc(32, 7), secretKey: Buffer.alloc(64, 0) },
    async leave () {}
  }
  node.seedingRegistry = {
    _custodyIntents: new Map([[intentId, { intentId, retainUntil: now - 1000 }]]),
    getCustodyIntent: () => ({ intentId, retainUntil: now - 1000 }),
    getCustodyStatus: () => ({
      intent: { intentId, retainUntil: now - 1000 },
      nonServingProofs: [ownProof],
      expiryWitnesses: []
    }),
    recordCustodyExpiryWitness: async () => { recordCalls++ }
  }

  const result = await node._runCustodyExpiryWitnessPass(now)

  t.is(result.witnessed, 0, 'no witnesses signed for own proof')
  t.is(recordCalls, 0, 'recordCustodyExpiryWitness not invoked')

  await node.appRegistry.flush()
})

test('RelayNode - witness pass deduplicates by (intent, relay) pair', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  const now = Date.now()
  const intentId = '3'.repeat(64)
  const myPubkey = Buffer.alloc(32, 5).toString('hex')
  const peerRelay = '4'.repeat(64)
  const peerProof = {
    type: 'custody-non-serving-proof',
    intentId,
    relayPubkey: peerRelay,
    notServing: true,
    signature: 'a'.repeat(128)
  }
  // Witness already exists from a previous pass.
  const existingWitness = { witnessPubkey: myPubkey, relayPubkey: peerRelay, intentId, signature: 'b'.repeat(128) }
  let recordCalls = 0

  node.appRegistry._filePath = null
  node.swarm = {
    keyPair: { publicKey: Buffer.alloc(32, 5), secretKey: Buffer.alloc(64, 0) },
    async leave () {}
  }
  node.seedingRegistry = {
    _custodyIntents: new Map([[intentId, { intentId, retainUntil: now - 1000 }]]),
    getCustodyIntent: () => ({ intentId, retainUntil: now - 1000 }),
    getCustodyStatus: () => ({
      intent: { intentId, retainUntil: now - 1000 },
      nonServingProofs: [peerProof],
      expiryWitnesses: [existingWitness]
    }),
    recordCustodyExpiryWitness: async () => { recordCalls++ }
  }

  const result = await node._runCustodyExpiryWitnessPass(now)

  t.is(result.witnessed, 0, 'no duplicate witness signed')
  t.is(recordCalls, 0)

  await node.appRegistry.flush()
})

test('RelayNode - witness pass skips intents whose retainUntil has not passed', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  const now = Date.now()
  const intentId = '5'.repeat(64)
  let recordCalls = 0

  node.appRegistry._filePath = null
  node.swarm = {
    keyPair: { publicKey: Buffer.alloc(32, 1), secretKey: Buffer.alloc(64, 0) },
    async leave () {}
  }
  node.seedingRegistry = {
    _custodyIntents: new Map([[intentId, { intentId, retainUntil: now + 60_000 }]]),
    getCustodyIntent: () => ({ intentId, retainUntil: now + 60_000 }),
    getCustodyStatus: () => ({
      intent: { intentId, retainUntil: now + 60_000 },
      nonServingProofs: [],
      expiryWitnesses: []
    }),
    recordCustodyExpiryWitness: async () => { recordCalls++ }
  }

  const result = await node._runCustodyExpiryWitnessPass(now)

  t.is(result.checked, 0, 'not-yet-expired intents not checked')
  t.is(result.skipped, 1)
  t.is(recordCalls, 0)

  await node.appRegistry.flush()
})

test('RelayNode - createCustodyExpiryWitness refuses to witness own proofs', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  const intentId = '6'.repeat(64)

  node.swarm = {
    keyPair: { publicKey: Buffer.alloc(32, 3), secretKey: Buffer.alloc(64) },
    async leave () {}
  }
  node.seedingRegistry = {
    getCustodyIntent: () => ({ intentId }),
    recordCustodyExpiryWitness: async () => { throw new Error('should not reach') }
  }

  const myPubkey = Buffer.alloc(32, 3).toString('hex')
  let threw = null
  try {
    await node.createCustodyExpiryWitness(intentId, myPubkey)
  } catch (err) {
    threw = err
  }
  t.ok(threw, 'throws')
  t.ok(threw.message.includes('SELF_WITNESS_REFUSED'), 'specific error code')
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
        maxStorageBytes: STORAGE_BOUND,
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
