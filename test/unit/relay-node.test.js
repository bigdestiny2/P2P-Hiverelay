import test from 'brittle'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import { ServiceProvider, ServiceRegistry } from 'p2p-hiverelay/core/services/index.js'
import path from 'path'
import { tmpdir } from 'os'
import { randomBytes } from 'crypto'
import { EventEmitter } from 'events'
import { rm, stat } from 'fs/promises'

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

test('RelayNode - custody expiry auto-emits non-serving-proof for blind handoffs with intent', async (t) => {
  const node = new RelayNode({ storage: tmpStorage(), enableAPI: false })
  const now = Date.now()
  const appKey = 'a'.repeat(64)
  const intentId = 'b'.repeat(64)
  const blindContentId = 'c'.repeat(64)
  const closed = []
  const attestedEvents = []
  const recordedProofs = []

  node.appRegistry._filePath = null
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
  const now = Date.now()
  const appKey = 'e'.repeat(64)
  const expiredEvents = []
  const attestedEvents = []
  const errorEvents = []

  node.appRegistry._filePath = null
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
  const now = Date.now()
  const appKey = 'f'.repeat(64)
  const intentId = '0'.repeat(64)
  const errorEvents = []
  const expiredEvents = []

  node.appRegistry._filePath = null
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
