// Tests for the /api/v1/seed + /api/v1/custody/{intent,commit,source-retired}
// publisher-signed REST endpoints. These endpoints do NOT require an operator
// API key — the publisher's Ed25519 signature is the authorization. Same
// trust model as the existing /api/v1/unseed endpoint, extended to the
// publish + custody-pipeline side.

import test from 'brittle'
import http from 'http'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { SeedingRegistry } from 'p2p-hiverelay/core/registry/index.js'
import {
  createCustodyIntent,
  createCustodyCommit,
  createSourceRetired,
  computeReceiptRoot,
  hashHex
} from 'p2p-hiverelay/core/custody-signing.js'
import { serializeSeedRequestForSigning } from 'p2p-hiverelay/core/protocol/seed-request.js'

const API_KEY = 'test-secret-key-12345'

function keyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

function makeMockNode () {
  // Minimal SeedingRegistry — the production class with an in-memory log
  // sink. Its publishCustodyIntent/publishCustodyCommit/publishSourceRetired
  // accept pre-signed entries and validate the embedded Ed25519 signature
  // before appending. That is exactly what /api/v1/custody/* relies on.
  const registry = new SeedingRegistry(null, null)
  const log = []
  registry.localLog = {
    async append (block) { log.push(JSON.parse(b4a.toString(block))) }
  }

  // Track every seedApp call so /api/v1/seed assertions can verify the
  // publisher fields and custody opts get forwarded verbatim.
  const seedCalls = []

  const node = {
    running: true,
    config: { storage: null, registryAutoAccept: false },
    metrics: { getSummary () { return { uptime: 100 } } },
    _catalogEntries: [],
    seededApps: new Map(),
    appRegistry: {
      get () { return null },
      has () { return false },
      apps: new Map(),
      catalog () { return [] },
      catalogForBroadcast () { return [] }
    },
    seedingRegistry: registry,
    appLifecycle: {},
    getStats () { return { running: true } },
    getHealthStatus () { return { healthy: true } },
    async stop () {},
    async seedApp (appKey, opts) {
      seedCalls.push({ appKey, opts })
      return { ok: true, accepted: true }
    },
    async unseedApp () {},
    verifyUnseedRequest () { return { ok: true } },
    broadcastUnseed () {},
    router: { async dispatch () { return { ok: true } } },
    serviceRegistry: null,
    reputation: null,
    networkDiscovery: null,
    relay: null,
    seeder: null,
    swarm: { keyPair: keyPair() },
    on () {},
    emit () {}
  }
  return { node, registry, log, seedCalls }
}

function request (port, method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: '127.0.0.1',
      port,
      method,
      path,
      headers: { 'Content-Type': 'application/json', ...headers }
    }
    const req = http.request(opts, (res) => {
      let data = ''
      res.on('data', (c) => { data += c })
      res.on('end', () => {
        let parsed
        try { parsed = JSON.parse(data) } catch (_) { parsed = data }
        resolve({ statusCode: res.statusCode, body: parsed })
      })
    })
    req.on('error', reject)
    if (body) req.write(JSON.stringify(body))
    req.end()
  })
}

// Build a publisher-signed seed-request body. Uses default Protomux v2
// shape so the signature canonicalizes the same way the relay verifies.
function signSeedRequest (publisherKp, fields = {}) {
  const appKey = b4a.from(fields.appKey || ('aa'.repeat(32)), 'hex')
  const discoveryKeys = (fields.discoveryKeys || []).map(dk => b4a.from(dk, 'hex'))
  const msg = {
    appKey,
    discoveryKeys,
    replicationFactor: fields.replicationFactor != null ? fields.replicationFactor : 3,
    maxStorageBytes: fields.maxStorageBytes != null ? fields.maxStorageBytes : 500 * 1024 * 1024,
    ttlSeconds: fields.ttlSeconds != null ? fields.ttlSeconds : 30 * 24 * 3600,
    bountyRate: fields.bountyRate != null ? fields.bountyRate : 0,
    revocable: fields.revocable !== false,
    unseedFreezeMs: fields.unseedFreezeMs || 0,
    durability: fields.durability || 0,
    publisherPubkey: publisherKp.publicKey,
    publisherSignature: b4a.alloc(64)
  }
  const payload = serializeSeedRequestForSigning(msg)
  sodium.crypto_sign_detached(msg.publisherSignature, payload, publisherKp.secretKey)
  return {
    appKey: b4a.toString(appKey, 'hex'),
    discoveryKeys: discoveryKeys.map(dk => b4a.toString(dk, 'hex')),
    replicationFactor: msg.replicationFactor,
    maxStorageBytes: msg.maxStorageBytes,
    ttlSeconds: msg.ttlSeconds,
    bountyRate: msg.bountyRate,
    revocable: msg.revocable,
    unseedFreezeMs: msg.unseedFreezeMs,
    durability: msg.durability,
    publisherPubkey: b4a.toString(publisherKp.publicKey, 'hex'),
    publisherSignature: b4a.toString(msg.publisherSignature, 'hex')
  }
}

let api = null
let port = 0
let fixture = null

test('publisher-signed: setup', async (t) => {
  const { RelayAPI } = await import('p2p-hiverelay/core/relay-node/api.js')
  fixture = makeMockNode()
  api = new RelayAPI(fixture.node, { apiPort: 0, apiKey: API_KEY, apiHost: '127.0.0.1' })
  await api.start()
  port = api.server.address().port
  t.ok(port > 0)
})

// ─── /api/v1/seed ─────────────────────────────────────────────────────

test('/api/v1/seed: rejects missing publisherPubkey', async (t) => {
  const res = await request(port, 'POST', '/api/v1/seed', {
    appKey: 'aa'.repeat(32),
    publisherSignature: '00'.repeat(64)
  })
  t.is(res.statusCode, 400)
  t.ok(res.body.error.toLowerCase().includes('publisherpubkey'))
})

test('/api/v1/seed: rejects missing publisherSignature', async (t) => {
  const res = await request(port, 'POST', '/api/v1/seed', {
    appKey: 'aa'.repeat(32),
    publisherPubkey: 'bb'.repeat(32)
  })
  t.is(res.statusCode, 400)
  t.ok(res.body.error.toLowerCase().includes('publishersignature'))
})

test('/api/v1/seed: rejects bad signature with 403', async (t) => {
  const publisher = keyPair()
  const body = signSeedRequest(publisher, { appKey: 'cc'.repeat(32) })
  // Tamper with one byte of the signature
  const sigBuf = b4a.from(body.publisherSignature, 'hex')
  sigBuf[0] ^= 1
  body.publisherSignature = b4a.toString(sigBuf, 'hex')

  const res = await request(port, 'POST', '/api/v1/seed', body)
  t.is(res.statusCode, 403)
  t.ok(res.body.error.includes('INVALID_SIGNATURE'))
})

test('/api/v1/seed: accepts valid publisher signature and forwards to seedApp', async (t) => {
  const publisher = keyPair()
  const callsBefore = fixture.seedCalls.length
  const body = signSeedRequest(publisher, {
    appKey: 'dd'.repeat(32),
    replicationFactor: 5,
    ttlSeconds: 7 * 24 * 3600
  })
  const res = await request(port, 'POST', '/api/v1/seed', body)
  t.is(res.statusCode, 200, JSON.stringify(res.body))
  t.ok(res.body.ok)
  t.is(fixture.seedCalls.length, callsBefore + 1, 'seedApp invoked exactly once')
  const last = fixture.seedCalls[fixture.seedCalls.length - 1]
  t.is(last.appKey, 'dd'.repeat(32))
  t.is(last.opts.replicas, 5, 'replicationFactor flows through as replicas')
  t.is(last.opts.ttlDays, 7, 'ttlSeconds converted to ttlDays')
  t.is(last.opts.publisherPubkey, b4a.toString(publisher.publicKey, 'hex'))
  t.is(last.opts.publisherSignature, body.publisherSignature)
})

test('/api/v1/seed: forwards atomic-custody binding fields', async (t) => {
  const publisher = keyPair()
  const intentId = hashHex('seed-test-intent-' + Date.now())
  const body = {
    ...signSeedRequest(publisher, { appKey: 'ee'.repeat(32) }),
    type: 'drive',
    blind: true,
    storageClass: 'temporary',
    availabilityClass: 'atomic-handoff',
    privacyTier: 'p2p-only',
    custodyIntentId: intentId,
    blindContentId: hashHex('blind-content'),
    ciphertextRoot: hashHex('ciphertext-root'),
    contentVersion: 1,
    retainUntil: Date.now() + 30 * 24 * 60 * 60 * 1000
  }
  const res = await request(port, 'POST', '/api/v1/seed', body)
  t.is(res.statusCode, 200, JSON.stringify(res.body))

  const last = fixture.seedCalls[fixture.seedCalls.length - 1]
  t.is(last.opts.blind, true, 'blind=true forwarded — required for auto-receipt')
  t.is(last.opts.storageClass, 'temporary')
  t.is(last.opts.availabilityClass, 'atomic-handoff')
  t.is(last.opts.privacyTier, 'p2p-only')
  t.is(last.opts.custodyIntentId, intentId.toLowerCase(),
    'custodyIntentId forwarded — _recordCustodyReceipt requires this to fire')
  t.is(last.opts.blindContentId, body.blindContentId.toLowerCase())
  t.is(last.opts.ciphertextRoot, body.ciphertextRoot.toLowerCase())
  t.is(last.opts.contentVersion, 1)
  t.is(last.opts.retainUntil, body.retainUntil)
})

test('/api/v1/seed: rejects when custodyIntentId publisher mismatches the intent', async (t) => {
  // Publisher A signs an intent and stores it in the registry.
  const publisherA = keyPair()
  const publisherB = keyPair() // a different publisher
  const intent = createCustodyIntent({
    addressKey: hashHex('addr-mismatch'),
    blindContentId: hashHex('bc-mismatch'),
    ciphertextRoot: hashHex('cr-mismatch'),
    contentVersion: 1,
    requiredReplicas: 3,
    deadline: Date.now() + 60_000,
    retainUntil: Date.now() + 120_000
  }, publisherA)
  await fixture.registry.publishCustodyIntent(intent, null)

  // Now publisher B tries to anchor THEIR seed to publisher A's intent.
  const body = {
    ...signSeedRequest(publisherB, { appKey: 'ff'.repeat(32) }),
    blind: true,
    custodyIntentId: intent.intentId
  }
  const res = await request(port, 'POST', '/api/v1/seed', body)
  t.is(res.statusCode, 403, JSON.stringify(res.body))
  t.ok(res.body.error.includes('CUSTODY_PUBLISHER_MISMATCH'))
})

// ─── /api/v1/custody/intent ────────────────────────────────────────────

test('/api/v1/custody/intent: rejects missing signature', async (t) => {
  const res = await request(port, 'POST', '/api/v1/custody/intent', {
    type: 'custody-intent', intentId: 'a'.repeat(64)
  })
  t.is(res.statusCode, 400)
  t.ok(res.body.error.toLowerCase().includes('signature'))
})

test('/api/v1/custody/intent: accepts publisher-signed entry without operator key', async (t) => {
  const publisher = keyPair()
  const intent = createCustodyIntent({
    addressKey: hashHex('addr-' + Date.now()),
    blindContentId: hashHex('bc-' + Date.now()),
    ciphertextRoot: hashHex('cr-' + Date.now()),
    contentVersion: 1,
    requiredReplicas: 3,
    deadline: Date.now() + 60_000,
    retainUntil: Date.now() + 120_000
  }, publisher)
  const res = await request(port, 'POST', '/api/v1/custody/intent', intent)
  t.is(res.statusCode, 200, JSON.stringify(res.body))
  t.ok(res.body.ok)
  t.is(res.body.intentId, intent.intentId)
})

test('/api/v1/custody/intent: registry rejects tampered signature', async (t) => {
  const publisher = keyPair()
  const intent = createCustodyIntent({
    addressKey: hashHex('addr-tamper'),
    blindContentId: hashHex('bc-tamper'),
    ciphertextRoot: hashHex('cr-tamper'),
    contentVersion: 1,
    requiredReplicas: 3,
    deadline: Date.now() + 60_000,
    retainUntil: Date.now() + 120_000
  }, publisher)
  // Mutate a field after signing — signature should no longer verify
  intent.contentVersion = 2
  const res = await request(port, 'POST', '/api/v1/custody/intent', intent)
  t.is(res.statusCode, 400)
  t.ok(res.body.error)
})

// ─── /api/v1/custody/{id}/commit ───────────────────────────────────────

test('/api/v1/custody/{id}/commit: rejects bad intentId in path', async (t) => {
  const res = await request(port, 'POST', '/api/v1/custody/not-hex/commit', { signature: '00'.repeat(64) })
  t.is(res.statusCode, 400)
  t.ok(res.body.error.includes('intentId'))
})

test('/api/v1/custody/{id}/commit: rejects missing signature', async (t) => {
  const res = await request(port, 'POST', '/api/v1/custody/' + 'b'.repeat(64) + '/commit', {})
  t.is(res.statusCode, 400)
  t.ok(res.body.error.toLowerCase().includes('signature'))
})

test('/api/v1/custody/{id}/commit: accepts publisher-signed commit after quorum', async (t) => {
  // Spin up a fresh publisher chain: intent → 3 receipts → commit
  const publisher = keyPair()
  const relayA = keyPair()
  const relayB = keyPair()
  const relayC = keyPair()
  const blindContentId = hashHex('commit-bc-' + Date.now())
  const ciphertextRoot = hashHex('commit-cr-' + Date.now())
  const addressKey = hashHex('commit-addr-' + Date.now())

  const intent = await fixture.registry.publishCustodyIntent({
    addressKey,
    blindContentId,
    ciphertextRoot,
    contentVersion: 1,
    requiredReplicas: 3,
    deadline: Date.now() + 60_000,
    retainUntil: Date.now() + 120_000
  }, publisher)

  const receipts = []
  for (const relay of [relayA, relayB, relayC]) {
    const r = await fixture.registry.recordCustodyReceipt({
      intentId: intent.intentId,
      addressKey,
      blindContentId,
      ciphertextRoot,
      contentVersion: 1,
      retainUntil: Date.now() + 120_000,
      shardIds: []
    }, relay)
    receipts.push(r)
  }

  const commit = createCustodyCommit({
    intentId: intent.intentId,
    addressKey,
    blindContentId,
    ciphertextRoot,
    contentVersion: 1,
    relayQuorum: receipts.map(r => r.relayPubkey).sort(),
    receiptRoot: computeReceiptRoot(receipts),
    nextAuthority: null
  }, publisher)

  const res = await request(port, 'POST', '/api/v1/custody/' + intent.intentId + '/commit', commit)
  t.is(res.statusCode, 200, JSON.stringify(res.body))
  t.ok(res.body.ok)
})

// ─── /api/v1/custody/{id}/source-retired ───────────────────────────────

test('/api/v1/custody/{id}/source-retired: accepts publisher-signed retirement', async (t) => {
  const publisher = keyPair()
  const blindContentId = hashHex('retire-bc-' + Date.now())
  const ciphertextRoot = hashHex('retire-cr-' + Date.now())
  const addressKey = hashHex('retire-addr-' + Date.now())

  const intent = await fixture.registry.publishCustodyIntent({
    addressKey,
    blindContentId,
    ciphertextRoot,
    contentVersion: 1,
    requiredReplicas: 1,
    deadline: Date.now() + 60_000,
    retainUntil: Date.now() + 120_000
  }, publisher)

  const relay = keyPair()
  const receipt = await fixture.registry.recordCustodyReceipt({
    intentId: intent.intentId,
    addressKey,
    blindContentId,
    ciphertextRoot,
    contentVersion: 1,
    retainUntil: Date.now() + 120_000,
    shardIds: []
  }, relay)

  await fixture.registry.publishCustodyCommit({
    intentId: intent.intentId,
    addressKey,
    blindContentId,
    ciphertextRoot,
    contentVersion: 1,
    relayQuorum: [receipt.relayPubkey],
    receiptRoot: computeReceiptRoot([receipt])
  }, publisher)

  const retired = createSourceRetired({
    intentId: intent.intentId,
    addressKey,
    blindContentId,
    retiredAtVersion: 1,
    nextAuthority: null
  }, publisher)

  const res = await request(port, 'POST', '/api/v1/custody/' + intent.intentId + '/source-retired', retired)
  t.is(res.statusCode, 200, JSON.stringify(res.body))
  t.ok(res.body.ok)
})

// ─── Regression: legacy operator endpoints still need API key ───────────

test('regression: POST /api/custody/intent still 401 without API key', async (t) => {
  // The new /api/v1 endpoints are publisher-signed; the legacy operator
  // endpoints must still gate on the operator API key.
  const res = await request(port, 'POST', '/api/custody/intent', { type: 'custody-intent' })
  t.is(res.statusCode, 401)
  t.ok(res.body.errorCode === 'auth-required')
})

test('regression: POST /seed still 401 without API key', async (t) => {
  const res = await request(port, 'POST', '/seed', { appKey: 'a'.repeat(64) })
  t.is(res.statusCode, 401)
})

// ─── teardown ──────────────────────────────────────────────────────────

test('publisher-signed: teardown', async (t) => {
  if (api && api.server) {
    api.server.close()
    if (api._rateLimitCleanup) clearInterval(api._rateLimitCleanup)
    if (api._dashboardFeed) {
      try { api._dashboardFeed.stop() } catch (_) {}
    }
  }
  t.pass('server closed')
})
