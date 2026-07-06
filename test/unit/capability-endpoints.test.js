/**
 * HTTP-level tests for the three new v0.5.1 endpoints:
 *   GET  /.well-known/hiverelay.json
 *   GET  /api/capabilities
 *   GET  /api/authors/<pubkey>/seeding.json
 *   POST /api/authors/seeding.json
 *
 * Uses the same RelayAPI-with-mock-node pattern as api-auth.test.js. Does
 * NOT spin up a real Hyperswarm — just a minimal stub that satisfies the
 * endpoint's reads. This keeps the test fast (<500ms) and deterministic.
 */

import test from 'brittle'
import http from 'http'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { ManifestStore } from 'p2p-hiverelay/core/manifest-store.js'
import { createSeedingManifest } from 'p2p-hiverelay/core/seeding-manifest.js'
import {
  buildCapabilityRoutePayload,
  CAPABILITY_DOC_CACHE_CONTROL,
  resolveCapabilityRoute
} from 'p2p-hiverelay/core/relay-node/api-capabilities.js'

// Build a GENUINE hypercore fork proof: two different blocks each signed
// by the hypercore's OWN key. Post-HR-SVC-004 the fork endpoints require
// this — a signed envelope over junk evidence no longer quarantines.
function genuineForkProof (sodium, b4a) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  const hypercoreKey = b4a.toString(publicKey, 'hex')
  const blockA = b4a.from('head-A@7', 'utf8')
  const blockB = b4a.from('head-B@7-conflict', 'utf8')
  const sigA = b4a.alloc(64); sodium.crypto_sign_detached(sigA, blockA, secretKey)
  const sigB = b4a.alloc(64); sodium.crypto_sign_detached(sigB, blockB, secretKey)
  return {
    hypercoreKey,
    evidenceA: { fromRelay: 'r1', block: b4a.toString(blockA, 'hex'), signature: b4a.toString(sigA, 'hex') },
    evidenceB: { fromRelay: 'r2', block: b4a.toString(blockB, 'hex'), signature: b4a.toString(sigB, 'hex') }
  }
}

function mockRelayNode ({ manifestStore, forkDetector } = {}) {
  return {
    running: true,
    config: {
      storage: null,
      acceptMode: 'review',
      maxPendingRequests: 5000,
      maxConnections: 256,
      regions: ['test-region']
    },
    metrics: { getSummary () { return { uptime: 100 } }, startedAt: Date.now() - 60000 },
    appRegistry: {
      apps: new Map(),
      catalog () {
        return [
          { type: 'app' },
          { type: 'drive' },
          { type: 'dataset' }
        ]
      },
      catalogForBroadcast () { return [] },
      has () { return false },
      get () { return null }
    },
    seededApps: new Map(),
    federation: {
      snapshot () {
        return { followed: [{ url: 'http://a' }], mirrored: [], republished: [] }
      }
    },
    manifestStore,
    forkDetector,
    _checkDelegation: () => {},
    _revokedCertSignatures: new Map(),
    getStats () { return { publicKey: 'deadbeef', connections: 0, seededApps: 0 } },
    getHealthStatus () { return { healthy: true } },
    on () {},
    removeListener () {},
    emit () {},
    async seedApp () { return { ok: true } },
    async unseedApp () {},
    swarm: null,
    relay: null,
    seeder: null,
    router: null,
    serviceRegistry: null,
    seedingRegistry: null,
    reputation: null,
    networkDiscovery: null,
    alertManager: null,
    selfHeal: null,
    torTransport: null,
    dhtRelayWs: null,
    holesailTransport: null,
    _bandwidthReceipt: null,
    paymentManager: null,
    // HyperGateway wants a corestore-shaped thing. We never hit gateway
    // routes in these tests, but RelayAPI.start() constructs the gateway
    // eagerly, so provide a minimal stub that satisfies close().
    store: { close: async () => {}, replicate: () => {} }
  }
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
      res.on('data', (chunk) => { data += chunk })
      res.on('end', () => {
        let parsed
        try { parsed = JSON.parse(data) } catch (_) { parsed = data }
        resolve({ statusCode: res.statusCode, body: parsed, headers: res.headers })
      })
    })
    req.on('error', reject)
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body))
    req.end()
  })
}

function requestRaw (port, method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: '127.0.0.1',
      port,
      method,
      path,
      agent: false,
      headers: { Connection: 'close', ...headers }
    }
    const req = http.request(opts, (res) => {
      let data = ''
      res.on('data', (chunk) => { data += chunk })
      res.on('end', () => {
        let parsed
        try { parsed = JSON.parse(data) } catch (_) { parsed = data }
        resolve({ statusCode: res.statusCode, body: parsed, headers: res.headers })
        req.destroy()
      })
    })
    req.on('error', reject)
    if (body) req.write(body)
    req.end()
  })
}

function makeKeyPair () {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

function validHex () {
  return Array.from({ length: 64 }).map((_, i) => (i % 16).toString(16)).join('')
}

async function setupApi (t, nodeExtras = {}) {
  const { RelayAPI } = await import('p2p-hiverelay/core/relay-node/api.js')
  const node = mockRelayNode(nodeExtras)
  // apiKey must be set for _requireAuth to actually enforce — without it
  // the implicit-localhost fallback lets every local request through.
  const api = new RelayAPI(node, {
    apiPort: 0,
    apiHost: '127.0.0.1',
    apiKey: 'test-key-' + Math.random().toString(36).slice(2)
  })
  await api.start()
  const port = api.server.address().port
  t.teardown(async () => {
    // Full async stop — shuts down DashboardFeed broadcast interval,
    // gateway, rate-limit sweep, and http server. Without this the
    // broadcast interval keeps firing past the test end and the
    // unref'd socket errors surface as ECONNRESET in the next test.
    try { await api.stop() } catch (_) {}
  })
  return { api, node, port }
}

test('capability route helper builds node runtime doc with public cache headers', (t) => {
  const node = mockRelayNode()
  const result = buildCapabilityRoutePayload({
    node,
    version: '1.2.3-test',
    runtime: 'node'
  })

  t.is(result.status, 200)
  t.alike(result.headers, { 'Cache-Control': CAPABILITY_DOC_CACHE_CONTROL })
  t.is(result.payload.version, '1.2.3-test')
  t.is(result.payload.runtime, 'node')
  t.is(result.payload.limitation.accept_mode, 'review')
  t.ok(result.payload.features.includes('capability-doc'))
})

test('capability route helper maps exact public capability routes', (t) => {
  t.alike(resolveCapabilityRoute('GET', '/.well-known/hiverelay.json'), {
    kind: 'capability-doc'
  })
  t.alike(resolveCapabilityRoute('GET', '/api/capabilities'), {
    kind: 'capability-doc'
  })

  t.is(resolveCapabilityRoute('POST', '/.well-known/hiverelay.json'), null)
  t.is(resolveCapabilityRoute('GET', '/.well-known/hiverelay.json/extra'), null)
  t.is(resolveCapabilityRoute('GET', '/api/capabilities/extra'), null)
})

test('GET /.well-known/hiverelay.json returns a valid capability doc', async (t) => {
  const { port } = await setupApi(t)
  const res = await request(port, 'GET', '/.well-known/hiverelay.json')
  t.is(res.statusCode, 200)
  t.is(res.body.schemaVersion, 1)
  t.is(res.body.runtime, 'node')
  t.is(res.body.limitation.accept_mode, 'review')
  t.is(res.body.limitation.max_pending_requests, 5000)
  t.is(res.body.region, 'test-region')
  t.ok(res.body.features.includes('capability-doc'))
  t.ok(res.body.features.includes('federation'))
  t.alike(res.body.federation, { followed: 1, mirrored: 0, republished: 0 })
  t.ok(res.body.catalog)
  t.is(res.body.catalog.total, 3)
  // Cache-Control header hint for CDNs / browsers.
  t.ok(res.headers['cache-control']?.includes('max-age=60'))
  t.ok(res.headers['content-type']?.includes('application/json; charset=utf-8'), 'capability docs are typed as JSON')
  t.is(res.headers['x-content-type-options'], 'nosniff', 'JSON responses disable content sniffing')
})

test('GET /api/capabilities mirrors /.well-known/hiverelay.json', async (t) => {
  const { port } = await setupApi(t)
  const a = await request(port, 'GET', '/.well-known/hiverelay.json')
  const b = await request(port, 'GET', '/api/capabilities')
  t.is(a.statusCode, 200)
  t.is(b.statusCode, 200)
  // Compare semantic content. attestedAt differs by ms between calls
  // (each is a fresh build) and so does signature (signs the
  // attestedAt). That's correct behavior — clients should always see
  // fresh attestation. Strip both for the equivalence check.
  const stripVolatile = (doc) => {
    const { attestedAt, signature, ...rest } = doc
    return rest
  }
  t.alike(stripVolatile(a.body), stripVolatile(b.body),
    'both endpoints return semantically-identical payloads')
})

test('GET /api/authors/<unknown>/seeding.json returns 404 with machine code', async (t) => {
  const store = new ManifestStore({})
  const { port } = await setupApi(t, { manifestStore: store })
  const pubkey = validHex()
  const res = await request(port, 'GET', '/api/authors/' + pubkey + '/seeding.json')
  t.is(res.statusCode, 404)
  t.ok(res.body.error?.startsWith('not-found: '),
    'error string carries machine-readable prefix')
  t.ok(res.headers['content-type']?.includes('application/json; charset=utf-8'), 'error response is typed as JSON')
  t.is(res.headers['x-content-type-options'], 'nosniff', 'error response disables content sniffing')
  t.is(res.headers['cache-control'], 'no-store, max-age=0', 'error response is not cached by default')
})

test('POST /api/authors/seeding.json stores a signed manifest, GET returns it', async (t) => {
  const store = new ManifestStore({}) // no storagePath → runtime-only
  const { port } = await setupApi(t, { manifestStore: store })

  const kp = makeKeyPair()
  const manifest = createSeedingManifest({
    keyPair: kp,
    relays: [{ url: 'hyperswarm://test', role: 'primary' }],
    drives: [{ driveKey: validHex() }]
  })

  const put = await request(port, 'POST', '/api/authors/seeding.json', manifest)
  t.is(put.statusCode, 200)
  t.ok(put.body.ok)
  t.is(put.body.replaced, false)

  const pubkeyHex = b4a.toString(kp.publicKey, 'hex')
  const got = await request(port, 'GET', '/api/authors/' + pubkeyHex + '/seeding.json')
  t.is(got.statusCode, 200)
  t.is(got.body.signature, manifest.signature)
  t.is(got.body.pubkey, pubkeyHex)
})

test('POST /api/authors/seeding.json rolls back memory when manifest save fails', async (t) => {
  const store = new ManifestStore({})
  store.save = async () => { throw new Error('readonly manifest store') }
  const { port } = await setupApi(t, { manifestStore: store })

  const kp = makeKeyPair()
  const manifest = createSeedingManifest({
    keyPair: kp,
    relays: [{ url: 'hyperswarm://test', role: 'primary' }],
    drives: [{ driveKey: validHex() }]
  })

  const put = await request(port, 'POST', '/api/authors/seeding.json', manifest)
  t.is(put.statusCode, 500)
  t.is(put.body.errorCode, 'persist-failed')
  t.ok(put.body.error?.startsWith('persist-failed: '))

  const pubkeyHex = b4a.toString(kp.publicKey, 'hex')
  t.absent(store.get(pubkeyHex), 'failed save did not leave runtime manifest')
  const got = await request(port, 'GET', '/api/authors/' + pubkeyHex + '/seeding.json')
  t.is(got.statusCode, 404)
})

test('POST with invalid signature is rejected with BAD_REQUEST prefix', async (t) => {
  const store = new ManifestStore({})
  const { port } = await setupApi(t, { manifestStore: store })

  const kp = makeKeyPair()
  const manifest = createSeedingManifest({
    keyPair: kp,
    relays: [{ url: 'hyperswarm://test', role: 'primary' }],
    drives: [{ driveKey: validHex() }]
  })
  // Tamper after signing.
  manifest.drives[0].channel = 'tampered'

  const res = await request(port, 'POST', '/api/authors/seeding.json', manifest)
  t.is(res.statusCode, 400)
  t.ok(res.body.error?.startsWith('bad-request: '))
})

test('POST with stale (older) manifest returns 409 Conflict', async (t) => {
  const store = new ManifestStore({})
  const { port } = await setupApi(t, { manifestStore: store })

  const kp = makeKeyPair()
  const newer = createSeedingManifest({
    keyPair: kp,
    relays: [{ url: 'hyperswarm://a' }],
    drives: [{ driveKey: validHex() }],
    timestamp: 2000
  })
  const older = createSeedingManifest({
    keyPair: kp,
    relays: [{ url: 'hyperswarm://a' }],
    drives: [{ driveKey: validHex() }],
    timestamp: 1000
  })

  const r1 = await request(port, 'POST', '/api/authors/seeding.json', newer)
  t.is(r1.statusCode, 200)
  const r2 = await request(port, 'POST', '/api/authors/seeding.json', older)
  t.is(r2.statusCode, 409, 'stale manifest → 409')
  t.ok(r2.body.error?.startsWith('bad-request: '))
})

test('POST with no manifestStore configured returns 503 unsupported', async (t) => {
  const { port } = await setupApi(t, { manifestStore: null })
  const kp = makeKeyPair()
  const manifest = createSeedingManifest({
    keyPair: kp,
    relays: [{ url: 'hyperswarm://a' }],
    drives: [{ driveKey: validHex() }]
  })
  const res = await request(port, 'POST', '/api/authors/seeding.json', manifest)
  t.is(res.statusCode, 503)
  t.ok(res.body.error?.startsWith('unsupported: '))
})

test('unauthenticated management endpoint returns errorCode auth-required', async (t) => {
  const { port } = await setupApi(t)
  // /api/manage/config requires auth — hit without it.
  const res = await request(port, 'POST', '/api/manage/config', { maxConnections: 100 })
  t.is(res.statusCode, 401)
  t.is(res.body.errorCode, 'auth-required',
    'errorCode field is machine-readable')
  t.ok(res.body.error, 'human-readable error string still present for back-compat')
})

// ─── Signed fork-proof server-side requirement ──────────────────

test('POST /api/forks/proof rejects unsigned bare proofs', async (t) => {
  // Set up node with ForkDetector
  const { ForkDetector } = await import('p2p-hiverelay/core/fork-detector.js')
  const fd = new ForkDetector({})
  const { port } = await setupApi(t, { forkDetector: fd })

  // Bare unsigned proof — pre-v0.6.0 shape
  const res = await request(port, 'POST', '/api/forks/proof', {
    hypercoreKey: 'a'.repeat(64),
    blockIndex: 0,
    evidenceA: { fromRelay: 'r1', block: 'b1', signature: 's1' },
    evidenceB: { fromRelay: 'r2', block: 'b2', signature: 's2' }
  })
  t.is(res.statusCode, 400)
  t.ok(res.body.error?.includes('invalid signed proof'))
})

test('POST /api/forks/proof accepts properly signed envelope', async (t) => {
  const { ForkDetector } = await import('p2p-hiverelay/core/fork-detector.js')
  const { signForkProof } = await import('p2p-hiverelay/core/fork-proof-signing.js')
  const sodium = (await import('sodium-universal')).default
  const b4a = (await import('b4a')).default

  const fd = new ForkDetector({})
  const { port } = await setupApi(t, { forkDetector: fd })

  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_keypair(publicKey, secretKey)

  // A genuine fork proof: two DIFFERENT blocks each signed by the
  // hypercore's own key. Post-HR-SVC-004 the endpoint requires this — a
  // signed envelope over junk evidence no longer quarantines.
  const fork = genuineForkProof(sodium, b4a)
  const signed = signForkProof({
    hypercoreKey: fork.hypercoreKey,
    blockIndex: 7,
    evidence: [fork.evidenceA, fork.evidenceB]
  }, { publicKey, secretKey })

  const res = await request(port, 'POST', '/api/forks/proof', signed)
  t.is(res.statusCode, 200)
  t.ok(res.body.ok)
  t.is(res.body.observer, b4a.toString(publicKey, 'hex'))
  t.ok(fd.isQuarantined(fork.hypercoreKey), 'genuine proof quarantined the drive')
})

test('POST /api/forks/proof rolls back memory when fork save fails', async (t) => {
  const { ForkDetector } = await import('p2p-hiverelay/core/fork-detector.js')
  const { signForkProof } = await import('p2p-hiverelay/core/fork-proof-signing.js')
  const sodium = (await import('sodium-universal')).default
  const b4a = (await import('b4a')).default

  const fd = new ForkDetector({})
  fd.save = async () => { throw new Error('readonly fork store') }
  const { port } = await setupApi(t, { forkDetector: fd })

  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_keypair(publicKey, secretKey)

  const fork = genuineForkProof(sodium, b4a)
  const signed = signForkProof({
    hypercoreKey: fork.hypercoreKey,
    blockIndex: 7,
    evidence: [fork.evidenceA, fork.evidenceB]
  }, { publicKey, secretKey })

  const res = await request(port, 'POST', '/api/forks/proof', signed)
  t.is(res.statusCode, 500)
  t.is(res.body.errorCode, 'persist-failed')
  t.ok(res.body.error?.startsWith('persist-failed: '))
  t.is(fd.list().length, 0, 'failed save did not leave runtime fork proof')
  t.absent(fd.isQuarantined(fork.hypercoreKey), 'failed save did not quarantine the key')
})

test('POST /api/forks/proof rejects tampered signed proof', async (t) => {
  const { ForkDetector } = await import('p2p-hiverelay/core/fork-detector.js')
  const { signForkProof } = await import('p2p-hiverelay/core/fork-proof-signing.js')
  const sodium = (await import('sodium-universal')).default
  const b4a = (await import('b4a')).default

  const fd = new ForkDetector({})
  const { port } = await setupApi(t, { forkDetector: fd })

  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_keypair(publicKey, secretKey)

  const signed = signForkProof({
    hypercoreKey: 'c'.repeat(64),
    blockIndex: 7,
    evidence: [{ fromRelay: 'r1', block: 'b1', signature: 's1' }, { fromRelay: 'r2', block: 'b2', signature: 's2' }]
  }, { publicKey, secretKey })
  // Tamper after signing
  signed.proof.blockIndex = 999

  const res = await request(port, 'POST', '/api/forks/proof', signed)
  t.is(res.statusCode, 400)
  t.ok(res.body.error?.includes('invalid signed proof'))
})

// ─── Per-endpoint rate limit ────────────────────────────────────

test('per-endpoint rate limit triggers on /api/wizard/payout brute force', async (t) => {
  const { port } = await setupApi(t)

  // Send 14 POSTs to /api/wizard/payout — limit is 10/min/IP
  let blockedCount = 0
  for (let i = 0; i < 14; i++) {
    const res = await request(port, 'POST', '/api/wizard/payout', { address: 'attempt-' + i })
    if (res.statusCode === 429) blockedCount++
  }
  t.ok(blockedCount >= 2, 'at least 2 of 14 requests were rate-limited (10/min cap)')
})

test('429 response includes machine-readable errorCode', async (t) => {
  const { port } = await setupApi(t)
  // Burst past the /api/wizard/payout limit (10/min)
  for (let i = 0; i < 10; i++) {
    await request(port, 'POST', '/api/wizard/payout', { address: 'x' })
  }
  const res = await request(port, 'POST', '/api/wizard/payout', { address: 'x' })
  t.is(res.statusCode, 429)
  t.is(res.body.errorCode, 'rate-limited')
  t.ok(res.body.error?.startsWith('rate-limited: '))
  t.is(res.headers['retry-after'], '60')
  t.ok(res.headers['content-type']?.includes('application/json; charset=utf-8'), 'rate-limit response is typed as JSON')
  t.is(res.headers['x-content-type-options'], 'nosniff', 'rate-limit response disables content sniffing')
  t.is(res.headers['cache-control'], 'no-store, max-age=0', 'rate-limit response is not cached by default')
})

test('non-rate-limited endpoints unaffected', async (t) => {
  const { port } = await setupApi(t)
  // /health should always work, no per-endpoint cap
  for (let i = 0; i < 30; i++) {
    const res = await request(port, 'GET', '/health')
    t.is(res.statusCode, 200, 'health unaffected by per-endpoint limit')
    if (res.statusCode !== 200) break
  }
})

// ─── Content-Type validation for POST (audit item 1.6) ──────────
// A POST carrying a non-JSON Content-Type must be rejected with 400 before
// any handler runs, so a body parser is never handed a non-JSON payload.

test('POST with non-JSON Content-Type is rejected with 400', async (t) => {
  const { port } = await setupApi(t)
  // /api/v1/dispatch sits after the global Content-Type gate; the gate fires
  // before its auth check, so a text/plain body is rejected up front.
  const res = await request(port, 'POST', '/api/v1/dispatch', 'route=ai.infer', {
    'Content-Type': 'text/plain'
  })
  t.is(res.statusCode, 400, 'non-JSON Content-Type rejected')
  t.ok(/Content-Type must be application\/json/.test(res.body.error || ''),
    'error explains the JSON requirement')
})

test('POST Content-Type requires exact application/json media type', async (t) => {
  const { port } = await setupApi(t)

  const parameterSmuggle = await request(port, 'POST', '/api/v1/dispatch', { route: 'ai.infer' }, {
    'Content-Type': 'text/plain; application/json'
  })
  t.is(parameterSmuggle.statusCode, 400, 'JSON-looking parameter rejected')

  const jsonp = await request(port, 'POST', '/api/v1/dispatch', { route: 'ai.infer' }, {
    'Content-Type': 'application/jsonp'
  })
  t.is(jsonp.statusCode, 400, 'JSON-looking subtype rejected')

  const jsonWithCharset = await request(port, 'POST', '/api/v1/dispatch', { route: 'ai.infer' }, {
    'Content-Type': 'application/json; charset=utf-8'
  })
  t.not(jsonWithCharset.statusCode, 400, 'application/json parameters still accepted')
})

test('POST with chunked body and no Content-Type is rejected with 400', async (t) => {
  const { port } = await setupApi(t)
  // No Content-Length and no Content-Type makes Node send a chunked request.
  // The content-type gate must still reject it before auth or body parsing.
  const res = await requestRaw(port, 'POST', '/api/v1/dispatch', JSON.stringify({ route: 'ai.infer' }))
  t.is(res.statusCode, 400, 'chunked body without Content-Type rejected')
  t.ok(/Content-Type must be application\/json/.test(res.body.error || ''),
    'error explains the JSON requirement')
  t.is(res.headers.connection, 'close', 'early body rejection closes the connection')
})

test('POST with application/json Content-Type passes the gate', async (t) => {
  const { port } = await setupApi(t)
  // Positive control: same endpoint, correct Content-Type → the gate does NOT
  // fire, so we get past it (401 auth, not the 400 Content-Type rejection).
  const res = await request(port, 'POST', '/api/v1/dispatch', { route: 'ai.infer' }, {
    'Content-Type': 'application/json'
  })
  t.not(res.statusCode, 400, 'JSON Content-Type is not blocked by the gate')
})

// ─── Unknown-route 404 ──────────────────────────────────────────

test('GET an unknown API route returns 404 with an error body', async (t) => {
  const { port } = await setupApi(t)
  const res = await request(port, 'GET', '/api/this-route-does-not-exist')
  t.is(res.statusCode, 404, 'unknown route is 404')
  t.ok(res.body.error, 'error body present')
})
