import test from 'brittle'
import http from 'http'

const API_KEY = 'test-secret-key-12345'

/**
 * Create a minimal mock RelayNode that satisfies RelayAPI's needs.
 */
function mockRelayNode () {
  const node = {
    running: true,
    config: { storage: null, registryAutoAccept: false },
    metrics: {
      snapshots: [{
        timestamp: Date.now(),
        connections: 1,
        seeder: { totalBytesServed: 2 },
        relay: { totalBytesRelayed: 3 },
        marker: 'raw-history-row',
        internalCredential: 'history-credential-should-not-leak',
        holesail: { connectionKey: 'history-connection-key-should-not-leak' }
      }],
      getSummary () { return { uptime: 100 } },
      toPrometheus () { return '# mock metrics\n' }
    },
    _bandwidthReceipt: {
      _issuedReceipts: [],
      getTotalProvenBandwidth () {
        return 350
      },
      exportReceipts () {
        return [
          { bytesTransferred: 100, timestamp: 1000 },
          { bytesTransferred: 250, timestamp: 2000 }
        ]
      }
    },
    pokerApp: {
      listTables () {
        return [
          { tableKey: 'alpha', writers: 2, length: 5 },
          { tableKey: 'beta', writers: { a: true, b: true, c: true }, length: 8 }
        ]
      }
    },
    _catalogEntries: [
      {
        appKey: '1'.repeat(64),
        type: 'app',
        id: 'peer-chat',
        name: 'Peer Chat',
        version: '1.0.0',
        categories: ['messaging']
      },
      {
        appKey: '2'.repeat(64),
        type: 'drive',
        id: 'ghost-drive-demo',
        name: 'Ghost Demo',
        version: '0.1.0',
        categories: ['ghost-drive', 'files'],
        parentKey: null,
        mountPath: null
      }
    ],
    seededApps: new Map(),
    appRegistry: {
      get () { return null },
      has () { return false },
      apps: new Map(),
      catalog () { return node._catalogEntries },
      catalogForBroadcast () { return [] }
    },
    getStats () { return { running: true, seededApps: 0, connections: 0 } },
    getHealthStatus () { return { healthy: true } },
    async stop () {},
    _seedCalls: [],
    _unseedCalls: [],
    _unseedVerifyCalls: [],
    _unseedBroadcastCalls: [],
    _purgeCalls: [],
    _revocationCalls: [],
    async seedApp (appKey, opts) {
      node._seedCalls.push({ appKey, opts })
      return { ok: true }
    },
    async manualPurge (appKey) {
      node._purgeCalls.push(appKey)
      return { bytes: 21 }
    },
    async unseedApp (appKey) {
      node._unseedCalls.push(appKey)
    },
    verifyUnseedRequest (appKey, publisherPubkey, signature, timestamp) {
      node._unseedVerifyCalls.push({ appKey, publisherPubkey, signature, timestamp })
      return { ok: true }
    },
    broadcastUnseed (appKey, publisherPubkey, signature, timestamp) {
      node._unseedBroadcastCalls.push({ appKey, publisherPubkey, signature, timestamp })
    },
    listRevocations () {
      return [{
        revokedCertSignature: 'A'.repeat(128),
        revokedAt: 10,
        expiresAt: 20,
        primaryPubkey: 'B'.repeat(64),
        reason: 'lost phone',
        secretToken: 'do-not-leak'
      }]
    },
    submitRevocation (revocation, opts) {
      node._revocationCalls.push({ revocation, opts })
      return {
        ok: true,
        revokedCertSignature: typeof revocation.revokedCertSignature === 'string'
          ? revocation.revokedCertSignature
          : 'c'.repeat(128)
      }
    },
    router: {
      async dispatch () {
        return { ok: true }
      }
    },
    serviceRegistry: null,
    reputation: null,
    networkDiscovery: null,
    seedingRegistry: null,
    relay: null,
    seeder: null,
    swarm: null,
    on () {},
    removeListener () {},
    emit () {}
  }
  return node
}

/**
 * Helper: make an HTTP request and return { statusCode, body }.
 */
function request (port, method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: '127.0.0.1',
      port,
      method,
      path,
      headers: {
        'Content-Type': 'application/json',
        ...headers
      }
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
    if (body) req.write(JSON.stringify(body))
    req.end()
  })
}

let api = null
let port = 0
let node = null

test('api-auth: setup server', async (t) => {
  const { RelayAPI } = await import('p2p-hiverelay/core/relay-node/api.js')
  node = mockRelayNode()
  // Use port 0 so the OS picks a free port
  api = new RelayAPI(node, { apiPort: 0, apiKey: API_KEY, apiHost: '127.0.0.1' })

  // Override the DashboardFeed import to avoid WebSocket setup issues
  await api.start()
  port = api.server.address().port
  t.ok(port > 0, 'server started on port ' + port)
})

test('api-auth: bearer token requires an exact match', (t) => {
  const reqFromRemote = (authorization) => ({
    socket: { remoteAddress: '10.0.0.5' },
    headers: authorization ? { authorization } : {}
  })

  t.ok(api._checkAuth(reqFromRemote('Bearer ' + API_KEY)), 'exact bearer token accepted')
  t.absent(api._checkAuth(reqFromRemote('Bearer ' + API_KEY + 'x')), 'longer token rejected')
  t.absent(api._checkAuth(reqFromRemote('Bearer ' + API_KEY.slice(0, -1) + 'x')), 'same-length wrong token rejected')
  t.absent(api._checkAuth(reqFromRemote(API_KEY)), 'missing Bearer prefix rejected')
  t.absent(api._checkAuth(reqFromRemote()), 'missing header rejected')
})

test('api-auth: localhost fallback rejects non-loopback Host and Origin headers', (t) => {
  const noKeyApi = new api.constructor(mockRelayNode(), { apiPort: 0, apiHost: '127.0.0.1' })
  const req = (headers = {}, remoteAddress = '127.0.0.1') => ({
    socket: { remoteAddress },
    headers
  })

  t.ok(noKeyApi._checkAuth(req({ host: '127.0.0.1:9100' })), 'loopback Host authorizes local dev')
  t.ok(noKeyApi._checkAuth(req({ host: 'localhost:9100', origin: 'http://localhost:9100' })), 'loopback Origin authorizes dashboard fetch')
  t.ok(noKeyApi._checkAuth(req({ host: '[::1]:9100', origin: 'http://[::1]:9100' }, '::1')), 'IPv6 loopback Host/Origin authorizes local dev')
  t.absent(noKeyApi._checkAuth(req({ host: 'attacker.test:9100' })), 'DNS-rebound Host is rejected')
  t.absent(noKeyApi._checkAuth(req({ host: '127.0.0.1:9100', origin: 'https://attacker.test' })), 'cross-site Origin is rejected')
  t.absent(noKeyApi._checkAuth(req({ host: 'attacker.test:9100', origin: 'http://attacker.test:9100' })), 'DNS-rebound same-origin Host/Origin is rejected')
  t.absent(noKeyApi._checkAuth(req({ host: '127.0.0.1:9100', origin: 'null' })), 'opaque browser Origin is rejected')
  t.absent(noKeyApi._checkAuth(req({ host: '127.0.0.1:9100' }, '10.0.0.5')), 'remote socket remains rejected')
})

test('api-auth: query-string api keys are not accepted', async (t) => {
  const res = await request(port, 'POST', '/seed?api_key=' + encodeURIComponent(API_KEY), { appKey: 'e'.repeat(64) })
  t.is(res.statusCode, 401, 'query-string API key does not authenticate management write')
  t.ok(api._authFailures.has('/seed'), 'auth-failure route excludes api_key query data')
})

test('api-auth: GET /health includes running package version', async (t) => {
  const res = await request(port, 'GET', '/health')
  t.is(res.statusCode, 200)
  t.is(res.body.running, true)
  t.ok(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(res.body.version), 'health version is semver')
})

test('api-auth: GET /status always returns bounded public status', async (t) => {
  const originalGetStats = node.getStats
  const originalConfig = node.config
  const calls = []

  t.teardown(() => {
    node.getStats = originalGetStats
    node.config = originalConfig
  })

  node.config = { ...node.config, regions: ['NA'] }
  node.getStats = (opts) => {
    calls.push(opts)
    return {
      running: true,
      mode: 'relay-core',
      publicKey: 'b'.repeat(64),
      seededApps: 3,
      connections: 4,
      holesail: { running: true, connectionKey: 'HOLESAIL_SECRET', apiPort: 9100 },
      tor: { running: true, onionAddress: 'secret.onion', socksProxy: '127.0.0.1:9050', activeConnections: 2 },
      disk: { usedPct: 12, mountPath: '/private/data', status: 'ok' },
      registry: { running: true, key: 'registry-secret' },
      accessControl: { pairedDevices: 1 }
    }
  }

  const publicStatus = await request(port, 'GET', '/status')
  t.is(publicStatus.statusCode, 200)
  t.alike(calls[0], { includeSecrets: false })
  t.is(publicStatus.body.publicKey, 'b'.repeat(64))
  t.is(publicStatus.body.region, 'NA')
  t.alike(publicStatus.body.transports.holesail, { running: true })
  t.alike(publicStatus.body.transports.tor, { running: true, activeConnections: 2 })
  t.alike(publicStatus.body.registry, { running: true })

  const authedStatus = await request(port, 'GET', '/status', null, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(authedStatus.statusCode, 200)
  t.alike(calls[1], { includeSecrets: false })
  t.alike(authedStatus.body, publicStatus.body, 'auth does not expand public status payload')

  const json = JSON.stringify(authedStatus.body)
  for (const secret of ['HOLESAIL_SECRET', 'secret.onion', '/private/data', 'registry-secret', 'accessControl', 'apiPort', 'socksProxy']) {
    t.absent(json.includes(secret), secret + ' omitted from /status')
  }
})

test('api-auth: GET /api/gateway returns sanitized public gateway stats', async (t) => {
  const originalGetStats = api._gateway.getStats
  t.teardown(() => { api._gateway.getStats = originalGetStats })
  api._gateway.getStats = () => ({
    cachedDrives: 2.9,
    totalRequests: 7,
    totalBytesServed: 123.8,
    openDriveKeys: ['a'.repeat(64)],
    storePath: '/private/data',
    secretToken: 'do-not-leak'
  })

  const res = await request(port, 'GET', '/api/gateway')
  t.is(res.statusCode, 200)
  t.alike(res.body, {
    cachedDrives: 2,
    totalRequests: 7,
    totalBytesServed: 123
  })
  t.absent(JSON.stringify(res.body).includes('openDriveKeys'))
  t.absent(JSON.stringify(res.body).includes('storePath'))
  t.absent(JSON.stringify(res.body).includes('secretToken'))
  t.absent(JSON.stringify(res.body).includes('do-not-leak'))
})

test('api-auth: GET /api/v1/services returns sanitized public service catalog', async (t) => {
  const original = node.serviceRegistry
  t.teardown(() => { node.serviceRegistry = original })
  node.serviceRegistry = {
    catalog () {
      return [
        {
          name: 'identity',
          version: '1.0.0',
          capabilities: ['verify', 'verify'],
          description: 'Identity verification',
          provider: { secret: true },
          secretToken: 'do-not-leak'
        },
        { name: 'bad\nname', version: '1.0.0' }
      ]
    }
  }

  const res = await request(port, 'GET', '/api/v1/services')
  t.is(res.statusCode, 200)
  t.is(res.headers['cache-control'], 'public, max-age=10')
  t.alike(res.body, {
    services: [{
      name: 'identity',
      version: '1.0.0',
      capabilities: ['verify'],
      description: 'Identity verification'
    }],
    count: 1,
    total: 2,
    truncated: true
  })
  t.absent(JSON.stringify(res.body).includes('secretToken'))
  t.absent(JSON.stringify(res.body).includes('provider'))
  t.absent(JSON.stringify(res.body).includes('do-not-leak'))
})

test('api-auth: GET /api/v1/router returns bounded public router info', async (t) => {
  const original = node.router
  t.teardown(() => { node.router = original })
  node.router = {
    getStats () {
      return { routes: 4 }
    },
    routes () {
      throw new Error('route list should not be materialized')
    },
    pubsub: {
      topics () {
        return ['table/alpha', 'bad\nname', 'x'.repeat(300)]
      },
      topicCount () {
        return 3
      },
      subscriberCount () {
        return 2
      }
    }
  }

  const res = await request(port, 'GET', '/api/v1/router')
  t.is(res.statusCode, 200)
  t.is(res.headers['cache-control'], 'public, max-age=10')
  t.alike(res.body, {
    routes: 4,
    pubsub: {
      topics: ['table/alpha'],
      topicCount: 3,
      subscriberCount: 2,
      truncated: true
    }
  })
})

test('api-auth: legacy /peers uses capped sanitized public peer payload', async (t) => {
  const originalSwarm = node.swarm
  t.teardown(() => { node.swarm = originalSwarm })
  const connections = []
  for (let i = 0; i < 1005; i++) {
    connections.push({ remotePublicKey: Buffer.alloc(32, i % 255), type: 'tcp' })
  }
  node.swarm = { connections }

  const res = await request(port, 'GET', '/peers')
  t.is(res.statusCode, 200)
  t.is(res.body.count, 1000, 'legacy peers response is capped')
  t.is(res.body.total, 1005, 'legacy peers response reports total seen')
  t.is(res.body.truncated, true, 'legacy peers response reports truncation')
  t.is(res.body.peers.length, 1000, 'legacy peers payload array is capped')
  t.is(res.body.peers[0].remotePublicKey, '00'.repeat(32))
  t.is(res.body.peers[0].type, 'tcp')
})

test('api-auth: GET /api/forks/proofs returns bounded sanitized public proofs', async (t) => {
  const originalForkDetector = node.forkDetector
  t.teardown(() => { node.forkDetector = originalForkDetector })
  const records = []
  for (let i = 0; i < 205; i++) {
    records.push({
      hypercoreKey: String(i % 10).repeat(64),
      discoveredAt: 10,
      blockIndex: i,
      evidence: [
        { fromRelay: 'relay-a', block: 'block-a', signature: 'sig-a', secret: 'hidden' },
        { fromRelay: 'relay-b', block: 'block-b', signature: 'sig-b' }
      ],
      resolutionNote: 'do-not-leak',
      secretToken: 'do-not-leak'
    })
  }
  node.forkDetector = { list: () => records }

  const res = await request(port, 'GET', '/api/forks/proofs')
  t.is(res.statusCode, 200)
  t.is(res.body.schemaVersion, 1)
  t.is(res.body.total, 205)
  t.is(res.body.count, 200)
  t.is(res.body.truncated, true)
  t.is(res.body.proofs.length, 200)
  t.alike(res.body.proofs[0].evidence[0], { fromRelay: 'relay-a', block: 'block-a', signature: 'sig-a' })
  t.absent(JSON.stringify(res.body).includes('resolutionNote'))
  t.absent(JSON.stringify(res.body).includes('secretToken'))
  t.absent(JSON.stringify(res.body).includes('do-not-leak'))
})

test('api-auth: detailed custody status requires auth and returns shaped diagnostics', async (t) => {
  const originalRegistry = node.seedingRegistry
  t.teardown(() => { node.seedingRegistry = originalRegistry })
  const intentId = 'a'.repeat(64)
  node.seedingRegistry = {
    getCustodyStatus () {
      return {
        intentId,
        blindContentId: 'b'.repeat(64),
        custodyMode: 'blind',
        requiredReplicas: 1,
        receiptCount: 1,
        quorumReached: true,
        receiptRoot: 'c'.repeat(64),
        relayQuorum: ['d'.repeat(64)],
        receipts: [{
          relayPubkey: 'd'.repeat(64),
          shareIndex: 1,
          shareVerified: true,
          anchored: true,
          relayRegion: 'na',
          signature: '7'.repeat(128),
          addressKey: '9'.repeat(64),
          ciphertextRoot: '8'.repeat(64)
        }],
        pvss: {
          shareScheme: 'pvss-secp256k1-v1',
          shareThreshold: 1,
          commitmentRoot: 'e'.repeat(64),
          shareIndices: [1]
        },
        intent: { shareBundleKey: 'f'.repeat(64) },
        commit: { publisherSignature: 'e'.repeat(128) },
        proofs: [{ nonce: 'proof-secret' }],
        nonServingProofs: [{ signature: 'non-serving-secret' }],
        expiryWitnesses: [{ signature: 'witness-secret' }]
      }
    }
  }

  const publicRes = await request(port, 'GET', `/api/custody/${intentId}/status`)
  t.is(publicRes.statusCode, 200)
  t.absent(publicRes.body.pvss, 'public status omits PVSS diagnostics')
  t.absent(JSON.stringify(publicRes.body).includes('shareBundleKey'), 'public status omits raw intent')

  const denied = await request(port, 'GET', `/api/custody/${intentId}/status?detailed=1`)
  t.is(denied.statusCode, 401, 'detailed custody status requires auth')

  const detailed = await request(port, 'GET', `/api/custody/${intentId}/status?detailed=1`, null, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(detailed.statusCode, 200)
  t.alike(detailed.body.pvss, {
    shareScheme: 'pvss-secp256k1-v1',
    shareThreshold: 1,
    commitmentRoot: 'e'.repeat(64),
    shareIndices: [1]
  })
  t.is(detailed.body.receipts[0].relayRegion, 'na')
  const json = JSON.stringify(detailed.body)
  for (const hidden of ['shareBundleKey', 'publisherSignature', 'proof-secret', 'non-serving-secret', 'witness-secret', '7'.repeat(128), '9'.repeat(64), '8'.repeat(64)]) {
    t.absent(json.includes(hidden), hidden + ' omitted from detailed custody status')
  }
})

test('api-auth: GET /api/reputation returns bounded sanitized public leaderboard', async (t) => {
  const originalReputation = node.reputation
  t.teardown(() => { node.reputation = originalReputation })
  const rows = []
  for (let i = 0; i < 105; i++) {
    rows.push({
      relay: i === 0 ? 'relay-a' : String(i % 10).repeat(64),
      score: 5.555,
      reliability: '90%',
      avgLatencyMs: 10.9,
      uptimeHours: 3.8,
      bytesServed: 900,
      totalChallenges: 10,
      passedChallenges: 9,
      failedChallenges: 1,
      region: 'NA',
      lastActivity: 20,
      firstSeen: 10,
      secretToken: 'do-not-leak'
    })
  }
  node.reputation = { getLeaderboard: () => rows }

  const res = await request(port, 'GET', '/api/reputation')
  t.is(res.statusCode, 200)
  t.is(res.body.length, 100)
  t.alike(res.body[0], {
    relay: 'relay-a',
    score: 5.56,
    reliability: '90%',
    avgLatencyMs: 10,
    uptimeHours: 3,
    bytesServed: 900,
    totalChallenges: 10,
    passedChallenges: 9,
    failedChallenges: 1,
    region: 'NA',
    lastActivity: 20,
    firstSeen: 10
  })
  t.is(res.headers['cache-control'], 'public, max-age=30')
  t.absent(JSON.stringify(res.body).includes('secretToken'))
  t.absent(JSON.stringify(res.body).includes('do-not-leak'))
})

test('api-auth: GET /api/reputation/:pubkey returns sanitized public record', async (t) => {
  const originalReputation = node.reputation
  t.teardown(() => { node.reputation = originalReputation })
  const pubkey = 'a'.repeat(64)
  let lookedUp = null
  node.reputation = {
    getRecord (key) {
      lookedUp = key
      return {
        score: 7.777,
        totalChallenges: 2,
        passedChallenges: 2,
        failedChallenges: 0,
        avgLatencyMs: 12.9,
        totalBytesServed: 123,
        totalUptimeHours: 4.5,
        region: 'EU',
        geoBonus: false,
        firstSeen: 10,
        lastActivity: 20,
        secretToken: 'do-not-leak'
      }
    }
  }

  const res = await request(port, 'GET', '/api/reputation/' + pubkey)
  t.is(res.statusCode, 200)
  t.is(lookedUp, pubkey)
  t.alike(res.body, {
    score: 7.78,
    totalChallenges: 2,
    passedChallenges: 2,
    failedChallenges: 0,
    avgLatencyMs: 12,
    totalBytesServed: 123,
    totalUptimeHours: 4.5,
    region: 'EU',
    geoBonus: false,
    firstSeen: 10,
    lastActivity: 20,
    pubkey
  })
  t.is(res.headers['cache-control'], 'public, max-age=30')
  t.absent(JSON.stringify(res.body).includes('secretToken'))
  t.absent(JSON.stringify(res.body).includes('do-not-leak'))

  lookedUp = null
  const invalid = await request(port, 'GET', '/api/reputation/not-hex')
  t.is(invalid.statusCode, 400)
  t.alike(invalid.body, { error: 'Invalid pubkey' })
  t.is(lookedUp, null, 'invalid pubkey does not reach reputation store')
})

test('api-auth: GET /api/manage/federation returns bounded sanitized management snapshot', async (t) => {
  const originalFederation = node.federation
  t.teardown(() => { node.federation = originalFederation })
  node.federation = {
    snapshot () {
      return {
        followed: [
          { url: 'https://relay.example', pubkey: 'A'.repeat(64), addedAt: 1, secretToken: 'do-not-leak' },
          { url: 'https://user:pass@secret.example', pubkey: 'B'.repeat(64), addedAt: 2 }
        ],
        mirrored: [],
        republished: [{
          appKey: 'C'.repeat(64),
          sourceUrl: 'https://source.example',
          sourcePubkey: 'D'.repeat(64),
          channel: 'stable',
          note: 'bad\nnote',
          addedAt: 3,
          privateKey: 'hidden'
        }],
        followIntervalMs: 5000,
        running: true,
        peerCatalogs: [{
          url: 'https://peer.example',
          apps: [{
            appKey: 'E'.repeat(64),
            publisherPubkey: 'F'.repeat(64),
            secret: 'hidden-app'
          }]
        }]
      }
    }
  }

  const res = await request(port, 'GET', '/api/manage/federation', null, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(res.statusCode, 200)
  t.alike(res.body.followed, [{
    url: 'https://relay.example',
    pubkey: 'a'.repeat(64),
    addedAt: 1
  }])
  t.is(res.body.followedTotal, 2)
  t.ok(res.body.followedTruncated)
  t.is(res.body.republished[0].note, null)
  t.is(res.body.peerCatalogs[0].apps[0].appKey, 'e'.repeat(64))
  const json = JSON.stringify(res.body)
  for (const hidden of ['do-not-leak', 'user:pass', 'privateKey', 'hidden-app']) {
    t.absent(json.includes(hidden), hidden + ' omitted from federation management response')
  }
})

test('api-auth: public overview requests use redacted stats and authenticated requests may include transport secrets', async (t) => {
  const originalGetStats = node.getStats
  const originalConfig = node.config
  const originalHolesail = node.holesailTransport
  const originalTor = node.torTransport
  const originalGatewayStats = api._gateway.getStats
  const calls = []

  t.teardown(() => {
    node.getStats = originalGetStats
    node.config = originalConfig
    node.holesailTransport = originalHolesail
    node.torTransport = originalTor
    api._gateway.getStats = originalGatewayStats
  })

  node.config = { ...node.config, regions: ['NA'], maxStorageBytes: 1000 }
  node.holesailTransport = { connectionKey: 'HOLESAIL_SECRET' }
  node.torTransport = { getInfo: () => ({ running: true, onionAddress: 'secret.onion', socksProxy: '127.0.0.1:9050' }) }
  api._gateway.getStats = () => ({
    cachedDrives: 1,
    totalRequests: 2,
    totalBytesServed: 3,
    storePath: '/private/data'
  })
  node.getStats = (opts) => {
    calls.push(opts)
    return {
      publicKey: 'p'.repeat(64),
      connections: { active: 1 },
      seededApps: 2,
      storage: { totalBytes: 100 },
      served: { totalBytesServed: 33, totalBlocksServed: 4 },
      seeder: { coresSeeded: 1, totalBytesStored: 1, totalBytesServed: 2 }
    }
  }

  const publicOverview = await request(port, 'GET', '/api/overview')
  t.is(publicOverview.statusCode, 200)
  t.alike(calls[0], { includeSecrets: false })
  t.is(publicOverview.body.holesailKey, null, 'public overview does not expose holesail key')
  t.is(publicOverview.body.tor, null, 'public overview does not expose tor info')
  t.is(publicOverview.body.storage.used, 100, 'overview still exposes non-secret measured storage')
  t.is(publicOverview.body.served.bytes, 33, 'overview still exposes non-secret measured served bytes')
  t.alike(publicOverview.body.gateway, {
    cachedDrives: 1,
    totalRequests: 2,
    totalBytesServed: 3
  })
  t.absent(JSON.stringify(publicOverview.body.gateway).includes('storePath'), 'overview gateway stats are sanitized')

  const authedOverview = await request(port, 'GET', '/api/overview', null, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(authedOverview.statusCode, 200)
  t.alike(calls[1], { includeSecrets: true })
  t.is(authedOverview.body.holesailKey, 'HOLESAIL_SECRET')
  t.alike(authedOverview.body.tor, { running: true, onionAddress: 'secret.onion', activeConnections: 0 })
  t.absent(JSON.stringify(authedOverview.body).includes('socksProxy'), 'overview tor details are shaped before response')
})

test('api-auth: disk-critical health gate returns hardened JSON 503', async (t) => {
  node.config.diskHealthGate = true
  node.diskMonitor = {
    getInfo () {
      return { status: 'critical', usedPct: 99, mountPath: '/data' }
    }
  }
  t.teardown(() => {
    node.config.diskHealthGate = false
    delete node.diskMonitor
  })

  const res = await request(port, 'GET', '/health')
  t.is(res.statusCode, 503)
  t.is(res.body.reason, 'disk-critical')
  t.alike(res.body.disk, { usedPct: 99, status: 'critical' })
  t.absent(JSON.stringify(res.body).includes('/data'), 'public health does not expose disk mount path')
  t.ok(res.headers['content-type']?.includes('application/json; charset=utf-8'), 'disk-critical health is typed as JSON')
  t.is(res.headers['x-content-type-options'], 'nosniff', 'disk-critical health disables content sniffing')
  t.is(res.headers['cache-control'], 'no-store, max-age=0', 'disk-critical health is not cached by default')
})

test('api-auth: POST /api/manage/shutdown without auth returns 401', async (t) => {
  const res = await request(port, 'POST', '/api/manage/shutdown', {})
  t.is(res.statusCode, 401, 'status is 401')
  t.ok(res.body.error, 'error message present')
})

test('api-auth: POST /api/manage/shutdown with valid Bearer token returns 200', async (t) => {
  const res = await request(port, 'POST', '/api/manage/shutdown', {}, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(res.statusCode, 200, 'status is 200')
  t.ok(res.body.ok, 'body.ok is true')
})

test('api-auth: POST /seed without auth returns 401', async (t) => {
  const res = await request(port, 'POST', '/seed', {
    appKey: 'a'.repeat(64)
  })
  t.is(res.statusCode, 401, 'status is 401')
  t.ok(res.body.error, 'error message present')
})

test('api-auth: POST /api/eviction/purge requires auth and reports mixed batch results', async (t) => {
  const originalCalls = node._purgeCalls
  node._purgeCalls = []
  t.teardown(() => { node._purgeCalls = originalCalls })

  const body = { appKeys: ['not-hex', 'f'.repeat(64)] }
  const unauthorized = await request(port, 'POST', '/api/eviction/purge', body)
  t.is(unauthorized.statusCode, 401, 'operator purge requires auth')
  t.alike(node._purgeCalls, [], 'unauthorized purge does not call manualPurge')

  const authorized = await request(port, 'POST', '/api/eviction/purge', body, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(authorized.statusCode, 200, 'authorized purge request succeeds')
  t.alike(node._purgeCalls, ['f'.repeat(64)])
  t.is(authorized.body.purged, 1)
  t.is(authorized.body.freedBytes, 21)
  t.alike(authorized.body.results, [
    { appKey: 'not-hex', ok: false, error: 'invalid appKey' },
    { appKey: 'f'.repeat(64), ok: true, bytes: 21 }
  ])
})

test('api-auth: POST /seed forwards metadata fields with auth', async (t) => {
  const res = await request(port, 'POST', '/seed', {
    appKey: 'c'.repeat(64),
    type: 'drive',
    parentKey: 'd'.repeat(64),
    mountPath: '/data',
    appId: 'ghost-drive-demo',
    version: '0.1.0',
    name: 'Ghost Drive Demo',
    description: 'Pinned drive for catalog testing',
    author: 'integration-test',
    categories: ['ghost-drive', 'files'],
    privacyTier: 'public',
    blind: true,
    storageClass: 'temporary',
    availabilityClass: 'atomic-handoff'
  }, {
    Authorization: 'Bearer ' + API_KEY
  })

  t.is(res.statusCode, 200, 'status is 200')
  t.ok(node._seedCalls.length > 0, 'seedApp invoked')

  const lastCall = node._seedCalls[node._seedCalls.length - 1]
  t.is(lastCall.appKey, 'c'.repeat(64), 'app key forwarded')
  t.is(lastCall.opts.type, 'drive', 'content type forwarded')
  t.is(lastCall.opts.parentKey, 'd'.repeat(64), 'parent key forwarded')
  t.is(lastCall.opts.mountPath, '/data', 'mount path forwarded')
  t.is(lastCall.opts.appId, 'ghost-drive-demo', 'appId forwarded')
  t.is(lastCall.opts.version, '0.1.0', 'version forwarded')
  t.is(lastCall.opts.name, 'Ghost Drive Demo', 'name forwarded')
  t.is(lastCall.opts.author, 'integration-test', 'author forwarded')
  t.alike(lastCall.opts.categories, ['ghost-drive', 'files'], 'categories forwarded')
  t.is(lastCall.opts.privacyTier, 'public', 'privacy tier forwarded')
  t.is(lastCall.opts.blind, true, 'blind flag forwarded')
  t.is(lastCall.opts.storageClass, 'temporary', 'storage class forwarded')
  t.is(lastCall.opts.availabilityClass, 'atomic-handoff', 'availability class forwarded')
})

test('api-auth: GET /catalog.json supports type filtering and typed buckets', async (t) => {
  const res = await request(port, 'GET', '/catalog.json?type=drive&page=1&pageSize=50')
  t.is(res.statusCode, 200, 'status is 200')
  t.is(res.body.version, 2, 'catalog version is 2')
  t.is(res.body.filters.type, 'drive', 'type filter reported')
  t.ok(Array.isArray(res.body.drives), 'drives array present')
  t.ok(Array.isArray(res.body.apps), 'apps array present for compatibility')
  t.is(res.body.drives.length, 1, 'drive entry returned')
  t.is(res.body.apps.length, 0, 'apps empty when filtering by drive')
})

test('api-auth: GET /api/drives returns only seeded drives', async (t) => {
  node._catalogEntries = [{
    appKey: 'a'.repeat(64),
    type: 'app',
    appId: 'peer-chat',
    categories: ['messaging']
  }, {
    appKey: 'b'.repeat(64),
    type: 'drive',
    appId: 'ghost-drive-demo',
    parentKey: null,
    mountPath: null,
    categories: ['ghost-drive']
  }]

  const res = await request(port, 'GET', '/api/drives')
  t.is(res.statusCode, 200, 'status is 200')
  t.ok(Array.isArray(res.body), 'body is array')
  t.is(res.body.length, 1, 'only one drive returned')
  t.is(res.body[0].type, 'drive', 'entry marked as drive')
  t.is(res.body[0].appKey, 'b'.repeat(64), 'drive key matches')
})

test('api-auth: legacy catalog type routes are bounded and paginated', async (t) => {
  node._catalogEntries = []
  for (let i = 0; i < 505; i++) {
    node._catalogEntries.push({
      appKey: String(i).padStart(64, '0'),
      type: 'drive',
      appId: 'drive-' + i
    })
  }
  node._catalogEntries.push({
    appKey: 'f'.repeat(64),
    type: 'app',
    appId: 'app-filtered'
  })

  const first = await request(port, 'GET', '/api/drives?pageSize=999999')
  t.is(first.statusCode, 200, 'status is 200')
  t.is(first.body.length, 500, 'legacy typed response is capped at catalog page max')
  t.is(first.body[0].appId, 'drive-0')
  t.is(first.body[499].appId, 'drive-499')

  const second = await request(port, 'GET', '/api/drives?page=2&pageSize=3')
  t.is(second.statusCode, 200, 'second page status is 200')
  t.alike(second.body.map(entry => entry.appId), ['drive-3', 'drive-4', 'drive-5'])

  const apps = await request(port, 'GET', '/api/apps?pageSize=10')
  t.is(apps.statusCode, 200, 'apps route status is 200')
  t.alike(apps.body.map(entry => entry.appId), ['app-filtered'])
})

test('api-auth: GET /api/registry/pending returns sanitized pending queue', async (t) => {
  const originalPending = node._pendingRequests
  const originalResolveAcceptMode = node._resolveAcceptMode
  const appKey = 'c'.repeat(64)
  const forgedAppKey = 'd'.repeat(64)

  t.teardown(() => {
    node._pendingRequests = originalPending
    node._resolveAcceptMode = originalResolveAcceptMode
  })

  node._pendingRequests = new Map([
    [appKey, {
      appKey: forgedAppKey,
      publisherPubkey: Buffer.alloc(32, 9),
      publisherSignature: Buffer.alloc(64, 10),
      privacyTier: 'public',
      categories: ['ghost-drive', { bad: true }, 'files'],
      blind: true,
      discoveredAt: 42,
      secretToken: 'do-not-leak'
    }]
  ])
  node._resolveAcceptMode = () => 'review'

  const unauth = await request(port, 'GET', '/api/registry/pending')
  t.is(unauth.statusCode, 401, 'pending queue requires management auth')

  const res = await request(port, 'GET', '/api/registry/pending', null, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(res.statusCode, 200, 'status is 200')
  t.is(res.body.count, 1)
  t.is(res.body.mode, 'review')
  t.is(res.body.requests[0].appKey, appKey, 'response uses canonical map key')
  t.is(res.body.requests[0].publisherPubkey, Buffer.alloc(32, 9).toString('hex'), 'byte pubkey is encoded')
  t.alike(res.body.requests[0].categories, ['ghost-drive', 'files'], 'categories are sanitized')
  t.absent(res.body.requests[0].publisherSignature, 'signature is not exposed')
  t.absent(res.body.requests[0].secretToken, 'unknown internal field is not exposed')
})

test('api-auth: GET /api/registry requires auth and returns bounded sanitized status', async (t) => {
  const originalRegistry = node.seedingRegistry
  t.teardown(() => { node.seedingRegistry = originalRegistry })
  const calls = []
  node.seedingRegistry = {
    key: Buffer.alloc(32, 9),
    async getActiveRequests () {
      calls.push('active')
      return [{
        type: 'seed-request',
        timestamp: 1,
        appKey: 'a'.repeat(64),
        discoveryKeys: ['b'.repeat(64)],
        contentType: 'drive',
        publisherPubkey: 'c'.repeat(64),
        publisherSignature: 'do-not-leak'
      }]
    },
    async getRelaysForApp (appKey) {
      calls.push(appKey)
      return [{ relayPubkey: 'd'.repeat(64), region: 'EU', secret: 'hidden' }]
    }
  }

  const denied = await request(port, 'GET', '/api/registry')
  t.is(denied.statusCode, 401, 'registry status requires management auth')
  t.alike(calls, [], 'unauthorized registry status does not query registry')

  const allowed = await request(port, 'GET', '/api/registry', null, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(allowed.statusCode, 200, 'authenticated registry status succeeds')
  t.is(allowed.body.key, '09'.repeat(32))
  t.is(allowed.body.activeRequests, 1)
  t.is(allowed.body.count, 1)
  t.is(allowed.body.truncated, false)
  t.alike(allowed.body.requests[0].relays, [{ pubkey: 'd'.repeat(64), region: 'EU' }])
  t.absent(JSON.stringify(allowed.body).includes('do-not-leak'))
  t.absent(JSON.stringify(allowed.body).includes('publisherSignature'))
  api._rateLimits.clear()
  api._endpointRateLimits.clear()
})

test('api-auth: delegation revocation routes require auth and validate before mutation', async (t) => {
  const originalCalls = node._revocationCalls
  node._revocationCalls = []
  t.teardown(() => { node._revocationCalls = originalCalls })

  const deniedList = await request(port, 'GET', '/api/manage/delegation/revocations')
  t.is(deniedList.statusCode, 401, 'revocation list requires management auth')

  const deniedWrite = await request(port, 'POST', '/api/manage/delegation/revoke', {
    revocation: { version: 1 }
  })
  t.is(deniedWrite.statusCode, 401, 'revocation submit requires management auth')
  t.alike(node._revocationCalls, [], 'unauthorized revocation submit does not mutate')

  const listed = await request(port, 'GET', '/api/manage/delegation/revocations', null, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(listed.statusCode, 200, 'authenticated revocation list succeeds')
  t.is(listed.body.count, 1)
  t.is(listed.body.total, 1)
  t.is(listed.body.truncated, false)
  t.is(listed.body.revocations[0].revokedCertSignature, 'a'.repeat(128), 'signature is canonicalized')
  t.absent(listed.body.revocations[0].secretToken, 'internal list fields are omitted')

  const malformedExpiry = await request(port, 'POST', '/api/manage/delegation/revoke', {
    revocation: { version: 1 },
    certExpiresAt: '1e3'
  }, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(malformedExpiry.statusCode, 400, 'malformed cert expiry rejected')
  t.is(malformedExpiry.body.error, 'certExpiresAt must be a positive safe integer')
  t.alike(node._revocationCalls, [], 'malformed expiry does not reach submitRevocation')

  const revocation = { version: 1, revokedCertSignature: 'D'.repeat(128) }
  const submitted = await request(port, 'POST', '/api/manage/delegation/revoke', {
    revocation,
    certExpiresAt: 123456
  }, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(submitted.statusCode, 200, 'valid revocation request succeeds')
  t.is(submitted.body.revokedCertSignature, 'D'.repeat(128))
  t.alike(node._revocationCalls, [{ revocation, opts: { certExpiresAt: 123456 } }])
})

test('api-auth: POST /unseed without auth returns 401', async (t) => {
  const res = await request(port, 'POST', '/unseed', {
    appKey: 'b'.repeat(64)
  })
  t.is(res.statusCode, 401, 'status is 401')
  t.ok(res.body.error, 'error message present')
})

test('api-auth: operator unseed validates appKey before mutation', async (t) => {
  const before = node._unseedCalls.length
  const invalid = await request(port, 'POST', '/unseed', {
    appKey: 'not-hex'
  }, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(invalid.statusCode, 400, 'invalid operator unseed rejected')
  t.is(invalid.body.error, 'appKey must be 64 hex characters')
  t.is(node._unseedCalls.length, before, 'invalid operator unseed does not mutate')

  const validKey = 'b'.repeat(64)
  const valid = await request(port, 'POST', '/unseed', {
    appKey: validKey
  }, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(valid.statusCode, 200, 'valid operator unseed accepted')
  t.alike(valid.body, { ok: true })
  t.is(node._unseedCalls[node._unseedCalls.length - 1], validKey)
  api._rateLimits.clear()
  api._endpointRateLimits.clear()
})

test('api-auth: POST /api/v1/dispatch without auth returns 401', async (t) => {
  const res = await request(port, 'POST', '/api/v1/dispatch', {
    route: 'ai.infer',
    params: { hello: 'world' }
  })
  t.is(res.statusCode, 401, 'status is 401')
  t.ok(res.body.error, 'error message present')
})

test('api-auth: POST /registry/publish without auth returns 401', async (t) => {
  const res = await request(port, 'POST', '/registry/publish', {
    appKey: 'a'.repeat(64)
  })
  t.is(res.statusCode, 401, 'status is 401')
  t.ok(res.body.error, 'error message present')
})

test('api-auth: POST /api/v1/dispatch local-only route allowed from localhost with auth', async (t) => {
  const res = await request(port, 'POST', '/api/v1/dispatch', {
    route: 'identity.sign',
    params: { message: 'hello' }
  }, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(res.statusCode, 200, 'status is 200')
  t.ok(res.body.ok, 'dispatch succeeded for local-only localhost call')
})

test('api-auth: OPTIONS preflight denied by default when origin is not allowed', async (t) => {
  const res = await request(port, 'OPTIONS', '/health', null, {
    Origin: 'https://example.com'
  })
  t.is(res.statusCode, 403, 'status is 403')
  t.ok(res.body.error.includes('CORS'), 'origin denied')
})

test('api-auth: configured CORS origins vary cached responses by Origin', async (t) => {
  const corsApi = new api.constructor(mockRelayNode(), {
    apiPort: 0,
    apiKey: API_KEY,
    apiHost: '127.0.0.1',
    corsOrigins: ['https://app.example']
  })
  await corsApi.start()
  const corsPort = corsApi.server.address().port
  t.teardown(async () => {
    try { await corsApi.stop() } catch (_) {}
  })

  const allowed = await request(corsPort, 'GET', '/health', null, {
    Origin: 'https://app.example'
  })
  t.is(allowed.statusCode, 200)
  t.is(allowed.headers['access-control-allow-origin'], 'https://app.example')
  t.is(allowed.headers.vary, 'Origin', 'allowed dynamic CORS response varies by Origin')

  const deniedPreflight = await request(corsPort, 'OPTIONS', '/api/v1/dispatch', null, {
    Origin: 'https://evil.example'
  })
  t.is(deniedPreflight.statusCode, 403)
  t.is(deniedPreflight.headers.vary, 'Origin', 'denied preflight also varies by Origin')
})

test('api-auth: GET /health without auth returns 200 (public endpoint)', async (t) => {
  const res = await request(port, 'GET', '/health')
  t.is(res.statusCode, 200, 'status is 200')
  t.ok(res.body.ok, 'body.ok is true')
})

test('api-auth: GET /api/alerts requires auth because alert details are operator-private', async (t) => {
  const before = api._authFailureTotal
  const denied = await request(port, 'GET', '/api/alerts')
  t.is(denied.statusCode, 401, 'unauthenticated alert log read rejected')
  t.is(api._authFailureTotal, before + 1, 'alert log auth failure counted')
  t.ok(api._authFailures.get('/api/alerts') >= 1, 'alert log route counted')

  const allowed = await request(port, 'GET', '/api/alerts', null, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(allowed.statusCode, 200, 'authenticated alert log read allowed')
  t.is(allowed.body.enabled, false, 'mock server reports alerts disabled')
})

test('api-auth: alert pagination query values are clamped before log lookup', async (t) => {
  const originalAlertManager = node.alertManager
  t.teardown(() => { node.alertManager = originalAlertManager })
  const calls = []
  node.alertManager = {
    getLog (opts) {
      calls.push(opts)
      return { total: 0, offset: opts.offset, limit: opts.limit, items: [] }
    }
  }

  const first = await request(port, 'GET', '/api/alerts?offset=-10&limit=999999999999999999999', null, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(first.statusCode, 200, 'clamped alert query succeeds')
  t.is(first.body.offset, 0, 'negative offset clamps to zero')
  t.is(first.body.limit, 500, 'oversized limit clamps to max')
  t.is(calls[0].offset, 0, 'log lookup receives clamped offset')
  t.is(calls[0].limit, 500, 'log lookup receives clamped limit')

  const second = await request(port, 'GET', '/api/alerts?offset=10abc&limit=1e3', null, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(second.statusCode, 200, 'malformed alert query succeeds')
  t.is(second.body.offset, 0, 'malformed offset falls back to default')
  t.is(second.body.limit, 50, 'malformed limit falls back to default')

  const invalidSeverity = await request(port, 'GET', '/api/alerts?severity=debug', null, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(invalidSeverity.statusCode, 400, 'invalid severity filter rejected')
  t.is(invalidSeverity.body.error, 'severity must be one of: info, warn, error, critical')

  const invalidType = await request(port, 'GET', '/api/alerts?type=../secret', null, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(invalidType.statusCode, 400, 'invalid type filter rejected')
  t.is(calls.length, 2, 'invalid alert filters do not reach getLog')
  api._rateLimits.clear()
  api._endpointRateLimits.clear()
})

test('api-auth: alert test route validates body before dispatch', async (t) => {
  const originalAlertManager = node.alertManager
  t.teardown(() => { node.alertManager = originalAlertManager })
  const calls = []
  node.alertManager = {
    fireTest (opts) {
      calls.push(opts)
      return true
    }
  }

  const badSeverity = await request(port, 'POST', '/api/alerts/test', {
    severity: 'debug'
  }, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(badSeverity.statusCode, 400, 'invalid alert severity rejected')

  const badMessage = await request(port, 'POST', '/api/alerts/test', {
    message: 'x'.repeat(513)
  }, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(badMessage.statusCode, 400, 'oversized alert message rejected')
  t.is(badMessage.body.error, 'message must be 512 bytes or smaller')

  const badDetails = await request(port, 'POST', '/api/alerts/test', {
    details: []
  }, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(badDetails.statusCode, 400, 'array alert details rejected')
  t.alike(calls, [], 'invalid alert test payloads do not dispatch')

  const ok = await request(port, 'POST', '/api/alerts/test', {
    severity: 'warn',
    message: 'manual test',
    details: { source: 'unit' }
  }, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(ok.statusCode, 200, 'valid alert test dispatches')
  t.alike(ok.body, { ok: true, dispatched: true })
  t.alike(calls, [{ severity: 'warn', message: 'manual test', details: { source: 'unit' } }])
  api._rateLimits.clear()
  api._endpointRateLimits.clear()
})

test('api-auth: operator diagnostics require auth', async (t) => {
  const originalGetHealthStatus = node.getHealthStatus
  const originalSelfHeal = node.selfHeal
  const originalAutoHeal = node.autoHeal
  t.teardown(() => {
    node.getHealthStatus = originalGetHealthStatus
    node.selfHeal = originalSelfHeal
    node.autoHeal = originalAutoHeal
  })

  node.getHealthStatus = () => ({
    healthy: true,
    checks: {
      disk: {
        ok: false,
        usedPct: 92,
        mountPath: '/should/not/leak'
      }
    },
    secret: 'health-should-not-leak'
  })
  node.selfHeal = {
    getActions () {
      return [{
        type: 'repair',
        timestamp: Date.now(),
        secret: 'action-should-not-leak'
      }]
    }
  }
  node.autoHeal = {
    snapshot () {
      return {
        enabled: true,
        running: true,
        tracked: 1,
        secret: 'auto-heal-should-not-leak',
        drives: [{
          appKey: 'e'.repeat(64),
          replicas: 2,
          regions: ['eu'],
          operators: ['operator-a'],
          meetsThreshold: false,
          secret: 'drive-should-not-leak'
        }]
      }
    }
  }

  const before = api._authFailureTotal
  const healthDenied = await request(port, 'GET', '/api/health-detail')
  const autoHealDenied = await request(port, 'GET', '/api/auto-heal')

  t.is(healthDenied.statusCode, 401, 'unauthenticated health details rejected')
  t.is(autoHealDenied.statusCode, 401, 'unauthenticated AutoHeal details rejected')
  t.is(api._authFailureTotal, before + 2, 'diagnostic auth failures counted')
  t.ok(api._authFailures.get('/api/health-detail') >= 1, 'health-detail route counted')
  t.ok(api._authFailures.get('/api/auto-heal') >= 1, 'auto-heal route counted')

  const auth = { Authorization: 'Bearer ' + API_KEY }
  const healthAllowed = await request(port, 'GET', '/api/health-detail', null, auth)
  const autoHealAllowed = await request(port, 'GET', '/api/auto-heal', null, auth)
  t.is(healthAllowed.statusCode, 200, 'authenticated health details allowed')
  t.is(healthAllowed.body.healthy, true, 'health detail body preserved')
  t.is(healthAllowed.body.checks.disk.usedPct, 92, 'health disk metric preserved')
  t.is(healthAllowed.body.actions[0].type, 'repair', 'self-heal action type preserved')
  t.absent(JSON.stringify(healthAllowed.body).includes('should-not-leak'), 'raw health details removed')
  t.is(autoHealAllowed.statusCode, 200, 'authenticated AutoHeal details allowed')
  t.is(autoHealAllowed.body.enabled, true, 'mock server reports AutoHeal enabled')
  t.is(autoHealAllowed.body.drives[0].appKey, 'e'.repeat(64), 'auto-heal drive key preserved')
  t.absent(JSON.stringify(autoHealAllowed.body).includes('should-not-leak'), 'raw auto-heal details removed')
})

test('api-auth: detailed anchor diagnostics require auth', async (t) => {
  const originalRegistry = node.appRegistry
  const originalCreateAnchorProof = node.createAnchorProof
  const originalLastCheckedAt = node._lastAnchorCheckAt
  t.teardown(() => {
    node.appRegistry = originalRegistry
    node.createAnchorProof = originalCreateAnchorProof
    node._lastAnchorCheckAt = originalLastCheckedAt
  })

  node._lastAnchorCheckAt = 12345
  node.appRegistry = {
    anchorStats () {
      return { total: 1, anchored: 0, unanchored: 1, neverChecked: 0 }
    },
    catalog () {
      return [{
        appKey: 'a'.repeat(64),
        type: 'drive',
        anchored: false,
        anchoredAt: null,
        anchoredLength: 0,
        custodyIntentId: 'b'.repeat(64),
        blind: true,
        storageClass: 'temporary',
        availabilityClass: 'atomic-handoff'
      }]
    }
  }

  const publicStats = await request(port, 'GET', '/api/anchors')
  t.is(publicStats.statusCode, 200, 'public anchor aggregates remain readable')
  t.is(publicStats.body.total, 1, 'public aggregate payload preserved')
  t.is(publicStats.body.entries, null, 'public aggregate omits detailed entries')

  const before = api._authFailureTotal
  const denied = await request(port, 'GET', '/api/anchors?detailed=1')
  t.is(denied.statusCode, 401, 'unauthenticated detailed anchor diagnostics rejected')
  t.is(api._authFailureTotal, before + 1, 'detailed anchor auth failure counted')
  t.ok(api._authFailures.get('/api/anchors') >= 1, 'anchor route counted without query data')

  const allowed = await request(port, 'GET', '/api/anchors?detailed=1', null, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(allowed.statusCode, 200, 'authenticated detailed anchor diagnostics allowed')
  t.is(allowed.body.lastCheckedAt, 12345, 'last checked timestamp preserved')
  t.is(allowed.body.entries[0].custodyIntentId, 'b'.repeat(64), 'custody linkage present under auth')

  const proofKey = 'c'.repeat(64)
  node.createAnchorProof = async (appKey) => {
    t.is(appKey, proofKey, 'anchor proof route passes validated key to signer')
    return { appKey, anchored: true, version: 9 }
  }

  const proof = await request(port, 'GET', '/api/anchors/' + proofKey + '/proof')
  t.is(proof.statusCode, 200, 'public anchor proof remains readable')
  t.is(proof.body.appKey, proofKey, 'proof payload returned')
  t.is(proof.body.version, 9, 'proof fields preserved')

  const invalidProof = await request(port, 'GET', '/api/anchors/not-hex/proof')
  t.is(invalidProof.statusCode, 400, 'malformed proof key rejected before signer')
  t.is(invalidProof.body.error, 'invalid appKey')
})

test('api-auth: public network state redacts connection details and detailed state requires auth', async (t) => {
  const originalNetworkDiscovery = node.networkDiscovery
  t.teardown(() => { node.networkDiscovery = originalNetworkDiscovery })

  node.networkDiscovery = {
    getNetworkState () {
      return {
        timestamp: 12345,
        summary: {
          totalRelays: 1,
          onlineRelays: 1,
          totalConnections: 3,
          totalStorage: 100,
          totalStorageMax: 200
        },
        relays: [{
          publicKey: 'c'.repeat(64),
          name: 'Relay cccccccc',
          host: '203.0.113.15',
          apiPort: 9100,
          region: 'EU',
          online: true,
          lastSeen: 999,
          uptime: { ms: 1000 },
          connections: 3,
          seededApps: 2,
          storage: { used: 100, max: 200 },
          relay: { totalBytesRelayed: 50 },
          seeder: { coresSeeded: 2 },
          memory: { heapUsed: 11, rss: 22 },
          tor: { running: true, onionAddress: 'network-secret.onion' },
          holesailKey: 'network-holesail-secret',
          holesailConnected: true,
          errors: 0
        }]
      }
    }
  }

  const publicState = await request(port, 'GET', '/api/network')
  t.is(publicState.statusCode, 200, 'public network state remains readable')
  t.is(publicState.body.relays[0].publicKey, 'c'.repeat(64), 'public relay id preserved')
  t.is(publicState.body.relays[0].apiReachable, true, 'public API availability boolean preserved')
  t.absent(Object.prototype.hasOwnProperty.call(publicState.body.relays[0], 'host'))
  t.absent(Object.prototype.hasOwnProperty.call(publicState.body.relays[0], 'apiPort'))
  t.absent(Object.prototype.hasOwnProperty.call(publicState.body.relays[0], 'memory'))
  t.absent(JSON.stringify(publicState.body).includes('network-holesail-secret'))
  t.absent(JSON.stringify(publicState.body).includes('network-secret.onion'))

  const before = api._authFailureTotal
  const denied = await request(port, 'GET', '/api/network?detailed=1')
  t.is(denied.statusCode, 401, 'unauthenticated detailed network state rejected')
  t.is(api._authFailureTotal, before + 1, 'detailed network auth failure counted')
  t.ok(api._authFailures.get('/api/network') >= 1, 'network route counted without query data')

  const allowed = await request(port, 'GET', '/api/network?detailed=1', null, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(allowed.statusCode, 200, 'authenticated detailed network state allowed')
  t.is(allowed.body.relays[0].host, '203.0.113.15', 'detailed host present under auth')
  t.is(allowed.body.relays[0].holesailKey, 'network-holesail-secret', 'detailed holesail key present under auth')
})

test('api-auth: metrics history requires auth and returns shaped snapshots', async (t) => {
  const before = api._authFailureTotal
  const denied = await request(port, 'GET', '/api/history?minutes=60')
  t.is(denied.statusCode, 401, 'unauthenticated history read rejected')
  t.is(api._authFailureTotal, before + 1, 'history auth failure counted')
  t.ok(api._authFailures.get('/api/history') >= 1, 'history route counted')

  const allowed = await request(port, 'GET', '/api/history?minutes=60', null, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(allowed.statusCode, 200, 'authenticated history read allowed')
  t.ok(Array.isArray(allowed.body), 'history body is an array')
  t.is(allowed.body[0].connections, 1, 'connection metric preserved')
  t.is(allowed.body[0].seeder.totalBytesServed, 2, 'seeder metric preserved')
  t.is(allowed.body[0].relay.totalBytesRelayed, 3, 'relay metric preserved')
  t.absent(Object.prototype.hasOwnProperty.call(allowed.body[0], 'marker'), 'raw row marker removed')
  t.absent(JSON.stringify(allowed.body).includes('should-not-leak'), 'raw snapshot fields removed')
})

test('api-auth: metrics history minutes query is clamped to metrics retention', async (t) => {
  const originalSnapshots = node.metrics.snapshots
  t.teardown(() => { node.metrics.snapshots = originalSnapshots })
  const now = Date.now()
  node.metrics.snapshots = [
    { timestamp: now - 2 * 60_000, marker: 'recent' },
    { timestamp: now - 25 * 60 * 60_000, marker: 'older-than-retention' }
  ]

  const huge = await request(port, 'GET', '/api/history?minutes=999999999999999999999', null, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(huge.statusCode, 200, 'oversized history window succeeds')
  t.alike(huge.body.map(s => s.timestamp), [now - 2 * 60_000], 'oversized window clamps to 24h retention')

  const malformed = await request(port, 'GET', '/api/history?minutes=1e9', null, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(malformed.statusCode, 200, 'malformed history window succeeds')
  t.alike(malformed.body.map(s => s.timestamp), [now - 2 * 60_000], 'malformed window falls back to default')
})

test('api-auth: operator usage telemetry requires auth and returns aggregate proof counters', async (t) => {
  const before = api._authFailureTotal
  const usageDenied = await request(port, 'GET', '/api/usage')
  const pokerDenied = await request(port, 'GET', '/api/poker/usage')

  t.is(usageDenied.statusCode, 401, 'unauthenticated usage telemetry rejected')
  t.is(pokerDenied.statusCode, 401, 'unauthenticated poker usage telemetry rejected')
  t.is(api._authFailureTotal, before + 2, 'usage auth failures counted')
  t.ok(api._authFailures.get('/api/usage') >= 1, 'usage route counted')
  t.ok(api._authFailures.get('/api/poker/usage') >= 1, 'poker usage route counted')

  const auth = { Authorization: 'Bearer ' + API_KEY }
  const usage = await request(port, 'GET', '/api/usage', null, auth)
  const poker = await request(port, 'GET', '/api/poker/usage', null, auth)

  t.is(usage.statusCode, 200, 'authenticated usage telemetry allowed')
  t.is(usage.body.enabled, true, 'bandwidth receipts are enabled')
  t.is(usage.body.verified.count, 2, 'signed receipt count returned')
  t.is(usage.body.verified.bytes, 350, 'signed receipt bytes summed')
  t.is(usage.body.verified.totals.bandwidthBytes, 350, 'dashboard totals include receipt bytes')

  t.is(poker.statusCode, 200, 'authenticated poker usage telemetry allowed')
  t.is(poker.body.enabled, true, 'poker app detected')
  t.is(poker.body.tables, 2, 'table count returned')
  t.is(poker.body.appends, 13, 'append count summed')
  t.is(poker.body.seats, 5, 'writer/seat count summed')
})

test('api-auth: POST /api/v1/unseed without API key auth works (developer-signed)', async (t) => {
  // This endpoint uses developer signature auth, not API key auth.
  // It should not return 401 — it will return 400 for missing fields instead.
  const res = await request(port, 'POST', '/api/v1/unseed', {})
  // Should be 400 (missing appKey), NOT 401
  t.is(res.statusCode, 400, 'status is 400 (not 401)')
  t.ok(res.body.error.includes('appKey'), 'error is about missing appKey, not auth')
})

test('api-auth: publisher-signed unseed validates before verifier, mutation, and broadcast', async (t) => {
  const beforeVerify = node._unseedVerifyCalls.length
  const beforeUnseed = node._unseedCalls.length
  const beforeBroadcast = node._unseedBroadcastCalls.length
  const body = {
    appKey: 'c'.repeat(64),
    publisherPubkey: 'd'.repeat(64),
    signature: 'e'.repeat(128)
  }

  const badTimestamp = await request(port, 'POST', '/api/v1/unseed', {
    ...body,
    timestamp: '123456789'
  })
  t.is(badTimestamp.statusCode, 400, 'malformed timestamp rejected before verifier')
  t.is(badTimestamp.body.error, 'timestamp must be a positive safe integer')
  t.is(node._unseedVerifyCalls.length, beforeVerify, 'malformed request does not verify')
  t.is(node._unseedCalls.length, beforeUnseed, 'malformed request does not unseed')
  t.is(node._unseedBroadcastCalls.length, beforeBroadcast, 'malformed request does not broadcast')

  const ok = await request(port, 'POST', '/api/v1/unseed', {
    ...body,
    timestamp: 123456789
  })
  t.is(ok.statusCode, 200, 'valid developer-signed unseed accepted')
  t.alike(ok.body, { ok: true, message: 'App unseeded and unseed broadcast to network' })
  t.alike(node._unseedVerifyCalls[node._unseedVerifyCalls.length - 1], {
    ...body,
    timestamp: 123456789
  })
  t.is(node._unseedCalls[node._unseedCalls.length - 1], body.appKey)
  t.alike(node._unseedBroadcastCalls[node._unseedBroadcastCalls.length - 1], {
    ...body,
    timestamp: 123456789
  })
  api._rateLimits.clear()
  api._endpointRateLimits.clear()
})

test('api-auth: POST /seed forwards durability for operator-pinned archive tier', async (t) => {
  // POLICY: archive tier (durability ≥ 1) requires a publisher signature on
  // the anonymous P2P channel, but the API-key-authenticated /seed endpoint
  // is operator authority — an operator may pin any key (incl. foreign
  // bare keys) at archive tier on their own relay.
  node._seedCalls.length = 0
  const res = await request(port, 'POST', '/seed', {
    appKey: 'e'.repeat(64),
    durability: 1
  }, { Authorization: 'Bearer ' + API_KEY })
  t.is(res.statusCode, 200, 'authenticated archive pin accepted')
  t.is(node._seedCalls.length, 1, 'seedApp called')
  t.is(node._seedCalls[0].opts.durability, 1, 'durability forwarded to seedApp')
})

test('api-auth: POST /seed rejects malformed durability', async (t) => {
  const res = await request(port, 'POST', '/seed', {
    appKey: 'e'.repeat(64),
    durability: 'archive'
  }, { Authorization: 'Bearer ' + API_KEY })
  t.is(res.statusCode, 400, 'non-integer durability rejected')
  t.ok(res.body.error.includes('durability'), 'error names the field')
})

test('api-auth: 401s are counted per route and surfaced on /metrics', async (t) => {
  const before = api._authFailureTotal
  await request(port, 'POST', '/seed', { appKey: 'b'.repeat(64) })
  await request(port, 'POST', '/seed', { appKey: 'b'.repeat(64) })
  t.is(api._authFailureTotal, before + 2, 'total auth-failure counter incremented')
  t.ok(api._authFailures.get('/seed') >= 2, 'per-route counter tracks /seed')

  const res = await request(port, 'GET', '/metrics')
  t.is(res.statusCode, 200, 'metrics endpoint responds')
  t.is(res.headers['content-type'], 'text/plain; charset=utf-8', 'metrics endpoint uses explicit text type')
  t.is(res.headers['x-content-type-options'], 'nosniff', 'metrics endpoint disables content sniffing')
  t.is(res.headers['cache-control'], 'no-store, max-age=0', 'metrics endpoint is not cached by default')
  t.ok(String(res.body).includes('hiverelay_auth_failures_total{route="/seed"}'), 'auth-failure counter exported to Prometheus')
})

test('api-auth: wizard and wallet auth failures are counted like management routes', async (t) => {
  const before = api._authFailureTotal
  const wallet = await request(port, 'POST', '/api/subsidy/destination', { destination: 'operator@example.com' })
  const wizard = await request(port, 'POST', '/api/wizard/payout', { address: 'operator@example.com' })

  t.is(wallet.statusCode, 401, 'wallet mutation rejects without bearer token')
  t.is(wizard.statusCode, 401, 'wizard mutation rejects without bearer token')
  t.is(api._authFailureTotal, before + 2, 'total auth-failure counter incremented')
  t.ok(api._authFailures.get('/api/subsidy/destination') >= 1, 'wallet route counted')
  t.ok(api._authFailures.get('/api/wizard/payout') >= 1, 'wizard route counted')

  const res = await request(port, 'GET', '/metrics')
  const metrics = String(res.body)
  t.ok(metrics.includes('hiverelay_auth_failures_total{route="/api/subsidy/destination"}'), 'wallet auth failure exported')
  t.ok(metrics.includes('hiverelay_auth_failures_total{route="/api/wizard/payout"}'), 'wizard auth failure exported')
})

test('api-auth: subsidy status and claim routes are auth-gated and shaped', async (t) => {
  const before = api._authFailureTotal
  const statusDenied = await request(port, 'GET', '/api/subsidy')
  const claimDenied = await request(port, 'GET', '/api/subsidy/claim')

  t.is(statusDenied.statusCode, 401, 'subsidy status rejects without bearer token')
  t.is(claimDenied.statusCode, 401, 'subsidy claim rejects without bearer token')
  t.is(api._authFailureTotal, before + 2, 'subsidy read auth failures counted')
  t.ok(api._authFailures.get('/api/subsidy') >= 1, 'subsidy status route counted')
  t.ok(api._authFailures.get('/api/subsidy/claim') >= 1, 'subsidy claim route counted')

  const disabled = await request(port, 'GET', '/api/subsidy', null, { Authorization: 'Bearer ' + API_KEY })
  t.is(disabled.statusCode, 200, 'disabled subsidy status succeeds')
  t.alike(disabled.body, { enabled: false, payoutDestination: null })

  node.subsidyAccrual = {
    getSummary () {
      return {
        payoutDestination: { type: 'lightning-address', value: 'operator@example.com' },
        accruedSats: 7
      }
    },
    buildClaim () {
      return { relay: 'a'.repeat(64), amountSats: 7 }
    }
  }

  const enabled = await request(port, 'GET', '/api/subsidy', null, { Authorization: 'Bearer ' + API_KEY })
  t.is(enabled.statusCode, 200, 'enabled subsidy status succeeds')
  t.alike(enabled.body, {
    enabled: true,
    payoutDestination: { type: 'lightning-address', value: 'operator@example.com' },
    accruedSats: 7
  })

  const claim = await request(port, 'GET', '/api/subsidy/claim', null, { Authorization: 'Bearer ' + API_KEY })
  t.is(claim.statusCode, 200, 'enabled subsidy claim succeeds')
  t.alike(claim.body, { relay: 'a'.repeat(64), amountSats: 7 })

  node.subsidyAccrual = {}
  const unavailable = await request(port, 'GET', '/api/subsidy/claim', null, { Authorization: 'Bearer ' + API_KEY })
  t.is(unavailable.statusCode, 503, 'malformed subsidy runtime returns a stable unavailable claim response')
  t.ok(unavailable.body.error.startsWith('unsupported: '), 'unavailable claim response names unsupported exporter')

  node.subsidyAccrual = null
})

test('api-auth: auth-failure route labels collapse hex ids (bounded cardinality)', async (t) => {
  const intentId = 'c'.repeat(64)
  await request(port, 'POST', '/api/custody/' + intentId + '/commit', {})
  t.ok(api._authFailures.has('/api/custody/:hex/commit'), 'hex id collapsed to :hex in route label')
  t.absent(api._authFailures.has('/api/custody/' + intentId + '/commit'), 'raw hex id not stored as its own route')
})

test('api-auth: auth-failure route labels strip query secrets and sanitize log characters', (t) => {
  const before = api._authFailureTotal
  api._recordAuthFailure({
    url: '/api/wallet\n"bad"/' + 'd'.repeat(64) + '?api_key=' + API_KEY + '&token=abc',
    socket: { remoteAddress: '203.0.113.9' }
  })

  t.is(api._authFailureTotal, before + 1, 'auth failure counted')
  t.ok(api._authFailures.has('/api/wallet:bad/:hex'), 'control/quote characters sanitized and hex id collapsed')

  const metrics = api._authFailureMetricsLines()
  t.absent(metrics.includes(API_KEY), 'API key query value is not exported')
  t.absent(metrics.includes('token=abc'), 'token query value is not exported')
  t.absent(metrics.includes('\n"bad"'), 'control/quote sequence is not exported')
})

test('api-auth: authed requests do not touch the auth-failure counter', async (t) => {
  const before = api._authFailureTotal
  await request(port, 'POST', '/seed', { appKey: 'd'.repeat(64) }, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(api._authFailureTotal, before, 'counter unchanged on authorized call')
})

test('api-auth: teardown server', async (t) => {
  if (api && api.server) {
    api.server.close()
    if (api._rateLimitCleanup) clearInterval(api._rateLimitCleanup)
    if (api._dashboardFeed) {
      try { api._dashboardFeed.stop() } catch (_) {}
    }
  }
  t.pass('server closed')
})
