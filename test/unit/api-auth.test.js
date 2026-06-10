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
      getSummary () { return { uptime: 100 } },
      toPrometheus () { return '# mock metrics\n' }
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
    async seedApp (appKey, opts) {
      node._seedCalls.push({ appKey, opts })
      return { ok: true }
    },
    async unseedApp () {},
    verifyUnseedRequest () { return { ok: true } },
    broadcastUnseed () {},
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
        resolve({ statusCode: res.statusCode, body: parsed })
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

test('api-auth: POST /unseed without auth returns 401', async (t) => {
  const res = await request(port, 'POST', '/unseed', {
    appKey: 'b'.repeat(64)
  })
  t.is(res.statusCode, 401, 'status is 401')
  t.ok(res.body.error, 'error message present')
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

test('api-auth: GET /health without auth returns 200 (public endpoint)', async (t) => {
  const res = await request(port, 'GET', '/health')
  t.is(res.statusCode, 200, 'status is 200')
  t.ok(res.body.ok, 'body.ok is true')
})

test('api-auth: POST /api/v1/unseed without API key auth works (developer-signed)', async (t) => {
  // This endpoint uses developer signature auth, not API key auth.
  // It should not return 401 — it will return 400 for missing fields instead.
  const res = await request(port, 'POST', '/api/v1/unseed', {})
  // Should be 400 (missing appKey), NOT 401
  t.is(res.statusCode, 400, 'status is 400 (not 401)')
  t.ok(res.body.error.includes('appKey'), 'error is about missing appKey, not auth')
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
  t.ok(String(res.body).includes('hiverelay_auth_failures_total{route="/seed"}'), 'auth-failure counter exported to Prometheus')
})

test('api-auth: auth-failure route labels collapse hex ids (bounded cardinality)', async (t) => {
  const intentId = 'c'.repeat(64)
  await request(port, 'POST', '/api/custody/' + intentId + '/commit', {})
  t.ok(api._authFailures.has('/api/custody/:hex/commit'), 'hex id collapsed to :hex in route label')
  t.absent(api._authFailures.has('/api/custody/' + intentId + '/commit'), 'raw hex id not stored as its own route')
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
