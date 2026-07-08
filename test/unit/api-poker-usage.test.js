import test from 'brittle'
import http from 'http'
import { RelayAPI } from 'p2p-hiverelay/core/relay-node/api.js'

const API_KEY = 'poker-usage-test-key'

// Regression guard for the release-image smoke gate: GET /api/poker/usage on a
// relay with NO poker service must answer 200 { enabled: false, ... } — "poker
// isn't enabled" is a valid telemetry answer, not an error. The 503 this used
// to return kept every Release surfaces run red from v0.24.0 through v0.24.3.

function mockNode (opts = {}) {
  return {
    running: true,
    config: { storage: null, plugins: opts.plugins || [], trustProxy: true },
    metrics: { getSummary () { return { uptime: 1 } } },
    seededApps: new Map(),
    appRegistry: { apps: new Map(), catalog () { return [] }, catalogForBroadcast () { return [] } },
    getStats () { return { running: true } },
    getHealthStatus () { return { healthy: true } },
    serviceRegistry: opts.registry || null,
    async stop () {},
    async start () {},
    on () {},
    emit () {}
  }
}

async function serverWithApi (t, node, opts = {}) {
  const api = new RelayAPI(node, { apiPort: 0, apiHost: '127.0.0.1', apiKey: API_KEY, ...opts })
  await api.start()
  const port = api.server.address().port
  t.teardown(async () => {
    if (api._rateLimitCleanup) clearInterval(api._rateLimitCleanup)
    if (api._dashboardFeed) { try { api._dashboardFeed.stop() } catch {} }
    if (api._pokerFeed) { try { api._pokerFeed.stop() } catch {} }
    await new Promise((resolve) => api.server.close(resolve))
  })
  return { api, port }
}

function request (port, method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      method,
      path,
      headers: { 'Content-Type': 'application/json', ...headers }
    }, (res) => {
      let data = ''
      res.on('data', (chunk) => { data += chunk })
      res.on('end', () => {
        let parsed
        try { parsed = JSON.parse(data) } catch { parsed = data }
        resolve({ statusCode: res.statusCode, body: parsed, headers: res.headers })
      })
    })
    req.on('error', reject)
    if (body != null) req.write(JSON.stringify(body))
    req.end()
  })
}

test('/api/poker/usage answers enabled:false (200) when poker is not running', async (t) => {
  const { port } = await serverWithApi(t, mockNode({ registry: null }))
  const res = await request(port, 'GET', '/api/poker/usage', null, {
    Authorization: `Bearer ${API_KEY}`
  })

  t.is(res.statusCode, 200, 'a stock (no-services) relay answers 200, not 503')
  t.is(res.body.enabled, false)
  t.is(res.body.service, 'poker')
  t.is(res.body.tables, 0)
  t.is(res.body.appends, 0)
  t.is(res.body.seats, 0)
  t.alike(res.body.perTable, [])
})

test('/api/poker/usage still requires auth', async (t) => {
  const { port } = await serverWithApi(t, mockNode({ registry: null }))
  const res = await request(port, 'GET', '/api/poker/usage')
  t.is(res.statusCode, 401)
})

test('/api/poker/usage reports live counts when a poker provider is running', async (t) => {
  const pokerProvider = {
    listTables () {
      return [
        { tableKey: 'a'.repeat(64), length: 5, writers: ['w1', 'w2'], lastTs: 1751900000000 }
      ]
    }
  }
  const registry = {
    get (name) { return name === 'poker' ? { provider: pokerProvider, status: 'running' } : null },
    services: new Map([['poker', { provider: pokerProvider, status: 'running' }]])
  }
  const { port } = await serverWithApi(t, mockNode({ registry }))
  const res = await request(port, 'GET', '/api/poker/usage', null, {
    Authorization: `Bearer ${API_KEY}`
  })

  t.is(res.statusCode, 200)
  t.is(res.body.enabled, true)
  t.is(res.body.tables, 1)
  t.is(res.body.appends, 5)
  t.is(res.body.seats, 2)
})
