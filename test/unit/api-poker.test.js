/**
 * Poker services wiring — the bundle/expand logic + the /api/poker/* gateway
 * mount. Boots a real RelayAPI over HTTP with a fake 'poker' provider in the
 * registry (the substrate + handlePokerRoute itself are covered by
 * scripts/test-poker-app.js). trustProxy:true so localhost doesn't bypass the
 * create auth gate.
 */
import test from 'brittle'
import http from 'http'
import { RelayAPI } from 'p2p-hiverelay/core/relay-node/api.js'
import { BUILTIN_SERVICE_NAMES, SERVICE_BUNDLES, expandServiceDeps } from 'p2p-hiverelay/core/plugin-loader.js'

const API_KEY = 'poker-test-key'
const AUTH = { Authorization: 'Bearer ' + API_KEY }

// ── plugin-loader bundle logic (pure) ──
test('poker is a builtin + the bundle expands to its support services', (t) => {
  t.ok(BUILTIN_SERVICE_NAMES.includes('poker'), 'poker registered as a builtin')
  t.alike(SERVICE_BUNDLES.poker.slice().sort(), ['arbitration', 'poker', 'vrf', 'zk'])
  t.alike(expandServiceDeps(['poker']).sort(), ['arbitration', 'poker', 'vrf', 'zk'], 'enabling poker pulls its deps')
  t.alike(expandServiceDeps(['ai', 'poker']).sort(), ['ai', 'arbitration', 'poker', 'vrf', 'zk'], 'never clobbers existing services')
  t.alike(expandServiceDeps(['ai']), ['ai'], 'a non-bundle list is unchanged')
  t.alike(expandServiceDeps(['bogus', 'vrf']), ['vrf'], 'non-builtins are filtered out')
})

// ── fakes ──
function fakePokerApp () {
  const tables = new Map()
  return {
    listTables () { return Array.from(tables.keys()).map((k) => ({ tableKey: k })) },
    createTable (args) {
      if (tables.has(args.tableKey)) throw new Error('createTable: table already exists')
      tables.set(args.tableKey, { entries: [], writers: args.writers || [] })
      return { tableKey: args.tableKey, writers: args.writers || [] }
    },
    getState (k) { return tables.has(k) ? { tableKey: k, length: tables.get(k).entries.length } : null },
    getLog (k, from = 0, limit = Infinity) {
      if (!tables.has(k)) return null
      const all = tables.get(k).entries
      const entries = all.slice(from, limit === Infinity ? undefined : from + limit)
      return { from, to: from + entries.length, entries }
    },
    submitEntry (k, entry) {
      if (!tables.has(k)) return { ok: false, reason: 'unknown-table' }
      tables.get(k).entries.push(entry)
      return { ok: true, index: tables.get(k).entries.length - 1, ts: 1 }
    },
    subscribe () { return () => {} }
  }
}
function pokerRegistry (provider) {
  const entry = { name: 'poker', version: '0.1.0', status: 'running', capabilities: ['createTable', 'submitEntry'], provider }
  return { services: new Map([['poker', entry]]) }
}
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
function request (port, method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, method, path, headers: { 'Content-Type': 'application/json', ...headers } }, (res) => {
      let d = ''
      res.on('data', (c) => { d += c })
      res.on('end', () => { let p; try { p = JSON.parse(d) } catch { p = d } resolve({ statusCode: res.statusCode, body: p }) })
    })
    req.on('error', reject)
    if (body != null) req.write(JSON.stringify(body))
    req.end()
  })
}
async function server (t, node) {
  const api = new RelayAPI(node, { apiPort: 0, apiHost: '127.0.0.1', apiKey: API_KEY })
  await api.start()
  const port = api.server.address().port
  t.teardown(async () => {
    if (api._rateLimitCleanup) clearInterval(api._rateLimitCleanup)
    if (api._dashboardFeed) { try { api._dashboardFeed.stop() } catch (_) {} }
    if (api._pokerFeed) { try { api._pokerFeed.stop() } catch (_) {} }
    await new Promise((resolve) => api.server.close(resolve))
  })
  return port
}

test('/available surfaces the poker bundle', async (t) => {
  const port = await server(t, mockNode({ registry: pokerRegistry(fakePokerApp()) }))
  const res = await request(port, 'GET', '/api/manage/services/available', null, AUTH)
  t.is(res.statusCode, 200)
  t.ok(res.body.bundles && Array.isArray(res.body.bundles.poker), 'bundles.poker present')
  t.ok(res.body.available.includes('poker'), 'poker in available list')
})

test('/api/poker/* → 503 when poker is not enabled', async (t) => {
  const port = await server(t, mockNode({ registry: null }))
  const res = await request(port, 'GET', '/api/poker/tables')
  t.is(res.statusCode, 503)
})

test('GET /api/poker/tables is open + lists tables', async (t) => {
  const app = fakePokerApp(); app.createTable({ tableKey: 'aa', writers: ['w1'] })
  const port = await server(t, mockNode({ registry: pokerRegistry(app) }))
  const res = await request(port, 'GET', '/api/poker/tables') // no auth — reads are open
  t.is(res.statusCode, 200)
  t.is(res.body.tables.length, 1)
})

test('POST /api/poker/tables (create) is auth-gated', async (t) => {
  const app = fakePokerApp()
  const port = await server(t, mockNode({ registry: pokerRegistry(app) }))
  const noauth = await request(port, 'POST', '/api/poker/tables', { tableKey: 'bb', writers: ['w1'] })
  t.is(noauth.statusCode, 401, 'create requires auth (anti-DoS on maxTables)')
  const ok = await request(port, 'POST', '/api/poker/tables', { tableKey: 'bb', writers: ['w1'] }, AUTH)
  t.ok(ok.statusCode === 200 || ok.statusCode === 201, 'create succeeds with auth')
  t.ok(app.getState('bb'), 'table actually created')
})

test('GET /api/poker/:table/state — 200 known, 404 unknown (open reads)', async (t) => {
  const app = fakePokerApp(); app.createTable({ tableKey: 'cc', writers: ['w1'] })
  const port = await server(t, mockNode({ registry: pokerRegistry(app) }))
  t.is((await request(port, 'GET', '/api/poker/cc/state')).statusCode, 200)
  t.is((await request(port, 'GET', '/api/poker/zz/state')).statusCode, 404)
})
