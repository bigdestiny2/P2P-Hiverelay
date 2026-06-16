/**
 * Services management API (the Services tab backend).
 *
 * Pins the two bug fixes (GET reads ServiceEntry fields, restart uses
 * registry.restart) and the two new endpoints (available, config opt-in).
 */

import test from 'brittle'
import http from 'http'
import { RelayAPI } from 'p2p-hiverelay/core/relay-node/api.js'

const API_KEY = 'svc-test-key'
const AUTH = { Authorization: 'Bearer ' + API_KEY }

function fakeRegistry () {
  const entry = {
    name: 'ai',
    version: '1.0.0',
    status: 'running',
    capabilities: ['infer', 'embed'],
    description: 'AI inference',
    stats: { requests: 3, errors: 0 },
    restartCount: 0,
    lastError: null
  }
  return {
    services: new Map([['ai', entry]]),
    _restarted: null,
    _unregistered: null,
    async restart (name) { this._restarted = name; return entry },
    async unregister (name) { this._unregistered = name; return true },
    catalog () { return [{ name: 'ai', version: '1.0.0', capabilities: entry.capabilities }] }
  }
}

function mockNode (opts = {}) {
  return {
    running: true,
    config: { storage: null, plugins: opts.plugins || [] },
    metrics: { getSummary () { return { uptime: 1 } } },
    seededApps: new Map(),
    appRegistry: { apps: new Map(), catalog () { return [] }, catalogForBroadcast () { return [] } },
    getStats () { return { running: true } },
    getHealthStatus () { return { healthy: true } },
    async stop () {},
    async start () {},
    serviceRegistry: opts.registry || null,
    _servicesConfigCalls: [],
    async setServicesConfig (cfg) {
      this._servicesConfigCalls.push(cfg)
      // mimic the real one: filter to a known builtin
      const plugins = (cfg.plugins || []).filter(p => ['ai', 'storage', 'identity', 'zk', 'sla', 'schema', 'arbitration', 'vrf'].includes(p))
      return { enabled: cfg.enabled === true, plugins }
    },
    on () {},
    emit () {}
  }
}

function request (port, method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, method, path, headers: { 'Content-Type': 'application/json', ...headers } }, (res) => {
      let d = ''
      res.on('data', c => { d += c })
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
    await new Promise(resolve => api.server.close(resolve))
  })
  return port
}

test('GET /api/manage/services: disabled when no registry', async (t) => {
  const port = await server(t, mockNode())
  const res = await request(port, 'GET', '/api/manage/services', null, AUTH)
  t.is(res.statusCode, 200)
  t.is(res.body.enabled, false)
  t.alike(res.body.services, [])
})

test('GET /api/manage/services: reads ServiceEntry fields (not provider.*)', async (t) => {
  const port = await server(t, mockNode({ registry: fakeRegistry() }))
  const res = await request(port, 'GET', '/api/manage/services', null, AUTH)
  t.is(res.statusCode, 200)
  t.is(res.body.enabled, true)
  t.is(res.body.count, 1)
  const s = res.body.services[0]
  t.is(s.name, 'ai')
  t.is(s.running, true, 'running derived from status === running')
  t.is(s.status, 'running')
  t.alike(s.capabilities, ['infer', 'embed'])
  t.alike(s.stats, { requests: 3, errors: 0 })
})

test('POST /api/manage/services restart: uses registry.restart, not entry.stop/start', async (t) => {
  const reg = fakeRegistry()
  const port = await server(t, mockNode({ registry: reg }))
  const res = await request(port, 'POST', '/api/manage/services', { action: 'restart', service: 'ai' }, AUTH)
  t.is(res.statusCode, 200)
  t.is(res.body.ok, true)
  t.is(reg._restarted, 'ai', 'registry.restart called with the service name')
})

test('POST restart: 404 for unknown service', async (t) => {
  const port = await server(t, mockNode({ registry: fakeRegistry() }))
  const res = await request(port, 'POST', '/api/manage/services', { action: 'restart', service: 'nope' }, AUTH)
  t.is(res.statusCode, 404)
})

test('GET /api/manage/services/available: builtins + active + plugins', async (t) => {
  const port = await server(t, mockNode({ registry: fakeRegistry(), plugins: ['ai'] }))
  const res = await request(port, 'GET', '/api/manage/services/available', null, AUTH)
  t.is(res.statusCode, 200)
  t.is(res.body.enabled, true)
  t.ok(res.body.available.includes('ai') && res.body.available.includes('storage'))
  t.alike(res.body.active, ['ai'])
  t.alike(res.body.plugins, ['ai'])
})

test('POST /api/manage/services/config: persists opt-in, restartRequired', async (t) => {
  const node = mockNode()
  const port = await server(t, node)
  const res = await request(port, 'POST', '/api/manage/services/config', { enabled: true, plugins: ['ai', 'bogus'] }, AUTH)
  t.is(res.statusCode, 200)
  t.is(res.body.ok, true)
  t.is(res.body.restartRequired, true)
  t.is(res.body.enabled, true)
  t.alike(res.body.plugins, ['ai'], 'bogus plugin filtered out')
  t.is(node._servicesConfigCalls.length, 1)
})

test('config endpoint requires auth', async (t) => {
  const port = await server(t, mockNode())
  const res = await request(port, 'POST', '/api/manage/services/config', { enabled: true, plugins: ['ai'] })
  t.is(res.statusCode, 401)
})
