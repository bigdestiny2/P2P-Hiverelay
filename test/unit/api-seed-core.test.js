/**
 * POST /seed-core — pin a BARE Hypercore (e.g. a replicable catalog bee) by
 * public key, via Seeder.seedCore. Distinct from /seed, which opens a
 * Hyperdrive. Operator-authed.
 */

import test from 'brittle'
import http from 'http'
import { RelayAPI } from 'p2p-hiverelay/core/relay-node/api.js'

const API_KEY = 'seed-core-test-key'
const HEX64 = 'a'.repeat(64)

function mockRelayNode (seeder) {
  return {
    running: true,
    config: { storage: null },
    metrics: { getSummary () { return { uptime: 100 } } },
    seededApps: new Map(),
    appRegistry: { apps: new Map(), catalog () { return [] }, catalogForBroadcast () { return [] } },
    getStats () { return { running: true, seededApps: 0, connections: 0 } },
    getHealthStatus () { return { healthy: true } },
    async stop () {},
    async start () {},
    async seedApp () { return { ok: true } },
    async unseedApp () {},
    seeder,
    swarm: null,
    on () {},
    emit () {}
  }
}

function request (port, method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, method, path, headers: { 'Content-Type': 'application/json', ...headers } }, (res) => {
      let data = ''
      res.on('data', (c) => { data += c })
      res.on('end', () => {
        let parsed
        try { parsed = JSON.parse(data) } catch (_) { parsed = data }
        resolve({ statusCode: res.statusCode, body: parsed })
      })
    })
    req.on('error', reject)
    if (body !== undefined && body !== null) req.write(JSON.stringify(body))
    req.end()
  })
}

async function makeServer (t, seeder) {
  const node = mockRelayNode(seeder)
  const api = new RelayAPI(node, { apiPort: 0, apiHost: '127.0.0.1', apiKey: API_KEY })
  await api.start()
  const port = api.server.address().port
  t.teardown(async () => {
    if (api._rateLimitCleanup) clearInterval(api._rateLimitCleanup)
    if (api._dashboardFeed) { try { api._dashboardFeed.stop() } catch (_) {} }
    await new Promise(resolve => api.server.close(resolve))
  })
  return { port, node }
}

test('seed-core: auth required', async (t) => {
  const { port } = await makeServer(t, { async seedCore () { return { core: { length: 1 } } } })
  const res = await request(port, 'POST', '/seed-core', { coreKey: HEX64 })
  t.is(res.statusCode, 401)
})

test('seed-core: valid key pins via seeder.seedCore', async (t) => {
  const calls = []
  const seeder = { async seedCore (key) { calls.push(key); return { core: { length: 7 } } } }
  const { port } = await makeServer(t, seeder)
  const res = await request(port, 'POST', '/seed-core', { coreKey: HEX64 }, { Authorization: 'Bearer ' + API_KEY })
  t.is(res.statusCode, 200)
  t.is(res.body.ok, true)
  t.is(res.body.coreKey, HEX64)
  t.is(res.body.length, 7)
  t.alike(calls, [HEX64], 'seedCore called once with the lowercased key')
})

test('seed-core: accepts appKey alias + lowercases', async (t) => {
  const calls = []
  const seeder = { async seedCore (key) { calls.push(key); return { core: { length: 0 } } } }
  const { port } = await makeServer(t, seeder)
  const res = await request(port, 'POST', '/seed-core', { appKey: 'B'.repeat(64) }, { Authorization: 'Bearer ' + API_KEY })
  t.is(res.statusCode, 200)
  t.alike(calls, ['b'.repeat(64)])
})

test('seed-core: rejects a non-64-hex key', async (t) => {
  const { port } = await makeServer(t, { async seedCore () { return { core: { length: 1 } } } })
  const res = await request(port, 'POST', '/seed-core', { coreKey: 'not-hex' }, { Authorization: 'Bearer ' + API_KEY })
  t.is(res.statusCode, 400)
  t.ok(/64 hex/.test(res.body.error))
})

test('seed-core: 503 when seeder is unavailable', async (t) => {
  const { port } = await makeServer(t, null)
  const res = await request(port, 'POST', '/seed-core', { coreKey: HEX64 }, { Authorization: 'Bearer ' + API_KEY })
  t.is(res.statusCode, 503)
})
