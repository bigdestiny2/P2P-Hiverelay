/**
 * POST /seed-core — pin a BARE Hypercore (e.g. a replicable catalog bee) by
 * public key, via Seeder.seedCore. Distinct from /seed, which opens a
 * Hyperdrive. Operator-authed.
 */

import test from 'brittle'
import http from 'http'
import { RelayAPI } from 'p2p-hiverelay/core/relay-node/api.js'
import {
  normalizeSeedCoreKey,
  resolveSeedCoreRoute,
  SEED_CORE_AUTH_MESSAGE,
  runSeedCoreAction
} from 'p2p-hiverelay/core/relay-node/api-seed-core.js'

const API_KEY = 'seed-core-test-key'
const HEX64 = 'a'.repeat(64)

function mockRelayNode (seeder, opts = {}) {
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
    federation: null,
    _resolveAcceptMode () { return 'open' },
    catalogBeeKey: opts.catalogBeeKey || null,
    _catalogSet: [],
    async setCatalogBeeKey (k) { this._catalogSet.push(k); this.catalogBeeKey = k; return k },
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
        resolve({ statusCode: res.statusCode, headers: res.headers, body: parsed })
      })
    })
    req.on('error', reject)
    if (body !== undefined && body !== null) req.write(JSON.stringify(body))
    req.end()
  })
}

async function makeServer (t, seeder, nodeOpts) {
  const node = mockRelayNode(seeder, nodeOpts)
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

test('seed-core helper: route resolver maps only the exact operator seed-core route', (t) => {
  t.alike(resolveSeedCoreRoute('POST', '/seed-core'), {
    kind: 'seed-core',
    authMessage: SEED_CORE_AUTH_MESSAGE
  })
  t.is(resolveSeedCoreRoute('GET', '/seed-core'), null, 'wrong method falls through')
  t.is(resolveSeedCoreRoute('POST', '/seed-core/extra'), null, 'subpath falls through')
  t.is(resolveSeedCoreRoute('POST', '/seed'), null, 'adjacent operator seed route falls through')
  t.is(resolveSeedCoreRoute('POST', '/api/v1/seed'), null, 'publisher seed route falls through')
})

test('seed-core helper: normalizes aliases and validates route contract', async (t) => {
  t.is(normalizeSeedCoreKey({ coreKey: '  ' + 'A'.repeat(64) + '  ' }), HEX64)
  t.is(normalizeSeedCoreKey({ appKey: 'B'.repeat(64) }), 'b'.repeat(64))
  t.is(normalizeSeedCoreKey({ coreKey: 'not-hex' }), null)

  const unavailable = await runSeedCoreAction({ node: {}, body: { coreKey: HEX64 } })
  t.alike(unavailable, { ok: false, status: 503, payload: { error: 'seeder not available' } })

  const calls = []
  const node = mockRelayNode({
    async seedCore (key) {
      calls.push(key)
      return { core: { length: 9 } }
    }
  })
  const seeded = await runSeedCoreAction({ node, body: { coreKey: 'A'.repeat(64), catalog: true } })
  t.alike(seeded, {
    ok: true,
    status: 200,
    payload: { ok: true, coreKey: HEX64, length: 9, catalogBee: true }
  })
  t.alike(calls, [HEX64])
  t.alike(node._catalogSet, [HEX64])
})

test('seed-core helper: delegates seed errors to caller error mapping', async (t) => {
  const err = new Error('corestore closed')
  const result = await runSeedCoreAction({
    node: mockRelayNode({
      async seedCore () {
        throw err
      }
    }),
    body: { coreKey: HEX64 }
  })

  t.is(result.ok, false)
  t.is(result.kind, 'seed-error')
  t.is(result.error, err)
})

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

test('seed-core: transient seed errors stay retryable through the route', async (t) => {
  const seeder = {
    async seedCore () {
      throw new Error('The corestore is closed')
    }
  }
  const { port } = await makeServer(t, seeder)
  const res = await request(port, 'POST', '/seed-core', { coreKey: HEX64 }, { Authorization: 'Bearer ' + API_KEY })
  t.is(res.statusCode, 503)
  t.is(res.headers['retry-after'], '5')
  t.is(res.body.retryable, true)
})

test('seed-core: catalog:true registers the catalog-bee pointer', async (t) => {
  const seeder = { async seedCore () { return { core: { length: 2 } } } }
  const { port, node } = await makeServer(t, seeder)
  const res = await request(port, 'POST', '/seed-core', { coreKey: HEX64, catalog: true }, { Authorization: 'Bearer ' + API_KEY })
  t.is(res.statusCode, 200)
  t.is(res.body.catalogBee, true)
  t.alike(node._catalogSet, [HEX64], 'setCatalogBeeKey called with the core key')
  t.is(node.catalogBeeKey, HEX64)
})

test('seed-core: without catalog flag, no pointer is set', async (t) => {
  const seeder = { async seedCore () { return { core: { length: 2 } } } }
  const { port, node } = await makeServer(t, seeder)
  const res = await request(port, 'POST', '/seed-core', { coreKey: HEX64 }, { Authorization: 'Bearer ' + API_KEY })
  t.is(res.body.catalogBee, false)
  t.alike(node._catalogSet, [], 'setCatalogBeeKey not called')
})

test('catalog.json surfaces catalogBeeKey', async (t) => {
  const { port } = await makeServer(t, null, { catalogBeeKey: HEX64 })
  const res = await request(port, 'GET', '/catalog.json')
  t.is(res.statusCode, 200)
  t.is(res.body.catalogBeeKey, HEX64, 'catalog pointer surfaced for consumers')
})

test('catalog.json: catalogBeeKey is null until a catalog bee is published', async (t) => {
  const { port } = await makeServer(t, null)
  const res = await request(port, 'GET', '/catalog.json')
  t.is(res.body.catalogBeeKey, null)
})
