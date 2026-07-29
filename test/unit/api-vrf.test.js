/**
 * VRF HTTP surface — drives the real RelayAPI mount of api-vrf.js against a
 * real VRFService instance (beacon enabled). No mocks of the route handler.
 */
import test from 'brittle'
import http from 'http'
import { RelayAPI } from 'p2p-hiverelay/core/relay-node/api.js'
import { BUILTIN_SERVICE_NAMES } from 'p2p-hiverelay/core/plugin-loader.js'
import { VRFService } from 'p2p-hiveservices/builtin/vrf-service.js'
import {
  isVrfHttpRoute,
  resolveVrfRoute,
  runVrfRouteAction
} from 'p2p-hiverelay/core/relay-node/api-vrf.js'

const API_KEY = 'vrf-test-key'
// Fixed seed so beacon outputs are deterministic across runs.
const FIXED_SEED = '01'.repeat(32)

function vrfRegistry (provider) {
  const entry = {
    name: 'vrf',
    version: '1.0.0',
    status: 'running',
    capabilities: provider.manifest().capabilities,
    provider
  }
  return { services: new Map([['vrf', entry]]) }
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
    keyPair: opts.keyPair || null,
    async stop () {},
    async start () {},
    on () {},
    emit () {}
  }
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

async function serverWithApi (t, node, opts = {}) {
  const api = new RelayAPI(node, { apiPort: 0, apiHost: '127.0.0.1', apiKey: API_KEY, ...opts })
  await api.start()
  const port = api.server.address().port
  t.teardown(async () => {
    await api.stop()
  })
  return { api, port }
}

async function startedVrf (t, opts = {}) {
  const service = new VRFService({
    seed: FIXED_SEED,
    beacon: { enabled: true, intervalMs: 60_000, retain: 8, ...(opts.beacon || {}) }
  })
  await service.start({})
  t.teardown(async () => { await service.stop() })
  return service
}

test('vrf is a builtin service provider', (t) => {
  t.ok(BUILTIN_SERVICE_NAMES.includes('vrf'))
})

test('VRF service consumes Node PluginLoader context.config.vrfBeacon', async (t) => {
  const service = new VRFService({ seed: FIXED_SEED })
  await service.start({
    config: {
      vrfBeacon: { enabled: true, intervalMs: 12_345, retain: 7, domain: 'context-beacon' }
    }
  })
  t.teardown(async () => { await service.stop() })

  const info = await service['beacon-info']()
  t.is(info.intervalMs, 12_345)
  t.is(info.retain, 7)
  t.ok(service.beacon, 'Node runtime config enables the beacon')
})

test('isVrfHttpRoute and resolveVrfRoute match the documented surface', (t) => {
  t.ok(isVrfHttpRoute('/api/v1/vrf/beacon-info'))
  t.ok(isVrfHttpRoute('/api/v1/vrf/beacon-latest'))
  t.absent(isVrfHttpRoute('/api/v1/notify/send'))

  const info = resolveVrfRoute('GET', '/api/v1/vrf/beacon-info')
  t.is(info.kind, 'vrf-call')
  t.is(info.method, 'beacon-info')

  const latest = resolveVrfRoute('GET', '/api/v1/vrf/beacon-latest')
  t.is(latest.method, 'beacon-latest')

  const round = resolveVrfRoute('GET', '/api/v1/vrf/beacon-round/3')
  t.is(round.method, 'beacon-round')
  t.is(round.round, 3)

  const select = resolveVrfRoute('POST', '/api/v1/vrf/select')
  t.is(select.method, 'select')

  t.is(resolveVrfRoute('POST', '/api/v1/vrf/beacon-info').kind, 'method-not-allowed')
  t.is(resolveVrfRoute('GET', '/api/v1/other'), null)
})

test('/api/v1/vrf/* returns 503 when vrf is not enabled', async (t) => {
  const { port } = await serverWithApi(t, mockNode({ registry: null }))
  const res = await request(port, 'GET', '/api/v1/vrf/beacon-info')
  t.is(res.statusCode, 503)
  t.ok(String(res.body.error).toLowerCase().includes('vrf'))
})

test('GET /api/v1/vrf/beacon-info and /beacon-latest return 200 with expected fields', async (t) => {
  const service = await startedVrf(t)
  const { port } = await serverWithApi(t, mockNode({ registry: vrfRegistry(service) }))

  const info = await request(port, 'GET', '/api/v1/vrf/beacon-info')
  t.is(info.statusCode, 200, 'beacon-info status')
  t.ok(info.body, 'beacon-info body')
  // Beacon info exposes genesis/round/retention (+ intervalMs from service)
  t.ok(typeof info.body.round === 'number' || typeof info.body.currentRound === 'number' || info.body.genesis != null || info.body.domain != null,
    'beacon-info has beacon identity fields')
  t.ok(info.body.intervalMs == null || typeof info.body.intervalMs === 'number')

  const latest = await request(port, 'GET', '/api/v1/vrf/beacon-latest')
  t.is(latest.statusCode, 200, 'beacon-latest status')
  t.ok(latest.body, 'beacon-latest body')
  // After start() the beacon advances once, so latest should carry a round + proof
  t.ok(typeof latest.body.round === 'number', 'latest.round is a number')
  t.ok(latest.body.pi || latest.body.beta || latest.body.hash || latest.body.pending === true || latest.body.domain,
    'latest has round material (pi/beta/hash) or pending genesis')
})

test('GET /api/v1/vrf/status and /info work through the same mount', async (t) => {
  const service = await startedVrf(t)
  const { port } = await serverWithApi(t, mockNode({ registry: vrfRegistry(service) }))

  const status = await request(port, 'GET', '/api/v1/vrf/status')
  t.is(status.statusCode, 200)
  t.alike(status.body, { ready: true, service: 'vrf' })

  const info = await request(port, 'GET', '/api/v1/vrf/info')
  t.is(info.statusCode, 200)
  t.ok(info.body.suite)
  t.ok(info.body.pubkey)
})

test('POST /api/v1/vrf/select returns a verifiable committee', async (t) => {
  const service = await startedVrf(t)
  const { port } = await serverWithApi(t, mockNode({ registry: vrfRegistry(service) }))

  const alpha = 'ab'.repeat(16)
  const res = await request(port, 'POST', '/api/v1/vrf/select', {
    alpha,
    candidates: ['a', 'b', 'c', 'd'],
    count: 2
  })
  t.is(res.statusCode, 200)
  t.ok(Array.isArray(res.body.committee))
  t.is(res.body.committee.length, 2)
  t.ok(res.body.pi)
  t.ok(res.body.beta)
  t.ok(res.body.pubkey)
})

test('runVrfRouteAction calls the real service methods (unit, no HTTP)', async (t) => {
  const service = await startedVrf(t)
  const providerResult = { ok: true, provider: service }

  const info = await runVrfRouteAction({
    route: resolveVrfRoute('GET', '/api/v1/vrf/beacon-info'),
    providerResult
  })
  t.is(info.status, 200)
  t.ok(info.payload)

  const latest = await runVrfRouteAction({
    route: resolveVrfRoute('GET', '/api/v1/vrf/beacon-latest'),
    providerResult
  })
  t.is(latest.status, 200)
  t.ok(typeof latest.payload.round === 'number')

  const round = await runVrfRouteAction({
    route: resolveVrfRoute('GET', '/api/v1/vrf/beacon-round/0'),
    providerResult
  })
  t.is(round.status, 200)
})
