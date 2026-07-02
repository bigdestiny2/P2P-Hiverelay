import test from 'brittle'
import http from 'http'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import { RelayAPI } from 'p2p-hiverelay/core/relay-node/api.js'
import { BUILTIN_SERVICE_NAMES } from 'p2p-hiverelay/core/plugin-loader.js'
import { WitnessLogApp, signWitnessRecord } from 'p2p-hiveservices/builtin/witnesslog/index.js'

const API_KEY = 'witnesslog-test-key'
const OBSERVED_AT = '2026-07-02T12:00:00.000Z'
const EXPIRES_AT = '2026-07-02T12:30:00.000Z'
const NOW = Date.parse('2026-07-02T12:05:00.000Z')
const TARGET = 'a'.repeat(64)
const TARGET_HASH = 'b'.repeat(64)

function witnessRegistry (provider) {
  const entry = {
    name: 'witnesslog',
    version: '0.1.0',
    status: 'running',
    capabilities: ['witnesslog.append', 'witnesslog.range', 'witnesslog.events'],
    provider
  }
  return { services: new Map([['witnesslog', entry]]) }
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

test('witnesslog is a builtin service provider', (t) => {
  t.ok(BUILTIN_SERVICE_NAMES.includes('witnesslog'))
})

test('/api/witness/status returns 503 when witnesslog is not enabled', async (t) => {
  const { port } = await serverWithApi(t, mockNode({ registry: null }))
  const res = await request(port, 'GET', '/api/witness/status')

  t.is(res.statusCode, 503)
  t.alike(res.body, { error: 'WitnessLog service is not enabled on this relay' })
})

test('/api/witness/status redacts adapter load failures and emits internals', async (t) => {
  const app = new WitnessLogApp({ verify: { now: NOW } })
  const { api, port } = await serverWithApi(t, mockNode({ registry: witnessRegistry(app) }))
  const events = []
  api.on('witnesslog-http-adapter-error', (event) => events.push(event))
  api._loadWitnessLogHttpAdapter = async function () {
    throw new Error('internal adapter path /data/hiverelay/private/witnesslog/http-adapter.js failed')
  }

  const res = await request(port, 'GET', '/api/witness/status')

  t.is(res.statusCode, 503)
  t.is(res.body.error, 'unsupported: witnesslog HTTP adapter unavailable')
  t.is(res.body.errorCode, 'witnesslog-http-adapter-unavailable')
  t.absent(JSON.stringify(res.body).includes('/data/hiverelay/private'))
  t.is(events.length, 1)
  t.ok(events[0].error.message.includes('/data/hiverelay/private'))
})

test('/api/witness bridge appends and reads signed availability observations through RelayAPI', async (t) => {
  const observer = keyPair(1)
  const app = new WitnessLogApp({ verify: { now: NOW } })
  const { port } = await serverWithApi(t, mockNode({ registry: witnessRegistry(app) }))
  const signed = signWitnessRecord(witnessInput(observer), observer.secretKey)

  const status = await request(port, 'GET', '/api/witness/status')
  t.alike(status.body, { ready: true, service: 'witnesslog' })

  const append = await request(port, 'POST', '/api/witness/append', { record: signed })
  t.is(append.statusCode, 200)
  t.alike(append.body, { ok: true, key: 'availability!' + signed.id, id: signed.id })

  const list = await request(port, 'GET', '/api/witness?target=' + TARGET_HASH)
  t.is(list.statusCode, 200)
  t.is(list.body.count, 1)
  t.is(list.body.records[0].id, signed.id)
  t.absent(list.body.records[0].target.key)
})

function witnessInput (observer) {
  return {
    observedAt: OBSERVED_AT,
    expiresAt: EXPIRES_AT,
    observer: {
      publicKey: observer.publicKeyHex,
      appId: 'probe-agent'
    },
    relay: {
      url: 'https://relay.example',
      operatorKey: 'c'.repeat(64)
    },
    target: {
      kind: 'hypercore',
      key: TARGET,
      keyHash: TARGET_HASH
    },
    probe: {
      nonce: 'nonce-1',
      method: 'gateway-head',
      range: { start: 0, end: 1024 }
    },
    result: {
      ok: true,
      httpStatus: 200,
      latencyMs: 42,
      bytes: 1024,
      headSeq: 7,
      digest: 'sha256:' + 'd'.repeat(64)
    }
  }
}

function keyPair (seedByte) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.alloc(32, seedByte))
  return {
    publicKey,
    secretKey,
    publicKeyHex: b4a.toString(publicKey, 'hex')
  }
}
