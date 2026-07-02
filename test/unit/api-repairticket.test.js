import test from 'brittle'
import http from 'http'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import { RelayAPI } from 'p2p-hiverelay/core/relay-node/api.js'
import { BUILTIN_SERVICE_NAMES } from 'p2p-hiverelay/core/plugin-loader.js'
import {
  REPAIRTICKET_RECORD_TYPE_TICKET,
  RepairTicketApp,
  signRepairRecord
} from 'p2p-hiveservices/builtin/repairticket/index.js'

const API_KEY = 'repairticket-test-key'
const CREATED_AT = '2026-07-02T12:00:00.000Z'
const EXPIRES_AT = '2026-07-02T18:00:00.000Z'
const NOW = Date.parse('2026-07-02T12:05:00.000Z')
const TARGET = 'a'.repeat(64)
const TARGET_HASH = 'b'.repeat(64)
const WITNESS_ID = 'c'.repeat(64)

function repairRegistry (provider) {
  const entry = {
    name: 'repairticket',
    version: '0.1.0',
    status: 'running',
    capabilities: ['repairticket.append', 'repairticket.range', 'repairticket.tickets', 'repairticket.events'],
    provider
  }
  return { services: new Map([['repairticket', entry]]) }
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

test('repairticket is a builtin service provider', (t) => {
  t.ok(BUILTIN_SERVICE_NAMES.includes('repairticket'))
})

test('/api/repair/status returns 503 when repairticket is not enabled', async (t) => {
  const { port } = await serverWithApi(t, mockNode({ registry: null }))
  const res = await request(port, 'GET', '/api/repair/status')

  t.is(res.statusCode, 503)
  t.alike(res.body, { error: 'RepairTicket service is not enabled on this relay' })
})

test('/api/repair/status redacts adapter load failures and emits internals', async (t) => {
  const app = new RepairTicketApp({ verify: { now: NOW } })
  const { api, port } = await serverWithApi(t, mockNode({ registry: repairRegistry(app) }))
  const events = []
  api.on('repairticket-http-adapter-error', (event) => events.push(event))
  api._loadRepairTicketHttpAdapter = async function () {
    throw new Error('internal adapter path /data/hiverelay/private/repairticket/http-adapter.js failed')
  }

  const res = await request(port, 'GET', '/api/repair/status')

  t.is(res.statusCode, 503)
  t.is(res.body.error, 'unsupported: repairticket HTTP adapter unavailable')
  t.is(res.body.errorCode, 'repairticket-http-adapter-unavailable')
  t.absent(JSON.stringify(res.body).includes('/data/hiverelay/private'))
  t.is(events.length, 1)
  t.ok(events[0].error.message.includes('/data/hiverelay/private'))
})

test('/api/repair bridge appends and reads signed repair tickets through RelayAPI', async (t) => {
  const signer = keyPair(1)
  const app = new RepairTicketApp({ verify: { now: NOW } })
  const { port } = await serverWithApi(t, mockNode({ registry: repairRegistry(app) }))
  const ticket = signRepairRecord(ticketInput(signer), signer.secretKey)

  const status = await request(port, 'GET', '/api/repair/status')
  t.alike(status.body, { ready: true, service: 'repairticket' })

  const append = await request(port, 'POST', '/api/repair/append', { record: ticket })
  t.is(append.statusCode, 200)
  t.alike(append.body, { ok: true, key: 'ticket!' + ticket.id, id: ticket.id, ticketId: ticket.id })

  const list = await request(port, 'GET', '/api/repair?target=' + TARGET_HASH)
  t.is(list.statusCode, 200)
  t.is(list.body.count, 1)
  t.is(list.body.tickets[0].id, ticket.id)
  t.absent(list.body.tickets[0].target.key)
})

function ticketInput (signer) {
  return {
    type: REPAIRTICKET_RECORD_TYPE_TICKET,
    createdAt: CREATED_AT,
    expiresAt: EXPIRES_AT,
    signer: {
      publicKey: signer.publicKeyHex,
      role: 'witness'
    },
    target: {
      kind: 'hypercore',
      key: TARGET,
      keyHash: TARGET_HASH
    },
    repair: {
      reason: 'witness-failure',
      priority: 80,
      desiredReplicas: 5,
      observedReplicas: 1,
      evidence: [WITNESS_ID]
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
