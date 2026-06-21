/**
 * Honest-metering HTTP surface: POST /api/usage/receipt (open, verified-only
 * collection) + GET /api/usage (auth-gated payout-eligible digest). Boots a
 * real RelayAPI over HTTP with a real UsageLedger on the node. trustProxy:true
 * so localhost doesn't bypass the auth gate on the digest view.
 */
import test from 'brittle'
import http from 'http'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { RelayAPI } from 'p2p-hiverelay/core/relay-node/api.js'
import { UsageLedger, createUsageReceipt } from 'p2p-hiverelay/core/protocol/usage-receipt.js'

const API_KEY = 'usage-test-key'
const AUTH = { Authorization: 'Bearer ' + API_KEY }
const RELAY = b4a.toString(b4a.alloc(32, 7), 'hex')

function keypair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}
function receipt (units = 4) {
  return createUsageReceipt(keypair(), { relayPubkey: RELAY, service: 'poker', capability: 'append', unitKind: 'appends', units, epoch: 1 })
}
function mockNode (opts = {}) {
  return {
    running: true,
    config: { storage: null, plugins: [], trustProxy: true },
    metrics: { getSummary () { return { uptime: 1 } } },
    seededApps: new Map(),
    appRegistry: { apps: new Map(), catalog () { return [] }, catalogForBroadcast () { return [] } },
    getStats () { return { running: true } },
    getHealthStatus () { return { healthy: true } },
    serviceRegistry: opts.registry || null,
    usageLedger: 'usageLedger' in opts ? opts.usageLedger : new UsageLedger(),
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
  return { port, node }
}

test('POST /api/usage/receipt records a verified receipt (open, no auth)', async (t) => {
  const { port, node } = await server(t, mockNode())
  const res = await request(port, 'POST', '/api/usage/receipt', receipt(4)) // no auth — the sig IS the authorization
  t.is(res.statusCode, 200)
  t.ok(res.body.ok)
  t.is(node.usageLedger.digest().count, 1, 'recorded into the ledger')
  t.is(node.usageLedger.totals()['poker.append.appends'], 4)
})

test('POST /api/usage/receipt rejects a forged receipt with 400', async (t) => {
  const { port, node } = await server(t, mockNode())
  const forged = { ...receipt(4), units: 999 } // tampered after signing
  const res = await request(port, 'POST', '/api/usage/receipt', forged)
  t.is(res.statusCode, 400)
  t.is(res.body.reason, 'bad-signature')
  t.is(node.usageLedger.digest().count, 0, 'nothing recorded')
})

test('POST /api/usage/receipt rejects a replay with 400', async (t) => {
  const { port } = await server(t, mockNode())
  const r = receipt(4)
  t.is((await request(port, 'POST', '/api/usage/receipt', r)).statusCode, 200)
  const second = await request(port, 'POST', '/api/usage/receipt', r)
  t.is(second.statusCode, 400)
  t.is(second.body.reason, 'replay')
})

test('POST /api/usage/receipt → 400 on garbage body, 503 when metering off', async (t) => {
  const { port } = await server(t, mockNode())
  t.is((await request(port, 'POST', '/api/usage/receipt', { not: 'a receipt' })).statusCode, 400)
  const off = await server(t, mockNode({ usageLedger: null }))
  t.is((await request(off.port, 'POST', '/api/usage/receipt', receipt())).statusCode, 503)
})

test('GET /api/usage is auth-gated and returns the payout-eligible digest', async (t) => {
  const { port, node } = await server(t, mockNode())
  node.usageLedger.record(receipt(3))
  node.usageLedger.record(receipt(5))
  t.is((await request(port, 'GET', '/api/usage')).statusCode, 401, 'no auth → 401')
  const ok = await request(port, 'GET', '/api/usage', null, AUTH)
  t.is(ok.statusCode, 200)
  t.is(ok.body.verified.count, 2)
  t.is(ok.body.verified.totals['poker.append.appends'], 8)
  t.ok(/payout-eligible/.test(ok.body.note), 'note distinguishes verified from self-reported')
})
