import test from 'brittle'
import http from 'http'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { RelayAPI } from 'p2p-hiverelay/core/relay-node/api.js'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import { verifyAccountingReceipt } from 'p2p-hiverelay/core/protocol/accounting-receipt.js'
import {
  accountingReceiptRefreshFlag,
  buildAccountingReceiptPayload,
  buildAccountingReceiptRoutePayload,
  resolveAccountingReceiptRoute
} from 'p2p-hiverelay/core/relay-node/api-accounting-receipt.js'

const API_KEY = 'accounting-runtime-test-key'
const AUTH = { Authorization: 'Bearer ' + API_KEY }

function keypairFromSeed (byte) {
  const seed = b4a.alloc(sodium.crypto_sign_SEEDBYTES, byte)
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)
  return { publicKey, secretKey }
}

function runtimeNode (opts = {}) {
  const node = Object.create(RelayNode.prototype)
  let measureCount = 0
  Object.assign(node, {
    keyPair: opts.keyPair || keypairFromSeed(4),
    storageAccounting: {
      async measureDisk () { measureCount++ },
      getSummary () {
        return opts.summary || {
          totalBytes: 4096,
          diskBytes: 3072,
          perEntryBytes: 2048,
          measuredEntries: 2
        }
      }
    },
    servedAccounting: {
      getSummary () {
        return { totalBytesServed: 900, totalBlocksServed: 3 }
      }
    },
    seeder: {
      getStats () {
        return { totalBytesServed: 100 }
      }
    },
    leaseManager: {
      getSummary () {
        return { leaseCount: 7 }
      }
    },
    measureCount: () => measureCount
  })
  return node
}

function apiNode (opts = {}) {
  return {
    running: true,
    config: { storage: null, plugins: [], trustProxy: true },
    metrics: { getSummary () { return { uptime: 1 } } },
    seededApps: new Map(),
    appRegistry: { apps: new Map(), catalog () { return [] }, catalogForBroadcast () { return [] } },
    getStats () { return { running: true } },
    getHealthStatus () { return { healthy: true } },
    createAccountingReceipt: opts.createAccountingReceipt,
    async stop () {},
    async start () {},
    on () {},
    emit () {}
  }
}

function request (port, method, path, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      method,
      path,
      headers
    }, (res) => {
      let body = ''
      res.on('data', (chunk) => { body += chunk })
      res.on('end', () => {
        let parsed
        try { parsed = JSON.parse(body) } catch { parsed = body }
        resolve({ statusCode: res.statusCode, body: parsed })
      })
    })
    req.on('error', reject)
    req.end()
  })
}

async function server (t, node) {
  const api = new RelayAPI(node, { apiPort: 0, apiHost: '127.0.0.1', apiKey: API_KEY, trustProxy: true })
  await api.start()
  const port = api.server.address().port
  t.teardown(async () => {
    if (api._rateLimitCleanup) clearInterval(api._rateLimitCleanup)
    if (api._dashboardFeed) { try { api._dashboardFeed.stop() } catch (_) {} }
    if (api._pokerFeed) { try { api._pokerFeed.stop() } catch (_) {} }
    await new Promise((resolve) => api.server.close(resolve))
  })
  return { port }
}

test('RelayNode.createAccountingReceipt signs the OS-grounded runtime summary', async (t) => {
  const node = runtimeNode()
  const receipt = await node.createAccountingReceipt({
    periodStart: 100,
    periodEnd: 200,
    measuredAt: 201,
    nonce: '11'.repeat(16)
  })

  t.is(node.measureCount(), 1, 'refreshes disk measurement before signing')
  t.is(receipt.storageBytes, 4096)
  t.is(receipt.diskBytes, 3072)
  t.is(receipt.perEntryBytes, 2048)
  t.is(receipt.bytesServed, 900, 'prefers served-accounting over seeder fallback')
  t.is(receipt.leaseCount, 7)
  t.is(receipt.seededCount, 2)
  t.ok(verifyAccountingReceipt(receipt).valid, 'runtime receipt verifies')
})

test('RelayNode.createAccountingReceipt refuses to sign without OS disk measurement', async (t) => {
  const node = runtimeNode({
    summary: {
      totalBytes: 4096,
      diskBytes: null,
      perEntryBytes: 2048,
      measuredEntries: 2
    }
  })

  await t.exception(node.createAccountingReceipt({ nonce: '22'.repeat(16) }), /OS disk measurement unavailable/)
})

test('RelayNode.createAccountingReceipt rejects malformed runtime counter overrides', async (t) => {
  const node = runtimeNode()
  await t.exception(node.createAccountingReceipt({
    bytesServed: -1,
    nonce: '44'.repeat(16)
  }), /bad bytesServed/)
})

test('api accounting receipt helper maps exact operator receipt route', (t) => {
  t.alike(resolveAccountingReceiptRoute('GET', '/api/accounting/receipt'), {
    kind: 'receipt',
    authMessage: 'Unauthorized — accounting receipt requires API key or localhost'
  })

  t.is(resolveAccountingReceiptRoute('POST', '/api/accounting/receipt'), null)
  t.is(resolveAccountingReceiptRoute('GET', '/api/accounting/receipt/extra'), null)
  t.is(resolveAccountingReceiptRoute('GET', '/api/accounting/receipts'), null)
})

test('api accounting receipt helper preserves refresh and error contract', async (t) => {
  t.is(accountingReceiptRefreshFlag(null), true)
  t.is(accountingReceiptRefreshFlag('1'), true)
  t.is(accountingReceiptRefreshFlag('0'), false)

  const unavailable = await buildAccountingReceiptPayload({ node: null })
  t.alike(unavailable, {
    status: 503,
    payload: { error: 'accounting receipts unavailable' }
  })

  const calls = []
  const ok = await buildAccountingReceiptPayload({
    node: {
      async createAccountingReceipt (opts) {
        calls.push(opts)
        return { kind: 'hiverelay-accounting-receipt-v1' }
      }
    },
    refresh: false
  })
  t.alike(ok, {
    status: 200,
    payload: { receipt: { kind: 'hiverelay-accounting-receipt-v1' } }
  })
  t.alike(calls, [{ refresh: false }])

  const failed = await buildAccountingReceiptPayload({
    node: {
      async createAccountingReceipt () {
        throw new Error('ACCOUNTING_RECEIPT_UNAVAILABLE: OS disk measurement unavailable')
      }
    }
  })
  t.alike(failed, {
    status: 503,
    payload: { error: 'ACCOUNTING_RECEIPT_UNAVAILABLE: OS disk measurement unavailable' }
  })
})

test('api accounting receipt route payload helper dispatches receipt reads', async (t) => {
  const calls = []
  const node = {
    async createAccountingReceipt (opts) {
      calls.push(opts)
      return { kind: 'hiverelay-accounting-receipt-v1', refresh: opts.refresh }
    }
  }

  const noRefresh = await buildAccountingReceiptRoutePayload({
    route: resolveAccountingReceiptRoute('GET', '/api/accounting/receipt'),
    node,
    url: new URL('http://relay.test/api/accounting/receipt?refresh=0')
  })
  t.alike(noRefresh, {
    status: 200,
    payload: { receipt: { kind: 'hiverelay-accounting-receipt-v1', refresh: false } }
  })

  const defaultRefresh = await buildAccountingReceiptRoutePayload({
    route: resolveAccountingReceiptRoute('GET', '/api/accounting/receipt'),
    node,
    url: new URL('http://relay.test/api/accounting/receipt')
  })
  t.alike(defaultRefresh, {
    status: 200,
    payload: { receipt: { kind: 'hiverelay-accounting-receipt-v1', refresh: true } }
  })
  t.alike(calls, [{ refresh: false }, { refresh: true }])

  const unknown = await buildAccountingReceiptRoutePayload({
    route: null,
    node: {
      async createAccountingReceipt () {
        throw new Error('should not create receipt')
      }
    }
  })
  t.alike(unknown, {
    status: 404,
    payload: { error: 'unknown accounting receipt route' }
  })
})

test('GET /api/accounting/receipt is auth-gated and returns a verifiable receipt', async (t) => {
  const node = runtimeNode()
  const refreshes = []
  const { port } = await server(t, apiNode({
    createAccountingReceipt: (opts) => {
      refreshes.push(opts.refresh)
      return node.createAccountingReceipt({
        ...opts,
        periodStart: 100,
        periodEnd: 200,
        measuredAt: 201,
        nonce: '33'.repeat(16)
      })
    }
  }))

  t.is((await request(port, 'GET', '/api/accounting/receipt')).statusCode, 401, 'no auth is rejected')
  const ok = await request(port, 'GET', '/api/accounting/receipt', AUTH)
  t.is(ok.statusCode, 200)
  t.ok(verifyAccountingReceipt(ok.body.receipt).valid)
  t.is(ok.body.receipt.diskBytes, 3072)

  const noRefresh = await request(port, 'GET', '/api/accounting/receipt?refresh=0', AUTH)
  t.is(noRefresh.statusCode, 200)
  t.alike(refreshes, [true, false])
})

test('GET /api/accounting/receipt reports unavailable receipts as 503', async (t) => {
  const { port } = await server(t, apiNode({
    async createAccountingReceipt () {
      throw new Error('ACCOUNTING_RECEIPT_UNAVAILABLE: OS disk measurement unavailable')
    }
  }))

  const res = await request(port, 'GET', '/api/accounting/receipt', AUTH)
  t.is(res.statusCode, 503)
  t.is(res.body.error, 'ACCOUNTING_RECEIPT_UNAVAILABLE: OS disk measurement unavailable')
})
