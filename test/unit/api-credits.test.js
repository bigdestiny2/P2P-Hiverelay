import test from 'brittle'
import http from 'http'
import {
  MAX_CREDITS_WALLETS,
  buildCreditsCompareRoutePayload,
  buildCreditsPricingRoutePayload,
  buildCreditsStatsRoutePayload,
  buildCreditsWalletsRoutePayload,
  resolveCreditsRoute
} from 'p2p-hiverelay/core/relay-node/api-credits.js'
import { RelayAPI } from 'p2p-hiverelay/core/relay-node/api.js'
import { CreditManager } from 'p2p-hiverelay/incentive/credits/index.js'
import { PricingEngine } from 'p2p-hiverelay/incentive/credits/pricing.js'

const API_KEY = 'credits-test-secret'
const APP_KEY = 'a'.repeat(64)
const PRIVATE_PATHS = [
  '/api/v1/credits/stats',
  '/api/v1/credits/wallets'
]

test('api credits: route policy keeps pricing public and finance views private', (t) => {
  t.alike(resolveCreditsRoute('GET', '/api/v1/credits/pricing'), {
    kind: 'credits-pricing',
    requiresAuth: false
  })
  t.alike(resolveCreditsRoute('GET', '/api/v1/credits/pricing/compare'), {
    kind: 'credits-pricing-compare',
    requiresAuth: false
  })
  t.alike(resolveCreditsRoute('GET', '/api/v1/credits/stats'), {
    kind: 'credits-stats',
    requiresAuth: true,
    authMessage: 'Unauthorized — credits stats require API key or localhost'
  })
  t.alike(resolveCreditsRoute('GET', '/api/v1/credits/wallets'), {
    kind: 'credits-wallets',
    requiresAuth: true,
    authMessage: 'Unauthorized — credits wallets require API key or localhost'
  })

  t.is(resolveCreditsRoute('POST', '/api/v1/credits/pricing'), null)
  t.is(resolveCreditsRoute('GET', '/api/v1/credits/unknown'), null)
})

test('api credits: pricing and comparison use configured pricing state', (t) => {
  const node = { pricingEngine: new PricingEngine({ margin: 1.5 }) }
  const pricing = buildCreditsPricingRoutePayload({
    route: resolveCreditsRoute('GET', '/api/v1/credits/pricing'),
    node
  })
  const comparison = buildCreditsCompareRoutePayload({
    route: resolveCreditsRoute('GET', '/api/v1/credits/pricing/compare'),
    node
  })

  t.is(pricing.status, 200)
  t.is(pricing.payload['ai.infer'].effectiveMargin, 1.5)
  t.is(comparison.status, 200)
  t.ok(comparison.payload.services['ai.infer'])
})

test('api credits: finance reads fail closed without lifecycle-owned state', (t) => {
  const node = {}
  const stats = buildCreditsStatsRoutePayload({
    route: resolveCreditsRoute('GET', '/api/v1/credits/stats'),
    node
  })
  const wallets = buildCreditsWalletsRoutePayload({
    route: resolveCreditsRoute('GET', '/api/v1/credits/wallets'),
    node
  })

  t.is(stats.status, 503)
  t.is(stats.payload.errorCode, 'credits-unavailable')
  t.is(wallets.status, 503)
  t.is(wallets.payload.errorCode, 'credits-unavailable')
  t.absent(Object.hasOwn(node, '_defaultCreditManager'), 'GET does not create fallback financial state')
  t.absent(Object.hasOwn(node, 'creditManager'), 'GET leaves node state untouched')
})

test('api credits: stats are shaped and wallet output is sorted, sanitized, and bounded', (t) => {
  const values = []
  for (let i = 0; i < MAX_CREDITS_WALLETS + 5; i++) {
    values.push({
      appPubkey: i.toString(16).padStart(64, '0'),
      balance: i,
      totalDeposited: i * 2,
      totalSpent: i / 2,
      totalBonusReceived: 1,
      welcomeCreditsReceived: 2,
      tier: i === MAX_CREDITS_WALLETS + 4 ? 'unlimited' : 'invalid',
      lastActivity: i + 1,
      createdAt: i + 1
    })
  }
  const manager = {
    wallets: new Map(values.map(wallet => [wallet.appPubkey, wallet])),
    stats () {
      return {
        totalWallets: '105.9',
        totalBalance: -1,
        totalDeposited: 12,
        totalSpent: Number.NaN,
        totalWelcomeCredits: 9,
        frozenWallets: 2.8,
        avgBalance: 4
      }
    }
  }

  const stats = buildCreditsStatsRoutePayload({
    route: resolveCreditsRoute('GET', '/api/v1/credits/stats'),
    node: { creditManager: manager }
  })
  t.alike(stats.payload.credits, {
    totalWallets: 105,
    totalBalance: 0,
    totalDeposited: 12,
    totalSpent: 0,
    totalWelcomeCredits: 9,
    frozenWallets: 2,
    avgBalance: 4
  })

  const wallets = buildCreditsWalletsRoutePayload({
    route: resolveCreditsRoute('GET', '/api/v1/credits/wallets'),
    node: { creditManager: manager }
  })
  t.is(wallets.status, 200)
  t.is(wallets.payload.total, MAX_CREDITS_WALLETS + 5)
  t.is(wallets.payload.wallets.length, MAX_CREDITS_WALLETS)
  t.is(wallets.payload.truncated, true)
  t.is(wallets.payload.wallets[0].appPubkey, (MAX_CREDITS_WALLETS + 4).toString(16).padStart(64, '0'))
  t.is(wallets.payload.wallets[0].tier, 'unlimited')
  t.is(wallets.payload.wallets[1].tier, 'free')
})

test('api credits: configured key gates both finance endpoints before state reads', async (t) => {
  const manager = seededManager()
  let managerReads = 0
  const node = mockNode()
  Object.defineProperty(node, 'creditManager', {
    configurable: true,
    get () {
      managerReads++
      return manager
    }
  })
  const { api, port } = await startServer(t, node, { apiKey: API_KEY })
  const baselineReads = managerReads

  for (const path of PRIVATE_PATHS) {
    const missing = await request(port, path)
    t.is(missing.statusCode, 401, path + ' rejects missing credentials')
    t.is(missing.body.errorCode, 'auth-required')

    const legacyHeader = await request(port, path, { 'x-api-key': API_KEY })
    t.is(legacyHeader.statusCode, 401, path + ' ignores unsupported x-api-key')

    const wrong = await request(port, path, { Authorization: 'Bearer wrong' })
    t.is(wrong.statusCode, 401, path + ' rejects wrong bearer token')
  }
  t.is(managerReads, baselineReads, 'unauthorized requests never read credit state')

  const stats = await request(port, PRIVATE_PATHS[0], { Authorization: 'Bearer ' + API_KEY })
  t.is(stats.statusCode, 200)
  t.is(stats.body.credits.totalWallets, 1)
  t.is(stats.body.credits.totalDeposited, 1000)

  const wallets = await request(port, PRIVATE_PATHS[1], { Authorization: 'Bearer ' + API_KEY })
  t.is(wallets.statusCode, 200)
  t.is(wallets.body.wallets.length, 1)
  t.is(wallets.body.wallets[0].appPubkey, APP_KEY)
  t.ok(managerReads > baselineReads, 'authorized requests reach lifecycle-owned state')

  const pricing = await request(port, '/api/v1/credits/pricing')
  t.is(pricing.statusCode, 200, 'configured API key does not make advertised pricing private')
  t.ok(pricing.body['ai.infer'])
  t.ok(api._authFailures.has('/api/v1/credits/stats'))
  t.ok(api._authFailures.has('/api/v1/credits/wallets'))
})

test('api credits: unconfigured key permits safe localhost and rejects proxy fallback', async (t) => {
  const local = await startServer(t, mockNode({ creditManager: seededManager() }))
  for (const path of PRIVATE_PATHS) {
    const response = await request(local.port, path)
    t.is(response.statusCode, 200, path + ' permits direct loopback operator access')
  }

  const proxied = await startServer(t, mockNode({ creditManager: seededManager() }), {
    trustProxy: true
  })
  for (const path of PRIVATE_PATHS) {
    const response = await request(proxied.port, path)
    t.is(response.statusCode, 401, path + ' fails closed behind a proxy without a key')
    t.is(response.body.errorCode, 'auth-required')
  }
})

function seededManager () {
  const manager = new CreditManager({ welcomeCredits: 0 })
  manager.getOrCreateWallet(APP_KEY)
  manager.topUp(APP_KEY, 1000)
  return manager
}

function mockNode (extra = {}) {
  const node = {
    running: true,
    config: { storage: null, plugins: [] },
    metrics: {
      getSummary () { return { uptime: 1 } },
      toPrometheus () { return '# credits test\n' }
    },
    seededApps: new Map(),
    appRegistry: {
      apps: new Map(),
      catalog () { return [] },
      catalogForBroadcast () { return [] }
    },
    getStats () { return { running: true } },
    getHealthStatus () { return { healthy: true } },
    async stop () {},
    async start () {},
    on () {},
    removeListener () {},
    emit () {}
  }
  return Object.assign(node, extra)
}

async function startServer (t, node, opts = {}) {
  const api = new RelayAPI(node, {
    apiPort: 0,
    apiHost: '127.0.0.1',
    ...opts
  })
  await api.start()
  t.teardown(() => api.stop())
  return { api, port: api.server.address().port }
}

function request (port, path, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      method: 'GET',
      path,
      headers
    }, (res) => {
      let data = ''
      res.on('data', chunk => { data += chunk })
      res.on('end', () => {
        let body
        try { body = JSON.parse(data) } catch { body = data }
        resolve({ statusCode: res.statusCode, body })
      })
    })
    req.on('error', reject)
    req.end()
  })
}
