/**
 * Tests that the WebSocket dashboard feed surfaces AutoHeal + custody state
 * in its broadcast payload. Tests the payload builder directly with a mock
 * node — avoids spinning up a real HTTP server / WebSocket clients.
 */

import test from 'brittle'
import { EventEmitter, once } from 'node:events'
import { createServer } from 'node:http'
import { WebSocket } from 'ws'
import { DashboardFeed } from 'p2p-hiverelay/core/relay-node/ws-feed.js'

function makeMockNode (opts = {}) {
  const node = new EventEmitter()
  Object.assign(node, {
    running: true,
    config: { regions: ['NA'], maxStorageBytes: 1024 * 1024 * 1024 },
    swarm: { keyPair: { publicKey: 'mockpubkey' } },
    startedAt: Date.now() - 60_000,
    getStats: () => ({
      publicKey: 'mockpubkey',
      connections: { active: 0, total: 0 },
      seededApps: 0,
      relay: { activeCircuits: 0, totalCircuitsServed: 0, totalBytesRelayed: 0 },
      seeder: { coresSeeded: 0, totalBytesStored: 0, totalBytesServed: 0 }
    }),
    autoHeal: opts.autoHeal,
    seedingRegistry: opts.seedingRegistry,
    metrics: null,
    reputation: null,
    torTransport: null,
    holesailTransport: null,
    creditManager: null,
    serviceMeter: null,
    invoiceManager: null,
    paymentManager: null,
    networkDiscovery: opts.networkDiscovery || null
  })
  return node
}

function makeFeed (node) {
  // Construct the feed without starting (no server needed for _buildPayload)
  const feed = new DashboardFeed({ node, server: null })
  feed.clientCount = 1 // pretend a client is connected
  return feed
}

test('ws-feed: payload omits autoHeal block when node has no autoHeal', async (t) => {
  const node = makeMockNode({ autoHeal: null })
  const payload = makeFeed(node)._buildPayload()
  t.absent(payload.autoHeal, 'no autoHeal in payload')
})

test('ws-feed: payload includes autoHeal snapshot when present', async (t) => {
  const autoHealSnap = {
    enabled: true,
    running: true,
    tickMs: 60_000,
    thresholds: { minReplicas: 7, minRegions: 4, minOperators: 5, secret: 'should-not-leak' },
    tracked: 3,
    below: 1,
    backoffs: 0,
    verifyProofs: true,
    proofCacheSize: 12,
    secret: 'should-not-leak',
    drives: [
      {
        appKey: 'not-hex',
        replicas: 1,
        secret: 'should-not-leak'
      },
      {
        appKey: 'a'.repeat(64),
        replicas: 7,
        regions: ['NA', 'EU', 'AS', 'OC', 'bad\nregion'],
        operators: ['alice', 'bob', 'carol', 'dave', 'erin', 'bad\noperator'],
        meetsThreshold: true,
        haveLocally: true,
        backoff: { failures: 1, retryInMs: 1000, reason: 'should-not-leak' },
        raw: [{ secret: 'should-not-leak' }]
      }
    ]
  }
  const node = makeMockNode({
    autoHeal: { snapshot: () => autoHealSnap }
  })
  const payload = makeFeed(node)._buildPayload()
  t.ok(payload.autoHeal, 'autoHeal block present')
  t.is(payload.autoHeal.tracked, 3)
  t.is(payload.autoHeal.below, 1)
  t.is(payload.autoHeal.verifyProofs, true)
  t.is(payload.autoHeal.proofCacheSize, 12)
  t.is(payload.autoHeal.drives.length, 1)
  t.alike(payload.autoHeal.drives[0], {
    appKey: 'a'.repeat(64),
    replicas: 7,
    regions: ['NA', 'EU', 'AS', 'OC'],
    operators: ['alice', 'bob', 'carol', 'dave', 'erin'],
    meetsThreshold: true,
    haveLocally: true,
    backoff: { failures: 1, retryInMs: 1000 }
  })
  t.absent(JSON.stringify(payload.autoHeal).includes('should-not-leak'), 'raw AutoHeal fields are removed from live feed')
})

test('ws-feed: payload sanitizes and caps autoHeal.drives at 50 to bound payload size', async (t) => {
  const drives = [{ appKey: 'not-hex', replicas: 0 }]
  for (let i = 0; i < 200; i++) {
    drives.push({
      appKey: (i % 2 === 0 ? 'a' : 'b').repeat(64),
      replicas: i,
      regions: ['NA'],
      operators: ['operator-a'],
      meetsThreshold: false,
      haveLocally: false,
      backoff: null,
      secret: 'should-not-leak'
    })
  }
  const node = makeMockNode({
    autoHeal: {
      snapshot: () => ({
        enabled: true, running: true, tickMs: 60_000, thresholds: {}, tracked: 200, below: 200, backoffs: 0, verifyProofs: true, proofCacheSize: 0, drives
      })
    }
  })
  const payload = makeFeed(node)._buildPayload()
  t.is(payload.autoHeal.drives.length, 50, 'drives capped at 50')
  t.is(payload.autoHeal.drives[0].appKey, 'a'.repeat(64), 'invalid rows do not consume the cap')
  t.is(payload.autoHeal.tracked, 200, 'tracked count preserved (full count surfaced)')
  t.absent(JSON.stringify(payload.autoHeal).includes('should-not-leak'), 'raw drive fields are removed')
})

test('ws-feed: payload includes custody snapshot when registry has one', async (t) => {
  const node = makeMockNode({
    seedingRegistry: {
      custodySnapshot: () => ({
        intents: 5,
        withQuorum: 3,
        committed: 2,
        retired: 1,
        withProof: 2,
        withNonServingProof: 0,
        withWitnessTombstone: 1,
        totalReceipts: 9,
        totalProofs: 4,
        totalNonServingProofs: 0,
        totalWitnessTombstones: 2,
        commitRate: 0.4,
        proofs: [{ secret: 'should-not-leak' }],
        intentsById: { hidden: 'should-not-leak' }
      })
    }
  })
  const payload = makeFeed(node)._buildPayload()
  t.ok(payload.custody, 'custody block present')
  t.alike(payload.custody, {
    intents: 5,
    withQuorum: 3,
    committed: 2,
    retired: 1,
    withProof: 2,
    withNonServingProof: 0,
    withWitnessTombstone: 1,
    totalReceipts: 9,
    totalProofs: 4,
    totalNonServingProofs: 0,
    totalWitnessTombstones: 2,
    commitRate: 0.4
  })
  t.absent(JSON.stringify(payload.custody).includes('should-not-leak'), 'raw custody fields are removed from live feed')
})

test('ws-feed: payload normalizes malformed custody snapshot counters', async (t) => {
  const node = makeMockNode({
    seedingRegistry: {
      custodySnapshot: () => ({
        intents: '5',
        withQuorum: -1,
        committed: Infinity,
        retired: 1.8,
        withProof: 2,
        withNonServingProof: null,
        withWitnessTombstone: undefined,
        totalReceipts: Number.MAX_SAFE_INTEGER + 1000,
        totalProofs: NaN,
        totalNonServingProofs: 3.9,
        totalWitnessTombstones: -4,
        commitRate: 1.5,
        receipts: [{ secret: 'should-not-leak' }]
      })
    }
  })
  const payload = makeFeed(node)._buildPayload()

  t.alike(payload.custody, {
    intents: 0,
    withQuorum: 0,
    committed: 0,
    retired: 1,
    withProof: 2,
    withNonServingProof: 0,
    withWitnessTombstone: 0,
    totalReceipts: Number.MAX_SAFE_INTEGER,
    totalProofs: 0,
    totalNonServingProofs: 3,
    totalWitnessTombstones: 0,
    commitRate: null
  })
  t.absent(JSON.stringify(payload.custody).includes('should-not-leak'), 'malformed custody snapshot raw fields are removed')
})

test('ws-feed: payload omits custody when no registry', async (t) => {
  const node = makeMockNode({ seedingRegistry: null })
  const payload = makeFeed(node)._buildPayload()
  t.absent(payload.custody, 'no custody in payload')
})

test('ws-feed: overview requests redacted stats and removes transport secrets', async (t) => {
  const calls = []
  const node = makeMockNode()
  node.getStats = (opts) => {
    calls.push(opts)
    return {
      publicKey: 'mockpubkey',
      connections: 2,
      seededApps: 1,
      relay: { activeCircuits: 0, totalCircuitsServed: 0, totalBytesRelayed: 0 },
      seeder: { coresSeeded: 1, totalBytesStored: 100, totalBytesServed: 200 },
      tor: {
        running: true,
        onionAddress: 'feed-secret.onion',
        socksProxy: '127.0.0.1:9905',
        activeConnections: 2
      },
      holesail: {
        running: true,
        connected: true,
        connectionKey: 'HOLESAIL_WS_SECRET',
        apiPort: 19100
      }
    }
  }

  const payload = makeFeed(node)._buildPayload()

  t.alike(calls, [{ includeSecrets: false }], 'feed asks RelayNode for redacted stats')
  t.alike(payload.overview.tor, { running: true, activeConnections: 2 })
  t.alike(payload.overview.holesail, { running: true, connected: true })
  const overview = JSON.stringify(payload.overview)
  t.absent(overview.includes('feed-secret.onion'), 'tor onion address omitted')
  t.absent(overview.includes('127.0.0.1:9905'), 'tor local proxy omitted')
  t.absent(overview.includes('HOLESAIL_WS_SECRET'), 'holesail connection key omitted')
  t.absent(overview.includes('19100'), 'holesail API port omitted')
})

test('ws-feed: overview shapes relay and seeder counters', async (t) => {
  const node = makeMockNode()
  node.getStats = () => ({
    publicKey: 'mockpubkey',
    connections: 0,
    seededApps: 0,
    relay: {
      activeCircuits: 2.9,
      totalCircuitsServed: -1,
      totalBytesRelayed: 4096,
      capacityUsedPct: 101,
      peersWithCircuits: 3,
      circuits: [{ secret: 'should-not-leak' }]
    },
    seeder: {
      coresSeeded: 4,
      totalBytesStored: Infinity,
      totalBytesServed: 700.9,
      capacityUsedPct: '<script>',
      cores: [{ secret: 'should-not-leak' }]
    },
    served: {
      totalBytesServed: 900.8,
      totalBlocksServed: 2,
      secret: 'should-not-leak'
    }
  })

  const payload = makeFeed(node)._buildPayload()

  t.alike(payload.overview.relay, {
    activeCircuits: 2,
    totalCircuitsServed: 0,
    totalBytesRelayed: 4096,
    capacityUsedPct: 100,
    peersWithCircuits: 3
  })
  t.alike(payload.overview.seeder, {
    coresSeeded: 4,
    totalBytesStored: 0,
    totalBytesServed: 700,
    capacityUsedPct: 0,
    totalBytesServedMeasured: 900
  })
  t.absent(JSON.stringify(payload.overview).includes('should-not-leak'), 'raw relay/seeder fields are removed')
})

test('ws-feed: overview shapes payment and service accounting telemetry', async (t) => {
  const accountEntries = []
  for (let i = 0; i < 30; i++) accountEntries.push(['relay-' + i, {}])
  const node = makeMockNode()
  node.getStats = () => ({
    publicKey: 'mockpubkey',
    connections: 0,
    seededApps: 0,
    relay: { activeCircuits: 0, totalCircuitsServed: 0, totalBytesRelayed: 0 },
    seeder: { coresSeeded: 0, totalBytesStored: 0, totalBytesServed: 0 },
    payment: { enabled: true, active: true, experimental: true, settlementIntervalMs: 86400000, secret: 'should-not-leak' }
  })
  node.creditManager = {
    stats: () => ({
      totalWallets: 3.9,
      totalBalance: 1200,
      totalDeposited: -1,
      totalSpent: 4,
      totalWelcomeCredits: Infinity,
      welcomeCreditsPerWallet: 1000,
      frozenWallets: 1,
      avgBalance: 400,
      wallets: [{ secret: 'should-not-leak' }]
    })
  }
  node.serviceMeter = {
    stats: () => ({
      totalApps: 2.9,
      totalCalls: 42,
      totalRevenue: 900,
      windowStart: -1,
      rates: { secret: 'should-not-leak' }
    })
  }
  node.invoiceManager = {
    stats: () => ({
      total: 5,
      pending: 1,
      settled: 2,
      expired: 1.9,
      cancelled: '<script>',
      totalSettledSats: 700,
      invoices: [{ secret: 'should-not-leak' }]
    })
  }
  node.paymentManager = {
    accounts: new Map(accountEntries),
    paymentProvider: { constructor: { name: 'bad\nprovider' } },
    getAccountSummary: (pubkey) => ({
      relay: pubkey,
      monthsActive: 7.8,
      heldPercentage: 125,
      totalEarned: 1000,
      totalPaid: -25,
      currentlyHeld: Infinity,
      pendingPayout: 300,
      lastSettlement: 12345,
      secret: 'should-not-leak'
    })
  }

  const payload = makeFeed(node)._buildPayload()

  t.alike(payload.overview.credits, {
    totalWallets: 3,
    totalBalance: 1200,
    totalDeposited: 0,
    totalSpent: 4,
    totalWelcomeCredits: 0,
    welcomeCreditsPerWallet: 1000,
    frozenWallets: 1,
    avgBalance: 400
  })
  t.alike(payload.overview.metering, {
    totalApps: 2,
    totalCalls: 42,
    totalRevenue: 900,
    windowStart: null
  })
  t.alike(payload.overview.invoices, {
    total: 5,
    pending: 1,
    settled: 2,
    expired: 1,
    cancelled: 0,
    totalSettledSats: 700
  })
  t.is(payload.overview.payment.provider, 'none', 'unsafe provider label falls back')
  t.is(payload.overview.payment.accounts.length, 25, 'payment accounts are capped')
  t.alike(payload.overview.payment.accounts[0], {
    monthsActive: 7,
    heldPercentage: 100,
    totalEarned: 1000,
    totalPaid: 0,
    currentlyHeld: 0,
    pendingPayout: 300,
    lastSettlement: 12345
  })
  const overview = JSON.stringify(payload.overview)
  t.absent(overview.includes('should-not-leak'), 'raw payment/service manager fields are removed')
  t.absent(overview.includes('relay-0'), 'payment account relay ids are not emitted')
  t.absent(overview.includes('bad\\nprovider'), 'unsafe provider constructor name is not emitted')
})

test('ws-feed: overview sanitizes reputation and bandwidth telemetry', async (t) => {
  const node = makeMockNode()
  node.reputation = {
    export: () => ({ a: {}, b: {}, secret: { token: 'should-not-leak' } }),
    getLeaderboard: () => [{
      relay: 'a'.repeat(64),
      score: 9.876,
      reliability: '<script>',
      avgLatencyMs: -1,
      uptimeHours: 3.9,
      bytesServed: 2048,
      totalChallenges: 5,
      passedChallenges: 7,
      failedChallenges: 99,
      region: 'NA',
      secretToken: 'should-not-leak'
    }]
  }
  node._bandwidthReceipt = {
    _issuedReceipts: new Array(3).fill({ secret: 'should-not-leak' }),
    getTotalProvenBandwidth: () => Infinity
  }

  const payload = makeFeed(node)._buildPayload()

  t.alike(payload.overview.reputation, {
    trackedRelays: 3,
    topRelay: {
      relay: 'a'.repeat(64),
      score: 9.88,
      reliability: '100%',
      avgLatencyMs: 0,
      uptimeHours: 3,
      bytesServed: 2048,
      totalChallenges: 5,
      passedChallenges: 5,
      failedChallenges: 0,
      region: 'NA',
      lastActivity: null,
      firstSeen: null
    }
  })
  t.alike(payload.overview.bandwidth, {
    totalProvenBytes: 0,
    receiptsIssued: 3
  })
  t.absent(JSON.stringify(payload.overview).includes('should-not-leak'), 'raw reputation/bandwidth fields are removed')
})

test('ws-feed: unauthenticated feed redacts network connection metadata', async (t) => {
  const node = makeMockNode({
    networkDiscovery: {
      getNetworkState () {
        return {
          timestamp: 12345,
          summary: { totalRelays: 1, onlineRelays: 1, totalConnections: 1, totalStorage: 0, totalStorageMax: 0 },
          relays: [{
            publicKey: 'a'.repeat(64),
            host: '203.0.113.22',
            apiPort: 9100,
            region: 'NA',
            online: true,
            tor: { running: true, onionAddress: 'feed-secret.onion' },
            holesailKey: 'feed-holesail-secret',
            memory: { rss: 42 }
          }]
        }
      }
    }
  })
  const payload = makeFeed(node)._buildPayload()

  t.ok(payload.network, 'network block present')
  t.is(payload.network.relays[0].apiReachable, true, 'public reachability boolean preserved')
  t.absent(Object.prototype.hasOwnProperty.call(payload.network.relays[0], 'host'))
  t.absent(Object.prototype.hasOwnProperty.call(payload.network.relays[0], 'apiPort'))
  t.absent(Object.prototype.hasOwnProperty.call(payload.network.relays[0], 'memory'))
  t.absent(JSON.stringify(payload.network).includes('feed-holesail-secret'))
  t.absent(JSON.stringify(payload.network).includes('feed-secret.onion'))
})

test('ws-feed: authenticated feed preserves detailed network state', async (t) => {
  const node = makeMockNode({
    networkDiscovery: {
      getNetworkState () {
        return {
          timestamp: 12345,
          summary: { totalRelays: 1, onlineRelays: 1, totalConnections: 1, totalStorage: 0, totalStorageMax: 0 },
          relays: [{
            publicKey: 'b'.repeat(64),
            host: '203.0.113.23',
            apiPort: 9100,
            holesailKey: 'authed-feed-holesail',
            memory: { heapUsed: 42, rss: 84, external: 'should-not-leak' },
            tor: { running: true, onionAddress: 'authed-feed.onion', socksProxy: 'should-not-leak' },
            raw: { secret: 'should-not-leak' }
          }]
        }
      }
    }
  })
  const feed = new DashboardFeed({ node, server: null, apiKey: 'secret' })
  feed.clientCount = 1
  const payload = feed._buildPayload()

  t.is(payload.network.relays[0].host, '203.0.113.23')
  t.is(payload.network.relays[0].holesailKey, 'authed-feed-holesail')
  t.alike(payload.network.relays[0].memory, { heapUsed: 42, rss: 84 })
  t.alike(payload.network.relays[0].tor, { running: true, onionAddress: 'authed-feed.onion', activeConnections: 0 })
  t.absent(JSON.stringify(payload.network).includes('should-not-leak'), 'authenticated network frames are detailed but shaped')
})

test('ws-feed: payload swallows snapshot errors (does not crash broadcast)', async (t) => {
  const node = makeMockNode({
    autoHeal: { snapshot: () => { throw new Error('boom') } },
    seedingRegistry: { custodySnapshot: () => { throw new Error('boom') } }
  })
  const payload = makeFeed(node)._buildPayload()
  // Must still produce a valid payload — autoHeal/custody just absent
  t.ok(payload.overview, 'overview still present')
  t.absent(payload.autoHeal, 'autoHeal absent on snapshot error')
  t.absent(payload.custody, 'custody absent on snapshot error')
})

test('ws-feed: authenticated clients must send in-band auth before snapshots', async (t) => {
  const { feed, server, url } = await startFeed({ apiKey: 'secret', authTimeoutMs: 250 })
  t.teardown(async () => {
    await feed.stop()
    await closeServer(server)
  })

  const ws = new WebSocket(url)
  t.teardown(() => {
    try { ws.terminate() } catch {}
  })

  const messages = []
  ws.on('message', (data) => messages.push(data.toString()))

  await once(ws, 'open')
  await delay(30)
  t.is(feed.clientCount, 0, 'client is not counted before auth')
  t.is(messages.length, 0, 'snapshot is not sent before auth')

  ws.send(JSON.stringify({ type: 'auth', token: 'secret' }))
  await waitUntil(() => messages.length > 0)

  t.is(feed.clientCount, 1, 'client is counted after valid auth')
  const payload = JSON.parse(messages[0])
  t.is(payload.type, 'update')
  t.ok(payload.overview, 'authenticated client receives initial snapshot')
})

test('ws-feed: query-string tokens do not authenticate dashboard sockets', async (t) => {
  const { feed, server, node, url } = await startFeed({ apiKey: 'secret', authTimeoutMs: 100 })
  t.teardown(async () => {
    await feed.stop()
    await closeServer(server)
  })

  const failures = []
  node.on('dashboard-ws-auth-failed', (evt) => failures.push(evt.reason))

  const ws = new WebSocket(url + '?token=secret')
  t.teardown(() => {
    try { ws.terminate() } catch {}
  })

  const [err] = await once(ws, 'error')
  t.ok(err.message.includes('401'), 'upgrade rejects query-token auth')
  t.alike(failures, ['query-token'])
  t.is(feed.clientCount, 0)
})

test('ws-feed: restricted CORS allows same-origin dashboard sockets only', async (t) => {
  const { feed, server, url, origin } = await startFeed({
    apiKey: 'secret',
    authTimeoutMs: 100,
    corsOrigins: []
  })
  t.teardown(async () => {
    await feed.stop()
    await closeServer(server)
  })

  const crossSite = new WebSocket(url, {
    headers: { Origin: 'https://attacker.example' }
  })
  t.teardown(() => {
    try { crossSite.terminate() } catch {}
  })

  const [err] = await once(crossSite, 'error')
  t.ok(err.message.includes('403'), 'cross-origin dashboard socket is rejected')

  const sameOrigin = new WebSocket(url, {
    headers: { Origin: origin }
  })
  t.teardown(() => {
    try { sameOrigin.terminate() } catch {}
  })

  await once(sameOrigin, 'open')
  sameOrigin.send(JSON.stringify({ type: 'auth', token: 'secret' }))
  const [msg] = await once(sameOrigin, 'message')
  const payload = JSON.parse(msg)
  t.is(payload.type, 'update')
  t.ok(payload.overview, 'same-origin dashboard socket receives authenticated update')
  t.is(feed.clientCount, 1)
})

test('ws-feed: bad auth frames close without counting the client', async (t) => {
  const { feed, server, node, url } = await startFeed({ apiKey: 'secret', authTimeoutMs: 100 })
  t.teardown(async () => {
    await feed.stop()
    await closeServer(server)
  })

  const failures = []
  node.on('dashboard-ws-auth-failed', (evt) => failures.push(evt.reason))

  const ws = new WebSocket(url)
  t.teardown(() => {
    try { ws.terminate() } catch {}
  })

  await once(ws, 'open')
  ws.send(JSON.stringify({ type: 'auth', token: 'wrong' }))
  const [code, reason] = await once(ws, 'close')

  t.is(code, 1008)
  t.is(reason.toString(), 'auth-failed')
  t.alike(failures, ['invalid'])
  t.is(feed.clientCount, 0)
})

test('ws-feed: stop tolerates lightweight event stubs used by API unit tests', async (t) => {
  const server = new EventEmitter()
  const node = {
    relay: null,
    on () {},
    getStats: () => ({ running: true })
  }
  const feed = new DashboardFeed({ server, node })

  feed.start()
  await feed.stop()

  t.pass('stopped without removeListener on node stub')
})

async function startFeed (opts = {}) {
  const server = createServer((req, res) => {
    res.statusCode = 404
    res.end()
  })
  const node = makeMockNode()
  const feed = new DashboardFeed({
    server,
    node,
    apiKey: opts.apiKey,
    authTimeoutMs: opts.authTimeoutMs || 100,
    corsOrigins: Object.prototype.hasOwnProperty.call(opts, 'corsOrigins') ? opts.corsOrigins : undefined
  })
  feed.start()
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = server.address().port
  return {
    feed,
    server,
    node,
    url: `ws://127.0.0.1:${port}/ws`,
    origin: `http://127.0.0.1:${port}`
  }
}

async function closeServer (server) {
  if (!server.listening) return
  await new Promise((resolve) => server.close(resolve))
}

function delay (ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function waitUntil (fn, timeoutMs = 500) {
  const started = Date.now()
  return new Promise((resolve, reject) => {
    const tick = () => {
      if (fn()) return resolve()
      if (Date.now() - started > timeoutMs) return reject(new Error('timed out waiting for condition'))
      setTimeout(tick, 10)
    }
    tick()
  })
}
