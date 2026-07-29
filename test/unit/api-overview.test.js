import test from 'brittle'
import {
  bandwidthOverview,
  buildOverviewPayload,
  buildOverviewRoutePayload,
  buildOverviewRouteResponse,
  formatOverviewUptime,
  overviewCompliance,
  overviewDisk,
  overviewGatewayDetail,
  overviewNamespaces,
  overviewPrivacyTransports,
  overviewRelay,
  overviewRoles,
  overviewSeeder,
  overviewServed,
  overviewHealth,
  overviewShardStore,
  overviewStorage,
  overviewTorInfo,
  overviewWal,
  registryOverview,
  reputationOverview,
  resolveOverviewRoute,
  sanitizeWalStats,
  walFromJournalInfo
} from 'p2p-hiverelay/core/relay-node/api-overview.js'

test('api overview: uptime formatter keeps hours and compact human text', (t) => {
  t.alike(formatOverviewUptime(90_061_000), {
    ms: 90_061_000,
    hours: 25.02,
    human: '1d 1h 1m'
  })
  t.alike(formatOverviewUptime(-1), {
    ms: 0,
    hours: 0,
    human: '0m'
  })
})

test('api overview: route helper maps exact public overview route', (t) => {
  t.alike(resolveOverviewRoute('GET', '/api/overview'), {
    kind: 'overview'
  })

  t.is(resolveOverviewRoute('POST', '/api/overview'), null)
  t.is(resolveOverviewRoute('GET', '/api/overview/extra'), null)
  t.is(resolveOverviewRoute('GET', '/api/overviews'), null)
})

test('api overview: route response helper dispatches overview reads', (t) => {
  const route = resolveOverviewRoute('GET', '/api/overview')
  const result = buildOverviewRouteResponse({
    route,
    node: {
      config: { regions: ['EU'], maxStorageBytes: 1000 },
      metrics: { startedAt: 1000, _errorCount: 1 },
      getStats (opts) {
        t.alike(opts, { includeSecrets: false })
        return {
          publicKey: 'a'.repeat(64),
          connections: 2,
          seededApps: 3,
          storage: { totalBytes: 100 }
        }
      }
    },
    authed: false,
    memory: { heapUsed: 4, rss: 5 },
    now: 7000
  })

  t.is(result.ok, true)
  t.is(result.status, undefined)
  t.is(result.payload.uptime.ms, 6000)
  t.is(result.payload.region, 'EU')
  t.alike(result.payload.memory, { heapUsed: 4, rss: 5 })

  t.alike(buildOverviewRouteResponse({ route: null }), {
    ok: false,
    status: 404,
    payload: { error: 'unknown overview route' }
  })
})

test('api overview: measured storage and served counters beat legacy seeder fallbacks', (t) => {
  const stats = {
    storage: { totalBytes: 4096 },
    served: { totalBytesServed: 900, totalBlocksServed: 4 },
    seeder: { coresSeeded: 2, totalBytesStored: 100, totalBytesServed: 50, capacityUsedPct: 12.345 }
  }
  const config = { maxStorageBytes: 8192 }

  t.alike(overviewStorage(stats, config), {
    used: 4096,
    max: 8192,
    pct: 0.5
  })
  t.alike(overviewServed(stats), {
    bytes: 900,
    blocks: 4,
    measured: true
  })
  t.alike(overviewSeeder(stats), {
    coresSeeded: 2,
    totalBytesStored: 100,
    totalBytesServed: 50,
    capacityUsedPct: 12.35,
    totalBytesServedMeasured: 900
  })
})

test('api overview: legacy storage and served fallbacks remain stable', (t) => {
  const stats = {
    storage: { totalBytes: 0 },
    seeder: { coresSeeded: 1, totalBytesStored: 300, totalBytesServed: 75 }
  }

  t.is(overviewStorage(stats, {}).used, 300)
  t.is(overviewStorage(stats, {}).max, 5368709120)
  t.alike(overviewServed(stats), {
    bytes: 75,
    blocks: null,
    measured: false
  })
  t.alike(overviewSeeder({}), {
    coresSeeded: 0,
    totalBytesStored: 0,
    totalBytesServed: 0,
    capacityUsedPct: 0,
    totalBytesServedMeasured: null
  })
})

test('api overview: optional reputation, bandwidth, and registry summaries are compact', (t) => {
  const relay = 'a'.repeat(64)
  const reputation = {
    export () {
      return { a: {}, b: {} }
    },
    getLeaderboard () {
      return [{
        relay,
        score: 10.129,
        totalChallenges: 8,
        passedChallenges: 7,
        failedChallenges: 9,
        region: 'EU',
        token: 'should-not-leak'
      }]
    }
  }
  const bandwidth = {
    _issuedReceipts: [{}, {}],
    getTotalProvenBandwidth () {
      return 1234
    }
  }

  t.alike(reputationOverview(reputation), {
    trackedRelays: 2,
    topRelay: {
      relay,
      score: 10.13,
      reliability: '88%',
      avgLatencyMs: 0,
      uptimeHours: 0,
      bytesServed: 0,
      totalChallenges: 8,
      passedChallenges: 7,
      failedChallenges: 1,
      region: 'EU',
      lastActivity: null,
      firstSeen: null
    }
  })
  t.alike(bandwidthOverview(bandwidth), {
    totalProvenBytes: 1234,
    receiptsIssued: 2
  })
  t.alike(registryOverview({ running: true }, { registryAutoAccept: false }), {
    running: true,
    autoAccept: false
  })
  t.is(reputationOverview(null), null)
  t.is(bandwidthOverview(null), null)
  t.is(registryOverview(null), null)
})

test('api overview: relay, seeder, and tor summaries are known-field only', (t) => {
  const stats = {
    relay: {
      activeCircuits: 2.9,
      totalCircuitsServed: 7,
      totalBytesRelayed: 99,
      capacityUsedPct: 150.456,
      peersWithCircuits: 3,
      circuits: [{ id: 'should-not-leak' }]
    },
    seeder: {
      coresSeeded: 4,
      totalBytesStored: 500,
      totalBytesServed: 600,
      capacityUsedPct: 8,
      cores: { secret: 'should-not-leak' }
    },
    served: { totalBytesServed: 700 }
  }

  t.alike(overviewRelay(stats), {
    activeCircuits: 2,
    totalCircuitsServed: 7,
    totalBytesRelayed: 99,
    capacityUsedPct: 150.46,
    peersWithCircuits: 3
  })
  t.alike(overviewSeeder(stats), {
    coresSeeded: 4,
    totalBytesStored: 500,
    totalBytesServed: 600,
    capacityUsedPct: 8,
    totalBytesServedMeasured: 700
  })
  t.alike(overviewTorInfo({
    running: true,
    onionAddress: 'relay.onion',
    activeConnections: 2,
    socksProxy: '127.0.0.1:9050'
  }), {
    running: true,
    onionAddress: 'relay.onion',
    activeConnections: 2
  })
  t.absent(JSON.stringify({
    relay: overviewRelay(stats),
    seeder: overviewSeeder(stats),
    tor: overviewTorInfo({ socksProxy: 'should-not-leak' })
  }).includes('should-not-leak'))
})

test('api overview: health summary is known-field only', (t) => {
  const health = overviewHealth({
    healthy: true,
    lastCheck: 1234.9,
    consecutiveFailures: 1.8,
    secret: 'should-not-leak',
    checks: {
      memory: { ok: true, heapPct: 12.5, rssMB: 99.25, raw: 'should-not-leak' },
      connections: { ok: false, critical: true, zeroFor: 2000, suggestion: 'should-not-leak' },
      disk: { ok: true, usedPct: 45.5, freeGB: 8.25, error: 'should-not-leak' },
      custom: { ok: true, token: 'should-not-leak' }
    }
  })

  t.alike(health, {
    healthy: true,
    lastCheck: 1234,
    consecutiveFailures: 1,
    checks: {
      memory: { ok: true, heapPct: 12.5, rssMB: 99.25 },
      connections: { ok: false, critical: true, zeroFor: 2000 },
      disk: { ok: true, usedPct: 45.5, freeGB: 8.25 }
    }
  })
  t.absent(JSON.stringify(health).includes('should-not-leak'))
  t.is(overviewHealth(null), null)
})

test('api overview: build payload preserves dashboard contract', (t) => {
  const payload = buildOverviewPayload({
    stats: {
      publicKey: 'pub',
      connections: 1,
      seededApps: 2,
      storage: { totalBytes: 4096 },
      served: { totalBytesServed: 900, totalBlocksServed: 4 },
      seeder: { coresSeeded: 2, totalBytesStored: 100, totalBytesServed: 50, raw: 'should-not-leak' },
      relay: { activeCircuits: 1, totalCircuitsServed: 2, totalBytesRelayed: 3, circuits: [{ id: 'should-not-leak' }] }
    },
    config: { regions: ['EU'], maxStorageBytes: 8192 },
    memory: { heapUsed: 10, rss: 20 },
    uptimeMs: 61_000,
    errors: 7,
    reputation: { trackedRelays: 1, topRelay: null },
    tor: { running: true, socksProxy: 'should-not-leak' },
    holesailKey: 'secret-key',
    health: { healthy: true, secret: 'should-not-leak' },
    bandwidth: { totalProvenBytes: 5, receiptsIssued: 1 },
    registry: { running: true, autoAccept: true },
    gateway: { requests: 3 }
  })

  t.is(payload.uptime.human, '1m')
  t.is(payload.region, 'EU')
  t.is(payload.storage.used, 4096)
  t.is(payload.served.bytes, 900)
  t.is(payload.relay.totalBytesRelayed, 3)
  t.is(payload.seeder.totalBytesServedMeasured, 900)
  t.alike(payload.memory, { heapUsed: 10, rss: 20 })
  t.alike(payload.tor, { running: true, onionAddress: null, activeConnections: 0 })
  t.is(payload.holesailKey, 'secret-key')
  t.alike(payload.health, { healthy: true })
  t.alike(payload.gateway, { requests: 3 })
  t.absent(JSON.stringify(payload).includes('should-not-leak'))
})

test('api overview: route helper assembles public and authenticated payloads', (t) => {
  const calls = []
  const outboxProvider = {
    operatorStats () {
      return {
        groups: 2,
        totalBytes: 4096,
        suppressedCount: 3,
        namespaces: [
          { name: 'peerit', blind: false, writers: 2, bytes24h: 100, capBytes24h: 1000, caps: {} }
        ]
      }
    },
    takedowns () {
      return { count: 3, takedowns: [] }
    },
    journalInfo () {
      return { mode: 'hypercore-outboxes', length: 42, buffered: 0, errors: 0 }
    }
  }
  const shardProvider = {
    _metrics: { put: 10, get: 20, proof: 5, rejected: 1, evicted: 0, sweep: 0 },
    _cachedBytes: 8192
  }
  const node = {
    config: {
      regions: ['NA'],
      maxStorageBytes: 1000,
      registryAutoAccept: false,
      enableSeeding: true,
      enableRelay: true,
      outboxlog: { adminKey: 'a'.repeat(32) }
    },
    metrics: { startedAt: 1000, _errorCount: 2 },
    getStats (opts) {
      calls.push(opts)
      return {
        publicKey: 'a'.repeat(64),
        connections: 3,
        seededApps: 4,
        storage: { totalBytes: 100 },
        seeder: { totalBytesStored: 50 },
        relay: { totalBytesRelayed: 9 }
      }
    },
    getHealthStatus () {
      return {
        healthy: true,
        lastCheck: 6000,
        secret: 'should-not-leak',
        checks: {
          memory: { ok: true, heapPct: 12.5, raw: 'should-not-leak' },
          connections: { ok: false, zeroFor: 2000, suggestion: 'should-not-leak' },
          disk: { ok: true, freeGB: 8.25, usedPct: 22, error: 'should-not-leak' },
          custom: { ok: true, token: 'should-not-leak' }
        }
      }
    },
    _bandwidthReceipt: {
      _issuedReceipts: [{}, {}],
      getTotalProvenBandwidth () {
        return 123
      }
    },
    seedingRegistry: { running: true },
    serviceRegistry: {
      services: new Map([
        ['outboxlog', { provider: outboxProvider }],
        ['shard-store', { provider: shardProvider }]
      ])
    },
    _shardStoreProvider () { return shardProvider },
    torTransport: {
      getInfo () {
        return {
          running: true,
          health: 'ready',
          onionAddress: 'relay.onion',
          socksProxy: 'should-not-leak',
          activeConnections: 2,
          negativeProbe: true
        }
      }
    },
    holesailTransport: { connectionKey: 'hole-key' }
  }
  const gateway = {
    port: 9200,
    host: '0.0.0.0',
    getStats () {
      return {
        cachedDrives: 2.9,
        totalRequests: 7,
        totalBytesServed: 11,
        verifyFails: 0,
        rawKeys: ['should-not-leak']
      }
    }
  }

  const pub = buildOverviewRoutePayload({ node, authed: false, gateway, memory: { heapUsed: 1, rss: 2 }, now: 7000 })
  t.alike(calls[0], { includeSecrets: false })
  t.is(pub.uptime.ms, 6000)
  t.alike(pub.memory, { heapUsed: 1, rss: 2 })
  t.alike(pub.bandwidth, { totalProvenBytes: 123, receiptsIssued: 2 })
  t.alike(pub.registry, { running: true, autoAccept: false })
  t.alike(pub.gateway, { cachedDrives: 2, totalRequests: 7, totalBytesServed: 11 })
  t.alike(pub.health, {
    healthy: true,
    lastCheck: 6000,
    checks: {
      memory: { ok: true, heapPct: 12.5 },
      connections: { ok: false, zeroFor: 2000 },
      disk: { ok: true, usedPct: 22, freeGB: 8.25 }
    }
  })
  t.is(pub.tor, null, 'public overview omits transport details')
  t.is(pub.holesailKey, null, 'public overview omits holesail key')
  t.ok(pub.roles)
  t.is(pub.roles.t1, true)
  t.is(pub.roles.t2, true)
  t.is(pub.roles.outboxlog, true)
  t.ok(pub.disk)
  t.is(pub.disk.usedPct, 22)
  t.ok(Array.isArray(pub.privacyTransports))
  t.is(pub.privacyTransports[0].id, 'tor-v3-onion-v1')
  t.is(pub.privacyTransports[0].health, 'ready')
  t.is(pub.privacyTransports[0].negativeProbe, true)
  t.absent(JSON.stringify(pub.privacyTransports).includes('relay.onion'))
  t.is(pub.namespaces, null, 'namespaces are management-only')
  t.is(pub.compliance, null, 'compliance is management-only')
  t.is(pub.shardStore, null, 'shardStore is management-only')
  t.is(pub.wal, null, 'wal is management-only')
  t.ok(pub.gatewayDetail)
  t.is(pub.gatewayDetail.enabled, true)
  t.is(pub.gatewayDetail.port, 9200)
  t.is(pub.gatewayDetail.roleConflict, true, 't2 + gateway → roleConflict')
  t.absent(JSON.stringify(pub).includes('should-not-leak'))

  const authed = buildOverviewRoutePayload({ node, authed: true, gateway: null, memory: {}, now: 7000 })
  t.alike(calls[1], { includeSecrets: true })
  t.alike(authed.tor, {
    running: true,
    onionAddress: 'relay.onion',
    activeConnections: 2,
    health: 'ready'
  })
  t.is(authed.holesailKey, 'hole-key')
  t.is(authed.gateway, null)
  t.ok(authed.namespaces)
  t.is(authed.namespaces.groups, 2)
  t.is(authed.namespaces.namespaces[0].name, 'peerit')
  t.ok(authed.compliance)
  t.is(authed.compliance.adminArmed, true)
  t.is(authed.compliance.suppressedKeys, 3)
  t.ok(authed.shardStore)
  t.is(authed.shardStore.rejected, 1)
  t.is(authed.shardStore.bytes, 8192)
  t.ok(authed.wal)
  t.is(authed.wal.source, 'outboxlog-journal')
  t.is(authed.wal.length, 42)
  t.is(authed.wal.healthy, true)
  t.absent(JSON.stringify(authed.wal).includes('coreKey'))
})

test('api overview: roles / disk / privacyTransports helpers', (t) => {
  const roles = overviewRoles(
    { enableSeeding: true, enableRelay: true, gatewayPort: 9200 },
    {
      serviceRegistry: {
        services: new Map([
          ['outboxlog', { provider: {} }],
          ['shard-store', { provider: {} }]
        ])
      }
    },
    null
  )
  t.alike(roles, {
    t1: true,
    t2: true,
    gateway: true,
    outboxlog: true,
    witness: false
  })

  t.alike(overviewDisk({
    checks: { disk: { ok: true, usedPct: 22.2, freeGB: 10, status: 'ok' } }
  }), {
    ok: true,
    usedPct: 22.2,
    freeGB: 10,
    status: 'ok'
  })

  t.is(overviewNamespaces({}, true), null)
  t.is(overviewCompliance({}, {}, false), null)
  t.is(overviewShardStore({}, true), null)

  const pt = overviewPrivacyTransports({
    torTransport: {
      getInfo () {
        return {
          running: true,
          health: 'ready',
          onionAddress: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion',
          activeConnections: 1,
          negativeProbe: false
        }
      }
    }
  })
  t.is(pt.length, 1)
  t.is(pt[0].health, 'ready')
  t.is(pt[0].negativeProbe, false)
  t.absent(JSON.stringify(pt).includes('.onion'))
})

test('api overview: v2 wal / gatewayDetail helpers', (t) => {
  t.alike(sanitizeWalStats({
    pruningSupported: true,
    framesPerSec: 42.2,
    fsyncP99Ms: 9,
    spendReplay24h: 0,
    healthy: true,
    secret: 'should-not-leak'
  }, 'blind-daemon'), {
    source: 'blind-daemon',
    pruningSupported: true,
    healthy: true,
    framesPerSec: 42.2,
    fsyncP99Ms: 9,
    spendReplay24h: 0
  })

  t.alike(walFromJournalInfo({
    mode: 'hypercore-outboxes',
    length: 10,
    buffered: 1,
    errors: 2,
    coreKey: 'should-not-leak'
  }), {
    source: 'outboxlog-journal',
    mode: 'hypercore-outboxes',
    length: 10,
    buffered: 1,
    errors: 2,
    healthy: false,
    pruningSupported: false
  })
  t.absent(JSON.stringify(walFromJournalInfo({ coreKey: 'abc', length: 1, errors: 0 })).includes('coreKey'))

  const wal = overviewWal({
    getWalStats () {
      return { framesPerSec: 5, fsyncP99Ms: 12, pruningSupported: true, healthy: true }
    }
  }, true)
  t.is(wal.source, 'node')
  t.is(wal.framesPerSec, 5)
  t.is(overviewWal({}, false), null)

  const gd = overviewGatewayDetail(
    {
      port: 9200,
      host: '127.0.0.1',
      getStats () {
        return { cachedDrives: 1, totalRequests: 2, totalBytesServed: 3, verifyFails: 4, keys: ['nope'] }
      }
    },
    {},
    { t2: true, gateway: true }
  )
  t.is(gd.enabled, true)
  t.is(gd.port, 9200)
  t.is(gd.verifyFails, 4)
  t.is(gd.roleConflict, true)
  t.absent(JSON.stringify(gd).includes('nope'))
})
