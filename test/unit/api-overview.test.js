import test from 'brittle'
import {
  bandwidthOverview,
  buildOverviewPayload,
  formatOverviewUptime,
  overviewRelay,
  overviewSeeder,
  overviewServed,
  overviewStorage,
  overviewTorInfo,
  registryOverview,
  reputationOverview
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
    health: { healthy: true },
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
