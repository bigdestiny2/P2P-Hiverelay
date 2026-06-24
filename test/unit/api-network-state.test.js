import test from 'brittle'
import {
  buildNetworkStatePayload,
  detailedNetworkState,
  isDetailedNetworkStateQuery,
  publicNetworkRelay,
  publicNetworkState
} from '../../packages/core/core/relay-node/api-network-state.js'

function detailedState () {
  return {
    timestamp: 12345,
    summary: {
      totalRelays: 1,
      onlineRelays: 1,
      totalConnections: 4,
      totalStorage: 100,
      totalStorageMax: 200
    },
    relays: [{
      publicKey: 'a'.repeat(64),
      name: 'Relay aaaaaaaa',
      host: '203.0.113.10',
      apiPort: 9100,
      region: 'NA',
      online: true,
      lastSeen: 999,
      uptime: { ms: 1000 },
      connections: 4,
      seededApps: 2,
      storage: { used: 100, max: 200 },
      relay: { totalBytesRelayed: 50 },
      seeder: { coresSeeded: 2 },
      memory: { heapUsed: 123, rss: 456 },
      tor: { running: true, onionAddress: 'relay-secret.onion' },
      holesailKey: 'holesail-secret-key',
      holesailConnected: true,
      errors: 1
    }]
  }
}

test('api network state: detailed query parser is explicit', (t) => {
  t.ok(isDetailedNetworkStateQuery('1'))
  t.ok(isDetailedNetworkStateQuery('true'))
  t.absent(isDetailedNetworkStateQuery('TRUE'))
  t.absent(isDetailedNetworkStateQuery('0'))
  t.absent(isDetailedNetworkStateQuery(null))
})

test('api network state: unavailable discovery returns stable 503 payload', (t) => {
  t.alike(buildNetworkStatePayload(), {
    ok: false,
    status: 503,
    payload: { error: 'Network discovery not running' }
  })
  t.alike(buildNetworkStatePayload({ networkDiscovery: {} }), {
    ok: false,
    status: 503,
    payload: { error: 'Network discovery not running' }
  })
})

test('api network state: public relay redacts connection metadata', (t) => {
  const relay = publicNetworkRelay(detailedState().relays[0])

  t.alike(relay, {
    publicKey: 'a'.repeat(64),
    name: 'Relay aaaaaaaa',
    region: 'NA',
    online: true,
    lastSeen: 999,
    uptime: { ms: 1000 },
    connections: 4,
    seededApps: 2,
    storage: { used: 100, max: 200, pct: 0 },
    relay: {
      activeCircuits: 0,
      totalCircuitsServed: 0,
      totalBytesRelayed: 50,
      capacityUsedPct: 0,
      peersWithCircuits: 0
    },
    seeder: {
      coresSeeded: 2,
      totalBytesStored: 0,
      totalBytesServed: 0,
      capacityUsedPct: 0
    },
    apiReachable: true,
    torAvailable: true,
    holesailAvailable: true,
    errors: 1
  })
  t.absent(Object.prototype.hasOwnProperty.call(relay, 'host'))
  t.absent(Object.prototype.hasOwnProperty.call(relay, 'apiPort'))
  t.absent(Object.prototype.hasOwnProperty.call(relay, 'memory'))
  t.absent(Object.prototype.hasOwnProperty.call(relay, 'tor'))
  t.absent(Object.prototype.hasOwnProperty.call(relay, 'holesailKey'))
  t.absent(JSON.stringify(relay).includes('holesail-secret-key'))
  t.absent(JSON.stringify(relay).includes('relay-secret.onion'))
})

test('api network state: public state keeps summary and redacted relays', (t) => {
  const state = publicNetworkState(detailedState())

  t.is(state.timestamp, 12345)
  t.is(state.summary.onlineRelays, 1)
  t.is(state.relays.length, 1)
  t.is(state.relays[0].apiReachable, true)
  t.absent(JSON.stringify(state).includes('203.0.113.10'))
  t.absent(JSON.stringify(state).includes('holesail-secret-key'))
})

test('api network state: build payload preserves detailed state only when requested', (t) => {
  const networkDiscovery = {
    getNetworkState: detailedState
  }

  const publicPayload = buildNetworkStatePayload({ networkDiscovery })
  t.is(publicPayload.status, 200)
  t.absent(publicPayload.payload.relays[0].host)

  const detailedPayload = buildNetworkStatePayload({ networkDiscovery, detailed: true })
  t.is(detailedPayload.status, 200)
  t.is(detailedPayload.payload.relays[0].host, '203.0.113.10')
  t.is(detailedPayload.payload.relays[0].holesailKey, 'holesail-secret-key')
  t.absent(Object.prototype.hasOwnProperty.call(detailedPayload.payload.relays[0], 'unknown'))
})

test('api network state: detailed payload is bounded and drops raw relay internals', (t) => {
  const state = {
    timestamp: -1,
    summary: {
      totalRelays: 1500,
      onlineRelays: 1.9,
      totalConnections: Infinity,
      totalStorage: 100.9,
      totalStorageMax: -1,
      secret: 'should-not-leak'
    },
    relays: []
  }
  for (let i = 0; i < 1005; i++) {
    state.relays.push({
      publicKey: i === 0 ? 'C'.repeat(64) : 'b'.repeat(64),
      name: i === 0 ? ' Relay <one> ' : 'Relay',
      host: i === 0 ? '203.0.113.10' : 'bad\nhost',
      apiPort: i === 0 ? 9100 : 999999,
      region: 'NA',
      online: true,
      lastSeen: 123.9,
      uptime: { ms: 456.8, human: '7m', secret: 'should-not-leak' },
      connections: 4.9,
      seededApps: -1,
      storage: { used: Infinity, max: 200.9, pct: 2, raw: 'should-not-leak' },
      relay: { activeCircuits: 1.8, totalBytesRelayed: 50, circuits: [{ secret: 'should-not-leak' }] },
      seeder: { coresSeeded: 2.9, totalBytesServed: 3, cores: [{ secret: 'should-not-leak' }] },
      memory: { heapUsed: 123.9, rss: -1, external: 'should-not-leak' },
      tor: { running: true, onionAddress: 'relay-secret.onion', socksProxy: 'should-not-leak' },
      holesailKey: 'holesail-secret-key',
      holesailConnected: true,
      errors: '<script>',
      raw: { secret: 'should-not-leak' }
    })
  }

  const payload = detailedNetworkState(state)

  t.is(payload.timestamp, null)
  t.alike(payload.summary, {
    totalRelays: 1500,
    onlineRelays: 1,
    totalConnections: 0,
    totalStorage: 100,
    totalStorageMax: 0
  })
  t.is(payload.relays.length, 1000, 'relay rows are capped')
  t.alike(payload.relays[0], {
    publicKey: 'c'.repeat(64),
    name: 'Relay <one>',
    host: '203.0.113.10',
    apiPort: 9100,
    region: 'NA',
    online: true,
    lastSeen: 123,
    uptime: { ms: 456, human: '7m' },
    connections: 4,
    seededApps: 0,
    storage: { used: 0, max: 200, pct: 2 },
    relay: {
      activeCircuits: 1,
      totalCircuitsServed: 0,
      totalBytesRelayed: 50,
      capacityUsedPct: 0,
      peersWithCircuits: 0
    },
    seeder: {
      coresSeeded: 2,
      totalBytesStored: 0,
      totalBytesServed: 3,
      capacityUsedPct: 0
    },
    memory: { heapUsed: 123, rss: 0 },
    tor: { running: true, onionAddress: 'relay-secret.onion', activeConnections: 0 },
    holesailKey: 'holesail-secret-key',
    holesailConnected: true,
    errors: 0
  })
  t.absent(JSON.stringify(payload).includes('should-not-leak'), 'raw detailed network fields are removed')
})
