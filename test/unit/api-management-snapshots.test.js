import test from 'brittle'
import { AVAILABLE_MODES } from '../../packages/core/core/relay-node/api-mode-transport.js'
import {
  MAX_MANAGEMENT_SERVICE_ERROR_BYTES,
  MAX_MANAGEMENT_SERVICE_METHODS,
  MAX_MANAGEMENT_SERVICE_SNAPSHOT_SERVICES,
  MAX_MANAGEMENT_SERVICE_STATS_ARRAY,
  MAX_MANAGEMENT_SERVICE_STATS_KEYS,
  MAX_MANAGEMENT_SERVICE_STATS_STRING_BYTES,
  buildDeviceStatusPayload,
  buildModeCatalogPayload,
  buildPairingStatusPayload,
  buildServiceRegistrySnapshot,
  buildTransportStatusPayload
} from '../../packages/core/core/relay-node/api-management-snapshots.js'

test('api management snapshots: service registry payload tolerates missing registry', (t) => {
  t.alike(buildServiceRegistrySnapshot(null), { services: [], count: 0 })
  t.alike(buildServiceRegistrySnapshot({ services: null }), { services: [], count: 0 })
})

test('api management snapshots: service entries prefer capabilities and isolate stats failures', (t) => {
  const registry = {
    services: new Map([
      ['ai', {
        version: '1.0.0',
        description: 'models',
        status: 'running',
        capabilities: ['infer'],
        provider: {
          methods: { ignored () {} },
          stats () { throw new Error('stats failed') }
        },
        restartCount: 2,
        lastStartedAt: 'start',
        lastStoppedAt: 'stop',
        lastError: 'previous error'
      }],
      ['poker', {
        running: true,
        provider: {
          methods: {
            listTables () {},
            joinTable () {}
          },
          stats () {
            return { tables: 3 }
          }
        }
      }]
    ])
  }

  const payload = buildServiceRegistrySnapshot(registry)
  t.is(payload.count, 2)
  t.is(payload.total, 2)
  t.absent(payload.truncated)
  t.alike(payload.services[0], {
    name: 'ai',
    version: '1.0.0',
    description: 'models',
    status: 'running',
    running: true,
    methods: ['infer'],
    stats: null,
    restartCount: 2,
    lastStartedAt: 'start',
    lastStoppedAt: 'stop',
    lastError: 'previous error'
  })
  t.alike(payload.services[1], {
    name: 'poker',
    version: null,
    description: '',
    status: 'running',
    running: true,
    methods: ['listTables', 'joinTable'],
    stats: { tables: 3 },
    restartCount: 0,
    lastStartedAt: null,
    lastStoppedAt: null,
    lastError: null
  })
})

test('api management snapshots: service entries sanitize provider stats and noisy metadata', (t) => {
  const registry = {
    services: new Map([
      ['bad\nname', { version: '1.0.0' }],
      ['storage', {
        version: '1.0.0',
        description: 'x'.repeat(200),
        status: 'running',
        capabilities: [
          'put',
          'put',
          'bad\nmethod',
          ...Array.from({ length: MAX_MANAGEMENT_SERVICE_METHODS + 8 }, (_, i) => 'method-' + i)
        ],
        stats: {
          requests: 12,
          nested: {
            ok: true,
            apiKey: 'do-not-leak',
            token: 'also-hidden'
          },
          labels: [
            'ok',
            'bad\nlabel',
            ...Array.from({ length: MAX_MANAGEMENT_SERVICE_STATS_ARRAY + 4 }, (_, i) => 'item-' + i)
          ],
          text: 'z'.repeat(MAX_MANAGEMENT_SERVICE_STATS_STRING_BYTES + 64),
          nope: Infinity
        },
        restartCount: 1.9,
        lastStartedAt: 'start',
        lastStoppedAt: 'bad\nstop',
        lastError: 'e'.repeat(MAX_MANAGEMENT_SERVICE_ERROR_BYTES + 64)
      }]
    ])
  }
  for (let i = 0; i < MAX_MANAGEMENT_SERVICE_STATS_KEYS + 10; i++) {
    registry.services.get('storage').stats['metric-' + i] = i
  }
  for (let i = 0; i < MAX_MANAGEMENT_SERVICE_SNAPSHOT_SERVICES + 4; i++) {
    registry.services.set('extra-' + i, { version: '1.0.0' })
  }

  const payload = buildServiceRegistrySnapshot(registry)

  t.is(payload.count, MAX_MANAGEMENT_SERVICE_SNAPSHOT_SERVICES)
  t.is(payload.total, MAX_MANAGEMENT_SERVICE_SNAPSHOT_SERVICES + 6)
  t.ok(payload.truncated)

  const badName = payload.services[0]
  t.is(badName.name, 'unknown')

  const service = payload.services[1]
  t.is(service.methods.length, MAX_MANAGEMENT_SERVICE_METHODS)
  t.is(service.methods[0], 'put')
  t.absent(service.methods.includes('bad\nmethod'))
  t.is(service.restartCount, 1)
  t.is(service.lastStoppedAt, null)
  t.is(Buffer.byteLength(service.lastError, 'utf8'), MAX_MANAGEMENT_SERVICE_ERROR_BYTES)
  t.is(Buffer.byteLength(service.stats.text, 'utf8'), MAX_MANAGEMENT_SERVICE_STATS_STRING_BYTES)
  t.is(service.stats.requests, 12)
  t.is(service.stats.nested.ok, true)
  t.absent(Object.prototype.hasOwnProperty.call(service.stats.nested, 'apiKey'))
  t.absent(Object.prototype.hasOwnProperty.call(service.stats.nested, 'token'))
  t.absent(Object.prototype.hasOwnProperty.call(service.stats, 'nope'))
  t.is(service.stats.labels.length, MAX_MANAGEMENT_SERVICE_STATS_ARRAY)
  t.absent(JSON.stringify(payload).includes('do-not-leak'))
  t.absent(JSON.stringify(payload).includes('also-hidden'))
})

test('api management snapshots: transport payload reports optional runtime transports', (t) => {
  const payload = buildTransportStatusPayload({
    config: { transports: { websocket: true }, wsPort: 9999 },
    holesailTransport: { connectionKey: 'hole-key', running: true },
    torTransport: { onionAddress: 'relay.onion', running: false }
  })

  t.alike(payload, {
    udp: true,
    holesail: {
      enabled: true,
      connectionKey: 'hole-key',
      running: true
    },
    tor: {
      enabled: true,
      onionAddress: 'relay.onion',
      running: false
    },
    websocket: {
      enabled: true,
      port: 9999
    }
  })

  t.alike(buildTransportStatusPayload({ config: {} }).websocket, {
    enabled: false,
    port: 8765
  })
})

test('api management snapshots: device and pairing status avoid private state leakage', (t) => {
  t.alike(buildDeviceStatusPayload({ mode: 'public' }), {
    enabled: false,
    mode: 'public',
    devices: []
  })
  t.alike(buildPairingStatusPayload({ mode: 'public' }), {
    enabled: false,
    mode: 'public',
    pairing: null
  })

  const device = { pubkey: 'A'.repeat(64), name: 'phone', pairedAt: 1, lastSeen: 2, token: 'do-not-leak-device-token' }
  const node = {
    mode: 'private',
    accessControl: {
      isPairing: true,
      _pairingState: {
        token: 'do-not-leak',
        relayPubkey: 'b'.repeat(64),
        expiresAt: 12345
      }
    },
    listDevices () {
      return [
        device,
        { pubkey: 'not-a-key', name: 'ignored', secret: 'hidden' },
        { pubkey: 'b'.repeat(64), name: 'bad\nname', pairedAt: -1, lastSeen: Infinity }
      ]
    }
  }

  t.alike(buildDeviceStatusPayload(node), {
    enabled: true,
    mode: 'private',
    count: 2,
    total: 3,
    truncated: true,
    devices: [
      { pubkey: 'a'.repeat(64), name: 'phone', pairedAt: 1, lastSeen: 2 },
      { pubkey: 'b'.repeat(64), name: 'manual', pairedAt: null, lastSeen: null }
    ]
  })
  t.absent(JSON.stringify(buildDeviceStatusPayload(node)).includes('do-not-leak-device-token'))

  const pairing = buildPairingStatusPayload(node)
  t.alike(pairing, {
    enabled: true,
    mode: 'private',
    pairing: {
      active: true,
      expiresAt: 12345
    }
  })
  t.absent(Object.prototype.hasOwnProperty.call(pairing.pairing, 'token'))
  t.absent(JSON.stringify(pairing).includes('do-not-leak'))
})

test('api management snapshots: mode catalog stays aligned with switchable modes', (t) => {
  const payload = buildModeCatalogPayload('private')
  t.is(payload.current, 'private')
  t.alike(payload.available.map(mode => mode.id), AVAILABLE_MODES)
  t.ok(payload.available.every(mode => mode.name && mode.description))
})
