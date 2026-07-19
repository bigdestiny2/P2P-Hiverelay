import test from 'brittle'
import {
  aggregateFleet,
  buildFleetPayload,
  buildFleetRoutePayload,
  isAllowedFleetBaseUrl,
  normalizeFleetBaseUrl,
  normalizeFleetPeers,
  resolveFleetConfig,
  resolveFleetRoute,
  sanitizeFleetPeerCard,
  sanitizeFleetPrivacy
} from 'p2p-hiverelay/core/relay-node/api-fleet.js'

test('api fleet: route helper maps management fleet route', (t) => {
  t.alike(resolveFleetRoute('GET', '/api/fleet'), {
    kind: 'fleet',
    authMessage: 'Unauthorized — API key required for /api/fleet'
  })
  t.is(resolveFleetRoute('POST', '/api/fleet'), null)
  t.is(resolveFleetRoute('GET', '/api/fleet/extra'), null)
})

test('api fleet: base URL allow-list rejects secrets and non-http schemes', (t) => {
  t.ok(isAllowedFleetBaseUrl('http://127.0.0.1:9100'))
  t.ok(isAllowedFleetBaseUrl('https://relay.example.com'))
  t.absent(isAllowedFleetBaseUrl('file:///etc/passwd'))
  t.absent(isAllowedFleetBaseUrl('http://user:pass@host:9100'))
  t.absent(isAllowedFleetBaseUrl('not a url'))
  t.is(normalizeFleetBaseUrl('https://a.example/path/'), 'https://a.example/path')
})

test('api fleet: peer config is bounded and deduped', (t) => {
  const peers = normalizeFleetPeers([
    { id: 'bern', baseUrl: 'http://45.59.123.112:9100', region: 'EU', pubkey: 'bc421fedea8a' },
    { id: 'dup', baseUrl: 'http://45.59.123.112:9100/' },
    { id: 'bad', baseUrl: 'ftp://nope' },
    'https://milkyb.example',
    { id: 'x', baseUrl: 'javascript:alert(1)' }
  ], { maxPeers: 10 })

  t.is(peers.length, 2)
  t.is(peers[0].id, 'bern')
  t.is(peers[0].region, 'EU')
  t.is(peers[0].declaredPubkey, 'bc421fedea8a')
  t.is(peers[1].baseUrl, 'https://milkyb.example')
})

test('api fleet: status cards allow-list fields and never keep onion material', (t) => {
  const card = sanitizeFleetPeerCard({
    id: 'peer-a',
    label: 'Utah',
    region: 'NA',
    baseUrl: 'http://144.172.101.215:9100',
    health: { ok: true, running: true, uptime: { ms: 60000 } },
    status: {
      running: true,
      publicKey: 'a'.repeat(64),
      connections: 4,
      seededApps: 2,
      health: { healthy: true },
      disk: { usedPct: 22, status: 'ok', freeGB: 40 },
      storage: { totalBytes: 1024, max: 4096 },
      transports: {
        tor: {
          running: true,
          health: 'ready',
          onionAddress: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion'
        }
      },
      holesailKey: 'should-not-leak',
      tor: { onionAddress: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion' }
    },
    fetchedAt: 1000
  })

  t.is(card.up, true)
  t.is(card.publicKey, 'aaaaaaaaaaaa')
  t.is(card.connections, 4)
  t.is(card.disk.usedPct, 22)
  t.is(card.storage.used, 1024)
  t.ok(card.privacyTransports)
  t.is(card.privacyTransports[0].health, 'ready')
  t.absent(JSON.stringify(card).includes('.onion'))
  t.absent(JSON.stringify(card).includes('should-not-leak'))
  t.absent(JSON.stringify(card).includes('holesail'))
})

test('api fleet: privacy sanitizer is coarse-only', (t) => {
  t.alike(sanitizeFleetPrivacy({
    tor: { running: false, health: 'down', onionAddress: 'x.onion' }
  }), [{ id: 'tor-v3-onion-v1', running: false, health: 'down' }])
  t.absent(JSON.stringify(sanitizeFleetPrivacy({
    tor: { running: true, health: 'degraded', onionAddress: 'y.onion' }
  })).includes('.onion'))
})

test('api fleet: aggregate counts up/down and disk alerts', (t) => {
  const summary = aggregateFleet([
    { up: true, region: 'EU', healthy: true, disk: { usedPct: 20 } },
    { up: false, region: 'NA', healthy: false, disk: { usedPct: 92, status: 'critical' } },
    {
      up: true,
      region: 'EU',
      privacyTransports: [{ health: 'degraded' }],
      disk: { usedPct: 80, status: 'warn' }
    }
  ], { now: 5000 })

  t.is(summary.peerCount, 3)
  t.is(summary.up, 2)
  t.is(summary.down, 1)
  t.is(summary.regions, 2)
  t.is(summary.diskCritical, 1)
  t.is(summary.diskWarn, 1)
  t.is(summary.unhealthy, 1)
  t.is(summary.privacyDegraded, 1)
  t.is(summary.updatedAt, 5000)
})

test('api fleet: buildFleetPayload polls peers via injected fetch and includes self', async (t) => {
  const calls = []
  const fetchJson = async (url) => {
    calls.push(url)
    if (url.endsWith('/health')) return { ok: true, running: true, uptime: { ms: 1000 } }
    if (url.endsWith('/status')) {
      return {
        running: true,
        publicKey: 'b'.repeat(64),
        connections: 1,
        seededApps: 0,
        health: { healthy: true },
        transports: { tor: { running: true, health: 'ready', onionAddress: 'secret.onion' } }
      }
    }
    throw new Error('unexpected ' + url)
  }

  const payload = await buildFleetPayload({
    config: {
      fleet: {
        includeSelf: true,
        peers: [{ id: 'bern', baseUrl: 'http://45.59.123.112:9100', region: 'EU' }]
      }
    },
    selfStatus: {
      running: true,
      publicKey: 'c'.repeat(64),
      connections: 9,
      health: { healthy: true }
    },
    selfHealth: { ok: true, running: true },
    selfPublicKey: 'c'.repeat(64),
    selfRegion: 'NA',
    fetchJson,
    now: 9000
  })

  t.is(payload.peers.length, 2)
  t.is(payload.peers[0].self, true)
  t.is(payload.peers[0].id, 'self')
  t.is(payload.peers[1].id, 'bern')
  t.is(payload.peers[1].up, true)
  t.is(payload.summary.up, 2)
  t.is(payload.config.peerTargets, 1)
  t.ok(calls.some((u) => u.includes('/health')))
  t.ok(calls.some((u) => u.includes('/status')))
  t.absent(JSON.stringify(payload).includes('.onion'))
})

test('api fleet: unreachable peers mark down without throwing', async (t) => {
  const payload = await buildFleetPayload({
    config: {
      fleet: {
        includeSelf: false,
        peers: [{ id: 'gone', baseUrl: 'http://203.0.113.9:9100' }]
      }
    },
    fetchJson: async () => { throw new Error('timeout') },
    now: 1
  })
  t.is(payload.peers.length, 1)
  t.is(payload.peers[0].up, false)
  t.ok(payload.peers[0].errors.length >= 1)
  t.is(payload.summary.down, 1)
})

test('api fleet: route payload unknown route 404', async (t) => {
  const bad = await buildFleetRoutePayload({ route: null })
  t.is(bad.ok, false)
  t.is(bad.status, 404)
})

test('api fleet: route payload assembles from node + fetch', async (t) => {
  const node = {
    config: {
      regions: ['EU'],
      fleet: {
        includeSelf: true,
        peers: [{ id: 'peer', baseUrl: 'http://198.51.100.10:9100' }]
      }
    },
    metrics: { startedAt: 1000 },
    getStats () {
      return {
        running: true,
        publicKey: 'd'.repeat(64),
        connections: 3,
        seededApps: 1,
        storage: { totalBytes: 50 }
      }
    },
    getHealthStatus () {
      return { healthy: true }
    }
  }

  const result = await buildFleetRoutePayload({
    route: { kind: 'fleet' },
    node,
    fetchJson: async (url) => {
      if (url.endsWith('/health')) return { ok: false }
      if (url.endsWith('/status')) throw new Error('down')
      throw new Error('nope')
    },
    now: 5000
  })

  t.is(result.ok, true)
  t.is(result.status, 200)
  t.ok(result.payload.summary.peerCount >= 2)
  t.ok(result.payload.peers.some((p) => p.self === true))
  t.absent(JSON.stringify(result.payload).includes('.onion'))
})

test('api fleet: resolveFleetConfig defaults', (t) => {
  const cfg = resolveFleetConfig({})
  t.is(cfg.includeSelf, true)
  t.is(cfg.peers.length, 0)
  t.ok(cfg.timeoutMs > 0)
})
