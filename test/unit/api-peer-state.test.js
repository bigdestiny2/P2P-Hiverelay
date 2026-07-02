import test from 'brittle'
import {
  MAX_PEER_LIST_ENTRIES,
  buildPeerListPayload,
  buildPeerStateRoutePayload,
  resolvePeerStateRoute
} from '../../packages/core/core/relay-node/api-peer-state.js'

test('api peer state: route helper maps exact public peer routes', (t) => {
  t.alike(resolvePeerStateRoute('GET', '/peers'), {
    kind: 'legacy-peer-list'
  })
  t.alike(resolvePeerStateRoute('GET', '/api/peers'), {
    kind: 'peer-list'
  })

  t.is(resolvePeerStateRoute('POST', '/peers'), null)
  t.is(resolvePeerStateRoute('GET', '/peers/extra'), null)
  t.is(resolvePeerStateRoute('GET', '/api/peers/extra'), null)
})

test('api peer state: route payload helper dispatches legacy and full peer lists', (t) => {
  const peerKey = Buffer.alloc(32, 0xab)
  const conn = { remotePublicKey: peerKey, type: 'tcp' }
  const connections = new Map([[conn, { lastActivity: 900 }]])
  const reputationCalls = []
  const reputation = {
    getRecord (pubkey) {
      reputationCalls.push(pubkey)
      return { score: 3 }
    }
  }

  const legacy = buildPeerStateRoutePayload({
    route: { kind: 'legacy-peer-list' },
    swarm: { connections: [conn] },
    connections,
    reputation,
    redact: false,
    now: 1000
  })
  const full = buildPeerStateRoutePayload({
    route: { kind: 'peer-list' },
    swarm: { connections: [conn] },
    connections,
    reputation,
    redact: false,
    now: 1000
  })
  const unknown = buildPeerStateRoutePayload({
    route: { kind: 'unknown' },
    swarm: { connections: [conn] }
  })

  t.is(legacy.ok, true)
  t.alike(legacy.payload.peers[0], {
    remotePublicKey: 'ab'.repeat(32),
    type: 'tcp',
    connectedFor: null
  })
  t.is(full.ok, true)
  t.is(full.payload.peers[0].connectedFor, 100)
  t.is(full.payload.peers[0].reputation.score, 3)
  t.alike(reputationCalls, ['ab'.repeat(32)])
  t.is(unknown.status, 404)
  t.is(unknown.payload.error, 'unknown peer state route')
})

test('api peer state: builds stable public peer list payload', (t) => {
  const peerKey = Buffer.alloc(32, 0xab)
  const conn = { remotePublicKey: peerKey, type: 'tcp' }
  const connections = new Map([[conn, { lastActivity: 900 }]])
  const seen = []

  const payload = buildPeerListPayload({
    swarm: { connections: [conn] },
    connections,
    reputation: {
      getRecord (pubkey) {
        seen.push(pubkey)
        return { score: 7, secretToken: 'do-not-leak' }
      }
    },
    now: 1000,
    redact: false
  })

  t.alike(payload, {
    count: 1,
    total: 1,
    truncated: false,
    redacted: false,
    peers: [{
      remotePublicKey: 'ab'.repeat(32),
      type: 'tcp',
      connectedFor: 100,
      reputation: {
        score: 7,
        totalChallenges: 0,
        passedChallenges: 0,
        failedChallenges: 0,
        avgLatencyMs: 0,
        totalBytesServed: 0,
        totalUptimeHours: 0,
        region: null,
        geoBonus: false,
        firstSeen: null,
        lastActivity: null
      }
    }]
  })
  t.alike(seen, ['ab'.repeat(32)])
  t.absent(JSON.stringify(payload).includes('secretToken'), 'raw reputation fields are omitted')
})

test('api peer state: redacts malformed peer metadata into JSON-safe fields', (t) => {
  const goodConn = { remotePublicKey: Buffer.alloc(32, 0x11), type: 'client-1' }
  const malformedKeyConn = { remotePublicKey: Buffer.alloc(31, 0x22), type: 'tcp\nbad' }
  const nonStringTypeConn = { remotePublicKey: null, type: { label: 'tcp' } }
  const futureConn = { remotePublicKey: Buffer.alloc(32, 0x33), type: 'udp' }
  const connections = new Map([
    [goodConn, { lastActivity: 100 }],
    [malformedKeyConn, { lastActivity: Number.NaN }],
    [nonStringTypeConn, { lastActivity: 50 }],
    [futureConn, { lastActivity: 1200 }]
  ])

  const payload = buildPeerListPayload({
    swarm: { connections: [goodConn, malformedKeyConn, nonStringTypeConn, futureConn] },
    connections,
    now: 1000,
    redact: false
  })

  t.is(payload.count, 4)
  t.is(payload.total, 4)
  t.is(payload.truncated, false)
  t.alike(payload.peers[0], {
    remotePublicKey: '11'.repeat(32),
    type: 'client-1',
    connectedFor: 900
  })
  t.alike(payload.peers[1], {
    remotePublicKey: null,
    type: null,
    connectedFor: null
  })
  t.alike(payload.peers[2], {
    remotePublicKey: null,
    type: null,
    connectedFor: 950
  })
  t.alike(payload.peers[3], {
    remotePublicKey: '33'.repeat(32),
    type: 'udp',
    connectedFor: 0
  })
})

test('api peer state: tolerates absent swarm and connection maps', (t) => {
  t.alike(buildPeerListPayload(), { count: 0, total: 0, truncated: false, redacted: true, peers: [] })
  t.alike(buildPeerListPayload({ swarm: { connections: null } }), { count: 0, total: 0, truncated: false, redacted: true, peers: [] })
})

test('api peer state: redacts peer pubkeys by default (metadata minimization)', (t) => {
  const peerKey = Buffer.alloc(32, 0xab)
  const conn = { remotePublicKey: peerKey, type: 'tcp' }
  const connections = new Map([[conn, { lastActivity: 900 }]])
  const seen = []

  const payload = buildPeerListPayload({
    swarm: { connections: [conn] },
    connections,
    reputation: {
      getRecord (pubkey) {
        seen.push(pubkey)
        return { score: 7 }
      }
    },
    now: 1000
  })

  t.is(payload.redacted, true, 'payload flags redaction')
  const shown = payload.peers[0].remotePublicKey
  t.ok(/^anon:[0-9a-f]{16}$/.test(shown), 'pubkey is a salted digest, not the raw key')
  t.absent(shown.includes('ab'.repeat(32)), 'raw pubkey never appears')
  t.alike(seen, ['ab'.repeat(32)], 'reputation still keyed on the REAL pubkey')
})

test('api peer state: supports Bare compatibility aliases without raw future timestamps', (t) => {
  const currentConn = { remotePublicKey: Buffer.alloc(32, 0x44), type: 'bare' }
  const futureConn = { remotePublicKey: Buffer.alloc(32, 0x55), type: 'bare' }
  const missingConn = { remotePublicKey: Buffer.alloc(32, 0x66), type: 'bare' }
  const connections = new Map([
    [currentConn, { lastActivity: 750 }],
    [futureConn, { lastActivity: 1200 }],
    [missingConn, { lastActivity: Infinity }]
  ])

  const payload = buildPeerListPayload({
    swarm: { connections: connections.keys() },
    connections,
    publicKeyAlias: true,
    includeLastActivity: true,
    now: 1000,
    redact: false
  })

  t.is(payload.count, 3)
  t.is(payload.total, 3)
  t.is(payload.truncated, false)
  t.alike(payload.peers[0], {
    remotePublicKey: '44'.repeat(32),
    type: 'bare',
    connectedFor: 250,
    publicKey: '44'.repeat(32),
    lastActivity: 750
  })
  t.is(payload.peers[1].connectedFor, 0)
  t.is(payload.peers[1].lastActivity, 1000)
  t.is(payload.peers[2].connectedFor, null)
  t.is(payload.peers[2].lastActivity, null)
})

test('api peer state: caps public peer arrays while preserving total count', (t) => {
  t.is(MAX_PEER_LIST_ENTRIES, 1000)
  const connections = []
  for (let i = 0; i < 1005; i++) {
    connections.push({ remotePublicKey: Buffer.alloc(32, i % 255), type: 'tcp' })
  }

  const payload = buildPeerListPayload({
    swarm: { connections },
    maxPeers: MAX_PEER_LIST_ENTRIES
  })

  t.is(payload.count, MAX_PEER_LIST_ENTRIES)
  t.is(payload.total, 1005)
  t.is(payload.truncated, true)
  t.is(payload.peers.length, MAX_PEER_LIST_ENTRIES)
})
