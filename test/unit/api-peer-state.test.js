import test from 'brittle'
import {
  MAX_PEER_LIST_ENTRIES,
  buildPeerListPayload
} from '../../packages/core/core/relay-node/api-peer-state.js'

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
    now: 1000
  })

  t.alike(payload, {
    count: 1,
    total: 1,
    truncated: false,
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
    now: 1000
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
  t.alike(buildPeerListPayload(), { count: 0, total: 0, truncated: false, peers: [] })
  t.alike(buildPeerListPayload({ swarm: { connections: null } }), { count: 0, total: 0, truncated: false, peers: [] })
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
    now: 1000
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
