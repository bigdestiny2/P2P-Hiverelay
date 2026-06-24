import test from 'brittle'
import {
  buildGatewayStatsPayload,
  sanitizeGatewayStats
} from 'p2p-hiverelay/core/relay-node/api-gateway-stats.js'

test('api gateway stats: missing gateway returns stable zero counters', (t) => {
  t.alike(buildGatewayStatsPayload(), {
    ok: true,
    payload: {
      cachedDrives: 0,
      totalRequests: 0,
      totalBytesServed: 0
    }
  })
})

test('api gateway stats: sanitizes public counters without raw fields', (t) => {
  const payload = sanitizeGatewayStats({
    cachedDrives: 3.7,
    totalRequests: '9',
    totalBytesServed: 1024.9,
    openDriveKeys: ['a'.repeat(64)],
    storePath: '/private/data',
    secretToken: 'do-not-leak'
  })

  t.alike(payload, {
    cachedDrives: 3,
    totalRequests: 9,
    totalBytesServed: 1024
  })
  t.absent(JSON.stringify(payload).includes('openDriveKeys'))
  t.absent(JSON.stringify(payload).includes('storePath'))
  t.absent(JSON.stringify(payload).includes('secretToken'))
  t.absent(JSON.stringify(payload).includes('do-not-leak'))
})

test('api gateway stats: malformed counters clamp to zero', (t) => {
  t.alike(sanitizeGatewayStats({
    cachedDrives: -1,
    totalRequests: Infinity,
    totalBytesServed: Number.NaN
  }), {
    cachedDrives: 0,
    totalRequests: 0,
    totalBytesServed: 0
  })
})
