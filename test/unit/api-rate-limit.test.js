import test from 'brittle'
import {
  API_ENDPOINT_RATE_LIMITS,
  API_RATE_LIMIT_MAX,
  checkApiRateLimit,
  checkEndpointRateLimit,
  checkFixedWindowRateLimit,
  clientIpFromRequest,
  endpointRateLimitKey,
  firstHeaderValue,
  sweepRateLimitMap
} from 'p2p-hiverelay/core/relay-node/api-rate-limit.js'

function req (headers = {}, remoteAddress = '10.0.0.9') {
  return { headers, socket: { remoteAddress } }
}

test('api rate limit: client IP honors trusted proxy headers only when enabled', (t) => {
  t.is(clientIpFromRequest(req({ 'x-forwarded-for': '203.0.113.4, 10.0.0.2' }), true), '203.0.113.4')
  t.is(clientIpFromRequest(req({ 'x-forwarded-for': '   ', 'x-real-ip': '198.51.100.9' }), true), '198.51.100.9')
  t.is(clientIpFromRequest(req({ 'x-forwarded-for': ['203.0.113.5, 10.0.0.2'] }), true), '203.0.113.5')
  t.is(clientIpFromRequest(req({ 'x-forwarded-for': '203.0.113.4' }), false), '10.0.0.9')
  t.is(firstHeaderValue(['a', 'b']), 'a')
  t.is(firstHeaderValue(123), '')
})

test('api rate limit: fixed window rejects over cap and resets after expiry', (t) => {
  const limits = new Map()
  t.ok(checkFixedWindowRateLimit(limits, 'ip', 2, 1_000, 60_000))
  t.ok(checkFixedWindowRateLimit(limits, 'ip', 2, 1_001, 60_000))
  t.absent(checkFixedWindowRateLimit(limits, 'ip', 2, 1_002, 60_000))
  t.ok(checkFixedWindowRateLimit(limits, 'ip', 2, 61_001, 60_000), 'window resets after resetAt')
})

test('api rate limit: endpoint caps are separate from the general per-IP cap', (t) => {
  const general = new Map()
  const endpoint = new Map()
  const ip = '203.0.113.7'

  for (let i = 0; i < API_RATE_LIMIT_MAX; i++) {
    t.ok(checkApiRateLimit(general, ip, 2_000 + i), 'general cap allows request ' + i)
  }
  t.absent(checkApiRateLimit(general, ip, 3_000), 'general cap rejects after max')

  for (let i = 0; i < API_ENDPOINT_RATE_LIMITS['/api/wizard/reset']; i++) {
    t.ok(checkEndpointRateLimit(endpoint, ip, '/api/wizard/reset', 2_000 + i), 'endpoint cap allows reset request ' + i)
  }
  t.absent(checkEndpointRateLimit(endpoint, ip, '/api/wizard/reset', 3_000), 'endpoint cap rejects sensitive route')
  t.ok(checkEndpointRateLimit(endpoint, ip, '/api/status', 3_000), 'uncapped endpoint remains governed by general limiter')
})

test('api rate limit: endpoint key separates path and IP without collisions', (t) => {
  t.is(endpointRateLimitKey('1.2.3.4', '/api/wizard/reset'), '/api/wizard/reset\x001.2.3.4')
  t.not(endpointRateLimitKey('1.2.3.4', '/api/wizard/reset'), endpointRateLimitKey('1.2.3.40', '/api/wizard/reset'))
  t.not(endpointRateLimitKey('1.2.3.4', '/api/wizard/reset'), endpointRateLimitKey('1.2.3.4', '/api/wizard/payout'))
})

test('api rate limit: cleanup removes expired windows only', (t) => {
  const limits = new Map([
    ['expired', { count: 1, resetAt: 10 }],
    ['fresh', { count: 1, resetAt: 100 }]
  ])
  t.is(sweepRateLimitMap(limits, 50), 1)
  t.absent(limits.has('expired'))
  t.ok(limits.has('fresh'))
})

test('api rate limit: rejected requests do not consume window budget (no self-lockout)', (t) => {
  const limits = new Map()
  t.ok(checkFixedWindowRateLimit(limits, 'ip', 2, 1_000, 60_000))
  t.ok(checkFixedWindowRateLimit(limits, 'ip', 2, 1_001, 60_000))
  let rejected = 0
  for (let i = 0; i < 100; i++) {
    if (!checkFixedWindowRateLimit(limits, 'ip', 2, 1_002 + i, 60_000)) rejected++
  }
  t.is(rejected, 100, 'over-cap requests keep rejecting inside the window')
  t.is(limits.get('ip').count, 2, 'rejected attempts never incremented the count')
  t.ok(checkFixedWindowRateLimit(limits, 'ip', 2, 61_001, 60_000), 'window still resets on schedule')
})
