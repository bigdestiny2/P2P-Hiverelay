import test from 'brittle'
import http from 'http'
import net from 'net'
import { GatewayServer } from 'p2p-hiverelay/core/relay-node/gateway-server.js'

function mockNode () {
  const entries = [
    { appKey: '1'.repeat(64), type: 'app', name: 'App One' },
    { appKey: '2'.repeat(64), type: 'drive', name: 'Drive Two' },
    { appKey: '3'.repeat(64), type: 'dataset', name: 'Dataset Three' }
  ]
  return {
    config: { custody: { redactedCatalog: true } },
    store: null,
    appRegistry: {
      catalog () {
        return entries
      }
    }
  }
}

function mockGateway () {
  return {
    async close () {},
    handle (req, res) {
      res.writeHead(404)
      res.end()
    }
  }
}

function request (port, path, opts = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      method: 'GET',
      path,
      headers: opts.headers || {}
    }, (res) => {
      let data = ''
      res.on('data', chunk => { data += chunk })
      res.on('end', () => {
        let body
        try { body = JSON.parse(data) } catch (_) { body = data }
        resolve({ statusCode: res.statusCode, headers: res.headers, body })
      })
    })
    req.on('error', reject)
    req.end()
  })
}

async function startGateway (t, opts = {}) {
  const server = new GatewayServer(mockNode(), {
    gatewayPort: 0,
    gatewayHost: '127.0.0.1',
    gateway: mockGateway(),
    ...opts
  })
  await server.start()
  t.teardown(async () => {
    await server.stop()
  })
  return server
}

test('GatewayServer - catalog pagination uses strict bounded integer parsing', async (t) => {
  const server = await startGateway(t)
  const port = server.server.address().port

  const paged = await request(port, '/catalog.json?page=2&pageSize=1')
  t.is(paged.statusCode, 200, 'valid pagination succeeds')
  t.is(paged.body.page, 2, 'valid page is honored')
  t.is(paged.body.pageSize, 1, 'valid pageSize is honored')
  t.is(paged.body.items.length, 1, 'single item returned')
  t.is(paged.body.items[0].type, 'drive', 'second item selected')

  const malformed = await request(port, '/catalog.json?page=2abc&pageSize=1e2')
  t.is(malformed.statusCode, 200, 'malformed integers fall back safely')
  t.is(malformed.body.page, 1, 'partial page integer is not accepted')
  t.is(malformed.body.pageSize, 50, 'exponential pageSize is not accepted')
  t.is(malformed.body.items.length, 3, 'default pageSize returns the full small catalog')

  const oversized = await request(port, '/catalog.json?page=-99&pageSize=999999999999999999999999')
  t.is(oversized.statusCode, 200, 'oversized integers are clamped')
  t.is(oversized.body.page, 1, 'negative page is clamped to minimum')
  t.is(oversized.body.pageSize, 200, 'unsafe oversized pageSize is clamped to maximum')
})

test('GatewayServer - invalid catalog type filter returns 400 instead of broadening response', async (t) => {
  const server = await startGateway(t)
  const port = server.server.address().port

  const drive = await request(port, '/catalog.json?type=drive')
  t.is(drive.statusCode, 200, 'known type filter succeeds')
  t.is(drive.body.items.length, 1, 'known type filter narrows response')
  t.is(drive.body.items[0].type, 'drive', 'drive item returned')

  const invalid = await request(port, '/catalog.json?type=unknown')
  t.is(invalid.statusCode, 400, 'unknown type is rejected')
  t.ok(/type must be one of/.test(invalid.body.error), 'clear type error returned')
})

test('GatewayServer - JSON responses use hardened headers and explicit catalog cache', async (t) => {
  const server = await startGateway(t)
  const port = server.server.address().port

  const health = await request(port, '/health')
  t.is(health.statusCode, 200, 'health succeeds')
  t.is(health.headers['content-type'], 'application/json; charset=utf-8')
  t.is(health.headers['x-content-type-options'], 'nosniff')
  t.is(health.headers['cache-control'], 'no-store, max-age=0', 'health is not cached by default')

  const catalog = await request(port, '/catalog.json')
  t.is(catalog.statusCode, 200, 'catalog succeeds')
  t.is(catalog.headers['content-type'], 'application/json; charset=utf-8')
  t.is(catalog.headers['x-content-type-options'], 'nosniff')
  t.is(catalog.headers['cache-control'], 'public, max-age=30', 'catalog keeps explicit public cache')

  const invalid = await request(port, '/catalog.json?type=unknown')
  t.is(invalid.statusCode, 400, 'invalid catalog filter is rejected')
  t.is(invalid.headers['content-type'], 'application/json; charset=utf-8')
  t.is(invalid.headers['x-content-type-options'], 'nosniff')
  t.is(invalid.headers['cache-control'], 'no-store, max-age=0', 'catalog errors are not cached')

  const missing = await request(port, '/missing')
  t.is(missing.statusCode, 404, 'missing route is rejected')
  t.is(missing.headers['content-type'], 'application/json; charset=utf-8')
  t.is(missing.headers['x-content-type-options'], 'nosniff')
  t.is(missing.headers['cache-control'], 'no-store, max-age=0', '404 is not cached')
})

test('GatewayServer - rate limit buckets reject new IPs at cap', async (t) => {
  const server = await startGateway(t, {
    trustProxy: true,
    maxRateLimitBuckets: 1
  })
  const port = server.server.address().port

  const first = await request(port, '/health', {
    headers: { 'x-forwarded-for': '203.0.113.1' }
  })
  t.is(first.statusCode, 200, 'first IP bucket is accepted')

  const same = await request(port, '/health', {
    headers: { 'x-forwarded-for': '203.0.113.1' }
  })
  t.is(same.statusCode, 200, 'existing IP bucket remains usable')

  const second = await request(port, '/health', {
    headers: { 'x-forwarded-for': '203.0.113.2' }
  })
  t.is(second.statusCode, 429, 'new IP bucket is rejected once the map is capped')
  t.is(second.body.error, 'Too many requests')
  t.is(server._rateLimits.size, 1, 'map remains capped')
})

test('GatewayServer - rate limit bucket cap prunes stale buckets before rejecting new IPs', async (t) => {
  const server = await startGateway(t, {
    trustProxy: true,
    maxRateLimitBuckets: 1
  })
  const port = server.server.address().port

  server._rateLimits.set('203.0.113.7', {
    count: 1,
    resetAt: Date.now() - 1
  })

  const fresh = await request(port, '/health', {
    headers: { 'x-forwarded-for': '203.0.113.8' }
  })
  t.is(fresh.statusCode, 200, 'fresh IP is accepted after stale bucket pruning')
  t.absent(server._rateLimits.has('203.0.113.7'))
  t.ok(server._rateLimits.has('203.0.113.8'))
  t.is(server._rateLimits.size, 1, 'map remains capped after pruning')
})

test('GatewayServer - malformed rate limit buckets reset instead of poisoning an IP', async (t) => {
  const server = await startGateway(t, {
    trustProxy: true,
    maxRateLimitBuckets: 1
  })
  const port = server.server.address().port

  server._rateLimits.set('203.0.113.9', {
    count: 'bad',
    resetAt: Date.now() + 60_000
  })

  const repaired = await request(port, '/health', {
    headers: { 'x-forwarded-for': '203.0.113.9' }
  })
  t.is(repaired.statusCode, 200, 'request from existing malformed bucket is accepted after reset')
  t.is(server._rateLimits.size, 1, 'malformed bucket did not grow the map')
  t.is(server._rateLimits.get('203.0.113.9').count, 1, 'malformed counter was reset')
})

test('GatewayServer - stop force-closes held client sockets', async (t) => {
  const server = await startGateway(t)
  const port = server.server.address().port

  const socket = net.connect(port, '127.0.0.1')
  await new Promise((resolve, reject) => {
    socket.once('connect', resolve)
    socket.once('error', reject)
  })

  const result = await Promise.race([
    server.stop().then(() => 'stopped'),
    new Promise(resolve => setTimeout(() => resolve('timeout'), 750))
  ])
  t.is(result, 'stopped', 'stop resolves despite held socket')
  t.is(server.server, null, 'server reference cleared')
  socket.destroy()
})
