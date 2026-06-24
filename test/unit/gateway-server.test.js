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

function request (port, path) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      method: 'GET',
      path
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

async function startGateway (t) {
  const server = new GatewayServer(mockNode(), {
    gatewayPort: 0,
    gatewayHost: '127.0.0.1',
    gateway: mockGateway()
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
