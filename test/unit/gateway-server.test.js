import test from 'brittle'
import http from 'http'
import net from 'net'
import { Readable } from 'stream'
import {
  GatewayServer,
  assertHiveAppGatewayIsolation
} from 'p2p-hiverelay/core/relay-node/gateway-server.js'

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
      method: opts.method || 'GET',
      path,
      headers: opts.headers || {}
    }, (res) => {
      const chunks = []
      res.on('data', chunk => { chunks.push(chunk) })
      res.on('end', () => {
        const raw = Buffer.concat(chunks)
        const data = raw.toString('utf8')
        let body
        try { body = JSON.parse(data) } catch (_) { body = data }
        resolve({ statusCode: res.statusCode, headers: res.headers, body, raw })
      })
    })
    req.on('error', reject)
    req.end(opts.body)
  })
}

function rawRequest (port, payload) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1')
    const chunks = []
    socket.setTimeout(2000, () => socket.destroy(new Error('raw request timed out')))
    socket.on('connect', () => socket.end(payload))
    socket.on('data', chunk => chunks.push(chunk))
    socket.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    socket.on('error', reject)
  })
}

async function startGateway (t, opts = {}) {
  const { node = mockNode(), ...serverOpts } = opts
  const server = new GatewayServer(node, {
    gatewayPort: 0,
    gatewayHost: '127.0.0.1',
    gateway: mockGateway(),
    ...serverOpts
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

test('GatewayServer - key subdomain routes an isolated exact-byte app origin', async (t) => {
  const appLabel = 'ikikikikikikikikikikikikikikikikikikikikikikikikikiy'
  const suffix = 'hive.relay.example'
  let seen = null
  const gateway = {
    async close () {},
    handle (req, res, context) {
      seen = context
      res.writeHead(200, { 'Content-Type': 'text/plain' })
      res.end('app')
    }
  }
  const server = await startGateway(t, {
    gateway,
    hiveAppHostSuffix: suffix,
    hiveAppPublicKeys: ['aa'.repeat(32)],
    trustProxy: true,
    corsOrigins: ['*']
  })
  const port = server.server.address().port

  const res = await request(port, '/assets/app.js', {
    headers: {
      Host: `${appLabel}.${suffix}`,
      Origin: 'https://attacker.example',
      'X-Forwarded-Host': `${'y'.repeat(52)}.${suffix}`,
      'X-Forwarded-For': '203.0.113.10'
    }
  })

  t.is(res.statusCode, 200)
  t.is(res.body, 'app')
  t.alike({
    appKey: seen.appKey,
    path: seen.path,
    byteMode: seen.byteMode
  }, {
    appKey: 'aa'.repeat(32),
    path: '/assets/app.js',
    byteMode: 'exact'
  })
  t.ok(seen.publicAppKeys.has('aa'.repeat(32)), 'local approval set is forwarded to the exact gateway')
  t.absent(res.headers['access-control-allow-origin'], 'app origin does not inherit wildcard gateway CORS')
})

test('GatewayServer - sibling app hosts resolve independently at the same path', async (t) => {
  const zeroLabel = 'y'.repeat(52)
  const aaLabel = 'ikikikikikikikikikikikikikikikikikikikikikikikikikiy'
  const suffix = 'hive.relay.example'
  const gateway = {
    async close () {},
    handle (req, res, context) {
      res.writeHead(200, { 'Content-Type': 'text/plain' })
      res.end(context.appKey)
    }
  }
  const server = await startGateway(t, {
    gateway,
    hiveAppHostSuffix: suffix,
    trustProxy: true
  })
  const port = server.server.address().port

  const zero = await request(port, '/index.html', { headers: { Host: `${zeroLabel}.${suffix}` } })
  const aa = await request(port, '/index.html', { headers: { Host: `${aaLabel}.${suffix}` } })

  t.is(zero.statusCode, 200)
  t.is(aa.statusCode, 200)
  t.is(zero.body, '00'.repeat(32))
  t.is(aa.body, 'aa'.repeat(32))
  t.unlike(zero.body, aa.body, 'same path on sibling app hosts cannot select the same key by accident')
})

test('GatewayServer - malformed app hosts fail closed while compatibility hosts remain available', async (t) => {
  const suffix = 'hive.relay.example'
  let gatewayCalls = 0
  const gateway = {
    async close () {},
    handle (req, res) {
      gatewayCalls++
      res.writeHead(200)
      res.end()
    }
  }
  const server = await startGateway(t, { gateway, hiveAppHostSuffix: suffix })
  const port = server.server.address().port

  const invalid = await request(port, '/index.html', {
    headers: { Host: `not-a-key.${suffix}` }
  })
  t.is(invalid.statusCode, 400, 'intended malformed app host rejected')
  t.is(invalid.body.error, 'invalid Hive app key label')
  t.is(gatewayCalls, 0, 'malformed host never reaches content gateway')

  const compatibility = await request(port, '/health', {
    headers: {
      Host: `127.0.0.1:${port}`,
      'X-Forwarded-Host': `ikikikikikikikikikikikikikikikikikikikikikikikikikiy.${suffix}`,
      'X-Forwarded-For': '203.0.113.11'
    }
  })
  t.is(compatibility.statusCode, 200, 'ordinary gateway host still works')
  t.is(compatibility.body.service, 'gateway')
  t.is(gatewayCalls, 0, 'forwarded host is not trusted for app routing')
})

test('GatewayServer - duplicate raw Host headers are rejected before routing', async (t) => {
  const appLabel = 'ikikikikikikikikikikikikikikikikikikikikikikikikikiy'
  const suffix = 'hive.relay.example'
  let gatewayCalls = 0
  const gateway = {
    async close () {},
    handle (req, res) {
      gatewayCalls++
      res.writeHead(200)
      res.end()
    }
  }
  const server = await startGateway(t, { gateway, hiveAppHostSuffix: suffix })
  const port = server.server.address().port

  const raw = await rawRequest(port,
    'GET /index.html HTTP/1.1\r\n' +
    `Host: ${appLabel}.${suffix}\r\n` +
    'Host: attacker.example\r\n' +
    'Connection: close\r\n\r\n')

  t.ok(/^HTTP\/1\.1 400 /.test(raw), 'duplicate Host request receives 400')
  t.is(gatewayCalls, 0, 'duplicate Host never reaches gateway')
})

test('GatewayServer - malformed Host traffic is rate limited before parsing', async (t) => {
  const server = await startGateway(t, {
    hiveAppHostSuffix: 'hive.relay.example',
    trustProxy: true
  })
  const port = server.server.address().port
  const ip = '203.0.113.12'
  server._rateLimits.set(ip, { count: 600, resetAt: Date.now() + 60_000 })

  const res = await request(port, '/index.html', {
    headers: {
      Host: 'not-a-key.hive.relay.example',
      'X-Forwarded-For': ip
    }
  })

  t.is(res.statusCode, 429, 'rate limiter bounds malformed Host floods')
  t.is(res.body.error, 'Too many requests')
})

test('GatewayServer - app-host throttling remains origin-isolated and counter-bounded', async (t) => {
  const appLabel = 'ikikikikikikikikikikikikikikikikikikikikikikikikikiy'
  const appKey = 'aa'.repeat(32)
  const suffix = 'hive.relay.example'
  const server = await startGateway(t, {
    hiveAppHostSuffix: suffix,
    trustProxy: true
  })
  const ip = '203.0.113.13'
  server._rateLimits.set(ip, { count: 600, resetAt: Date.now() + 60_000 })

  const res = await request(server.server.address().port, '/index.html', {
    headers: {
      Host: `${appLabel}.${suffix}`,
      'X-Forwarded-For': ip
    }
  })

  t.is(res.statusCode, 429)
  t.is(res.headers['x-hive-app-key'], appKey)
  t.is(res.headers.vary, 'Host')
  t.is(res.headers['cache-control'], 'no-store, max-age=0')
  t.is(server._rateLimits.get(ip).count, 600, 'rejected requests cannot grow the bucket counter without bound')
})

test('GatewayServer - app hosts stay on the read-only content plane', async (t) => {
  const appLabel = 'ikikikikikikikikikikikikikikikikikikikikikikikikikiy'
  const appKey = 'aa'.repeat(32)
  const suffix = 'hive.relay.example'
  let seen = null
  const gateway = {
    async close () {},
    handle (req, res, context) {
      seen = context
      res.writeHead(404)
      res.end()
    }
  }
  const server = await startGateway(t, {
    gateway,
    hiveAppHostSuffix: suffix,
    hiveAppPublicKeys: [appKey],
    hiveAppPublicVersions: { [appKey]: 7 }
  })
  const port = server.server.address().port

  const res = await request(port, '/api/manage/config', {
    headers: { Host: `${appLabel}.${suffix}` }
  })
  t.is(res.statusCode, 404)
  t.is(seen.path, '/api/manage/config', 'path is treated only as an app file')
  t.is(seen.byteMode, 'exact')
  t.is(seen.driveVersion, 7, 'app Host carries its immutable runtime version pin')
})

test('GatewayServer - signed relay capabilities stay on the read-only plane', async (t) => {
  const server = await startGateway(t)
  const result = await request(server.server.address().port, '/.well-known/hiverelay.json')
  t.is(result.statusCode, 200)
  t.is(result.body.schemaVersion, 1)
  t.is(result.headers['cache-control'], 'public, max-age=60')

  const management = await request(server.server.address().port, '/api/manage/config')
  t.is(management.statusCode, 404, 'capability support does not add management routes')
})

test('GatewayServer - app host exposes bounded generated well-known metadata', async (t) => {
  const appLabel = 'ikikikikikikikikikikikikikikikikikikikikikikikikikiy'
  const appKey = 'aa'.repeat(32)
  const suffix = 'hive.relay.example'
  const node = mockNode()
  node.config.hiveAppPublicKeys = [appKey]
  node.config.hiveAppPublicVersions = { [appKey]: 1 }
  const metadataDrive = { closed: false, closing: false }
  node.seededApps = new Map([[appKey, {
    drive: metadataDrive,
    blind: false,
    privacyTier: 'public',
    storageClass: 'persistent',
    availabilityClass: 'always-on',
    storageProvedDriveVersion: 1
  }]])
  node.appLifecycle = {
    acquireDriveReadLease (key) {
      const drive = node.seededApps.get(key)?.drive
      return drive ? { drive, release () {} } : null
    }
  }
  const server = await startGateway(t, {
    node,
    hiveAppHostSuffix: suffix,
    hiveAppPublicVersions: { [appKey]: 1 }
  })
  const port = server.server.address().port
  const headers = { Host: `${appLabel}.${suffix}` }

  const get = await request(port, '/.well-known/hiverelay-app.json', { headers })
  t.is(get.statusCode, 200)
  t.is(get.body.type, 'hiverelay-public-app-v1')
  t.is(get.body.appKey, appKey)
  t.is(get.body.gatewayHost, `${appLabel}.${suffix}`)
  t.is(get.body.byteMode, 'exact')
  t.is(get.body.signed, false, 'unsigned transport metadata is honest')
  t.is(get.headers['x-hive-byte-mode'], 'generated')
  t.is(get.headers.vary, 'Host')
  t.is(get.headers['origin-agent-cluster'], '?1')
  t.absent(get.headers['set-cookie'], 'generated gateway metadata stays cookie-free')

  const head = await request(port, '/.well-known/hiverelay-app.json', { headers, method: 'HEAD' })
  t.is(head.statusCode, 200)
  t.is(head.body, '', 'HEAD does not return metadata body')
  t.ok(Number(head.headers['content-length']) > 0, 'HEAD preserves generated representation length')
  t.is(head.headers['x-hive-byte-mode'], 'generated')

  const ranged = await request(port, '/.well-known/hiverelay-app.json', {
    headers: { ...headers, Range: 'bytes=0-0' }
  })
  t.is(ranged.statusCode, 206)
  t.is(ranged.raw.length, 1)
  t.is(ranged.headers['x-hive-byte-mode'], 'generated')
  const rejectedRange = await request(port, '/.well-known/hiverelay-app.json', {
    headers: { ...headers, Range: 'items=0-1' }
  })
  t.is(rejectedRange.statusCode, 416)
  t.is(rejectedRange.headers['x-hive-byte-mode'], 'generated')

  node.appLifecycle.acquireDriveReadLease = () => ({ drive: {}, release () {} })
  const substitutedLease = await request(port, '/.well-known/hiverelay-app.json', { headers })
  t.is(substitutedLease.statusCode, 403, 'metadata rejects a lease for a substituted drive')

  node.seededApps.set(appKey, {
    blind: true,
    privacyTier: 'p2p-only',
    storageClass: 'temporary',
    availabilityClass: 'atomic-handoff'
  })
  const privateResult = await request(port, '/.well-known/hiverelay-app.json', { headers })
  t.is(privateResult.statusCode, 403, 'private/custody entry receives no public metadata')
})

test('GatewayServer - zero drive version cannot authorize public metadata', async (t) => {
  const appLabel = 'ikikikikikikikikikikikikikikikikikikikikikikikikikiy'
  const appKey = 'aa'.repeat(32)
  const suffix = 'hive.relay.example'
  const drive = { closed: false, closing: false }
  let leaseAcquisitions = 0
  const node = mockNode()
  node.seededApps = new Map([[appKey, {
    drive,
    blind: false,
    privacyTier: 'public',
    storageClass: 'persistent',
    availabilityClass: 'always-on',
    storageProvedDriveVersion: 0
  }]])
  node.appLifecycle = {
    acquireDriveReadLease () {
      leaseAcquisitions++
      return { drive, release () {} }
    }
  }
  const server = await startGateway(t, {
    node,
    hiveAppHostSuffix: suffix,
    hiveAppPublicKeys: [appKey],
    hiveAppPublicVersions: { [appKey]: 0 }
  })

  const result = await request(server.server.address().port, '/.well-known/hiverelay-app.json', {
    headers: { Host: `${appLabel}.${suffix}` }
  })
  t.is(result.statusCode, 403, 'zero is never accepted as a proved public snapshot')
  t.is(leaseAcquisitions, 0, 'zero authority fails before lifecycle acquisition')
})

test('GatewayServer - app Host routes through HyperGateway exact serving', async (t) => {
  const appLabel = 'ikikikikikikikikikikikikikikikikikikikikikikikikikiy'
  const appKey = 'aa'.repeat(32)
  const suffix = 'hive.relay.example'
  const files = {
    '/index.html': Buffer.from('<script src="/assets/app.js"></script>\r\n'),
    '/assets/app.js': Buffer.from('console.log("exact")\n')
  }
  const drive = {
    closed: false,
    closing: false,
    version: 1,
    async ready () {},
    async update () {},
    async close () { this.closed = true },
    async entry (path) {
      const value = files[path]
      return value ? { value: { blob: { byteLength: value.byteLength } } } : null
    },
    createReadStream (path, opts = {}) {
      const value = files[path] || Buffer.alloc(0)
      const start = opts.start || 0
      const end = opts.length == null ? value.length : start + opts.length
      return Readable.from([value.subarray(start, end)])
    },
    async * list () {}
  }
  drive.checkout = () => ({ ...drive, closed: false, closing: false })
  const node = {
    config: {
      gatewayPublicOnlyPrivacyTier: true,
      hiveAppPublicKeys: [appKey]
    },
    store: null,
    seededApps: new Map([[appKey, {
      drive,
      blind: false,
      privacyTier: 'public',
      storageClass: 'persistent',
      availabilityClass: 'always-on',
      storageProvedDriveVersion: 1
    }]])
  }
  node.appLifecycle = {
    acquireDriveReadLease (key) {
      const seeded = node.seededApps.get(key)?.drive
      return seeded ? { drive: seeded, release () {} } : null
    }
  }
  const server = await startGateway(t, {
    node,
    gateway: undefined,
    hiveAppHostSuffix: suffix,
    hiveAppPublicVersions: { [appKey]: 1 }
  })
  const port = server.server.address().port
  const headers = { Host: `${appLabel}.${suffix}` }

  const html = await request(port, '/', { headers })
  t.is(html.statusCode, 200)
  t.ok(html.raw.equals(files['/index.html']), 'root index is served byte-identically')
  t.is(html.headers['x-hive-byte-mode'], 'exact')

  const asset = await request(port, '/assets/app.js', { headers })
  t.is(asset.statusCode, 200)
  t.ok(asset.raw.equals(files['/assets/app.js']), 'absolute asset path resolves inside the same drive')
  t.is(asset.headers['x-hive-app-key'], appKey)
})

test('GatewayServer - invalid configured app suffix is rejected at construction', (t) => {
  t.exception(() => new GatewayServer(mockNode(), {
    gateway: mockGateway(),
    hiveAppHostSuffix: 'localhost'
  }), /must be a valid DNS suffix/)
})

test('GatewayServer - app hosts require a distinct data-plane listener', (t) => {
  t.is(assertHiveAppGatewayIsolation({ hiveAppHostSuffix: null }), null, 'disabled feature needs no gateway')
  t.is(assertHiveAppGatewayIsolation({
    hiveAppHostSuffix: 'hive.relay.example',
    gatewayPort: 9200,
    apiPort: 9100
  }), 'hive.relay.example')

  t.exception(() => assertHiveAppGatewayIsolation({
    hiveAppHostSuffix: 'hive.relay.example',
    gatewayPort: null,
    apiPort: 9100
  }), /requires a distinct dedicated gatewayPort/)
  t.exception(() => assertHiveAppGatewayIsolation({
    hiveAppHostSuffix: 'hive.relay.example',
    gatewayPort: 9100,
    apiPort: 9100
  }), /requires a distinct dedicated gatewayPort/)
  t.exception(() => assertHiveAppGatewayIsolation({
    hiveAppHostSuffix: 'hive.relay.example',
    hiveAppPublicKeys: ['not-a-key'],
    gatewayPort: 9200,
    apiPort: 9100
  }), /hiveAppPublicKeys/)
  t.exception(() => assertHiveAppGatewayIsolation({
    hiveAppHostSuffix: 'hive.relay.example',
    hiveAppPublicKeys: ['a'.repeat(64)],
    hiveAppPublicVersions: { ['a'.repeat(64)]: '7' },
    gatewayPort: 9200,
    apiPort: 9100
  }), /hiveAppPublicVersions/)
  t.exception(() => assertHiveAppGatewayIsolation({
    hiveAppHostSuffix: 'hive.relay.example',
    hiveAppPublicKeys: ['a'.repeat(64)],
    hiveAppPublicVersions: { ['b'.repeat(64)]: 7 },
    gatewayPort: 9200,
    apiPort: 9100
  }), /outside hiveAppPublicKeys/)
  t.exception(() => assertHiveAppGatewayIsolation({
    hiveAppHostSuffix: 'hive.relay.example',
    gatewayPort: 9200,
    apiPort: 9100,
    enableAPI: false
  }), /requires enableAPI/)
  t.exception(() => assertHiveAppGatewayIsolation({
    hiveAppHostSuffix: 'hive.relay.example',
    gatewayPort: '9200',
    apiPort: 9100
  }), /requires a distinct dedicated gatewayPort/, 'numeric strings cannot select the Unix-socket listen overload')
  t.exception(() => assertHiveAppGatewayIsolation({
    hiveAppHostSuffix: 'hive.relay.example',
    gatewayPort: 9200,
    gatewayHost: '0.0.0.0',
    apiPort: 9100
  }), /requires gatewayHost to bind loopback/)
  t.exception(() => assertHiveAppGatewayIsolation({
    hiveAppHostSuffix: 'hive.relay.example',
    gatewayPort: 9200,
    apiPort: 9100,
    mode: 'custody-relay'
  }), /forbidden for custody or restricted relay profiles/)
  t.exception(() => assertHiveAppGatewayIsolation({
    hiveAppHostSuffix: 'hive.relay.example',
    gatewayPort: 9200,
    apiPort: 9100,
    productProfile: 'CUSTODY-RELAY'
  }), /forbidden for custody or restricted relay profiles/, 'profile checks are case-insensitive')
})

test('GatewayServer - public-t1 product profile is a complete fail-closed runtime contract', (t) => {
  const key = 'a'.repeat(64)
  const production = {
    productProfile: 'public-t1-gateway',
    mode: 'public-t1-gateway',
    hiveAppHostSuffix: 'hive.relay.example',
    hiveAppPublicKeys: [key],
    hiveAppPublicVersions: { [key]: 7 },
    gatewayPort: 9200,
    gatewayHost: '127.0.0.1',
    gatewayTrustProxy: true,
    gatewayRequireForwardedSNI: true,
    gatewayMaxResponseBytes: 64 * 1024 * 1024,
    gatewayMaxTransformBytes: 4 * 1024 * 1024,
    gatewayEgressBytesPerWindow: 256 * 1024 * 1024,
    gatewayEgressWindowMs: 60 * 1000,
    gatewayMaxResponseLifetimeMs: 15 * 60 * 1000,
    apiPort: 9100,
    apiHost: '127.0.0.1',
    enableAPI: true,
    enableSeeding: true,
    requirePhysicalEnforcement: true,
    custody: { enabled: false }
  }

  const missingPhysicalEnforcement = { ...production }
  delete missingPhysicalEnforcement.requirePhysicalEnforcement
  t.exception(() => assertHiveAppGatewayIsolation(missingPhysicalEnforcement),
    /requires requirePhysicalEnforcement to be true/,
    'direct isolation validation rejects a missing physical-enforcement authority')
  t.exception(() => assertHiveAppGatewayIsolation({
    ...production,
    requirePhysicalEnforcement: false
  }), /requires requirePhysicalEnforcement to be true/,
  'direct isolation validation rejects an explicit physical-enforcement downgrade')
  t.is(assertHiveAppGatewayIsolation({
    ...production,
    enforceCompiledAdmission: false
  }), 'hive.relay.example', 'the complete physical-enforcement contract passes before the transitional compiled gate')

  t.exception(() => assertHiveAppGatewayIsolation({
    ...production,
    apiHost: '0.0.0.0'
  }), /requires apiHost to bind loopback/)
  t.exception(() => assertHiveAppGatewayIsolation({
    ...production,
    gatewayTrustProxy: false
  }), /requires gatewayTrustProxy/)
  t.exception(() => assertHiveAppGatewayIsolation({
    ...production,
    gatewayRequireForwardedSNI: false
  }), /requires gatewayRequireForwardedSNI/)
  t.exception(() => assertHiveAppGatewayIsolation({
    ...production,
    custody: { enabled: true }
  }), /requires custody.enabled to be false/)
  t.exception(() => assertHiveAppGatewayIsolation({
    ...production,
    hiveAppPublicKeys: [key, 'b'.repeat(64)]
  }), /requires exactly one hiveAppPublicKeys entry/)
  t.exception(() => assertHiveAppGatewayIsolation({
    ...production,
    hiveAppPublicVersions: {}
  }), /requires exactly one matching immutable hiveAppPublicVersions pin/)
  t.exception(() => assertHiveAppGatewayIsolation({
    ...production,
    gatewayMaxResponseBytes: 1
  }), /requires gatewayMaxResponseBytes to equal/)
  t.exception(() => assertHiveAppGatewayIsolation(production),
    /compiled fleet-ready non-transitional admission capability/,
    'the production profile remains closed while compiled substrate admission is transitional')

  for (const [mode, productProfile] of [
    ['PUBLIC-T1-GATEWAY', 'public-t1-gateway'],
    ['public-t1-gateway', 'PUBLIC-T1-GATEWAY'],
    [undefined, 'public-t1-gateway'],
    ['public-t1-gateway', undefined],
    ['relay-core', 'public-t1-gateway']
  ]) {
    t.exception(() => assertHiveAppGatewayIsolation({ ...production, mode, productProfile }),
      /exact canonical matching mode and productProfile/)
  }

  const directNode = {
    mode: 'PUBLIC-T1-GATEWAY',
    store: null,
    config: {
      ...production,
      productProfile: 'PUBLIC-T1-GATEWAY',
      hiveAppPublicKeys: [key],
      hiveAppPublicVersions: { [key]: 7 }
    }
  }
  t.exception(() => new GatewayServer(directNode),
    /exact canonical matching mode and productProfile/,
    'direct GatewayServer construction cannot normalize a fake production profile into authority')

  const canonicalDirectNode = {
    mode: 'public-t1-gateway',
    store: null,
    config: { ...production, hiveAppPublicKeys: [key], hiveAppPublicVersions: { [key]: 7 } }
  }
  t.exception(() => new GatewayServer(canonicalDirectNode, { gatewayHost: '0.0.0.0' }),
    /gatewayHost override must exactly match node config/)
  t.exception(() => new GatewayServer(canonicalDirectNode, { gateway: mockGateway() }),
    /forbids an injected Gateway handler/)
})

test('GatewayServer - every exact-host posture forbids an enabled custody plane', (t) => {
  t.exception(() => assertHiveAppGatewayIsolation({
    hiveAppHostSuffix: 'hive.relay.example',
    hiveAppPublicKeys: ['a'.repeat(64)],
    gatewayPort: 9200,
    apiPort: 9100,
    custody: { enabled: true }
  }), /forbids an enabled custody plane/)
})

test('GatewayServer - concurrency configuration fails closed', (t) => {
  t.exception(() => new GatewayServer(mockNode(), {
    gateway: mockGateway(),
    maxInFlight: '256'
  }), /gatewayMaxInFlight must be an integer/)
  t.exception(() => new GatewayServer(mockNode(), {
    gateway: mockGateway(),
    maxInFlight: 8,
    maxInFlightPerApp: 9
  }), /must not exceed gatewayMaxInFlight/)
  t.exception(() => new GatewayServer(mockNode(), {
    gateway: mockGateway(),
    maxRateLimitBuckets: 0
  }), /maxRateLimitBuckets must be an integer/)
  t.exception(() => new GatewayServer(mockNode(), {
    gateway: mockGateway(),
    maxResponseLifetimeMs: 0
  }), /gatewayMaxResponseLifetimeMs must be an integer/)
  t.exception(() => new GatewayServer(mockNode(), {
    gateway: mockGateway(),
    egressBytesPerWindow: null
  }), /gatewayEgressBytesPerWindow/)
  t.exception(() => new GatewayServer(mockNode(), {
    gateway: mockGateway(),
    corsOrigins: 'https://example.com'
  }), /corsOrigins/)
})

test('GatewayServer - request bodies and absolute-form targets fail closed', async (t) => {
  let gatewayCalls = 0
  const gateway = {
    async close () {},
    handle (req, res) {
      gatewayCalls++
      res.writeHead(200)
      res.end('unexpected')
    }
  }
  const server = await startGateway(t, { gateway })
  const port = server.server.address().port

  const body = await request(port, '/v1/hyper/' + 'a'.repeat(64) + '/x', {
    headers: { 'Content-Length': '1' },
    body: 'x'
  })
  t.is(body.statusCode, 400)
  t.is(body.body.error, 'Request body is not allowed')
  t.is(body.headers.connection, 'close')

  const absolute = await rawRequest(port,
    'GET http://attacker.example/health HTTP/1.1\r\n' +
    `Host: 127.0.0.1:${port}\r\n` +
    'Connection: close\r\n\r\n')
  t.ok(/^HTTP\/1\.1 400 /.test(absolute), 'absolute-form proxy target is rejected')
  t.is(gatewayCalls, 0, 'neither hostile request reaches the content engine')
})

test('GatewayServer - proof content negotiation stays closed until bounded proof mode exists', async (t) => {
  const appLabel = 'ikikikikikikikikikikikikikikikikikikikikikikikikikiy'
  const suffix = 'hive.relay.example'
  let gatewayCalls = 0
  const gateway = {
    async close () {},
    handle () { gatewayCalls++ }
  }
  const server = await startGateway(t, { gateway, hiveAppHostSuffix: suffix })
  const result = await request(server.server.address().port, '/index.html', {
    headers: {
      Host: `${appLabel}.${suffix}`,
      Accept: 'application/vnd.hiverelay.proof+binary;version=1'
    }
  })
  t.is(result.statusCode, 406)
  t.is(result.body.error, 'Proof-carrying HTTP mode is not available')
  t.is(result.headers.vary, 'Host')
  t.is(gatewayCalls, 0, 'proof request cannot fall through to ordinary bytes')
})

test('GatewayServer - app-host listener rejects unallowlisted compatibility Hosts', async (t) => {
  const suffix = 'hive.relay.example'
  const strict = await startGateway(t, { hiveAppHostSuffix: suffix })
  const strictPort = strict.server.address().port

  const rejected = await request(strictPort, '/health', { headers: { Host: 'relay.example' } })
  t.is(rejected.statusCode, 421, 'unrelated Host cannot reach legacy routes on the app listener')
  t.is(rejected.body.error, 'Misdirected request')

  const onionHost = 'b'.repeat(56) + '.onion'
  strict.addCompatibilityHost(onionHost)
  const onion = await request(strictPort, '/health', { headers: { Host: onionHost } })
  t.is(onion.statusCode, 200, 'the active signed onion address can be admitted after creation')

  const compatible = await startGateway(t, {
    hiveAppHostSuffix: suffix,
    compatibilityHosts: ['relay.example']
  })
  const compatiblePort = compatible.server.address().port
  const allowed = await request(compatiblePort, '/health', { headers: { Host: 'relay.example' } })
  t.is(allowed.statusCode, 200, 'operator can explicitly retain a compatibility Host')
})

test('GatewayServer - trusted TLS edge must bind forwarded SNI to Host', async (t) => {
  const appLabel = 'ikikikikikikikikikikikikikikikikikikikikikikikikikiy'
  const suffix = 'hive.relay.example'
  const host = `${appLabel}.${suffix}`
  const gateway = {
    async close () {},
    async handle (req, res) {
      res.writeHead(200)
      res.end('app')
    }
  }
  const server = await startGateway(t, {
    gateway,
    hiveAppHostSuffix: suffix,
    trustProxy: true,
    requireForwardedSNI: true
  })
  const port = server.server.address().port

  const missing = await request(port, '/', { headers: { Host: host } })
  t.is(missing.statusCode, 421, 'missing edge SNI attestation rejected')

  const mismatch = await request(port, '/', {
    headers: { Host: host, 'X-Hive-Forwarded-SNI': `${'y'.repeat(52)}.${suffix}` }
  })
  t.is(mismatch.statusCode, 421, 'mismatched SNI and Host rejected')

  const match = await request(port, '/', {
    headers: { Host: host, 'X-Hive-Forwarded-SNI': host }
  })
  t.is(match.statusCode, 200, 'matching SNI from a trusted loopback edge accepted')
})

test('GatewayServer - proxy IP trust is scoped, bounded, and canonical', (t) => {
  const server = new GatewayServer(mockNode(), {
    gateway: mockGateway(),
    gatewayHost: '127.0.0.1',
    trustProxy: true,
    trustedProxyAddresses: ['127.0.0.1']
  })

  t.is(server._getClientIP({
    socket: { remoteAddress: '::ffff:127.0.0.1' },
    headers: { 'x-forwarded-for': '203.0.113.40' }
  }), '203.0.113.40', 'trusted edge can provide one validated client IP')
  t.is(server._getClientIP({
    socket: { remoteAddress: '127.0.0.1' },
    headers: { 'x-forwarded-for': 'attacker, 203.0.113.40' }
  }), '127.0.0.1', 'appended or malformed forwarding input is ignored')
  t.is(server._getClientIP({
    socket: { remoteAddress: '198.51.100.9' },
    headers: { 'x-forwarded-for': '203.0.113.40' }
  }), '198.51.100.9', 'untrusted direct peers cannot spoof forwarding headers')
})

test('GatewayServer - asynchronous gateway failures are contained', async (t) => {
  const appLabel = 'ikikikikikikikikikikikikikikikikikikikikikikikikikiy'
  const suffix = 'hive.relay.example'
  const gateway = {
    async close () {},
    async handle () { throw new Error('drive exploded with internal detail') }
  }
  const server = await startGateway(t, { gateway, hiveAppHostSuffix: suffix })
  const errors = []
  server.on('request-error', event => errors.push(event))
  const res = await request(server.server.address().port, '/', {
    headers: { Host: `${appLabel}.${suffix}` }
  })

  t.is(res.statusCode, 500)
  t.is(res.body.error, 'Internal error', 'public failure is bounded and generic')
  t.is(errors.length, 1, 'operator receives one diagnostic event without EventEmitter error semantics')
})

test('GatewayServer - in-flight requests are bounded per app', async (t) => {
  const appLabel = 'ikikikikikikikikikikikikikikikikikikikikikikikikikiy'
  const suffix = 'hive.relay.example'
  let releaseFirst
  let firstStarted
  const started = new Promise(resolve => { firstStarted = resolve })
  const gateway = {
    async close () {},
    handle (req, res) {
      firstStarted()
      return new Promise(resolve => {
        releaseFirst = () => {
          res.writeHead(200)
          res.end('done')
          resolve()
        }
      })
    }
  }
  const server = await startGateway(t, {
    gateway,
    hiveAppHostSuffix: suffix,
    maxInFlight: 1,
    maxInFlightPerApp: 1
  })
  const port = server.server.address().port
  const headers = { Host: `${appLabel}.${suffix}` }
  t.is(server.server.maxConnections, 64, 'slow-header sockets have an independent hard cap')
  t.is(server.server.dropMaxConnection, true)
  const first = request(port, '/', { headers })
  await started

  const busy = await request(port, '/', { headers })
  t.is(busy.statusCode, 503)
  t.is(busy.body.error, 'Gateway busy')
  t.is(busy.headers['retry-after'], '1')
  t.is(busy.headers.vary, 'Host', 'app-origin errors retain Host cache isolation')

  releaseFirst()
  const completed = await first
  t.is(completed.statusCode, 200)
})

test('GatewayServer - response lifetime tears down a stalled reader and releases admission', async (t) => {
  let resolveResponseClosed
  const responseClosed = new Promise(resolve => { resolveResponseClosed = resolve })
  const gateway = {
    async close () {},
    handle (req, res) {
      res.writeHead(200, { 'Content-Type': 'application/octet-stream' })
      res.write(Buffer.alloc(1))
      return new Promise(resolve => {
        res.once('close', () => {
          resolveResponseClosed()
          resolve()
        })
      })
    }
  }
  const server = await startGateway(t, {
    gateway,
    maxResponseLifetimeMs: 25,
    maxInFlight: 1,
    maxInFlightPerApp: 1
  })
  const timeouts = []
  server.on('request-timeout', event => timeouts.push(event))

  const client = http.get({
    hostname: '127.0.0.1',
    port: server.server.address().port,
    path: `/v1/hyper/${'a'.repeat(64)}/slow.bin`,
    agent: false
  })
  client.on('error', () => {})
  client.on('response', res => {
    res.pause()
    res.on('error', () => {})
  })

  await responseClosed
  await new Promise(resolve => setImmediate(resolve))
  t.is(timeouts.length, 1, 'finite response lifetime fired once')
  t.is(server._activeRequests, 0, 'destroyed response releases global admission')
  t.is(server._activeRequestsByApp.size, 0, 'destroyed response releases bucket admission')
  client.destroy()
})

test('GatewayServer - exact app egress is charged by bytes before headers', async (t) => {
  const appLabel = 'ikikikikikikikikikikikikikikikikikikikikikikikikikiy'
  const appKey = 'aa'.repeat(32)
  const suffix = 'hive.relay.example'
  const data = Buffer.from('123456')
  const drive = {
    closed: false,
    closing: false,
    version: 1,
    async ready () {},
    async update () {},
    async entry () { return { value: { blob: { byteLength: data.byteLength } } } },
    createReadStream () { return Readable.from([data]) },
    async * list () {}
  }
  drive.checkout = () => ({ ...drive, closed: false, closing: false, async close () { this.closed = true } })
  const node = mockNode()
  node.config.gatewayPublicOnlyPrivacyTier = true
  node.seededApps = new Map([[appKey, {
    drive,
    blind: false,
    privacyTier: 'public',
    storageClass: 'persistent',
    availabilityClass: 'always-on',
    storageProvedDriveVersion: 1
  }]])
  node.appLifecycle = {
    acquireDriveReadLease (key) {
      const seeded = node.seededApps.get(key)?.drive
      return seeded ? { drive: seeded, release () {} } : null
    }
  }
  const server = await startGateway(t, {
    node,
    gateway: undefined,
    hiveAppHostSuffix: suffix,
    hiveAppPublicKeys: [appKey],
    hiveAppPublicVersions: { [appKey]: 1 },
    egressBytesPerWindow: 8
  })
  const headers = { Host: `${appLabel}.${suffix}` }
  const port = server.server.address().port

  const first = await request(port, '/asset.bin', { headers })
  t.is(first.statusCode, 200)
  t.ok(first.raw.equals(data))

  const second = await request(port, '/asset.bin', { headers })
  t.is(second.statusCode, 429, 'second full response exceeds remaining byte budget')
  t.is(second.body.error, 'Gateway byte-rate limit exceeded')
  t.is(second.headers['retry-after'], '60')
  t.is(second.headers['x-hive-byte-mode'], 'generated')

  const head = await request(port, '/asset.bin', { headers, method: 'HEAD' })
  t.is(head.statusCode, 200, 'body-free HEAD does not consume egress budget')
  t.is([...server._egressLimits.values()][0].bytes, data.byteLength)
})

test('GatewayServer - exact-host admission is immutable for the listener lifetime', async (t) => {
  const appLabel = 'ikikikikikikikikikikikikikikikikikikikikikikikikikiy'
  const appKey = 'aa'.repeat(32)
  const suffix = 'hive.relay.example'
  const node = mockNode()
  const drive = { closed: false, closing: false }
  node.seededApps = new Map([[appKey, {
    drive,
    blind: false,
    privacyTier: 'public',
    storageClass: 'persistent',
    availabilityClass: 'always-on',
    storageProvedDriveVersion: 1
  }]])
  node.appLifecycle = {
    acquireDriveReadLease (key) {
      return key === appKey ? { drive, release () {} } : null
    }
  }
  const server = await startGateway(t, {
    node,
    hiveAppHostSuffix: suffix,
    hiveAppPublicKeys: [appKey],
    hiveAppPublicVersions: { [appKey]: 1 }
  })
  const port = server.server.address().port
  const headers = { Host: `${appLabel}.${suffix}` }

  t.is((await request(port, '/.well-known/hiverelay-app.json', { headers })).statusCode, 200)
  t.exception(() => server.updateHiveAppPublicKeys([]), /immutable for the GatewayServer lifetime/)
  t.exception(() => server.hiveAppPublicKeys.add('b'.repeat(64)), /admission set is immutable/)
  t.exception(() => server.hiveAppPublicVersions.set(appKey, 99), /version pins are immutable/)
  t.is((await request(port, '/.well-known/hiverelay-app.json', { headers })).statusCode, 200,
    'failed mutators cannot change live admission')
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

test('GatewayServer - stop is idempotent and the same instance restarts cleanly', async (t) => {
  const server = await startGateway(t)
  const firstPort = server.server.address().port
  t.ok(firstPort > 0)

  await Promise.all([server.stop(), server.stop()])
  t.is(server.server, null)
  await server.start()
  const restarted = await request(server.server.address().port, '/health')
  t.is(restarted.statusCode, 200)
  t.is(server._activeRequests, 0)

  let duplicateFailure = null
  try { await server.start() } catch (err) { duplicateFailure = err }
  t.is(duplicateFailure?.message, 'GatewayServer is already started or starting')
})
