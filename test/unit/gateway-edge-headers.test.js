/**
 * R3/R5/R6/R7 — gateway edge header & advertisement bundle.
 *
 * Pins the lane × ingress matrix documented in packages/core/gateway/edge-headers.js:
 *   - R3: the shared-origin path lane is stateless-only — Service-Worker-Allowed
 *     never reaches the wire, and a drive cannot set it through content
 *     (entry metadata is never mapped to headers; the commit-time guard strips
 *     even a header handed straight to writeHead).
 *   - R5: onion ingress (a `.onion` Host on the read plane) carries the exact
 *     restrictive CSP default; clearnet lanes carry none.
 *   - R6: COOP/CORP/Referrer-Policy on both lanes — CORP cross-origin on the
 *     compatibility path lane (matches its ACAO:* posture), same-origin on the
 *     isolated app-origin lane.
 *   - R7: Link: <hive://<key>/<path>>; rel="canonical" on every admitted
 *     path-lane response, completing the app-origin lane's existing hint.
 */

import test from 'brittle'
import http from 'http'
import { Readable } from 'stream'
import { HyperGateway } from 'p2p-hiverelay/gateway'
import { issueExactAppContext } from '../../packages/core/gateway/exact-app-context.js'
import {
  ONION_READ_PLANE_CSP,
  SERVICE_WORKER_ALLOWED_HEADER,
  buildHivePathLinkHeader,
  guardPathLaneStatelessHeaders,
  isOnionReadPlaneHost
} from 'p2p-hiverelay/gateway/edge-headers.js'

const KEY = 'a'.repeat(64)
const OTHER_KEY = 'b'.repeat(64)
const ONION_HOST = 'ftp4zc2one5hc2e3sev5hoddho63hm2dfwfh7pkcpqdc4k5z5ykaaaaa.onion'

function fakeDrive (files = {}) {
  return {
    closed: false,
    closing: false,
    version: 1,
    async ready () {},
    async update () {},
    async close () { this.closed = true },
    async entry (filePath) {
      const data = files[filePath]
      if (!data) return null
      return { value: { blob: { byteLength: data.length }, metadata: data.metadata || null } }
    },
    async get (filePath) {
      return files[filePath] || null
    },
    createReadStream (filePath, opts = {}) {
      const data = files[filePath] || Buffer.alloc(0)
      const start = opts.start || 0
      const end = opts.length == null ? data.length : start + opts.length
      return Readable.from([data.subarray(start, end)])
    },
    checkout () { return fakeDrive(files) },
    async * list () {}
  }
}

async function bootGatewayWithDrive (t, drive, gatewayOpts = {}, seededEntryExtras = {}) {
  const node = {
    config: { gatewayPublicOnlyPrivacyTier: true },
    seededApps: new Map([[KEY, { drive, blind: false, privacyTier: 'public', ...seededEntryExtras }]])
  }
  const gateway = new HyperGateway(node, gatewayOpts)
  const server = http.createServer((req, res) => gateway.handle(req, res))

  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })

  t.teardown(async () => {
    if (typeof server.closeAllConnections === 'function') {
      try { server.closeAllConnections() } catch (_) {}
    }
    await new Promise(resolve => server.close(resolve))
    await gateway.close()
  })

  return {
    gateway,
    port: server.address().port,
    path: (filePath = '/data.bin') => `/v1/hyper/${KEY}${filePath}`
  }
}

async function bootGateway (t, files = { '/data.bin': Buffer.from('0123456789abcdef') }, gatewayOpts = {}) {
  return bootGatewayWithDrive(t, fakeDrive(files), gatewayOpts)
}

async function bootExactGatewayWithEntry (
  t,
  entry,
  files = { '/index.html': Buffer.from('<h1>hello</h1>') },
  publicAppKeys = [KEY]
) {
  const drive = fakeDrive(files)
  const node = {
    config: { gatewayPublicOnlyPrivacyTier: false, hiveAppPublicKeys: publicAppKeys },
    seededApps: new Map([[KEY, { drive, ...entry }]])
  }
  const gateway = new HyperGateway(node)
  const server = http.createServer((req, res) => {
    const path = new URL(req.url, 'http://localhost').pathname
    gateway.handle(req, res, issueExactAppContext({
      appKey: KEY,
      path,
      byteMode: 'exact',
      publicAppKeys
    }))
  })

  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })

  t.teardown(async () => {
    if (typeof server.closeAllConnections === 'function') {
      try { server.closeAllConnections() } catch (_) {}
    }
    await new Promise(resolve => server.close(resolve))
    await gateway.close()
  })

  return { gateway, port: server.address().port }
}

function request (port, method, path, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      method,
      path,
      agent: false,
      headers: { Connection: 'close', ...headers }
    }, (res) => {
      const chunks = []
      res.on('data', chunk => chunks.push(chunk))
      res.on('end', () => {
        const raw = Buffer.concat(chunks)
        let body = raw
        try { body = JSON.parse(raw.toString('utf8')) } catch (_) {}
        resolve({ statusCode: res.statusCode, headers: res.headers, body, raw })
      })
    })
    req.on('error', reject)
    req.end()
  })
}

function expectPathLaneEdgeHeaders (t, res, label) {
  t.is(res.headers['cross-origin-opener-policy'], 'same-origin', `${label}: COOP isolates the browsing context`)
  t.is(res.headers['cross-origin-resource-policy'], 'cross-origin', `${label}: CORP matches the compatibility lane's ACAO:* posture`)
  t.is(res.headers['referrer-policy'], 'no-referrer', `${label}: Referrer-Policy never leaks the key/path being read`)
  t.absent(res.headers['content-security-policy'], `${label}: clearnet path lane carries no gateway CSP`)
  t.absent(res.headers['service-worker-allowed'], `${label}: no service-worker scope escape on the shared origin`)
}

test('path lane emits R6 edge headers + R7 canonical Link on every response class', async (t) => {
  const html = Buffer.from('<script src="/assets/app.js"></script>')
  const ctx = await bootGateway(t, {
    '/data.bin': Buffer.from('0123456789abcdef'),
    '/index.html': html
  })

  const file = await request(ctx.port, 'GET', ctx.path('/data.bin'))
  t.is(file.statusCode, 200)
  expectPathLaneEdgeHeaders(t, file, 'streamed file')
  t.is(file.headers.link, `<hive://${KEY}/data.bin>; rel="canonical"`, 'R7 upgrade hint names the canonical hive:// URI')

  const page = await request(ctx.port, 'GET', ctx.path('/index.html'))
  t.is(page.statusCode, 200)
  expectPathLaneEdgeHeaders(t, page, 'transformed HTML')
  t.is(page.headers.link, `<hive://${KEY}/index.html>; rel="canonical"`)

  const listing = await request(ctx.port, 'GET', ctx.path('/'))
  t.is(listing.statusCode, 200)
  expectPathLaneEdgeHeaders(t, listing, 'directory listing')
  t.is(listing.headers.link, `<hive://${KEY}/>; rel="canonical"`, 'directory URLs hint at the canonical drive root')

  const missing = await request(ctx.port, 'GET', ctx.path('/nope.txt'))
  t.is(missing.statusCode, 404)
  expectPathLaneEdgeHeaders(t, missing, 'JSON error')
  t.is(missing.headers.link, `<hive://${KEY}/nope.txt>; rel="canonical"`)

  const method = await request(ctx.port, 'POST', ctx.path('/data.bin'))
  t.is(method.statusCode, 405)
  expectPathLaneEdgeHeaders(t, method, 'method rejection')
  t.absent(method.headers.link, 'no canonical hint before a key was parsed')

  const traversal = await request(ctx.port, 'GET', ctx.path('/%252e%252e/etc/passwd'))
  t.is(traversal.statusCode, 403)
  t.absent(traversal.headers.link, 'rejected paths get no canonical hint')
  t.is(traversal.headers['cross-origin-opener-policy'], 'same-origin')

  const head = await request(ctx.port, 'HEAD', ctx.path('/data.bin'))
  t.is(head.statusCode, 200)
  expectPathLaneEdgeHeaders(t, head, 'HEAD')
  t.is(head.headers.link, `<hive://${KEY}/data.bin>; rel="canonical"`)
})

test('path-lane Link hint survives admission refusals that point at P2P', async (t) => {
  const ctx = await bootGatewayWithDrive(t, fakeDrive({ '/index.html': Buffer.from('<p>x</p>') }), {}, { blind: true })

  const res = await request(ctx.port, 'GET', ctx.path('/index.html'))
  t.is(res.statusCode, 403, 'blind content stays hard-403')
  t.is(res.body.blind, true)
  t.is(res.headers.link, `<hive://${KEY}/index.html>; rel="canonical"`,
    'the refusal and the upgrade hint agree: use the native P2P transport')
  expectPathLaneEdgeHeaders(t, res, 'blind refusal')
})

test('app-origin lane applies same-origin CORP and keeps its describedby Link', async (t) => {
  const ctx = await bootExactGatewayWithEntry(t, {
    blind: false,
    privacyTier: 'public',
    storageClass: 'persistent',
    availabilityClass: 'always-on'
  })

  const file = await request(ctx.port, 'GET', '/index.html')
  t.is(file.statusCode, 200)
  t.is(file.headers['cross-origin-opener-policy'], 'same-origin')
  t.is(file.headers['cross-origin-resource-policy'], 'same-origin',
    'isolated app origins deny no-cors subresource embedding — they never inherit compatibility CORS')
  t.is(file.headers['referrer-policy'], 'no-referrer')
  t.is(file.headers['origin-agent-cluster'], '?1', 'existing app-origin posture unchanged')
  t.absent(file.headers['content-security-policy'], 'clearnet app lane carries no gateway CSP')
  t.is(file.headers.link, `<hive://${KEY}/index.html>; rel="canonical", </.well-known/hiverelay-app.json>; rel="describedby"`,
    'the app lane keeps its existing canonical + describedby hint byte-for-byte')

  const missing = await request(ctx.port, 'GET', '/nope.txt')
  t.is(missing.statusCode, 404)
  t.is(missing.headers['cross-origin-resource-policy'], 'same-origin', 'generated app-lane errors carry the same R6 posture')

  const listing = await request(ctx.port, 'GET', '/')
  t.is(listing.statusCode, 200)
  t.is(listing.headers['cross-origin-resource-policy'], 'same-origin')
  t.is(listing.headers.link, `<hive://${KEY}/>; rel="canonical", </.well-known/hiverelay-app.json>; rel="describedby"`)
})

test('onion ingress carries the documented CSP default; clearnet does not', async (t) => {
  const ctx = await bootGateway(t, {
    '/data.bin': Buffer.from('0123456789abcdef'),
    '/index.html': Buffer.from('<script src="/assets/app.js"></script>')
  })

  const onion = await request(ctx.port, 'GET', ctx.path('/data.bin'), { Host: ONION_HOST })
  t.is(onion.statusCode, 200)
  t.is(onion.headers['content-security-policy'], ONION_READ_PLANE_CSP,
    'the exact documented restrictive default — pinned byte-for-byte')
  t.ok(onion.headers['content-security-policy'].includes("script-src 'none'"), 'no script execution on the read plane')
  t.ok(onion.headers['content-security-policy'].includes("connect-src 'none'"), 'no network beacons on the read plane')
  t.is(onion.headers['cross-origin-opener-policy'], 'same-origin')
  t.is(onion.headers['cross-origin-resource-policy'], 'cross-origin')
  t.is(onion.headers['referrer-policy'], 'no-referrer')
  t.is(onion.headers.link, `<hive://${KEY}/data.bin>; rel="canonical"`)
  t.absent(onion.headers['service-worker-allowed'])

  const onionPage = await request(ctx.port, 'GET', ctx.path('/index.html'), { Host: ONION_HOST })
  t.is(onionPage.statusCode, 200)
  t.is(onionPage.headers['content-security-policy'], ONION_READ_PLANE_CSP,
    'transformed HTML stays renderable (self + inline style) and scriptless')

  const onionError = await request(ctx.port, 'GET', ctx.path('/nope.txt'), { Host: `${ONION_HOST}:9200` })
  t.is(onionError.statusCode, 404)
  t.is(onionError.headers['content-security-policy'], ONION_READ_PLANE_CSP,
    'the policy covers generated errors too, port suffix and all')

  const clearnet = await request(ctx.port, 'GET', ctx.path('/data.bin'), { Host: 'gateway.example' })
  t.is(clearnet.statusCode, 200)
  t.absent(clearnet.headers['content-security-policy'], 'clearnet path lane stays CSP-free (legacy compatibility)')

  const lookalike = await request(ctx.port, 'GET', ctx.path('/data.bin'), { Host: 'not-really.onion.example.com' })
  t.absent(lookalike.headers['content-security-policy'], 'a .onion lookalike suffix is not onion ingress')

  const head = await request(ctx.port, 'HEAD', ctx.path('/data.bin'), { Host: ONION_HOST })
  t.is(head.statusCode, 200)
  t.is(head.headers['content-security-policy'], ONION_READ_PLANE_CSP, 'HEAD carries the same onion headers')
  t.is(head.raw.length, 0)
})

test('R3: a drive cannot set Service-Worker-Allowed through content or metadata', async (t) => {
  const swScript = Buffer.from('self.addEventListener("fetch", () => {})')
  swScript.metadata = { 'Service-Worker-Allowed': '/' }
  const html = Buffer.from('<script>navigator.serviceWorker.register("./sw.js", { scope: "/" })</script>')
  const ctx = await bootGateway(t, { '/sw.js': swScript, '/index.html': html })

  const sw = await request(ctx.port, 'GET', ctx.path('/sw.js'))
  t.is(sw.statusCode, 200)
  t.absent(sw.headers['service-worker-allowed'],
    'entry metadata never becomes a response header — a worker script cannot widen its scope past its key prefix')

  const page = await request(ctx.port, 'GET', ctx.path('/index.html'))
  t.is(page.statusCode, 200)
  t.absent(page.headers['service-worker-allowed'],
    'page content cannot smuggle the header either; registration stays capped at the script\'s own directory')
})

test('R3: the commit-time guard strips the header even if gateway code sets it', async (t) => {
  const server = http.createServer((req, res) => {
    guardPathLaneStatelessHeaders(res)
    res.setHeader(SERVICE_WORKER_ALLOWED_HEADER, '/')
    if (req.url === '/object') {
      res.writeHead(200, { [SERVICE_WORKER_ALLOWED_HEADER]: '/', 'X-Probe': 'object' })
    } else {
      res.writeHead(200, [SERVICE_WORKER_ALLOWED_HEADER, '/', 'X-Probe', 'array'])
    }
    res.end('ok')
  })
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  t.teardown(async () => {
    if (typeof server.closeAllConnections === 'function') {
      try { server.closeAllConnections() } catch (_) {}
    }
    await new Promise(resolve => server.close(resolve))
  })
  const port = server.address().port

  for (const path of ['/object', '/array']) {
    const res = await request(port, 'GET', path)
    t.is(res.statusCode, 200)
    t.absent(res.headers['service-worker-allowed'], `${path}: stripped from both the setHeader queue and the writeHead argument`)
    t.ok(res.headers['x-probe'], `${path}: unrelated headers pass through`)
    t.is(res.raw.toString(), 'ok')
  }
})

test('onion read-plane Host detection is strict', async (t) => {
  t.ok(isOnionReadPlaneHost(ONION_HOST))
  t.ok(isOnionReadPlaneHost(`${ONION_HOST}:80`), 'explicit port still counts')
  t.ok(isOnionReadPlaneHost(ONION_HOST.toUpperCase()), 'case-insensitive')
  t.ok(isOnionReadPlaneHost(`${ONION_HOST}.`), 'trailing root dot still counts (fail-safe toward the stricter policy)')
  t.absent(isOnionReadPlaneHost('not-really.onion.example.com'))
  t.absent(isOnionReadPlaneHost('onion.example.com'))
  t.absent(isOnionReadPlaneHost('gateway.example'))
  t.absent(isOnionReadPlaneHost('127.0.0.1:9100'))
  t.absent(isOnionReadPlaneHost('[::1]:9100'), 'IPv6 literal is never an onion name')
  t.absent(isOnionReadPlaneHost(''))
  t.absent(isOnionReadPlaneHost(undefined))
  t.absent(isOnionReadPlaneHost(null))
})

test('R7 path-lane Link builder percent-encodes like the app lane', async (t) => {
  t.is(buildHivePathLinkHeader(KEY, '/data.bin'), `<hive://${KEY}/data.bin>; rel="canonical"`)
  t.is(buildHivePathLinkHeader(KEY, '/'), `<hive://${KEY}/>; rel="canonical"`)
  t.is(
    buildHivePathLinkHeader(KEY, '/dir/some file.html'),
    `<hive://${KEY}/dir/some%20file.html>; rel="canonical"`,
    'paths are URI-encoded through the same URL machinery as the app lane'
  )
  t.is(buildHivePathLinkHeader(OTHER_KEY, '/data.bin'), `<hive://${OTHER_KEY}/data.bin>; rel="canonical"`)
})
