import test from 'brittle'
import http from 'http'
import { Readable } from 'stream'
import { HyperGateway } from 'p2p-hiverelay/gateway'
import { issueExactAppContext } from '../../packages/core/gateway/exact-app-context.js'

const KEY = 'a'.repeat(64)

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
      return { value: { blob: { byteLength: data.length } } }
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

async function bootGatewayWithDrive (t, drive, gatewayOpts = {}) {
  const node = {
    config: { gatewayPublicOnlyPrivacyTier: true },
    seededApps: new Map([[KEY, { drive, blind: false, privacyTier: 'public' }]])
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
  publicAppKeys = [KEY],
  seeded = true,
  gatewayOpts = {}
) {
  const drive = fakeDrive(files)
  const node = {
    config: { gatewayPublicOnlyPrivacyTier: false, hiveAppPublicKeys: publicAppKeys },
    seededApps: seeded ? new Map([[KEY, { drive, ...entry }]]) : new Map()
  }
  const gateway = new HyperGateway(node, gatewayOpts)
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

function requestAllowAbort (port, path) {
  return new Promise((resolve, reject) => {
    let settled = false
    const finish = value => {
      if (settled) return
      settled = true
      resolve(value)
    }
    const req = http.get({ hostname: '127.0.0.1', port, path, agent: false }, res => {
      const chunks = []
      res.on('data', chunk => chunks.push(chunk))
      res.on('end', () => finish({
        statusCode: res.statusCode,
        raw: Buffer.concat(chunks),
        aborted: false
      }))
      res.on('aborted', () => finish({
        statusCode: res.statusCode,
        raw: Buffer.concat(chunks),
        aborted: true
      }))
      res.on('error', () => {})
    })
    req.on('error', err => {
      if (err.code === 'ECONNRESET') finish({ statusCode: null, raw: Buffer.alloc(0), aborted: true })
      else reject(err)
    })
  })
}

test('HyperGateway - rejects unsupported methods before serving content', async (t) => {
  const ctx = await bootGateway(t)

  const res = await request(ctx.port, 'POST', ctx.path())
  t.is(res.statusCode, 405, 'POST is rejected')
  t.is(res.headers.allow, 'GET, HEAD', 'allowed methods are advertised')
  t.is(res.headers['content-type'], 'application/json; charset=utf-8', 'JSON errors have explicit content type')
  t.is(res.headers['x-content-type-options'], 'nosniff', 'JSON errors disable content sniffing')
  t.is(res.headers['cache-control'], 'no-store, max-age=0', 'JSON errors are not cached')
  t.is(res.body.error, 'Method Not Allowed', 'JSON error returned')
})

test('HyperGateway - public drive failures are redacted and use hardened JSON errors', async (t) => {
  const secretMessage = 'drive.entry leaked /private/data HIVERELAY_API_KEY=secret'
  const drive = fakeDrive()
  drive.entry = async () => {
    throw new Error(secretMessage)
  }
  const ctx = await bootGatewayWithDrive(t, drive)
  const events = []
  ctx.gateway.on('drive-error', event => events.push(event))

  const res = await request(ctx.port, 'GET', ctx.path())

  t.is(res.statusCode, 502, 'unexpected drive failure returns gateway error')
  t.is(res.headers['content-type'], 'application/json; charset=utf-8', 'error is JSON')
  t.is(res.headers['x-content-type-options'], 'nosniff', 'error disables content sniffing')
  t.is(res.headers['cache-control'], 'no-store, max-age=0', 'error is not cached')
  t.is(res.body.error, 'Gateway read failed', 'public error is stable and generic')
  t.absent(res.raw.toString('utf8').includes('HIVERELAY_API_KEY'), 'secret marker is not in response body')
  t.absent(res.raw.toString('utf8').includes('/private/data'), 'path detail is not in response body')
  t.ok(events.some(event => event.error === secretMessage), 'internal event keeps operator diagnostics')
})

test('HyperGateway - successful drive timeouts clear their timer handles', async (t) => {
  const gateway = new HyperGateway({}, {})
  const setTimeoutOriginal = globalThis.setTimeout
  const clearTimeoutOriginal = globalThis.clearTimeout
  let created = 0
  let cleared = 0
  let unrefed = 0

  const fakeTimer = {
    unref () {
      unrefed++
    }
  }

  globalThis.setTimeout = function () {
    created++
    return fakeTimer
  }
  globalThis.clearTimeout = function (timer) {
    if (timer === fakeTimer) cleared++
  }

  try {
    const value = await gateway._withTimeout(Promise.resolve('ok'), 30_000, 'fast-op')
    t.is(value, 'ok', 'successful promise result is preserved')
    t.is(created, 1, 'timeout was created')
    t.is(cleared, 1, 'successful promise cleared timeout')
    t.is(unrefed, 1, 'timeout was unrefed')
  } finally {
    globalThis.setTimeout = setTimeoutOriginal
    globalThis.clearTimeout = clearTimeoutOriginal
  }
})

test('HyperGateway - malformed path encoding returns 400 instead of surfacing a 500', async (t) => {
  const ctx = await bootGateway(t)

  const direct = await request(ctx.port, 'GET', ctx.path('/%E0%A4%A'))
  t.is(direct.statusCode, 400, 'malformed direct percent encoding is a client error')
  t.is(direct.body.error, 'Malformed path encoding', 'direct encoding error is clear')

  const double = await request(ctx.port, 'GET', ctx.path('/%25E0%25A4%25A'))
  t.is(double.statusCode, 400, 'malformed double-decoded percent encoding is a client error')
  t.is(double.body.error, 'Malformed path encoding', 'double encoding error is clear')
})

test('HyperGateway - double-encoded traversal remains forbidden', async (t) => {
  const ctx = await bootGateway(t)

  const res = await request(ctx.port, 'GET', ctx.path('/%252e%252e/etc/passwd'))
  t.is(res.statusCode, 403, 'double-encoded traversal is rejected')
  t.ok(/path traversal/.test(res.body.error), 'traversal error returned')
})

test('HyperGateway - byte ranges reject permissive JavaScript number syntax', async (t) => {
  const ctx = await bootGateway(t)

  for (const range of ['bytes=1e1-', 'bytes=+1-3', 'bytes=1.5-3', 'bytes=0-1.5']) {
    const res = await request(ctx.port, 'GET', ctx.path(), { Range: range })
    t.is(res.statusCode, 416, `${range} rejected`)
    t.is(res.headers['content-range'], 'bytes */16', `${range} reports unsatisfied range`)
  }

  const valid = await request(ctx.port, 'GET', ctx.path(), { Range: 'bytes=10-' })
  t.is(valid.statusCode, 206, 'ordinary decimal range still works')
  t.is(valid.headers['content-range'], 'bytes 10-15/16', 'valid content-range returned')
  t.is(valid.raw.toString(), 'abcdef', 'valid range body returned')
})

test('HyperGateway - unsupported range units and multi-ranges are ignored as full responses', async (t) => {
  const ctx = await bootGateway(t)

  const unit = await request(ctx.port, 'GET', ctx.path(), { Range: 'items=0-2' })
  t.is(unit.statusCode, 200, 'unknown range unit is ignored')
  t.is(unit.raw.toString(), '0123456789abcdef', 'unknown unit returns full body')

  const multi = await request(ctx.port, 'GET', ctx.path(), { Range: 'bytes=0-1,4-5' })
  t.is(multi.statusCode, 200, 'multi-range is ignored')
  t.is(multi.raw.toString(), '0123456789abcdef', 'multi-range returns full body')
})

test('HyperGateway - oversized objects require one bounded range before headers', async (t) => {
  const data = Buffer.from('0123456789abcdef')
  let streamCalls = 0
  const drive = fakeDrive({ '/data.bin': data })
  const createReadStream = drive.createReadStream.bind(drive)
  drive.createReadStream = (...args) => {
    streamCalls++
    return createReadStream(...args)
  }
  const ctx = await bootGatewayWithDrive(t, drive, { maxResponseBytes: 8 })

  const full = await request(ctx.port, 'GET', ctx.path())
  t.is(full.statusCode, 413, 'oversized full GET is rejected')
  t.is(full.body.maxResponseBytes, 8)

  const head = await request(ctx.port, 'HEAD', ctx.path())
  t.is(head.statusCode, 413, 'oversized HEAD cannot advertise an unservable representation')

  const bounded = await request(ctx.port, 'GET', ctx.path(), { Range: 'bytes=4-11' })
  t.is(bounded.statusCode, 206)
  t.is(bounded.raw.toString(), '456789ab', 'bounded single range is served')

  const largeRange = await request(ctx.port, 'GET', ctx.path(), { Range: 'bytes=0-8' })
  t.is(largeRange.statusCode, 416, 'oversized single range is rejected')
  t.is(largeRange.headers['content-range'], 'bytes */16')

  const multi = await request(ctx.port, 'GET', ctx.path(), { Range: 'bytes=0-1,4-5' })
  t.is(multi.statusCode, 416, 'multi-range cannot trigger an oversized 200 fallback')

  const unknown = await request(ctx.port, 'GET', ctx.path(), { Range: 'items=0-1' })
  t.is(unknown.statusCode, 416, 'unknown range unit cannot trigger an oversized 200 fallback')
  t.is(streamCalls, 1, 'only the admitted bounded range opens a body stream')
})

test('HyperGateway - response and legacy transform ceilings are finite', async (t) => {
  t.exception(() => new HyperGateway({}, { maxResponseBytes: null }), /finite and non-null/)
  t.exception(() => new HyperGateway({}, { maxResponseBytes: 8, maxTransformBytes: 9 }), /maxTransformBytes/)

  const html = Buffer.from('<script src="/x"></script>')
  let getCalls = 0
  const drive = fakeDrive({ '/index.html': html })
  const get = drive.get.bind(drive)
  drive.get = async (...args) => { getCalls++; return get(...args) }
  const ctx = await bootGatewayWithDrive(t, drive, {
    maxResponseBytes: 32,
    maxTransformBytes: 8
  })
  const result = await request(ctx.port, 'GET', ctx.path('/index.html'))
  t.is(result.statusCode, 413)
  t.is(result.body.maxResponseBytes, 8)
  t.is(getCalls, 0, 'oversized transform input is rejected before buffering')
})

test('HyperGateway - stream output cannot exceed or undershoot declared metadata length', async (t) => {
  const overrunDrive = fakeDrive({ '/data.bin': Buffer.from('ignored') })
  overrunDrive.entry = async () => ({ value: { blob: { byteLength: 4 } } })
  overrunDrive.createReadStream = () => Readable.from([Buffer.from('123456')])
  const overrun = await bootGatewayWithDrive(t, overrunDrive, { maxResponseBytes: 8 })
  const overrunResult = await requestAllowAbort(overrun.port, overrun.path())
  t.ok(overrunResult.statusCode === null || overrunResult.statusCode === 200, 'connection closes before or with admitted headers')
  t.ok(overrunResult.aborted, 'metadata overrun aborts the response')
  t.ok(overrunResult.raw.byteLength <= 4, 'no bytes beyond Content-Length reach the client')
  t.is(overrun.gateway.getStats().totalBytesServed, 0, 'failed stream is not counted as served')

  const underrunDrive = fakeDrive({ '/data.bin': Buffer.from('ignored') })
  underrunDrive.entry = async () => ({ value: { blob: { byteLength: 4 } } })
  underrunDrive.createReadStream = () => Readable.from([Buffer.from('12')])
  const underrun = await bootGatewayWithDrive(t, underrunDrive, { maxResponseBytes: 8 })
  const underrunResult = await requestAllowAbort(underrun.port, underrun.path())
  t.ok(underrunResult.aborted, 'metadata underrun aborts instead of hanging a keep-alive socket')
  t.is(underrunResult.raw.toString(), '12')
  t.is(underrun.gateway.getStats().totalBytesServed, 0)
})

test('HyperGateway - HEAD preserves range headers without serving bytes', async (t) => {
  const ctx = await bootGateway(t)

  const res = await request(ctx.port, 'HEAD', ctx.path(), { Range: 'bytes=2-5' })

  t.is(res.statusCode, 206, 'HEAD range request returns partial-content headers')
  t.is(res.headers['accept-ranges'], 'bytes', 'range support is advertised')
  t.is(res.headers['content-range'], 'bytes 2-5/16', 'content range is preserved')
  t.is(res.headers['content-length'], '4', 'partial content length is preserved')
  t.is(res.raw.length, 0, 'HEAD response has no body')
  t.is(ctx.gateway.getStats().totalBytesServed, 0, 'HEAD does not count bytes as served')
})

test('HyperGateway - HEAD on rewritten HTML and directory listings is header-only', async (t) => {
  const html = Buffer.from('<script src="/assets/app.js"></script>')
  const rewritten = Buffer.from('<script src="./assets/app.js"></script>')
  const ctx = await bootGateway(t, { '/index.html': html })

  const htmlHead = await request(ctx.port, 'HEAD', ctx.path('/index.html'))
  t.is(htmlHead.statusCode, 200, 'HTML HEAD succeeds')
  t.is(htmlHead.headers['content-type'], 'text/html; charset=utf-8', 'HTML content type is preserved')
  t.is(htmlHead.headers['content-length'], String(rewritten.length), 'HTML HEAD reports rewritten length')
  t.is(htmlHead.raw.length, 0, 'HTML HEAD does not send the rewritten body')
  t.is(ctx.gateway.getStats().totalBytesServed, 0, 'HTML HEAD does not count bytes')

  const listingCtx = await bootGateway(t, {})
  const listingHead = await request(listingCtx.port, 'HEAD', listingCtx.path('/'))
  t.is(listingHead.statusCode, 200, 'directory listing HEAD succeeds')
  t.is(listingHead.headers['content-type'], 'application/json; charset=utf-8', 'directory listing stays JSON')
  t.is(listingHead.headers['x-hyper-key'], KEY, 'directory listing keeps gateway metadata')
  t.absent(listingHead.headers['x-hive-app-key'], 'legacy path listing does not claim an app origin')
  t.absent(listingHead.headers['x-hive-byte-mode'], 'legacy path listing has no app-origin representation marker')
  t.absent(listingHead.headers['origin-agent-cluster'], 'legacy path listing keeps compatibility origin semantics')
  t.absent(listingHead.headers.vary, 'legacy path listing does not vary on Host')
  t.is(listingHead.raw.length, 0, 'directory listing HEAD is header-only')
})

test('HyperGateway - exact app mode serves byte-identical HTML and ranges', async (t) => {
  const html = Buffer.from('\ufeff<!doctype html>\r\n<script src="/assets/app.js"></script>\r\n')
  const ctx = await bootExactGatewayWithEntry(t, {
    blind: false,
    privacyTier: 'public',
    storageClass: 'persistent',
    availabilityClass: 'always-on'
  }, { '/index.html': html })

  const full = await request(ctx.port, 'GET', '/index.html')
  t.is(full.statusCode, 200)
  t.ok(full.raw.equals(html), 'HTML bytes are not rewritten or normalized')
  t.is(full.headers['content-length'], String(html.length), 'stored byte length is preserved')
  t.is(full.headers['x-hive-app-key'], KEY)
  t.is(full.headers['x-hive-byte-mode'], 'exact')
  t.is(full.headers.vary, 'Host', 'shared caches are told the Host selects content')
  t.is(full.headers['cache-control'], 'no-store, max-age=0', 'mutable exact-host URLs are not shared-cacheable in Phase 1')
  t.is(full.headers['origin-agent-cluster'], '?1', 'app requests an origin-keyed agent cluster')
  t.is(full.headers.link, `<hive://${KEY}/index.html>; rel="canonical", </.well-known/hiverelay-app.json>; rel="describedby"`)
  t.absent(full.headers['set-cookie'], 'gateway response emits no cookie; parent-domain isolation still requires a Public Suffix boundary')

  const range = await request(ctx.port, 'GET', '/index.html', { Range: 'bytes=0-7' })
  t.is(range.statusCode, 206, 'exact HTML supports byte ranges')
  t.ok(range.raw.equals(html.subarray(0, 8)), 'range uses original stored bytes')

  for (const unsupported of ['items=0-7', 'bytes=0-1,4-7']) {
    const rejected = await request(ctx.port, 'GET', '/index.html', { Range: unsupported })
    t.is(rejected.statusCode, 416, `${unsupported} is rejected in exact-byte mode`)
    t.is(rejected.headers['content-range'], `bytes */${html.length}`)
  }

  const head = await request(ctx.port, 'HEAD', '/index.html')
  t.is(head.statusCode, 200)
  t.is(head.headers['content-length'], String(html.length))
  t.is(head.raw.length, 0)
})

test('HyperGateway - exact app directory listings retain app-origin headers', async (t) => {
  const ctx = await bootExactGatewayWithEntry(t, {
    blind: false,
    privacyTier: 'public',
    storageClass: 'persistent',
    availabilityClass: 'always-on'
  }, {})

  const res = await request(ctx.port, 'GET', '/')
  t.is(res.statusCode, 200)
  t.is(res.headers['x-hive-app-key'], KEY)
  t.is(res.headers['x-hive-byte-mode'], 'generated')
  t.is(res.headers['origin-agent-cluster'], '?1')
  t.is(res.headers.vary, 'Host')
  t.is(res.headers['cache-control'], 'no-store, max-age=0')
  t.is(res.headers.link, `<hive://${KEY}/>; rel="canonical", </.well-known/hiverelay-app.json>; rel="describedby"`)
})

test('HyperGateway - exact context issuer is not public and forged contexts never reach drives', async (t) => {
  await t.exception(async () => import('p2p-hiverelay/gateway/exact-app-context.js'),
    /not exported|ERR_PACKAGE_PATH_NOT_EXPORTED/)
  const drive = fakeDrive({ '/index.html': Buffer.from('secret') })
  let driveReads = 0
  drive.entry = async () => { driveReads++; return { value: { blob: { byteLength: 6 } } } }
  const gateway = new HyperGateway({
    config: { gatewayPublicOnlyPrivacyTier: false, hiveAppPublicKeys: [KEY] },
    seededApps: new Map([[KEY, { drive, blind: false, privacyTier: 'public' }]])
  })
  const forged = [
    { appKey: KEY, path: '/index.html', byteMode: 'exact', publicAppKeys: [KEY] },
    Object.freeze({ appKey: KEY, path: '/index.html', byteMode: 'exact', publicAppKeys: [KEY] }),
    { appKey: KEY, path: '/index.html', byteMode: 'generated', publicAppKeys: [KEY] }
  ]
  let index = 0
  const server = http.createServer((req, res) => gateway.handle(req, res, forged[index++]))
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  t.teardown(async () => {
    await new Promise(resolve => server.close(resolve))
    await gateway.close()
  })
  for (const context of forged) {
    const response = await request(server.address().port, 'GET', '/')
    t.is(response.statusCode, 403, context.byteMode)
    t.is(response.body.error, 'Gateway request context is not authorized')
    t.absent(response.headers['x-hive-app-key'])
  }
  t.is(driveReads, 0, 'forged contexts never reach drive admission or headers')
})

test('HyperGateway - legacy path mode keeps explicit transformed HTML compatibility', async (t) => {
  const html = Buffer.from('<script src="/assets/app.js"></script>')
  const ctx = await bootGateway(t, { '/index.html': html })

  const res = await request(ctx.port, 'GET', ctx.path('/index.html'))
  t.is(res.statusCode, 200)
  t.is(res.raw.toString(), '<script src="./assets/app.js"></script>')
  t.is(res.headers['x-hive-byte-mode'], 'transformed')
  t.absent(res.headers['x-hive-app-key'], 'legacy path response does not claim app-origin mode')
})

test('HyperGateway - RelayNode authority never opens placeholders and serves only proved immutable versions', async (t) => {
  const oldBytes = Buffer.from('proved-version-bytes')
  let updateCalls = 0
  let checkoutCalls = 0
  let liveReads = 0
  let leaseReleases = 0
  let leaseAcquisitions = 0
  let wrongLease = false
  const snapshot = fakeDrive({ '/data.bin': oldBytes })
  snapshot.version = 7
  const liveDrive = {
    ...fakeDrive({ '/data.bin': Buffer.from('unproved-new-head') }),
    version: 99,
    async update () { updateCalls++ },
    checkout (version) {
      checkoutCalls++
      t.is(version, 7, 'only the persisted storage-proved version is checked out')
      return snapshot
    },
    createReadStream () {
      liveReads++
      throw new Error('mutable live head must never be read')
    }
  }
  const entry = {
    drive: null,
    blind: false,
    privacyTier: 'public',
    storageClass: 'persistent',
    availabilityClass: 'always-on',
    storageProvedDriveVersion: 7
  }
  const node = {
    config: { gatewayPublicOnlyPrivacyTier: false, hiveAppPublicKeys: [KEY] },
    seededApps: new Map([[KEY, entry]]),
    appLifecycle: {
      acquireDriveReadLease (key) {
        t.is(key, KEY)
        if (!entry.drive) return null
        leaseAcquisitions++
        if (wrongLease) return { drive: {}, release: () => { leaseReleases++ } }
        return { drive: entry.drive, release: () => { leaseReleases++ } }
      }
    }
  }
  const gateway = new HyperGateway(node, { requireLifecycleDriveAuthority: true })
  const server = http.createServer((req, res) => {
    const exact = req.url.startsWith('/exact/')
    const version = exact ? Number(req.url.slice('/exact/'.length)) : null
    return gateway.handle(req, res, exact
      ? issueExactAppContext({
        appKey: KEY,
        path: '/data.bin',
        publicAppKeys: [KEY],
        driveVersion: version
      })
      : null)
  })
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  t.teardown(async () => {
    await new Promise(resolve => server.close(resolve))
    await gateway.close()
  })

  const placeholder = await request(server.address().port, 'GET', `/v1/hyper/${KEY}/data.bin`)
  t.is(placeholder.statusCode, 404, 'startup placeholder is bounded unavailable')
  t.is(checkoutCalls, 0, 'placeholder never opens or checks out a drive')

  entry.drive = liveDrive
  entry.storageProvedDriveVersion = 0
  const zeroLegacy = await request(server.address().port, 'GET', `/v1/hyper/${KEY}/data.bin`)
  t.is(zeroLegacy.statusCode, 404, 'zero is not a persisted storage proof')
  const zeroExact = await request(server.address().port, 'GET', '/exact/0')
  t.is(zeroExact.statusCode, 404, 'zero cannot authorize an exact snapshot')
  t.is(leaseAcquisitions, 0, 'zero proof is rejected before lifecycle acquisition')
  entry.storageProvedDriveVersion = 7
  const legacy = await request(server.address().port, 'GET', `/v1/hyper/${KEY}/data.bin`)
  t.is(legacy.statusCode, 200)
  t.ok(legacy.raw.equals(oldBytes), 'legacy RelayNode path serves the persisted proved snapshot')

  const exact = await request(server.address().port, 'GET', '/exact/7')
  t.is(exact.statusCode, 200)
  t.ok(exact.raw.equals(oldBytes), 'new oversized head cannot change signed exact bytes')

  const mismatched = await request(server.address().port, 'GET', '/exact/6')
  t.is(mismatched.statusCode, 403, 'release/storage authority mismatch fails before drive acquisition')
  wrongLease = true
  const substituted = await request(server.address().port, 'GET', `/v1/hyper/${KEY}/data.bin`)
  t.is(substituted.statusCode, 404, 'a lease for a substituted drive is rejected')
  t.is(updateCalls, 0, 'RelayNode routes never fetch or advance an unproved head')
  t.is(liveReads, 0, 'no new-head block is pulled')
  t.is(checkoutCalls, 2, 'legacy and exact reads share the same proved immutable authority')
  t.is(leaseAcquisitions, 3, 'only positive proofs reach lifecycle acquisition')
  t.is(leaseReleases, 3, 'successful and rejected lifecycle leases are released')
})

test('HyperGateway - exact app admission requires local approval and public metadata', async (t) => {
  const base = {
    blind: false,
    privacyTier: 'public',
    storageClass: 'persistent',
    availabilityClass: 'always-on'
  }

  const notApproved = await bootExactGatewayWithEntry(t, base, undefined, [])
  const notApprovedRes = await request(notApproved.port, 'GET', '/index.html')
  t.is(notApprovedRes.statusCode, 403, 'registry metadata alone cannot publish an app')
  t.is(notApprovedRes.body.error, 'App unavailable through public Hive gateway')
  t.is(notApprovedRes.headers.vary, 'Host', 'exact-host denials remain isolated in shared caches')
  t.is(notApprovedRes.headers['cache-control'], 'no-store, max-age=0')
  t.is(notApprovedRes.headers['x-hive-byte-mode'], 'generated')

  const unseeded = await bootExactGatewayWithEntry(t, base, undefined, [], false)
  const unseededRes = await request(unseeded.port, 'GET', '/index.html')
  t.alike({ statusCode: unseededRes.statusCode, body: unseededRes.body }, {
    statusCode: notApprovedRes.statusCode,
    body: notApprovedRes.body
  }, 'unknown and locally seeded private keys are indistinguishable on exact hosts')

  const privateEntry = await bootExactGatewayWithEntry(t, { ...base, privacyTier: 'p2p-only' })
  const privateRes = await request(privateEntry.port, 'GET', '/index.html')
  t.is(privateRes.statusCode, 403, 'operator approval cannot override private metadata')
  t.is(privateRes.body.error, 'App unavailable through public Hive gateway')

  const allowed = await bootExactGatewayWithEntry(t, base)
  const allowedRes = await request(allowed.port, 'GET', '/index.html')
  t.is(allowedRes.statusCode, 200, 'operator-approved public persistent entry accepted')
})

test('HyperGateway - exact generated errors preserve provenance for missing and oversized bytes', async (t) => {
  const entry = {
    blind: false,
    privacyTier: 'public',
    storageClass: 'persistent',
    availabilityClass: 'always-on'
  }
  const missing = await bootExactGatewayWithEntry(t, entry)
  const notFound = await request(missing.port, 'GET', '/missing.bin')
  t.is(notFound.statusCode, 404)
  t.is(notFound.headers['x-hive-byte-mode'], 'generated')

  const oversized = await bootExactGatewayWithEntry(
    t,
    entry,
    { '/large.bin': Buffer.alloc(9, 1) },
    [KEY],
    true,
    { maxResponseBytes: 8, maxTransformBytes: 8 }
  )
  const full = await request(oversized.port, 'GET', '/large.bin')
  t.is(full.statusCode, 413)
  t.is(full.headers['x-hive-byte-mode'], 'generated')
  const range = await request(oversized.port, 'GET', '/large.bin', { Range: 'bytes=0-8' })
  t.is(range.statusCode, 416)
  t.is(range.headers['x-hive-byte-mode'], 'generated')
  const head = await request(oversized.port, 'HEAD', '/large.bin')
  t.is(head.statusCode, 413)
  t.is(head.headers['x-hive-byte-mode'], 'generated')
  t.is(head.raw.length, 0)
})

test('HyperGateway - exact policy denials do not expose internal policy reasons', async (t) => {
  const ctx = await bootExactGatewayWithEntry(t, {
    blind: false,
    privacyTier: 'public',
    storageClass: 'persistent',
    availabilityClass: 'always-on'
  })
  ctx.gateway.node.policyGuard = {
    check () { return { allowed: false, reason: 'secret-operator-rule-name' } }
  }

  const denied = await request(ctx.port, 'GET', '/index.html')
  t.is(denied.statusCode, 403)
  t.is(denied.body.error, 'App unavailable through public Hive gateway')
  t.absent(denied.raw.toString().includes('secret-operator-rule-name'))
  t.is(denied.headers['cache-control'], 'no-store, max-age=0')
})
