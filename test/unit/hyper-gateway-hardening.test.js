import test from 'brittle'
import http from 'http'
import { Readable } from 'stream'
import { HyperGateway } from 'p2p-hiverelay/gateway'

const KEY = 'a'.repeat(64)

function fakeDrive (files = {}) {
  return {
    closed: false,
    closing: false,
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
    async * list () {}
  }
}

async function bootGatewayWithDrive (t, drive) {
  const node = {
    config: { gatewayPublicOnlyPrivacyTier: true },
    seededApps: new Map([[KEY, { drive, blind: false, privacyTier: 'public' }]])
  }
  const gateway = new HyperGateway(node, {})
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

async function bootGateway (t, files = { '/data.bin': Buffer.from('0123456789abcdef') }) {
  return bootGatewayWithDrive(t, fakeDrive(files))
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
  t.is(listingHead.raw.length, 0, 'directory listing HEAD is header-only')
})
