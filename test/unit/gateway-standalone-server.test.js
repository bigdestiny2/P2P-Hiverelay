import test from 'brittle'
import http from 'http'
import { Readable } from 'stream'
import { mkdtemp, rm } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import {
  buildGatewaySeedErrorResponse,
  isStandaloneSeedRequestAuthorized,
  readGatewaySeedBody,
  startGateway,
  validateStandaloneGatewayOptions,
  validateGatewaySeedKey
} from 'p2p-hiverelay/gateway/server.js'

function reqFor (body, headers = {}) {
  const req = Readable.from(body === null || body === undefined ? [] : [body])
  req.method = 'POST'
  req.headers = {
    'content-type': 'application/json',
    ...(body === null || body === undefined ? {} : { 'content-length': String(Buffer.byteLength(body)) }),
    ...headers
  }
  return req
}

function request (port, method, path, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      method,
      path,
      agent: false,
      headers
    }, res => {
      const chunks = []
      res.on('data', chunk => chunks.push(chunk))
      res.on('end', () => {
        const raw = Buffer.concat(chunks)
        let payload = raw.toString()
        try { payload = JSON.parse(payload) } catch {}
        resolve({ statusCode: res.statusCode, headers: res.headers, payload })
      })
    })
    req.on('error', reject)
    req.end(body)
  })
}

async function rejects (t, promise, pattern, statusCode) {
  let err = null
  try {
    await promise
  } catch (e) {
    err = e
  }
  t.ok(err, 'expected rejection')
  t.ok(pattern.test(err.message), `message matches ${pattern}`)
  if (statusCode !== undefined) t.is(err.statusCode, statusCode)
  return err
}

test('standalone gateway seed body validates 64-hex keys', async (t) => {
  const key = 'A'.repeat(64)
  const body = await readGatewaySeedBody(reqFor(JSON.stringify({ key })))

  t.alike(body, { key: key.toLowerCase() })
  t.is(validateGatewaySeedKey(key), key.toLowerCase())
  t.exception(() => validateGatewaySeedKey('a'.repeat(63)), /64 hex/)
  t.exception(() => validateGatewaySeedKey('z'.repeat(64)), /64 hex/)
})

test('standalone gateway seed body rejects non-json media types before parsing', async (t) => {
  const err = await rejects(t, readGatewaySeedBody(reqFor('key=' + 'a'.repeat(64), {
    'content-type': 'application/x-www-form-urlencoded'
  })), /Content-Type must be application\/json/, 400)
  t.is(err.close, true, 'body-bearing media-type rejection should close')
})

test('standalone gateway seed body rejects oversized and non-object JSON bodies', async (t) => {
  await rejects(t, readGatewaySeedBody(reqFor(JSON.stringify({
    key: 'a'.repeat(64),
    pad: 'x'.repeat(4096)
  }))), /Request body too large/, 413)

  await rejects(t, readGatewaySeedBody(reqFor(JSON.stringify(['a'.repeat(64)]))), /JSON body must be an object/, 400)
  await rejects(t, readGatewaySeedBody(reqFor(JSON.stringify({ key: 'not-a-key' }))), /64 hex/, 400)
})

test('standalone gateway seed errors redact unexpected internals', async (t) => {
  const validation = await rejects(t, readGatewaySeedBody(reqFor('key=' + 'a'.repeat(64), {
    'content-type': 'application/x-www-form-urlencoded'
  })), /Content-Type must be application\/json/, 400)

  const exposed = buildGatewaySeedErrorResponse(validation)
  t.is(exposed.status, 400, 'validation status is preserved')
  t.alike(exposed.payload, { error: 'Content-Type must be application/json' })
  t.is(exposed.close, true, 'body-bearing media-type rejection keeps close signal')

  const internal = new Error('failed opening /private/data with HIVERELAY_API_KEY=secret')
  internal.statusCode = 503
  const redacted = buildGatewaySeedErrorResponse(internal)
  t.is(redacted.status, 500, 'unexpected internal status is collapsed')
  t.alike(redacted.payload, { error: 'Gateway seed failed' }, 'public error is generic')
  t.is(redacted.close, false, 'unexpected internal errors do not force close by default')
})

test('standalone gateway defaults to loopback with dynamic mutation disabled', (t) => {
  const config = validateStandaloneGatewayOptions({ port: 0 })
  t.is(config.host, '127.0.0.1')
  t.is(config.port, 0, 'ephemeral test port remains valid')
  t.is(config.allowDynamicSeed, false)
  t.is(config.seedToken, null)
  t.is(config.maxSeededDrives, 64, 'total drive count has a finite default')
  t.is(config.maxSeedRequestsPerMinute, 30, 'mutating request rate has a finite default')
  t.is(config.seedOperationTimeoutMs, 30_000, 'drive open has a finite default')
})

test('standalone gateway non-loopback dynamic seed requires complete bounded auth config', (t) => {
  t.exception(() => validateStandaloneGatewayOptions({
    host: '0.0.0.0',
    allowDynamicSeed: true
  }), /requires a configured seedToken/)
  t.exception(() => validateStandaloneGatewayOptions({
    host: '0.0.0.0',
    allowDynamicSeed: true,
    seedToken: 'short'
  }), /32 to 4096/)
  t.exception(() => validateStandaloneGatewayOptions({
    host: '0.0.0.0',
    allowDynamicSeed: true,
    seedToken: 's'.repeat(32),
    maxSeededDrives: 0
  }), /maxSeededDrives/)
  t.exception(() => validateStandaloneGatewayOptions({
    host: '0.0.0.0',
    allowDynamicSeed: true,
    seedToken: 's'.repeat(32),
    maxSeedRequestsPerMinute: 601
  }), /maxSeedRequestsPerMinute/)

  const config = validateStandaloneGatewayOptions({
    host: '0.0.0.0',
    allowDynamicSeed: true,
    seedToken: 's'.repeat(32),
    maxSeededDrives: 8,
    maxSeedRequestsPerMinute: 4
  })
  t.is(config.host, '0.0.0.0')
  t.is(config.maxSeededDrives, 8)
  t.is(config.maxSeedRequestsPerMinute, 4)
})

test('standalone gateway bearer authorization rejects missing, wrong, and duplicate headers', (t) => {
  const token = 'correct-token-'.padEnd(32, 'x')
  const req = value => ({
    headers: value == null ? {} : { authorization: value },
    headersDistinct: value == null ? {} : { authorization: [value] },
    rawHeaders: value == null ? [] : ['Authorization', value]
  })
  t.ok(isStandaloneSeedRequestAuthorized(req(`Bearer ${token}`), token))
  t.absent(isStandaloneSeedRequestAuthorized(req(null), token))
  t.absent(isStandaloneSeedRequestAuthorized(req('Basic nope'), token))
  t.absent(isStandaloneSeedRequestAuthorized(req('Bearer wrong-token-that-is-long-enough'), token))
  t.absent(isStandaloneSeedRequestAuthorized({
    headers: { authorization: `Bearer ${token}` },
    headersDistinct: { authorization: [`Bearer ${token}`, `Bearer ${token}`] },
    rawHeaders: ['Authorization', `Bearer ${token}`, 'Authorization', `Bearer ${token}`]
  }, token), 'duplicate authorization is never coalesced')
  t.ok(isStandaloneSeedRequestAuthorized(req(null), null), 'loopback opt-in may omit a token')
})

test('standalone gateway validates and bounds configured seed keys', (t) => {
  const key = 'A'.repeat(64)
  const config = validateStandaloneGatewayOptions({ seedKeys: [key, key.toLowerCase()] })
  t.alike(config.seedKeys, [key.toLowerCase()], 'duplicate keys collapse before opening sessions')
  t.exception(() => validateStandaloneGatewayOptions({
    seedKeys: [key, 'b'.repeat(64)],
    maxSeededDrives: 1
  }), /exceeds maxSeededDrives/)
  t.exception(() => validateStandaloneGatewayOptions({ host: 'example.com' }), /canonical IP address or localhost/)
  t.exception(() => validateStandaloneGatewayOptions({ port: '9100' }), /port must be an integer/)
})

test('standalone gateway live defaults bind loopback and hide dynamic seed', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'hiverelay-standalone-gateway-'))
  let gateway = null
  t.teardown(async () => {
    if (gateway) await gateway.close()
    await rm(dir, { recursive: true, force: true })
  })

  gateway = await startGateway({
    port: 0,
    storage: dir,
    enableDiscovery: false,
    seedOperationTimeoutMs: 1000
  })
  const address = gateway.server.address()
  t.is(address.address, '127.0.0.1')
  t.is(gateway.config.allowDynamicSeed, false)

  const health = await request(address.port, 'GET', '/health')
  t.is(health.statusCode, 200)
  t.is(health.payload.dynamicSeedEnabled, false)

  const body = JSON.stringify({ key: 'a'.repeat(64) })
  const seed = await request(address.port, 'POST', '/v1/seed', body, {
    'Content-Type': 'application/json',
    'Content-Length': String(Buffer.byteLength(body))
  })
  t.is(seed.statusCode, 404, 'mutating route is absent without explicit opt-in')
  t.is(seed.headers['access-control-allow-methods'], 'GET, HEAD, OPTIONS', 'CORS never advertises mutation')
  t.is(gateway.seededDrives.size, 0)

  await Promise.all([gateway.close(), gateway.close()])
  t.absent(gateway.server.listening, 'concurrent close is idempotent')
})

test('standalone gateway live opt-in enforces a configured bearer before opening drives', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'hiverelay-standalone-gateway-auth-'))
  const token = 'standalone-secret-'.padEnd(32, 'x')
  let gateway = null
  t.teardown(async () => {
    if (gateway) await gateway.close()
    await rm(dir, { recursive: true, force: true })
  })
  gateway = await startGateway({
    port: 0,
    storage: dir,
    enableDiscovery: false,
    allowDynamicSeed: true,
    seedToken: token,
    seedOperationTimeoutMs: 1000
  })
  const body = JSON.stringify({ key: 'a'.repeat(64) })
  const headers = {
    'Content-Type': 'application/json',
    'Content-Length': String(Buffer.byteLength(body))
  }
  const missing = await request(gateway.server.address().port, 'POST', '/v1/seed', body, headers)
  t.is(missing.statusCode, 401)
  t.ok(/^Bearer /.test(missing.headers['www-authenticate']))
  const wrong = await request(gateway.server.address().port, 'POST', '/v1/seed', body, {
    ...headers,
    Authorization: 'Bearer wrong-token-that-is-long-enough'
  })
  t.is(wrong.statusCode, 401)
  t.is(gateway.seededDrives.size, 0, 'authentication fails before drive/session creation')
})
