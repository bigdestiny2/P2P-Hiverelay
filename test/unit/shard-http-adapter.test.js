import test from 'brittle'
import { EventEmitter } from 'node:events'
import { Readable } from 'node:stream'
import {
  handleShardHttp,
  resolveShardRoute,
  createShardHttpState
} from 'p2p-hiveservices/builtin/shard-store/http-adapter.js'

const HASH = 'a'.repeat(64)

// The rate-limit gate runs before any service call, so a minimal fake service
// that reports "not held" is enough to exercise it: allowed requests fall
// through to 404, throttled ones short-circuit to 429.
const fakeService = { async has () { return { present: false, byteLength: 0 } } }

function fakeReq (method, url, headers = {}) {
  const req = Readable.from([])
  req.method = method
  req.url = url
  req.headers = { ...headers }
  req.socket = { remoteAddress: headers.remoteAddress || '203.0.113.7' }
  return req
}

function fakeRes () {
  const res = new EventEmitter()
  res.statusCode = null
  res.body = ''
  res.ended = false
  res.writeHead = function writeHead (status) { this.statusCode = status; return this }
  res.end = function end (body = '') { this.body = String(body); this.ended = true; return this }
  res.write = function write () { return true }
  return res
}

test('shard http adapter: enforces per-IP rate limiting (v0.21.1 audit)', async (t) => {
  const state = createShardHttpState()
  const rateLimit = { windowMs: 60000, max: 3 }
  const route = resolveShardRoute('HEAD', '/api/v1/shard/' + HASH)
  t.ok(route && route.kind === 'head', 'HEAD route resolves')

  const codes = []
  for (let i = 0; i < 5; i++) {
    const res = fakeRes()
    await handleShardHttp(fakeService, route, fakeReq('HEAD', '/api/v1/shard/' + HASH), res, { state, rateLimit })
    codes.push(res.statusCode)
  }
  // First `max` requests reach the service (404 = not held); the rest are 429.
  t.alike(codes, [404, 404, 404, 429, 429], 'requests past the cap are throttled')
})

test('shard http adapter: rate-limit buckets are keyed per-IP', async (t) => {
  const state = createShardHttpState()
  const rateLimit = { windowMs: 60000, max: 1 }
  const route = resolveShardRoute('HEAD', '/api/v1/shard/' + HASH)

  const a1 = fakeRes()
  await handleShardHttp(fakeService, route, fakeReq('HEAD', '/h', { remoteAddress: '198.51.100.1' }), a1, { state, rateLimit })
  const a2 = fakeRes()
  await handleShardHttp(fakeService, route, fakeReq('HEAD', '/h', { remoteAddress: '198.51.100.1' }), a2, { state, rateLimit })
  const b1 = fakeRes()
  await handleShardHttp(fakeService, route, fakeReq('HEAD', '/h', { remoteAddress: '198.51.100.2' }), b1, { state, rateLimit })

  t.is(a1.statusCode, 404, 'first request from IP A is allowed')
  t.is(a2.statusCode, 429, 'second request from IP A is throttled')
  t.is(b1.statusCode, 404, 'IP B has its own bucket')
})

test('shard http adapter: rate limiting honors X-Forwarded-For only under trustProxy', async (t) => {
  const state = createShardHttpState()
  const rateLimit = { windowMs: 60000, max: 1 }
  const route = resolveShardRoute('HEAD', '/api/v1/shard/' + HASH)

  // Same socket IP, different XFF. Without trustProxy the XFF is ignored, so
  // both count against the socket bucket (second is throttled).
  const r1 = fakeRes()
  await handleShardHttp(fakeService, route, fakeReq('HEAD', '/h', { remoteAddress: '10.0.0.1', 'x-forwarded-for': '1.1.1.1' }), r1, { state, rateLimit })
  const r2 = fakeRes()
  await handleShardHttp(fakeService, route, fakeReq('HEAD', '/h', { remoteAddress: '10.0.0.1', 'x-forwarded-for': '2.2.2.2' }), r2, { state, rateLimit })
  t.is(r1.statusCode, 404)
  t.is(r2.statusCode, 429, 'XFF ignored without trustProxy')

  // With trustProxy the XFF is the bucket key, so distinct XFFs are separate.
  const p1state = createShardHttpState()
  const p1 = fakeRes()
  await handleShardHttp(fakeService, route, fakeReq('HEAD', '/h', { remoteAddress: '10.0.0.1', 'x-forwarded-for': '1.1.1.1' }), p1, { state: p1state, rateLimit, trustProxy: true })
  const p2 = fakeRes()
  await handleShardHttp(fakeService, route, fakeReq('HEAD', '/h', { remoteAddress: '10.0.0.1', 'x-forwarded-for': '2.2.2.2' }), p2, { state: p1state, rateLimit, trustProxy: true })
  t.is(p1.statusCode, 404)
  t.is(p2.statusCode, 404, 'distinct XFFs are separate buckets under trustProxy')
})
