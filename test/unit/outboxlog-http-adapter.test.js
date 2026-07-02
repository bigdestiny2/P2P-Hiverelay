import test from 'brittle'
import { EventEmitter } from 'node:events'
import { Readable } from 'node:stream'
import { OutboxLogApp } from 'p2p-hiveservices/builtin/outboxlog/index.js'
import {
  createOutboxLogHttpHandler,
  createOutboxLogHttpState,
  createOutboxLogTokenAuth,
  handleOutboxLogRoute
} from 'p2p-hiveservices/builtin/outboxlog/http-adapter.js'

const A = 'a'.repeat(64)
const B = 'b'.repeat(64)
const C = 'c'.repeat(64)

function fakeReq (method, url, body = null, headers = {}) {
  const chunks = body === null || body === undefined ? [] : [body]
  const req = Readable.from(chunks)
  req.method = method
  req.url = url
  req.headers = { ...headers }
  req.socket = { remoteAddress: headers.remoteAddress || '127.0.0.1' }
  return req
}

function jsonReq (method, url, body, token = '') {
  const text = JSON.stringify(body || {})
  const headers = {
    'content-type': 'application/json',
    'content-length': String(Buffer.byteLength(text))
  }
  if (token) headers['x-pear-token'] = token
  return fakeReq(method, url, text, headers)
}

function fakeRes () {
  const res = new EventEmitter()
  res.headers = {}
  res.statusCode = null
  res.body = ''
  res.chunks = []
  res.ended = false
  res.setHeader = function setHeader (name, value) {
    this.headers[name] = value
  }
  res.getHeader = function getHeader (name) {
    return this.header(name)
  }
  res.hasHeader = function hasHeader (name) {
    return this.header(name) !== undefined
  }
  res.header = function header (name) {
    const lower = name.toLowerCase()
    const key = Object.keys(this.headers).find(key => key.toLowerCase() === lower)
    return key ? this.headers[key] : undefined
  }
  res.writeHead = function writeHead (status) {
    this.statusCode = status
  }
  res.write = function write (chunk) {
    this.chunks.push(String(chunk))
    return true
  }
  res.end = function end (body = '') {
    this.body = String(body)
    this.ended = true
    this.emit('finish')
  }
  return res
}

function parseBody (res) {
  return JSON.parse(res.body)
}

function ssePayloads (res) {
  const payloads = []
  for (const block of res.chunks.join('').split('\n\n')) {
    const line = block.split('\n').find(line => line.startsWith('data: '))
    if (line) payloads.push(JSON.parse(line.slice('data: '.length)))
  }
  return payloads
}

function createCtx (opts = {}) {
  const auth = opts.auth || createOutboxLogTokenAuth()
  const app = opts.app || new OutboxLogApp({ verifyAppend: () => true })
  return {
    outboxLogApp: app,
    auth,
    state: opts.state || createOutboxLogHttpState(),
    rateLimit: opts.rateLimit,
    sseMaxPerIp: opts.sseMaxPerIp,
    sseMaxTotal: opts.sseMaxTotal,
    syncEventMaxAppIds: opts.syncEventMaxAppIds,
    syncEventMaxAppIdLength: opts.syncEventMaxAppIdLength,
    syncEventMaxReplay: opts.syncEventMaxReplay,
    ssePingMs: 60 * 1000
  }
}

test('outboxlog http adapter: ignores non-OutboxLog paths', async (t) => {
  const res = fakeRes()
  const handled = await handleOutboxLogRoute(fakeReq('GET', '/api/poker/tables'), res, createCtx())

  t.is(handled, false)
  t.is(res.statusCode, null)
})

test('outboxlog http adapter: issues tokens and gates bridge status', async (t) => {
  const ctx = createCtx()
  const tokenRes = fakeRes()
  const tokenHandled = await handleOutboxLogRoute(fakeReq('POST', '/api/token'), tokenRes, ctx)
  const token = parseBody(tokenRes).token

  t.is(tokenHandled, true)
  t.is(tokenRes.statusCode, 200)
  t.ok(token)

  const denied = fakeRes()
  await handleOutboxLogRoute(fakeReq('GET', '/api/bridge/status'), denied, ctx)
  t.is(denied.statusCode, 401)
  t.alike(parseBody(denied), { error: 'missing or invalid token' })

  const ok = fakeRes()
  await handleOutboxLogRoute(fakeReq('GET', '/api/bridge/status?token=' + encodeURIComponent(token)), ok, ctx)
  t.is(ok.statusCode, 200)
  t.alike(parseBody(ok), { ready: true, service: 'outboxlog' })
})

test('outboxlog http adapter: serves Peerit sync routes and directory', async (t) => {
  const ctx = createCtx()
  const token = ctx.auth.issue()

  const create = fakeRes()
  await handleOutboxLogRoute(jsonReq('POST', '/api/sync/create', { appId: A }, token), create, ctx)
  t.is(create.statusCode, 200)
  t.is(parseBody(create).appId, A)

  const appendPost = fakeRes()
  await handleOutboxLogRoute(jsonReq('POST', '/api/sync/append', { appId: A, op: { type: 'post', data: { id: 'p1', t: 'hello' } } }, token), appendPost, ctx)
  t.alike(parseBody(appendPost), { ok: true, key: 'post!p1' })

  const appendHead = fakeRes()
  await handleOutboxLogRoute(jsonReq('POST', '/api/sync/append', { appId: A, op: { type: 'head', data: { id: A, version: 2, root: 'r' } } }, token), appendHead, ctx)
  t.alike(parseBody(appendHead), { ok: true, key: 'head!' + A })

  const get = fakeRes()
  await handleOutboxLogRoute(fakeReq('GET', '/api/sync/get?appId=' + A + '&key=post!p1', null, { 'x-pear-token': token }), get, ctx)
  t.alike(parseBody(get), { id: 'p1', t: 'hello' })

  const list = fakeRes()
  await handleOutboxLogRoute(fakeReq('GET', '/api/sync/list?appId=' + A + '&prefix=post!', null, { 'x-pear-token': token }), list, ctx)
  t.alike(parseBody(list).map(row => row.key), ['post!p1'])

  const range = fakeRes()
  await handleOutboxLogRoute(fakeReq('GET', '/api/sync/range?appId=' + A + '&gt=head!' + A + '&limit=10', null, { 'x-pear-token': token }), range, ctx)
  t.alike(parseBody(range).map(row => row.key), ['post!p1'])

  const count = fakeRes()
  await handleOutboxLogRoute(fakeReq('GET', '/api/sync/count?appId=' + A + '&prefix=post!', null, { 'x-pear-token': token }), count, ctx)
  t.alike(parseBody(count), { count: 1 })

  const heads = fakeRes()
  await handleOutboxLogRoute(jsonReq('POST', '/api/sync/heads', { appIds: [A, B] }, token), heads, ctx)
  t.alike(parseBody(heads), { heads: { [A]: 2, [B]: 0 } })

  const directory = fakeRes()
  await handleOutboxLogRoute(fakeReq('GET', '/api/directory', null, { 'x-pear-token': token }), directory, ctx)
  t.is(parseBody(directory).heads[A].version, 2)
})

test('outboxlog http adapter: directory query exposes pagination and delta cursors', async (t) => {
  const ctx = createCtx()
  const token = ctx.auth.issue()
  for (const [appId, version] of [[B, 2], [A, 1], [C, 3]]) {
    await handleOutboxLogRoute(jsonReq('POST', '/api/sync/create', { appId }, token), fakeRes(), ctx)
    await handleOutboxLogRoute(jsonReq('POST', '/api/sync/append', {
      appId,
      op: { type: 'head', data: { id: appId, version, root: 'r' + version } }
    }, token), fakeRes(), ctx)
  }

  const first = fakeRes()
  await handleOutboxLogRoute(fakeReq('GET', '/api/directory?limit=2', null, { 'x-pear-token': token }), first, ctx)
  const firstBody = parseBody(first)
  t.alike(Object.keys(firstBody.heads), [A, B])
  t.is(firstBody.count, 2)
  t.is(firstBody.total, 3)
  t.is(firstBody.hasMore, true)
  t.is(firstBody.nextCursor, B)
  t.is(firstBody.watermark, 3)

  const second = fakeRes()
  await handleOutboxLogRoute(fakeReq('GET', '/api/directory?cursor=' + encodeURIComponent(firstBody.nextCursor) + '&limit=2', null, { 'x-pear-token': token }), second, ctx)
  const secondBody = parseBody(second)
  t.alike(Object.keys(secondBody.heads), [C])
  t.is(secondBody.hasMore, false)

  await handleOutboxLogRoute(jsonReq('POST', '/api/sync/append', {
    appId: A,
    op: { type: 'head', data: { id: A, version: 10, root: 'r10' } }
  }, token), fakeRes(), ctx)

  const delta = fakeRes()
  await handleOutboxLogRoute(fakeReq('GET', '/api/directory?since=' + firstBody.watermark, null, { 'x-pear-token': token }), delta, ctx)
  const deltaBody = parseBody(delta)
  t.alike(Object.keys(deltaBody.heads), [A])
  t.is(deltaBody.heads[A].version, 10)
  t.is(deltaBody.count, 1)
  t.is(deltaBody.watermark, 4)
})

test('outboxlog http adapter: sync events expose bounded per-outbox replay markers', async (t) => {
  const ctx = createCtx()
  const token = ctx.auth.issue()
  for (const appId of [A, B]) {
    await handleOutboxLogRoute(jsonReq('POST', '/api/sync/create', { appId }, token), fakeRes(), ctx)
  }
  await handleOutboxLogRoute(jsonReq('POST', '/api/sync/append', { appId: A, op: { type: 'post', data: { id: 'p1', t: 'one' } } }, token), fakeRes(), ctx)
  await handleOutboxLogRoute(jsonReq('POST', '/api/sync/append', { appId: B, op: { type: 'post', data: { id: 'b1' } } }, token), fakeRes(), ctx)
  await handleOutboxLogRoute(jsonReq('POST', '/api/sync/append', { appId: A, op: { type: 'post', data: { id: 'p2', t: 'two' } } }, token), fakeRes(), ctx)

  const first = fakeRes()
  await handleOutboxLogRoute(fakeReq('GET', '/api/sync/events?appId=' + A + '&limit=1', null, { 'x-pear-token': token }), first, ctx)
  const firstBody = parseBody(first)
  t.is(first.statusCode, 200)
  t.alike(firstBody.events.map(event => event.key), ['post!p1'])
  t.is(firstBody.events[0].topic, 'outbox/' + A)
  t.is(firstBody.events[0].seq, 1)
  t.absent('value' in firstBody.events[0])
  t.is(firstBody.count, 1)
  t.is(firstBody.watermark, 3)
  t.is(firstBody.nextSince, 1)
  t.is(firstBody.hasMore, true)

  const delta = fakeRes()
  await handleOutboxLogRoute(fakeReq('GET', '/api/sync/events?appId=' + A + '&since=' + firstBody.nextSince, null, { 'x-pear-token': token }), delta, ctx)
  const deltaBody = parseBody(delta)
  t.alike(deltaBody.events.map(event => event.key), ['post!p2'])
  t.is(deltaBody.events[0].seq, 3)
  t.is(deltaBody.hasMore, false)
})

test('outboxlog http adapter: sync event stream replays markers and follows live appends', async (t) => {
  const ctx = createCtx()
  const token = ctx.auth.issue()
  for (const appId of [A, B]) {
    await handleOutboxLogRoute(jsonReq('POST', '/api/sync/create', { appId }, token), fakeRes(), ctx)
  }
  await handleOutboxLogRoute(jsonReq('POST', '/api/sync/append', { appId: A, op: { type: 'post', data: { id: 'p1', body: 'old-body' } } }, token), fakeRes(), ctx)
  await handleOutboxLogRoute(jsonReq('POST', '/api/sync/append', { appId: B, op: { type: 'post', data: { id: 'b1', body: 'opaque-body' } } }, token), fakeRes(), ctx)
  await handleOutboxLogRoute(jsonReq('POST', '/api/sync/append', { appId: A, op: { type: 'post', data: { id: 'p2', body: 'new-body' } } }, token), fakeRes(), ctx)

  const streamReq = fakeReq('GET', '/api/sync/events?appIds=' + A + ',' + B + '&since=1&limit=10&stream=1&token=' + token)
  const streamRes = fakeRes()
  await handleOutboxLogRoute(streamReq, streamRes, ctx)

  t.is(streamRes.statusCode, 200)
  t.is(streamRes.header('Content-Type'), 'text/event-stream')
  t.ok(streamRes.chunks.join('').includes(': ok'))
  t.ok(streamRes.chunks.join('').includes('event: append'))
  t.ok(streamRes.chunks.join('').includes('id: 2'))

  const replay = ssePayloads(streamRes)
  t.alike(replay.map(event => event.key), ['post!b1', 'post!p2'])
  t.alike(replay.map(event => event.topic), ['outbox/' + B, 'outbox/' + A])
  t.alike(replay.map(event => event.seq), [2, 3])
  t.absent('value' in replay[0])
  t.absent(streamRes.chunks.join('').includes('opaque-body'))
  t.absent(streamRes.chunks.join('').includes('new-body'))

  await handleOutboxLogRoute(jsonReq('POST', '/api/sync/append', { appId: B, op: { type: 'vote', data: { id: 'b2', body: 'live-body' } } }, token), fakeRes(), ctx)
  const live = ssePayloads(streamRes)
  t.alike(live.map(event => event.key), ['post!b1', 'post!p2', 'vote!b2'])
  t.alike(live.map(event => event.seq), [2, 3, 4])
  t.absent('value' in live[2])
  t.absent(streamRes.chunks.join('').includes('live-body'))

  streamReq.emit('close')
  t.is(ctx.state.sseTotal, 0)
  t.is(ctx.state.ssePerIp.size, 0)
})

test('outboxlog http adapter: sync event stream honors backpressure and resumes on drain', async (t) => {
  const ctx = createCtx()
  const token = ctx.auth.issue()
  await handleOutboxLogRoute(jsonReq('POST', '/api/sync/create', { appId: A }, token), fakeRes(), ctx)

  const streamReq = fakeReq('GET', '/api/sync/events?appIds=' + A + '&since=0&stream=1&token=' + token)
  const streamRes = fakeRes()
  // Simulate a full socket send buffer: every write reports backpressure.
  streamRes.write = function write (chunk) { this.chunks.push(String(chunk)); return false }
  await handleOutboxLogRoute(streamReq, streamRes, ctx)
  t.is(streamRes.statusCode, 200)

  // First live append completes its frame (the write that discovers the full
  // buffer still lands), then the stream pauses.
  await handleOutboxLogRoute(jsonReq('POST', '/api/sync/append', { appId: A, op: { type: 'post', data: { id: 'p1', body: 'x' } } }, token), fakeRes(), ctx)
  const afterP1 = streamRes.chunks.length

  // While paused, further events are dropped — no unbounded heap growth.
  await handleOutboxLogRoute(jsonReq('POST', '/api/sync/append', { appId: A, op: { type: 'post', data: { id: 'p2', body: 'y' } } }, token), fakeRes(), ctx)
  t.is(streamRes.chunks.length, afterP1, 'p2 dropped while backpressured')

  // Drain: writes are accepted again, delivery resumes.
  streamRes.write = function write (chunk) { this.chunks.push(String(chunk)); return true }
  streamRes.emit('drain')
  await handleOutboxLogRoute(jsonReq('POST', '/api/sync/append', { appId: A, op: { type: 'post', data: { id: 'p3', body: 'z' } } }, token), fakeRes(), ctx)
  t.ok(streamRes.chunks.length > afterP1, 'writes resume after drain')

  const keys = ssePayloads(streamRes).map(event => event.key)
  t.ok(keys.includes('post!p1'), 'p1 delivered before pause')
  t.absent(keys.includes('post!p2'), 'p2 dropped during backpressure')
  t.ok(keys.includes('post!p3'), 'p3 delivered after drain')

  streamReq.emit('close')
})

test('outboxlog http adapter: sync event stream bounds appId fan-in', async (t) => {
  const ctx = createCtx({ syncEventMaxAppIds: 1, syncEventMaxAppIdLength: 64 })
  const token = ctx.auth.issue()

  const missing = fakeRes()
  await handleOutboxLogRoute(fakeReq('GET', '/api/sync/events?stream=1&token=' + token), missing, ctx)
  t.is(missing.statusCode, 400)
  t.alike(parseBody(missing), { error: 'missing appId' })

  const tooLong = fakeRes()
  await handleOutboxLogRoute(fakeReq('GET', '/api/sync/events?appId=' + 'x'.repeat(65) + '&stream=1&token=' + token), tooLong, ctx)
  t.is(tooLong.statusCode, 400)
  t.alike(parseBody(tooLong), { error: 'appId too long' })

  const tooMany = fakeRes()
  await handleOutboxLogRoute(fakeReq('GET', '/api/sync/events?appIds=' + A + ',' + B + '&stream=1&token=' + token), tooMany, ctx)
  t.is(tooMany.statusCode, 400)
  t.alike(parseBody(tooMany), { error: 'too many appIds' })
})

test('outboxlog http adapter: rejects identity signing on the relay', async (t) => {
  const ctx = createCtx()
  const token = ctx.auth.issue()
  const res = fakeRes()

  await handleOutboxLogRoute(fakeReq('GET', '/api/identity', null, { 'x-pear-token': token }), res, ctx)

  t.is(res.statusCode, 410)
  t.alike(parseBody(res), { error: 'identity is browser-local; this relay never signs' })
})

test('outboxlog http adapter: hardens JSON body parsing before sync mutation', async (t) => {
  let created = false
  const ctx = createCtx({
    app: {
      sync: {
        create () {
          created = true
          return { appId: A }
        }
      }
    }
  })
  const token = ctx.auth.issue()
  const res = fakeRes()
  const body = '{"appId":'

  await handleOutboxLogRoute(fakeReq('POST', '/api/sync/create', body, {
    'x-pear-token': token,
    'content-type': 'text/plain',
    'content-length': String(Buffer.byteLength(body))
  }), res, ctx)

  t.is(res.statusCode, 400)
  t.alike(parseBody(res), { error: 'Content-Type must be application/json' })
  t.is(res.header('Connection'), 'close')
  t.is(created, false)
})

test('outboxlog http adapter: rejects oversized JSON bodies with close hint', async (t) => {
  const ctx = createCtx()
  const token = ctx.auth.issue()
  const res = fakeRes()
  const body = JSON.stringify({ appId: A, blob: 'x'.repeat(1024 * 1024) })

  await handleOutboxLogRoute(fakeReq('POST', '/api/sync/create', body, {
    'x-pear-token': token,
    'content-type': 'application/json',
    'content-length': String(Buffer.byteLength(body))
  }), res, ctx)

  t.is(res.statusCode, 413)
  t.alike(parseBody(res), { error: 'Request body too large' })
  t.is(res.header('Connection'), 'close')
})

test('outboxlog http adapter: redacts unexpected route failures', async (t) => {
  const ctx = createCtx({
    app: {
      sync: {
        create () {
          throw new Error('failed opening /data/private/outboxlog-token')
        }
      }
    }
  })
  const token = ctx.auth.issue()
  const res = fakeRes()

  await handleOutboxLogRoute(jsonReq('POST', '/api/sync/create', { appId: A }, token), res, ctx)

  t.is(res.statusCode, 500)
  t.alike(parseBody(res), { error: 'outboxlog route failed' })
  t.absent(res.body.includes('/data/private'))
})

test('outboxlog http adapter: applies CORS and OPTIONS headers', async (t) => {
  const ctx = createCtx()
  ctx.allowOrigin = ['https://peerit.example']
  const res = fakeRes()

  await handleOutboxLogRoute(fakeReq('OPTIONS', '/api/sync/create', null, { origin: 'https://peerit.example' }), res, ctx)

  t.is(res.statusCode, 204)
  t.is(res.header('Access-Control-Allow-Origin'), 'https://peerit.example')
  t.is(res.header('Access-Control-Allow-Headers'), 'Content-Type, X-Pear-Token')
  t.is(res.header('Access-Control-Allow-Methods'), 'GET, POST, OPTIONS')
  t.is(res.header('Vary'), 'Origin')
})

test('outboxlog http adapter: rate limits by client IP', async (t) => {
  const auth = createOutboxLogTokenAuth()
  const token = auth.issue()
  const handler = createOutboxLogHttpHandler({
    outboxLogApp: new OutboxLogApp({ verifyAppend: () => true }),
    auth,
    rateLimit: { windowMs: 60000, max: 1 }
  })

  const ok = fakeRes()
  await handler(fakeReq('GET', '/api/bridge/status', null, { 'x-pear-token': token }), ok)
  t.is(ok.statusCode, 200)

  const limited = fakeRes()
  await handler(fakeReq('GET', '/api/bridge/status', null, { 'x-pear-token': token }), limited)
  t.is(limited.statusCode, 429)
  t.alike(parseBody(limited), { error: 'rate limited' })
})

test('outboxlog http adapter: tokenized swarm SSE receives peer messages', async (t) => {
  const ctx = createCtx()
  const token = ctx.auth.issue()

  const joinA = fakeRes()
  await handleOutboxLogRoute(jsonReq('POST', '/api/swarm/join', { topicHex: 'f'.repeat(64), protocol: 'pear.swarm.v1', version: 1 }, token), joinA, ctx)
  const channelA = parseBody(joinA).channelId

  const joinB = fakeRes()
  await handleOutboxLogRoute(jsonReq('POST', '/api/swarm/join', { topicHex: 'f'.repeat(64), protocol: 'pear.swarm.v1', version: 1 }, token), joinB, ctx)
  const channelB = parseBody(joinB).channelId

  const streamReq = fakeReq('GET', '/api/swarm/events?channelId=' + channelB + '&token=' + token)
  const streamRes = fakeRes()
  await handleOutboxLogRoute(streamReq, streamRes, ctx)

  t.is(streamRes.statusCode, 200)
  t.is(streamRes.header('Content-Type'), 'text/event-stream')
  t.ok(streamRes.chunks.join('').includes(': ok'))

  const send = fakeRes()
  await handleOutboxLogRoute(jsonReq('POST', '/api/swarm/send', {
    channelId: channelA,
    peerId: channelB,
    data: 'descriptor'
  }, token), send, ctx)

  t.alike(parseBody(send), { ok: true })
  t.ok(streamRes.chunks.join('').includes('"type":"message"'))
  t.ok(streamRes.chunks.join('').includes('"peerId":"' + channelA + '"'))
  t.ok(streamRes.chunks.join('').includes('"data":"descriptor"'))

  streamReq.emit('close')
  t.is(ctx.outboxLogApp.swarm._channelCount(), 1)
})

test('outboxlog http adapter: caps open SSE streams per IP', async (t) => {
  const ctx = createCtx({ sseMaxPerIp: 1 })
  const token = ctx.auth.issue()
  const joinA = fakeRes()
  await handleOutboxLogRoute(jsonReq('POST', '/api/swarm/join', { topicHex: '1'.repeat(64) }, token), joinA, ctx)
  const channelA = parseBody(joinA).channelId

  const firstReq = fakeReq('GET', '/api/swarm/events?channelId=' + channelA + '&token=' + token)
  const first = fakeRes()
  await handleOutboxLogRoute(firstReq, first, ctx)
  t.is(first.statusCode, 200)

  const second = fakeRes()
  await handleOutboxLogRoute(fakeReq('GET', '/api/sync/events?appId=' + A + '&stream=1&token=' + token), second, ctx)
  t.is(second.statusCode, 429)
  t.alike(parseBody(second), { error: 'too many open streams' })

  firstReq.emit('close')
})
