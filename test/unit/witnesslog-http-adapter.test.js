import test from 'brittle'
import { EventEmitter } from 'node:events'
import { Readable } from 'node:stream'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import { WitnessLogApp, signWitnessRecord } from 'p2p-hiveservices/builtin/witnesslog/index.js'
import {
  createWitnessLogHttpState,
  handleWitnessLogRoute
} from 'p2p-hiveservices/builtin/witnesslog/http-adapter.js'

const OBSERVED_AT = '2026-07-02T12:00:00.000Z'
const EXPIRES_AT = '2026-07-02T12:30:00.000Z'
const NOW = Date.parse('2026-07-02T12:05:00.000Z')
const TARGET = 'a'.repeat(64)
const TARGET_HASH = 'b'.repeat(64)

function fakeReq (method, url, body = null, headers = {}) {
  const chunks = body === null || body === undefined ? [] : [body]
  const req = Readable.from(chunks)
  req.method = method
  req.url = url
  req.headers = { ...headers }
  req.socket = { remoteAddress: headers.remoteAddress || '127.0.0.1' }
  return req
}

function jsonReq (method, url, body, headers = {}) {
  const text = JSON.stringify(body || {})
  return fakeReq(method, url, text, {
    'content-type': 'application/json',
    'content-length': String(Buffer.byteLength(text)),
    ...headers
  })
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

function createCtx (opts = {}) {
  return {
    witnessLogApp: opts.app || new WitnessLogApp({ verify: { now: NOW } }),
    state: opts.state || createWitnessLogHttpState(),
    rateLimit: opts.rateLimit,
    sseMaxPerIp: opts.sseMaxPerIp,
    sseMaxTotal: opts.sseMaxTotal,
    ssePingMs: 60 * 1000
  }
}

test('witnesslog http adapter: ignores non-WitnessLog paths', async (t) => {
  const res = fakeRes()
  const handled = await handleWitnessLogRoute(fakeReq('GET', '/api/poker/tables'), res, createCtx())

  t.is(handled, false)
  t.is(res.statusCode, null)
})

test('witnesslog http adapter: status and CORS preflight are public', async (t) => {
  const ctx = createCtx()
  const status = fakeRes()
  await handleWitnessLogRoute(fakeReq('GET', '/api/witness/status'), status, ctx)

  t.is(status.statusCode, 200)
  t.alike(parseBody(status), { ready: true, service: 'witnesslog' })

  const options = fakeRes()
  await handleWitnessLogRoute(fakeReq('OPTIONS', '/api/witness/append', null, { origin: 'https://app.example' }), options, {
    ...ctx,
    allowOrigin: ['https://app.example']
  })

  t.is(options.statusCode, 204)
  t.is(options.header('Access-Control-Allow-Origin'), 'https://app.example')
  t.ok(options.header('Access-Control-Allow-Methods').includes('POST'))
})

test('witnesslog http adapter: appends signed observations and lists redacted records', async (t) => {
  const observer = keyPair(1)
  const ctx = createCtx()
  const signed = signWitnessRecord(witnessInput(observer), observer.secretKey)

  const append = fakeRes()
  await handleWitnessLogRoute(jsonReq('POST', '/api/witness/append', { record: signed }), append, ctx)
  t.is(append.statusCode, 200)
  t.alike(parseBody(append), { ok: true, key: 'availability!' + signed.id, id: signed.id })

  const list = fakeRes()
  await handleWitnessLogRoute(fakeReq('GET', '/api/witness/records?target=' + TARGET_HASH), list, ctx)
  const listed = parseBody(list)
  t.is(list.statusCode, 200)
  t.is(listed.count, 1)
  t.is(listed.records[0].id, signed.id)
  t.absent(listed.records[0].target.key)
  t.is(listed.records[0].target.keyHash, TARGET_HASH)
})

test('witnesslog http adapter: exposes bounded marker replay for event polling', async (t) => {
  const observer = keyPair(2)
  const ctx = createCtx()
  const signed = signWitnessRecord(witnessInput(observer), observer.secretKey)
  await handleWitnessLogRoute(jsonReq('POST', '/api/witness/append', signed), fakeRes(), ctx)

  const events = fakeRes()
  await handleWitnessLogRoute(fakeReq('GET', '/api/witness/events?target=' + TARGET + '&limit=1'), events, ctx)
  const body = parseBody(events)

  t.is(events.statusCode, 200)
  t.is(body.count, 1)
  t.is(body.markers[0].id, signed.id)
  t.absent('signature' in body.markers[0])
})

test('witnesslog http adapter: rejects malformed JSON and bad records without leaking internals', async (t) => {
  const ctx = createCtx()
  const badJson = fakeRes()
  await handleWitnessLogRoute(fakeReq('POST', '/api/witness/append', '{', {
    'content-type': 'application/json',
    'content-length': '1'
  }), badJson, ctx)
  t.is(badJson.statusCode, 400)
  t.alike(parseBody(badJson), { error: 'bad json body' })

  const badRecord = fakeRes()
  await handleWitnessLogRoute(jsonReq('POST', '/api/witness/append', { observedAt: OBSERVED_AT }), badRecord, ctx)
  t.is(badRecord.statusCode, 400)
  t.ok(parseBody(badRecord).error.startsWith('WitnessLog:'))
})

function witnessInput (observer) {
  return {
    observedAt: OBSERVED_AT,
    expiresAt: EXPIRES_AT,
    observer: {
      publicKey: observer.publicKeyHex,
      appId: 'probe-agent'
    },
    relay: {
      url: 'https://relay.example',
      operatorKey: 'c'.repeat(64)
    },
    target: {
      kind: 'hypercore',
      key: TARGET,
      keyHash: TARGET_HASH
    },
    probe: {
      nonce: 'nonce-1',
      method: 'gateway-head',
      range: { start: 0, end: 1024 }
    },
    result: {
      ok: true,
      httpStatus: 200,
      latencyMs: 42,
      bytes: 1024,
      headSeq: 7,
      digest: 'sha256:' + 'd'.repeat(64)
    }
  }
}

function keyPair (seedByte) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.alloc(32, seedByte))
  return {
    publicKey,
    secretKey,
    publicKeyHex: b4a.toString(publicKey, 'hex')
  }
}
