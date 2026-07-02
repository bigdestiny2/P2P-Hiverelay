import test from 'brittle'
import { EventEmitter } from 'node:events'
import { Readable } from 'node:stream'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import {
  REPAIRTICKET_RECORD_TYPE_TICKET,
  RepairTicketApp,
  signRepairRecord
} from 'p2p-hiveservices/builtin/repairticket/index.js'
import {
  createRepairTicketHttpState,
  handleRepairTicketRoute
} from 'p2p-hiveservices/builtin/repairticket/http-adapter.js'

const CREATED_AT = '2026-07-02T12:00:00.000Z'
const EXPIRES_AT = '2026-07-02T18:00:00.000Z'
const NOW = Date.parse('2026-07-02T12:05:00.000Z')
const TARGET = 'a'.repeat(64)
const TARGET_HASH = 'b'.repeat(64)
const WITNESS_ID = 'c'.repeat(64)

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
    repairTicketApp: opts.app || new RepairTicketApp({ verify: { now: NOW } }),
    state: opts.state || createRepairTicketHttpState(),
    rateLimit: opts.rateLimit,
    sseMaxPerIp: opts.sseMaxPerIp,
    sseMaxTotal: opts.sseMaxTotal,
    ssePingMs: 60 * 1000
  }
}

test('repairticket http adapter: ignores non-RepairTicket paths', async (t) => {
  const res = fakeRes()
  const handled = await handleRepairTicketRoute(fakeReq('GET', '/api/witness/status'), res, createCtx())

  t.is(handled, false)
  t.is(res.statusCode, null)
})

test('repairticket http adapter: status and CORS preflight are public', async (t) => {
  const ctx = createCtx()
  const status = fakeRes()
  await handleRepairTicketRoute(fakeReq('GET', '/api/repair/status'), status, ctx)

  t.is(status.statusCode, 200)
  t.alike(parseBody(status), { ready: true, service: 'repairticket' })

  const options = fakeRes()
  await handleRepairTicketRoute(fakeReq('OPTIONS', '/api/repair/append', null, { origin: 'https://app.example' }), options, {
    ...ctx,
    allowOrigin: ['https://app.example']
  })

  t.is(options.statusCode, 204)
  t.is(options.header('Access-Control-Allow-Origin'), 'https://app.example')
  t.ok(options.header('Access-Control-Allow-Methods').includes('POST'))
})

test('repairticket http adapter: appends signed tickets and lists redacted summaries', async (t) => {
  const signer = keyPair(1)
  const ctx = createCtx()
  const ticket = signRepairRecord(ticketInput(signer), signer.secretKey)

  const append = fakeRes()
  await handleRepairTicketRoute(jsonReq('POST', '/api/repair/append', { record: ticket }), append, ctx)
  t.is(append.statusCode, 200)
  t.alike(parseBody(append), { ok: true, key: 'ticket!' + ticket.id, id: ticket.id, ticketId: ticket.id })

  const tickets = fakeRes()
  await handleRepairTicketRoute(fakeReq('GET', '/api/repair/tickets?target=' + TARGET_HASH), tickets, ctx)
  const listed = parseBody(tickets)
  t.is(tickets.statusCode, 200)
  t.is(listed.count, 1)
  t.is(listed.tickets[0].id, ticket.id)
  t.absent(listed.tickets[0].target.key)
  t.is(listed.tickets[0].target.keyHash, TARGET_HASH)

  const records = fakeRes()
  await handleRepairTicketRoute(fakeReq('GET', '/api/repair/records?ticketId=' + ticket.id), records, ctx)
  t.is(parseBody(records).records[0].id, ticket.id)
})

test('repairticket http adapter: exposes bounded marker replay for event polling', async (t) => {
  const signer = keyPair(2)
  const ctx = createCtx()
  const ticket = signRepairRecord(ticketInput(signer), signer.secretKey)
  await handleRepairTicketRoute(jsonReq('POST', '/api/repair/append', ticket), fakeRes(), ctx)

  const events = fakeRes()
  await handleRepairTicketRoute(fakeReq('GET', '/api/repair/events?target=' + TARGET + '&limit=1'), events, ctx)
  const body = parseBody(events)

  t.is(events.statusCode, 200)
  t.is(body.count, 1)
  t.is(body.markers[0].id, ticket.id)
  t.absent('signature' in body.markers[0])
})

test('repairticket http adapter: rejects malformed JSON and bad records without leaking internals', async (t) => {
  const ctx = createCtx()
  const badJson = fakeRes()
  await handleRepairTicketRoute(fakeReq('POST', '/api/repair/append', '{', {
    'content-type': 'application/json',
    'content-length': '1'
  }), badJson, ctx)
  t.is(badJson.statusCode, 400)
  t.alike(parseBody(badJson), { error: 'bad json body' })

  const badRecord = fakeRes()
  await handleRepairTicketRoute(jsonReq('POST', '/api/repair/append', { createdAt: CREATED_AT }), badRecord, ctx)
  t.is(badRecord.statusCode, 400)
  t.ok(parseBody(badRecord).error.startsWith('RepairTicket:'))
})

function ticketInput (signer) {
  return {
    type: REPAIRTICKET_RECORD_TYPE_TICKET,
    createdAt: CREATED_AT,
    expiresAt: EXPIRES_AT,
    signer: {
      publicKey: signer.publicKeyHex,
      role: 'witness'
    },
    target: {
      kind: 'hypercore',
      key: TARGET,
      keyHash: TARGET_HASH
    },
    repair: {
      reason: 'witness-failure',
      priority: 80,
      desiredReplicas: 5,
      observedReplicas: 1,
      evidence: [WITNESS_ID]
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
