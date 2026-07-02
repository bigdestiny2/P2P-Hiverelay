/**
 * Peerit-compatible HTTP/SSE adapter for OutboxLog.
 *
 * Exposes the token-gated `/api/*` surface that Peerit's browser bridge speaks:
 * `/api/token`, `/api/bridge/status`, `/api/sync/*`, `/api/directory`, and
 * `/api/swarm/*`. The adapter is standalone so HiveRelay can mount it later
 * without moving sync, auth, or SSE mechanics into the large relay dispatcher.
 */

import { randomBytes, timingSafeEqual } from 'node:crypto'
import { readJsonBody } from 'p2p-hiverelay/core/relay-node/api-body.js'
import { getPostJsonContentTypeProblem } from 'p2p-hiverelay/core/relay-node/api-request.js'
import { appendVaryHeader, writeJson } from 'p2p-hiverelay/core/relay-node/api-response.js'

export const OUTBOXLOG_API_PREFIX = '/api'
export const OUTBOXLOG_MAX_JSON_BODY_BYTES = 1024 * 1024
export const OUTBOXLOG_SSE_PING_MS = 25000

const DEFAULT_RATE_LIMIT = { windowMs: 60000, max: 1200 }
const DEFAULT_SSE_MAX_PER_IP = 8
const DEFAULT_SSE_MAX_TOTAL = 2000
const DEFAULT_SYNC_EVENT_APP_ID_LIMIT = 128
const DEFAULT_SYNC_EVENT_APP_ID_LENGTH = 128
const DEFAULT_SYNC_EVENT_REPLAY_LIMIT = 1000
const MAX_RATE_BUCKETS = 50000

export function createOutboxLogHttpHandler (opts = {}) {
  const state = createOutboxLogHttpState()
  return (req, res) => handleOutboxLogRoute(req, res, { ...opts, state })
}

export function createOutboxLogHttpState () {
  return {
    buckets: new Map(),
    sseTotal: 0,
    ssePerIp: new Map()
  }
}

export function createOutboxLogTokenAuth ({ tokenBytes = 32, maxTokens = 4096 } = {}) {
  const tokens = new Set()
  const order = []

  return {
    issue () {
      const token = randomBytes(tokenBytes).toString('hex')
      tokens.add(token)
      order.push(token)
      while (order.length > maxTokens) tokens.delete(order.shift())
      return token
    },

    verify (token) {
      if (typeof token !== 'string' || !token) return false
      for (const known of tokens) {
        if (safeTokenEqual(token, known)) return true
      }
      return false
    },

    _size () {
      return tokens.size
    }
  }
}

export async function handleOutboxLogRoute (req, res, ctx = {}) {
  let parsed
  try {
    parsed = new URL(req.url, 'http://localhost')
  } catch {
    return false
  }

  const path = parsed.pathname
  if (!isOutboxLogApiPath(path)) return false

  applyCors(req, res, ctx)
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    res.writeHead(204)
    res.end()
    return true
  }

  const state = ctx.state || createOutboxLogHttpState()
  const ip = clientIp(req, ctx)
  if (overLimit(ip, ctx.rateLimit || DEFAULT_RATE_LIMIT, state)) {
    return respond(res, 429, { error: 'rate limited' })
  }

  const auth = ctx.auth || ctx.outboxLogAuth
  if (path === '/api/token') {
    if (req.method !== 'POST') return respond(res, 405, { error: 'method not allowed' })
    if (!auth || typeof auth.issue !== 'function') return respond(res, 503, { error: 'outboxlog auth unavailable' })
    return respond(res, 200, { token: auth.issue() })
  }

  if (!auth || typeof auth.verify !== 'function' || !auth.verify(tokenFrom(req, parsed))) {
    return respond(res, 401, { error: 'missing or invalid token' })
  }

  const app = ctx.outboxLogApp || ctx.outboxlogApp || ctx.app || ctx.core
  const sync = ctx.sync || (app && app.sync)
  const swarm = ctx.swarm || (app && app.swarm)

  try {
    if (path === '/api/bridge/status') {
      if (req.method !== 'GET') return respond(res, 405, { error: 'method not allowed' })
      return respond(res, 200, { ready: true, service: 'outboxlog' })
    }

    if (path.startsWith('/api/identity')) {
      return respond(res, 410, { error: 'identity is browser-local; this relay never signs' })
    }

    if (!sync) return respond(res, 503, { error: 'outboxlog sync unavailable' })

    if (path === '/api/sync/create' && req.method === 'POST') {
      const body = await readJson(req)
      if (!body.ok) return respondReadProblem(res, body)
      return respond(res, 200, await sync.create(body.body.appId, { namespace: body.body.namespace }))
    }

    if (path === '/api/sync/join' && req.method === 'POST') {
      const body = await readJson(req)
      if (!body.ok) return respondReadProblem(res, body)
      return respond(res, 200, await sync.join(body.body.appId, body.body.inviteKey))
    }

    if (path === '/api/sync/append' && req.method === 'POST') {
      const body = await readJson(req)
      if (!body.ok) return respondReadProblem(res, body)
      return respond(res, 200, await sync.append(body.body.appId, body.body.op))
    }

    if (path === '/api/sync/heads' && req.method === 'POST') {
      const body = await readJson(req)
      if (!body.ok) return respondReadProblem(res, body)
      return respond(res, 200, sync.heads ? await sync.heads(body.body.appIds) : { heads: {} })
    }

    if (path === '/api/sync/events' && req.method === 'GET') {
      if (wantsSyncEventStream(req, parsed)) {
        if (!sync.events || !app || typeof app.subscribe !== 'function') return respond(res, 503, { error: 'outboxlog events unavailable' })
        return await openSyncEvents(req, res, parsed, ip, app, sync, state, ctx)
      }
      return respond(res, 200, sync.events ? await sync.events(parsed.searchParams.get('appId'), eventOptsFrom(parsed)) : { events: [], count: 0, watermark: 0, nextSince: 0, hasMore: false })
    }

    if (path === '/api/sync/get' && req.method === 'GET') {
      return respond(res, 200, await sync.get(parsed.searchParams.get('appId'), parsed.searchParams.get('key')))
    }

    if (path === '/api/sync/list' && req.method === 'GET') {
      return respond(res, 200, await sync.list(parsed.searchParams.get('appId'), parsed.searchParams.get('prefix') || '', {
        limit: parsed.searchParams.get('limit')
      }))
    }

    if (path === '/api/sync/range' && req.method === 'GET') {
      return respond(res, 200, await sync.range(parsed.searchParams.get('appId'), rangeOptsFrom(parsed)))
    }

    if (path === '/api/sync/count' && req.method === 'GET') {
      return respond(res, 200, await sync.count(parsed.searchParams.get('appId'), parsed.searchParams.get('prefix') || ''))
    }

    if (path === '/api/sync/status' && req.method === 'GET') {
      return respond(res, 200, await sync.status(parsed.searchParams.get('appId')))
    }

    if (path === '/api/directory' && req.method === 'GET') {
      return respond(res, 200, sync.directory ? await sync.directory(directoryOptsFrom(parsed)) : { heads: {}, count: 0, total: 0, nextCursor: null, hasMore: false, watermark: 0 })
    }

    if (path === '/api/swarm/events' && req.method === 'GET') {
      if (!swarm || typeof swarm.subscribe !== 'function') return respond(res, 503, { error: 'outboxlog swarm unavailable' })
      return openSwarmEvents(req, res, parsed, ip, swarm, state, ctx)
    }

    if (path === '/api/swarm/join' && req.method === 'POST') {
      if (!swarm || typeof swarm.join !== 'function') return respond(res, 503, { error: 'outboxlog swarm unavailable' })
      const body = await readJson(req)
      if (!body.ok) return respondReadProblem(res, body)
      return respond(res, 200, await swarm.join(body.body.topicHex, body.body))
    }

    if (path === '/api/swarm/send' && req.method === 'POST') {
      if (!swarm || typeof swarm.send !== 'function') return respond(res, 503, { error: 'outboxlog swarm unavailable' })
      const body = await readJson(req)
      if (!body.ok) return respondReadProblem(res, body)
      return respond(res, 200, await swarm.send(body.body.channelId, body.body.peerId, body.body.data))
    }

    if (path === '/api/swarm/leave' && req.method === 'POST') {
      if (!swarm || typeof swarm.leave !== 'function') return respond(res, 503, { error: 'outboxlog swarm unavailable' })
      const body = await readJson(req)
      if (!body.ok) return respondReadProblem(res, body)
      return respond(res, 200, await swarm.leave(body.body.channelId))
    }

    if (isMethodMismatch(path, req.method)) return respond(res, 405, { error: 'method not allowed' })
    return respond(res, 404, { error: 'not found' })
  } catch (err) {
    if (err && Number.isInteger(err.status) && err.status >= 400 && err.status < 500) {
      return respond(res, err.status, { error: err.message || 'outboxlog request failed' })
    }
    return respond(res, 500, { error: 'outboxlog route failed' })
  }
}

function isOutboxLogApiPath (path) {
  return (
    path === '/api/token' ||
    path === '/api/bridge/status' ||
    path === '/api/directory' ||
    path.startsWith('/api/identity') ||
    path.startsWith('/api/sync/') ||
    path.startsWith('/api/swarm/')
  )
}

function isMethodMismatch (path, method) {
  const postOnly = new Set([
    '/api/sync/create',
    '/api/sync/join',
    '/api/sync/append',
    '/api/sync/heads',
    '/api/swarm/join',
    '/api/swarm/send',
    '/api/swarm/leave'
  ])
  const getOnly = new Set([
    '/api/bridge/status',
    '/api/sync/get',
    '/api/sync/list',
    '/api/sync/range',
    '/api/sync/count',
    '/api/sync/status',
    '/api/sync/events',
    '/api/directory',
    '/api/swarm/events'
  ])
  return (postOnly.has(path) && method !== 'POST') || (getOnly.has(path) && method !== 'GET')
}

function applyCors (req, res, ctx) {
  const allowOrigin = ctx.allowOrigin || '*'
  const requestOrigin = req && req.headers ? req.headers.origin : null
  const origin = allowOrigin === '*'
    ? '*'
    : (Array.isArray(allowOrigin) && requestOrigin && allowOrigin.includes(requestOrigin) ? requestOrigin : allowOrigin[0] || '*')
  res.setHeader('Access-Control-Allow-Origin', origin)
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Pear-Token')
  res.setHeader('Access-Control-Max-Age', '86400')
  appendVaryHeader(res, 'Origin')
}

function clientIp (req, ctx) {
  if (ctx.trustProxy && req.headers && req.headers['x-forwarded-for']) {
    return String(req.headers['x-forwarded-for']).split(',')[0].trim() || 'unknown'
  }
  return (req.socket && req.socket.remoteAddress) || 'unknown'
}

function overLimit (ip, rateLimit, state) {
  if (!rateLimit || rateLimit.max === false || rateLimit.max === Infinity) return false
  const now = Date.now()
  let bucket = state.buckets.get(ip)
  if (!bucket || now - bucket.start > rateLimit.windowMs) {
    bucket = { start: now, count: 0 }
    state.buckets.set(ip, bucket)
  }
  bucket.count++
  if (state.buckets.size > MAX_RATE_BUCKETS) {
    for (const [key, value] of state.buckets) {
      if (now - value.start > rateLimit.windowMs) state.buckets.delete(key)
    }
  }
  return bucket.count > rateLimit.max
}

function tokenFrom (req, url) {
  const headers = req.headers || {}
  return headers['x-pear-token'] || headers['X-Pear-Token'] || url.searchParams.get('token') || ''
}

async function readJson (req) {
  const contentTypeProblem = getPostJsonContentTypeProblem(req)
  if (contentTypeProblem) {
    return {
      ok: false,
      status: 400,
      error: contentTypeProblem.error,
      close: contentTypeProblem.close
    }
  }

  try {
    return { ok: true, body: await readJsonBody(req, OUTBOXLOG_MAX_JSON_BODY_BYTES) }
  } catch (err) {
    if (err && err.message === 'Request body too large') {
      return { ok: false, status: 413, error: 'Request body too large', close: true }
    }
    return { ok: false, status: 400, error: 'bad json body', close: false }
  }
}

function respondReadProblem (res, problem) {
  return respond(res, problem.status, { error: problem.error }, problem.close ? { Connection: 'close' } : null)
}

function respond (res, status, body, headers = null) {
  writeJson(res, body, status, headers)
  return true
}

function rangeOptsFrom (url) {
  const out = { limit: url.searchParams.get('limit') }
  for (const bound of ['gt', 'gte', 'lt', 'lte']) {
    const value = url.searchParams.get(bound)
    if (value != null) out[bound] = value
  }
  if (url.searchParams.get('reverse')) out.reverse = true
  return out
}

function directoryOptsFrom (url) {
  return {
    limit: url.searchParams.get('limit'),
    cursor: url.searchParams.get('cursor'),
    since: url.searchParams.get('since')
  }
}

function eventOptsFrom (url) {
  return {
    limit: url.searchParams.get('limit'),
    since: url.searchParams.get('since')
  }
}

function wantsSyncEventStream (req, url) {
  const accept = req && req.headers ? String(req.headers.accept || req.headers.Accept || '') : ''
  return (
    url.searchParams.get('stream') === '1' ||
    url.searchParams.get('format') === 'sse' ||
    accept.toLowerCase().includes('text/event-stream')
  )
}

async function openSyncEvents (req, res, url, ip, app, sync, state, ctx) {
  const selection = eventAppIdsFrom(url, ctx)
  if (!selection.ok) return respond(res, 400, { error: selection.error })

  const replay = await syncEventReplay(sync, selection.appIds, streamEventOptsFrom(url, ctx))
  const releaseSlot = claimSseSlot(ip, state, ctx)
  if (!releaseSlot) return respond(res, 429, { error: 'too many open streams' })

  const unsubscribers = []
  try {
    for (const appId of selection.appIds) {
      unsubscribers.push(app.subscribe(appId, { replay: false }, (event) => {
        const marker = appendEventMarker(event)
        if (marker) writeSseData(res, marker, 'append')
      }))
    }
  } catch (err) {
    releaseSlot()
    throw err
  }

  writeSseStart(res)
  for (const marker of replay) writeSseData(res, marker, 'append')

  const ping = startSsePing(res, ctx)
  attachSseCleanup(req, res, ping, () => {
    for (const unsubscribe of unsubscribers) {
      try {
        unsubscribe()
      } catch {}
    }
    releaseSlot()
  })
  return true
}

function eventAppIdsFrom (url, ctx) {
  const max = ctx.syncEventMaxAppIds == null ? DEFAULT_SYNC_EVENT_APP_ID_LIMIT : ctx.syncEventMaxAppIds
  const maxLength = ctx.syncEventMaxAppIdLength == null ? DEFAULT_SYNC_EVENT_APP_ID_LENGTH : ctx.syncEventMaxAppIdLength
  const raw = []
  const single = url.searchParams.get('appId')
  if (single) raw.push(single)
  for (const value of url.searchParams.getAll('appIds')) {
    for (const appId of String(value).split(',')) raw.push(appId.trim())
  }

  const appIds = []
  const seen = new Set()
  for (const appId of raw) {
    if (!appId || seen.has(appId)) continue
    if (appId.length > maxLength) return { ok: false, error: 'appId too long' }
    if (appIds.length >= max) return { ok: false, error: 'too many appIds' }
    seen.add(appId)
    appIds.push(appId)
  }
  if (appIds.length === 0) return { ok: false, error: 'missing appId' }
  return { ok: true, appIds }
}

function streamEventOptsFrom (url, ctx) {
  const opts = eventOptsFrom(url)
  opts.limit = streamReplayLimitFrom(url, ctx)
  return opts
}

function streamReplayLimitFrom (url, ctx) {
  const max = ctx.syncEventMaxReplay == null ? DEFAULT_SYNC_EVENT_REPLAY_LIMIT : ctx.syncEventMaxReplay
  const value = Number.parseInt(url.searchParams.get('limit'), 10)
  if (!Number.isFinite(value) || value < 1) return max
  return Math.min(value, max)
}

async function syncEventReplay (sync, appIds, opts) {
  const replay = []
  for (const appId of appIds) {
    const page = await sync.events(appId, opts)
    const events = page && Array.isArray(page.events) ? page.events : []
    for (const event of events) {
      const marker = appendEventMarker(event)
      if (marker) replay.push(marker)
    }
  }
  return replay.sort(compareAppendMarkers).slice(0, opts.limit)
}

function appendEventMarker (event) {
  if (!event || typeof event !== 'object') return null
  return {
    seq: event.seq,
    topic: event.topic || (event.appId ? 'outbox/' + event.appId : undefined),
    appId: event.appId,
    key: event.key,
    type: event.type,
    version: event.version
  }
}

function compareAppendMarkers (a, b) {
  return markerSeq(a) - markerSeq(b) || String(a.appId || '').localeCompare(String(b.appId || '')) || String(a.key || '').localeCompare(String(b.key || ''))
}

function markerSeq (marker) {
  const seq = Number(marker && marker.seq)
  return Number.isFinite(seq) ? seq : 0
}

function openSwarmEvents (req, res, url, ip, swarm, state, ctx) {
  const releaseSlot = claimSseSlot(ip, state, ctx)
  if (!releaseSlot) return respond(res, 429, { error: 'too many open streams' })

  let unsubscribe = null
  const channelId = url.searchParams.get('channelId')
  try {
    unsubscribe = swarm.subscribe(channelId, (event) => {
      writeSseData(res, event)
    })
  } catch (err) {
    releaseSlot()
    throw err
  }

  writeSseStart(res)

  const ping = startSsePing(res, ctx)
  attachSseCleanup(req, res, ping, () => {
    try {
      unsubscribe()
    } catch {}
    releaseSlot()
  })
  return true
}

function claimSseSlot (ip, state, ctx) {
  const maxTotal = ctx.sseMaxTotal == null ? DEFAULT_SSE_MAX_TOTAL : ctx.sseMaxTotal
  const maxPerIp = ctx.sseMaxPerIp == null ? DEFAULT_SSE_MAX_PER_IP : ctx.sseMaxPerIp
  if (state.sseTotal >= maxTotal || (state.ssePerIp.get(ip) || 0) >= maxPerIp) return null
  state.sseTotal++
  state.ssePerIp.set(ip, (state.ssePerIp.get(ip) || 0) + 1)
  return () => {
    state.sseTotal = Math.max(0, state.sseTotal - 1)
    const next = (state.ssePerIp.get(ip) || 1) - 1
    if (next <= 0) state.ssePerIp.delete(ip)
    else state.ssePerIp.set(ip, next)
  }
}

function writeSseStart (res) {
  res.setHeader('Content-Type', 'text/event-stream')
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('Cache-Control', 'no-cache')
  res.setHeader('Connection', 'keep-alive')
  res.writeHead(200)
  res.write(': ok\n\n')
}

function writeSseData (res, event, name = null) {
  try {
    if (name) res.write('event: ' + name + '\n')
    if (event && Number.isFinite(Number(event.seq))) res.write('id: ' + event.seq + '\n')
    res.write('data: ' + JSON.stringify(event) + '\n\n')
  } catch {}
}

function startSsePing (res, ctx) {
  const ping = setInterval(() => {
    try {
      res.write(': ping\n\n')
    } catch {}
  }, ctx.ssePingMs || OUTBOXLOG_SSE_PING_MS)
  if (ping.unref) ping.unref()
  return ping
}

function attachSseCleanup (req, res, ping, onCleanup) {
  let closed = false
  const cleanup = () => {
    if (closed) return
    closed = true
    clearInterval(ping)
    try {
      onCleanup()
    } catch {}
  }
  req.on('close', cleanup)
  res.on('close', cleanup)
  return cleanup
}

function safeTokenEqual (a, b) {
  const left = Buffer.from(String(a || ''), 'utf8')
  const right = Buffer.from(String(b || ''), 'utf8')
  if (left.length !== right.length) return false
  return timingSafeEqual(left, right)
}
