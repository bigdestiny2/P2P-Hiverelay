/**
 * Peerit-compatible HTTP/SSE adapter for OutboxLog.
 *
 * Exposes the token-gated `/api/*` surface that Peerit's browser bridge speaks:
 * `/api/token`, `/api/bridge/status`, `/api/sync/*`, `/api/directory`, and
 * `/api/swarm/*`. The adapter is standalone so HiveRelay can mount it later
 * without moving sync, auth, or SSE mechanics into the large relay dispatcher.
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { readJsonBody } from 'p2p-hiverelay/core/relay-node/api-body.js'
import {
  normalizeOutboxLogHttpRateLimit
} from 'p2p-hiverelay/core/relay-node/api-outboxlog-http-adapter.js'
import { getPostJsonContentTypeProblem } from 'p2p-hiverelay/core/relay-node/api-request.js'
import { appendVaryHeader, writeJson } from 'p2p-hiverelay/core/relay-node/api-response.js'

export const OUTBOXLOG_API_PREFIX = '/api'
export const OUTBOXLOG_MAX_JSON_BODY_BYTES = 1024 * 1024
export const OUTBOXLOG_SSE_PING_MS = 25000

const DEFAULT_SSE_MAX_PER_IP = 8
const DEFAULT_SSE_MAX_TOTAL = 2000
const DEFAULT_SYNC_EVENT_APP_ID_LIMIT = 128
const DEFAULT_SYNC_EVENT_APP_ID_LENGTH = 128
const DEFAULT_SYNC_EVENT_REPLAY_LIMIT = 1000
export const OUTBOXLOG_HTTP_MAX_RATE_BUCKETS = 50000
export const OUTBOXLOG_TOKEN_TTL_MS = 15 * 60 * 1000

export function createOutboxLogHttpHandler (opts = {}) {
  const state = createOutboxLogHttpState()
  const rateLimit = normalizeOutboxLogHttpRateLimit(opts.rateLimit)
  const effectivePublicWriteRateLimit = opts.effectivePublicWriteRateLimit === undefined
    ? rateLimit
    : normalizeOutboxLogHttpRateLimit(opts.effectivePublicWriteRateLimit)
  const rateLimitSource = opts.rateLimitSource || (opts.rateLimit === undefined ? 'outboxlog-default' : 'operator')
  return (req, res) => handleOutboxLogRoute(req, res, {
    ...opts,
    effectivePublicWriteRateLimit,
    rateLimit,
    rateLimitSource,
    state
  })
}

export function createOutboxLogHttpState () {
  return {
    buckets: new Map(),
    sseTotal: 0,
    ssePerIp: new Map()
  }
}

export function createOutboxLogTokenAuth ({ tokenBytes = 16, ttlMs = OUTBOXLOG_TOKEN_TTL_MS, secret = randomBytes(32), now = () => Date.now() } = {}) {
  const nonceBytes = Number.isSafeInteger(tokenBytes) && tokenBytes >= 8 && tokenBytes <= 64 ? tokenBytes : 16
  const lifetime = Number.isSafeInteger(ttlMs) && ttlMs > 0 ? ttlMs : OUTBOXLOG_TOKEN_TTL_MS
  const key = Buffer.isBuffer(secret) || secret instanceof Uint8Array ? Buffer.from(secret) : Buffer.from(String(secret), 'utf8')
  if (key.byteLength < 16) throw new Error('OutboxLog: token auth secret must be at least 16 bytes')

  return {
    ttlMs: lifetime,
    issue () {
      const expiresAt = Math.floor(now() + lifetime)
      const payload = 'v1.' + expiresAt.toString(36) + '.' + randomBytes(nonceBytes).toString('hex')
      return payload + '.' + tokenMac(key, payload)
    },

    verify (token) {
      const parsed = parseStatelessToken(token)
      if (!parsed || parsed.expiresAt < now()) return false
      const expected = tokenMac(key, parsed.payload)
      return safeTokenEqual(parsed.mac, expected)
    },

    expiresAt (token) {
      const parsed = parseStatelessToken(token)
      return parsed ? parsed.expiresAt : null
    },

    _size () {
      return 0
    }
  }
}

// Admin auth for the takedown surface. Unlike the browser token (which is
// issued on demand and short-lived), admin tokens are operator-provisioned
// secrets supplied up front. verify() is constant-time. An empty token never
// verifies, so an unauthenticated caller is always rejected.
export function createOutboxLogAdminAuth ({ tokens = [] } = {}) {
  const known = new Set()
  for (const token of Array.isArray(tokens) ? tokens : [tokens]) {
    if (typeof token === 'string' && token) known.add(token)
  }
  return {
    verify (token) {
      if (typeof token !== 'string' || !token) return false
      let ok = false
      // Compare against every known token (no early return) so timing does not
      // leak how many/which tokens matched.
      for (const candidate of known) {
        if (safeTokenEqual(token, candidate)) ok = true
      }
      return ok
    },
    _size () {
      return known.size
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
  const rateLimit = normalizeOutboxLogHttpRateLimit(ctx.rateLimit)
  const rate = consumeRateLimit(ip, rateLimit, state)
  if (!rate.allowed) {
    res.setHeader('Retry-After', String(rate.retryAfterSeconds))
    return respond(res, 429, { error: 'rate limited' })
  }

  const app = ctx.outboxLogApp || ctx.outboxlogApp || ctx.app || ctx.core
  const sync = ctx.sync || (app && app.sync)
  const swarm = ctx.swarm || (app && app.swarm)

  // Operator admin surface (DO-NOT-SERVE takedown). Gated by a SEPARATE admin
  // auth — never the browser sync token — so an ordinary client that holds a
  // /api/token can't take content down. No admin auth configured => 404 (the
  // surface is simply not enabled), unauthenticated => 401.
  if (isAdminPath(path)) {
    return await handleAdminRoute(req, res, parsed, ctx, sync)
  }

  const auth = ctx.auth || ctx.outboxLogAuth
  if (path === '/api/token') {
    if (req.method !== 'POST') return respond(res, 405, { error: 'method not allowed' })
    if (!auth || typeof auth.issue !== 'function') return respond(res, 503, { error: 'outboxlog auth unavailable' })
    const token = auth.issue()
    return respond(res, 200, {
      token,
      expiresAt: typeof auth.expiresAt === 'function' ? auth.expiresAt(token) : null,
      ttlMs: Number.isSafeInteger(auth.ttlMs) ? auth.ttlMs : null
    })
  }

  if (!auth || typeof auth.verify !== 'function' || !auth.verify(tokenFrom(req, parsed))) {
    return respond(res, 401, { error: 'missing or invalid token' })
  }

  try {
    if (path === '/api/bridge/status') {
      if (req.method !== 'GET') return respond(res, 405, { error: 'method not allowed' })
      const capabilities = sync && typeof sync.capabilities === 'function'
        ? await sync.capabilities()
        : unavailableCommitCapabilities()
      return respond(res, 200, {
        ready: capabilities.ready === true,
        service: 'outboxlog',
        serviceVersion: capabilities.serviceVersion,
        atomicCommit: capabilities.atomicCommit,
        legacyWrites: capabilities.legacyWrites,
        httpRateLimit: publicRateLimit(rateLimit, ctx)
      })
    }

    if (path.startsWith('/api/identity')) {
      return respond(res, 410, { error: 'identity is browser-local; this relay never signs' })
    }

    if (!sync) return respond(res, 503, { error: 'outboxlog sync unavailable' })

    if (path === '/api/sync/capabilities' && req.method === 'GET') {
      return respond(res, 200, typeof sync.capabilities === 'function' ? await sync.capabilities() : unavailableCommitCapabilities())
    }

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

    if (path === '/api/sync/commit' && req.method === 'POST') {
      if (typeof sync.commit !== 'function') return respond(res, 503, { error: 'atomic commit unavailable' })
      const body = await readJson(req)
      if (!body.ok) return respondReadProblem(res, body)
      return respond(res, 200, await sync.commit(body.body.appId, body.body.commit))
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
    if (err && Number.isInteger(err.status) && err.status >= 400 && (err.status < 500 || err.status === 503)) {
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
    path.startsWith('/api/swarm/') ||
    // Exactly the three takedown routes — not the whole /api/admin/* namespace,
    // so a stray /api/admin/<other> is not owned by outboxlog even when this
    // adapter is mounted standalone.
    isAdminPath(path)
  )
}

function isAdminPath (path) {
  return path === '/api/admin/takedown' || path === '/api/admin/restore' || path === '/api/admin/takedowns' || path === '/api/admin/sweep'
}

// The operator admin surface. Authenticated with a dedicated admin auth that is
// distinct from the browser sync token, and passed via the X-Pear-Admin-Token
// header (or ?adminToken=). Takedown drops a record by its opaque (appId,key)
// id — content is never read — for operator liability parity.
async function handleAdminRoute (req, res, parsed, ctx, sync) {
  const adminAuth = ctx.adminAuth || ctx.outboxLogAdminAuth || null
  if (!adminAuth || typeof adminAuth.verify !== 'function') {
    return respond(res, 404, { error: 'not found' })
  }
  if (!adminAuth.verify(adminTokenFrom(req, parsed))) {
    return respond(res, 401, { error: 'missing or invalid admin token' })
  }
  if (!sync) return respond(res, 503, { error: 'outboxlog sync unavailable' })

  const path = parsed.pathname
  try {
    if (path === '/api/admin/takedowns') {
      if (req.method !== 'GET') return respond(res, 405, { error: 'method not allowed' })
      if (typeof sync.takedowns !== 'function') return respond(res, 503, { error: 'outboxlog takedown unavailable' })
      return respond(res, 200, sync.takedowns())
    }

    // Operator-triggered ghost sweep (break-glass: reclaim empty group slots
    // NOW instead of waiting for the periodic tick). Body is optional JSON;
    // { "ttlMs": 0 } sweeps every currently-empty group regardless of age.
    if (path === '/api/admin/sweep') {
      if (req.method !== 'POST') return respond(res, 405, { error: 'method not allowed' })
      if (typeof sync.sweepGhosts !== 'function') return respond(res, 503, { error: 'outboxlog sweep unavailable' })
      const body = await readJson(req)
      if (!body.ok) return respondReadProblem(res, body)
      const rawTtl = body.body && body.body.ttlMs
      const ttlMs = Number.isFinite(Number(rawTtl)) && Number(rawTtl) >= 0 ? Number(rawTtl) : undefined
      return respond(res, 200, sync.sweepGhosts(ttlMs === undefined ? {} : { ttlMs }))
    }

    const drop = path === '/api/admin/takedown'
    if (req.method !== 'POST') return respond(res, 405, { error: 'method not allowed' })
    const method = drop ? sync.takedown : sync.restore
    if (typeof method !== 'function') return respond(res, 503, { error: 'outboxlog takedown unavailable' })
    const body = await readJson(req)
    if (!body.ok) return respondReadProblem(res, body)
    return respond(res, 200, await method.call(sync, body.body.appId, body.body.key))
  } catch (err) {
    if (err && Number.isInteger(err.status) && err.status >= 400 && err.status < 500) {
      return respond(res, err.status, { error: err.message || 'outboxlog admin request failed' })
    }
    return respond(res, 500, { error: 'outboxlog admin route failed' })
  }
}

function isMethodMismatch (path, method) {
  const postOnly = new Set([
    '/api/sync/create',
    '/api/sync/join',
    '/api/sync/append',
    '/api/sync/commit',
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
    '/api/sync/capabilities',
    '/api/directory',
    '/api/swarm/events'
  ])
  return (postOnly.has(path) && method !== 'POST') || (getOnly.has(path) && method !== 'GET')
}

function unavailableCommitCapabilities () {
  return {
    schema: 1,
    ready: false,
    serviceVersion: null,
    atomicCommit: {
      schema: 1,
      method: 'POST',
      route: '/api/sync/commit',
      enabled: false,
      durable: false,
      ready: false,
      cas: true,
      idempotent: false,
      idempotency: null
    },
    legacyWrites: {
      create: false,
      append: false
    }
  }
}

function applyCors (req, res, ctx) {
  const allowOrigin = ctx.allowOrigin || '*'
  const requestOrigin = req && req.headers ? req.headers.origin : null
  const origin = allowOrigin === '*'
    ? '*'
    : (Array.isArray(allowOrigin) && requestOrigin && allowOrigin.includes(requestOrigin) ? requestOrigin : allowOrigin[0] || '*')
  res.setHeader('Access-Control-Allow-Origin', origin)
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Pear-Token, X-Pear-Admin-Token')
  res.setHeader('Access-Control-Expose-Headers', 'Retry-After')
  res.setHeader('Access-Control-Max-Age', '86400')
  appendVaryHeader(res, 'Origin')
}

function clientIp (req, ctx) {
  if (ctx.trustProxy && req.headers && req.headers['x-forwarded-for']) {
    return String(req.headers['x-forwarded-for']).split(',')[0].trim() || 'unknown'
  }
  return (req.socket && req.socket.remoteAddress) || 'unknown'
}

function consumeRateLimit (ip, rateLimit, state) {
  if (!rateLimit.enabled) return { allowed: true }
  const now = Date.now()
  let bucket = state.buckets.get(ip)
  if (!bucket || now - bucket.start >= rateLimit.windowMs) {
    // Keep attacker-controlled IP cardinality from growing memory without
    // bound. Deleting and reinserting expired buckets keeps Map insertion
    // order aligned with window age, so the first entry is the oldest window
    // and can be evicted in O(1) when the fixed cap is full.
    if (bucket) state.buckets.delete(ip)
    while (state.buckets.size >= OUTBOXLOG_HTTP_MAX_RATE_BUCKETS) {
      state.buckets.delete(state.buckets.keys().next().value)
    }
    bucket = { start: now, count: 0 }
    state.buckets.set(ip, bucket)
  }
  // Check-before-increment: a rejected request must not consume window budget,
  // otherwise a client retrying through a 429 can never recover within the
  // window even when its accepted-rate would fit (self-lockout).
  if (bucket.count >= rateLimit.max) {
    return {
      allowed: false,
      retryAfterSeconds: Math.max(1, Math.ceil((bucket.start + rateLimit.windowMs - now) / 1000))
    }
  }
  bucket.count++
  return { allowed: true }
}

function publicRateLimit (rateLimit, ctx) {
  const effective = ctx.effectivePublicWriteRateLimit
    ? normalizeOutboxLogHttpRateLimit(ctx.effectivePublicWriteRateLimit)
    : rateLimit
  return {
    scope: 'public-writes',
    source: ctx.rateLimitSource || 'outboxlog-default',
    enabled: effective.enabled,
    windowMs: effective.windowMs,
    max: effective.max,
    outboxLogEnvelope: {
      enabled: rateLimit.enabled,
      windowMs: rateLimit.windowMs,
      max: rateLimit.max
    }
  }
}

function tokenFrom (req, url) {
  const headers = req.headers || {}
  return headers['x-pear-token'] || headers['X-Pear-Token'] || url.searchParams.get('token') || ''
}

function adminTokenFrom (req, url) {
  const headers = req.headers || {}
  return headers['x-pear-admin-token'] || headers['X-Pear-Admin-Token'] || url.searchParams.get('adminToken') || ''
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
  // Honor backpressure. res.write() returns false when the socket's send
  // buffer is full; if we keep writing we grow the process heap without bound
  // for a slow reader. While paused we DROP live events rather than buffer
  // them — the client re-syncs on reconnect (markers are replayed) or via p2p,
  // so a dropped push is recoverable: "push wakes the app; p2p sync gives the
  // app truth". The paused flag clears on the next 'drain'.
  if (res._ssePaused || res.writableEnded || res.destroyed) return false
  let ok = true
  try {
    if (name) res.write('event: ' + name + '\n')
    if (event && Number.isFinite(Number(event.seq))) res.write('id: ' + event.seq + '\n')
    ok = res.write('data: ' + JSON.stringify(event) + '\n\n')
  } catch {
    return false
  }
  if (ok === false) {
    res._ssePaused = true
    if (typeof res.once === 'function') res.once('drain', () => { res._ssePaused = false })
  }
  return ok
}

function startSsePing (res, ctx) {
  const ping = setInterval(() => {
    if (res._ssePaused || res.writableEnded || res.destroyed) return
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

function tokenMac (key, payload) {
  return createHmac('sha256', key).update(payload, 'utf8').digest('hex')
}

function parseStatelessToken (token) {
  if (typeof token !== 'string' || token.length < 32 || token.length > 512) return null
  const parts = token.split('.')
  if (parts.length !== 4 || parts[0] !== 'v1' || !/^[0-9a-z]+$/.test(parts[1]) || !/^[0-9a-f]{16,128}$/.test(parts[2]) || !/^[0-9a-f]{64}$/.test(parts[3])) return null
  const expiresAt = Number.parseInt(parts[1], 36)
  if (!Number.isSafeInteger(expiresAt) || expiresAt < 0) return null
  return { payload: parts.slice(0, 3).join('.'), expiresAt, mac: parts[3] }
}

function safeTokenEqual (a, b) {
  const left = Buffer.from(String(a || ''), 'utf8')
  const right = Buffer.from(String(b || ''), 'utf8')
  if (left.length !== right.length) return false
  return timingSafeEqual(left, right)
}
