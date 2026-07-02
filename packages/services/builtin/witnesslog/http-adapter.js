import { readJsonBody } from 'p2p-hiverelay/core/relay-node/api-body.js'
import { getPostJsonContentTypeProblem } from 'p2p-hiverelay/core/relay-node/api-request.js'
import { appendVaryHeader, writeJson } from 'p2p-hiverelay/core/relay-node/api-response.js'

export const WITNESSLOG_API_PREFIX = '/api/witness'
export const WITNESSLOG_MAX_JSON_BODY_BYTES = 128 * 1024
export const WITNESSLOG_SSE_PING_MS = 25000

const DEFAULT_RATE_LIMIT = { windowMs: 60000, max: 1200 }
const DEFAULT_SSE_MAX_PER_IP = 8
const DEFAULT_SSE_MAX_TOTAL = 2000
const MAX_RATE_BUCKETS = 50000

export function createWitnessLogHttpState () {
  return {
    buckets: new Map(),
    sseTotal: 0,
    ssePerIp: new Map()
  }
}

export function createWitnessLogHttpHandler (opts = {}) {
  const state = createWitnessLogHttpState()
  return (req, res) => handleWitnessLogRoute(req, res, { ...opts, state })
}

export async function handleWitnessLogRoute (req, res, ctx = {}) {
  let parsed
  try {
    parsed = new URL(req.url, 'http://localhost')
  } catch {
    return false
  }

  const path = parsed.pathname
  if (!isWitnessLogApiPath(path)) return false

  applyCors(req, res, ctx)
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    res.writeHead(204)
    res.end()
    return true
  }

  const state = ctx.state || createWitnessLogHttpState()
  const ip = clientIp(req, ctx)
  if (overLimit(ip, ctx.rateLimit || DEFAULT_RATE_LIMIT, state)) {
    return respond(res, 429, { error: 'rate limited' })
  }

  const app = ctx.witnessLogApp || ctx.witnesslogApp || ctx.app
  if (!app) return respond(res, 503, { error: 'witnesslog unavailable' })

  try {
    if (path === '/api/witness/status' && req.method === 'GET') {
      return respond(res, 200, { ready: true, service: 'witnesslog' })
    }

    if (path === '/api/witness/append' && req.method === 'POST') {
      if (typeof app.append !== 'function') return respond(res, 503, { error: 'witnesslog append unavailable' })
      const body = await readJson(req)
      if (!body.ok) return respondReadProblem(res, body)
      return respond(res, 200, app.append(body.body.record || body.body))
    }

    if ((path === '/api/witness' || path === '/api/witness/records') && req.method === 'GET') {
      if (typeof app.list !== 'function') return respond(res, 503, { error: 'witnesslog range unavailable' })
      return respond(res, 200, app.list(listOptsFrom(parsed)))
    }

    if (path === '/api/witness/events' && req.method === 'GET') {
      if (wantsEventStream(req, parsed)) {
        if (typeof app.subscribe !== 'function') return respond(res, 503, { error: 'witnesslog events unavailable' })
        return openWitnessEvents(req, res, parsed, ip, app, state, ctx)
      }
      if (typeof app.markers !== 'function') return respond(res, 503, { error: 'witnesslog events unavailable' })
      return respond(res, 200, app.markers(listOptsFrom(parsed)))
    }

    if (isMethodMismatch(path, req.method)) return respond(res, 405, { error: 'method not allowed' })
    return respond(res, 404, { error: 'not found' })
  } catch (err) {
    if (err && err.message && err.message.startsWith('WitnessLog:')) {
      return respond(res, 400, { error: err.message })
    }
    return respond(res, 500, { error: 'witnesslog route failed' })
  }
}

function isWitnessLogApiPath (path) {
  return path === '/api/witness' || path.startsWith('/api/witness/')
}

function isMethodMismatch (path, method) {
  const postOnly = new Set(['/api/witness/append'])
  const getOnly = new Set(['/api/witness', '/api/witness/records', '/api/witness/events', '/api/witness/status'])
  return (postOnly.has(path) && method !== 'POST') || (getOnly.has(path) && method !== 'GET')
}

function listOptsFrom (url) {
  return {
    target: url.searchParams.get('target') || url.searchParams.get('key') || url.searchParams.get('keyHash'),
    since: url.searchParams.get('since'),
    limit: url.searchParams.get('limit')
  }
}

function wantsEventStream (req, url) {
  const accept = req && req.headers ? String(req.headers.accept || req.headers.Accept || '') : ''
  return (
    url.searchParams.get('stream') === '1' ||
    url.searchParams.get('format') === 'sse' ||
    accept.toLowerCase().includes('text/event-stream')
  )
}

function openWitnessEvents (req, res, url, ip, app, state, ctx) {
  const releaseSlot = claimSseSlot(ip, state, ctx)
  if (!releaseSlot) return respond(res, 429, { error: 'too many open streams' })

  const opts = listOptsFrom(url)
  let unsubscribe = null
  try {
    unsubscribe = app.subscribe(opts, marker => {
      writeSseData(res, marker, 'witness')
    })
  } catch (err) {
    releaseSlot()
    throw err
  }

  writeSseStart(res)
  const replay = typeof app.markers === 'function' ? app.markers(opts).markers : []
  for (const marker of replay) writeSseData(res, marker, 'witness')

  const ping = startSsePing(res, ctx)
  attachSseCleanup(req, res, ping, () => {
    try {
      if (unsubscribe) unsubscribe()
    } catch {}
    releaseSlot()
  })
  return true
}

function applyCors (req, res, ctx) {
  const allowOrigin = ctx.allowOrigin || '*'
  const requestOrigin = req && req.headers ? req.headers.origin : null
  const origin = allowOrigin === '*'
    ? '*'
    : (Array.isArray(allowOrigin) && requestOrigin && allowOrigin.includes(requestOrigin) ? requestOrigin : allowOrigin[0] || '*')
  res.setHeader('Access-Control-Allow-Origin', origin)
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')
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
    return { ok: true, body: await readJsonBody(req, WITNESSLOG_MAX_JSON_BODY_BYTES) }
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
    if (event && event.id) res.write('id: ' + event.id + '\n')
    res.write('data: ' + JSON.stringify(event) + '\n\n')
  } catch {}
}

function startSsePing (res, ctx) {
  const ping = setInterval(() => {
    try {
      res.write(': ping\n\n')
    } catch {}
  }, ctx.ssePingMs || WITNESSLOG_SSE_PING_MS)
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
