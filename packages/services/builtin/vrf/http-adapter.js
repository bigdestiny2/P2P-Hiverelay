import { readJsonBody } from 'p2p-hiverelay/core/relay-node/api-body.js'
import { getPostJsonContentTypeProblem } from 'p2p-hiverelay/core/relay-node/api-request.js'
import { appendVaryHeader, writeJson } from 'p2p-hiverelay/core/relay-node/api-response.js'

export const VRF_API_PREFIX = '/api/v1/vrf'
export const VRF_MAX_JSON_BODY_BYTES = 64 * 1024

const DEFAULT_RATE_LIMIT = { windowMs: 60000, max: 600 }
const MAX_RATE_BUCKETS = 10000

/**
 * VRF HTTP route handler — mirrors the witnesslog/shard-store HTTP adapter pattern.
 * Exposes the VRF service's beacon and sortition operations over HTTP so they're
 * reachable from browsers, not just Protomux.
 *
 * Routes:
 *   GET  /api/v1/vrf/info            — suite params + beacon status
 *   GET  /api/v1/vrf/beacon-info     — beacon genesis/round/retention
 *   GET  /api/v1/vrf/beacon-latest   — most recent beacon round
 *   GET  /api/v1/vrf/beacon-round/:n — specific retained round
 *   GET  /api/v1/vrf/beacon-range    — recent retained rounds
 *   GET  /api/v1/vrf/beacon-verify   — server-side chain verification
 *   POST /api/v1/vrf/select          — verifiable committee sortition
 *   POST /api/v1/vrf/select-verify   — recheck a committee
 *   POST /api/v1/vrf/verify          — verify (pubkey, alpha, pi)
 */
export function createVrfHttpState () {
  return { buckets: new Map() }
}

export function createVrfHttpHandler (opts = {}) {
  const state = createVrfHttpState()
  return (req, res) => handleVrfRoute(req, res, { ...opts, state })
}

export async function handleVrfRoute (req, res, ctx = {}) {
  let parsed
  try {
    parsed = new URL(req.url, 'http://localhost')
  } catch {
    return false
  }

  const path = parsed.pathname
  if (!isVrfApiPath(path)) return false

  applyCors(req, res, ctx)
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    res.writeHead(204)
    res.end()
    return true
  }

  const state = ctx.state || createVrfHttpState()
  const ip = clientIp(req, ctx)
  if (overLimit(ip, ctx.rateLimit || DEFAULT_RATE_LIMIT, state)) {
    return respond(res, 429, { error: 'rate limited' })
  }

  const vrf = ctx.vrfService || ctx.vrf
  if (!vrf) return respond(res, 503, { error: 'vrf unavailable' })

  try {
    // GET routes
    if (path === '/api/v1/vrf/info' && req.method === 'GET') {
      if (typeof vrf.info !== 'function') return respond(res, 503, { error: 'vrf info unavailable' })
      return respond(res, 200, vrf.info())
    }

    if (path === '/api/v1/vrf/beacon-info' && req.method === 'GET') {
      if (typeof vrf.beaconInfo !== 'function') return respond(res, 503, { error: 'vrf beacon-info unavailable' })
      return respond(res, 200, vrf.beaconInfo())
    }

    if (path === '/api/v1/vrf/beacon-latest' && req.method === 'GET') {
      if (typeof vrf.beaconLatest !== 'function') return respond(res, 503, { error: 'vrf beacon-latest unavailable' })
      return respond(res, 200, vrf.beaconLatest())
    }

    // beacon-round/:n
    const roundMatch = path.match(/^\/api\/v1\/vrf\/beacon-round\/(\d+)$/)
    if (roundMatch && req.method === 'GET') {
      if (typeof vrf.beaconRound !== 'function') return respond(res, 503, { error: 'vrf beacon-round unavailable' })
      const round = parseInt(roundMatch[1], 10)
      return respond(res, 200, vrf.beaconRound(round))
    }

    if (path === '/api/v1/vrf/beacon-range' && req.method === 'GET') {
      if (typeof vrf.beaconRange !== 'function') return respond(res, 503, { error: 'vrf beacon-range unavailable' })
      const limit = parseInt(parsed.searchParams.get('limit') || '10', 10)
      return respond(res, 200, vrf.beaconRange(limit))
    }

    if (path === '/api/v1/vrf/beacon-verify' && req.method === 'GET') {
      if (typeof vrf.beaconVerify !== 'function') return respond(res, 503, { error: 'vrf beacon-verify unavailable' })
      return respond(res, 200, vrf.beaconVerify())
    }

    // POST routes
    if (path === '/api/v1/vrf/select' && req.method === 'POST') {
      if (typeof vrf.select !== 'function') return respond(res, 503, { error: 'vrf select unavailable' })
      const body = await readJson(req)
      if (!body.ok) return respondReadProblem(res, body)
      const { alpha, candidates, weights, count } = body.body
      return respond(res, 200, vrf.select(alpha, candidates, { weights, count }))
    }

    if (path === '/api/v1/vrf/select-verify' && req.method === 'POST') {
      if (typeof vrf.selectVerify !== 'function') return respond(res, 503, { error: 'vrf select-verify unavailable' })
      const body = await readJson(req)
      if (!body.ok) return respondReadProblem(res, body)
      const { alpha, pi, candidates, committee, weights, count } = body.body
      return respond(res, 200, vrf.selectVerify(alpha, pi, candidates, committee, { weights, count }))
    }

    if (path === '/api/v1/vrf/verify' && req.method === 'POST') {
      if (typeof vrf.verify !== 'function') return respond(res, 503, { error: 'vrf verify unavailable' })
      const body = await readJson(req)
      if (!body.ok) return respondReadProblem(res, body)
      const { alpha, pi, pubkey } = body.body
      return respond(res, 200, vrf.verify(pubkey || vrf.publicKey, alpha, pi))
    }

    if (path === '/api/v1/vrf/status' && req.method === 'GET') {
      return respond(res, 200, { ready: true, service: 'vrf' })
    }

    if (isMethodMismatch(path, req.method)) return respond(res, 405, { error: 'method not allowed' })
    return respond(res, 404, { error: 'not found' })
  } catch (err) {
    if (err && err.message && err.message.startsWith('VRF:')) {
      return respond(res, 400, { error: err.message })
    }
    return respond(res, 500, { error: 'vrf route failed' })
  }
}

function isVrfApiPath (path) {
  return path === '/api/v1/vrf' || path.startsWith('/api/v1/vrf/')
}

function isMethodMismatch (path, method) {
  const postPaths = new Set(['/api/v1/vrf/select', '/api/v1/vrf/select-verify', '/api/v1/vrf/verify'])
  const getPaths = new Set([
    '/api/v1/vrf/info', '/api/v1/vrf/beacon-info', '/api/v1/vrf/beacon-latest',
    '/api/v1/vrf/beacon-range', '/api/v1/vrf/beacon-verify', '/api/v1/vrf/status'
  ])
  if (path.match(/^\/api\/v1\/vrf\/beacon-round\/\d+$/)) return method !== 'GET'
  return (postPaths.has(path) && method !== 'POST') || (getPaths.has(path) && method !== 'GET')
}

// ─── shared helpers (same shape as witnesslog adapter) ─────────────

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
    return { ok: false, status: 400, error: contentTypeProblem.error, close: contentTypeProblem.close }
  }
  try {
    return { ok: true, body: await readJsonBody(req, VRF_MAX_JSON_BODY_BYTES) }
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
