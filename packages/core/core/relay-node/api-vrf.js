/**
 * VRF HTTP route module — maps /api/v1/vrf/* onto the running VRF service.
 * Mirrors the notify route module (resolve + run against a ServiceProvider)
 * while exposing the same surface as the service-owned HTTP adapter
 * (beacon-info, beacon-latest, beacon-round, select, …).
 *
 * The VRF service uses hyphenated RPC method names ('beacon-info', etc.).
 * This module translates HTTP paths into those capability calls.
 */

export const VRF_HTTP_ROUTE = '/api/v1/vrf'
export const VRF_HTTP_ROUTE_PREFIX = '/api/v1/vrf/'

const GET_ROUTES = Object.freeze({
  '/api/v1/vrf/info': Object.freeze({ kind: 'vrf-call', method: 'info' }),
  '/api/v1/vrf/beacon-info': Object.freeze({ kind: 'vrf-call', method: 'beacon-info' }),
  '/api/v1/vrf/beacon-latest': Object.freeze({ kind: 'vrf-call', method: 'beacon-latest' }),
  '/api/v1/vrf/beacon-range': Object.freeze({ kind: 'vrf-call', method: 'beacon-range' }),
  '/api/v1/vrf/beacon-verify': Object.freeze({ kind: 'vrf-call', method: 'beacon-verify' }),
  '/api/v1/vrf/status': Object.freeze({ kind: 'vrf-status' })
})

const POST_ROUTES = Object.freeze({
  '/api/v1/vrf/select': Object.freeze({ kind: 'vrf-call', method: 'select' }),
  '/api/v1/vrf/select-verify': Object.freeze({ kind: 'vrf-call', method: 'select-verify' }),
  '/api/v1/vrf/verify': Object.freeze({ kind: 'vrf-call', method: 'verify' }),
  '/api/v1/vrf/prove': Object.freeze({ kind: 'vrf-call', method: 'prove' }),
  '/api/v1/vrf/shuffle': Object.freeze({ kind: 'vrf-call', method: 'shuffle' }),
  '/api/v1/vrf/shuffle-verify': Object.freeze({ kind: 'vrf-call', method: 'shuffle-verify' })
})

const BEACON_ROUND_RE = /^\/api\/v1\/vrf\/beacon-round\/(\d+)$/

export function isVrfHttpRoute (path) {
  return typeof path === 'string' &&
    (path === VRF_HTTP_ROUTE || path.startsWith(VRF_HTTP_ROUTE_PREFIX))
}

/**
 * Resolve method+path to a VRF route descriptor, or null if not a VRF path.
 * Returns { kind, method?, round?, status? } for known routes;
 * for unknown subpaths under /api/v1/vrf returns { kind: 'not-found' };
 * for non-VRF paths returns null.
 */
export function resolveVrfRoute (method, path) {
  if (!isVrfHttpRoute(path)) return null

  if (method === 'GET') {
    const fixed = GET_ROUTES[path]
    if (fixed) return { ...fixed }
    const roundMatch = path.match(BEACON_ROUND_RE)
    if (roundMatch) {
      return { kind: 'vrf-call', method: 'beacon-round', round: parseInt(roundMatch[1], 10) }
    }
    // Known path prefix but wrong method or unknown subpath
    if (POST_ROUTES[path]) return { kind: 'method-not-allowed' }
    return { kind: 'not-found' }
  }

  if (method === 'POST') {
    const fixed = POST_ROUTES[path]
    if (fixed) return { ...fixed }
    if (GET_ROUTES[path] || BEACON_ROUND_RE.test(path)) return { kind: 'method-not-allowed' }
    return { kind: 'not-found' }
  }

  if (method === 'OPTIONS') return { kind: 'options' }
  return { kind: 'method-not-allowed' }
}

/**
 * Drive a resolved VRF route against a service provider result.
 * @param {{ route, providerResult, body?, query? }} args
 * @returns {Promise<{ status: number, payload: object }>}
 */
export async function runVrfRouteAction ({
  route,
  providerResult,
  body = {},
  query = {}
} = {}) {
  if (!route) return { status: 404, payload: { error: 'unknown vrf route' } }

  if (route.kind === 'options') {
    return { status: 204, payload: null, headers: { 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS' } }
  }
  if (route.kind === 'method-not-allowed') {
    return { status: 405, payload: { error: 'method not allowed' } }
  }
  if (route.kind === 'not-found') {
    return { status: 404, payload: { error: 'not found' } }
  }

  if (!providerResult || !providerResult.ok) {
    return {
      status: providerResult && providerResult.status ? providerResult.status : 503,
      payload: {
        error: providerResult && providerResult.error
          ? providerResult.error
          : 'VRF service is not enabled on this relay'
      }
    }
  }

  const provider = providerResult.provider

  if (route.kind === 'vrf-status') {
    return { status: 200, payload: { ready: true, service: 'vrf' } }
  }

  if (route.kind === 'vrf-call') {
    const fn = provider[route.method]
    if (typeof fn !== 'function') {
      return { status: 503, payload: { error: 'VRF service does not expose method: ' + route.method } }
    }
    try {
      const params = buildCallParams(route, body, query)
      const payload = await fn.call(provider, params)
      return { status: 200, payload }
    } catch (err) {
      return vrfErrorResponse(err)
    }
  }

  return { status: 404, payload: { error: 'unknown vrf route' } }
}

function buildCallParams (route, body, query) {
  // beacon-round path param wins over body
  if (route.method === 'beacon-round') {
    return { round: route.round != null ? route.round : Number(body.round) }
  }
  if (route.method === 'beacon-range') {
    const limit = query.limit != null ? Number(query.limit) : (body.count != null ? Number(body.count) : undefined)
    return limit != null && !Number.isNaN(limit) ? { count: limit } : {}
  }
  if (route.method === 'beacon-verify') {
    const count = query.count != null ? Number(query.count) : (body.count != null ? Number(body.count) : undefined)
    return count != null && !Number.isNaN(count) ? { count } : {}
  }
  // GET capability calls with no params
  if (route.method === 'info' || route.method === 'beacon-info' || route.method === 'beacon-latest' || route.method === 'pubkey') {
    return {}
  }
  // POST bodies pass through (select, verify, prove, shuffle, …)
  return body && typeof body === 'object' ? body : {}
}

function vrfErrorResponse (err) {
  const msg = err && err.message ? String(err.message) : 'vrf route failed'
  // Service uses INVALID_PARAM / NOT_FOUND / BEACON_DISABLED / SERVICE_UNAVAILABLE prefixes
  if (msg.startsWith('INVALID_PARAM') || msg.startsWith('VRF:')) {
    return { status: 400, payload: { error: msg } }
  }
  if (msg.startsWith('NOT_FOUND')) {
    return { status: 404, payload: { error: msg } }
  }
  if (msg.startsWith('BEACON_DISABLED') || msg.startsWith('SERVICE_UNAVAILABLE')) {
    return { status: 503, payload: { error: msg } }
  }
  return { status: 500, payload: { error: 'vrf route failed' } }
}
