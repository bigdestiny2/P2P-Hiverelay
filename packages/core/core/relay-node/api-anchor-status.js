import { isValidHexKey } from '../constants.js'

const ANCHOR_PROOF_PREFIX = '/api/anchors/'
const ANCHOR_PROOF_SUFFIX = '/proof'

const ANCHOR_STATUS_ROUTES = Object.freeze({
  'GET /api/anchors': Object.freeze({ kind: 'anchor-status' })
})

function count (value) {
  const n = Number(value)
  if (!Number.isFinite(n) || n < 0) return 0
  return Math.min(Math.floor(n), Number.MAX_SAFE_INTEGER)
}

function timestampOrNull (value) {
  const n = Number(value)
  if (!Number.isFinite(n) || n < 0) return null
  return Math.min(Math.floor(n), Number.MAX_SAFE_INTEGER)
}

export function isDetailedAnchorStatusQuery (value) {
  return value === '1' || value === 'true'
}

export function resolveAnchorStatusRoute (method, path) {
  const route = ANCHOR_STATUS_ROUTES[`${method} ${path}`]
  if (!route) return null
  return { ...route }
}

export function isAnchorProofRoute (path) {
  return typeof path === 'string' && path.startsWith(ANCHOR_PROOF_PREFIX) && path.endsWith(ANCHOR_PROOF_SUFFIX)
}

export function resolveAnchorProofRoute (method, path) {
  if (method !== 'GET') return null
  if (isAnchorProofRoute(path)) return { kind: 'anchor-proof' }
  return null
}

export function anchorProofAppKeyFromPath (path) {
  return isAnchorProofRoute(path)
    ? path.slice(ANCHOR_PROOF_PREFIX.length, -ANCHOR_PROOF_SUFFIX.length)
    : ''
}

export async function buildAnchorProofRoutePayload ({
  node,
  path
} = {}) {
  return buildAnchorProofPayload({
    node,
    appKey: anchorProofAppKeyFromPath(path)
  })
}

export function buildAnchorStatusRouteContext (url) {
  const params = url && url.searchParams
  const detailed = isDetailedAnchorStatusQuery(params && typeof params.get === 'function' ? params.get('detailed') : null)
  return {
    detailed,
    requiresAuth: detailed
  }
}

export function buildAnchorStatusRoutePayload ({
  route,
  context = null,
  url,
  appRegistry,
  lastCheckedAt = null
} = {}) {
  if (!route || route.kind !== 'anchor-status') {
    return {
      ok: false,
      status: 404,
      payload: { error: 'unknown anchor status route' }
    }
  }

  const routeContext = context || buildAnchorStatusRouteContext(url)
  return buildAnchorStatusPayload({
    appRegistry,
    detailed: routeContext.detailed,
    lastCheckedAt
  })
}

export async function buildAnchorProofPayload ({
  node,
  appKey
} = {}) {
  if (!isValidHexKey(appKey)) {
    return {
      ok: false,
      status: 400,
      payload: { error: 'invalid appKey' }
    }
  }

  if (!node || typeof node.createAnchorProof !== 'function') {
    return {
      ok: false,
      status: 503,
      payload: { error: 'proof generation failed' }
    }
  }

  try {
    return {
      ok: true,
      status: 200,
      payload: await node.createAnchorProof(appKey)
    }
  } catch (err) {
    const message = err && err.message ? err.message : String(err || 'proof generation failed')
    const status = /invalid appKey/.test(message) ? 400 : 503
    return {
      ok: false,
      status,
      payload: { error: message || 'proof generation failed' }
    }
  }
}

export function buildAnchorStatusPayload ({
  appRegistry,
  detailed = false,
  lastCheckedAt = null
} = {}) {
  if (!appRegistry || typeof appRegistry.anchorStats !== 'function') {
    return {
      ok: false,
      status: 503,
      payload: { error: 'anchor stats unavailable' }
    }
  }

  const stats = appRegistry.anchorStats()
  const entries = detailed
    ? anchorStatusEntries(appRegistry)
    : null

  return {
    ok: true,
    status: 200,
    payload: {
      total: count(stats && stats.total),
      anchored: count(stats && stats.anchored),
      unanchored: count(stats && stats.unanchored),
      neverChecked: count(stats && stats.neverChecked),
      lastCheckedAt: timestampOrNull(lastCheckedAt),
      entries
    }
  }
}

export function anchorStatusEntries (appRegistry) {
  if (!appRegistry || typeof appRegistry.catalog !== 'function') return []
  return appRegistry.catalog().map(anchorStatusEntry)
}

export function anchorStatusEntry (entry = {}) {
  return {
    appKey: entry.appKey,
    type: entry.type,
    anchored: entry.anchored,
    anchoredAt: entry.anchoredAt,
    anchoredLength: entry.anchoredLength,
    custodyIntentId: entry.custodyIntentId || null,
    blind: entry.blind === true,
    storageClass: entry.storageClass || null,
    availabilityClass: entry.availabilityClass || null
  }
}
