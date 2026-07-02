function safeCounter (value) {
  const n = Number(value)
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : 0
}

const GATEWAY_STATS_ROUTES = Object.freeze({
  'GET /api/gateway': Object.freeze({ kind: 'gateway-stats' })
})

export function resolveGatewayStatsRoute (method, path) {
  const route = GATEWAY_STATS_ROUTES[`${method} ${path}`]
  if (!route) return null
  return { ...route }
}

export function buildGatewayStatsRoutePayload ({
  route,
  gateway = null
} = {}) {
  if (!route || route.kind !== 'gateway-stats') {
    return {
      ok: false,
      status: 404,
      payload: { error: 'unknown gateway stats route' }
    }
  }
  return buildGatewayStatsPayload({ gateway })
}

export function sanitizeGatewayStats (stats = null) {
  return {
    cachedDrives: safeCounter(stats && stats.cachedDrives),
    totalRequests: safeCounter(stats && stats.totalRequests),
    totalBytesServed: safeCounter(stats && stats.totalBytesServed)
  }
}

export function buildGatewayStatsPayload ({ gateway = null } = {}) {
  const raw = gateway && typeof gateway.getStats === 'function'
    ? gateway.getStats()
    : null
  return {
    ok: true,
    payload: sanitizeGatewayStats(raw)
  }
}
