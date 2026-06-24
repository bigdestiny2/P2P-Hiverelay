function safeCounter (value) {
  const n = Number(value)
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : 0
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
