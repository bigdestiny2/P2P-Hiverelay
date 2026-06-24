export function isPublicPokerCorsRoute (path) {
  return typeof path === 'string' &&
    path.startsWith('/api/poker/') &&
    path !== '/api/poker/usage'
}

export function getAllowedOrigin (corsOrigins, requestOrigin) {
  if (corsOrigins === '*') return '*'

  if (typeof requestOrigin !== 'string' || requestOrigin.length === 0) return null
  const allowed = Array.isArray(corsOrigins) ? corsOrigins : [corsOrigins]
  return allowed.includes(requestOrigin) ? requestOrigin : null
}

export function buildCorsDecision (corsOrigins, requestOrigin, path) {
  const publicPokerRoute = isPublicPokerCorsRoute(path)
  const allowedOrigin = getAllowedOrigin(corsOrigins, requestOrigin)
  return {
    allowedOrigin: publicPokerRoute ? '*' : allowedOrigin,
    publicPokerRoute,
    varyOrigin: Boolean(requestOrigin && !publicPokerRoute && corsOrigins !== '*'),
    preflightDenied: Boolean(requestOrigin && !allowedOrigin && !publicPokerRoute)
  }
}
