export const API_RATE_LIMIT_WINDOW_MS = 60_000
export const API_RATE_LIMIT_MAX = 60

export const API_ENDPOINT_RATE_LIMITS = Object.freeze({
  '/api/wizard/payout': 10,
  '/api/wizard/complete': 10,
  '/api/wizard/relay-name': 30,
  '/api/wizard/accept-mode': 30,
  '/api/wizard/goto': 30,
  '/api/wizard/reset': 5,
  '/api/forks/proof': 20,
  '/api/v1/seed': 30,
  '/api/v1/custody/intent': 30
})

export function firstHeaderValue (value) {
  if (Array.isArray(value)) return value.length > 0 ? value[0] : ''
  if (typeof value === 'string') return value
  return ''
}

export function clientIpFromRequest (req, trustProxy = false) {
  const headers = req && req.headers ? req.headers : {}
  if (trustProxy) {
    const xff = firstHeaderValue(headers['x-forwarded-for'])
    if (xff) {
      const first = xff.split(',')[0].trim()
      if (first) return first
    }
    const realIP = firstHeaderValue(headers['x-real-ip']).trim()
    if (realIP) return realIP
  }
  return (req && req.socket && req.socket.remoteAddress) || ''
}

export function endpointRateLimitKey (ip, path) {
  return String(path || '') + '\x00' + String(ip || '')
}

export function checkFixedWindowRateLimit (limits, key, cap, now = Date.now(), windowMs = API_RATE_LIMIT_WINDOW_MS) {
  if (!limits || typeof limits.get !== 'function' || typeof limits.set !== 'function') {
    throw new TypeError('limits map required')
  }
  const max = Number(cap)
  if (!Number.isFinite(max) || max <= 0) return false

  let entry = limits.get(key)
  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + windowMs }
    limits.set(key, entry)
  }

  entry.count++
  return entry.count <= max
}

export function checkApiRateLimit (limits, ip, now = Date.now()) {
  return checkFixedWindowRateLimit(limits, ip, API_RATE_LIMIT_MAX, now, API_RATE_LIMIT_WINDOW_MS)
}

export function checkEndpointRateLimit (
  limits,
  ip,
  path,
  now = Date.now(),
  endpointLimits = API_ENDPOINT_RATE_LIMITS
) {
  const cap = endpointLimits[path]
  if (!cap) return true
  return checkFixedWindowRateLimit(limits, endpointRateLimitKey(ip, path), cap, now, API_RATE_LIMIT_WINDOW_MS)
}

export function sweepRateLimitMap (limits, now = Date.now()) {
  if (!limits || typeof limits.delete !== 'function') return 0
  let removed = 0
  for (const [key, entry] of limits) {
    if (now > entry.resetAt) {
      limits.delete(key)
      removed++
    }
  }
  return removed
}
