import { timingSafeEqual } from 'crypto'

export const LOOPBACK_HOSTS = Object.freeze(new Set([
  'localhost',
  'localhost.',
  '127.0.0.1',
  '::1',
  '::ffff:127.0.0.1'
]))

export function constantTimeStringEqual (actual, expected) {
  if (typeof actual !== 'string' || typeof expected !== 'string') return false
  const actualBuf = Buffer.from(actual)
  const expectedBuf = Buffer.from(expected)
  if (actualBuf.length !== expectedBuf.length) return false
  return timingSafeEqual(actualBuf, expectedBuf)
}

export function normalizeHostLike (value) {
  let host = String(value || '').trim().toLowerCase()
  if (!host) return ''
  if (host.startsWith('[')) {
    const end = host.indexOf(']')
    if (end !== -1) return host.slice(1, end)
  }
  const colonCount = (host.match(/:/g) || []).length
  if (colonCount === 1) host = host.slice(0, host.lastIndexOf(':'))
  return host
}

export function isLoopbackHost (value) {
  const normalized = normalizeHostLike(value)
  return LOOPBACK_HOSTS.has(normalized)
}

export function hasLoopbackHostHeader (req) {
  const host = req?.headers?.host
  if (!host) return true
  return isLoopbackHost(host)
}

export function hasLoopbackOrigin (req) {
  const origin = req?.headers?.origin
  if (!origin) return true
  let parsed
  try {
    parsed = new URL(origin)
  } catch (_) {
    return false
  }
  return isLoopbackHost(parsed.hostname)
}

export function isLoopbackLocalRequest (req, trustProxy = false) {
  if (trustProxy) return false
  const ip = req?.socket ? req.socket.remoteAddress || '' : ''
  return isLoopbackHost(ip) &&
    hasLoopbackHostHeader(req) &&
    hasLoopbackOrigin(req)
}
