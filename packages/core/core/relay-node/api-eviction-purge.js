import { isValidHexKey } from '../constants.js'
import { formatErr } from '../error-prefixes.js'

export const MAX_PURGE_APP_KEYS = 50
export const EVICTION_PURGE_AUTH_MESSAGE = 'Unauthorized — API key required for /api/eviction/purge'

const EVICTION_PURGE_ROUTES = Object.freeze({
  'POST /api/eviction/purge': Object.freeze({
    kind: 'eviction-purge',
    authMessage: EVICTION_PURGE_AUTH_MESSAGE
  })
})

export function resolveEvictionPurgeRoute (method, path) {
  const route = EVICTION_PURGE_ROUTES[`${method} ${path}`]
  if (!route) return null
  return { ...route }
}

function badRequest (message) {
  return { error: formatErr('BAD_REQUEST', message) }
}

function normalizeFreedBytes (value) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0
    ? value
    : 0
}

export async function runEvictionPurgeAction ({ body, node }) {
  if (!body || !Array.isArray(body.appKeys) || body.appKeys.length === 0) {
    return { ok: false, status: 400, payload: badRequest('appKeys (non-empty array) required') }
  }
  if (body.appKeys.length > MAX_PURGE_APP_KEYS) {
    return { ok: false, status: 400, payload: badRequest('max 50 appKeys per request') }
  }

  const results = []
  for (const appKey of body.appKeys) {
    if (!isValidHexKey(appKey, 64)) {
      results.push({ appKey, ok: false, error: 'invalid appKey' })
      continue
    }
    try {
      if (!node || typeof node.manualPurge !== 'function') {
        throw new Error('manual purge unavailable')
      }
      const out = await node.manualPurge(appKey)
      results.push({
        appKey,
        ok: true,
        bytes: normalizeFreedBytes(out && out.bytes)
      })
    } catch (err) {
      results.push({
        appKey,
        ok: false,
        error: err && (err.code || err.message) ? (err.code || err.message) : String(err || 'unknown error')
      })
    }
  }

  const purged = results.filter(r => r.ok)
  return {
    ok: true,
    status: 200,
    payload: {
      ok: true,
      purged: purged.length,
      freedBytes: purged.reduce((total, r) => total + normalizeFreedBytes(r.bytes), 0),
      results
    }
  }
}
