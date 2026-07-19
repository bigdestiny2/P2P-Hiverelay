import { GATEWAY_DENYLIST_VERSION } from '../gateway-denylist.js'

export const MAX_DENYLIST_RECORDS = 10_000

const GATEWAY_DENYLIST_READ_ROUTES = Object.freeze({
  'GET /api/gateway/denylist': Object.freeze({ kind: 'gateway-denylist-list' })
})

export function resolveGatewayDenylistReadRoute (method, path) {
  const route = GATEWAY_DENYLIST_READ_ROUTES[`${method} ${path}`]
  if (!route) return null
  return { ...route }
}

/**
 * Serve the local signed gateway-denylist entries for federation gossip.
 * Entries are self-authenticating signed envelopes naming HASHED drive keys
 * only, so this endpoint carries no plaintext keys and needs no caller
 * trust — receiving relays independently verify each signature and gate on
 * their own trusted-admin allow-list before enforcing anything.
 */
export function buildGatewayDenylistRoutePayload ({
  route,
  denylist = null,
  maxRecords = MAX_DENYLIST_RECORDS
} = {}) {
  if (!route || route.kind !== 'gateway-denylist-list') {
    return {
      ok: false,
      status: 404,
      payload: { error: 'unknown gateway denylist read route' }
    }
  }

  const recordLimit = Number.isSafeInteger(maxRecords) && maxRecords >= 0
    ? Math.min(maxRecords, MAX_DENYLIST_RECORDS)
    : MAX_DENYLIST_RECORDS
  const entries = denylist && typeof denylist.list === 'function' ? denylist.list() : []
  const selected = entries.slice(0, recordLimit)
  return {
    ok: true,
    payload: {
      schemaVersion: GATEWAY_DENYLIST_VERSION,
      entries: selected,
      count: selected.length,
      total: entries.length,
      truncated: entries.length > selected.length
    },
    headers: { 'Cache-Control': 'public, max-age=30' }
  }
}
