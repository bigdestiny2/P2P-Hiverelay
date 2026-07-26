export const HYPER_GATEWAY_ROUTE_PREFIX = '/v1/hyper/'
export const INDEX_PROXY_ROOM_ROUTE = '/api/index/room'
export const INDEX_PROXY_ROUTE_PREFIX = '/index/'
export const OUTBOXLOG_HTTP_EXACT_ROUTES = Object.freeze([
  '/api/token',
  '/api/bridge/status',
  '/api/directory',
  '/api/identity',
  // Operator takedown admin surface — claimed as exactly these three routes so
  // outboxlog does NOT reserve the whole /api/admin/* namespace. Any future
  // non-outboxlog /api/admin/<x> route stays free to mount, and a stray
  // /api/admin/<other> falls through to the server's generic not-found rather
  // than being swallowed here. Routed into the outboxlog dispatch so
  // ctx.adminAuth can gate them; the adapter's isAdminPath matches the same
  // three and serves them as 404 when no admin auth is configured
  // (safe-by-default).
  '/api/admin/takedown',
  '/api/admin/restore',
  '/api/admin/takedowns'
])
export const OUTBOXLOG_HTTP_ROUTE_PREFIXES = Object.freeze([
  '/api/identity/',
  '/api/sync/',
  '/api/swarm/'
])
export const WITNESSLOG_HTTP_ROUTE = '/api/witness'
export const WITNESSLOG_HTTP_ROUTE_PREFIX = '/api/witness/'
export const REPAIRTICKET_HTTP_ROUTE = '/api/repair'
export const REPAIRTICKET_HTTP_ROUTE_PREFIX = '/api/repair/'
export const SHARD_HTTP_ROUTE = '/api/v1/shard'
export const SHARD_HTTP_ROUTE_PREFIX = '/api/v1/shard/'
export const POKER_HTTP_ROUTE = '/api/poker'
export const POKER_HTTP_ROUTE_PREFIX = '/api/poker/'
export const POKER_TABLE_CREATE_ROUTE = '/api/poker/tables'
export const POKER_TABLE_CREATE_AUTH_MESSAGE = 'Unauthorized — API key required to create a poker table'
export const MANAGEMENT_API_ROUTE_PREFIX = '/api/manage/'

export function isHyperGatewayRoute (path) {
  return typeof path === 'string' && path.startsWith(HYPER_GATEWAY_ROUTE_PREFIX)
}

export function isIndexProxyRoute (method, path) {
  return method === 'GET' && typeof path === 'string' &&
    (path === INDEX_PROXY_ROOM_ROUTE || path.startsWith(INDEX_PROXY_ROUTE_PREFIX))
}

export function isPokerHttpRoute (path) {
  return typeof path === 'string' &&
    (path === POKER_HTTP_ROUTE || path.startsWith(POKER_HTTP_ROUTE_PREFIX))
}

export function isOutboxLogHttpRoute (path) {
  return typeof path === 'string' &&
    (OUTBOXLOG_HTTP_EXACT_ROUTES.includes(path) ||
      OUTBOXLOG_HTTP_ROUTE_PREFIXES.some(prefix => path.startsWith(prefix)))
}

// The outboxlog READ surface. These routes only ever serve signed rows the
// client re-verifies (Ed25519 + key-binding), so throttling them protects no
// integrity property — and a cold browser boot legitimately bursts ~10+ reads,
// which is how the coarse per-IP budget locked returning visitors out to an
// empty feed. /api/sync/heads is POST (appIds ride in the body) but is a read.
// By default, writes (/api/token, create/join/append, swarm join/send/leave)
// and the admin surface also stay under the global budget. An explicitly
// configured OutboxLog HTTP envelope replaces that coarse budget for the
// public data plane only; admin routes retain both their global and auth gates.
export const OUTBOXLOG_HTTP_READ_GET_ROUTES = Object.freeze([
  '/api/bridge/status',
  '/api/directory',
  '/api/sync/get',
  '/api/sync/list',
  '/api/sync/range',
  '/api/sync/count',
  '/api/sync/status',
  '/api/sync/events',
  '/api/swarm/events'
])

export function isOutboxLogHttpReadRequest (method, path) {
  if (typeof path !== 'string') return false
  if (method === 'GET') return OUTBOXLOG_HTTP_READ_GET_ROUTES.includes(path)
  if (method === 'POST') return path === '/api/sync/heads'
  return false
}

export function isWitnessLogHttpRoute (path) {
  return typeof path === 'string' &&
    (path === WITNESSLOG_HTTP_ROUTE || path.startsWith(WITNESSLOG_HTTP_ROUTE_PREFIX))
}

export function isRepairTicketHttpRoute (path) {
  return typeof path === 'string' &&
    (path === REPAIRTICKET_HTTP_ROUTE || path.startsWith(REPAIRTICKET_HTTP_ROUTE_PREFIX))
}

export function isShardHttpRoute (path) {
  return typeof path === 'string' &&
    (path === SHARD_HTTP_ROUTE || path.startsWith(SHARD_HTTP_ROUTE_PREFIX))
}

export function resolvePokerHttpRoutePolicy (method, path) {
  if (method === 'POST' && path === POKER_TABLE_CREATE_ROUTE) {
    return {
      kind: 'poker-table-create',
      authRequired: true,
      authMessage: POKER_TABLE_CREATE_AUTH_MESSAGE
    }
  }
  return null
}

export function isManagementApiRoute (path) {
  return typeof path === 'string' && path.startsWith(MANAGEMENT_API_ROUTE_PREFIX)
}
