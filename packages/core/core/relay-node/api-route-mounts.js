export const HYPER_GATEWAY_ROUTE_PREFIX = '/v1/hyper/'
export const INDEX_PROXY_ROOM_ROUTE = '/api/index/room'
export const INDEX_PROXY_ROUTE_PREFIX = '/index/'
export const OUTBOXLOG_HTTP_EXACT_ROUTES = Object.freeze([
  '/api/token',
  '/api/bridge/status',
  '/api/directory',
  '/api/identity'
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

export function isWitnessLogHttpRoute (path) {
  return typeof path === 'string' &&
    (path === WITNESSLOG_HTTP_ROUTE || path.startsWith(WITNESSLOG_HTTP_ROUTE_PREFIX))
}

export function isRepairTicketHttpRoute (path) {
  return typeof path === 'string' &&
    (path === REPAIRTICKET_HTTP_ROUTE || path.startsWith(REPAIRTICKET_HTTP_ROUTE_PREFIX))
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
