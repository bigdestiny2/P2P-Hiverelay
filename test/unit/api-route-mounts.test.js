import test from 'brittle'
import {
  HYPER_GATEWAY_ROUTE_PREFIX,
  INDEX_PROXY_ROOM_ROUTE,
  INDEX_PROXY_ROUTE_PREFIX,
  MANAGEMENT_API_ROUTE_PREFIX,
  OUTBOXLOG_HTTP_EXACT_ROUTES,
  OUTBOXLOG_HTTP_ROUTE_PREFIXES,
  POKER_HTTP_ROUTE,
  POKER_HTTP_ROUTE_PREFIX,
  POKER_TABLE_CREATE_AUTH_MESSAGE,
  POKER_TABLE_CREATE_ROUTE,
  isHyperGatewayRoute,
  isIndexProxyRoute,
  isManagementApiRoute,
  isOutboxLogHttpRoute,
  isPokerHttpRoute,
  resolvePokerHttpRoutePolicy
} from '../../packages/core/core/relay-node/api-route-mounts.js'

test('api route mounts: hyper gateway predicate stays bound to RelayKernel route prefix', (t) => {
  t.is(HYPER_GATEWAY_ROUTE_PREFIX, '/v1/hyper/')
  t.is(isHyperGatewayRoute('/v1/hyper/drive-key/index.html'), true)
  t.is(isHyperGatewayRoute('/v1/hyper'), false)
  t.is(isHyperGatewayRoute('/v1/hyperion/drive-key'), false)
  t.is(isHyperGatewayRoute(null), false)
})

test('api route mounts: index sidecar proxy remains read-only', (t) => {
  t.is(INDEX_PROXY_ROOM_ROUTE, '/api/index/room')
  t.is(INDEX_PROXY_ROUTE_PREFIX, '/index/')
  t.is(isIndexProxyRoute('GET', '/api/index/room'), true)
  t.is(isIndexProxyRoute('GET', '/index/rooms/demo'), true)
  t.is(isIndexProxyRoute('POST', '/api/index/room'), false)
  t.is(isIndexProxyRoute('GET', '/index'), false)
  t.is(isIndexProxyRoute('GET', '/api/index/room/extra'), false)
})

test('api route mounts: poker substrate keeps exact root plus subtree', (t) => {
  t.is(POKER_HTTP_ROUTE, '/api/poker')
  t.is(POKER_HTTP_ROUTE_PREFIX, '/api/poker/')
  t.is(isPokerHttpRoute('/api/poker'), true)
  t.is(isPokerHttpRoute('/api/poker/tables'), true)
  t.is(isPokerHttpRoute('/api/poker/usage'), true)
  t.is(isPokerHttpRoute('/api/pokerish'), false)
  t.is(isPokerHttpRoute('/api/poker-tables'), false)
})

test('api route mounts: outboxlog bridge owns exact Peerit /api routes only', (t) => {
  t.alike(OUTBOXLOG_HTTP_EXACT_ROUTES, ['/api/token', '/api/bridge/status', '/api/directory', '/api/identity', '/api/admin/takedown', '/api/admin/restore', '/api/admin/takedowns'])
  t.alike(OUTBOXLOG_HTTP_ROUTE_PREFIXES, ['/api/identity/', '/api/sync/', '/api/swarm/'])
  t.is(isOutboxLogHttpRoute('/api/token'), true)
  t.is(isOutboxLogHttpRoute('/api/bridge/status'), true)
  t.is(isOutboxLogHttpRoute('/api/directory'), true)
  t.is(isOutboxLogHttpRoute('/api/identity'), true)
  t.is(isOutboxLogHttpRoute('/api/identity/sign'), true)
  t.is(isOutboxLogHttpRoute('/api/sync/create'), true)
  t.is(isOutboxLogHttpRoute('/api/swarm/events'), true)
  // Takedown admin surface routes into the outboxlog dispatch (adapter gates it)
  // as EXACTLY these three routes — outboxlog does not reserve the whole
  // /api/admin/* namespace.
  t.is(isOutboxLogHttpRoute('/api/admin/takedown'), true)
  t.is(isOutboxLogHttpRoute('/api/admin/restore'), true)
  t.is(isOutboxLogHttpRoute('/api/admin/takedowns'), true)
  t.is(isOutboxLogHttpRoute('/api/tokens'), false)
  t.is(isOutboxLogHttpRoute('/api/identityish'), false)
  t.is(isOutboxLogHttpRoute('/api/identity-sign'), false)
  t.is(isOutboxLogHttpRoute('/api/synchronize'), false)
  t.is(isOutboxLogHttpRoute('/api/admin'), false)
  // Namespace exclusivity: a future non-outboxlog /api/admin/<x> route must NOT
  // be swallowed by the outboxlog dispatch (it falls through to generic 404).
  t.is(isOutboxLogHttpRoute('/api/admin/other'), false)
  t.is(isOutboxLogHttpRoute('/api/admin/takedown/extra'), false)
  t.is(isOutboxLogHttpRoute('/api/poker/tables'), false)
})

test('api route mounts: poker create-table mutation is the only auth policy override', (t) => {
  t.is(POKER_TABLE_CREATE_ROUTE, '/api/poker/tables')
  t.is(POKER_TABLE_CREATE_AUTH_MESSAGE, 'Unauthorized — API key required to create a poker table')
  t.alike(resolvePokerHttpRoutePolicy('POST', '/api/poker/tables'), {
    kind: 'poker-table-create',
    authRequired: true,
    authMessage: POKER_TABLE_CREATE_AUTH_MESSAGE
  })
  t.is(resolvePokerHttpRoutePolicy('GET', '/api/poker/tables'), null)
  t.is(resolvePokerHttpRoutePolicy('POST', '/api/poker/tables/'), null)
  t.is(resolvePokerHttpRoutePolicy('POST', '/api/poker/aa/move'), null)
  t.is(resolvePokerHttpRoutePolicy('POST', '/api/pokerish/tables'), null)
})

test('api route mounts: management API predicate covers control-plane subtree only', (t) => {
  t.is(MANAGEMENT_API_ROUTE_PREFIX, '/api/manage/')
  t.is(isManagementApiRoute('/api/manage/config'), true)
  t.is(isManagementApiRoute('/api/manage/services/config'), true)
  t.is(isManagementApiRoute('/api/manage'), false)
  t.is(isManagementApiRoute('/api/management/config'), false)
  t.is(isManagementApiRoute(undefined), false)
})
