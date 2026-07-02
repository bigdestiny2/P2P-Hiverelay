export const LOCAL_ONLY_DISPATCH_ROUTES = new Set([
  'identity.sign',
  'identity.verify'
])

export const DISPATCH_AUTH_MESSAGE = 'Unauthorized — API key required for /api/v1/dispatch'

export function resolveDispatchRoute (method, path) {
  if (method === 'POST' && path === '/api/v1/dispatch') {
    return { kind: 'dispatch', authMessage: DISPATCH_AUTH_MESSAGE }
  }
  return null
}

function errorPayload (message) {
  return { error: message }
}

function dispatchRole ({ router, route, isLocalRequest }) {
  if (isLocalRequest) return 'local'
  const routeAccess = router && router.getRouteAccess
    ? router.getRouteAccess(route)
    : null
  return routeAccess === 'relay-admin' ? 'relay-admin' : 'authenticated-user'
}

export async function runDispatchAction ({
  body = {},
  router,
  isLocalRequest = false
}) {
  body = body || {}
  if (!router) {
    return { ok: false, status: 503, payload: errorPayload('Router not enabled') }
  }
  if (!body.route || typeof body.route !== 'string') {
    return { ok: false, status: 400, payload: errorPayload('route required (e.g. "ai.infer", "zk.commit")') }
  }
  if (body.params !== undefined && (body.params === null || typeof body.params !== 'object' || Array.isArray(body.params))) {
    return { ok: false, status: 400, payload: errorPayload('params must be an object') }
  }

  if (LOCAL_ONLY_DISPATCH_ROUTES.has(body.route) && !isLocalRequest) {
    return { ok: false, status: 403, payload: errorPayload(`ACCESS_DENIED: ${body.route} is local-only`) }
  }

  try {
    const result = await router.dispatch(body.route, body.params || {}, {
      transport: 'http',
      caller: 'remote',
      role: dispatchRole({ router, route: body.route, isLocalRequest }),
      authenticated: true
    })
    return { ok: true, payload: { ok: true, result } }
  } catch (err) {
    return { ok: false, status: 400, payload: errorPayload(err.message) }
  }
}
