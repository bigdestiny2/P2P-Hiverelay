import test from 'brittle'
import { runDispatchAction } from '../../packages/core/core/relay-node/api-dispatch.js'

function makeRouter (opts = {}) {
  const calls = []
  return {
    calls,
    getRouteAccess: opts.getRouteAccess || (() => null),
    async dispatch (route, params, ctx) {
      calls.push({ route, params, ctx })
      if (opts.error) throw opts.error
      return opts.result || { route, params, role: ctx.role }
    }
  }
}

test('api dispatch: readiness and route validation happen before dispatch', async (t) => {
  let out = await runDispatchAction({
    body: {},
    router: null
  })
  t.is(out.status, 503)
  t.alike(out.payload, { error: 'Router not enabled' })

  const router = makeRouter()
  out = await runDispatchAction({
    body: {},
    router
  })
  t.is(out.status, 400)
  t.alike(out.payload, { error: 'route required (e.g. "ai.infer", "zk.commit")' })
  t.is(router.calls.length, 0, 'missing route does not reach router')
})

test('api dispatch: remote callers cannot use local-only identity routes', async (t) => {
  const router = makeRouter()

  const out = await runDispatchAction({
    body: { route: 'identity.sign', params: { message: 'secret' } },
    router,
    isLocalRequest: false
  })

  t.is(out.status, 403)
  t.alike(out.payload, { error: 'ACCESS_DENIED: identity.sign is local-only' })
  t.is(router.calls.length, 0, 'local-only denial happens before dispatch')
})

test('api dispatch: rejects non-object params before dispatch', async (t) => {
  const router = makeRouter()

  for (const params of [null, [], 'value', 1, true]) {
    const out = await runDispatchAction({
      body: { route: 'storage.get', params },
      router,
      isLocalRequest: false
    })
    t.is(out.status, 400)
    t.alike(out.payload, { error: 'params must be an object' })
  }

  t.is(router.calls.length, 0, 'malformed params do not reach router')
})

test('api dispatch: role mapping preserves HTTP remote caller contract', async (t) => {
  const router = makeRouter({
    getRouteAccess (route) {
      return route === 'secure.admin' ? 'relay-admin' : 'authenticated-user'
    }
  })

  let out = await runDispatchAction({
    body: { route: 'secure.admin', params: { value: 1 } },
    router,
    isLocalRequest: false
  })
  t.alike(out.payload, { ok: true, result: { route: 'secure.admin', params: { value: 1 }, role: 'relay-admin' } })

  out = await runDispatchAction({
    body: { route: 'storage.get' },
    router,
    isLocalRequest: false
  })
  t.is(out.payload.result.role, 'authenticated-user')

  out = await runDispatchAction({
    body: { route: 'identity.verify', params: { signed: true } },
    router,
    isLocalRequest: true
  })
  t.is(out.payload.result.role, 'local')

  t.alike(router.calls.map(call => call.ctx), [
    { transport: 'http', caller: 'remote', role: 'relay-admin', authenticated: true },
    { transport: 'http', caller: 'remote', role: 'authenticated-user', authenticated: true },
    { transport: 'http', caller: 'remote', role: 'local', authenticated: true }
  ])
  t.alike(router.calls[1].params, {}, 'missing params default to empty object')
})

test('api dispatch: router errors stay mapped as bad requests', async (t) => {
  const router = makeRouter({ error: new Error('ROUTE_NOT_FOUND') })

  const out = await runDispatchAction({
    body: { route: 'missing.route' },
    router,
    isLocalRequest: false
  })

  t.is(out.status, 400)
  t.alike(out.payload, { error: 'ROUTE_NOT_FOUND' })
  t.is(router.calls.length, 1)
})
