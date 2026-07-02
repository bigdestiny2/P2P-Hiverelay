import test from 'brittle'
import {
  resolveServiceManagementRoute,
  runServiceManagementAction
} from 'p2p-hiverelay/core/relay-node/api-service-management.js'

function makeRegistry () {
  return {
    services: new Map([
      ['identity', { status: 'running', running: true }],
      ['vrf', { status: 'running', running: true }],
      ['ai', { status: 'running', restartCount: 2 }]
    ]),
    unregistered: [],
    async unregister (name) {
      this.unregistered.push(name)
      this.services.delete(name)
      return true
    }
  }
}

test('api service management: route helper maps exact live service management endpoint', (t) => {
  t.alike(resolveServiceManagementRoute('POST', '/api/manage/services'), {
    kind: 'service-management'
  })

  t.is(resolveServiceManagementRoute('GET', '/api/manage/services'), null)
  t.is(resolveServiceManagementRoute('POST', '/api/manage/services/config'), null)
  t.is(resolveServiceManagementRoute('POST', '/api/manage/services/restart'), null)
})

test('api service management: validates service registry and action payload', async (t) => {
  t.alike(await runServiceManagementAction({ body: {}, registry: null, config: {} }), {
    ok: false,
    kind: 'unavailable',
    status: 503,
    payload: { error: 'Services not enabled' }
  })

  t.alike(await runServiceManagementAction({ body: {}, registry: makeRegistry(), config: {} }), {
    ok: false,
    kind: 'bad-request',
    status: 400,
    payload: { error: 'action and service required (action: disable|restart)' }
  })

  t.alike(await runServiceManagementAction({
    body: { action: 'unknown', service: 'identity' },
    registry: makeRegistry(),
    config: {}
  }), {
    ok: false,
    kind: 'bad-request',
    status: 400,
    payload: { error: 'Unknown action: unknown (use: disable, restart)' }
  })
})

test('api service management: RelayKernel lock rejects service actions before registry or persistence', async (t) => {
  let persisted = false
  const out = await runServiceManagementAction({
    body: { action: 'disable', service: 'ai' },
    registry: null,
    config: { productProfile: 'relaykernel', enableServices: true, plugins: ['ai'] },
    persistConfig: async () => { persisted = true },
    serviceConfigPayload: () => ({
      enabled: false,
      plugins: [],
      active: [],
      locked: true,
      lockReason: 'relaykernel-profile'
    })
  })

  t.is(out.ok, false)
  t.is(out.kind, 'locked')
  t.is(out.status, 409)
  t.is(out.payload.error, 'Services are locked off by the RelayKernel profile')
  t.is(out.payload.errorCode, 'relaykernel-services-locked')
  t.alike(out.payload.config, {
    enabled: false,
    plugins: [],
    active: [],
    locked: true,
    lockReason: 'relaykernel-profile'
  })
  t.is(persisted, false)
})

test('api service management: disable persists configured plugin removal before unregistering', async (t) => {
  const registry = makeRegistry()
  const config = { enableServices: true, plugins: ['identity', 'vrf'] }
  const calls = []

  const out = await runServiceManagementAction({
    body: { action: 'disable', service: 'identity' },
    registry,
    config,
    persistConfig: async () => { calls.push('persist:' + config.plugins.join(',')) },
    serviceConfigPayload: () => ({ plugins: config.plugins, active: Array.from(registry.services.keys()) })
  })

  t.is(out.ok, true)
  t.alike(calls, ['persist:vrf'])
  t.alike(registry.unregistered, ['identity'])
  t.alike(config.plugins, ['vrf'])
  t.is(config.enableServices, true)
  t.alike(out.payload, {
    ok: true,
    action: 'disabled',
    service: 'identity',
    persistent: true,
    config: { plugins: ['vrf'], active: ['vrf', 'ai'] }
  })
})

test('api service management: disable turns off service flag when last configured plugin is removed', async (t) => {
  const registry = makeRegistry()
  const config = { enableServices: true, plugins: ['identity'] }

  const out = await runServiceManagementAction({
    body: { action: 'disable', service: 'identity' },
    registry,
    config,
    persistConfig: async () => {}
  })

  t.is(out.ok, true)
  t.alike(config.plugins, [])
  t.is(config.enableServices, false)
})

test('api service management: disable rolls back config when persistence fails', async (t) => {
  const registry = makeRegistry()
  const config = { enableServices: true, plugins: ['identity', 'vrf'] }

  const out = await runServiceManagementAction({
    body: { action: 'disable', service: 'identity' },
    registry,
    config,
    persistConfig: async () => { throw new Error('readonly config') }
  })

  t.is(out.ok, false)
  t.is(out.kind, 'config-persist')
  t.alike(config.plugins, ['identity', 'vrf'])
  t.is(config.enableServices, true)
  t.alike(registry.unregistered, [])
  t.ok(registry.services.has('identity'))
})

test('api service management: disable rejects bundle dependencies before persistence', async (t) => {
  const registry = makeRegistry()
  const config = { enableServices: true, plugins: ['poker', 'vrf', 'arbitration', 'zk'] }
  let persisted = false

  const out = await runServiceManagementAction({
    body: { action: 'disable', service: 'vrf' },
    registry,
    config,
    persistConfig: async () => { persisted = true }
  })

  t.is(out.ok, false)
  t.is(out.status, 409)
  t.is(out.kind, 'bundle-required')
  t.ok(out.payload.error.includes("Service 'vrf' is required by bundle: poker"))
  t.alike(out.payload.bundles, ['poker'])
  t.is(persisted, false)
  t.alike(registry.unregistered, [])
})

test('api service management: disable handles unconfigured live services', async (t) => {
  const registry = makeRegistry()
  const config = { enableServices: true, plugins: ['identity'] }
  let persisted = false

  const out = await runServiceManagementAction({
    body: { action: 'disable', service: 'vrf' },
    registry,
    config,
    persistConfig: async () => { persisted = true }
  })

  t.is(out.ok, true)
  t.is(out.payload.persistent, false)
  t.is(persisted, false)
  t.alike(config.plugins, ['identity'])
  t.alike(registry.unregistered, ['vrf'])
})

test('api service management: restart delegates to registry restart with node context', async (t) => {
  const registry = makeRegistry()
  const node = { id: 'node' }
  const store = { id: 'store' }
  const config = { plugins: ['ai'] }
  registry.restart = async (service, ctx) => {
    t.is(service, 'ai')
    t.alike(ctx, { node, store, config })
    return { status: 'running', restartCount: 3 }
  }

  const out = await runServiceManagementAction({
    body: { action: 'restart', service: 'ai' },
    registry,
    config,
    node,
    store
  })

  t.alike(out, {
    ok: true,
    payload: {
      ok: true,
      action: 'restarted',
      service: 'ai',
      status: 'running',
      restartCount: 3
    }
  })
})

test('api service management: provider errors and missing services stay typed', async (t) => {
  const registry = makeRegistry()

  let out = await runServiceManagementAction({
    body: { action: 'disable', service: 'missing' },
    registry,
    config: {}
  })
  t.is(out.ok, false)
  t.is(out.kind, 'not-found')
  t.is(out.status, 404)

  registry.restart = async () => { throw new Error('restart failed') }
  out = await runServiceManagementAction({
    body: { action: 'restart', service: 'ai' },
    registry,
    config: {}
  })
  t.alike(out, {
    ok: false,
    kind: 'provider-error',
    status: 500,
    payload: { error: 'restart failed' }
  })
})
