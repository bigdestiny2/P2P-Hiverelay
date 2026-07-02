import test from 'brittle'
import {
  BUILTIN_SERVICE_PLUGINS,
  SERVICE_PLUGIN_BUNDLES,
  activeServiceNames,
  bundleParentsForService,
  configuredBuiltinServicePlugins,
  configuredServicePlugins,
  normalizeManageServicePlugins,
  resolveServiceConfigUpdateRoute,
  runServiceConfigUpdateAction,
  serviceConfigPayload
} from 'p2p-hiverelay/core/relay-node/api-service-config.js'

test('api service config helpers: route helper maps exact service config update', (t) => {
  t.alike(resolveServiceConfigUpdateRoute('POST', '/api/manage/services/config'), {
    kind: 'service-config-update'
  })

  t.is(resolveServiceConfigUpdateRoute('GET', '/api/manage/services/config'), null)
  t.is(resolveServiceConfigUpdateRoute('POST', '/api/manage/services'), null)
  t.is(resolveServiceConfigUpdateRoute('POST', '/api/manage/services/config/extra'), null)
})

test('api service config helpers: normalize builtins and expand bundles', (t) => {
  const normalized = normalizeManageServicePlugins([' Poker ', 'AI', 'vrf', 'outboxlog', 'notify', ''])

  t.alike(normalized, {
    ok: true,
    plugins: ['poker', 'vrf', 'arbitration', 'zk', 'ai', 'outboxlog', 'notify']
  })

  t.alike(normalizeManageServicePlugins(null), { ok: true, plugins: [] })
  t.alike(normalizeManageServicePlugins(undefined), { ok: true, plugins: [] })
  t.alike(normalizeManageServicePlugins('ai'), { ok: false, error: 'plugins must be an array' })
  t.alike(normalizeManageServicePlugins(['ai', 1]), { ok: false, error: 'plugins must contain service names only' })
})

test('api service config helpers: unknown plugins return available services and bundles', (t) => {
  const rejected = normalizeManageServicePlugins(['../../evil.js'])

  t.is(rejected.ok, false)
  t.is(rejected.error, 'unknown service plugin: ../../evil.js')
  t.alike(rejected.available, BUILTIN_SERVICE_PLUGINS)
  t.alike(rejected.bundles, SERVICE_PLUGIN_BUNDLES)
})

test('api service config helpers: payload reports configured builtins and active providers', (t) => {
  const registry = {
    services: new Map([
      ['identity', { status: 'running' }],
      [123, { status: 'ignored' }],
      ['ai', { status: 'running' }]
    ])
  }
  const config = {
    enableServices: true,
    plugins: ['identity', 'unknown', 'identity', 7, 'poker']
  }

  t.alike(activeServiceNames(registry), ['identity', 'ai'])
  t.alike(configuredBuiltinServicePlugins(config), ['identity', 'poker'])
  t.alike(serviceConfigPayload(config, registry), {
    enabled: true,
    available: BUILTIN_SERVICE_PLUGINS,
    plugins: ['identity', 'poker'],
    active: ['identity', 'ai'],
    bundles: SERVICE_PLUGIN_BUNDLES,
    locked: false,
    lockReason: null
  })

  t.is(serviceConfigPayload({ enableServices: false, plugins: ['ai'] }, registry).enabled, false)
  t.is(serviceConfigPayload({ enableServices: true, plugins: [] }, registry).enabled, false)
  t.is(serviceConfigPayload(null, registry).enabled, false)
  t.alike(activeServiceNames({ services: null }), [])
})

test('api service config helpers: bundle parents identify configured bundle dependencies', (t) => {
  const configured = configuredServicePlugins({
    plugins: ['poker', 'vrf', false, 'arbitration', 'zk']
  })

  t.alike(configured, ['poker', 'vrf', 'arbitration', 'zk'])
  t.alike(bundleParentsForService('vrf', configured), ['poker'])
  t.alike(bundleParentsForService('arbitration', configured), ['poker'])
  t.alike(bundleParentsForService('poker', configured), [])
  t.alike(bundleParentsForService('ai', configured), [])
  t.alike(bundleParentsForService('vrf', null), [])
})

test('api service config helpers: update action persists normalized plugins', async (t) => {
  const config = { enableServices: false, plugins: [] }
  const registry = { services: new Map([['ai', {}]]) }
  const persistCalls = []

  const out = await runServiceConfigUpdateAction({
    body: { enabled: true, plugins: ['poker', 'ai'] },
    config,
    registry,
    persistConfig: async () => { persistCalls.push(config.plugins.join(',')) }
  })

  t.is(out.ok, true)
  t.alike(persistCalls, ['poker,vrf,arbitration,zk,ai'])
  t.alike(config.plugins, ['poker', 'vrf', 'arbitration', 'zk', 'ai'])
  t.is(config.enableServices, true)
  t.is(out.payload.restartRequired, true)
  t.alike(out.payload.config.plugins, ['poker', 'vrf', 'arbitration', 'zk', 'ai'])
  t.alike(out.payload.config.active, ['ai'])
})

test('api service config helpers: update action rejects locked profiles before mutation', async (t) => {
  const config = { productProfile: 'relaykernel', enableServices: false, plugins: [] }
  let persisted = false

  const out = await runServiceConfigUpdateAction({
    body: { enabled: true, plugins: ['ai'] },
    config,
    persistConfig: async () => { persisted = true }
  })

  t.is(out.ok, false)
  t.is(out.status, 409)
  t.is(out.payload.errorCode, 'relaykernel-services-locked')
  t.is(out.payload.config.locked, true)
  t.alike(config.plugins, [])
  t.is(config.enableServices, false)
  t.is(persisted, false)
})

test('api service config helpers: update action rolls back on persistence failure', async (t) => {
  const config = { enableServices: true, plugins: ['identity', 'vrf'] }

  const out = await runServiceConfigUpdateAction({
    body: { enabled: true, plugins: ['ai'] },
    config,
    persistConfig: async () => { throw new Error('readonly') }
  })

  t.is(out.ok, false)
  t.is(out.kind, 'config-persist')
  t.alike(config.plugins, ['identity', 'vrf'])
  t.is(config.enableServices, true)
})
