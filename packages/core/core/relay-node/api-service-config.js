export const BUILTIN_SERVICE_PLUGINS = Object.freeze([
  'identity',
  'storage',
  'schema',
  'vrf',
  'ai',
  'zk',
  'sla',
  'arbitration',
  'poker',
  'outboxlog',
  'witnesslog',
  'repairticket',
  'notify',
  'shard-store'
])

export const BUILTIN_SERVICE_PLUGIN_SET = new Set(BUILTIN_SERVICE_PLUGINS)

export const SERVICE_PLUGIN_BUNDLES = Object.freeze({
  poker: Object.freeze(['poker', 'vrf', 'arbitration', 'zk'])
})
const SERVICE_CONFIG_UPDATE_ROUTES = Object.freeze({
  'POST /api/manage/services/config': Object.freeze({ kind: 'service-config-update' })
})

export function resolveServiceConfigUpdateRoute (method, path) {
  const route = SERVICE_CONFIG_UPDATE_ROUTES[`${method} ${path}`]
  if (!route) return null
  return { ...route }
}

export function normalizeManageServicePlugins (plugins) {
  if (plugins === undefined || plugins === null) return { ok: true, plugins: [] }
  if (!Array.isArray(plugins)) return { ok: false, error: 'plugins must be an array' }

  const selected = []
  const seen = new Set()
  const add = (name) => {
    if (!seen.has(name)) {
      seen.add(name)
      selected.push(name)
    }
  }

  for (const raw of plugins) {
    if (typeof raw !== 'string') {
      return { ok: false, error: 'plugins must contain service names only' }
    }
    const name = raw.trim().toLowerCase()
    if (!name) continue
    const bundle = SERVICE_PLUGIN_BUNDLES[name]
    if (bundle) {
      for (const bundled of bundle) add(bundled)
      continue
    }
    if (!BUILTIN_SERVICE_PLUGIN_SET.has(name)) {
      return {
        ok: false,
        error: `unknown service plugin: ${raw}`,
        available: BUILTIN_SERVICE_PLUGINS,
        bundles: SERVICE_PLUGIN_BUNDLES
      }
    }
    add(name)
  }

  return { ok: true, plugins: selected }
}

export function activeServiceNames (registry) {
  if (!registry || !registry.services || typeof registry.services.keys !== 'function') return []
  return Array.from(registry.services.keys()).filter(name => typeof name === 'string')
}

export function configuredBuiltinServicePlugins (config) {
  const plugins = config && Array.isArray(config.plugins) ? config.plugins : []
  return plugins
    .filter(name => typeof name === 'string' && BUILTIN_SERVICE_PLUGIN_SET.has(name))
    .filter((name, index, list) => list.indexOf(name) === index)
}

export function configuredServicePlugins (config) {
  const plugins = config && Array.isArray(config.plugins) ? config.plugins : []
  return plugins.filter(name => typeof name === 'string')
}

export function servicesLockedByProfile (config) {
  return !!config && config.productProfile === 'relaykernel'
}

export function serviceConfigPayload (config, registry) {
  const locked = servicesLockedByProfile(config)
  const plugins = locked ? [] : configuredBuiltinServicePlugins(config)
  const active = locked ? [] : activeServiceNames(registry)
  return {
    enabled: !locked && !!config && config.enableServices !== false && plugins.length > 0,
    available: BUILTIN_SERVICE_PLUGINS,
    plugins,
    active,
    bundles: SERVICE_PLUGIN_BUNDLES,
    locked,
    lockReason: locked ? 'relaykernel-profile' : null
  }
}

export async function runServiceConfigUpdateAction ({
  body,
  config,
  registry = null,
  persistConfig = null,
  serviceConfigPayload: buildPayload = serviceConfigPayload
} = {}) {
  if (!body || typeof body !== 'object') {
    return {
      ok: false,
      kind: 'bad-request',
      status: 400,
      payload: { error: 'request body required' }
    }
  }

  if (servicesLockedByProfile(config)) {
    return {
      ok: false,
      kind: 'locked',
      status: 409,
      payload: {
        error: 'Services are locked off by the RelayKernel profile',
        errorCode: 'relaykernel-services-locked',
        config: buildPayload(config, registry)
      }
    }
  }

  const normalized = normalizeManageServicePlugins(body.plugins)
  if (!normalized.ok) {
    return {
      ok: false,
      kind: 'bad-request',
      status: 400,
      payload: {
        error: normalized.error,
        available: normalized.available || BUILTIN_SERVICE_PLUGINS,
        bundles: normalized.bundles || SERVICE_PLUGIN_BUNDLES
      }
    }
  }

  const enabled = body.enabled !== false && normalized.plugins.length > 0
  const previousEnableServices = config && config.enableServices
  const previousPlugins = config && config.plugins
  config.enableServices = enabled
  config.plugins = normalized.plugins

  try {
    if (typeof persistConfig === 'function') await persistConfig()
  } catch (err) {
    config.enableServices = previousEnableServices
    config.plugins = previousPlugins
    return {
      ok: false,
      kind: 'config-persist',
      error: err
    }
  }

  return {
    ok: true,
    payload: {
      ok: true,
      restartRequired: true,
      config: buildPayload(config, registry)
    }
  }
}

export function bundleParentsForService (service, configuredPlugins, bundles = SERVICE_PLUGIN_BUNDLES) {
  const plugins = Array.isArray(configuredPlugins) ? configuredPlugins : []
  return Object.entries(bundles)
    .filter(([bundle, services]) => bundle !== service && plugins.includes(bundle) && Array.isArray(services) && services.includes(service))
    .map(([bundle]) => bundle)
}
