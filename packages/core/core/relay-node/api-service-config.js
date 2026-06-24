export const BUILTIN_SERVICE_PLUGINS = Object.freeze([
  'identity',
  'storage',
  'schema',
  'vrf',
  'ai',
  'zk',
  'sla',
  'arbitration',
  'poker'
])

export const BUILTIN_SERVICE_PLUGIN_SET = new Set(BUILTIN_SERVICE_PLUGINS)

export const SERVICE_PLUGIN_BUNDLES = Object.freeze({
  poker: Object.freeze(['poker', 'vrf', 'arbitration', 'zk'])
})

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

export function serviceConfigPayload (config, registry) {
  const plugins = configuredBuiltinServicePlugins(config)
  const active = activeServiceNames(registry)
  return {
    enabled: !!config && config.enableServices !== false && plugins.length > 0,
    available: BUILTIN_SERVICE_PLUGINS,
    plugins,
    active,
    bundles: SERVICE_PLUGIN_BUNDLES
  }
}

export function bundleParentsForService (service, configuredPlugins, bundles = SERVICE_PLUGIN_BUNDLES) {
  const plugins = Array.isArray(configuredPlugins) ? configuredPlugins : []
  return Object.entries(bundles)
    .filter(([bundle, services]) => bundle !== service && plugins.includes(bundle) && Array.isArray(services) && services.includes(service))
    .map(([bundle]) => bundle)
}
