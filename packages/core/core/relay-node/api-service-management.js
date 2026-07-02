import {
  bundleParentsForService,
  configuredServicePlugins,
  servicesLockedByProfile
} from './api-service-config.js'

const SERVICE_MANAGEMENT_ROUTES = Object.freeze({
  'POST /api/manage/services': Object.freeze({ kind: 'service-management' })
})

function errorPayload (message) {
  return { error: message }
}

export function resolveServiceManagementRoute (method, path) {
  const route = SERVICE_MANAGEMENT_ROUTES[`${method} ${path}`]
  if (!route) return null
  return { ...route }
}

export async function runServiceManagementAction ({
  body,
  registry,
  config,
  node = null,
  store = null,
  persistConfig = async () => {},
  serviceConfigPayload = () => ({})
}) {
  if (servicesLockedByProfile(config)) {
    return {
      ok: false,
      kind: 'locked',
      status: 409,
      payload: {
        error: 'Services are locked off by the RelayKernel profile',
        errorCode: 'relaykernel-services-locked',
        config: serviceConfigPayload()
      }
    }
  }

  if (!registry) {
    return { ok: false, kind: 'unavailable', status: 503, payload: errorPayload('Services not enabled') }
  }

  const { action, service } = body || {}
  if (!action || !service) {
    return {
      ok: false,
      kind: 'bad-request',
      status: 400,
      payload: errorPayload('action and service required (action: disable|restart)')
    }
  }

  if (action === 'disable') {
    return disableService({
      service,
      registry,
      config,
      persistConfig,
      serviceConfigPayload
    })
  }

  if (action === 'restart') {
    return restartService({ service, registry, config, node, store })
  }

  return {
    ok: false,
    kind: 'bad-request',
    status: 400,
    payload: errorPayload('Unknown action: ' + action + ' (use: disable, restart)')
  }
}

async function disableService ({
  service,
  registry,
  config,
  persistConfig,
  serviceConfigPayload
}) {
  if (!registry.services.has(service)) {
    return {
      ok: false,
      kind: 'not-found',
      status: 404,
      payload: errorPayload(`Service '${service}' not found`)
    }
  }

  const configuredPlugins = configuredServicePlugins(config)
  const bundleParents = bundleParentsForService(service, configuredPlugins)
  if (bundleParents.length > 0) {
    return {
      ok: false,
      kind: 'bundle-required',
      status: 409,
      payload: {
        error: `Service '${service}' is required by bundle: ${bundleParents.join(', ')}`,
        bundles: bundleParents,
        hint: 'Use /api/manage/services/config to change the selected service bundle.'
      }
    }
  }

  const configured = configuredPlugins.includes(service)
  const previousPlugins = config.plugins
  const previousEnableServices = config.enableServices

  if (configured) {
    const nextPlugins = configuredPlugins.filter(name => name !== service)
    config.plugins = nextPlugins
    if (nextPlugins.length === 0) config.enableServices = false
    try {
      await persistConfig()
    } catch (err) {
      config.plugins = previousPlugins
      config.enableServices = previousEnableServices
      return { ok: false, kind: 'config-persist', error: err }
    }
  }

  try {
    await registry.unregister(service)
    return {
      ok: true,
      payload: {
        ok: true,
        action: 'disabled',
        service,
        persistent: configured,
        config: serviceConfigPayload()
      }
    }
  } catch (err) {
    return {
      ok: false,
      kind: 'provider-error',
      status: 500,
      payload: errorPayload(err.message)
    }
  }
}

async function restartService ({ service, registry, config, node, store }) {
  if (!registry.services.has(service)) {
    return {
      ok: false,
      kind: 'not-found',
      status: 404,
      payload: errorPayload(`Service '${service}' not found`)
    }
  }

  const ctx = { node, store, config }
  try {
    const entry = typeof registry.restart === 'function'
      ? await registry.restart(service, ctx)
      : registry.services.get(service)
    return {
      ok: true,
      payload: {
        ok: true,
        action: 'restarted',
        service,
        status: entry && entry.status ? entry.status : 'running',
        restartCount: entry && entry.restartCount ? entry.restartCount : 0
      }
    }
  } catch (err) {
    return {
      ok: false,
      kind: 'provider-error',
      status: 500,
      payload: errorPayload(err.message)
    }
  }
}
