import {
  MAX_SERVICE_CATALOG_ENTRIES,
  sanitizeServiceCatalogEntries,
  serviceCatalogTotal
} from '../services/service-catalog.js'

const SERVICE_READ_ROUTES = Object.freeze({
  'GET /api/v1/services': Object.freeze({ kind: 'service-catalog' })
})

export function resolveServiceReadRoute (method, path) {
  const route = SERVICE_READ_ROUTES[`${method} ${path}`]
  if (!route) return null
  return { ...route }
}

export function buildServiceReadRoutePayload ({
  route,
  registry = null
} = {}) {
  if (!route || route.kind !== 'service-catalog') {
    return {
      status: 404,
      payload: { error: 'unknown service read route' }
    }
  }
  return buildServiceCatalogPayload({ registry })
}

export function buildServiceCatalogPayload ({ registry = null } = {}) {
  if (!registry || typeof registry.catalog !== 'function') {
    return {
      status: 503,
      payload: { error: 'Services not enabled' }
    }
  }

  const raw = registry.catalog()
  const services = sanitizeServiceCatalogEntries(raw)
  const total = serviceCatalogTotal(raw)
  return {
    status: 200,
    payload: {
      services,
      count: services.length,
      total,
      truncated: total > services.length || total > MAX_SERVICE_CATALOG_ENTRIES
    },
    headers: { 'Cache-Control': 'public, max-age=10' }
  }
}
