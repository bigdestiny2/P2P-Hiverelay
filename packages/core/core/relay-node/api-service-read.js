import {
  MAX_SERVICE_CATALOG_ENTRIES,
  sanitizeServiceCatalogEntries,
  serviceCatalogTotal
} from '../services/service-catalog.js'

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
