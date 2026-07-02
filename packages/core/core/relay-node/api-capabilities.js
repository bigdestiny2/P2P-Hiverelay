import { buildCapabilityDoc } from '../capability-doc.js'

export const CAPABILITY_DOC_CACHE_CONTROL = 'public, max-age=60'

const CAPABILITY_ROUTES = Object.freeze({
  'GET /.well-known/hiverelay.json': Object.freeze({ kind: 'capability-doc' }),
  'GET /api/capabilities': Object.freeze({ kind: 'capability-doc' })
})

export function resolveCapabilityRoute (method, path) {
  const route = CAPABILITY_ROUTES[`${method} ${path}`]
  if (!route) return null
  return { ...route }
}

export function buildCapabilityRoutePayload ({
  node = null,
  version = null,
  runtime = 'node'
} = {}) {
  return {
    status: 200,
    headers: { 'Cache-Control': CAPABILITY_DOC_CACHE_CONTROL },
    payload: buildCapabilityDoc({
      relay: node,
      version,
      runtime
    })
  }
}
