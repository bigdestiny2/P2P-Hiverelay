import { X402_PRICE_MANIFEST_PATH } from '../../incentive/x402/config.js'
import { buildX402PriceManifest } from '../../incentive/x402/price-manifest.js'

export const X402_PRICE_MANIFEST_CACHE_CONTROL = 'public, max-age=30'

export function resolveX402PriceManifestRoute (method, path) {
  if (method === 'GET' && path === X402_PRICE_MANIFEST_PATH) {
    return { kind: 'x402-price-manifest' }
  }
  return null
}

export function buildX402PriceManifestRoutePayload ({
  route,
  node,
  attestedAt
} = {}) {
  if (!route || route.kind !== 'x402-price-manifest') {
    return { status: 404, payload: { error: 'unknown x402 route' } }
  }
  try {
    return {
      status: 200,
      headers: { 'Cache-Control': X402_PRICE_MANIFEST_CACHE_CONTROL },
      payload: buildX402PriceManifest({
        relay: node,
        config: node?.config?.x402 || {},
        attestedAt
      })
    }
  } catch (err) {
    return {
      status: 503,
      payload: {
        error: 'x402 price manifest configuration is invalid',
        errorCode: 'x402-config-invalid',
        detail: err && err.message ? err.message : String(err)
      }
    }
  }
}

export async function runX402ServiceRequest ({
  facade,
  req,
  url,
  readBody,
  router,
  registry
} = {}) {
  if (!facade) {
    return {
      handled: true,
      status: 503,
      headers: { 'Retry-After': '30' },
      payload: { error: 'x402 facade unavailable', errorCode: 'x402-unavailable' }
    }
  }

  return facade.handle({
    req,
    url,
    readBody,
    execute: (route, params, context) => {
      if (router && typeof router.dispatch === 'function') {
        return router.dispatch(route.serviceRoute, params, context)
      }
      if (registry && typeof registry.handleRequest === 'function') {
        const dot = route.serviceRoute.indexOf('.')
        return registry.handleRequest(
          route.serviceRoute.slice(0, dot),
          route.serviceRoute.slice(dot + 1),
          params,
          context
        )
      }
      throw new Error('SERVICE_UNAVAILABLE: service router is not enabled')
    }
  })
}
