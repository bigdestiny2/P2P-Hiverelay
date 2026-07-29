export const X402_PROTOCOL_VERSION = 2
export const X402_PRICE_MANIFEST_PATH = '/.well-known/x402-prices'
export const X402_SERVICE_PREFIX = '/svc/'
export const X402_DEFAULT_FACILITATOR_URL = 'https://x402.org/facilitator'

const ROUTE_KEY_RE = /^(GET|POST) (\/svc\/[a-z0-9][a-z0-9/_-]*)$/
const SERVICE_ROUTE_RE = /^[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9-]*$/
const EVM_ADDRESS_RE = /^0x[0-9a-f]{40}$/i
const EVM_NETWORK_RE = /^eip155:[1-9][0-9]*$/
const POSITIVE_INTEGER_RE = /^[1-9][0-9]*$/
const SIDE_EFFECT_POLICIES = new Set(['read-only', 'idempotent-write'])

export function isX402ServicePath (path) {
  return typeof path === 'string' && path.startsWith(X402_SERVICE_PREFIX)
}

export function normalizeX402Config (input = {}) {
  const source = isObject(input) ? input : {}
  const enabled = source.enabled === true
  const facilitatorUrl = optionalUrl(
    source.facilitatorUrl || X402_DEFAULT_FACILITATOR_URL,
    'x402.facilitatorUrl'
  )
  const publicBaseUrl = source.publicBaseUrl == null
    ? null
    : optionalUrl(source.publicBaseUrl, 'x402.publicBaseUrl')
  const routeEntries = isObject(source.routes) ? Object.entries(source.routes) : []
  const routes = {}
  const paymentFingerprints = new Map()

  for (const [routeKey, rawRoute] of routeEntries) {
    const match = routeKey.match(ROUTE_KEY_RE)
    if (!match) {
      throw new Error('X402_CONFIG_INVALID: route keys must look like "POST /svc/vrf/prove"')
    }

    const route = normalizeRoute(rawRoute, routeKey, match[1], match[2])
    for (const accept of route.accepts) {
      const fingerprint = paymentFingerprint(accept)
      const existing = paymentFingerprints.get(fingerprint)
      if (existing && existing !== routeKey) {
        throw new Error(
          `X402_CONFIG_INVALID: ${routeKey} and ${existing} reuse the same payment tuple; ` +
          'use a distinct amount, asset, network, or recipient so one authorization cannot match both routes'
        )
      }
      paymentFingerprints.set(fingerprint, routeKey)
    }
    routes[routeKey] = route
  }

  if (enabled && routeEntries.length > 0 && !publicBaseUrl) {
    throw new Error('X402_CONFIG_INVALID: x402.publicBaseUrl is required when paid routes are enabled')
  }

  return {
    enabled,
    facilitatorUrl,
    publicBaseUrl,
    claimTtlMs: positiveInteger(source.claimTtlMs, 10 * 60 * 1000, 'x402.claimTtlMs'),
    maxClaims: positiveInteger(source.maxClaims, 50_000, 'x402.maxClaims'),
    routes
  }
}

export function x402SdkRoutes (config) {
  const normalized = normalizeX402Config(config)
  const routes = {}
  if (!normalized.enabled) return routes

  for (const [routeKey, route] of Object.entries(normalized.routes)) {
    routes[routeKey] = {
      accepts: route.accepts,
      resource: new URL(route.path, normalized.publicBaseUrl).toString(),
      description: route.description,
      mimeType: route.mimeType,
      serviceName: route.serviceRoute,
      tags: ['hiverelay', route.unit, route.proofType].filter(Boolean),
      unpaidResponseBody: () => ({
        contentType: 'application/json',
        body: {
          error: 'payment required',
          errorCode: 'x402-payment-required',
          service: route.serviceRoute
        }
      }),
      settlementFailedResponseBody: (_context, failure) => ({
        contentType: 'application/json',
        body: {
          error: failure.errorMessage || failure.errorReason || 'payment settlement failed',
          errorCode: 'x402-settlement-failed',
          service: route.serviceRoute
        }
      })
    }
  }
  return routes
}

export function x402RouteForRequest (config, method, path) {
  const normalized = normalizeX402Config(config)
  if (!normalized.enabled) return null
  return normalized.routes[`${method} ${path}`] || null
}

function normalizeRoute (value, routeKey, method, path) {
  if (!isObject(value)) {
    throw new Error(`X402_CONFIG_INVALID: ${routeKey} must be an object`)
  }
  if (!SERVICE_ROUTE_RE.test(value.serviceRoute || '')) {
    throw new Error(`X402_CONFIG_INVALID: ${routeKey}.serviceRoute must look like "vrf.prove"`)
  }
  if (!SIDE_EFFECT_POLICIES.has(value.sideEffects)) {
    throw new Error(
      `X402_CONFIG_INVALID: ${routeKey}.sideEffects must be "read-only" or "idempotent-write"`
    )
  }
  if (value.sideEffects === 'idempotent-write' && value.requireIdempotencyKey !== true) {
    throw new Error(
      `X402_CONFIG_INVALID: ${routeKey} is an idempotent write and must set requireIdempotencyKey:true`
    )
  }

  const accepts = Array.isArray(value.accepts) ? value.accepts : [value.accepts]
  if (accepts.length === 0 || accepts[0] == null) {
    throw new Error(`X402_CONFIG_INVALID: ${routeKey}.accepts must not be empty`)
  }

  return {
    method,
    path,
    serviceRoute: value.serviceRoute,
    sideEffects: value.sideEffects,
    requireIdempotencyKey: value.requireIdempotencyKey === true,
    description: boundedString(value.description, 512) || value.serviceRoute,
    mimeType: boundedString(value.mimeType, 128) || 'application/json',
    unit: boundedString(value.unit, 64) || 'request',
    proofType: boundedString(value.proofType, 128) || null,
    accepts: accepts.map((accept, index) => normalizeAccept(accept, routeKey, index))
  }
}

function normalizeAccept (value, routeKey, index) {
  const label = `${routeKey}.accepts[${index}]`
  if (!isObject(value)) throw new Error(`X402_CONFIG_INVALID: ${label} must be an object`)
  if (value.scheme !== 'exact') {
    throw new Error(`X402_CONFIG_INVALID: ${label}.scheme must be "exact" in the canary scaffold`)
  }
  if (!EVM_NETWORK_RE.test(value.network || '')) {
    throw new Error(`X402_CONFIG_INVALID: ${label}.network must be a CAIP-2 EVM id`)
  }
  if (!EVM_ADDRESS_RE.test(value.payTo || '')) {
    throw new Error(`X402_CONFIG_INVALID: ${label}.payTo must be an EVM address`)
  }
  if (!isObject(value.price) || !EVM_ADDRESS_RE.test(value.price.asset || '')) {
    throw new Error(`X402_CONFIG_INVALID: ${label}.price.asset must be an EVM token address`)
  }
  if (!POSITIVE_INTEGER_RE.test(value.price.amount || '')) {
    throw new Error(`X402_CONFIG_INVALID: ${label}.price.amount must be a positive atomic-unit string`)
  }

  return {
    scheme: 'exact',
    network: value.network,
    payTo: value.payTo,
    price: {
      asset: value.price.asset,
      amount: value.price.amount
    },
    ...(value.maxTimeoutSeconds == null
      ? {}
      : { maxTimeoutSeconds: positiveInteger(value.maxTimeoutSeconds, null, `${label}.maxTimeoutSeconds`) })
  }
}

function paymentFingerprint (accept) {
  return [
    accept.scheme,
    accept.network,
    accept.payTo.toLowerCase(),
    accept.price.asset.toLowerCase(),
    accept.price.amount
  ].join('|')
}

function optionalUrl (value, label) {
  try {
    const url = new URL(value)
    if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error('unsupported protocol')
    return url.toString().replace(/\/$/, '')
  } catch {
    throw new Error(`X402_CONFIG_INVALID: ${label} must be an http(s) URL`)
  }
}

function positiveInteger (value, fallback, label) {
  if (value == null && fallback != null) return fallback
  const number = Number(value)
  if (!Number.isSafeInteger(number) || number <= 0) {
    throw new Error(`X402_CONFIG_INVALID: ${label} must be a positive integer`)
  }
  return number
}

function boundedString (value, maxLength) {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  if (!trimmed || trimmed.length > maxLength || hasControlCharacter(trimmed)) return null
  return trimmed
}

function hasControlCharacter (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code <= 0x1f || code === 0x7f) return true
  }
  return false
}

function isObject (value) {
  return !!value && typeof value === 'object' && !Array.isArray(value)
}
