import { formatErr } from '../error-prefixes.js'

export const OUTBOXLOG_HTTP_ADAPTER_UNAVAILABLE_CODE = 'outboxlog-http-adapter-unavailable'
export const OUTBOXLOG_HTTP_RATE_LIMIT_DEFAULT = Object.freeze({
  enabled: true,
  windowMs: 60_000,
  max: 1200
})
export const OUTBOXLOG_HTTP_RATE_LIMIT_MAX_WINDOW_MS = 24 * 60 * 60 * 1000
export const OUTBOXLOG_HTTP_RATE_LIMIT_MAX_REQUESTS = 10_000_000
const OUTBOXLOG_HTTP_RATE_LIMIT_FIELDS = new Set(['enabled', 'windowMs', 'max'])

export function normalizeOutboxLogHttpRateLimit (value) {
  if (value === undefined) return { ...OUTBOXLOG_HTTP_RATE_LIMIT_DEFAULT }
  if (value === false) return disabledRateLimit(OUTBOXLOG_HTTP_RATE_LIMIT_DEFAULT.windowMs)
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('outboxlog.http.rateLimit must be an object or false')
  }
  for (const key of Object.keys(value)) {
    if (!OUTBOXLOG_HTTP_RATE_LIMIT_FIELDS.has(key)) throw new TypeError('outboxlog.http.rateLimit has unknown field: ' + key)
  }
  if (value.enabled !== undefined && typeof value.enabled !== 'boolean') {
    throw new TypeError('outboxlog.http.rateLimit.enabled must be boolean')
  }
  const windowMs = value.windowMs === undefined
    ? OUTBOXLOG_HTTP_RATE_LIMIT_DEFAULT.windowMs
    : positiveSafeInteger(value.windowMs, 'outboxlog.http.rateLimit.windowMs', OUTBOXLOG_HTTP_RATE_LIMIT_MAX_WINDOW_MS)
  // Accept our own normalized disabled descriptor so normalization remains
  // idempotent across the RelayAPI and service adapter boundaries. A raw
  // max=null remains invalid unless the envelope is explicitly disabled.
  const disabledMax = value.max === false || value.max === Infinity ||
    (value.enabled === false && value.max === null)
  const configuredMax = value.max === undefined || disabledMax
    ? null
    : positiveSafeInteger(value.max, 'outboxlog.http.rateLimit.max', OUTBOXLOG_HTTP_RATE_LIMIT_MAX_REQUESTS)
  const legacyDisabled = value.enabled === undefined && disabledMax
  if (value.enabled === false || legacyDisabled) return disabledRateLimit(windowMs)
  if (value.enabled === true && disabledMax) {
    throw new TypeError('outboxlog.http.rateLimit.max conflicts with enabled=true')
  }
  const max = configuredMax == null ? OUTBOXLOG_HTTP_RATE_LIMIT_DEFAULT.max : configuredMax
  return { enabled: true, windowMs, max }
}

// Core and p2p-hiveservices may be upgraded independently. Older adapters
// recognize max=false (but not enabled=false/max=null) as the explicit disable
// sentinel, so keep the transport shape backward-compatible while the public
// status descriptor uses null for a disabled numeric ceiling.
export function outboxLogHttpRateLimitAdapterConfig (value) {
  const normalized = normalizeOutboxLogHttpRateLimit(value)
  if (normalized.enabled) return normalized
  return { enabled: false, windowMs: normalized.windowMs, max: false }
}

export function configuredOutboxLogHttpRateLimit (config) {
  const outboxlog = config && config.outboxlog
  if (!outboxlog || typeof outboxlog !== 'object' || Array.isArray(outboxlog)) return undefined
  if (outboxlog.http && typeof outboxlog.http === 'object' && !Array.isArray(outboxlog.http) && Object.prototype.hasOwnProperty.call(outboxlog.http, 'rateLimit')) {
    return outboxlog.http.rateLimit
  }
  // Compatibility aliases for early deployments. New config should use the
  // documented outboxlog.http.rateLimit path above.
  if (outboxlog.api && typeof outboxlog.api === 'object' && !Array.isArray(outboxlog.api) && Object.prototype.hasOwnProperty.call(outboxlog.api, 'rateLimit')) {
    return outboxlog.api.rateLimit
  }
  if (Object.prototype.hasOwnProperty.call(outboxlog, 'httpRateLimit')) return outboxlog.httpRateLimit
  return undefined
}

function disabledRateLimit (windowMs) {
  return { enabled: false, windowMs, max: null }
}

function positiveSafeInteger (value, name, max) {
  if (!Number.isSafeInteger(value) || value < 1 || value > max) {
    throw new TypeError(name + ' must be an integer from 1 to ' + max)
  }
  return value
}

export async function loadOutboxLogHttpAdapterModule () {
  return import('p2p-hiveservices/builtin/outboxlog/http-adapter.js')
}

export async function resolveOutboxLogHttpAdapter ({
  cachedAdapter = null,
  loadAdapter = loadOutboxLogHttpAdapterModule
} = {}) {
  if (cachedAdapter) return cachedAdapter

  const mod = await loadAdapter()
  const handleOutboxLogRoute = mod && mod.handleOutboxLogRoute
  const createOutboxLogTokenAuth = mod && mod.createOutboxLogTokenAuth
  const createOutboxLogHttpState = mod && mod.createOutboxLogHttpState
  // The takedown admin auth is service-owned (constant-time verify, separate
  // from the browser sync token). Core resolves it here so it can construct
  // ctx.adminAuth from operator config without reimplementing the primitive.
  const createOutboxLogAdminAuth = mod && mod.createOutboxLogAdminAuth
  if (typeof handleOutboxLogRoute !== 'function') throw new Error('missing handleOutboxLogRoute export')
  if (typeof createOutboxLogTokenAuth !== 'function') throw new Error('missing createOutboxLogTokenAuth export')
  if (typeof createOutboxLogHttpState !== 'function') throw new Error('missing createOutboxLogHttpState export')
  if (typeof createOutboxLogAdminAuth !== 'function') throw new Error('missing createOutboxLogAdminAuth export')
  return {
    handleOutboxLogRoute,
    createOutboxLogTokenAuth,
    createOutboxLogHttpState,
    createOutboxLogAdminAuth
  }
}

export function buildOutboxLogHttpAdapterUnavailableResponse (err) {
  return {
    kind: 'json',
    status: 503,
    payload: {
      error: formatErr('UNSUPPORTED', 'outboxlog HTTP adapter unavailable'),
      errorCode: OUTBOXLOG_HTTP_ADAPTER_UNAVAILABLE_CODE
    },
    event: {
      name: 'outboxlog-http-adapter-error',
      detail: { error: err }
    }
  }
}
