const PUBLIC_NOTIFY_ROUTES = Object.freeze({
  'GET /api/v1/notify/capabilities': Object.freeze({ kind: 'notify-capabilities' }),
  'GET /api/v1/notify/status': Object.freeze({ kind: 'notify-status' }),
  'POST /api/v1/notify/status': Object.freeze({ kind: 'notify-status' }),
  'POST /api/v1/notify/provider': Object.freeze({ kind: 'notify-call', method: 'bind-provider' }),
  'POST /api/v1/notify/device': Object.freeze({ kind: 'notify-call', method: 'register-device' }),
  'POST /api/v1/notify/receive-cap': Object.freeze({ kind: 'notify-call', method: 'install-receive-cap' }),
  'POST /api/v1/notify/send-cap': Object.freeze({ kind: 'notify-call', method: 'install-send-cap' }),
  'POST /api/v1/notify/revoke': Object.freeze({ kind: 'notify-call', method: 'revoke' }),
  'POST /api/v1/notify/send': Object.freeze({ kind: 'notify-call', method: 'send' }),
  'POST /api/v1/notify/watch': Object.freeze({ kind: 'notify-call', method: 'watch' }),
  'POST /api/v1/notify/unwatch': Object.freeze({ kind: 'notify-call', method: 'unwatch' })
})

const MANAGEMENT_NOTIFY_ROUTES = Object.freeze({
  'GET /api/manage/notify': Object.freeze({ kind: 'notify-management-status', authMessage: 'Unauthorized — API key required for notify diagnostics' }),
  'GET /api/manage/notify/production-gates': Object.freeze({ kind: 'notify-production-gates', authMessage: 'Unauthorized — API key required for notify production gates' })
})

const STATUS_CODES = Object.freeze({
  BAD_KEY: 400,
  BAD_REQUEST: 400,
  BAD_SCOPE: 400,
  BAD_GENERATION: 400,
  BAD_SIGNATURE: 401,
  AUDIENCE_MISMATCH: 403,
  CHANNEL_DENIED: 403,
  MODE_DENIED: 403,
  SOURCE_DENIED: 403,
  PROVIDER_UNSUPPORTED: 400,
  MODE_UNSUPPORTED: 400,
  CREDENTIAL_MODE_UNSUPPORTED: 400,
  EXPIRED: 410,
  STALE_GENERATION: 409,
  TOKEN_MISMATCH: 409,
  DEVICE_NOT_REGISTERED: 409,
  BINDING_MISSING: 404,
  BINDING_MISMATCH: 409,
  PROVIDER_TOKEN_INVALID: 409,
  RECEIVE_CAP_MISSING: 404,
  SEND_CAP_MISSING: 404,
  CAP_MISMATCH: 409,
  WATCH_LIMIT: 429
})

export function resolveNotifyRoute (method, path) {
  const key = `${method} ${path}`
  const route = PUBLIC_NOTIFY_ROUTES[key] || MANAGEMENT_NOTIFY_ROUTES[key]
  if (!route) return null
  return { ...route, management: !!MANAGEMENT_NOTIFY_ROUTES[key] }
}

export function notifyQueryParams (url) {
  const params = {}
  if (!url || !url.searchParams) return params
  for (const [key, value] of url.searchParams) params[key] = value
  return params
}

export async function runNotifyRouteAction ({
  route,
  providerResult,
  body = {},
  query = {}
} = {}) {
  if (!route) return { status: 404, payload: { error: 'unknown notify route' } }
  if (!providerResult || !providerResult.ok) {
    return {
      status: providerResult && providerResult.status ? providerResult.status : 503,
      payload: { error: providerResult && providerResult.error ? providerResult.error : 'Notify service is not enabled on this relay' }
    }
  }

  const provider = providerResult.provider
  try {
    if (route.kind === 'notify-capabilities') return notifyCapabilities(provider, providerResult.entry)
    if (route.kind === 'notify-status') {
      const params = normalizeStatusRequest(body)
      if (!params.signature) return { status: 401, payload: { error: 'signed notify status request required' } }
      return { status: 200, payload: await provider.status(params) }
    }
    if (route.kind === 'notify-management-status') {
      return { status: 200, payload: await provider.status(query) }
    }
    if (route.kind === 'notify-production-gates') {
      if (typeof provider['production-gates'] !== 'function') {
        return { status: 503, payload: { error: 'Notify service does not expose production gates' } }
      }
      return { status: 200, payload: await provider['production-gates'](query) }
    }
    if (route.kind === 'notify-call') {
      if (typeof provider[route.method] !== 'function') {
        return { status: 503, payload: { error: 'Notify service does not expose method: ' + route.method } }
      }
      return { status: 200, payload: await provider[route.method](body) }
    }
  } catch (err) {
    return notifyErrorResponse(err)
  }

  return { status: 404, payload: { error: 'unknown notify route' } }
}

function notifyCapabilities (provider, entry) {
  const manifest = safeManifest(provider, entry)
  const limits = safeLimits(provider)
  return {
    status: 200,
    headers: { 'Cache-Control': 'public, max-age=10' },
    payload: {
      ok: true,
      service: 'notify',
      version: manifest.version || '0.1.0',
      capabilities: Array.isArray(manifest.capabilities) ? manifest.capabilities : [],
      providers: Array.isArray(limits.providers) ? limits.providers : ['runtime', 'apns', 'fcm', 'webpush'],
      credentialModes: ['runtime-owned', 'app-owned'],
      modes: ['direct', 'watch', 'presence-fallback'],
      payload: {
        plaintextAllowed: false,
        maxCiphertextBytes: limits.maxPayloadBytes || 3072,
        privacyProfiles: Array.isArray(limits.privacyProfiles) ? limits.privacyProfiles : ['generic', 'local-template']
      },
      limits: {
        maxTtlSeconds: limits.maxTtlSeconds || 604800,
        maxWatchesPerReceiveCap: limits.maxWatchesPerReceiveCap || 128
      }
    }
  }
}

function normalizeStatusRequest (body) {
  return body && typeof body === 'object' && !Array.isArray(body) ? body : {}
}

function safeManifest (provider, entry) {
  if (provider && typeof provider.manifest === 'function') {
    try {
      const manifest = provider.manifest()
      if (manifest && typeof manifest === 'object') return manifest
    } catch (_) {}
  }
  return {
    name: 'notify',
    version: entry && typeof entry.version === 'string' ? entry.version : '0.1.0',
    capabilities: Array.isArray(entry && entry.capabilities) ? entry.capabilities : []
  }
}

function safeLimits (provider) {
  if (provider && typeof provider.limits === 'function') {
    try {
      const limits = provider.limits()
      if (limits && typeof limits === 'object') return limits
    } catch (_) {}
  }
  return {}
}

function notifyErrorResponse (err) {
  const code = err && typeof err.code === 'string' ? err.code : null
  const status = STATUS_CODES[code] || 400
  return {
    status,
    payload: {
      error: code ? (err.message || code) : 'Notify request failed',
      errorCode: code || 'notify-request-failed'
    }
  }
}
