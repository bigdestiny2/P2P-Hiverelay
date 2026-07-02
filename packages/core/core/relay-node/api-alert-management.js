import { queryInt } from './api-validation.js'

export const ALERT_SEVERITIES = ['info', 'warn', 'error', 'critical']
export const MAX_ALERT_TYPE_FILTER_BYTES = 80
export const MAX_ALERT_TEST_MESSAGE_BYTES = 512
export const MAX_ALERT_TEST_DETAILS_BYTES = 2048

const ALERT_MANAGEMENT_ROUTES = Object.freeze({
  'GET /api/alerts': Object.freeze({
    kind: 'log',
    authMessage: 'Unauthorized — API key required for /api/alerts'
  }),
  'POST /api/alerts/test': Object.freeze({
    kind: 'test',
    authMessage: 'Unauthorized — API key required for /api/alerts/test'
  })
})

function errorPayload (message) {
  return { error: message }
}

function objectRecord (value) {
  return value && typeof value === 'object' && !Array.isArray(value)
}

function byteLength (value) {
  return Buffer.byteLength(String(value), 'utf8')
}

function validateSeverity (value, field = 'severity') {
  if (value === undefined || value === null || value === '') return { ok: true, value: undefined }
  if (typeof value !== 'string' || !ALERT_SEVERITIES.includes(value)) {
    return { ok: false, payload: errorPayload(`${field} must be one of: ${ALERT_SEVERITIES.join(', ')}`) }
  }
  return { ok: true, value }
}

function validateTypeFilter (value) {
  if (value === undefined || value === null || value === '') return { ok: true, value: undefined }
  if (typeof value !== 'string' ||
    byteLength(value) > MAX_ALERT_TYPE_FILTER_BYTES ||
    !/^[a-z0-9][a-z0-9._:-]*$/i.test(value)) {
    return {
      ok: false,
      payload: errorPayload('type must be 1-80 bytes of letters, numbers, dot, underscore, colon, or dash')
    }
  }
  return { ok: true, value }
}

function validateTestMessage (value) {
  if (value === undefined || value === null) return { ok: true, value: undefined }
  if (typeof value !== 'string') return { ok: false, payload: errorPayload('message must be a string') }
  if (byteLength(value) > MAX_ALERT_TEST_MESSAGE_BYTES) {
    return { ok: false, payload: errorPayload('message must be 512 bytes or smaller') }
  }
  return { ok: true, value }
}

function validateTestDetails (value) {
  if (value === undefined || value === null) return { ok: true, value: undefined }
  if (!objectRecord(value)) return { ok: false, payload: errorPayload('details must be an object') }
  if (byteLength(JSON.stringify(value)) > MAX_ALERT_TEST_DETAILS_BYTES) {
    return { ok: false, payload: errorPayload('details must be 2048 bytes or smaller') }
  }
  return { ok: true, value }
}

export function resolveAlertManagementRoute (method, path) {
  const route = ALERT_MANAGEMENT_ROUTES[`${method} ${path}`]
  if (!route) return null
  return { ...route }
}

export function buildAlertLogPayload ({
  alertManager = null,
  url
} = {}) {
  const parsed = url instanceof URL ? url : new URL(url || '/', 'http://0.0.0.0')
  if (!alertManager || typeof alertManager.getLog !== 'function') {
    return { ok: true, payload: { enabled: false, total: 0, offset: 0, limit: 0, items: [] } }
  }

  const severity = validateSeverity(parsed.searchParams.get('severity'))
  if (!severity.ok) return { ok: false, status: 400, payload: severity.payload }

  const type = validateTypeFilter(parsed.searchParams.get('type'))
  if (!type.ok) return { ok: false, status: 400, payload: type.payload }

  const offset = queryInt(parsed, 'offset', 0, 0, 10_000)
  const limit = queryInt(parsed, 'limit', 50, 1, 500)
  const logOut = alertManager.getLog({
    offset,
    limit,
    severity: severity.value,
    type: type.value
  })
  return { ok: true, payload: { enabled: true, ...logOut } }
}

export function runAlertTestAction ({
  body = {},
  alertManager = null
} = {}) {
  body = body || {}
  if (!alertManager || typeof alertManager.fireTest !== 'function') {
    return { ok: false, status: 503, payload: errorPayload('AlertManager not enabled') }
  }

  const severity = validateSeverity(body.severity)
  if (!severity.ok) return { ok: false, status: 400, payload: severity.payload }

  const message = validateTestMessage(body.message)
  if (!message.ok) return { ok: false, status: 400, payload: message.payload }

  const details = validateTestDetails(body.details)
  if (!details.ok) return { ok: false, status: 400, payload: details.payload }

  const dispatched = alertManager.fireTest({
    severity: severity.value,
    message: message.value,
    details: details.value
  })
  return { ok: true, payload: { ok: true, dispatched } }
}

export function runAlertManagementRouteAction ({
  route,
  body = {},
  alertManager = null,
  url
} = {}) {
  const kind = route && route.kind
  if (kind === 'log') return buildAlertLogPayload({ alertManager, url })
  if (kind === 'test') return runAlertTestAction({ body, alertManager })
  return { ok: false, status: 404, payload: errorPayload('unknown alert management route') }
}
