import { formatErr } from '../error-prefixes.js'

export const OUTBOXLOG_HTTP_ADAPTER_UNAVAILABLE_CODE = 'outboxlog-http-adapter-unavailable'

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
