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
  if (typeof handleOutboxLogRoute !== 'function') throw new Error('missing handleOutboxLogRoute export')
  if (typeof createOutboxLogTokenAuth !== 'function') throw new Error('missing createOutboxLogTokenAuth export')
  if (typeof createOutboxLogHttpState !== 'function') throw new Error('missing createOutboxLogHttpState export')
  return {
    handleOutboxLogRoute,
    createOutboxLogTokenAuth,
    createOutboxLogHttpState
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
