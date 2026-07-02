import { formatErr } from '../error-prefixes.js'

export const POKER_HTTP_ADAPTER_UNAVAILABLE_CODE = 'poker-http-adapter-unavailable'

export async function loadPokerHttpAdapterModule () {
  return import('p2p-hiveservices/builtin/poker/http-adapter.js')
}

export async function resolvePokerHttpRouteHandler ({
  cachedHandler = null,
  loadAdapter = loadPokerHttpAdapterModule
} = {}) {
  if (cachedHandler) return cachedHandler

  const mod = await loadAdapter()
  const handlePokerRoute = mod && mod.handlePokerRoute
  if (typeof handlePokerRoute !== 'function') throw new Error('missing handlePokerRoute export')
  return handlePokerRoute
}

export function buildPokerHttpAdapterUnavailableResponse (err) {
  return {
    kind: 'json',
    status: 503,
    payload: {
      error: formatErr('UNSUPPORTED', 'poker HTTP adapter unavailable'),
      errorCode: POKER_HTTP_ADAPTER_UNAVAILABLE_CODE
    },
    event: {
      name: 'poker-http-adapter-error',
      detail: { error: err }
    }
  }
}
