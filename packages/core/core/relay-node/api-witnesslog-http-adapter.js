import { formatErr } from '../error-prefixes.js'

export const WITNESSLOG_HTTP_ADAPTER_UNAVAILABLE_CODE = 'witnesslog-http-adapter-unavailable'

export async function loadWitnessLogHttpAdapterModule () {
  return import('p2p-hiveservices/builtin/witnesslog/http-adapter.js')
}

export async function resolveWitnessLogHttpAdapter ({
  cachedAdapter = null,
  loadAdapter = loadWitnessLogHttpAdapterModule
} = {}) {
  if (cachedAdapter) return cachedAdapter

  const mod = await loadAdapter()
  const handleWitnessLogRoute = mod && mod.handleWitnessLogRoute
  const createWitnessLogHttpState = mod && mod.createWitnessLogHttpState
  if (typeof handleWitnessLogRoute !== 'function') throw new Error('missing handleWitnessLogRoute export')
  if (typeof createWitnessLogHttpState !== 'function') throw new Error('missing createWitnessLogHttpState export')
  return {
    handleWitnessLogRoute,
    createWitnessLogHttpState
  }
}

export function buildWitnessLogHttpAdapterUnavailableResponse (err) {
  return {
    kind: 'json',
    status: 503,
    payload: {
      error: formatErr('UNSUPPORTED', 'witnesslog HTTP adapter unavailable'),
      errorCode: WITNESSLOG_HTTP_ADAPTER_UNAVAILABLE_CODE
    },
    event: {
      name: 'witnesslog-http-adapter-error',
      detail: { error: err }
    }
  }
}
