import { formatErr } from '../error-prefixes.js'

export const VRF_HTTP_ADAPTER_UNAVAILABLE_CODE = 'vrf-http-adapter-unavailable'

export async function loadVrfHttpAdapterModule () {
  return import('p2p-hiveservices/builtin/vrf/http-adapter.js')
}

export async function resolveVrfHttpAdapter ({
  cachedAdapter = null,
  loadAdapter = loadVrfHttpAdapterModule
} = {}) {
  if (cachedAdapter) return cachedAdapter

  const mod = await loadAdapter()
  const handleVrfRoute = mod && mod.handleVrfRoute
  const createVrfHttpState = mod && mod.createVrfHttpState
  if (typeof handleVrfRoute !== 'function') throw new Error('missing handleVrfRoute export')
  if (typeof createVrfHttpState !== 'function') throw new Error('missing createVrfHttpState export')
  return {
    handleVrfRoute,
    createVrfHttpState
  }
}

export function buildVrfHttpAdapterUnavailableResponse (err) {
  return {
    kind: 'json',
    status: 503,
    payload: {
      error: formatErr('UNSUPPORTED', 'vrf HTTP adapter unavailable'),
      errorCode: VRF_HTTP_ADAPTER_UNAVAILABLE_CODE
    },
    event: {
      name: 'vrf-http-adapter-error',
      detail: { error: err }
    }
  }
}
