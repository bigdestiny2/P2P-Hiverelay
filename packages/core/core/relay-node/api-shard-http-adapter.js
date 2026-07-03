import { formatErr } from '../error-prefixes.js'

export const SHARD_HTTP_ADAPTER_UNAVAILABLE_CODE = 'shard-http-adapter-unavailable'

export async function loadShardHttpAdapterModule () {
  return import('p2p-hiveservices/builtin/shard-store/http-adapter.js')
}

export async function resolveShardHttpAdapter ({
  cachedAdapter = null,
  loadAdapter = loadShardHttpAdapterModule
} = {}) {
  if (cachedAdapter) return cachedAdapter

  const mod = await loadAdapter()
  const resolveShardRoute = mod && mod.resolveShardRoute
  const handleShardHttp = mod && mod.handleShardHttp
  const createShardHttpState = mod && mod.createShardHttpState
  if (typeof resolveShardRoute !== 'function') throw new Error('missing resolveShardRoute export')
  if (typeof handleShardHttp !== 'function') throw new Error('missing handleShardHttp export')
  if (typeof createShardHttpState !== 'function') throw new Error('missing createShardHttpState export')
  return {
    resolveShardRoute,
    handleShardHttp,
    createShardHttpState
  }
}

export function buildShardHttpAdapterUnavailableResponse (err) {
  return {
    kind: 'json',
    status: 503,
    payload: {
      error: formatErr('UNSUPPORTED', 'shard HTTP adapter unavailable'),
      errorCode: SHARD_HTTP_ADAPTER_UNAVAILABLE_CODE
    },
    event: {
      name: 'shard-http-adapter-error',
      detail: { error: err }
    }
  }
}
