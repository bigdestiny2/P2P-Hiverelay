import { formatErr } from '../error-prefixes.js'

export const REPAIRTICKET_HTTP_ADAPTER_UNAVAILABLE_CODE = 'repairticket-http-adapter-unavailable'

export async function loadRepairTicketHttpAdapterModule () {
  return import('p2p-hiveservices/builtin/repairticket/http-adapter.js')
}

export async function resolveRepairTicketHttpAdapter ({
  cachedAdapter = null,
  loadAdapter = loadRepairTicketHttpAdapterModule
} = {}) {
  if (cachedAdapter) return cachedAdapter

  const mod = await loadAdapter()
  const handleRepairTicketRoute = mod && mod.handleRepairTicketRoute
  const createRepairTicketHttpState = mod && mod.createRepairTicketHttpState
  if (typeof handleRepairTicketRoute !== 'function') throw new Error('missing handleRepairTicketRoute export')
  if (typeof createRepairTicketHttpState !== 'function') throw new Error('missing createRepairTicketHttpState export')
  return {
    handleRepairTicketRoute,
    createRepairTicketHttpState
  }
}

export function buildRepairTicketHttpAdapterUnavailableResponse (err) {
  return {
    kind: 'json',
    status: 503,
    payload: {
      error: formatErr('UNSUPPORTED', 'repairticket HTTP adapter unavailable'),
      errorCode: REPAIRTICKET_HTTP_ADAPTER_UNAVAILABLE_CODE
    },
    event: {
      name: 'repairticket-http-adapter-error',
      detail: { error: err }
    }
  }
}
