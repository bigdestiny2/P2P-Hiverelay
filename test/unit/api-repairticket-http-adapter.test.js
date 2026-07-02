import test from 'brittle'
import {
  REPAIRTICKET_HTTP_ADAPTER_UNAVAILABLE_CODE,
  buildRepairTicketHttpAdapterUnavailableResponse,
  resolveRepairTicketHttpAdapter
} from '../../packages/core/core/relay-node/api-repairticket-http-adapter.js'

test('api repairticket http adapter: cached adapter is reused without loading optional module', async (t) => {
  const cached = {
    handleRepairTicketRoute: async function handleRepairTicketRoute () {},
    createRepairTicketHttpState () {}
  }
  const adapter = await resolveRepairTicketHttpAdapter({
    cachedAdapter: cached,
    loadAdapter: async () => {
      t.fail('cached adapter must skip optional adapter import')
    }
  })

  t.is(adapter, cached)
})

test('api repairticket http adapter: loader returns required exports', async (t) => {
  const loaded = {
    handleRepairTicketRoute: async function handleRepairTicketRoute () {},
    createRepairTicketHttpState () {}
  }
  const adapter = await resolveRepairTicketHttpAdapter({
    loadAdapter: async () => loaded
  })

  t.is(adapter.handleRepairTicketRoute, loaded.handleRepairTicketRoute)
  t.is(adapter.createRepairTicketHttpState, loaded.createRepairTicketHttpState)
})

test('api repairticket http adapter: missing exports fail before request handling', async (t) => {
  let routeErr = null
  try {
    await resolveRepairTicketHttpAdapter({
      loadAdapter: async () => ({
        createRepairTicketHttpState () {}
      })
    })
  } catch (error) {
    routeErr = error
  }
  t.is(routeErr && routeErr.message, 'missing handleRepairTicketRoute export')

  let stateErr = null
  try {
    await resolveRepairTicketHttpAdapter({
      loadAdapter: async () => ({
        handleRepairTicketRoute: async function handleRepairTicketRoute () {}
      })
    })
  } catch (error) {
    stateErr = error
  }
  t.is(stateErr && stateErr.message, 'missing createRepairTicketHttpState export')
})

test('api repairticket http adapter: unavailable response redacts public payload and keeps event detail', (t) => {
  const err = new Error('internal adapter path /data/hiverelay/private/repairticket/http-adapter.js failed')
  const result = buildRepairTicketHttpAdapterUnavailableResponse(err)

  t.is(result.kind, 'json')
  t.is(result.status, 503)
  t.is(result.payload.error, 'unsupported: repairticket HTTP adapter unavailable')
  t.is(result.payload.errorCode, REPAIRTICKET_HTTP_ADAPTER_UNAVAILABLE_CODE)
  t.absent(JSON.stringify(result.payload).includes('/data/hiverelay/private'))
  t.is(result.event.name, 'repairticket-http-adapter-error')
  t.is(result.event.detail.error, err)
})
