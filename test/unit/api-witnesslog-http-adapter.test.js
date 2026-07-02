import test from 'brittle'
import {
  WITNESSLOG_HTTP_ADAPTER_UNAVAILABLE_CODE,
  buildWitnessLogHttpAdapterUnavailableResponse,
  resolveWitnessLogHttpAdapter
} from '../../packages/core/core/relay-node/api-witnesslog-http-adapter.js'

test('api witnesslog http adapter: cached adapter is reused without loading optional module', async (t) => {
  const cached = {
    handleWitnessLogRoute: async function handleWitnessLogRoute () {},
    createWitnessLogHttpState () {}
  }
  const adapter = await resolveWitnessLogHttpAdapter({
    cachedAdapter: cached,
    loadAdapter: async () => {
      t.fail('cached adapter must skip optional adapter import')
    }
  })

  t.is(adapter, cached)
})

test('api witnesslog http adapter: loader returns required exports', async (t) => {
  const loaded = {
    handleWitnessLogRoute: async function handleWitnessLogRoute () {},
    createWitnessLogHttpState () {}
  }
  const adapter = await resolveWitnessLogHttpAdapter({
    loadAdapter: async () => loaded
  })

  t.is(adapter.handleWitnessLogRoute, loaded.handleWitnessLogRoute)
  t.is(adapter.createWitnessLogHttpState, loaded.createWitnessLogHttpState)
})

test('api witnesslog http adapter: missing exports fail before request handling', async (t) => {
  let routeErr = null
  try {
    await resolveWitnessLogHttpAdapter({
      loadAdapter: async () => ({
        createWitnessLogHttpState () {}
      })
    })
  } catch (error) {
    routeErr = error
  }
  t.is(routeErr && routeErr.message, 'missing handleWitnessLogRoute export')

  let stateErr = null
  try {
    await resolveWitnessLogHttpAdapter({
      loadAdapter: async () => ({
        handleWitnessLogRoute: async function handleWitnessLogRoute () {}
      })
    })
  } catch (error) {
    stateErr = error
  }
  t.is(stateErr && stateErr.message, 'missing createWitnessLogHttpState export')
})

test('api witnesslog http adapter: unavailable response redacts public payload and keeps event detail', (t) => {
  const err = new Error('internal adapter path /data/hiverelay/private/witnesslog/http-adapter.js failed')
  const result = buildWitnessLogHttpAdapterUnavailableResponse(err)

  t.is(result.kind, 'json')
  t.is(result.status, 503)
  t.is(result.payload.error, 'unsupported: witnesslog HTTP adapter unavailable')
  t.is(result.payload.errorCode, WITNESSLOG_HTTP_ADAPTER_UNAVAILABLE_CODE)
  t.absent(JSON.stringify(result.payload).includes('/data/hiverelay/private'))
  t.is(result.event.name, 'witnesslog-http-adapter-error')
  t.is(result.event.detail.error, err)
})
