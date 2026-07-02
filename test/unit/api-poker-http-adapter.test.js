import test from 'brittle'
import {
  POKER_HTTP_ADAPTER_UNAVAILABLE_CODE,
  buildPokerHttpAdapterUnavailableResponse,
  resolvePokerHttpRouteHandler
} from '../../packages/core/core/relay-node/api-poker-http-adapter.js'

test('api poker http adapter: cached handler is reused without loading optional module', async (t) => {
  const cached = async function handlePokerRoute () {}
  const handler = await resolvePokerHttpRouteHandler({
    cachedHandler: cached,
    loadAdapter: async () => {
      t.fail('cached handler must skip optional adapter import')
    }
  })

  t.is(handler, cached)
})

test('api poker http adapter: loader returns exact handlePokerRoute export', async (t) => {
  const loaded = async function handlePokerRoute () {}
  const handler = await resolvePokerHttpRouteHandler({
    loadAdapter: async () => ({ handlePokerRoute: loaded })
  })

  t.is(handler, loaded)
})

test('api poker http adapter: missing route export fails before request handling', async (t) => {
  let err = null
  try {
    await resolvePokerHttpRouteHandler({
      loadAdapter: async () => ({})
    })
  } catch (error) {
    err = error
  }

  t.ok(err)
  t.is(err.message, 'missing handlePokerRoute export')
})

test('api poker http adapter: unavailable response redacts public payload and keeps event detail', (t) => {
  const err = new Error('internal adapter path /data/hiverelay/private/poker/http-adapter.js failed')
  const result = buildPokerHttpAdapterUnavailableResponse(err)

  t.is(result.kind, 'json')
  t.is(result.status, 503)
  t.is(result.payload.error, 'unsupported: poker HTTP adapter unavailable')
  t.is(result.payload.errorCode, POKER_HTTP_ADAPTER_UNAVAILABLE_CODE)
  t.absent(JSON.stringify(result.payload).includes('/data/hiverelay/private'))
  t.is(result.event.name, 'poker-http-adapter-error')
  t.is(result.event.detail.error, err)
})
