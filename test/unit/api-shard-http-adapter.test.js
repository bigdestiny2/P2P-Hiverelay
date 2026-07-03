import test from 'brittle'
import {
  SHARD_HTTP_ADAPTER_UNAVAILABLE_CODE,
  resolveShardHttpAdapter,
  buildShardHttpAdapterUnavailableResponse
} from 'p2p-hiverelay/core/relay-node/api-shard-http-adapter.js'

const goodModule = {
  resolveShardRoute () { return null },
  handleShardHttp () { return true },
  createShardHttpState () { return { buckets: new Map() } }
}

test('resolveShardHttpAdapter surfaces the three shard adapter exports', async (t) => {
  const adapter = await resolveShardHttpAdapter({ loadAdapter: async () => goodModule })
  t.is(typeof adapter.resolveShardRoute, 'function')
  t.is(typeof adapter.handleShardHttp, 'function')
  t.is(typeof adapter.createShardHttpState, 'function')
})

test('resolveShardHttpAdapter returns a cached adapter without reloading', async (t) => {
  let loads = 0
  const cached = { resolveShardRoute () {}, handleShardHttp () {}, createShardHttpState () {} }
  const adapter = await resolveShardHttpAdapter({
    cachedAdapter: cached,
    loadAdapter: async () => { loads++; return goodModule }
  })
  t.is(adapter, cached)
  t.is(loads, 0, 'cached adapter short-circuits the loader')
})

test('resolveShardHttpAdapter throws when an export is missing', async (t) => {
  await t.exception(
    resolveShardHttpAdapter({ loadAdapter: async () => ({ handleShardHttp () {}, createShardHttpState () {} }) }),
    /missing resolveShardRoute export/
  )
  await t.exception(
    resolveShardHttpAdapter({ loadAdapter: async () => ({ resolveShardRoute () {}, createShardHttpState () {} }) }),
    /missing handleShardHttp export/
  )
  await t.exception(
    resolveShardHttpAdapter({ loadAdapter: async () => ({ resolveShardRoute () {}, handleShardHttp () {} }) }),
    /missing createShardHttpState export/
  )
})

test('buildShardHttpAdapterUnavailableResponse redacts internals into an event', (t) => {
  const err = new Error('internal adapter path /data/hiverelay/private/shard/http-adapter.js failed')
  const out = buildShardHttpAdapterUnavailableResponse(err)
  t.is(out.status, 503)
  t.is(out.payload.errorCode, SHARD_HTTP_ADAPTER_UNAVAILABLE_CODE)
  t.absent(JSON.stringify(out.payload).includes('/data/hiverelay/private'), 'client payload never leaks the path')
  t.is(out.event.name, 'shard-http-adapter-error')
  t.ok(out.event.detail.error.message.includes('/data/hiverelay/private'), 'operator event keeps the detail')
})
