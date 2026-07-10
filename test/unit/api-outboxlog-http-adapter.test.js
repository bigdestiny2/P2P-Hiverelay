import test from 'brittle'
import {
  OUTBOXLOG_HTTP_ADAPTER_UNAVAILABLE_CODE,
  OUTBOXLOG_HTTP_RATE_LIMIT_DEFAULT,
  buildOutboxLogHttpAdapterUnavailableResponse,
  configuredOutboxLogHttpRateLimit,
  normalizeOutboxLogHttpRateLimit,
  outboxLogHttpRateLimitAdapterConfig,
  resolveOutboxLogHttpAdapter
} from '../../packages/core/core/relay-node/api-outboxlog-http-adapter.js'

test('api outboxlog rate limit config: defaults, explicit overrides, disable, aliases, and invalid values', (t) => {
  t.alike(normalizeOutboxLogHttpRateLimit(), OUTBOXLOG_HTTP_RATE_LIMIT_DEFAULT)
  t.alike(normalizeOutboxLogHttpRateLimit({ windowMs: 120_000, max: 12_000 }), { enabled: true, windowMs: 120_000, max: 12_000 })
  t.alike(normalizeOutboxLogHttpRateLimit(false), { enabled: false, windowMs: 60_000, max: null })
  t.alike(normalizeOutboxLogHttpRateLimit({ enabled: false, windowMs: 5_000 }), { enabled: false, windowMs: 5_000, max: null })
  t.alike(normalizeOutboxLogHttpRateLimit(normalizeOutboxLogHttpRateLimit(false)), { enabled: false, windowMs: 60_000, max: null })
  t.alike(outboxLogHttpRateLimitAdapterConfig(false), { enabled: false, windowMs: 60_000, max: false })
  t.is(configuredOutboxLogHttpRateLimit({ outboxlog: { http: { rateLimit: { max: 2 } } } }).max, 2)
  t.is(configuredOutboxLogHttpRateLimit({ outboxlog: { api: { rateLimit: false } } }), false)

  for (const invalid of [null, true, { max: 0 }, { max: 10_000_001 }, { max: '1200' }, { max: null }, { windowMs: 0 }, { enabled: 'no' }, { enabled: true, max: false }, { unknown: 1 }]) {
    let err = null
    try { normalizeOutboxLogHttpRateLimit(invalid) } catch (error) { err = error }
    t.ok(err, 'invalid config rejected: ' + JSON.stringify(invalid))
  }
})

test('api outboxlog http adapter: cached adapter is reused without loading optional module', async (t) => {
  const cached = {
    handleOutboxLogRoute: async function handleOutboxLogRoute () {},
    createOutboxLogTokenAuth () {},
    createOutboxLogHttpState () {},
    createOutboxLogAdminAuth () {}
  }
  const adapter = await resolveOutboxLogHttpAdapter({
    cachedAdapter: cached,
    loadAdapter: async () => {
      t.fail('cached adapter must skip optional adapter import')
    }
  })

  t.is(adapter, cached)
})

test('api outboxlog http adapter: loader returns required exports', async (t) => {
  const loaded = {
    handleOutboxLogRoute: async function handleOutboxLogRoute () {},
    createOutboxLogTokenAuth () {},
    createOutboxLogHttpState () {},
    createOutboxLogAdminAuth () {}
  }
  const adapter = await resolveOutboxLogHttpAdapter({
    loadAdapter: async () => loaded
  })

  t.is(adapter.handleOutboxLogRoute, loaded.handleOutboxLogRoute)
  t.is(adapter.createOutboxLogTokenAuth, loaded.createOutboxLogTokenAuth)
  t.is(adapter.createOutboxLogHttpState, loaded.createOutboxLogHttpState)
  t.is(adapter.createOutboxLogAdminAuth, loaded.createOutboxLogAdminAuth)
})

test('api outboxlog http adapter: missing route export fails before request handling', async (t) => {
  let err = null
  try {
    await resolveOutboxLogHttpAdapter({
      loadAdapter: async () => ({
        createOutboxLogTokenAuth () {},
        createOutboxLogHttpState () {}
      })
    })
  } catch (error) {
    err = error
  }

  t.ok(err)
  t.is(err.message, 'missing handleOutboxLogRoute export')
})

test('api outboxlog http adapter: missing token/state exports fail before request handling', async (t) => {
  let tokenErr = null
  try {
    await resolveOutboxLogHttpAdapter({
      loadAdapter: async () => ({
        handleOutboxLogRoute: async function handleOutboxLogRoute () {},
        createOutboxLogHttpState () {}
      })
    })
  } catch (error) {
    tokenErr = error
  }
  t.is(tokenErr && tokenErr.message, 'missing createOutboxLogTokenAuth export')

  let stateErr = null
  try {
    await resolveOutboxLogHttpAdapter({
      loadAdapter: async () => ({
        handleOutboxLogRoute: async function handleOutboxLogRoute () {},
        createOutboxLogTokenAuth () {}
      })
    })
  } catch (error) {
    stateErr = error
  }
  t.is(stateErr && stateErr.message, 'missing createOutboxLogHttpState export')

  let adminErr = null
  try {
    await resolveOutboxLogHttpAdapter({
      loadAdapter: async () => ({
        handleOutboxLogRoute: async function handleOutboxLogRoute () {},
        createOutboxLogTokenAuth () {},
        createOutboxLogHttpState () {}
      })
    })
  } catch (error) {
    adminErr = error
  }
  t.is(adminErr && adminErr.message, 'missing createOutboxLogAdminAuth export')
})

test('api outboxlog http adapter: unavailable response redacts public payload and keeps event detail', (t) => {
  const err = new Error('internal adapter path /data/hiverelay/private/outboxlog/http-adapter.js failed')
  const result = buildOutboxLogHttpAdapterUnavailableResponse(err)

  t.is(result.kind, 'json')
  t.is(result.status, 503)
  t.is(result.payload.error, 'unsupported: outboxlog HTTP adapter unavailable')
  t.is(result.payload.errorCode, OUTBOXLOG_HTTP_ADAPTER_UNAVAILABLE_CODE)
  t.absent(JSON.stringify(result.payload).includes('/data/hiverelay/private'))
  t.is(result.event.name, 'outboxlog-http-adapter-error')
  t.is(result.event.detail.error, err)
})
