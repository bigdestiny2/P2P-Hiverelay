import test from 'brittle'
import {
  EVICTION_PURGE_AUTH_MESSAGE,
  MAX_PURGE_APP_KEYS,
  resolveEvictionPurgeRoute,
  runEvictionPurgeAction
} from '../../packages/core/core/relay-node/api-eviction-purge.js'

function key (char) {
  return char.repeat(64)
}

test('api eviction purge: route helper maps exact operator purge route', (t) => {
  t.alike(resolveEvictionPurgeRoute('POST', '/api/eviction/purge'), {
    kind: 'eviction-purge',
    authMessage: EVICTION_PURGE_AUTH_MESSAGE
  })

  t.is(resolveEvictionPurgeRoute('GET', '/api/eviction/purge'), null)
  t.is(resolveEvictionPurgeRoute('POST', '/api/eviction'), null)
  t.is(resolveEvictionPurgeRoute('POST', '/api/eviction/purge/all'), null)
})

test('api eviction purge: validates request body before purging', async (t) => {
  const node = {
    async manualPurge () {
      t.fail('invalid request must not purge')
    }
  }

  let out = await runEvictionPurgeAction({ body: null, node })
  t.is(out.status, 400)
  t.ok(out.payload.error.includes('appKeys (non-empty array) required'))

  out = await runEvictionPurgeAction({ body: { appKeys: [] }, node })
  t.is(out.status, 400)
  t.ok(out.payload.error.includes('appKeys (non-empty array) required'))
})

test('api eviction purge: caps batch size before purging', async (t) => {
  const node = {
    async manualPurge () {
      t.fail('oversized request must not purge')
    }
  }
  const out = await runEvictionPurgeAction({
    body: { appKeys: Array.from({ length: MAX_PURGE_APP_KEYS + 1 }, () => key('a')) },
    node
  })

  t.is(out.status, 400)
  t.ok(out.payload.error.includes('max 50 appKeys per request'))
})

test('api eviction purge: reports invalid keys per item and keeps valid purges moving', async (t) => {
  const calls = []
  const node = {
    async manualPurge (appKey) {
      calls.push(appKey)
      return { bytes: 12 }
    }
  }

  const out = await runEvictionPurgeAction({
    body: { appKeys: ['not-hex', key('b')] },
    node
  })

  t.is(out.status, 200)
  t.is(out.payload.ok, true)
  t.is(out.payload.purged, 1)
  t.is(out.payload.freedBytes, 12)
  t.alike(calls, [key('b')])
  t.alike(out.payload.results[0], { appKey: 'not-hex', ok: false, error: 'invalid appKey' })
  t.alike(out.payload.results[1], { appKey: key('b'), ok: true, bytes: 12 })
})

test('api eviction purge: isolates manual purge failures per key', async (t) => {
  const node = {
    async manualPurge (appKey) {
      if (appKey === key('c')) {
        const err = new Error('custody-bound')
        err.code = 'NOT_PURGABLE'
        throw err
      }
      return { bytes: 5 }
    }
  }

  const out = await runEvictionPurgeAction({
    body: { appKeys: [key('c'), key('d')] },
    node
  })

  t.is(out.status, 200)
  t.is(out.payload.purged, 1)
  t.is(out.payload.freedBytes, 5)
  t.alike(out.payload.results, [
    { appKey: key('c'), ok: false, error: 'NOT_PURGABLE' },
    { appKey: key('d'), ok: true, bytes: 5 }
  ])
})

test('api eviction purge: freed byte aggregation ignores malformed byte results', async (t) => {
  const bytes = new Map([
    [key('a'), 10],
    [key('b'), '11'],
    [key('c'), -4],
    [key('d'), Infinity]
  ])
  const node = {
    async manualPurge (appKey) {
      return { bytes: bytes.get(appKey) }
    }
  }

  const out = await runEvictionPurgeAction({
    body: { appKeys: [key('a'), key('b'), key('c'), key('d')] },
    node
  })

  t.is(out.status, 200)
  t.is(out.payload.purged, 4)
  t.is(out.payload.freedBytes, 10)
  t.alike(out.payload.results.map(result => result.bytes), [10, 0, 0, 0])
})

test('api eviction purge: unavailable manual purge is reported per valid key', async (t) => {
  const out = await runEvictionPurgeAction({
    body: { appKeys: [key('e')] },
    node: {}
  })

  t.is(out.status, 200)
  t.is(out.payload.purged, 0)
  t.alike(out.payload.results, [
    { appKey: key('e'), ok: false, error: 'manual purge unavailable' }
  ])
})
