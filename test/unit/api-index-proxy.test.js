import test from 'brittle'
import {
  INDEX_PROXY_RESPONSE_LIMIT,
  INDEX_PROXY_TIMEOUT_MS,
  buildIndexProxyDisabledResponse,
  buildIndexProxyRouteResponse,
  buildIndexProxyTarget
} from '../../packages/core/core/relay-node/api-index-proxy.js'

function headers (values = {}) {
  return {
    get (name) {
      return values[String(name).toLowerCase()] || null
    }
  }
}

function response (opts = {}) {
  return {
    status: opts.status || 200,
    headers: headers(opts.headers),
    body: opts.body || null,
    text: opts.text || (async () => opts.textValue || '')
  }
}

function streamBody (chunks) {
  let index = 0
  return {
    getReader () {
      return {
        async read () {
          if (index >= chunks.length) return { done: true }
          return { done: false, value: chunks[index++] }
        }
      }
    }
  }
}

function abortFactory (calls) {
  return () => ({
    signal: { aborted: false },
    abort () {
      calls.push('abort')
      this.signal.aborted = true
    }
  })
}

test('api index proxy: disabled response is stable and public-safe', (t) => {
  t.alike(buildIndexProxyDisabledResponse(), {
    kind: 'json',
    status: 501,
    payload: {
      error: 'index sidecar not configured',
      errorCode: 'index-disabled'
    }
  })
})

test('api index proxy: target preserves path and query without forwarding client headers', async (t) => {
  const url = new URL('http://relay.local/index/rooms/demo?limit=2')
  t.is(buildIndexProxyTarget('http://127.0.0.1:9000', url), 'http://127.0.0.1:9000/index/rooms/demo?limit=2')

  const calls = []
  const result = await buildIndexProxyRouteResponse({
    base: 'http://127.0.0.1:9000',
    url,
    fetchImpl: async (target, opts) => {
      calls.push({ target, opts })
      return response({
        status: 202,
        textValue: '{"ok":true}'
      })
    },
    createAbortController: abortFactory([]),
    setTimeoutFn: () => 1,
    clearTimeoutFn: () => {}
  })

  t.is(calls.length, 1)
  t.is(calls[0].target, 'http://127.0.0.1:9000/index/rooms/demo?limit=2')
  t.alike(calls[0].opts.headers, { Accept: 'application/json' })
  t.is(calls[0].opts.method, 'GET')
  t.is(result.kind, 'text')
  t.is(result.status, 202)
  t.is(result.text, '{"ok":true}')
  t.alike(result.headers, { 'Content-Type': 'application/json' })
})

test('api index proxy: streams upstream JSON while enforcing a byte cap', async (t) => {
  const result = await buildIndexProxyRouteResponse({
    base: 'http://sidecar',
    url: new URL('http://relay.local/api/index/room'),
    fetchImpl: async () => response({
      body: streamBody([Buffer.from('{"room":'), Buffer.from('"abc"}')])
    }),
    createAbortController: abortFactory([]),
    setTimeoutFn: () => 1,
    clearTimeoutFn: () => {}
  })

  t.is(result.kind, 'buffer')
  t.is(result.status, 200)
  t.is(result.body.toString(), '{"room":"abc"}')
})

test('api index proxy: declared oversized upstream body aborts before buffering', async (t) => {
  const aborts = []
  const result = await buildIndexProxyRouteResponse({
    base: 'http://sidecar',
    url: new URL('http://relay.local/index/search'),
    fetchImpl: async () => response({
      headers: { 'content-length': String(INDEX_PROXY_RESPONSE_LIMIT + 1) },
      textValue: 'must not be read'
    }),
    createAbortController: abortFactory(aborts),
    setTimeoutFn: () => 1,
    clearTimeoutFn: () => {}
  })

  t.alike(aborts, ['abort'])
  t.alike(result, {
    kind: 'json',
    status: 502,
    payload: { error: 'index response too large' }
  })
})

test('api index proxy: streamed oversized upstream body aborts incrementally', async (t) => {
  const aborts = []
  const result = await buildIndexProxyRouteResponse({
    base: 'http://sidecar',
    url: new URL('http://relay.local/index/search'),
    limitBytes: 4,
    fetchImpl: async () => response({
      body: streamBody([Buffer.from('abcd'), Buffer.from('e')])
    }),
    createAbortController: abortFactory(aborts),
    setTimeoutFn: () => 1,
    clearTimeoutFn: () => {}
  })

  t.alike(aborts, ['abort'])
  t.is(result.kind, 'json')
  t.is(result.status, 502)
  t.is(result.payload.error, 'index response too large')
})

test('api index proxy: text fallback uses byte length for cap enforcement', async (t) => {
  const result = await buildIndexProxyRouteResponse({
    base: 'http://sidecar',
    url: new URL('http://relay.local/index/search'),
    limitBytes: 3,
    fetchImpl: async () => response({
      textValue: 'éé'
    }),
    createAbortController: abortFactory([]),
    setTimeoutFn: () => 1,
    clearTimeoutFn: () => {}
  })

  t.is(result.kind, 'json')
  t.is(result.status, 502)
  t.is(result.payload.error, 'index response too large')
})

test('api index proxy: timeout and fetch failures produce stable public errors with internal event detail', async (t) => {
  const timeout = new Error('private sidecar path /tmp/index.sock stalled')
  timeout.name = 'AbortError'
  const unreachable = new Error('connect ECONNREFUSED 127.0.0.1:9100')

  for (const [err, status] of [[timeout, 504], [unreachable, 502]]) {
    const result = await buildIndexProxyRouteResponse({
      base: 'http://sidecar',
      url: new URL('http://relay.local/index/search'),
      fetchImpl: async () => { throw err },
      createAbortController: abortFactory([]),
      setTimeoutFn: (fn, ms) => {
        t.is(ms, INDEX_PROXY_TIMEOUT_MS)
        return fn
      },
      clearTimeoutFn: () => {}
    })

    t.is(result.kind, 'json')
    t.is(result.status, status)
    t.is(result.payload.error, 'unsupported: index sidecar unreachable')
    t.is(result.payload.errorCode, 'index-unreachable')
    t.is(result.event.name, 'index-proxy-error')
    t.is(result.event.detail.error, err)
    t.is(result.event.detail.status, status)
  }
})
