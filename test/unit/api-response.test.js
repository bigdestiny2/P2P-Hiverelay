import test from 'brittle'
import {
  appendVaryHeader,
  getResponseHeader,
  hasResponseHeader,
  writeJson,
  writeText
} from 'p2p-hiverelay/core/relay-node/api-response.js'

function fakeRes (opts = {}) {
  const headers = { ...(opts.headers || {}) }
  const res = {
    headers,
    statusCode: null,
    body: null,
    setHeader (name, value) {
      headers[name] = value
    },
    getHeader (name) {
      const lower = name.toLowerCase()
      const key = Object.keys(headers).find(key => key.toLowerCase() === lower)
      return key ? headers[key] : undefined
    },
    hasHeader (name) {
      const lower = name.toLowerCase()
      return Object.keys(headers).some(key => key.toLowerCase() === lower)
    },
    writeHead (status) {
      this.statusCode = status
    },
    end (body) {
      this.body = body
    }
  }
  if (opts.getHeader === false) delete res.getHeader
  if (opts.hasHeader === false) delete res.hasHeader
  return res
}

test('api response: header helpers are case-insensitive with fallback storage', (t) => {
  const res = fakeRes({ headers: { 'cache-control': 'public, max-age=60' }, getHeader: false, hasHeader: false })
  t.ok(hasResponseHeader(res, 'Cache-Control'))
  t.is(getResponseHeader(res, 'CACHE-CONTROL'), 'public, max-age=60')
  t.absent(hasResponseHeader(res, 'Vary'))
})

test('api response: appendVaryHeader preserves wildcard and avoids duplicates', (t) => {
  const res = fakeRes({ headers: { Vary: 'Accept-Encoding' } })
  appendVaryHeader(res, 'Origin')
  t.is(res.headers.Vary, 'Accept-Encoding, Origin')
  appendVaryHeader(res, 'origin')
  t.is(res.headers.Vary, 'Accept-Encoding, Origin', 'duplicate Vary value is not appended')

  const wildcard = fakeRes({ headers: { Vary: '*' } })
  appendVaryHeader(wildcard, 'Origin')
  t.is(wildcard.headers.Vary, '*', 'wildcard Vary is preserved')
})

test('api response: writeJson applies JSON security defaults', (t) => {
  const res = fakeRes()
  writeJson(res, { ok: true })

  t.is(res.statusCode, 200)
  t.is(res.headers['Content-Type'], 'application/json; charset=utf-8')
  t.is(res.headers['X-Content-Type-Options'], 'nosniff')
  t.is(res.headers['Cache-Control'], 'no-store, max-age=0')
  t.is(res.body, '{"ok":true}\n')
})

test('api response: writeJson preserves explicit cache and extra headers', (t) => {
  const res = fakeRes()
  writeJson(res, { ok: true }, 202, {
    'Cache-Control': 'public, max-age=60',
    'Retry-After': '60'
  })

  t.is(res.statusCode, 202)
  t.is(res.headers['Cache-Control'], 'public, max-age=60')
  t.is(res.headers['Retry-After'], '60')
  t.is(res.headers['X-Content-Type-Options'], 'nosniff')
})

test('api response: writeJson preserves explicit cache on minimal response objects', (t) => {
  const res = fakeMinimalRes()
  writeJson(res, { ok: true }, 200, { 'Cache-Control': 'public, max-age=60' })

  t.is(res.statusCode, 200)
  t.is(res.header('Cache-Control'), 'public, max-age=60')
  t.is(res.header('Content-Type'), 'application/json; charset=utf-8')
  t.is(res.header('X-Content-Type-Options'), 'nosniff')
  t.is(res.body, '{"ok":true}\n')
})

test('api response: writeText applies plain-text security defaults', (t) => {
  const res = fakeRes()
  writeText(res, 'hello\n')

  t.is(res.statusCode, 200)
  t.is(res.headers['Content-Type'], 'text/plain; charset=utf-8')
  t.is(res.headers['X-Content-Type-Options'], 'nosniff')
  t.is(res.headers['Cache-Control'], 'no-store, max-age=0')
  t.is(res.body, 'hello\n')
})

test('api response: writeText preserves explicit cache and status', (t) => {
  const res = fakeMinimalRes()
  writeText(res, 'created\n', 201, { 'Cache-Control': 'public, max-age=10' })

  t.is(res.statusCode, 201)
  t.is(res.header('Content-Type'), 'text/plain; charset=utf-8')
  t.is(res.header('X-Content-Type-Options'), 'nosniff')
  t.is(res.header('Cache-Control'), 'public, max-age=10')
  t.is(res.body, 'created\n')
})

function fakeMinimalRes () {
  const headers = {}
  return {
    statusCode: null,
    body: null,
    setHeader (name, value) {
      headers[name] = value
    },
    header (name) {
      const lower = name.toLowerCase()
      const key = Object.keys(headers).find(key => key.toLowerCase() === lower)
      return key ? headers[key] : undefined
    },
    writeHead (status) {
      this.statusCode = status
    },
    end (body) {
      this.body = body
    }
  }
}
