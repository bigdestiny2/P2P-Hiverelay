import test from 'brittle'
import { BareHttpServer } from '../../packages/core/core/relay-node/bare-http-server.js'
import { CATALOG_TYPE_ERROR } from '../../packages/core/core/relay-node/api-catalog-read.js'

test('bare http server: public JSON responses use hardened headers', (t) => {
  const server = new BareHttpServer(fakeRelay())
  const res = fakeRes()

  server._handle({ url: '/health', headers: { host: 'localhost' } }, res)

  t.is(res.statusCode, 200)
  t.is(res.headers['Content-Type'], 'application/json; charset=utf-8')
  t.is(res.headers['X-Content-Type-Options'], 'nosniff')
  t.is(res.headers['Cache-Control'], 'no-store, max-age=0')
  t.is(res.headers['Access-Control-Allow-Origin'], '*')
  t.is(JSON.parse(res.body).runtime, 'bare')
})

test('bare http server: capability docs preserve public cache while keeping JSON hardening', (t) => {
  const server = new BareHttpServer(fakeRelay(), { version: '1.2.3' })
  const res = fakeBareRes()

  server._handle({ url: '/api/capabilities', headers: { host: 'localhost' } }, res)

  t.is(res.statusCode, 200)
  t.is(res.header('Content-Type'), 'application/json; charset=utf-8')
  t.is(res.header('X-Content-Type-Options'), 'nosniff')
  t.is(res.header('Cache-Control'), 'public, max-age=60')
  t.is(res.header('Access-Control-Allow-Origin'), '*')
  const body = JSON.parse(res.body)
  t.is(body.runtime, 'bare')
  t.is(body.version, '1.2.3')
})

test('bare http server: anchors route reuses bounded public anchor payload', (t) => {
  const relay = fakeRelay()
  relay._lastAnchorCheckAt = 12345
  relay.appRegistry.anchorStats = function () {
    return {
      total: 2,
      anchored: 1,
      unanchored: 1,
      neverChecked: 0,
      rawSchedulerState: 'should-not-leak'
    }
  }
  relay.appRegistry.catalog = function () {
    t.fail('Bare public anchors route must not enumerate catalog entries')
    return []
  }

  const server = new BareHttpServer(relay)
  const res = fakeRes()

  server._handle({ url: '/api/anchors', headers: { host: 'localhost' } }, res)

  t.is(res.statusCode, 200)
  t.alike(JSON.parse(res.body), {
    total: 2,
    anchored: 1,
    unanchored: 1,
    neverChecked: 0,
    lastCheckedAt: 12345,
    entries: null
  })
  t.absent(res.body.includes('should-not-leak'))
})

test('bare http server: catalog route reuses bounded relay catalog helper', (t) => {
  const relay = fakeRelay()
  const entries = [
    { type: 'drive', key: 'drive-1', name: 'Drive 1', categories: ['docs'] },
    { type: 'drive', key: 'drive-2', name: 'Drive 2', categories: ['docs'] },
    { type: 'drive', key: 'mounted-1', parentKey: 'drive-1', name: 'Mounted resource' },
    { type: 'app', key: 'app-1', name: 'Filtered app' }
  ]
  let catalogOpts = null
  relay.publicKey = Buffer.alloc(32, 9)
  relay.config.operator = 'operator-one'
  relay.appRegistry.catalog = function (opts) {
    catalogOpts = opts
    return entries
  }

  const server = new BareHttpServer(relay)
  const res = fakeRes()

  server._handle({ url: '/catalog.json?pageSize=1&type=drive', headers: { host: 'localhost' } }, res)

  const body = JSON.parse(res.body)
  t.is(res.statusCode, 200)
  t.is(body.version, 2)
  t.is(body.relayKey, '09'.repeat(32))
  t.is(body.region, 'test')
  t.is(body.operator, 'operator-one')
  t.alike(body.filters, { type: 'drive', parent: null, category: null })
  t.alike(body.pagination, {
    page: 1,
    pageSize: 1,
    total: 3,
    totalPages: 3,
    hasNext: true,
    hasPrev: false
  })
  t.alike(body.count, {
    total: 3,
    apps: 0,
    drives: 2,
    resources: 1,
    datasets: 0,
    media: 0
  })
  t.alike(body.entries, [entries[0]])
  t.alike(body.drives, [entries[0]])
  t.alike(body.resources, [])
  t.alike(catalogOpts, { redactPrivate: true })
  t.absent(res.body.includes('app-1'))
})

test('bare http server: catalog route rejects invalid type filters', (t) => {
  const server = new BareHttpServer(fakeRelay())
  const res = fakeRes()

  server._handle({ url: '/catalog.json?type=unknown', headers: { host: 'localhost' } }, res)

  t.is(res.statusCode, 400)
  t.alike(JSON.parse(res.body), { error: CATALOG_TYPE_ERROR })
})

test('bare http server: 404 responses use the same hardened JSON path', (t) => {
  const server = new BareHttpServer(fakeRelay())
  const res = fakeRes()

  server._handle({ url: '/missing?token=secret', headers: { host: 'localhost' } }, res)

  t.is(res.statusCode, 404)
  t.is(res.headers['Content-Type'], 'application/json; charset=utf-8')
  t.is(res.headers['X-Content-Type-Options'], 'nosniff')
  t.is(res.headers['Cache-Control'], 'no-store, max-age=0')
  t.is(res.headers['Access-Control-Allow-Origin'], '*')
  t.alike(JSON.parse(res.body), { error: 'Not found', path: '/missing' })
})

function fakeRelay () {
  return {
    startedAt: Date.now() - 1000,
    publicKey: null,
    config: {
      regions: ['test'],
      maxStorageBytes: 123,
      discovery: { dht: true }
    },
    connections: new Map(),
    seeder: { totalBytesStored: 0 },
    appRegistry: {
      apps: new Map(),
      anchorStats () {
        return { total: 0, anchored: 0, unanchored: 0, neverChecked: 0 }
      },
      catalog () {
        return []
      }
    },
    serviceRegistry: null
  }
}

function fakeRes () {
  const headers = {}
  return {
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
}

function fakeBareRes () {
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
