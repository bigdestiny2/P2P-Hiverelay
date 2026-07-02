import test from 'brittle'
import {
  buildServiceCatalogPayload,
  buildServiceReadRoutePayload,
  resolveServiceReadRoute
} from 'p2p-hiverelay/core/relay-node/api-service-read.js'

test('api service read: route helper maps exact service catalog route', (t) => {
  t.alike(resolveServiceReadRoute('GET', '/api/v1/services'), {
    kind: 'service-catalog'
  })

  t.is(resolveServiceReadRoute('POST', '/api/v1/services'), null)
  t.is(resolveServiceReadRoute('GET', '/api/v1/services/extra'), null)
  t.is(resolveServiceReadRoute('GET', '/api/v1/router'), null)
})

test('api service read: route payload helper dispatches sanitized service catalog', (t) => {
  let calls = 0
  const registry = {
    catalog () {
      calls++
      return [{
        name: 'poker',
        version: '1.0.0',
        capabilities: ['table-log'],
        secretToken: 'do-not-leak'
      }]
    }
  }

  const result = buildServiceReadRoutePayload({
    route: { kind: 'service-catalog' },
    registry
  })
  const unknown = buildServiceReadRoutePayload({
    route: { kind: 'unknown' },
    registry
  })

  t.is(calls, 1)
  t.is(result.status, 200)
  t.is(result.headers['Cache-Control'], 'public, max-age=10')
  t.is(result.payload.count, 1)
  t.is(result.payload.services[0].name, 'poker')
  t.absent(JSON.stringify(result.payload).includes('secretToken'))
  t.is(unknown.status, 404)
  t.is(unknown.payload.error, 'unknown service read route')
})

test('api service read: missing registry returns stable disabled payload', (t) => {
  t.alike(buildServiceCatalogPayload(), {
    status: 503,
    payload: { error: 'Services not enabled' }
  })
})
