import test from 'brittle'
import {
  ALERT_SEVERITIES,
  MAX_ALERT_TEST_DETAILS_BYTES,
  MAX_ALERT_TEST_MESSAGE_BYTES,
  MAX_ALERT_TYPE_FILTER_BYTES,
  buildAlertLogPayload,
  resolveAlertManagementRoute,
  runAlertManagementRouteAction,
  runAlertTestAction
} from 'p2p-hiverelay/core/relay-node/api-alert-management.js'

test('api alert management: route helper maps exact alert management routes', (t) => {
  t.alike(resolveAlertManagementRoute('GET', '/api/alerts'), {
    kind: 'log',
    authMessage: 'Unauthorized — API key required for /api/alerts'
  })
  t.alike(resolveAlertManagementRoute('POST', '/api/alerts/test'), {
    kind: 'test',
    authMessage: 'Unauthorized — API key required for /api/alerts/test'
  })
  t.is(resolveAlertManagementRoute('POST', '/api/alerts'), null)
  t.is(resolveAlertManagementRoute('GET', '/api/alerts/test'), null)
  t.is(resolveAlertManagementRoute('GET', '/api/alerts/test/extra'), null)
  t.is(resolveAlertManagementRoute('GET', '/api/alerts-public'), null)
})

test('api alert management: route action helper dispatches log and test primitives', (t) => {
  const getLogCalls = []
  const fireTestCalls = []
  const alertManager = {
    getLog (opts) {
      getLogCalls.push(opts)
      return { total: 1, offset: opts.offset, limit: opts.limit, items: [{ type: 'disk' }] }
    },
    fireTest (opts) {
      fireTestCalls.push(opts)
      return true
    }
  }

  const log = runAlertManagementRouteAction({
    route: { kind: 'log' },
    alertManager,
    url: new URL('http://relay.local/api/alerts?offset=3&limit=4&severity=warn&type=disk')
  })
  const testAlert = runAlertManagementRouteAction({
    route: { kind: 'test' },
    alertManager,
    body: { severity: 'critical', message: 'manual test', details: { source: 'unit' } }
  })
  const unknown = runAlertManagementRouteAction({
    route: { kind: 'unknown' },
    alertManager
  })

  t.is(log.ok, true)
  t.alike(getLogCalls, [{ offset: 3, limit: 4, severity: 'warn', type: 'disk' }])
  t.alike(log.payload, { enabled: true, total: 1, offset: 3, limit: 4, items: [{ type: 'disk' }] })
  t.is(testAlert.ok, true)
  t.alike(testAlert.payload, { ok: true, dispatched: true })
  t.alike(fireTestCalls, [{ severity: 'critical', message: 'manual test', details: { source: 'unit' } }])
  t.is(unknown.status, 404)
  t.is(unknown.payload.error, 'unknown alert management route')
})

test('api alert management: alert log validates filters and clamps pagination before lookup', (t) => {
  t.alike(ALERT_SEVERITIES, ['info', 'warn', 'error', 'critical'])
  t.is(MAX_ALERT_TYPE_FILTER_BYTES, 80)
  const calls = []
  const alertManager = {
    getLog (opts) {
      calls.push(opts)
      return { total: 0, offset: opts.offset, limit: opts.limit, items: [] }
    }
  }

  const ok = buildAlertLogPayload({
    alertManager,
    url: new URL('http://relay.local/api/alerts?offset=-10&limit=999999999999999999&type=disk-low&severity=critical')
  })
  t.is(ok.ok, true)
  t.alike(calls[0], { offset: 0, limit: 500, severity: 'critical', type: 'disk-low' })
  t.alike(ok.payload, { enabled: true, total: 0, offset: 0, limit: 500, items: [] })

  const badSeverity = buildAlertLogPayload({
    alertManager,
    url: new URL('http://relay.local/api/alerts?severity=debug')
  })
  t.is(badSeverity.status, 400)
  t.is(badSeverity.payload.error, 'severity must be one of: info, warn, error, critical')

  const badType = buildAlertLogPayload({
    alertManager,
    url: new URL('http://relay.local/api/alerts?type=' + encodeURIComponent('../secret'))
  })
  t.is(badType.status, 400)
  t.is(calls.length, 1, 'invalid filters do not reach getLog')
})

test('api alert management: missing manager returns disabled alert log payload', (t) => {
  const result = buildAlertLogPayload({ url: new URL('http://relay.local/api/alerts') })
  t.alike(result, {
    ok: true,
    payload: { enabled: false, total: 0, offset: 0, limit: 0, items: [] }
  })
})

test('api alert management: test alert validates body before dispatch', (t) => {
  t.is(MAX_ALERT_TEST_MESSAGE_BYTES, 512)
  t.is(MAX_ALERT_TEST_DETAILS_BYTES, 2048)
  const calls = []
  const alertManager = {
    fireTest (opts) {
      calls.push(opts)
      return true
    }
  }

  const badSeverity = runAlertTestAction({
    alertManager,
    body: { severity: 'debug' }
  })
  t.is(badSeverity.status, 400)

  const badMessage = runAlertTestAction({
    alertManager,
    body: { message: 'x'.repeat(513) }
  })
  t.is(badMessage.status, 400)
  t.is(badMessage.payload.error, 'message must be 512 bytes or smaller')

  const badDetailsShape = runAlertTestAction({
    alertManager,
    body: { details: [] }
  })
  t.is(badDetailsShape.status, 400)
  t.is(badDetailsShape.payload.error, 'details must be an object')

  const badDetailsSize = runAlertTestAction({
    alertManager,
    body: { details: { data: 'x'.repeat(2048) } }
  })
  t.is(badDetailsSize.status, 400)
  t.is(badDetailsSize.payload.error, 'details must be 2048 bytes or smaller')
  t.is(calls.length, 0, 'invalid test alerts do not dispatch')

  const ok = runAlertTestAction({
    alertManager,
    body: { severity: 'warn', message: 'test message', details: { source: 'unit' } }
  })
  t.is(ok.ok, true)
  t.alike(ok.payload, { ok: true, dispatched: true })
  t.alike(calls, [{ severity: 'warn', message: 'test message', details: { source: 'unit' } }])
})

test('api alert management: test alert reports disabled manager', (t) => {
  const result = runAlertTestAction({ body: { severity: 'warn' } })
  t.is(result.status, 503)
  t.alike(result.payload, { error: 'AlertManager not enabled' })
})
