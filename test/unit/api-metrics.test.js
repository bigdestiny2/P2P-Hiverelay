import test from 'brittle'
import {
  buildMetricsRouteResponse,
  resolveMetricsRoute
} from 'p2p-hiverelay/core/relay-node/api-metrics.js'

test('api metrics: route resolver maps only the exact public metrics route', (t) => {
  t.alike(resolveMetricsRoute('GET', '/metrics'), { kind: 'metrics' })
  t.is(resolveMetricsRoute('POST', '/metrics'), null, 'wrong method falls through')
  t.is(resolveMetricsRoute('GET', '/metrics/extra'), null, 'subpath falls through')
  t.is(resolveMetricsRoute('GET', '/health'), null, 'adjacent health route falls through')
  t.is(resolveMetricsRoute('GET', '/status'), null, 'adjacent status route falls through')
})

test('api metrics: response builder appends auth-failure metrics to exporter output', (t) => {
  const calls = []
  const out = buildMetricsRouteResponse({
    metrics: {
      toPrometheus () {
        calls.push('toPrometheus')
        return '# base metrics\nhiverelay_connections 2\n'
      }
    },
    authFailureLines: 'hiverelay_auth_failures_total{route="/seed"} 2\n'
  })

  t.is(out.ok, true)
  t.is(out.status, 200)
  t.is(out.text, '# base metrics\nhiverelay_connections 2\nhiverelay_auth_failures_total{route="/seed"} 2\n')
  t.alike(calls, ['toPrometheus'])
})

test('api metrics: response builder preserves disabled metrics fallback', (t) => {
  const out = buildMetricsRouteResponse({ metrics: null })

  t.alike(out, {
    ok: false,
    status: 503,
    payload: { error: 'Metrics not enabled' }
  })
})
