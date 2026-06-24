import test from 'brittle'
import {
  authFailureRoute,
  escapePrometheusLabelValue,
  sanitizeAuthFailureRouteChars
} from 'p2p-hiverelay/core/relay-node/api-auth-failures.js'

test('api auth failures: route labels strip query secrets and collapse long hex ids', (t) => {
  const appKey = 'a'.repeat(64)
  const route = authFailureRoute({
    url: '/api/custody/' + appKey + '/commit?api_key=secret&token=abc'
  })
  t.is(route, '/api/custody/:hex/commit')
  t.absent(route.includes('secret'))
  t.absent(route.includes('token=abc'))
  t.absent(route.includes(appKey))
})

test('api auth failures: route labels sanitize unsafe characters and keep leading slash', (t) => {
  t.is(authFailureRoute({ url: 'api/wallet\n"bad"/' + 'd'.repeat(64) }), '/api/wallet:bad/:hex')
  t.is(authFailureRoute({ url: '' }), '/')
  t.is(authFailureRoute(null), '/')
  t.is(sanitizeAuthFailureRouteChars('ok path\n"x"\\y'), 'ok:path::x::y')
})

test('api auth failures: route labels are bounded after normalization', (t) => {
  const route = authFailureRoute({ url: '/' + 'a'.repeat(400) + '?api_key=secret' })
  t.ok(route.length <= 200, 'normalized route is bounded')
  t.absent(route.includes('secret'))
})

test('api auth failures: Prometheus label values escape backslashes quotes and newlines', (t) => {
  t.is(escapePrometheusLabelValue('/api/"bad"\\path\nnext'), '/api/\\"bad\\"\\\\path\\nnext')
})
