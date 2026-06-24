import test from 'brittle'
import {
  queryInt,
  validatePositiveInt,
  validatePositiveNumber
} from 'p2p-hiverelay/core/relay-node/api-validation.js'

test('api validation: queryInt clamps safe integers and defaults malformed values', (t) => {
  const url = new URL('http://relay.local/api/alerts?offset=-10&limit=999999999999999999999&page=10abc&empty=&plus=%2B8')

  t.is(queryInt(url, 'offset', 0, 0, 10_000), 0)
  t.is(queryInt(url, 'limit', 50, 1, 500), 500)
  t.is(queryInt(url, 'page', 1, 1, 100), 1)
  t.is(queryInt(url, 'missing', 7, 1, 100), 7)
  t.is(queryInt(url, 'empty', 7, 1, 100), 7)
  t.is(queryInt(url, 'plus', 1, 1, 10), 8)
})

test('api validation: queryInt clamps unsafe negative integers to min', (t) => {
  const url = new URL('http://relay.local/api/history?minutes=-999999999999999999999')
  t.is(queryInt(url, 'minutes', 60, 1, 24 * 60), 1)
})

test('api validation: validatePositiveInt accepts plain decimal integers only', (t) => {
  t.alike(validatePositiveInt('12', 0, 100, 'maxConnections'), { ok: true, value: 12, error: null })
  t.alike(validatePositiveInt(12, 0, 100, 'maxConnections'), { ok: true, value: 12, error: null })
  t.alike(validatePositiveInt('12.5', 0, 100, 'maxConnections'), {
    ok: false,
    value: null,
    error: 'maxConnections must be a valid integer'
  })
  t.alike(validatePositiveInt('1e3', 0, 100, 'maxConnections'), {
    ok: false,
    value: null,
    error: 'maxConnections must be a valid integer'
  })
  t.alike(validatePositiveInt(Number.MAX_SAFE_INTEGER + 1, 0, 100, 'maxConnections'), {
    ok: false,
    value: null,
    error: 'maxConnections must be a valid integer'
  })
  t.alike(validatePositiveInt(101, 0, 100, 'maxConnections'), {
    ok: false,
    value: null,
    error: 'maxConnections must be between 0 and 100'
  })
})

test('api validation: validatePositiveNumber accepts plain decimals and rejects exponent/unsafe values', (t) => {
  t.alike(validatePositiveNumber('12.5', 0.1, 100, 'maxRelayBandwidthMbps'), {
    ok: true,
    value: 12.5,
    error: null
  })
  t.alike(validatePositiveNumber('.5', 0.1, 100, 'maxRelayBandwidthMbps'), {
    ok: true,
    value: 0.5,
    error: null
  })
  t.alike(validatePositiveNumber('1e3', 0.1, 100, 'maxRelayBandwidthMbps'), {
    ok: false,
    value: null,
    error: 'maxRelayBandwidthMbps must be a valid number'
  })
  t.alike(validatePositiveNumber(Infinity, 0.1, 100, 'maxRelayBandwidthMbps'), {
    ok: false,
    value: null,
    error: 'maxRelayBandwidthMbps must be a valid number'
  })
  t.alike(validatePositiveNumber(0, 0.1, 100, 'maxRelayBandwidthMbps'), {
    ok: false,
    value: null,
    error: 'maxRelayBandwidthMbps must be between 0.1 and 100'
  })
})
