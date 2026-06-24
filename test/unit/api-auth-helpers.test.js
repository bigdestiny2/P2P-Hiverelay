import test from 'brittle'
import {
  constantTimeStringEqual,
  hasLoopbackHostHeader,
  hasLoopbackOrigin,
  isLoopbackHost,
  isLoopbackLocalRequest,
  normalizeHostLike
} from 'p2p-hiverelay/core/relay-node/api-auth-helpers.js'

function req (headers = {}, remoteAddress = '127.0.0.1') {
  return { socket: { remoteAddress }, headers }
}

test('api auth helpers: constant-time string check requires exact string and length', (t) => {
  t.ok(constantTimeStringEqual('Bearer secret', 'Bearer secret'))
  t.absent(constantTimeStringEqual('Bearer secretx', 'Bearer secret'))
  t.absent(constantTimeStringEqual('Bearer secreu', 'Bearer secret'))
  t.absent(constantTimeStringEqual(null, 'Bearer secret'))
  t.absent(constantTimeStringEqual('Bearer secret', null))
})

test('api auth helpers: loopback host normalization handles ports and IPv6 brackets', (t) => {
  t.is(normalizeHostLike('LOCALHOST:9100'), 'localhost')
  t.is(normalizeHostLike('localhost.'), 'localhost.')
  t.is(normalizeHostLike('[::1]:9100'), '::1')
  t.is(normalizeHostLike('::1'), '::1')
  t.is(normalizeHostLike('attacker.test:9100'), 'attacker.test')
  t.ok(isLoopbackHost('127.0.0.1:9100'))
  t.ok(isLoopbackHost('[::1]:9100'))
  t.absent(isLoopbackHost('attacker.test:9100'))
})

test('api auth helpers: Host and Origin loopback checks reject rebinding inputs', (t) => {
  t.ok(hasLoopbackHostHeader(req({ host: 'localhost:9100' })))
  t.ok(hasLoopbackHostHeader(req({ host: '[::1]:9100' })))
  t.absent(hasLoopbackHostHeader(req({ host: 'attacker.test:9100' })))

  t.ok(hasLoopbackOrigin(req({ origin: 'http://localhost:9100' })))
  t.ok(hasLoopbackOrigin(req({ origin: 'http://[::1]:9100' })))
  t.absent(hasLoopbackOrigin(req({ origin: 'https://attacker.test' })))
  t.absent(hasLoopbackOrigin(req({ origin: 'null' })))
})

test('api auth helpers: local fallback requires loopback socket, host, origin, and no trustProxy', (t) => {
  t.ok(isLoopbackLocalRequest(req({ host: 'localhost:9100', origin: 'http://localhost:9100' })))
  t.ok(isLoopbackLocalRequest(req({ host: '[::1]:9100', origin: 'http://[::1]:9100' }, '::1')))
  t.absent(isLoopbackLocalRequest(req({ host: 'attacker.test:9100', origin: 'http://attacker.test:9100' })))
  t.absent(isLoopbackLocalRequest(req({ host: 'localhost:9100', origin: 'https://attacker.test' })))
  t.absent(isLoopbackLocalRequest(req({ host: 'localhost:9100' }, '10.0.0.5')))
  t.absent(isLoopbackLocalRequest(req({ host: 'localhost:9100' }), true))
})
