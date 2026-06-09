/**
 * trustProxy auth-bypass regression test.
 *
 * _isLocalRequest is the authority for the API-key-less auth fallback AND
 * the LOCAL_ONLY_DISPATCH_ROUTES gate (identity.sign). Two bugs:
 *
 *   1. It derived the client IP from _getClientIP, which honors the
 *      attacker-controlled X-Forwarded-For / X-Real-IP headers — so a
 *      remote caller could spoof `X-Forwarded-For: 127.0.0.1` and pass
 *      every localhost-gated check.
 *   2. Under trustProxy a 127.0.0.1 socket is the co-located reverse proxy,
 *      not a trusted local admin, so localhost is never sufficient for
 *      authorization in that mode.
 *
 * The fix: _isLocalRequest reads the real socket address (never XFF) and
 * returns false whenever trustProxy is set.
 */

import test from 'brittle'
import { RelayAPI } from 'p2p-hiverelay/core/relay-node/api.js'

function makeApi (opts = {}) {
  // Minimal node stub — _isLocalRequest/_checkAuth touch nothing on it.
  const api = new RelayAPI({ emit () {} }, { apiPort: 0, apiHost: '127.0.0.1' })
  api._apiKey = opts.apiKey || null // deterministic regardless of env
  api.trustProxy = opts.trustProxy || false
  return api
}

const reqFrom = (remoteAddress, headers = {}) => ({ socket: { remoteAddress }, headers })

test('_isLocalRequest: real localhost socket passes (no trustProxy)', (t) => {
  const api = makeApi()
  t.ok(api._isLocalRequest(reqFrom('127.0.0.1')), 'loopback socket is local')
  t.ok(api._isLocalRequest(reqFrom('::1')), 'ipv6 loopback is local')
})

test('_isLocalRequest: external socket is not local', (t) => {
  const api = makeApi()
  t.absent(api._isLocalRequest(reqFrom('203.0.113.5')), 'external socket is not local')
})

test('_isLocalRequest: spoofed X-Forwarded-For: 127.0.0.1 does NOT pass', (t) => {
  const api = makeApi()
  const req = reqFrom('203.0.113.5', { 'x-forwarded-for': '127.0.0.1' })
  t.absent(api._isLocalRequest(req), 'XFF is ignored for the localhost decision')
})

test('_isLocalRequest: trustProxy disables the localhost determination entirely', (t) => {
  const api = makeApi({ trustProxy: true })
  t.absent(api._isLocalRequest(reqFrom('127.0.0.1')), 'co-located proxy socket is not a trusted admin')
  t.absent(api._isLocalRequest(reqFrom('203.0.113.5', { 'x-forwarded-for': '127.0.0.1' })), 'spoofed XFF still blocked under trustProxy')
})

test('_checkAuth: trustProxy + no API key rejects (no localhost fallback)', (t) => {
  const api = makeApi({ trustProxy: true })
  t.absent(api._checkAuth(reqFrom('127.0.0.1')), 'localhost fallback disabled under trustProxy')
  t.absent(api._checkAuth(reqFrom('203.0.113.5', { 'x-forwarded-for': '127.0.0.1' })), 'spoof rejected')
})

test('_checkAuth: valid Bearer key authorizes regardless of IP / trustProxy', (t) => {
  const api = makeApi({ apiKey: 'sekret', trustProxy: true })
  const req = reqFrom('203.0.113.5', { authorization: 'Bearer sekret' })
  t.ok(api._checkAuth(req), 'valid key authorizes')
  t.absent(api._checkAuth(reqFrom('203.0.113.5', { authorization: 'Bearer wrong' })), 'wrong key rejected')
})

test('_checkAuth: no key, real localhost still works when trustProxy is off', (t) => {
  const api = makeApi()
  t.ok(api._checkAuth(reqFrom('127.0.0.1')), 'local dev/no-proxy case unchanged')
})
