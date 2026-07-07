/**
 * outboxlog CORS preflight regression (PR #178, shipped v0.24.2).
 *
 * RelayAPI._handle runs the global CORS gate BEFORE the outboxlog HTTP adapter.
 * With the fleet-default empty corsOrigins, a cross-origin OPTIONS preflight was
 * denied 403 — or answered without the X-Pear-Token auth header. Browsers send
 * preflights; Node clients don't, which is why every Node/local E2E passed while
 * a real browser (peerit.site → outbox.peerit.site) hung at "connecting to
 * peers" and community-create failed.
 *
 * The fix treats every outboxlog HTTP route as a public, app-agnostic blind
 * pipe: ACAO '*', ACAH incl. X-Pear-Token / X-Pear-Admin-Token, and never
 * preflight-denied — while NON-outboxlog routes keep deny-by-default. These
 * tests drive the real _handle OPTIONS path, so reverting the publicOutboxLog
 * override (api.js) or dropping a route from isOutboxLogHttpRoute fails here.
 */
import test from 'brittle'
import { RelayAPI } from 'p2p-hiverelay/core/relay-node/api.js'
import { isOutboxLogHttpRoute } from 'p2p-hiverelay/core/relay-node/api-route-mounts.js'

function makeApi (corsOrigins = []) {
  // Minimal node stub; the OPTIONS path touches only corsOrigins/port and the
  // pure CORS helpers, returning before rate limiting or any adapter dispatch.
  const api = new RelayAPI({ emit () {} }, { apiPort: 0, apiHost: '127.0.0.1', corsOrigins })
  api.trustProxy = false
  return api
}

function mockRes () {
  const cap = { statusCode: null, headers: {}, body: null, ended: false }
  const res = {
    setHeader (k, v) { cap.headers[String(k).toLowerCase()] = v },
    getHeader (k) { return cap.headers[String(k).toLowerCase()] },
    removeHeader (k) { delete cap.headers[String(k).toLowerCase()] },
    writeHead (code, arg2, arg3) {
      cap.statusCode = code
      const h = (arg3 && typeof arg3 === 'object') ? arg3 : (arg2 && typeof arg2 === 'object' ? arg2 : null)
      if (h) for (const k of Object.keys(h)) cap.headers[String(k).toLowerCase()] = h[k]
      return res
    },
    end (chunk) {
      if (chunk != null) cap.body = Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk)
      cap.ended = true
    }
  }
  Object.defineProperty(res, 'statusCode', { get () { return cap.statusCode }, set (v) { cap.statusCode = v } })
  return { res, cap }
}

async function preflight (api, path, { origin = 'https://peerit.site' } = {}) {
  const req = { method: 'OPTIONS', url: path, headers: origin ? { origin } : {}, socket: { remoteAddress: '203.0.113.9' } }
  const { res, cap } = mockRes()
  await api._handle(req, res)
  return cap
}

test('isOutboxLogHttpRoute: covers the browser-critical outboxlog surface, excludes the rest', (t) => {
  for (const p of ['/api/token', '/api/sync/heads', '/api/sync/append', '/api/swarm/announce', '/api/identity', '/api/identity/x']) {
    t.ok(isOutboxLogHttpRoute(p), `${p} is an outboxlog route`)
  }
  for (const p of ['/api/config', '/health', '/api/poker/tables', '/api/status']) {
    t.absent(isOutboxLogHttpRoute(p), `${p} is NOT an outboxlog route`)
  }
})

test('outboxlog preflight: cross-origin OPTIONS is allowed with token headers under empty corsOrigins', async (t) => {
  const api = makeApi([]) // fleet default — deny-by-default for managed routes
  for (const path of ['/api/token', '/api/sync/append', '/api/sync/heads', '/api/swarm/announce']) {
    const cap = await preflight(api, path, { origin: 'https://peerit.site' })
    t.is(cap.statusCode, 204, `${path} preflight → 204 (not 403)`)
    t.is(cap.headers['access-control-allow-origin'], '*', `${path} ACAO is wildcard (public blind pipe)`)
    const acah = String(cap.headers['access-control-allow-headers'] || '')
    t.ok(acah.includes('X-Pear-Token'), `${path} ACAH advertises X-Pear-Token`)
    t.ok(acah.includes('X-Pear-Admin-Token'), `${path} ACAH advertises X-Pear-Admin-Token`)
    t.is(cap.headers['access-control-allow-methods'], 'GET, POST, OPTIONS', `${path} advertises methods`)
    t.absent(/CORS origin denied/.test(String(cap.body || '')), `${path} is not denied`)
  }
})

test('non-outboxlog preflight: managed route stays deny-by-default under empty corsOrigins', async (t) => {
  const api = makeApi([])
  const cap = await preflight(api, '/api/config', { origin: 'https://evil.example' })
  t.is(cap.statusCode, 403, 'foreign preflight on a managed route is denied')
  t.ok(/CORS origin denied/.test(String(cap.body || '')), 'denial body is explicit')
})

test('non-outboxlog preflight: allowlisted origin gets the managed (non-public) header contract', async (t) => {
  const api = makeApi(['https://peerit.site'])
  const cap = await preflight(api, '/api/config', { origin: 'https://peerit.site' })
  t.is(cap.statusCode, 204, 'allowlisted origin passes preflight')
  t.is(cap.headers['access-control-allow-origin'], 'https://peerit.site', 'echoes the specific origin, not wildcard')
  t.is(cap.headers['access-control-allow-headers'], 'Content-Type, Authorization', 'managed routes do NOT advertise the outboxlog token headers')
})
