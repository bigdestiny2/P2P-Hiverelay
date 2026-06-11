/**
 * UI-token (ui.exposeToken) tests.
 *
 * exposeToken lets the relay embed its management token into the served
 * dashboard/wizard HTML so the browser UI can authenticate when it reaches
 * the relay through a trusted authenticating reverse proxy (e.g. Umbrel's
 * app_proxy), where the localhost check can never apply. Off by default —
 * direct/localhost and existing fleet deployments are entirely unaffected.
 *
 * Also covers the dashboard-asset path resolver: the git-tracked source
 * lives at the repo root, which is what a fresh clone and the Docker image
 * have — so serving must not depend on the legacy packages/core/dashboard
 * copy that only lingers on long-lived installs.
 */

import test from 'brittle'
import { createHmac } from 'crypto'
import { RelayAPI } from 'p2p-hiverelay/core/relay-node/api.js'
import { deriveTokenFromSeed } from 'p2p-hiverelay/config/loader.js'

function makeApi (opts = {}) {
  // Minimal node stub; set auth fields deterministically (ignore env).
  const api = new RelayAPI({ emit () {} }, { apiPort: 0, apiHost: '127.0.0.1' })
  api._apiKey = opts.apiKey || null
  api._uiExposeToken = opts.uiExposeToken || false
  api.trustProxy = opts.trustProxy || false
  return api
}

function fakeRes () {
  return {
    headers: {},
    statusCode: null,
    body: null,
    setHeader (k, v) { this.headers[k.toLowerCase()] = v },
    writeHead (s) { this.statusCode = s },
    end (b) { this.body = b }
  }
}

const reqFrom = (remoteAddress, headers = {}) => ({ socket: { remoteAddress }, headers })

// ─── deriveTokenFromSeed ───────────────────────────────────────────

test('deriveTokenFromSeed: stable, hex, distinct per seed', (t) => {
  const seed = 'a'.repeat(48)
  const tok = deriveTokenFromSeed(seed)
  t.is(typeof tok, 'string', 'returns a string')
  t.is(tok.length, 64, '32-byte token rendered as hex')
  t.is(tok, deriveTokenFromSeed(seed), 'same seed -> same token (reinstall-safe)')
  t.not(deriveTokenFromSeed('b'.repeat(48)), tok, 'different seed -> different token')
})

test('deriveTokenFromSeed: guards missing/short/non-string input', (t) => {
  t.is(deriveTokenFromSeed(null), null, 'null -> null')
  t.is(deriveTokenFromSeed(undefined), null, 'undefined -> null')
  t.is(deriveTokenFromSeed(''), null, 'empty -> null')
  t.is(deriveTokenFromSeed('short'), null, 'too short -> null')
  t.is(deriveTokenFromSeed(12345), null, 'non-string -> null')
})

test('deriveTokenFromSeed: domain-separated from wizard identity key', (t) => {
  const seed = 'c'.repeat(48)
  const wizardKey = createHmac('sha256', 'hiverelay/wizard/v1')
    .update(Buffer.from(seed, 'utf8')).digest('hex')
  t.not(deriveTokenFromSeed(seed), wizardKey, 'ui-token salt differs from wizard salt')
})

// ─── token injection into served HTML ──────────────────────────────

test('exposeToken OFF: no token injected (default / fleet path)', async (t) => {
  const api = makeApi() // no key, no exposeToken
  const res = fakeRes()
  await api._serveDashboard(res, '_t_off', 'index.html')
  t.is(res.statusCode, 200, 'served ok')
  // The page's inert fetch-shim mentions the meta NAME, so assert on the
  // injected <meta ... content=> tag specifically, not the bare string.
  t.absent(res.body.includes('<meta name="hiverelay-ui-token" content='), 'no injected token meta')
  t.absent(res.headers['cache-control'], 'no no-store header when not exposing')
})

test('exposeToken ON + key: token meta embedded + no-store', async (t) => {
  const api = makeApi({ apiKey: 'deadbeefcafe', uiExposeToken: true })
  const res = fakeRes()
  await api._serveDashboard(res, '_t_on', 'index.html')
  t.ok(res.body.includes('<meta name="hiverelay-ui-token" content="deadbeefcafe">'), 'token meta injected into head')
  t.is(res.headers['cache-control'], 'no-store', 'token response is not cacheable')
})

test('exposeToken ON but no key: nothing injected (start() would disable)', async (t) => {
  const api = makeApi({ uiExposeToken: true }) // _apiKey null
  const res = fakeRes()
  await api._serveDashboard(res, '_t_nokey', 'index.html')
  t.absent(res.body.includes('<meta name="hiverelay-ui-token" content='), 'no token to embed -> no injected meta')
})

test('token value is HTML-attribute-escaped (no breakout)', async (t) => {
  const api = makeApi({ apiKey: 'a"><script>x', uiExposeToken: true })
  const res = fakeRes()
  await api._serveDashboard(res, '_t_esc', 'index.html')
  t.ok(res.body.includes('content="a&quot;&gt;&lt;script&gt;x"'), 'special chars escaped')
  t.absent(res.body.includes('content="a"><script>x"'), 'no raw attribute breakout')
})

test('wizard.html is served + token-injected in exposeToken mode', async (t) => {
  const api = makeApi({ apiKey: 'feed', uiExposeToken: true })
  const res = fakeRes()
  await api._serveDashboard(res, '_t_wiz', 'wizard.html')
  t.is(res.statusCode, 200, 'wizard served (resolved from repo-root dashboard)')
  t.ok(res.body.includes('<meta name="hiverelay-ui-token" content="feed">'), 'wizard carries the injected token')
})

// ─── auth: wizard/management endpoints honor the bearer token ──────

test('_checkAuth: bearer token accepted behind proxy (exposeToken)', (t) => {
  const api = makeApi({ apiKey: 'tok', uiExposeToken: true, trustProxy: true })
  t.ok(api._checkAuth(reqFrom('10.0.0.5', { authorization: 'Bearer tok' })), 'proxy request with token authorizes')
  t.absent(api._checkAuth(reqFrom('10.0.0.5', {})), 'proxy request without token rejected')
})

test('no key + no exposeToken: localhost still authorizes (unchanged)', (t) => {
  const api = makeApi()
  t.ok(api._checkAuth(reqFrom('127.0.0.1')), 'localhost dev path unchanged')
})
