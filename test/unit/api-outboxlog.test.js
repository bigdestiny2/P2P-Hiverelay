import test from 'brittle'
import http from 'http'
import { RelayAPI } from 'p2p-hiverelay/core/relay-node/api.js'
import { BUILTIN_SERVICE_NAMES } from 'p2p-hiverelay/core/plugin-loader.js'

const API_KEY = 'outboxlog-test-key'

function fakeOutboxLogApp () {
  const groups = new Map()
  let channelSeq = 0
  const channels = new Map()
  const suppressed = new Set()

  function ensureGroup (appId) {
    let group = groups.get(appId)
    if (!group) {
      group = { inviteKey: 'i'.repeat(64), rows: new Map(), version: 0 }
      groups.set(appId, group)
    }
    return group
  }

  return {
    sync: {
      capabilities () {
        return {
          schema: 1,
          ready: true,
          serviceVersion: 'test-fixture',
          atomicCommit: {
            schema: 1,
            enabled: false,
            durable: false,
            ready: false,
            cas: false,
            idempotent: false
          },
          legacyWrites: { create: true, append: true }
        }
      },
      create (appId) {
        const group = ensureGroup(appId)
        return { appId, inviteKey: group.inviteKey, writerPublicKey: appId }
      },
      append (appId, op) {
        const group = ensureGroup(appId)
        const key = op.type.replace(':', '!') + '!' + op.data.id
        group.rows.set(key, op.data)
        group.version++
        return { ok: true, key }
      },
      get (appId, key) {
        const group = groups.get(appId)
        return group ? (group.rows.get(key) || null) : null
      },
      list () { return [] },
      range () { return [] },
      count () { return { count: 0 } },
      status (appId) { return { appId, inviteKey: null, writerCount: 0, viewLength: 0 } },
      heads (appIds) {
        const heads = {}
        for (const appId of appIds || []) heads[appId] = groups.get(appId)?.version || 0
        return { heads }
      },
      directory () { return { heads: {}, count: 0 } },
      takedown (appId, key) {
        suppressed.add(appId + '|' + key)
        return { appId, key, suppressed: true }
      },
      restore (appId, key) {
        suppressed.delete(appId + '|' + key)
        return { appId, key, suppressed: false }
      },
      takedowns () {
        const list = [...suppressed].map((id) => {
          const [appId, key] = id.split('|')
          return { appId, key }
        })
        return { takedowns: list, count: list.length }
      }
    },
    swarm: {
      join (topicHex) {
        const channelId = 'ch-' + (++channelSeq)
        channels.set(channelId, { topicHex, onEvent: null })
        return { channelId, topicHex, protocol: 'pear.swarm.v1', version: 1, tier: 'A' }
      },
      send () { return { ok: true } },
      leave (channelId) { channels.delete(channelId); return { ok: true } },
      subscribe (channelId, fn) {
        const channel = channels.get(channelId)
        if (channel) channel.onEvent = fn
        return () => channels.delete(channelId)
      }
    }
  }
}

function outboxRegistry (provider) {
  const entry = {
    name: 'outboxlog',
    version: '0.1.0',
    status: 'running',
    capabilities: ['outboxlog.sync'],
    provider
  }
  return { services: new Map([['outboxlog', entry]]) }
}

function mockNode (opts = {}) {
  return {
    running: true,
    config: { storage: null, plugins: opts.plugins || [], trustProxy: true, ...(opts.config || {}) },
    metrics: { getSummary () { return { uptime: 1 } } },
    seededApps: new Map(),
    appRegistry: { apps: new Map(), catalog () { return [] }, catalogForBroadcast () { return [] } },
    getStats () { return { running: true } },
    getHealthStatus () { return { healthy: true } },
    serviceRegistry: opts.registry || null,
    async stop () {},
    async start () {},
    on () {},
    emit () {}
  }
}

function request (port, method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      method,
      path,
      headers: { 'Content-Type': 'application/json', ...headers }
    }, (res) => {
      let data = ''
      res.on('data', (chunk) => { data += chunk })
      res.on('end', () => {
        let parsed
        try { parsed = JSON.parse(data) } catch { parsed = data }
        resolve({ statusCode: res.statusCode, body: parsed, headers: res.headers })
      })
    })
    req.on('error', reject)
    if (body != null) req.write(JSON.stringify(body))
    req.end()
  })
}

async function serverWithApi (t, node, opts = {}) {
  const api = new RelayAPI(node, { apiPort: 0, apiHost: '127.0.0.1', apiKey: API_KEY, ...opts })
  await api.start()
  const port = api.server.address().port
  t.teardown(async () => {
    if (api._rateLimitCleanup) clearInterval(api._rateLimitCleanup)
    if (api._dashboardFeed) { try { api._dashboardFeed.stop() } catch {} }
    if (api._pokerFeed) { try { api._pokerFeed.stop() } catch {} }
    await new Promise((resolve) => api.server.close(resolve))
  })
  return { api, port }
}

test('outboxlog is a builtin service provider', (t) => {
  t.ok(BUILTIN_SERVICE_NAMES.includes('outboxlog'))
})

test('/api/token returns 503 when outboxlog is not enabled', async (t) => {
  const { port } = await serverWithApi(t, mockNode({ registry: null }))
  const res = await request(port, 'POST', '/api/token')

  t.is(res.statusCode, 503)
  t.alike(res.body, { error: 'OutboxLog service is not enabled on this relay' })
})

test('/api/token redacts adapter load failures and emits internals', async (t) => {
  const app = fakeOutboxLogApp()
  const { api, port } = await serverWithApi(t, mockNode({ registry: outboxRegistry(app) }))
  const events = []
  api.on('outboxlog-http-adapter-error', (event) => events.push(event))
  api._loadOutboxLogHttpAdapter = async function () {
    throw new Error('internal adapter path /data/hiverelay/private/outboxlog/http-adapter.js failed')
  }

  const res = await request(port, 'POST', '/api/token')

  t.is(res.statusCode, 503)
  t.is(res.body.error, 'unsupported: outboxlog HTTP adapter unavailable')
  t.is(res.body.errorCode, 'outboxlog-http-adapter-unavailable')
  t.absent(JSON.stringify(res.body).includes('/data/hiverelay/private'))
  t.is(events.length, 1)
  t.ok(events[0].error.message.includes('/data/hiverelay/private'))
})

test('/api/outboxlog browser preflight exposes only the public blind-pipe headers', async (t) => {
  const { port } = await serverWithApi(t, mockNode({ registry: null }))
  const res = await request(port, 'OPTIONS', '/api/sync/create', null, {
    Origin: 'https://peerit.example',
    'Access-Control-Request-Method': 'POST',
    'Access-Control-Request-Headers': 'Content-Type, X-Pear-Token'
  })

  t.is(res.statusCode, 204)
  t.is(res.headers['access-control-allow-origin'], '*')
  t.is(res.headers['access-control-allow-methods'], 'GET, POST, OPTIONS')
  t.is(res.headers['access-control-allow-headers'], 'Content-Type, X-Pear-Token, X-Pear-Admin-Token')
  t.is(res.headers['access-control-expose-headers'], 'Retry-After')
  t.is(res.headers.vary, 'Origin', 'the outer API cache key remains origin-safe before adapter handoff')
})

test('/api/token explicit OutboxLog config retains a coarse fail-safe when adapter loading fails', async (t) => {
  const app = fakeOutboxLogApp()
  const node = mockNode({
    registry: outboxRegistry(app),
    config: { outboxlog: { http: { rateLimit: { windowMs: 60_000, max: 12_000 } } } }
  })
  const { api, port } = await serverWithApi(t, node)
  let loads = 0
  api._loadOutboxLogHttpAdapter = async function () {
    loads++
    throw new Error('adapter unavailable')
  }

  for (let i = 0; i < 60; i++) {
    t.is((await request(port, 'POST', '/api/token')).statusCode, 503)
  }
  const limited = await request(port, 'POST', '/api/token')
  t.is(limited.statusCode, 429)
  t.alike(limited.body, { error: 'Too many requests' })
  t.is(limited.headers['access-control-expose-headers'], 'Retry-After')
  t.is(loads, 60, 'rate gate stops repeated dynamic adapter resolution failures')
})

test('/api/bridge/status default read exemption retains a coarse fail-safe until the adapter resolves', async (t) => {
  const app = fakeOutboxLogApp()
  const { api, port } = await serverWithApi(t, mockNode({ registry: outboxRegistry(app) }), { trustProxy: true })
  let loads = 0
  api._loadOutboxLogHttpAdapter = async function () {
    loads++
    throw new Error('adapter unavailable')
  }
  const ip = '198.51.100.77'
  api._rateLimits.set(ip, { count: 59, resetAt: Date.now() + 60_000 })
  const headers = { 'X-Forwarded-For': ip }

  t.is((await request(port, 'GET', '/api/bridge/status', null, headers)).statusCode, 503)
  const limited = await request(port, 'GET', '/api/bridge/status', null, headers)
  t.is(limited.statusCode, 429)
  t.is(loads, 1, 'fallback gate rejects before repeating failed adapter work')
})

test('/api/outboxlog bridge token gates sync routes through RelayAPI', async (t) => {
  const app = fakeOutboxLogApp()
  const { port } = await serverWithApi(t, mockNode({ registry: outboxRegistry(app) }))
  const tokenRes = await request(port, 'POST', '/api/token')
  const token = tokenRes.body.token

  t.is(tokenRes.statusCode, 200)
  t.ok(token)

  const denied = await request(port, 'GET', '/api/bridge/status')
  t.is(denied.statusCode, 401)

  const status = await request(port, 'GET', '/api/bridge/status', null, { 'X-Pear-Token': token })
  t.is(status.body.ready, true)
  t.is(status.body.service, 'outboxlog')
  t.alike(status.body.httpRateLimit, {
    scope: 'public-writes',
    source: 'relay-api-default',
    enabled: true,
    windowMs: 60000,
    max: 60,
    outboxLogEnvelope: { enabled: true, windowMs: 60000, max: 1200 }
  })

  const created = await request(port, 'POST', '/api/sync/create', { appId: 'a'.repeat(64) }, { 'X-Pear-Token': token })
  t.is(created.statusCode, 200)
  t.is(created.body.appId, 'a'.repeat(64))
})

test('/api/outboxlog preserves the default coarse 60/minute public-write gate', async (t) => {
  const app = fakeOutboxLogApp()
  const { port } = await serverWithApi(t, mockNode({ registry: outboxRegistry(app) }))
  for (let i = 0; i < 60; i++) {
    t.is((await request(port, 'POST', '/api/token')).statusCode, 200)
  }
  const limited = await request(port, 'POST', '/api/token')
  t.is(limited.statusCode, 429)
  t.alike(limited.body, { error: 'Too many requests' })
  t.is(limited.headers['retry-after'], '60')
  t.is(limited.headers['access-control-expose-headers'], 'Retry-After')
})

test('/api/outboxlog accepts validated shared-NAT rate config and returns Retry-After at the configured ceiling', async (t) => {
  const app = fakeOutboxLogApp()
  const node = mockNode({
    registry: outboxRegistry(app),
    config: { outboxlog: { http: { rateLimit: { windowMs: 120_000, max: 65 } } } }
  })
  const { port } = await serverWithApi(t, node)
  const tokenRes = await request(port, 'POST', '/api/token')
  const token = tokenRes.body.token
  const headers = { 'X-Pear-Token': token }

  const status = await request(port, 'GET', '/api/bridge/status', null, headers)
  t.is(status.statusCode, 200)
  t.alike(status.body.httpRateLimit, {
    scope: 'public-writes',
    source: 'operator',
    enabled: true,
    windowMs: 120000,
    max: 65,
    outboxLogEnvelope: { enabled: true, windowMs: 120000, max: 65 }
  })
  // Token + status consumed two dedicated slots. Sixty-three writes now cross
  // the generic management API's 60/minute ceiling while staying within the
  // explicitly configured OutboxLog envelope.
  for (let i = 0; i < 63; i++) {
    const appId = i.toString(16).padStart(64, '0')
    t.is((await request(port, 'POST', '/api/sync/create', { appId }, headers)).statusCode, 200)
  }
  const limited = await request(port, 'GET', '/api/bridge/status', null, headers)
  t.is(limited.statusCode, 429)
  t.ok(/^\d+$/.test(limited.headers['retry-after']))
  t.ok(Number(limited.headers['retry-after']) >= 1)
  t.is(limited.headers['access-control-expose-headers'], 'Retry-After')
})

test('/api/outboxlog supports explicit staging disable without weakening token auth', async (t) => {
  const app = fakeOutboxLogApp()
  const { port } = await serverWithApi(t, mockNode({ registry: outboxRegistry(app) }), { outboxLogHttpRateLimit: false })
  const tokenRes = await request(port, 'POST', '/api/token')
  const headers = { 'X-Pear-Token': tokenRes.body.token }
  for (let i = 0; i < 5; i++) {
    const status = await request(port, 'GET', '/api/bridge/status', null, headers)
    t.is(status.statusCode, 200)
    t.is(status.body.httpRateLimit.enabled, false)
  }
  t.is((await request(port, 'GET', '/api/bridge/status')).statusCode, 401)
})

test('/api/outboxlog healthy first adapter resolution honors explicit data-plane config over a saturated generic bucket', async (t) => {
  const app = fakeOutboxLogApp()
  const { api, port } = await serverWithApi(t, mockNode({ registry: outboxRegistry(app) }), {
    outboxLogHttpRateLimit: false,
    trustProxy: true
  })
  const ip = '198.51.100.88'
  api._rateLimits.set(ip, { count: 60, resetAt: Date.now() + 60_000 })

  const token = await request(port, 'POST', '/api/token', null, { 'X-Forwarded-For': ip })
  t.is(token.statusCode, 200, 'healthy adapter bootstraps under the explicit data-plane policy')
  t.ok(token.body.token)
})

test('/api/outboxlog explicit data-plane config does not bypass the global admin rate gate', async (t) => {
  const app = fakeOutboxLogApp()
  const { port } = await serverWithApi(t, mockNode({ registry: outboxRegistry(app) }), {
    outboxLogAdminKey: 'admin-secret',
    outboxLogHttpRateLimit: false
  })
  for (let i = 0; i < 60; i++) {
    const denied = await request(port, 'GET', '/api/admin/takedowns')
    t.is(denied.statusCode, 401)
  }
  const limited = await request(port, 'GET', '/api/admin/takedowns')
  t.is(limited.statusCode, 429)
  t.alike(limited.body, { error: 'Too many requests' })
})

test('/api/outboxlog rejects malformed operator rate config at RelayAPI construction', (t) => {
  let err = null
  let api = null
  try {
    api = new RelayAPI(mockNode({ config: { outboxlog: { http: { rateLimit: { max: 'unbounded' } } } } }), {
      apiPort: 0,
      apiHost: '127.0.0.1',
      apiKey: API_KEY
    })
  } catch (error) {
    err = error
  }
  t.absent(api)
  t.ok(err)
  t.ok(err.message.includes('outboxlog.http.rateLimit.max'))
})

test('/api/admin/takedown is 404 through RelayAPI when no admin key is configured', async (t) => {
  const app = fakeOutboxLogApp()
  // No outboxLogAdminKey opt and no HIVERELAY_OUTBOXLOG_ADMIN_KEY env => the
  // takedown surface must stay disabled (safe-by-default), even with an admin
  // token supplied by the caller.
  const { port } = await serverWithApi(t, mockNode({ registry: outboxRegistry(app) }))
  const res = await request(port, 'POST', '/api/admin/takedown', { appId: 'a'.repeat(64), key: 'post!p1' }, { 'X-Pear-Admin-Token': 'anything' })

  t.is(res.statusCode, 404, 'admin surface not enabled without an admin key')
})

test('/api/admin/takedown activates through RelayAPI when an admin key is configured', async (t) => {
  const app = fakeOutboxLogApp()
  const ADMIN_KEY = 'outboxlog-admin-secret'
  const { port } = await serverWithApi(t, mockNode({ registry: outboxRegistry(app) }), { outboxLogAdminKey: ADMIN_KEY })
  const appId = 'a'.repeat(64)

  // Reachable (not 404) but rejects an absent admin token with 401.
  const noToken = await request(port, 'POST', '/api/admin/takedown', { appId, key: 'post!p1' })
  t.is(noToken.statusCode, 401, 'missing admin token rejected once the surface is enabled')

  // Rejects a wrong admin token with 401. The browser sync token must NOT work
  // on the admin surface, so exercise a plausible-but-wrong secret.
  const wrongToken = await request(port, 'POST', '/api/admin/takedown', { appId, key: 'post!p1' }, { 'X-Pear-Admin-Token': 'wrong-secret' })
  t.is(wrongToken.statusCode, 401, 'wrong admin token rejected')

  // Accepts the configured admin token and performs the takedown.
  const ok = await request(port, 'POST', '/api/admin/takedown', { appId, key: 'post!p1' }, { 'X-Pear-Admin-Token': ADMIN_KEY })
  t.is(ok.statusCode, 200, 'correct admin token accepted')
  t.alike(ok.body, { appId, key: 'post!p1', suppressed: true })

  // The audit list surface is reachable under the same credential.
  const list = await request(port, 'GET', '/api/admin/takedowns', null, { 'X-Pear-Admin-Token': ADMIN_KEY })
  t.is(list.statusCode, 200)
  t.alike(list.body, { takedowns: [{ appId, key: 'post!p1' }], count: 1 })
})
