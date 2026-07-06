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
    config: { storage: null, plugins: opts.plugins || [], trustProxy: true },
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
  t.alike(status.body, { ready: true, service: 'outboxlog' })

  const created = await request(port, 'POST', '/api/sync/create', { appId: 'a'.repeat(64) }, { 'X-Pear-Token': token })
  t.is(created.statusCode, 200)
  t.is(created.body.appId, 'a'.repeat(64))
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
