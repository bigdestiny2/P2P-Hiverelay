import test from 'brittle'
import http from 'http'
import { RelayAPI } from 'p2p-hiverelay/core/relay-node/api.js'
import { ServiceRegistry } from 'p2p-hiverelay/core/services/registry.js'
import { AIService } from 'p2p-hiveservices/builtin/ai-service.js'

const API_KEY = 'qvac-api-test-key'

function mockRelayNode (serviceRegistry) {
  return {
    running: true,
    config: { storage: null },
    metrics: { getSummary () { return { uptime: 100 } } },
    seededApps: new Map(),
    appRegistry: {
      apps: new Map(),
      catalog () { return [] },
      catalogForBroadcast () { return [] }
    },
    getStats () { return { running: true, seededApps: 0, connections: 0 } },
    getHealthStatus () { return { healthy: true } },
    async stop () {},
    async start () {},
    async seedApp () { return { ok: true } },
    async unseedApp () {},
    verifyUnseedRequest () { return { ok: true } },
    broadcastUnseed () {},
    serviceRegistry,
    router: null,
    reputation: null,
    networkDiscovery: null,
    seedingRegistry: null,
    relay: null,
    seeder: null,
    swarm: null,
    on () {},
    emit () {}
  }
}

function request (port, method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: '127.0.0.1',
      port,
      method,
      path,
      headers: {
        'Content-Type': 'application/json',
        ...headers
      }
    }
    const req = http.request(opts, (res) => {
      let data = ''
      res.on('data', (chunk) => { data += chunk })
      res.on('end', () => {
        let parsed
        try { parsed = JSON.parse(data) } catch (_) { parsed = data }
        resolve({ statusCode: res.statusCode, body: parsed })
      })
    })
    req.on('error', reject)
    if (body) req.write(JSON.stringify(body))
    req.end()
  })
}

async function makeServer (t, opts = {}) {
  const calls = []
  const sdk = {
    loadModel: async (params) => {
      calls.push({ op: 'loadModel', params })
      return 'loaded-' + params.modelSrc
    },
    completion: async (params) => {
      calls.push({ op: 'completion', params })
      return { text: 'ok', stats: { tokens: 1 } }
    },
    unloadModel: async (params) => {
      calls.push({ op: 'unloadModel', params })
    }
  }
  const registry = new ServiceRegistry({ metering: false })
  const ai = opts.provider || new AIService({ qvac: { sdk } })
  registry.register(ai)
  await registry.startAll({})

  const node = mockRelayNode(registry)
  const api = new RelayAPI(node, { apiPort: 0, apiHost: '127.0.0.1', apiKey: API_KEY })
  await api.start()
  const port = api.server.address().port

  t.teardown(async () => {
    if (api._rateLimitCleanup) clearInterval(api._rateLimitCleanup)
    if (api._dashboardFeed) {
      try { api._dashboardFeed.stop() } catch (_) {}
    }
    await new Promise(resolve => api.server.close(resolve))
    await registry.stopAll()
  })

  return { port, calls, ai }
}

test('manage api qvac models: auth required', async (t) => {
  const { port } = await makeServer(t)
  const res = await request(port, 'GET', '/api/manage/ai/models')
  t.is(res.statusCode, 401)
  t.ok(res.body.error)
})

test('manage api qvac models: register, list, remove', async (t) => {
  const { port } = await makeServer(t)
  const auth = { Authorization: 'Bearer ' + API_KEY }

  const registered = await request(port, 'POST', '/api/manage/ai/models', {
    modelId: 'operator-qvac',
    type: 'llm',
    modelSrc: '/models/operator.gguf',
    modelType: 'llm',
    modelConfig: { ctx_size: 512 }
  }, auth)
  t.is(registered.statusCode, 200)
  t.is(registered.body.ok, true)
  t.is(registered.body.action, 'registered')
  t.is(registered.body.model.modelId, 'operator-qvac')
  t.is(registered.body.model.backend, 'qvac')
  t.is(registered.body.model.status, 'registered')
  t.is(registered.body.model.qvac.loaded, false)

  const listed = await request(port, 'GET', '/api/manage/ai/models', null, auth)
  t.is(listed.statusCode, 200)
  t.is(listed.body.qvac.available, true)
  t.is(listed.body.qvacCount, 1)
  t.is(listed.body.models[0].status, 'registered')

  const removed = await request(port, 'POST', '/api/manage/ai/models/remove', {
    modelId: 'operator-qvac'
  }, auth)
  t.is(removed.statusCode, 200)
  t.is(removed.body.ok, true)
  t.is(removed.body.removed, true)
  t.is(removed.body.qvacCount, 0)
})

test('manage api qvac models: rejects non-qvac registration', async (t) => {
  const { port } = await makeServer(t)
  const res = await request(port, 'POST', '/api/manage/ai/models', {
    modelId: 'http-model',
    type: 'llm',
    backend: 'http',
    endpoint: 'http://127.0.0.1:11434/api/generate'
  }, { Authorization: 'Bearer ' + API_KEY })
  t.is(res.statusCode, 400)
  t.ok(res.body.error.includes('qvac-backed'))
})

test('manage api qvac models: redacts unexpected provider errors', async (t) => {
  const secretPath = '/data/models/private/qvac-secret'
  const provider = {
    manifest () {
      return { name: 'ai', version: '1.0.0', capabilities: ['list-models', 'register-model', 'remove-model'] }
    },
    async 'list-models' () {
      throw new Error('list failed at ' + secretPath)
    },
    async 'register-model' () {
      throw new Error('register failed at ' + secretPath)
    },
    async 'remove-model' () {
      throw new Error('remove failed at ' + secretPath)
    }
  }
  const { port } = await makeServer(t, { provider })
  const auth = { Authorization: 'Bearer ' + API_KEY }

  const listed = await request(port, 'GET', '/api/manage/ai/models', null, auth)
  t.is(listed.statusCode, 500)
  t.alike(listed.body, { error: 'AI model list failed' })
  t.absent(JSON.stringify(listed.body).includes(secretPath))

  const registered = await request(port, 'POST', '/api/manage/ai/models', {
    modelId: 'operator-qvac',
    modelSrc: '/models/operator.gguf'
  }, auth)
  t.is(registered.statusCode, 500)
  t.alike(registered.body, { error: 'AI model registration failed' })
  t.absent(JSON.stringify(registered.body).includes(secretPath))

  const removed = await request(port, 'POST', '/api/manage/ai/models/remove', {
    modelId: 'operator-qvac'
  }, auth)
  t.is(removed.statusCode, 500)
  t.alike(removed.body, { error: 'AI model removal failed' })
  t.absent(JSON.stringify(removed.body).includes(secretPath))
})

test('manage api qvac models: preserves known AI model errors', async (t) => {
  const provider = {
    manifest () {
      return { name: 'ai', version: '1.0.0', capabilities: ['list-models', 'register-model', 'remove-model'] }
    },
    async 'list-models' () {
      return []
    },
    async 'register-model' () {
      throw new Error('AI_MODEL_EXISTS: operator-qvac')
    },
    async 'remove-model' () {
      throw new Error('AI_MODEL_NOT_FOUND: operator-qvac')
    }
  }
  const { port } = await makeServer(t, { provider })
  const auth = { Authorization: 'Bearer ' + API_KEY }

  const registered = await request(port, 'POST', '/api/manage/ai/models', {
    modelId: 'operator-qvac',
    modelSrc: '/models/operator.gguf'
  }, auth)
  t.is(registered.statusCode, 400)
  t.alike(registered.body, { error: 'AI_MODEL_EXISTS: operator-qvac' })

  const removed = await request(port, 'POST', '/api/manage/ai/models/remove', {
    modelId: 'operator-qvac'
  }, auth)
  t.is(removed.statusCode, 400)
  t.alike(removed.body, { error: 'AI_MODEL_NOT_FOUND: operator-qvac' })
})
