import test from 'brittle'
import http from 'http'
import { RelayAPI } from 'p2p-hiverelay/core/relay-node/api.js'
import { Federation } from 'p2p-hiverelay/core/federation.js'

const API_KEY = 'service-config-test-key'

function mockRelayNode () {
  return {
    running: true,
    config: {
      storage: null,
      enableServices: true,
      plugins: ['identity', 'vrf']
    },
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
    serviceRegistry: {
      services: new Map([
        ['identity', { status: 'running', running: true, capabilities: [] }]
      ])
    },
    router: null,
    reputation: null,
    networkDiscovery: null,
    seedingRegistry: null,
    relay: null,
    seeder: null,
    swarm: null,
    on () {},
    removeListener () {},
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
        resolve({ statusCode: res.statusCode, body: parsed, headers: res.headers })
      })
    })
    req.on('error', reject)
    if (body !== null && body !== undefined) req.write(JSON.stringify(body))
    req.end()
  })
}

async function makeServer (t, opts = {}) {
  const node = mockRelayNode()
  const api = new RelayAPI(node, { apiPort: 0, apiHost: '127.0.0.1', apiKey: API_KEY })
  let persisted = null
  api._persistConfig = async () => {
    if (opts.persistError) throw opts.persistError
    persisted = api._getSafeConfig()
  }
  await api.start()
  const port = api.server.address().port

  t.teardown(async () => {
    await api.stop()
  })

  return {
    api,
    node,
    port,
    auth: { Authorization: 'Bearer ' + API_KEY },
    persisted: () => persisted
  }
}

test('service config api: catalog is authenticated and reports configured services', async (t) => {
  const { port, auth } = await makeServer(t)

  const denied = await request(port, 'GET', '/api/manage/services/available')
  t.is(denied.statusCode, 401)

  const res = await request(port, 'GET', '/api/manage/services/available', null, auth)
  t.is(res.statusCode, 200)
  t.is(res.body.enabled, true)
  t.alike(res.body.plugins, ['identity', 'vrf'])
  t.ok(res.body.available.includes('ai'))
  t.ok(res.body.available.includes('poker'))
  t.ok(res.body.available.includes('outboxlog'))
  t.ok(res.body.available.includes('notify'))
  t.alike(res.body.bundles.poker, ['poker', 'vrf', 'arbitration', 'zk'])
  t.alike(res.body.active, ['identity'])
})

test('service config api: saves builtins and expands poker bundle', async (t) => {
  const { node, port, auth, persisted } = await makeServer(t)

  const res = await request(port, 'POST', '/api/manage/services/config', {
    enabled: true,
    plugins: ['poker', 'ai', 'ai']
  }, auth)

  t.is(res.statusCode, 200)
  t.is(res.body.ok, true)
  t.is(res.body.restartRequired, true)
  t.alike(node.config.plugins, ['poker', 'vrf', 'arbitration', 'zk', 'ai'])
  t.is(node.config.enableServices, true)
  t.alike(res.body.config.plugins, node.config.plugins)
  t.alike(persisted().plugins, node.config.plugins)
  t.is(persisted().enableServices, true)
})

test('service config api: relaykernel profile rejects services opt-in', async (t) => {
  const { node, port, auth, persisted } = await makeServer(t)
  node.mode = 'relaykernel'
  node._operatingMode = 'relaykernel'
  node.config.productProfile = 'relaykernel'
  node.config.enableServices = false
  node.config.plugins = []

  const res = await request(port, 'POST', '/api/manage/services/config', {
    enabled: true,
    plugins: ['ai']
  }, auth)

  t.is(res.statusCode, 409)
  t.is(res.body.errorCode, 'relaykernel-services-locked')
  t.is(res.body.config.enabled, false)
  t.is(res.body.config.locked, true)
  t.alike(res.body.config.plugins, [])
  t.is(node.config.enableServices, false)
  t.alike(node.config.plugins, [])
  t.is(persisted(), null)
})

test('poker service http api is delegated when poker provider is running', async (t) => {
  const { node, port } = await makeServer(t)
  node.serviceRegistry.services.set('poker', {
    status: 'running',
    running: true,
    provider: {
      listTables () {
        return [{ tableKey: 'table-1', length: 2, writers: ['a'.repeat(64), 'b'.repeat(64)] }]
      }
    }
  })

  const res = await request(port, 'GET', '/api/poker/tables')
  t.is(res.statusCode, 200)
  t.is(res.body.tables.length, 1)
  t.is(res.body.tables[0].tableKey, 'table-1')
})

test('poker table api keeps app-facing CORS separate from management usage telemetry', async (t) => {
  const { port } = await makeServer(t)

  const tables = await request(port, 'OPTIONS', '/api/poker/tables', null, {
    Origin: 'https://app.example'
  })
  t.is(tables.statusCode, 204)
  t.is(tables.headers['access-control-allow-origin'], '*')

  const usage = await request(port, 'OPTIONS', '/api/poker/usage', null, {
    Origin: 'https://app.example'
  })
  t.is(usage.statusCode, 403)
})

test('service management api: disable persists configured plugins before unregistering', async (t) => {
  const { node, port, auth, persisted } = await makeServer(t)
  const unregistered = []
  node.config.plugins = ['identity', 'vrf']
  node.serviceRegistry = {
    services: new Map([
      ['identity', { status: 'running', running: true, capabilities: [] }],
      ['vrf', { status: 'running', running: true, capabilities: [] }]
    ]),
    async unregister (name) {
      unregistered.push(name)
      this.services.delete(name)
      return true
    }
  }

  const res = await request(port, 'POST', '/api/manage/services', {
    action: 'disable',
    service: 'identity'
  }, auth)

  t.is(res.statusCode, 200)
  t.is(res.body.ok, true)
  t.is(res.body.persistent, true)
  t.alike(unregistered, ['identity'])
  t.alike(node.config.plugins, ['vrf'])
  t.alike(persisted().plugins, ['vrf'])
  t.is(node.config.enableServices, true)
  t.absent(node.serviceRegistry.services.has('identity'))
})

test('service management api: disable rolls back configured plugins when persistence fails', async (t) => {
  const { node, port, auth, persisted } = await makeServer(t, { persistError: new Error('readonly config') })
  const unregistered = []
  node.config.plugins = ['identity', 'vrf']
  node.serviceRegistry = {
    services: new Map([
      ['identity', { status: 'running', running: true, capabilities: [] }]
    ]),
    async unregister (name) {
      unregistered.push(name)
      this.services.delete(name)
      return true
    }
  }

  const res = await request(port, 'POST', '/api/manage/services', {
    action: 'disable',
    service: 'identity'
  }, auth)

  t.is(res.statusCode, 500)
  t.ok(res.body.error.startsWith('persist-failed: '))
  t.is(res.body.errorCode, 'persist-failed')
  t.alike(node.config.plugins, ['identity', 'vrf'])
  t.alike(unregistered, [], 'live service is not unregistered before durable config save')
  t.ok(node.serviceRegistry.services.has('identity'))
  t.is(persisted(), null)
})

test('service management api: disable rejects services required by configured bundles', async (t) => {
  const { node, port, auth, persisted } = await makeServer(t)
  const unregistered = []
  node.config.plugins = ['poker', 'vrf', 'arbitration', 'zk']
  node.serviceRegistry = {
    services: new Map([
      ['vrf', { status: 'running', running: true, capabilities: [] }]
    ]),
    async unregister (name) {
      unregistered.push(name)
      this.services.delete(name)
      return true
    }
  }

  const res = await request(port, 'POST', '/api/manage/services', {
    action: 'disable',
    service: 'vrf'
  }, auth)

  t.is(res.statusCode, 409)
  t.ok(res.body.error.includes("Service 'vrf' is required by bundle: poker"))
  t.alike(res.body.bundles, ['poker'])
  t.alike(node.config.plugins, ['poker', 'vrf', 'arbitration', 'zk'])
  t.alike(unregistered, [])
  t.ok(node.serviceRegistry.services.has('vrf'))
  t.is(persisted(), null)
})

test('service config api: persistence failure is reported before success', async (t) => {
  const { node, port, auth, persisted } = await makeServer(t, { persistError: new Error('disk full') })

  const res = await request(port, 'POST', '/api/manage/services/config', {
    enabled: true,
    plugins: ['ai']
  }, auth)

  t.is(res.statusCode, 500)
  t.ok(res.body.error.startsWith('persist-failed: '))
  t.is(res.body.errorCode, 'persist-failed')
  t.absent(res.body.ok)
  t.is(persisted(), null)
  t.alike(node.config.plugins, ['identity', 'vrf'])
  t.is(node.config.enableServices, true)
})

test('wallet destination api: persistence failure is not reported as a bad wallet', async (t) => {
  const { node, port, auth } = await makeServer(t, { persistError: new Error('readonly volume') })

  const res = await request(port, 'POST', '/api/subsidy/destination', {
    destination: 'Satoshi@GetAlby.com'
  }, auth)

  t.is(res.statusCode, 500)
  t.ok(res.body.error.startsWith('persist-failed: '))
  t.is(res.body.errorCode, 'persist-failed')
  t.absent(node.config.subsidy)
})

test('wallet destination api: wizard persistence failure rolls back config before success', async (t) => {
  const { api, node, port, auth, persisted } = await makeServer(t)
  node.config.subsidy = { payoutDestination: 'old@example.com', enabled: true }
  const wizard = makeWizard({
    relayName: 'Umbrel relay',
    acceptMode: 'review',
    payoutDestination: 'old@example.com'
  })
  const oldWizardState = { ...wizard.state }
  api._wizard = wizard
  wizard.save = async () => { throw new Error('wizard disk full') }

  const res = await request(port, 'POST', '/api/subsidy/destination', {
    destination: 'operator@example.com'
  }, auth)

  t.is(res.statusCode, 500)
  t.ok(res.body.error.startsWith('persist-failed: '))
  t.is(res.body.errorCode, 'persist-failed')
  t.alike(node.config.subsidy, { payoutDestination: 'old@example.com', enabled: true })
  t.alike(wizard.state, oldWizardState)
  t.is(persisted(), null)
})

test('wallet destination api: config persistence failure restores saved wizard state', async (t) => {
  const { api, node, port, auth } = await makeServer(t, { persistError: new Error('readonly config') })
  node.config.subsidy = { payoutDestination: 'old@example.com', enabled: true }
  const wizard = makeWizard({
    relayName: 'Umbrel relay',
    acceptMode: 'review',
    payoutDestination: 'old@example.com'
  })
  const savedStates = []
  api._wizard = wizard
  wizard.save = async () => {
    savedStates.push({ ...wizard.state })
  }

  const res = await request(port, 'POST', '/api/subsidy/destination', {
    destination: 'operator@example.com'
  }, auth)

  t.is(res.statusCode, 500)
  t.ok(res.body.error.startsWith('persist-failed: '))
  t.is(res.body.errorCode, 'persist-failed')
  t.alike(node.config.subsidy, { payoutDestination: 'old@example.com', enabled: true })
  t.is(wizard.state.payoutDestination, 'old@example.com')
  t.is(savedStates.length, 2)
  t.is(savedStates[0].payoutDestination, 'operator@example.com')
  t.is(savedStates[1].payoutDestination, 'old@example.com')
})

test('wallet destination api: live subsidy persistence failure rolls back config and wizard files', async (t) => {
  const { api, node, port, auth, persisted } = await makeServer(t)
  node.config.subsidy = { payoutDestination: 'old@example.com', enabled: true }
  const wizard = makeWizard({
    relayName: 'Umbrel relay',
    acceptMode: 'review',
    payoutDestination: 'old@example.com'
  })
  const savedStates = []
  const liveWrites = []
  const persistErrors = []
  api._wizard = wizard
  api.on('subsidy-persist-error', (info) => persistErrors.push(info.message))
  wizard.save = async () => {
    savedStates.push({ ...wizard.state })
  }
  node.subsidyAccrual = {
    async setPayoutDestination (value) {
      liveWrites.push(value)
      throw new Error('subsidy store readonly')
    }
  }

  const res = await request(port, 'POST', '/api/subsidy/destination', {
    destination: 'operator@example.com'
  }, auth)

  t.is(res.statusCode, 500)
  t.ok(res.body.error.startsWith('persist-failed: '))
  t.is(res.body.errorCode, 'persist-failed')
  t.alike(liveWrites, ['operator@example.com'])
  t.alike(node.config.subsidy, { payoutDestination: 'old@example.com', enabled: true })
  t.is(wizard.state.payoutDestination, 'old@example.com')
  t.is(savedStates.length, 2)
  t.is(savedStates[0].payoutDestination, 'operator@example.com')
  t.is(savedStates[1].payoutDestination, 'old@example.com')
  t.is(persisted().subsidy.payoutDestination, 'old@example.com')
  t.alike(persistErrors, ['subsidy store readonly'])
})

test('service config api: oversized JSON body returns 413 without resetting the client', async (t) => {
  const { port, auth } = await makeServer(t)

  const res = await request(port, 'POST', '/api/manage/services/config', {
    enabled: true,
    plugins: ['ai'],
    padding: 'x'.repeat(70000)
  }, auth)

  t.is(res.statusCode, 413)
  t.is(res.body.error, 'Request body too large')
  t.is(res.headers.connection, 'close')

  const health = await request(port, 'GET', '/health')
  t.is(health.statusCode, 200)
})

test('service config api: rejects top-level non-object JSON bodies before mutation', async (t) => {
  const { node, port, auth } = await makeServer(t)

  const res = await request(port, 'POST', '/api/manage/services/config', [], auth)

  t.is(res.statusCode, 400)
  t.is(res.body.error, 'JSON body must be an object')
  t.alike(node.config.plugins, ['identity', 'vrf'])
  t.is(node.config.enableServices, true)
})

test('service config api: disables services and rejects arbitrary plugin paths', async (t) => {
  const { node, port, auth } = await makeServer(t)

  const disabled = await request(port, 'POST', '/api/manage/services/config', {
    enabled: false,
    plugins: []
  }, auth)
  t.is(disabled.statusCode, 200)
  t.is(node.config.enableServices, false)
  t.alike(node.config.plugins, [])

  const before = node.config.plugins.slice()
  const rejected = await request(port, 'POST', '/api/manage/services/config', {
    enabled: true,
    plugins: ['../../evil.js']
  }, auth)
  t.is(rejected.statusCode, 400)
  t.ok(rejected.body.error.includes('unknown service plugin'))
  t.alike(node.config.plugins, before)
  t.is(node.config.enableServices, false)
})

test('config management api: rejects malformed integer strings and rolls back earlier fields', async (t) => {
  const { node, port, auth, persisted } = await makeServer(t)
  node.config.maxConnections = 7
  node.config.maxStorageBytes = 2 * 1048576

  const partial = await request(port, 'POST', '/api/manage/config', {
    maxConnections: '12',
    maxStorageBytes: '1e9'
  }, auth)

  t.is(partial.statusCode, 400)
  t.is(partial.body.error, 'maxStorageBytes must be a valid integer')
  t.is(node.config.maxConnections, 7, 'earlier valid field was rolled back')
  t.is(node.config.maxStorageBytes, 2 * 1048576, 'invalid field did not mutate')
  t.is(persisted(), null, 'invalid config was not persisted')

  const decimal = await request(port, 'POST', '/api/manage/config', {
    maxConnections: '12.5'
  }, auth)
  t.is(decimal.statusCode, 400)
  t.is(decimal.body.error, 'maxConnections must be a valid integer')
  t.is(node.config.maxConnections, 7, 'decimal value did not mutate config')

  const valid = await request(port, 'POST', '/api/manage/config', {
    maxConnections: '12',
    maxStorageBytes: String(3 * 1048576)
  }, auth)
  t.is(valid.statusCode, 200)
  t.is(node.config.maxConnections, 12, 'plain decimal integer string is accepted')
  t.is(node.config.maxStorageBytes, 3 * 1048576, 'valid integer string is accepted')
  t.is(persisted().maxConnections, 12, 'valid integer config persisted')
})

test('config management api: rejects malformed decimal strings and rolls back earlier fields', async (t) => {
  const { node, port, auth, persisted } = await makeServer(t)
  node.config.maxConnections = 7
  node.config.maxRelayBandwidthMbps = 25

  const exponential = await request(port, 'POST', '/api/manage/config', {
    maxConnections: '12',
    maxRelayBandwidthMbps: '1e3'
  }, auth)
  t.is(exponential.statusCode, 400)
  t.is(exponential.body.error, 'maxRelayBandwidthMbps must be a valid number')
  t.is(node.config.maxConnections, 7, 'earlier integer field was rolled back')
  t.is(node.config.maxRelayBandwidthMbps, 25, 'malformed bandwidth did not mutate')
  t.is(persisted(), null, 'malformed decimal config was not persisted')

  const blank = await request(port, 'POST', '/api/manage/config', {
    maxRelayBandwidthMbps: '   '
  }, auth)
  t.is(blank.statusCode, 400)
  t.is(blank.body.error, 'maxRelayBandwidthMbps must be a valid number')
  t.is(node.config.maxRelayBandwidthMbps, 25, 'blank string did not mutate bandwidth')

  const valid = await request(port, 'POST', '/api/manage/config', {
    maxRelayBandwidthMbps: '12.5'
  }, auth)
  t.is(valid.statusCode, 200)
  t.is(node.config.maxRelayBandwidthMbps, 12.5, 'plain decimal string is accepted')
  t.is(persisted().maxRelayBandwidthMbps, 12.5, 'plain decimal config persisted')
})

test('config management api: rejects malformed boolean fields before mutation', async (t) => {
  const { node, port, auth, persisted } = await makeServer(t)
  node.config.maxConnections = 7
  node.config.registryAutoAccept = false

  const malformed = await request(port, 'POST', '/api/manage/config', {
    maxConnections: '12',
    registryAutoAccept: 'false'
  }, auth)

  t.is(malformed.statusCode, 400)
  t.is(malformed.body.error, 'registryAutoAccept must be a boolean')
  t.is(node.config.maxConnections, 7, 'earlier integer field was rolled back')
  t.is(node.config.registryAutoAccept, false, 'malformed boolean did not mutate')
  t.is(persisted(), null, 'invalid config was not persisted')
})

test('catalog mode api: persists accept mode and removes legacy auto-accept alias', async (t) => {
  const { node, port, auth, persisted } = await makeServer(t)
  node.config.registryAutoAccept = true

  const res = await request(port, 'POST', '/api/manage/catalog/mode', {
    mode: 'open'
  }, auth)

  t.is(res.statusCode, 200)
  t.is(res.body.mode, 'open')
  t.is(node.config.acceptMode, 'open')
  t.absent(node.config.registryAutoAccept)
  t.is(persisted().acceptMode, 'open')
  t.absent(persisted().registryAutoAccept)
})

test('catalog mode api: persistence failure rolls back accept mode', async (t) => {
  const { node, port, auth, persisted } = await makeServer(t, { persistError: new Error('readonly config') })
  node.config.acceptMode = 'review'
  node.config.registryAutoAccept = false

  const res = await request(port, 'POST', '/api/manage/catalog/mode', {
    mode: 'open'
  }, auth)

  t.is(res.statusCode, 500)
  t.ok(res.body.error.startsWith('persist-failed: '))
  t.is(res.body.errorCode, 'persist-failed')
  t.is(node.config.acceptMode, 'review')
  t.is(node.config.registryAutoAccept, false)
  t.is(persisted(), null)
})

test('legacy auto-accept api: persists and rolls back on failure', async (t) => {
  {
    const { node, port, auth, persisted } = await makeServer(t)
    node.config.acceptMode = 'review'

    const res = await request(port, 'POST', '/registry/auto-accept', {
      enabled: true
    }, auth)

    t.is(res.statusCode, 200)
    t.is(res.body.autoAccept, true)
    t.absent(node.config.acceptMode)
    t.is(node.config.registryAutoAccept, true)
    t.absent(persisted().acceptMode)
    t.is(persisted().registryAutoAccept, true)
  }

  {
    const { node, port, auth, persisted } = await makeServer(t)
    node.config.acceptMode = 'review'
    node.config.registryAutoAccept = false

    const res = await request(port, 'POST', '/registry/auto-accept', {
      enabled: 'false'
    }, auth)

    t.is(res.statusCode, 400)
    t.is(res.body.error, 'enabled must be a boolean')
    t.is(node.config.acceptMode, 'review')
    t.is(node.config.registryAutoAccept, false)
    t.is(persisted(), null)
  }

  {
    const { node, port, auth, persisted } = await makeServer(t, { persistError: new Error('readonly config') })
    node.config.acceptMode = 'review'
    node.config.registryAutoAccept = false

    const res = await request(port, 'POST', '/registry/auto-accept', {
      enabled: true
    }, auth)

    t.is(res.statusCode, 500)
    t.ok(res.body.error.startsWith('persist-failed: '))
    t.is(node.config.acceptMode, 'review')
    t.is(node.config.registryAutoAccept, false)
    t.is(persisted(), null)
  }
})

test('catalog allowlist api: normalizes, de-duplicates, and persists publisher keys', async (t) => {
  const { node, port, auth, persisted } = await makeServer(t)
  const upper = 'A'.repeat(64)
  const lower = 'b'.repeat(64)

  const res = await request(port, 'POST', '/api/manage/catalog/allowlist', {
    allowlist: [upper, lower, upper.toLowerCase()]
  }, auth)

  t.is(res.statusCode, 200)
  t.alike(res.body.allowlist, [upper.toLowerCase(), lower])
  t.alike(node.config.acceptAllowlist, [upper.toLowerCase(), lower])
  t.alike(persisted().acceptAllowlist, [upper.toLowerCase(), lower])
})

test('catalog allowlist api: rejects malformed entries without mutating state', async (t) => {
  const { node, port, auth, persisted } = await makeServer(t)
  node.config.acceptAllowlist = ['c'.repeat(64)]

  const res = await request(port, 'POST', '/api/manage/catalog/allowlist', {
    allowlist: ['not-a-pubkey']
  }, auth)

  t.is(res.statusCode, 400)
  t.ok(res.body.error.includes('64-char hex'))
  t.alike(node.config.acceptAllowlist, ['c'.repeat(64)])
  t.is(persisted(), null)
})

test('catalog allowlist api: persistence failure rolls back publisher keys', async (t) => {
  const { node, port, auth, persisted } = await makeServer(t, { persistError: new Error('readonly config') })
  const previous = ['d'.repeat(64)]
  node.config.acceptAllowlist = previous.slice()

  const res = await request(port, 'POST', '/api/manage/catalog/allowlist', {
    allowlist: ['e'.repeat(64)]
  }, auth)

  t.is(res.statusCode, 500)
  t.ok(res.body.error.startsWith('persist-failed: '))
  t.is(res.body.errorCode, 'persist-failed')
  t.alike(node.config.acceptAllowlist, previous)
  t.is(persisted(), null)
})

test('wizard complete api: persists applied accept mode before success', async (t) => {
  const node = mockRelayNode()
  const auth = { Authorization: 'Bearer ' + API_KEY }
  node.config.name = 'old-relay'
  node.config.registryAutoAccept = true
  node._applyWizardConfig = function (cfg) {
    this.config.name = cfg.name
    this.config.acceptMode = cfg.acceptMode
    delete this.config.registryAutoAccept
    this.config.subsidy = { ...this.config.subsidy, ...cfg.subsidy }
  }

  const wizard = makeWizard({
    relayName: 'Umbrel relay',
    acceptMode: 'open',
    payoutDestination: 'operator@example.com'
  })
  const api = new RelayAPI(node, { apiPort: 0, apiHost: '127.0.0.1', apiKey: API_KEY })
  let saved = false
  let persistedConfig = null
  api._wizard = wizard
  wizard.save = async () => { saved = true }
  api._persistConfig = async () => { persistedConfig = api._getSafeConfig() }
  await api.start()
  const wizardPort = api.server.address().port
  t.teardown(async () => {
    await api.stop()
  })

  const res = await request(wizardPort, 'POST', '/api/wizard/complete', {}, auth)

  t.is(res.statusCode, 200)
  t.is(saved, true)
  t.is(node.config.name, 'Umbrel relay')
  t.is(node.config.acceptMode, 'open')
  t.absent(node.config.registryAutoAccept)
  t.is(persistedConfig.name, 'Umbrel relay')
  t.is(persistedConfig.acceptMode, 'open')
  t.absent(persistedConfig.registryAutoAccept)
  t.is(persistedConfig.subsidy.payoutDestination, 'operator@example.com')
})

test('wizard complete api: persistence failure rolls back applied config and wizard state', async (t) => {
  const node = mockRelayNode()
  const auth = { Authorization: 'Bearer ' + API_KEY }
  node.config.name = 'old-relay'
  node.config.acceptMode = 'review'
  node.config.registryAutoAccept = false
  node.config.subsidy = { payoutDestination: null }
  node._applyWizardConfig = function (cfg) {
    this.config.name = cfg.name
    this.config.acceptMode = cfg.acceptMode
    delete this.config.registryAutoAccept
    this.config.subsidy = { ...this.config.subsidy, ...cfg.subsidy }
  }

  const wizard = makeWizard({
    relayName: 'Umbrel relay',
    acceptMode: 'open',
    payoutDestination: 'operator@example.com'
  })
  const oldState = { ...wizard.state }
  const api = new RelayAPI(node, { apiPort: 0, apiHost: '127.0.0.1', apiKey: API_KEY })
  api._wizard = wizard
  api._persistConfig = async () => { throw new Error('readonly config') }
  await api.start()
  const wizardPort = api.server.address().port
  t.teardown(async () => {
    await api.stop()
  })

  const res = await request(wizardPort, 'POST', '/api/wizard/complete', {}, auth)

  t.is(res.statusCode, 500)
  t.ok(res.body.error.startsWith('persist-failed: '))
  t.is(node.config.name, 'old-relay')
  t.is(node.config.acceptMode, 'review')
  t.is(node.config.registryAutoAccept, false)
  t.is(node.config.subsidy.payoutDestination, null)
  t.alike(wizard.state, oldState)
})

test('mode management api: persists applied mode before reporting success', async (t) => {
  const { node, port, auth, persisted } = await makeServer(t)
  node.mode = 'standard'
  node._operatingMode = 'standard'
  node.applyMode = async function (mode, overrides = {}) {
    this.mode = mode
    this._operatingMode = mode
    this.config = {
      ...this.config,
      mode,
      maxConnections: overrides.maxConnections
    }
    return this.config
  }

  const res = await request(port, 'POST', '/api/manage/mode', {
    mode: 'homehive',
    maxConnections: 12
  }, auth)

  t.is(res.statusCode, 200)
  t.is(res.body.ok, true)
  t.is(node.mode, 'homehive')
  t.is(node.config.maxConnections, 12)
  t.is(persisted().mode, 'homehive')
  t.is(persisted().maxConnections, 12)
})

test('mode management api: rejects malformed integer overrides before applying mode', async (t) => {
  const { node, port, auth, persisted } = await makeServer(t)
  node.mode = 'standard'
  node._operatingMode = 'standard'
  let applyCalls = 0
  node.applyMode = async function (mode, overrides = {}) {
    applyCalls++
    this.mode = mode
    this._operatingMode = mode
    this.config = { ...this.config, mode, ...overrides }
    return this.config
  }

  const malformed = await request(port, 'POST', '/api/manage/mode', {
    mode: 'homehive',
    maxConnections: '12abc'
  }, auth)
  t.is(malformed.statusCode, 400)
  t.is(malformed.body.error, 'maxConnections must be a valid integer')
  t.is(applyCalls, 0, 'mode was not applied after malformed maxConnections')
  t.is(node.mode, 'standard')
  t.is(persisted(), null)

  const exponential = await request(port, 'POST', '/api/manage/mode', {
    mode: 'homehive',
    maxStorageBytes: '1e9'
  }, auth)
  t.is(exponential.statusCode, 400)
  t.is(exponential.body.error, 'maxStorageBytes must be a valid integer')
  t.is(applyCalls, 0, 'mode was not applied after exponential maxStorageBytes')
  t.is(node.mode, 'standard')

  const booleanLike = await request(port, 'POST', '/api/manage/mode', {
    mode: 'homehive',
    registryAutoAccept: 'false'
  }, auth)
  t.is(booleanLike.statusCode, 400)
  t.is(booleanLike.body.error, 'registryAutoAccept must be a boolean')
  t.is(applyCalls, 0, 'mode was not applied after malformed boolean')
  t.is(node.mode, 'standard')
})

test('mode management api: rejects malformed bandwidth override before applying mode', async (t) => {
  const { node, port, auth, persisted } = await makeServer(t)
  node.mode = 'standard'
  node._operatingMode = 'standard'
  let applyCalls = 0
  node.applyMode = async function (mode, overrides = {}) {
    applyCalls++
    this.mode = mode
    this._operatingMode = mode
    this.config = { ...this.config, mode, ...overrides }
    return this.config
  }

  const blank = await request(port, 'POST', '/api/manage/mode', {
    mode: 'homehive',
    maxRelayBandwidthMbps: '   '
  }, auth)
  t.is(blank.statusCode, 400)
  t.is(blank.body.error, 'maxRelayBandwidthMbps must be a valid number')
  t.is(applyCalls, 0, 'mode was not applied after blank bandwidth')
  t.is(node.mode, 'standard')
  t.is(persisted(), null)

  const exponential = await request(port, 'POST', '/api/manage/mode', {
    mode: 'homehive',
    maxRelayBandwidthMbps: '1e3'
  }, auth)
  t.is(exponential.statusCode, 400)
  t.is(exponential.body.error, 'maxRelayBandwidthMbps must be a valid number')
  t.is(applyCalls, 0, 'mode was not applied after exponential bandwidth')
  t.is(node.mode, 'standard')

  const valid = await request(port, 'POST', '/api/manage/mode', {
    mode: 'homehive',
    maxRelayBandwidthMbps: '12.5'
  }, auth)
  t.is(valid.statusCode, 200)
  t.is(node.mode, 'homehive')
  t.is(node.config.maxRelayBandwidthMbps, 12.5, 'plain decimal bandwidth is applied')
  t.is(persisted().maxRelayBandwidthMbps, 12.5, 'plain decimal bandwidth is persisted')
})

test('mode management api: persistence failure rolls back applied mode', async (t) => {
  const { node, port, auth, persisted } = await makeServer(t, { persistError: new Error('readonly config') })
  const previousConfig = node.config
  node.mode = 'standard'
  node._operatingMode = 'standard'
  let syncCalls = 0
  node._syncAccessControl = async () => { syncCalls++ }
  node.applyMode = async function (mode, overrides = {}) {
    this.mode = mode
    this._operatingMode = mode
    this.config = {
      ...this.config,
      mode,
      maxConnections: overrides.maxConnections
    }
    return this.config
  }

  const res = await request(port, 'POST', '/api/manage/mode', {
    mode: 'homehive',
    maxConnections: 12
  }, auth)

  t.is(res.statusCode, 500)
  t.ok(res.body.error.startsWith('persist-failed: '))
  t.is(res.body.errorCode, 'persist-failed')
  t.is(node.mode, 'standard')
  t.is(node._operatingMode, 'standard')
  t.is(node.config, previousConfig)
  t.absent(node.config.maxConnections)
  t.is(syncCalls, 1)
  t.is(persisted(), null)
})

test('transport management api: persists before success and rolls back on failure', async (t) => {
  {
    const { node, port, auth, persisted } = await makeServer(t)
    delete node.config.transports

    const res = await request(port, 'POST', '/api/manage/transport', {
      transport: 'tor',
      enabled: 'false'
    }, auth)

    t.is(res.statusCode, 400)
    t.is(res.body.error, 'enabled must be a boolean')
    t.absent(node.config.transports)
    t.is(persisted(), null)
  }

  {
    const { node, port, auth, persisted } = await makeServer(t)
    node.config.transports = { udp: true }

    const res = await request(port, 'POST', '/api/manage/transport', {
      transport: 'tor',
      enabled: true
    }, auth)

    t.is(res.statusCode, 200)
    t.is(res.body.ok, true)
    t.is(node.config.transports.tor, true)
    t.is(persisted().transports.tor, true)
  }

  {
    const { node, port, auth, persisted } = await makeServer(t, { persistError: new Error('readonly config') })
    node.config.transports = { udp: true }

    const res = await request(port, 'POST', '/api/manage/transport', {
      transport: 'tor',
      enabled: true
    }, auth)

    t.is(res.statusCode, 500)
    t.ok(res.body.error.startsWith('persist-failed: '))
    t.is(res.body.errorCode, 'persist-failed')
    t.alike(node.config.transports, { udp: true })
    t.is(persisted(), null)
  }
})

test('pairing management api: rejects malformed timeout before enabling pairing', async (t) => {
  const { node, port, auth } = await makeServer(t)
  let enabled = 0
  node.mode = 'private'
  node.accessControl = {
    isPairing: false,
    _pairingState: null,
    disablePairing () {}
  }
  node.enablePairing = (opts = {}) => {
    enabled++
    return { token: 'a'.repeat(32), expiresAt: Date.now() + opts.timeoutMs }
  }

  const malformed = await request(port, 'POST', '/api/manage/pairing', {
    action: 'start',
    timeoutMs: '1e3'
  }, auth)
  t.is(malformed.statusCode, 400)
  t.is(malformed.body.error, 'timeoutMs must be a valid integer')
  t.is(enabled, 0, 'malformed timeout does not enable pairing')

  const zero = await request(port, 'POST', '/api/manage/pairing', {
    action: 'start',
    timeoutMs: 0
  }, auth)
  t.is(zero.statusCode, 400)
  t.is(zero.body.error, 'timeoutMs must be between 10000 and 1800000')
  t.is(enabled, 0, 'out-of-range timeout does not enable pairing')

  const valid = await request(port, 'POST', '/api/manage/pairing', {
    action: 'start',
    timeoutMs: '10000'
  }, auth)
  t.is(valid.statusCode, 200)
  t.is(valid.body.ok, true)
  t.is(enabled, 1, 'plain integer string enables pairing')
})

test('device management api: add/list/remove canonicalizes keys and bounds names', async (t) => {
  const { node, port, auth } = await makeServer(t)
  const devices = new Map()
  node.accessControl = {}
  node.listDevices = () => Array.from(devices.values())
  node.addDevice = async (pubkey, name) => {
    devices.set(pubkey, { pubkey, name, pairedAt: 1, lastSeen: null })
  }
  node.removeDevice = async (pubkey) => {
    if (!devices.has(pubkey)) throw new Error('Device not in allowlist')
    devices.delete(pubkey)
  }

  const upperPubkey = 'A'.repeat(64)
  const res = await request(port, 'POST', '/api/manage/devices', {
    action: 'add',
    pubkey: upperPubkey,
    name: '  Operator phone  '
  }, auth)

  t.is(res.statusCode, 200)
  t.is(res.body.pubkey, 'a'.repeat(64))
  t.is(res.body.name, 'Operator phone')
  t.is(devices.get('a'.repeat(64)).name, 'Operator phone')

  const listed = await request(port, 'GET', '/api/manage/devices', null, auth)
  t.is(listed.statusCode, 200)
  t.is(listed.body.count, 1)
  t.is(listed.body.devices[0].pubkey, 'a'.repeat(64))

  const removed = await request(port, 'POST', '/api/manage/devices', {
    action: 'remove',
    pubkey: upperPubkey
  }, auth)

  t.is(removed.statusCode, 200)
  t.is(removed.body.pubkey, 'a'.repeat(64))
  t.is(devices.size, 0)
})

test('device management api: rejects invalid names and known access-control errors as bad requests', async (t) => {
  const { node, port, auth } = await makeServer(t)
  node.accessControl = {}
  node.listDevices = () => []
  node.removeDevice = async () => { throw new Error('Device not in allowlist') }

  const invalidName = await request(port, 'POST', '/api/manage/devices', {
    action: 'add',
    pubkey: 'a'.repeat(64),
    name: { label: 'phone' }
  }, auth)
  t.is(invalidName.statusCode, 400)
  t.is(invalidName.body.error, 'name must be a string')

  const longName = await request(port, 'POST', '/api/manage/devices', {
    action: 'add',
    pubkey: 'a'.repeat(64),
    name: 'x'.repeat(81)
  }, auth)
  t.is(longName.statusCode, 400)
  t.is(longName.body.error, 'name exceeds max length (80)')

  node.addDevice = async () => { throw new Error('Maximum devices reached (50)') }
  const maxDevices = await request(port, 'POST', '/api/manage/devices', {
    action: 'add',
    pubkey: 'a'.repeat(64),
    name: 'phone'
  }, auth)
  t.is(maxDevices.statusCode, 400)
  t.is(maxDevices.body.error, 'Maximum devices reached (50)')

  const missing = await request(port, 'POST', '/api/manage/devices', {
    action: 'remove',
    pubkey: 'b'.repeat(64)
  }, auth)
  t.is(missing.statusCode, 400)
  t.is(missing.body.error, 'Device not in allowlist')
})

test('device management api: persistence failures return persist-failed response', async (t) => {
  const { api, node, port, auth } = await makeServer(t)
  node.accessControl = {}
  node.listDevices = () => []
  node.addDevice = async () => { throw new Error('disk full') }
  node.removeDevice = async () => { throw new Error('readonly allowlist') }

  const errors = []
  api.on('device-persist-error', (info) => errors.push(info.message))

  const add = await request(port, 'POST', '/api/manage/devices', {
    action: 'add',
    pubkey: 'a'.repeat(64),
    name: 'phone'
  }, auth)
  t.is(add.statusCode, 500)
  t.ok(add.body.error.startsWith('persist-failed: '))
  t.is(add.body.errorCode, 'persist-failed')

  const remove = await request(port, 'POST', '/api/manage/devices', {
    action: 'remove',
    pubkey: 'a'.repeat(64)
  }, auth)
  t.is(remove.statusCode, 500)
  t.ok(remove.body.error.startsWith('persist-failed: '))
  t.is(remove.body.errorCode, 'persist-failed')
  t.alike(errors, ['disk full', 'readonly allowlist'])
})

test('federation management api: persists every mutation before reporting success', async (t) => {
  const { node, port, auth } = await makeServer(t)
  const federation = new Federation({ node })
  node.federation = federation

  let saveCalls = 0
  federation.save = async (opts = {}) => {
    saveCalls++
    t.is(opts.throwOnError, true, 'management save waits for durable persistence')
  }

  const followed = await request(port, 'POST', '/api/manage/federation/follow', {
    url: 'http://relay-a.example'
  }, auth)
  t.is(followed.statusCode, 200)
  t.is(followed.body.mode, 'follow')

  const mirrored = await request(port, 'POST', '/api/manage/federation/mirror', {
    url: 'https://relay-b.example',
    pubkey: 'b'.repeat(64)
  }, auth)
  t.is(mirrored.statusCode, 200)
  t.is(mirrored.body.mode, 'mirror')

  const republished = await request(port, 'POST', '/api/manage/federation/republish', {
    appKey: 'a'.repeat(64),
    sourceUrl: 'https://source.example',
    sourcePubkey: 'c'.repeat(64),
    channel: 'stable',
    note: 'operator curated'
  }, auth)
  t.is(republished.statusCode, 200)
  t.is(republished.body.appKey, 'a'.repeat(64))

  const unfollowed = await request(port, 'POST', '/api/manage/federation/unfollow', {
    url: 'http://relay-a.example'
  }, auth)
  t.is(unfollowed.statusCode, 200)
  t.is(unfollowed.body.removed, true)

  const unrepublished = await request(port, 'POST', '/api/manage/federation/unrepublish', {
    appKey: 'a'.repeat(64)
  }, auth)
  t.is(unrepublished.statusCode, 200)
  t.is(unrepublished.body.removed, true)

  const snap = federation.snapshot()
  t.alike(snap.followed, [])
  t.is(snap.mirrored.length, 1)
  t.is(snap.mirrored[0].url, 'https://relay-b.example')
  t.alike(snap.republished, [])
  t.is(saveCalls, 5)
})

test('federation management api: persistence failure rolls back in-memory state', async (t) => {
  const { node, port, auth } = await makeServer(t)
  const federation = new Federation({ node })
  federation.follow('http://existing.example', { persist: false })
  node.federation = federation

  federation.save = async () => {
    throw new Error('readonly federation volume')
  }

  const res = await request(port, 'POST', '/api/manage/federation/follow', {
    url: 'http://new.example'
  }, auth)

  t.is(res.statusCode, 500)
  t.ok(res.body.error.startsWith('persist-failed: '))
  t.is(res.body.errorCode, 'persist-failed')
  const snap = federation.snapshot()
  t.is(snap.followed.length, 1)
  t.is(snap.followed[0].url, 'http://existing.example')
})

test('federation management api: validation failure rolls back and does not persist', async (t) => {
  const { node, port, auth } = await makeServer(t)
  const federation = new Federation({ node })
  node.federation = federation

  let saveCalls = 0
  federation.save = async () => { saveCalls++ }

  const res = await request(port, 'POST', '/api/manage/federation/republish', {
    appKey: 'd'.repeat(64),
    sourceUrl: 'javascript:alert(1)'
  }, auth)

  t.is(res.statusCode, 400)
  t.ok(res.body.error.startsWith('Federation:'))
  t.alike(federation.snapshot().republished, [])
  t.is(saveCalls, 0)
})

test('custody witness api uses parsed body once and validates intent ids at the route boundary', async (t) => {
  const { node, port, auth } = await makeServer(t)
  const calls = []
  const intentId = 'a'.repeat(64)
  node.swarm = { keyPair: { publicKey: Buffer.alloc(32), secretKey: Buffer.alloc(64) } }
  node.seedingRegistry = {
    async recordCustodyExpiryWitness (payload, keyPair) {
      calls.push({ payload, keyPair })
      return {
        ok: true,
        type: 'custody-expiry-witness',
        intentId: payload.intentId,
        nonServingProofHash: payload.nonServingProofHash
      }
    }
  }

  const invalid = await request(port, 'POST', '/api/custody/not-hex/witness', {
    nonServingProofHash: 'b'.repeat(64)
  }, auth)
  t.is(invalid.statusCode, 400)
  t.is(invalid.body.error, 'intentId must be 64 hex characters')
  t.is(calls.length, 0, 'invalid route id does not reach registry')

  const res = await request(port, 'POST', `/api/custody/${intentId}/witness`, {
    nonServingProofHash: 'b'.repeat(64)
  }, auth)
  t.is(res.statusCode, 200)
  t.is(res.body.ok, true)
  t.is(res.body.intentId, intentId)
  t.is(res.body.nonServingProofHash, 'b'.repeat(64))
  t.is(calls.length, 1, 'registry called exactly once')
  t.alike(calls[0].payload, {
    nonServingProofHash: 'b'.repeat(64),
    intentId
  })
  t.is(calls[0].keyPair, node.swarm.keyPair)
})

function makeWizard ({ relayName, acceptMode, payoutDestination }) {
  return {
    state: {
      schemaVersion: 3,
      step: 'accept_mode',
      relayName,
      payoutDestination,
      acceptMode,
      startedAt: 1,
      completedAt: null
    },
    snapshot () {
      return {
        ...this.state,
        hasPayout: !!this.state.payoutDestination,
        isComplete: this.state.step === 'complete'
      }
    },
    setPayoutDestination ({ address } = {}) {
      this.state.payoutDestination = address || null
      return { ok: true, state: this.snapshot() }
    },
    complete () {
      this.state.step = 'complete'
      this.state.completedAt = 2
      return { ok: true, state: this.snapshot() }
    },
    toConfig () {
      return {
        name: this.state.relayName,
        acceptMode: this.state.acceptMode,
        subsidy: { payoutDestination: this.state.payoutDestination }
      }
    },
    async save () {}
  }
}
