import test from 'brittle'
import {
  AVAILABLE_MODES,
  runModeSwitchAction,
  runTransportToggleAction
} from '../../packages/core/core/relay-node/api-mode-transport.js'

test('api mode transport: validates mode action before applying', async (t) => {
  let applyCalls = 0
  const node = {
    config: {},
    async applyMode () {
      applyCalls++
    }
  }

  t.ok(AVAILABLE_MODES.includes('homehive'))
  t.ok(AVAILABLE_MODES.includes('relaykernel'))

  const missing = await runModeSwitchAction({ body: {}, node })
  t.is(missing.status, 400)
  t.alike(missing.payload, { error: 'mode required' })

  const unknown = await runModeSwitchAction({ body: { mode: 'warp' }, node })
  t.is(unknown.status, 400)
  t.is(unknown.payload.error, 'Unknown mode: warp')
  t.alike(unknown.payload.available, AVAILABLE_MODES)

  const malformed = await runModeSwitchAction({
    body: { mode: 'homehive', maxConnections: '12abc' },
    node
  })
  t.is(malformed.status, 400)
  t.alike(malformed.payload, { error: 'maxConnections must be a valid integer' })
  t.is(applyCalls, 0)

  for (const [field, value] of [
    ['discovery', []],
    ['access', null],
    ['pairing', 'enabled']
  ]) {
    const out = await runModeSwitchAction({
      body: { mode: 'homehive', [field]: value },
      node
    })
    t.is(out.status, 400)
    t.alike(out.payload, { error: `${field} must be an object` })
    t.is(applyCalls, 0)
  }

  const malformedBoolean = await runModeSwitchAction({
    body: { mode: 'homehive', registryAutoAccept: 'false' },
    node
  })
  t.is(malformedBoolean.status, 400)
  t.alike(malformedBoolean.payload, { error: 'registryAutoAccept must be a boolean' })
  t.is(applyCalls, 0)
})

test('api mode transport: applies mode overrides and persists before success', async (t) => {
  const persisted = []
  const node = {
    config: { mode: 'standard' },
    mode: 'standard',
    _operatingMode: 'standard',
    async applyMode (mode, overrides) {
      this.mode = mode
      this._operatingMode = mode
      this.config = { ...this.config, mode, ...overrides }
    }
  }

  const result = await runModeSwitchAction({
    body: {
      mode: 'homehive',
      maxConnections: '12',
      maxRelayBandwidthMbps: '12.5',
      discovery: { mdns: false },
      access: { privateMode: true },
      pairing: { enabled: true },
      registryAutoAccept: false
    },
    node,
    persistConfig: async () => {
      persisted.push({ ...node.config })
    }
  })

  t.is(result.ok, true)
  t.is(result.payload.mode, 'homehive')
  t.is(result.payload.note, 'HomeHive mode active — low resource, LAN-priority')
  t.is(node.config.maxConnections, 12)
  t.is(node.config.maxRelayBandwidthMbps, 12.5)
  t.alike(node.config.discovery, { mdns: false })
  t.alike(node.config.access, { privateMode: true })
  t.alike(node.config.pairing, { enabled: true })
  t.is(node.config.registryAutoAccept, false)
  t.is(persisted.length, 1)
  t.is(persisted[0].mode, 'homehive')
})

test('api mode transport: applies relaykernel mode', async (t) => {
  const node = {
    config: { mode: 'relay-core' },
    mode: 'relay-core',
    _operatingMode: 'relay-core',
    async applyMode (mode, overrides) {
      this.mode = mode
      this._operatingMode = mode
      this.config = { ...this.config, mode, ...overrides }
    }
  }

  const result = await runModeSwitchAction({
    body: { mode: 'relaykernel' },
    node
  })

  t.is(result.ok, true)
  t.is(result.payload.mode, 'relaykernel')
  t.is(result.payload.note, 'RelayKernel profile active — seed/proof/circuit/meta/accounting only')
  t.is(node.mode, 'relaykernel')
})

test('api mode transport: rolls back mode when persistence fails', async (t) => {
  const previousConfig = { mode: 'standard' }
  let syncCalls = 0
  const events = []
  const node = {
    config: previousConfig,
    mode: 'standard',
    _operatingMode: 'standard',
    running: true,
    async applyMode (mode, overrides) {
      this.mode = mode
      this._operatingMode = mode
      this.config = { ...this.config, mode, ...overrides }
    },
    async _syncAccessControl () {
      syncCalls++
    }
  }

  const result = await runModeSwitchAction({
    body: { mode: 'homehive', maxConnections: 12 },
    node,
    persistConfig: async () => { throw new Error('readonly config') },
    emit: (event, payload) => events.push({ event, payload })
  })

  t.is(result.ok, false)
  t.is(result.kind, 'config-persist')
  t.is(result.error.message, 'readonly config')
  t.is(node.config, previousConfig)
  t.is(node.mode, 'standard')
  t.is(node._operatingMode, 'standard')
  t.is(syncCalls, 1)
  t.alike(events, [])
})

test('api mode transport: reports applyMode failures as bad requests', async (t) => {
  let persisted = false
  const node = {
    config: {},
    async applyMode () {
      throw new Error('mode unavailable')
    }
  }

  const result = await runModeSwitchAction({
    body: { mode: 'homehive' },
    node,
    persistConfig: async () => { persisted = true }
  })

  t.is(result.ok, false)
  t.is(result.kind, 'apply-mode')
  t.is(result.status, 400)
  t.alike(result.payload, { error: 'mode unavailable' })
  t.is(persisted, false)
})

test('api mode transport: validates transport names before mutation', async (t) => {
  const config = { transports: { udp: true } }
  let persisted = false

  for (const transport of [null, '__proto__', 'constructor', 'prototype', 'bad.name', 'bad name']) {
    const result = await runTransportToggleAction({
      body: { transport, enabled: true },
      config,
      persistConfig: async () => { persisted = true }
    })
    t.is(result.status, 400)
  }

  t.alike(config.transports, { udp: true })
  t.is(persisted, false)

  const missingConfig = {}
  const malformedEnabled = await runTransportToggleAction({
    body: { transport: 'tor', enabled: 'false' },
    config: missingConfig,
    persistConfig: async () => { persisted = true }
  })
  t.is(malformedEnabled.status, 400)
  t.alike(malformedEnabled.payload, { error: 'enabled must be a boolean' })
  t.absent(missingConfig.transports)
  t.is(persisted, false)
})

test('api mode transport: persists transport toggles and rolls back failures', async (t) => {
  {
    const config = {}
    const persisted = []
    const result = await runTransportToggleAction({
      body: { transport: 'tor', enabled: true },
      config,
      persistConfig: async () => persisted.push({ ...config.transports })
    })

    t.is(result.ok, true)
    t.is(config.transports.udp, true)
    t.is(config.transports.tor, true)
    t.alike(persisted, [{ udp: true, tor: true }])
  }

  {
    const config = {}
    const result = await runTransportToggleAction({
      body: { transport: 'tor', enabled: true },
      config,
      persistConfig: async () => { throw new Error('readonly config') }
    })

    t.is(result.ok, false)
    t.is(result.kind, 'config-persist')
    t.absent(config.transports)
  }

  {
    const config = { transports: { udp: true } }
    const result = await runTransportToggleAction({
      body: { transport: 'tor', enabled: true },
      config,
      persistConfig: async () => { throw new Error('readonly config') }
    })

    t.is(result.ok, false)
    t.alike(config.transports, { udp: true })
  }
})
