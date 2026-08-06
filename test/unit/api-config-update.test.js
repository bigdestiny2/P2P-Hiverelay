import test from 'brittle'
import {
  resolveConfigUpdateRoute,
  runConfigUpdateAction
} from '../../packages/core/core/relay-node/api-config-update.js'
import { getStorageCapProvenance } from '../../packages/core/config/storage-cap.js'

test('api config update: route helper maps exact config update route', (t) => {
  t.alike(resolveConfigUpdateRoute('POST', '/api/manage/config'), {
    kind: 'config-update'
  })

  t.is(resolveConfigUpdateRoute('GET', '/api/manage/config'), null)
  t.is(resolveConfigUpdateRoute('POST', '/api/manage/config/extra'), null)
  t.is(resolveConfigUpdateRoute('POST', '/api/manage/configuration'), null)
})

test('api config update: rejects malformed integers and rolls back earlier fields', async (t) => {
  const config = {
    maxConnections: 7,
    maxStorageBytes: 2 * 1048576
  }
  let persisted = false

  const result = await runConfigUpdateAction({
    body: {
      maxConnections: '12',
      maxStorageBytes: '1e9'
    },
    config,
    persistConfig: async () => { persisted = true }
  })

  t.is(result.ok, false)
  t.is(result.status, 400)
  t.alike(result.payload, { error: 'maxStorageBytes must be a valid integer' })
  t.is(config.maxConnections, 7)
  t.is(config.maxStorageBytes, 2 * 1048576)
  t.is(persisted, false)
})

test('api config update: rejects malformed decimals and rolls back earlier fields', async (t) => {
  const config = {
    maxConnections: 7,
    maxRelayBandwidthMbps: 25
  }

  const result = await runConfigUpdateAction({
    body: {
      maxConnections: '12',
      maxRelayBandwidthMbps: '1e3'
    },
    config
  })

  t.is(result.ok, false)
  t.is(result.status, 400)
  t.alike(result.payload, { error: 'maxRelayBandwidthMbps must be a valid number' })
  t.is(config.maxConnections, 7)
  t.is(config.maxRelayBandwidthMbps, 25)
})

test('api config update: applies booleans arrays objects and persists before success', async (t) => {
  const config = {
    discovery: { mdns: true, bootstrap: ['old'] },
    access: { privateMode: false },
    pairing: { enabled: false }
  }
  const persisted = []

  const result = await runConfigUpdateAction({
    body: {
      registryAutoAccept: false,
      replicationRepairEnabled: false,
      gatewayPublicOnlyPrivacyTier: true,
      strictSeedingPrivacy: false,
      enableDistributedDriveBridge: true,
      requireSignedCatalog: true,
      regions: ['NA', 'EU'],
      discovery: { bootstrap: ['new'] },
      access: { privateMode: true },
      pairing: { enabled: true }
    },
    config,
    persistConfig: async () => {
      persisted.push(JSON.parse(JSON.stringify(config)))
    },
    safeConfigPayload: () => ({ safe: true, config })
  })

  t.is(result.ok, true)
  t.alike(result.payload.config, { safe: true, config })
  t.is(config.registryAutoAccept, false)
  t.is(config.replicationRepairEnabled, false)
  t.is(config.gatewayPublicOnlyPrivacyTier, true)
  t.is(config.strictSeedingPrivacy, false)
  t.is(config.enableDistributedDriveBridge, true)
  t.is(config.requireSignedCatalog, true)
  t.alike(config.regions, ['NA', 'EU'])
  t.alike(config.discovery, { mdns: true, bootstrap: ['new'] })
  t.alike(config.access, { privateMode: true })
  t.alike(config.pairing, { enabled: true })
  t.is(persisted.length, 1)
  t.alike(persisted[0].regions, ['NA', 'EU'])
})

test('api config update: rejects malformed regions and nested object fields without mutation', async (t) => {
  const config = {
    maxConnections: 7,
    regions: ['NA'],
    discovery: { mdns: true },
    access: { privateMode: false },
    pairing: { enabled: false }
  }
  let persisted = false

  let result = await runConfigUpdateAction({
    body: {
      maxConnections: '12',
      regions: 'EU'
    },
    config,
    persistConfig: async () => { persisted = true }
  })
  t.is(result.status, 400)
  t.alike(result.payload, { error: 'regions must be an array of strings' })
  t.is(config.maxConnections, 7)
  t.alike(config.regions, ['NA'])
  t.is(persisted, false)

  result = await runConfigUpdateAction({
    body: {
      maxConnections: '12',
      discovery: []
    },
    config,
    persistConfig: async () => { persisted = true }
  })
  t.is(result.status, 400)
  t.alike(result.payload, { error: 'discovery must be an object' })
  t.is(config.maxConnections, 7)
  t.alike(config.discovery, { mdns: true })

  result = await runConfigUpdateAction({
    body: {
      access: null
    },
    config,
    persistConfig: async () => { persisted = true }
  })
  t.is(result.status, 400)
  t.alike(result.payload, { error: 'access must be an object' })
  t.alike(config.access, { privateMode: false })

  result = await runConfigUpdateAction({
    body: {
      pairing: 'enabled'
    },
    config,
    persistConfig: async () => { persisted = true }
  })
  t.is(result.status, 400)
  t.alike(result.payload, { error: 'pairing must be an object' })
  t.alike(config.pairing, { enabled: false })

  result = await runConfigUpdateAction({
    body: {
      maxConnections: '12',
      registryAutoAccept: 'false'
    },
    config,
    persistConfig: async () => { persisted = true }
  })
  t.is(result.status, 400)
  t.alike(result.payload, { error: 'registryAutoAccept must be a boolean' })
  t.is(config.maxConnections, 7)
  t.absent(config.registryAutoAccept)

  result = await runConfigUpdateAction({
    body: {
      requireSignedCatalog: { enabled: true }
    },
    config,
    persistConfig: async () => { persisted = true }
  })
  t.is(result.status, 400)
  t.alike(result.payload, { error: 'requireSignedCatalog must be a boolean' })
  t.absent(config.requireSignedCatalog)
})

test('api config update: persistence failure rolls back all applied fields', async (t) => {
  const previousDiscovery = { mdns: true }
  const config = {
    maxConnections: 7,
    discovery: previousDiscovery
  }

  const result = await runConfigUpdateAction({
    body: {
      maxConnections: '12',
      registryAutoAccept: false,
      discovery: { bootstrap: ['new'] }
    },
    config,
    persistConfig: async () => { throw new Error('readonly config') }
  })

  t.is(result.ok, false)
  t.is(result.kind, 'config-persist')
  t.is(result.error.message, 'readonly config')
  t.is(config.maxConnections, 7)
  t.absent(config.registryAutoAccept)
  t.is(config.discovery, previousDiscovery)
})

test('api config update: maxStorageBytes equal to 50 GiB is marked explicit before persistence', async (t) => {
  const config = { maxStorageBytes: 10 * 1024 ** 3 }
  let persistedProvenance = null

  const result = await runConfigUpdateAction({
    body: { maxStorageBytes: 50 * 1024 ** 3 },
    config,
    persistConfig: async () => {
      persistedProvenance = getStorageCapProvenance(config)
    }
  })

  t.is(result.ok, true)
  t.is(config.maxStorageBytes, 50 * 1024 ** 3)
  t.is(persistedProvenance.explicit, true)
  t.is(persistedProvenance.source, 'management-api')
})

test('api config update: validates, normalizes, and clears capacityProfile', async (t) => {
  const config = { capacityProfile: null }

  let result = await runConfigUpdateAction({
    body: { capacityProfile: ' SEEDER-REGIONAL ' },
    config
  })
  t.ok(result.ok)
  t.is(config.capacityProfile, 'seeder-regional')
  t.is(config.capacityProfileConfigured, true)
  t.alike(result.payload.applied, ['capacityProfile'])

  result = await runConfigUpdateAction({
    body: { capacityProfile: 'monster-box' },
    config
  })
  t.is(result.status, 400)
  t.is(config.capacityProfile, 'seeder-regional', 'invalid update rolls back')

  result = await runConfigUpdateAction({
    body: { capacityProfile: null },
    config
  })
  t.ok(result.ok)
  t.is(config.capacityProfile, null)
  t.is(config.capacityProfileConfigured, true, 'explicit clear is persisted over deployment env defaults')
})
