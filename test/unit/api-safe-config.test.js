import test from 'brittle'
import {
  buildSafeConfigPayload,
  restoreWizardConfig,
  snapshotWizardConfig
} from '../../packages/core/core/relay-node/api-safe-config.js'

test('api safe config: emits only operator-safe persisted config fields', (t) => {
  const node = {
    _operatingMode: 'private',
    config: {
      name: 'relay',
      storage: '/data',
      acceptMode: 'review',
      acceptAllowlist: ['a'.repeat(64)],
      plugins: ['poker'],
      regions: ['NA'],
      discovery: { dht: false },
      access: { open: false },
      pairing: { enabled: true },
      transports: { udp: true, websocket: true },
      subsidy: { enabled: true, payoutDestination: 'operator@example.com' },
      apiPort: 9100,
      apiHost: '127.0.0.1',
      corsOrigins: ['https://operator.example'],
      maxConnections: 32,
      maxStorageBytes: 1000,
      maxRelayBandwidthMbps: 50,
      enableRelay: true,
      enableSeeding: true,
      enableServices: true,
      enableMetrics: true,
      enableAPI: true,
      registryAutoAccept: false,
      maxCircuitsPerPeer: 5,
      maxCircuitDuration: 1000,
      maxCircuitBytes: 2048,
      announceInterval: 3000,
      requireSignedCatalog: true,
      catalogSignatureMaxAgeMs: 4000,
      catalogMaxAppAgeMs: 5000,
      strictSeedingPrivacy: true,
      enableDistributedDriveBridge: false,
      gatewayPublicOnlyPrivacyTier: true,
      replicationCheckInterval: 6000,
      replicationRepairEnabled: true,
      targetReplicaFloor: 3,
      shutdownTimeoutMs: 7000,
      apiKey: 'do-not-persist',
      ui: { exposeToken: true },
      holesail: { connectionKey: 'hole-secret' },
      tor: { onionAddress: 'secret.onion' },
      pairingToken: 'pair-secret',
      privateKey: 'private-secret'
    }
  }

  const payload = buildSafeConfigPayload(node)
  t.is(payload.name, 'relay')
  t.is(payload.mode, 'private')
  t.alike(payload.plugins, ['poker'])
  t.alike(payload.transports, { udp: true, websocket: true })
  t.alike(payload.subsidy, { enabled: true, payoutDestination: 'operator@example.com' })
  t.absent(Object.prototype.hasOwnProperty.call(payload, 'apiKey'))
  t.absent(Object.prototype.hasOwnProperty.call(payload, 'ui'))
  t.absent(Object.prototype.hasOwnProperty.call(payload, 'holesail'))
  t.absent(Object.prototype.hasOwnProperty.call(payload, 'tor'))
  t.absent(Object.prototype.hasOwnProperty.call(payload, 'pairingToken'))
  t.absent(Object.prototype.hasOwnProperty.call(payload, 'privateKey'))
  t.absent(JSON.stringify(payload).includes('do-not-persist'))
  t.absent(JSON.stringify(payload).includes('hole-secret'))
  t.absent(JSON.stringify(payload).includes('secret.onion'))
  t.absent(JSON.stringify(payload).includes('pair-secret'))
})

test('api safe config: normalizes missing arrays and nested defaults', (t) => {
  const payload = buildSafeConfigPayload({ config: {} })
  t.alike(payload.acceptAllowlist, [])
  t.alike(payload.plugins, [])
  t.alike(payload.regions, [])
  t.alike(payload.discovery, { dht: true, announce: true, mdns: false })
  t.alike(payload.access, { open: true, allowlist: [] })
  t.alike(payload.pairing, { enabled: false })
  t.alike(payload.transports, { udp: true })
  t.alike(payload.subsidy, { enabled: false, payoutDestination: null })
  t.is(payload.mode, 'standard')
})

test('api safe config: wizard snapshot and restore preserves missing fields', (t) => {
  const config = {
    name: 'old',
    subsidy: { payoutDestination: 'old@example.com' }
  }
  const snapshot = snapshotWizardConfig(config)
  t.alike(snapshot, {
    name: 'old',
    acceptMode: undefined,
    hasAcceptMode: false,
    registryAutoAccept: undefined,
    hasRegistryAutoAccept: false,
    subsidy: { payoutDestination: 'old@example.com' },
    hasSubsidy: true
  })

  config.name = 'new'
  config.acceptMode = 'open'
  config.registryAutoAccept = true
  config.subsidy.payoutDestination = 'new@example.com'

  restoreWizardConfig(config, snapshot)
  t.is(config.name, 'old')
  t.absent(Object.prototype.hasOwnProperty.call(config, 'acceptMode'))
  t.absent(Object.prototype.hasOwnProperty.call(config, 'registryAutoAccept'))
  t.alike(config.subsidy, { payoutDestination: 'old@example.com' })
})

test('api safe config: wizard restore removes fields absent from snapshot', (t) => {
  const config = {
    acceptMode: 'review',
    registryAutoAccept: false,
    subsidy: { payoutDestination: null }
  }
  const snapshot = snapshotWizardConfig({})

  restoreWizardConfig(config, snapshot)
  t.absent(Object.prototype.hasOwnProperty.call(config, 'name'))
  t.absent(Object.prototype.hasOwnProperty.call(config, 'acceptMode'))
  t.absent(Object.prototype.hasOwnProperty.call(config, 'registryAutoAccept'))
  t.absent(Object.prototype.hasOwnProperty.call(config, 'subsidy'))
})
