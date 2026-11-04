import { copyStorageCapProvenance } from '../../config/storage-cap.js'
import { corestoreGenerationPublicConfig } from '../persistence/corestore-generation-envelope.js'

export function buildSafeConfigPayload (node) {
  const c = node && node.config ? node.config : {}
  const payload = {
    name: c.name,
    storage: c.storage,
    // Public digests/identifier only. The envelope authority key bytes never
    // enter runtime configuration or API persistence.
    hiverelayGeneration: corestoreGenerationPublicConfig(c.hiverelayGeneration),
    capacityProfile: c.capacityProfile == null ? null : c.capacityProfile,
    acceptMode: c.acceptMode,
    acceptAllowlist: Array.isArray(c.acceptAllowlist) ? c.acceptAllowlist : [],
    maxStorageBytes: c.maxStorageBytes,
    maxConnections: c.maxConnections,
    maxRelayBandwidthMbps: c.maxRelayBandwidthMbps,
    enableRelay: c.enableRelay,
    enableSeeding: c.enableSeeding,
    enableServices: c.enableServices,
    plugins: Array.isArray(c.plugins) ? c.plugins : [],
    enableMetrics: c.enableMetrics,
    enableAPI: c.enableAPI,
    apiPort: c.apiPort,
    apiHost: c.apiHost,
    corsOrigins: c.corsOrigins,
    regions: c.regions || [],
    discovery: c.discovery || { dht: true, announce: true, mdns: false },
    access: c.access || { open: true, allowlist: [] },
    pairing: c.pairing || { enabled: false },
    transports: c.transports || { udp: true },
    registryAutoAccept: c.registryAutoAccept,
    maxCircuitsPerPeer: c.maxCircuitsPerPeer,
    maxCircuitDuration: c.maxCircuitDuration,
    maxCircuitBytes: c.maxCircuitBytes,
    announceInterval: c.announceInterval,
    requireSignedCatalog: c.requireSignedCatalog,
    catalogSignatureMaxAgeMs: c.catalogSignatureMaxAgeMs,
    catalogMaxAppAgeMs: c.catalogMaxAppAgeMs,
    strictSeedingPrivacy: c.strictSeedingPrivacy,
    enableDistributedDriveBridge: c.enableDistributedDriveBridge,
    gatewayPublicOnlyPrivacyTier: c.gatewayPublicOnlyPrivacyTier,
    replicationCheckInterval: c.replicationCheckInterval,
    replicationRepairEnabled: c.replicationRepairEnabled,
    targetReplicaFloor: c.targetReplicaFloor,
    shutdownTimeoutMs: c.shutdownTimeoutMs,
    subsidy: c.subsidy || { enabled: false, payoutDestination: null },
    mode: node && node._operatingMode ? node._operatingMode : 'standard'
  }
  return copyStorageCapProvenance(c, payload)
}

export function snapshotWizardConfig (config = {}) {
  return {
    name: config.name,
    acceptMode: config.acceptMode,
    hasAcceptMode: Object.prototype.hasOwnProperty.call(config, 'acceptMode'),
    registryAutoAccept: config.registryAutoAccept,
    hasRegistryAutoAccept: Object.prototype.hasOwnProperty.call(config, 'registryAutoAccept'),
    subsidy: config.subsidy && typeof config.subsidy === 'object' ? { ...config.subsidy } : config.subsidy,
    hasSubsidy: Object.prototype.hasOwnProperty.call(config, 'subsidy')
  }
}

export function restoreWizardConfig (config, snapshot) {
  if (!snapshot || !config) return
  if (snapshot.name === undefined) delete config.name
  else config.name = snapshot.name
  if (snapshot.hasAcceptMode) config.acceptMode = snapshot.acceptMode
  else delete config.acceptMode
  if (snapshot.hasRegistryAutoAccept) config.registryAutoAccept = snapshot.registryAutoAccept
  else delete config.registryAutoAccept
  if (snapshot.hasSubsidy) config.subsidy = snapshot.subsidy
  else delete config.subsidy
}
