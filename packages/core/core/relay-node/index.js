import Hyperswarm from 'hyperswarm'
import { openCorestore } from '../persistence/storage-root-restore.js'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { EventEmitter } from 'events'
import { readFile, writeFile, rename, unlink, mkdir, chmod } from 'fs/promises'
import { join, dirname } from 'path'
import { Seeder } from './seeder.js'
import { Relay } from './relay.js'
import { Metrics } from './metrics.js'
import { RelayAPI } from './api.js'
import { DistributedDriveBridge } from './distributed-drive-bridge.js'
import { WebSocketTransport } from '../../transports/websocket/index.js'
import { DHTRelayWS } from '../../transports/dht-relay-ws/index.js'
import { TorTransport } from '../../transports/tor/index.js'
import { OnionPeerListener } from '../../transports/tor/peer-listener.js'
import { completeOnionEnrollment } from '../../transports/tor/enrollment.js'
import { HolesailTransport } from '../../transports/holesail/index.js'
import http from 'http'
import { BootstrapCache } from '../bootstrap-cache.js'
import { Federation } from '../federation.js'
import { GatewayDenylist } from '../gateway-denylist.js'
import { AutoHeal } from '../auto-heal.js'
import { ManifestStore } from '../manifest-store.js'
import { resolveAcceptMode, decideAcceptance } from '../accept-mode.js'
import { SeedProtocol } from '../protocol/seed-request.js'
import { AnchorProtocol } from '../protocol/anchor-channel.js'
import { CustodyProtocol } from '../protocol/custody-channel.js'
import { PublishProtocol } from '../protocol/publish-channel.js'
import {
  accountingFieldsFromStorageSummary,
  createAccountingReceipt
} from '../protocol/accounting-receipt.js'
import {
  buildPublisherSignedSeedOpts,
  consumePublisherSeedReplayNonce,
  extractCustodySeedOpts
} from '../seed-request-builder.js'
import { isTransientCoreError } from '../transient-core-errors.js'
import { verifyDelegationCert, verifyRevocation } from '../delegation.js'
import { CircuitRelay } from '../protocol/relay-circuit.js'
import { ForwardRelay } from '../protocol/forward-relay.js'
import { SignedDirectory } from '../services/signed-directory.js'
import { ProofOfRelay } from '../protocol/proof-of-relay.js'
import { BandwidthReceipt } from '../protocol/bandwidth-receipt.js'
import { UsageLedger } from '../protocol/usage-receipt.js'
import { ReputationSystem } from '../../incentive/reputation/index.js'
import { NetworkDiscovery } from '../network-discovery.js'
import { HealthMonitor } from './health-monitor.js'
import { DiskMonitor } from './disk-monitor.js'
import { StorageAccounting } from './storage-accounting.js'
import { ServedAccounting } from './served-accounting.js'
import { EvictionManager, assertPurgable, purgeDriveCores } from './eviction.js'
import { SubsidyAccrual } from '../../incentive/subsidy/index.js'
import { LeaseManager } from '../../incentive/lease/index.js'
import { evaluateSeedLease, isLeaseExempt } from '../../incentive/lease/gate.js'
import { MockProvider } from '../../incentive/payment/mock-provider.js'
import { AlertManager } from './alert-manager.js'
import { SelfHeal } from './self-heal.js'
import { AccessControl } from './access-control.js'
import { SeedingRegistry } from '../registry/index.js'
import { ServiceRegistry, ServiceProtocol } from '../services/index.js'
// Builtin services live in the p2p-hiveservices package and are loaded at
// runtime via PluginLoader when an operator opts in (config.plugins).
// Core no longer hardcodes Services constructors.
import { PluginLoader, expandServiceDeps } from '../plugin-loader.js'
import { Router } from '../router/index.js'
import { AppRegistry } from '../app-registry.js'
import {
  RELAY_DISCOVERY_TOPIC,
  FOUNDATION_TOPIC,
  DISCOVERY_EPOCH_MS,
  syncEpochDiscoveryTopics,
  isValidHexKey,
  normalizeAvailabilityClass,
  normalizePrivacyTier,
  normalizeStorageClass
} from '../constants.js'
import { SwarmFirewall } from './swarm-firewall.js'
import { PolicyGuard } from '../policy-guard.js'
import { AppLifecycle } from './app-lifecycle.js'
import { GatewayServer, assertHiveAppGatewayIsolation } from './gateway-server.js'
import { hasActiveExactGateway } from '../../gateway/exact-app-context.js'
import { LifecycleScope, isAbortError } from './lifecycle-scope.js'
import { buildDedupReport } from './dedup-report.js'
import { encodeRelayRecord, relayRecordHasContent } from './relay-record.js'
import { hashHex } from '../custody-signing.js'
import {
  copyStorageCapProvenance,
  getStorageCapProvenance,
  markStorageCapDefault,
  markStorageCapExplicit,
  measureProvenStorageTreeBytes,
  positiveStorageBound,
  resolveStorageCap
} from '../../config/storage-cap.js'
import { StorageAdmissionAuthority } from '../../config/storage-admission-authority.js'

// z32-encoded 32-byte key (the Hypercore/Autobase z-base-32 alphabet), 52 chars.
// Used to validate the index-room pointer published by the sidecar.
const Z32_KEY_RE = /^[ybndrfg8ejkmcpqxot1uwisza345h769]{52}$/

const DEFAULT_CONFIG = {
  productProfile: 'relay-core',
  storage: './storage',
  maxStorageBytes: 50 * 1024 * 1024 * 1024, // 50 GB
  maxConnections: 256,
  maxRelayBandwidthMbps: 100,
  maxCircuitDuration: 10 * 60 * 1000,
  maxCircuitBytes: 64 * 1024 * 1024,
  maxCircuitsPerPeer: 5,
  maxCircuitRateBytesPerSecond: 1024 * 1024,
  reservationTTL: 60 * 60 * 1000,
  announceInterval: 15 * 60 * 1000, // 15 minutes
  regions: [],
  enableRelay: true,
  enableSeeding: true,
  enableMetrics: true,
  enableAPI: true,
  apiPort: 9100,
  apiHost: '0.0.0.0',
  corsOrigins: [],
  strictSeedingPrivacy: true,
  enableDistributedDriveBridge: false,
  custody: {
    enabled: true,
    defaultMode: 'blind',
    allowTransparent: false,
    requireEncryptedPayload: true,
    metadataVisibility: 'redacted',
    redactedCatalog: true,
    proofTarget: 'ciphertext',
    defaultRetainMs: 30 * 24 * 60 * 60 * 1000
  },
  custodyExpiryInterval: 60_000,
  custodyExpiryGraceMs: 0,
  gatewayPublicOnlyPrivacyTier: true,
  gatewayPort: null,
  gatewayHost: '127.0.0.1',
  gatewayTrustProxy: false,
  gatewayTrustedProxyAddresses: ['127.0.0.1', '::1', '::ffff:127.0.0.1'],
  gatewayRequireForwardedSNI: false,
  gatewayCompatibilityHosts: ['127.0.0.1', 'localhost', '[::1]'],
  gatewayMaxInFlight: 256,
  gatewayMaxInFlightPerApp: 32,
  gatewayMaxResponseBytes: 64 * 1024 * 1024,
  gatewayMaxTransformBytes: 4 * 1024 * 1024,
  gatewayEgressBytesPerWindow: 256 * 1024 * 1024,
  gatewayEgressWindowMs: 60 * 1000,
  gatewayMaxResponseLifetimeMs: 15 * 60 * 1000,
  hiveAppHostSuffix: null,
  hiveAppPublicKeys: [],
  hiveAppPublicVersions: {},
  requireSignedCatalog: false,
  catalogSignatureMaxAgeMs: 5 * 60 * 1000,
  catalogMaxAppAgeMs: 30 * 24 * 60 * 60 * 1000,
  // Optional bare 64-hex key of a signed Hyperbee catalog to advertise (in
  // /catalog.json and the gateway firehose) as `catalogBeeKey`. Clients that
  // can replicate + verify a signed P2P catalog (e.g. PearBrowser) PREFER it
  // over the HTTP firehose, so an operator can pin a curated, queryable
  // catalogue. Empty = don't advertise (each operator sets their own key; it's
  // intentionally NOT a product default). Read at boot + by /seed-core.
  catalogBeeKey: '',
  // Catalog accept-mode controls how inbound seed requests are handled.
  //   'open'      — auto-accept every signed seed request (legacy behaviour)
  //   'review'    — queue seed requests for operator approval (default)
  //   'allowlist' — auto-accept only requests from publishers in acceptAllowlist
  //   'closed'    — reject all inbound seed requests; operator-initiated seeds only
  // Left undefined here so deprecated `registryAutoAccept` can still be honored
  // when callers haven't migrated. Default mode is decided in `_resolveAcceptMode`.
  acceptMode: undefined,
  acceptAllowlist: [], // array of publisher pubkeys (hex) — only used when acceptMode === 'allowlist'
  // P2P service auth defaults. Secure-by-default: anonymous swarm peers get the
  // 'anonymous' role and therefore cannot reach 'authenticated-user' or
  // 'relay-admin' service routes. Operators promote selected pubkeys to
  // relay-admin via serviceAdminAllowlist, or — only if they explicitly want an
  // open, unauthenticated service surface — set serviceDefaultPeerRole to
  // 'authenticated-user'. Knowing the discovery key must not be enough to call
  // storage/ai/zk/arbitration/sla over the swarm.
  serviceDefaultPeerRole: 'anonymous',
  serviceAdminAllowlist: [],
  enableServices: false,
  plugins: [],
  serviceSupervision: {
    enabled: true,
    intervalMs: 30_000,
    maxRestarts: 3
  },
  subsidy: {
    enabled: false,
    rateSatsPerDay: 500,
    epochMs: 10 * 60 * 1000,
    payoutDestination: null
  },
  lease: {
    enabled: false,
    satsPerGiBDay: 10,
    maxSatsPerGiBDay: 1_000_000,
    quoteTtlMs: 60 * 60 * 1000,
    minLeaseDays: 1,
    maxLeaseDays: 3650,
    provider: 'mock'
  },
  payment: {
    enabled: false,
    settlementInterval: 24 * 60 * 60 * 1000,
    minSettlementSats: 1000
  },
  x402: {
    enabled: false,
    facilitatorUrl: 'https://x402.org/facilitator',
    publicBaseUrl: null,
    claimTtlMs: 10 * 60 * 1000,
    maxClaims: 50_000,
    routes: {}
  },
  signedDirectory: {
    enabled: false,
    maxEntryBytes: 8 * 1024,
    ttlSeconds: 24 * 60 * 60,
    maxEntriesPerAuthor: 1,
    publishRatePerMinute: 5,
    maxTotalEntries: 10_000,
    clockSkewToleranceSeconds: 60
  },
  // Federation: opt-in cross-relay catalog sharing. No automatic sync.
  // Operators explicitly follow / mirror / unfollow other relays at runtime.
  federation: {
    enabled: false,
    followInterval: 5 * 60 * 1000, // 5 min poll for followed catalogs
    followed: [], // [{ url, pubkey?, mode: 'follow' }] — pulls catalogs, queues for review
    mirrored: [] // [{ url, pubkey?, mode: 'mirror' }] — auto-accepts everything (use only for trusted partners)
  },
  discovery: {
    dht: true,
    announce: true,
    mdns: false
  },
  access: {
    open: true,
    allowlist: []
  },
  pairing: {
    enabled: false
  },
  replicationCheckInterval: 60_000,
  replicationRepairEnabled: true,
  targetReplicaFloor: 2,
  bootstrapNodes: null, // null = use HyperDHT defaults
  dhtFlushTimeoutMs: 1000,
  shutdownTimeoutMs: 10_000,
  // Legacy seed-time "evict oldest" behavior is disabled. The reviewed
  // EvictionManager remains independently opt-in via eviction.enabled.
  enableEviction: false,
  // Bound the in-memory pending-approval queue. With `acceptMode: 'review'` an
  // attacker (or a misconfigured peer) could otherwise pile up unbounded entries
  // in `_pendingRequests` until the operator approves/rejects them. When the cap
  // is hit, the oldest pending entry (by `discoveredAt`) is evicted and a
  // `'pending-evicted'` event fires.
  maxPendingRequests: 5000
}

const MODE_PRESETS = {
  'relay-core': {
    productProfile: 'relay-core',
    enableRelay: true,
    enableSeeding: true,
    enableServices: false,
    plugins: [],
    maxConnections: 256,
    maxRelayBandwidthMbps: 100
  },
  relaykernel: {
    productProfile: 'relaykernel',
    enableRelay: true,
    enableSeeding: true,
    enableMetrics: true,
    enableAPI: true,
    enableServices: false,
    plugins: [],
    acceptMode: 'review',
    registryAutoAccept: false,
    strictSeedingPrivacy: true,
    gatewayPublicOnlyPrivacyTier: true,
    requireSignedCatalog: true,
    custody: {
      enabled: false,
      defaultMode: 'blind',
      allowTransparent: false,
      requireEncryptedPayload: true,
      metadataVisibility: 'redacted',
      redactedCatalog: true,
      proofTarget: 'ciphertext',
      defaultRetainMs: 0
    },
    signedDirectory: {
      enabled: false
    },
    federation: {
      enabled: false,
      followed: [],
      mirrored: []
    },
    lease: {
      enabled: false
    },
    payment: {
      enabled: false
    },
    subsidy: {
      enabled: false,
      payoutDestination: null
    }
  },
  'custody-relay': {
    productProfile: 'custody-relay',
    enableRelay: true,
    enableSeeding: true,
    enableServices: false,
    plugins: [],
    strictSeedingPrivacy: true,
    custody: {
      enabled: true,
      defaultMode: 'blind',
      allowTransparent: false,
      requireEncryptedPayload: true,
      metadataVisibility: 'redacted',
      redactedCatalog: true,
      proofTarget: 'ciphertext',
      defaultRetainMs: 30 * 24 * 60 * 60 * 1000
    },
    custodyExpiryInterval: 60_000,
    targetReplicaFloor: 3
  },
  'public-t1-gateway': {
    productProfile: 'public-t1-gateway',
    requirePhysicalEnforcement: true,
    enableRelay: false,
    enableSeeding: true,
    enableAPI: true,
    enableServices: false,
    plugins: [],
    strictSeedingPrivacy: true,
    gatewayPublicOnlyPrivacyTier: true,
    requireSignedCatalog: true,
    custody: {
      enabled: false,
      defaultMode: 'blind',
      allowTransparent: false,
      requireEncryptedPayload: true,
      metadataVisibility: 'redacted',
      redactedCatalog: true,
      proofTarget: 'ciphertext',
      defaultRetainMs: 0
    },
    signedDirectory: { enabled: false },
    federation: { enabled: false, followed: [], mirrored: [] },
    lease: { enabled: false },
    payment: { enabled: false },
    subsidy: { enabled: false, payoutDestination: null }
  },
  public: {},
  standard: {
    productProfile: 'relay-core',
    enableRelay: true,
    enableSeeding: true,
    enableServices: false,
    plugins: [],
    maxConnections: 256,
    maxRelayBandwidthMbps: 100
  },
  private: {
    discovery: { dht: false, announce: false, mdns: true },
    access: { open: false },
    pairing: { enabled: true },
    enableRelay: false,
    enableAPI: false
  },
  hybrid: {
    discovery: { dht: true, announce: false, mdns: true },
    access: { open: false },
    pairing: { enabled: true }
  },
  homehive: {
    productProfile: 'homehive',
    discovery: { dht: true, announce: false, mdns: true },
    access: { open: false },
    pairing: { enabled: true },
    enableServices: false,
    plugins: [],
    maxConnections: 32,
    maxRelayBandwidthMbps: 25,
    maxStorageBytes: 10 * 1024 * 1024 * 1024,
    // HomeHive defaults to allowlist — operator chooses which dev keys can
    // seed on their hardware. They populate `acceptAllowlist` themselves.
    acceptMode: 'allowlist'
  },
  'seed-only': {
    enableRelay: false,
    enableSeeding: true
  },
  'relay-only': {
    enableRelay: true,
    enableSeeding: false
  },
  stealth: {
    enableRelay: true,
    enableSeeding: true,
    maxConnections: 32,
    maxRelayBandwidthMbps: 25
  },
  gateway: {
    enableRelay: false,
    enableSeeding: true,
    maxConnections: 512,
    maxRelayBandwidthMbps: 500
  },
  'service-operator': {
    productProfile: 'service-operator',
    enableRelay: true,
    enableSeeding: true,
    enableServices: true
  },
  'experimental-lab': {
    productProfile: 'experimental-lab',
    enableRelay: true,
    enableSeeding: true,
    enableServices: true,
    maxConnections: 1024,
    maxRelayBandwidthMbps: 500,
    maxStorageBytes: 200 * 1024 * 1024 * 1024
  }
}

function buildConfig (mode, opts) {
  const preset = MODE_PRESETS[mode]
  if (!preset) {
    throw new Error('Invalid mode: ' + mode + ' (expected one of: ' + Object.keys(MODE_PRESETS).join(', ') + ')')
  }

  const config = {
    ...DEFAULT_CONFIG,
    ...preset,
    ...opts,
    discovery: {
      ...DEFAULT_CONFIG.discovery,
      ...(preset.discovery || {}),
      ...(opts.discovery || {})
    },
    access: {
      ...DEFAULT_CONFIG.access,
      ...(preset.access || {}),
      ...(opts.access || {})
    },
    pairing: {
      ...DEFAULT_CONFIG.pairing,
      ...(preset.pairing || {}),
      ...(opts.pairing || {})
    },
    custody: {
      ...DEFAULT_CONFIG.custody,
      ...(preset.custody || {}),
      ...(opts.custody || {})
    },
    signedDirectory: {
      ...DEFAULT_CONFIG.signedDirectory,
      ...(preset.signedDirectory || {}),
      ...(opts.signedDirectory || {})
    },
    federation: {
      ...DEFAULT_CONFIG.federation,
      ...(preset.federation || {}),
      ...(opts.federation || {})
    },
    lease: {
      ...(DEFAULT_CONFIG.lease || {}),
      ...(preset.lease || {}),
      ...(opts.lease || {})
    },
    payment: {
      ...(DEFAULT_CONFIG.payment || {}),
      ...(preset.payment || {}),
      ...(opts.payment || {})
    },
    x402: {
      ...(DEFAULT_CONFIG.x402 || {}),
      ...(preset.x402 || {}),
      ...(opts.x402 || {}),
      routes: {
        ...(DEFAULT_CONFIG.x402?.routes || {}),
        ...(preset.x402?.routes || {}),
        ...(opts.x402?.routes || {})
      }
    },
    subsidy: {
      ...(DEFAULT_CONFIG.subsidy || {}),
      ...(preset.subsidy || {}),
      ...(opts.subsidy || {})
    }
  }

  if ((mode === 'public-t1-gateway' || config.productProfile === 'public-t1-gateway') &&
      config.requirePhysicalEnforcement !== true) {
    throw new Error('public-t1-gateway requires requirePhysicalEnforcement to be true')
  }

  return mode === 'relaykernel' ? enforceRelayKernelProfile(config) : config
}

function enforceRelayKernelProfile (config) {
  return {
    ...config,
    productProfile: 'relaykernel',
    enableServices: false,
    plugins: [],
    custody: {
      ...(config.custody || {}),
      enabled: false,
      allowTransparent: false,
      requireEncryptedPayload: true,
      metadataVisibility: 'redacted',
      redactedCatalog: true,
      proofTarget: 'ciphertext'
    },
    signedDirectory: {
      ...(config.signedDirectory || {}),
      enabled: false
    },
    federation: {
      ...(config.federation || {}),
      enabled: false,
      followed: [],
      mirrored: []
    },
    lease: {
      ...(config.lease || {}),
      enabled: false
    },
    payment: {
      ...(config.payment || {}),
      enabled: false
    },
    x402: {
      ...(config.x402 || {}),
      enabled: false,
      routes: {}
    },
    subsidy: {
      ...(config.subsidy || {}),
      enabled: false,
      payoutDestination: null
    }
  }
}

function isRelayKernelProfile (node) {
  return !!node && (
    node.mode === 'relaykernel' ||
    node._operatingMode === 'relaykernel' ||
    (node.config && (node.config.productProfile === 'relaykernel' ||
      node.config.productProfile === 'public-t1-gateway'))
  )
}

function withTimeout (promise, ms, label) {
  let timer
  return Promise.race([
    promise.finally(() => clearTimeout(timer)),
    new Promise((_resolve, reject) => {
      timer = setTimeout(() => {
        const err = new Error(`${label} timed out after ${ms}ms`)
        err.code = 'OPERATION_TIMEOUT'
        reject(err)
      }, ms)
    })
  ])
}

function receiptCounter (value, fallback = 0, name = 'counter') {
  const n = value == null ? fallback : value
  if (Number.isSafeInteger(n) && n >= 0) return n
  if (value != null) throw new Error('ACCOUNTING_RECEIPT_INVALID: bad ' + name)
  return 0
}

function identityTempPath (keyPath) {
  const suffix = b4a.alloc(8)
  sodium.randombytes_buf(suffix)
  return keyPath + '.tmp-' + Date.now() + '-' + b4a.toString(suffix, 'hex')
}

export class RelayNode extends EventEmitter {
  constructor (opts = {}) {
    super()
    const explicitMode = typeof opts.mode === 'string' ? opts.mode.trim().toLowerCase() : null
    const explicitProfile = typeof opts.productProfile === 'string' ? opts.productProfile.trim().toLowerCase() : null
    if ((explicitMode === 'public-t1-gateway' && opts.mode !== 'public-t1-gateway') ||
        (explicitProfile === 'public-t1-gateway' && opts.productProfile !== 'public-t1-gateway')) {
      throw new Error('public-t1-gateway mode and productProfile must use exact canonical spelling')
    }
    if ((explicitMode === 'public-t1-gateway' || explicitProfile === 'public-t1-gateway') &&
        ((explicitMode && explicitMode !== 'public-t1-gateway') ||
         (explicitProfile && explicitProfile !== 'public-t1-gateway'))) {
      throw new Error('public-t1-gateway productProfile and mode must select the same exact preset')
    }
    this.mode = explicitProfile === 'public-t1-gateway'
      ? 'public-t1-gateway'
      : (opts.mode || opts.productProfile || 'relay-core')
    this._storagePathExplicit = Object.prototype.hasOwnProperty.call(opts, 'storage')
    this.config = buildConfig(this.mode, opts)
    if (Object.prototype.hasOwnProperty.call(opts, 'maxStorageBytes') &&
        !getStorageCapProvenance(opts) && positiveStorageBound(opts.maxStorageBytes) === null) {
      throw new TypeError('maxStorageBytes must be a positive safe integer')
    }
    if (!getStorageCapProvenance(this.config)) {
      if (Object.prototype.hasOwnProperty.call(opts, 'maxStorageBytes')) {
        markStorageCapExplicit(this.config, 'constructor')
      } else {
        markStorageCapDefault(this.config, positiveStorageBound(this.config.maxStorageBytes))
      }
    }
    // Validate origin-isolated gateway topology before Corestore, swarm, or
    // either HTTP listener is created. A bad public-host configuration must
    // fail without leaving partially initialized network state behind.
    assertHiveAppGatewayIsolation({
      hiveAppHostSuffix: this.config.hiveAppHostSuffix,
      hiveAppPublicKeys: this.config.hiveAppPublicKeys,
      hiveAppPublicVersions: this.config.hiveAppPublicVersions,
      gatewayPort: this.config.gatewayPort,
      gatewayHost: this.config.gatewayHost,
      gatewayCompatibilityHosts: this.config.gatewayCompatibilityHosts,
      gatewayTrustedProxyAddresses: this.config.gatewayTrustedProxyAddresses,
      gatewayTrustProxy: this.config.gatewayTrustProxy,
      gatewayRequireForwardedSNI: this.config.gatewayRequireForwardedSNI,
      gatewayMaxResponseBytes: this.config.gatewayMaxResponseBytes,
      gatewayMaxTransformBytes: this.config.gatewayMaxTransformBytes,
      gatewayEgressBytesPerWindow: this.config.gatewayEgressBytesPerWindow,
      gatewayEgressWindowMs: this.config.gatewayEgressWindowMs,
      gatewayMaxResponseLifetimeMs: this.config.gatewayMaxResponseLifetimeMs,
      apiPort: this.config.apiPort,
      apiHost: this.config.apiHost,
      enableAPI: this.config.enableAPI,
      enableSeeding: this.config.enableSeeding,
      enableRelay: this.config.enableRelay,
      enableServices: this.config.enableServices,
      plugins: this.config.plugins,
      signedDirectory: this.config.signedDirectory,
      federation: this.config.federation,
      lease: this.config.lease,
      payment: this.config.payment,
      subsidy: this.config.subsidy,
      shardStore: this.config.shardStore,
      custody: this.config.custody,
      requirePhysicalEnforcement: this.config.requirePhysicalEnforcement,
      mode: this.mode,
      productProfile: this.config.productProfile
    })
    this._operatingMode = this.mode
    // Opening Corestore can create its directory. Defer it until start() has
    // proved that an explicit storage path already exists on the configured
    // filesystem; otherwise a missing mount would be silently replaced on the
    // ancestor filesystem during construction.
    this.store = null
    this.swarm = null
    this.swarmFirewall = null
    this.seeder = null
    this.relay = null
    this.metrics = null
    this.api = null
    this.gatewayServer = null
    this.wsTransport = null
    this.dhtRelayWs = null
    this.torTransport = null
    this.paymentManager = null
    this.settlementInterval = null
    // Pointer to this relay's replicable catalog bee (a Hyperbee whose core is
    // pinned via /seed-core). Surfaced in /catalog.json so consumers (e.g.
    // PearBrowser) can replicate the catalog over P2P instead of polling HTTP.
    // Set by /seed-core { catalog: true } or config; persisted in catalog-bee.json.
    this.catalogBeeKey = (typeof this.config.catalogBeeKey === 'string' && /^[0-9a-f]{64}$/i.test(this.config.catalogBeeKey))
      ? this.config.catalogBeeKey.toLowerCase()
      : null
    // Pointer (z32) to this relay's schema-sheets index room, published by the
    // index sidecar. Surfaced in the capability doc + /catalog.json so clients
    // can blind-replicate the richer signed index. Persisted in index-room.json.
    // The room itself is hosted out-of-process (corestore-7/hc11), so the relay
    // only advertises the pointer + optionally proxies the sidecar's query API.
    this.indexRoom = (typeof this.config.indexRoom === 'string' && Z32_KEY_RE.test(this.config.indexRoom))
      ? this.config.indexRoom
      : null
    this.indexSidecarUrl = (typeof this.config.indexSidecarUrl === 'string' && this.config.indexSidecarUrl)
      ? this.config.indexSidecarUrl.replace(/\/+$/, '')
      : null
    this.appRegistry = new AppRegistry(this.config.storage)
    // Federated signed gateway denylist (takedown channel). Always-on as a
    // manager so the HTTP gateway, the federation gossip pull, and the
    // /api/gateway/denylist endpoint all share one store. An empty
    // trustedAdmins list fails closed: no entry can censor a drive here
    // until the operator explicitly trusts takedown admin keys.
    this.gatewayDenylist = new GatewayDenylist({
      trustedAdmins: this.config.gatewayDenylist?.trustedAdmins || [],
      storagePath: join(this.config.storage, 'gateway-denylist.json')
    })
    this.appLifecycle = new AppLifecycle(this)
    // Forward lifecycle events so existing listeners on RelayNode keep working
    for (const ev of ['seeding', 'unseeded', 'reseeded', 'reseed-error', 'app-replaced', 'app-version-rejected']) {
      this.appLifecycle.on(ev, (payload) => this._emitSafely(ev, payload))
    }
    this.connections = new Map() // conn -> { lastActivity }
    this._healthCheckInterval = null
    this.bootstrapCache = new BootstrapCache(this.config.storage, {
      enabled: this.config.bootstrapCacheEnabled !== false,
      maxPeers: this.config.bootstrapCachePeers || 50
    })
    this.reputation = new ReputationSystem()
    this._proofOfRelay = null
    this._anchorProtocol = null
    this._custodyProtocol = null
    this._publishProtocol = null
    this._bandwidthReceipt = null
    // Honest metering: collects consumer-signed UsageReceipts (payout-eligible).
    // Lightweight + in-memory; available before start() so the API can record
    // submitted receipts whether or not the services layer is enabled.
    this.usageLedger = new UsageLedger()
    this._reputationDecayInterval = null
    this._reputationSaveInterval = null
    this.networkDiscovery = null
    this.healthMonitor = null
    this.diskMonitor = null
    this.storageAccounting = null
    this.storageAdmission = new StorageAdmissionAuthority(this.config, {
      getUsedBytes: () => this._storageUsedBytes(),
      getActualBytes: (key, record) => this._storageActualBytes(key, record),
      recoveryKinds: ['drives', 'cores'],
      physicalEnforcer: this.config.physicalEnforcer || null
    })
    this.appRegistry.setStorageAdmission(this.storageAdmission, {
      requirePhysicalEnforcement: this.config.requirePhysicalEnforcement === true ||
        !!this.config.physicalEnforcer
    })
    this.servedAccounting = null
    this.eviction = null
    this.subsidyAccrual = null
    this.leaseManager = null
    this.alertManager = null
    this.selfHeal = null
    this.seedingRegistry = null
    this.distributedDriveBridge = null
    this._registryScanInterval = null
    this._registryInitialScanTimer = null
    this._acceptanceReconcileTimer = null
    this._coldStartPrimerTimer = null
    this.serviceRegistry = null
    this.serviceProtocol = null
    this._serviceSupervisionInterval = null
    this._serviceContext = null
    this.router = null
    this.policyGuard = new PolicyGuard()
    this.policyGuard.on('violation', (details) => this.emit('privacy-violation', details))
    this.policyGuard.on('reinstated', (details) => this.emit('privacy-reinstated', details))
    this.accessControl = null
    this._rejectedConnections = 0
    this._pendingRequests = new Map() // appKey -> registry entry (approval mode queue)
    // Revoked delegation certs, keyed by cert signature (hex).
    // Value: { revokedAt, expiresAt, reason, primaryPubkey }. expiresAt is
    // the original cert's expiresAt — no point tracking a revocation past
    // the cert's own expiry. A periodic sweep drops stale entries.
    this._revokedCertSignatures = new Map()
    this._revocationSweepInterval = null
    this.federation = null // lazily constructed in start() if config.federation.enabled
    this.manifestStore = null // lazily constructed in start() once storage dir exists
    this._catalogBroadcastTimer = null
    this._catalogPeerThrottle = new Map() // peerKey -> lastCatalogTime
    this._catalogThrottleCleanup = null
    this._replicationCheckInterval = null
    this._replicationHealth = new Map() // appKey -> { state, current, target, missing }
    this._lastReplicationCheckAt = null
    this._anchorCheckInterval = null
    this._anchorInitialTimer = null
    this._lastAnchorCheckAt = null
    this._repairInterval = null
    this._repairInitialTimer = null
    this._lastRepairAt = null
    this._custodyExpiryInterval = null
    this._custodyExpiryInitialTimer = null
    this._lastCustodyExpiryAt = null
    // LifecycleScope — cancellation contract for fire-and-forget loops and
    // event handlers (see lifecycle-scope.js). Recreated by every start()
    // call so post-stop+start sequences get a fresh signal. stop()'s
    // first action is `await this._scope.drain()` so no closure outlives
    // the corestore.
    this._scope = null
    this._epochDiscoveryTopics = new Map()
    this._retiringEpochDiscoveryHandles = new Set()
    this._relayDiscoveryHandle = null
    this._foundationDiscoveryHandle = null
    this.running = false
    this._starting = false
    this._stopping = null
    this._ownerOperations = new WeakMap()
    this._ownerDeadline = null
    this._startCompletion = null
    this._lastStartCompletion = null
    this._stopRequested = false
    this._startupRollbackPending = false
    this._storageIngressReady = false
  }

  // Backwards compat: expose the seeded apps Map owned by AppLifecycle.
  get seededApps () {
    return this.appLifecycle.seededApps
  }

  /**
   * Register a fire-and-forget promise with the active LifecycleScope so
   * stop() drains it before tearing down state. Used by all the
   * `setInterval(...)`/`setTimeout(...)` handlers that previously did
   * `someAsync().catch(() => {})` — see CANCELLATION-CONTRACT.md.
   *
   * Returns the promise unchanged. If start() has not run (no active
   * scope), the promise is left alone — caller is responsible for its
   * lifetime.
   *
   * @param {Promise} promise
   * @returns {Promise}
   */
  _trackFireAndForget (promise) {
    if (this._scope) this._scope.tracked(promise)
    return promise
  }

  _emitSafely (event, ...args) {
    let firstError = null
    for (const listener of this.rawListeners(event)) {
      try { listener.apply(this, args) } catch (err) { if (!firstError) firstError = err }
    }
    if (firstError && event !== 'observer-error') {
      for (const listener of this.rawListeners('observer-error')) {
        try { listener.call(this, { event, error: firstError }) } catch (_) {}
      }
    }
    return this.listenerCount(event) > 0
  }

  _isRestrictedMode () {
    return (
      this.mode === 'private' ||
      this.mode === 'homehive' ||
      this.mode === 'hybrid' ||
      this.config?.access?.open === false
    )
  }

  async _syncAccessControl () {
    const restrictedMode = this._isRestrictedMode()

    if (!restrictedMode) {
      if (this.accessControl) {
        try { this.accessControl.disablePairing() } catch {}
        this.accessControl = null
      }
      return
    }

    if (!this.accessControl) {
      this.accessControl = new AccessControl(this.config.storage, {
        maxDevices: this.config?.access?.maxDevices || 50
      })
      await this.accessControl.load()
    }

    const bootstrapAllowlist = this.config?.access?.allowlist
    if (Array.isArray(bootstrapAllowlist)) {
      for (const pubkey of bootstrapAllowlist) {
        if (!isValidHexKey(pubkey)) continue
        if (!this.accessControl.isAllowed(pubkey)) {
          await this.accessControl.addDevice(pubkey, 'config-allowlist')
        }
      }
    }
  }

  async applyMode (mode, overrides = {}) {
    if (hasActiveExactGateway(this)) {
      throw new Error('Runtime mode changes are forbidden while an exact app-host GatewayServer is active; stop and perform a reviewed restart')
    }
    const rollbackState = this._captureModeState()
    const previousStorageCap = getStorageCapProvenance(this.config)
    const previousMaxStorageBytes = positiveStorageBound(this.config.maxStorageBytes)
    const hasStorageOverride = Object.prototype.hasOwnProperty.call(overrides, 'maxStorageBytes')
    if (hasStorageOverride && positiveStorageBound(overrides.maxStorageBytes) === null) {
      throw new Error('maxStorageBytes must be a positive safe integer')
    }
    const carry = { ...this.config }
    for (const key of [
      'mode',
      'enableRelay',
      'enableSeeding',
      'enableAPI',
      'maxConnections',
      'maxRelayBandwidthMbps',
      'maxStorageBytes',
      'productProfile',
      'enableServices',
      'plugins',
      'registryAutoAccept',
      'acceptMode',
      'acceptAllowlist',
      'federation',
      'discovery',
      'access',
      'pairing',
      'custody',
      'custodyExpiryInterval',
      'custodyExpiryGraceMs',
      'signedDirectory',
      'lease',
      'payment',
      'subsidy'
    ]) {
      delete carry[key]
    }

    const nextConfig = buildConfig(mode, {
      ...carry,
      ...overrides,
      mode
    })

    // The physical storage ceiling is installed against an exact storage-root
    // identity during startup. A live mode change cannot safely add, remove, or
    // replace that authority: doing so would let config claim hard enforcement
    // while AppRegistry continued under its previous admission contract. Keep
    // both controls restart-only so startup can prove the complete binding
    // before any durable registry write is admitted.
    if (nextConfig.requirePhysicalEnforcement !== this.config.requirePhysicalEnforcement ||
        nextConfig.physicalEnforcer !== this.config.physicalEnforcer) {
      const err = new Error('physical storage enforcement changes require restart')
      err.code = 'PHYSICAL_ENFORCEMENT_RESTART_REQUIRED'
      throw err
    }

    if (hasStorageOverride) {
      markStorageCapExplicit(nextConfig, 'management-api')
      resolveStorageCap(nextConfig)
    } else if (previousStorageCap?.explicit === true && previousMaxStorageBytes !== null) {
      nextConfig.maxStorageBytes = previousMaxStorageBytes
      copyStorageCapProvenance(this.config, nextConfig)
      resolveStorageCap(nextConfig)
    } else {
      const targetDefault = positiveStorageBound(nextConfig.maxStorageBytes) || previousMaxStorageBytes
      const nonWideningDefault = previousMaxStorageBytes === null
        ? targetDefault
        : Math.min(targetDefault || previousMaxStorageBytes, previousMaxStorageBytes)
      nextConfig.maxStorageBytes = nonWideningDefault
      markStorageCapDefault(nextConfig, nonWideningDefault)
      resolveStorageCap(nextConfig)
    }

    this.mode = mode
    this._operatingMode = mode
    this.config = nextConfig
    this.storageAdmission.setConfig(nextConfig)
    this.storageAdmission.refreshFilesystem()
    if (this.seeder) this.seeder.maxStorageBytes = nextConfig.maxStorageBytes

    if (this.running) {
      try {
        await this._syncAccessControl()
      } catch (err) {
        try { await this._restoreModeState(rollbackState) } catch (rollbackErr) {
          try { this.emit('mode-rollback-error', { error: rollbackErr }) } catch (_) {}
        }
        throw err
      }
    }

    return this.config
  }

  _captureModeState () {
    return {
      config: this.config,
      mode: this.mode,
      operatingMode: this._operatingMode,
      seederMaxStorageBytes: this.seeder ? this.seeder.maxStorageBytes : null
    }
  }

  async _restoreModeState (state, opts = {}) {
    if (!state || !state.config) throw new Error('mode rollback state unavailable')
    this.config = state.config
    this.mode = state.mode
    this._operatingMode = state.operatingMode
    if (this.storageAdmission) {
      this.storageAdmission.setConfig(state.config)
      this.storageAdmission.refreshFilesystem()
    }
    if (this.seeder) {
      this.seeder.maxStorageBytes = state.seederMaxStorageBytes == null
        ? state.config.maxStorageBytes
        : state.seederMaxStorageBytes
    }
    if (this.running && opts.syncAccess !== false) await this._syncAccessControl()
    return this.config
  }

  // ─── Services-layer opt-in (Services tab; config + restart) ────────
  _servicesOverridePath () {
    return this.config.storage ? join(this.config.storage, 'services.json') : null
  }

  async _loadServicesOverride () {
    if (isRelayKernelProfile(this)) {
      this.config.enableServices = false
      this.config.plugins = []
      return
    }

    const path = this._servicesOverridePath()
    if (!path) return
    try {
      const data = JSON.parse(await readFile(path, 'utf8'))
      if (data && data.enabled === true && Array.isArray(data.plugins)) {
        this.config.enableServices = true
        // expandServiceDeps pulls in bundle support services (e.g. poker -> vrf+
        // arbitration+zk) and filters to builtins, in case services.json was
        // hand-edited to list a bundle key without its deps.
        this.config.plugins = expandServiceDeps(data.plugins)
      }
    } catch {
      // Missing/corrupt -> leave config as-is (services stay off by default).
    }
  }

  /**
   * Persist the operator's Services-layer choice (the Services tab toggle).
   * Takes full effect on the next restart — _loadServicesOverride reads it
   * before the services-init block. Validates plugin names against builtins.
   */
  async setServicesConfig ({ enabled, plugins } = {}) {
    // expandServiceDeps dedups, filters to builtins, AND auto-unions bundle
    // support services so enabling 'poker' also enables vrf+arbitration+zk.
    const locked = isRelayKernelProfile(this)
    const list = locked ? [] : (Array.isArray(plugins) ? expandServiceDeps(plugins) : [])
    const payload = {
      enabled: locked ? false : enabled === true,
      plugins: list,
      updatedAt: Date.now()
    }
    if (locked) {
      payload.locked = true
      payload.lockReason = this.config.productProfile === 'public-t1-gateway'
        ? 'public-t1-gateway-profile'
        : 'relaykernel-profile'
    }
    const path = this._servicesOverridePath()
    if (path) {
      const tmp = path + '.tmp'
      try {
        await mkdir(dirname(path), { recursive: true })
        await writeFile(tmp, JSON.stringify(payload))
        await rename(tmp, path)
      } catch (err) {
        try { await unlink(tmp) } catch (_) {}
        this.emit('services-config-persist-error', err)
      }
    }
    // Reflect in live config; the registry itself (re)starts on restart.
    this.config.enableServices = payload.enabled
    this.config.plugins = payload.plugins
    return payload
  }

  _catalogBeePath () {
    return this.config.storage ? join(this.config.storage, 'catalog-bee.json') : null
  }

  async _loadCatalogBeeKey () {
    const path = this._catalogBeePath()
    if (!path) return
    try {
      const data = JSON.parse(await readFile(path, 'utf8'))
      if (typeof data.key === 'string' && /^[0-9a-f]{64}$/i.test(data.key)) {
        this.catalogBeeKey = data.key.toLowerCase()
      }
    } catch {
      // Missing/corrupt -> keep whatever the constructor set from config (or null).
    }
  }

  /**
   * Set + persist this relay's advertised catalog-bee pointer. The key is the
   * core key of a Hyperbee catalog pinned via /seed-core; it is surfaced in
   * /catalog.json so consumers (e.g. PearBrowser) can replicate the catalog
   * over P2P instead of polling HTTP. Atomic tmp+rename.
   */
  async setCatalogBeeKey (hex) {
    if (typeof hex !== 'string' || !/^[0-9a-f]{64}$/i.test(hex)) {
      throw new Error('catalogBeeKey must be 64 hex characters')
    }
    this.catalogBeeKey = hex.toLowerCase()
    const path = this._catalogBeePath()
    if (path) {
      const tmp = path + '.tmp'
      try {
        await mkdir(dirname(path), { recursive: true })
        await writeFile(tmp, JSON.stringify({ key: this.catalogBeeKey, updatedAt: Date.now() }))
        await rename(tmp, path)
      } catch (err) {
        try { await unlink(tmp) } catch (_) {}
        this.emit('catalog-bee-persist-error', err)
      }
    }
    this.emit('catalog-bee-key', { key: this.catalogBeeKey })
    return this.catalogBeeKey
  }

  _indexRoomPath () {
    return this.config.storage ? join(this.config.storage, 'index-room.json') : null
  }

  async _loadIndexRoom () {
    const path = this._indexRoomPath()
    if (!path) return
    try {
      const data = JSON.parse(await readFile(path, 'utf8'))
      if (typeof data.room === 'string' && Z32_KEY_RE.test(data.room)) {
        this.indexRoom = data.room
      }
    } catch {
      // Missing/corrupt -> keep whatever the constructor set from config (or null).
    }
  }

  /**
   * Set + persist this relay's advertised index-room pointer. The value is the
   * z32 room link of the schema-sheets index hosted by the index sidecar; it is
   * surfaced in the capability doc + /catalog.json so clients can blind-replicate
   * the richer signed index. Called by the sidecar (loopback) once its room is
   * ready. Atomic tmp+rename. Idempotent on an unchanged value.
   */
  async setIndexRoom (z32) {
    if (typeof z32 !== 'string' || !Z32_KEY_RE.test(z32)) {
      throw new Error('indexRoom must be a 52-char z32 key')
    }
    if (this.indexRoom === z32) return this.indexRoom
    this.indexRoom = z32
    const path = this._indexRoomPath()
    if (path) {
      const tmp = path + '.tmp'
      try {
        await mkdir(dirname(path), { recursive: true })
        await writeFile(tmp, JSON.stringify({ room: this.indexRoom, updatedAt: Date.now() }))
        await rename(tmp, path)
      } catch (err) {
        try { await unlink(tmp) } catch (_) {}
        this.emit('index-room-persist-error', err)
      }
    }
    this.emit('index-room', { room: this.indexRoom })
    // A newly-published index room should propagate to the DHT record promptly
    // so key-only clients resolve it without waiting for the next republish.
    this.publishRelayRecord()
    return this.indexRoom
  }

  /**
   * Publish this relay's self-description (gatewayUrl + indexRoom) as a hyperdht
   * MUTABLE record keyed by the relay's identity key, so a client that knows
   * only the relay's pubkey can resolve its current address + index room over
   * the DHT (hyperdht verifies the signature on get). Phase 1 of the iroh
   * adoption — see docs/IROH-ADOPTION-ROADMAP.md. Best-effort: failures log and
   * retry on the next republish tick; never throws into the caller.
   */
  async publishRelayRecord () {
    const dht = this.swarm && this.swarm.dht
    if (!dht || typeof dht.mutablePut !== 'function' || !this.keyPair) return false
    const record = { gatewayUrl: this.config.gatewayUrl || null, indexRoom: this.indexRoom || null }
    if (!relayRecordHasContent(record)) return false // nothing to advertise yet
    // Monotonic seq is REQUIRED: hyperdht rejects a *changed* value at an equal
    // or lower seq (SEQ_REUSED / SEQ_TOO_LOW), so the default seq=0 would pin us
    // to the first value forever — the gateway-only boot record could never gain
    // its indexRoom, and the 30-min republish could never correct a changed
    // value. Seed from the wall clock (so a fresh process after restart is still
    // ahead of the last published seq) and bump per publish (so two republishes
    // in the same second still differ).
    if (this._recordSeq === undefined) this._recordSeq = Math.floor(Date.now() / 1000)
    const seq = this._recordSeq++
    try {
      await dht.mutablePut(this.keyPair, encodeRelayRecord(record), { seq })
      return true
    } catch (err) {
      this.emit('relay-record-error', err)
      return false
    }
  }

  start () {
    if (this._startCompletion) return this._startCompletion
    // A completed start remains the exact authority for an already-running
    // node. Returning it keeps Node and Bare semantics identical and avoids
    // manufacturing a fresh wrapper promise for every caller.
    if (!this._stopping && this.running) {
      if (!this._lastStartCompletion) this._lastStartCompletion = Promise.resolve(this)
      return this._lastStartCompletion
    }

    this._starting = true
    const operation = this._startLifecycle()
    this._startCompletion = operation
    operation.then(
      value => {
        if (this._startCompletion !== operation) return
        this._startCompletion = null
        this._starting = false
        if (value === this && this.running) this._lastStartCompletion = operation
      },
      () => {
        if (this._startCompletion !== operation) return
        this._startCompletion = null
        this._starting = false
      }
    )
    return operation
  }

  async _startLifecycle () {
    if (this._stopping) await this._stopping
    if (this.running) return this
    if (this._startupRollbackPending) {
      const err = new Error('startup rollback is still pending storage mutation settlement')
      err.code = 'STORAGE_STARTUP_ROLLBACK_PENDING'
      throw err
    }
    this._stopRequested = false
    this._storageIngressReady = false

    assertHiveAppGatewayIsolation({
      hiveAppHostSuffix: this.config.hiveAppHostSuffix,
      hiveAppPublicKeys: this.config.hiveAppPublicKeys,
      hiveAppPublicVersions: this.config.hiveAppPublicVersions,
      gatewayPort: this.config.gatewayPort,
      gatewayHost: this.config.gatewayHost,
      gatewayCompatibilityHosts: this.config.gatewayCompatibilityHosts,
      gatewayTrustedProxyAddresses: this.config.gatewayTrustedProxyAddresses,
      gatewayTrustProxy: this.config.gatewayTrustProxy,
      gatewayRequireForwardedSNI: this.config.gatewayRequireForwardedSNI,
      gatewayMaxResponseBytes: this.config.gatewayMaxResponseBytes,
      gatewayMaxTransformBytes: this.config.gatewayMaxTransformBytes,
      gatewayEgressBytesPerWindow: this.config.gatewayEgressBytesPerWindow,
      gatewayEgressWindowMs: this.config.gatewayEgressWindowMs,
      gatewayMaxResponseLifetimeMs: this.config.gatewayMaxResponseLifetimeMs,
      apiPort: this.config.apiPort,
      apiHost: this.config.apiHost,
      enableAPI: this.config.enableAPI,
      enableSeeding: this.config.enableSeeding,
      enableRelay: this.config.enableRelay,
      enableServices: this.config.enableServices,
      plugins: this.config.plugins,
      signedDirectory: this.config.signedDirectory,
      federation: this.config.federation,
      lease: this.config.lease,
      payment: this.config.payment,
      subsidy: this.config.subsidy,
      shardStore: this.config.shardStore,
      custody: this.config.custody,
      requirePhysicalEnforcement: this.config.requirePhysicalEnforcement,
      mode: this.mode,
      productProfile: this.config.productProfile
    })

    // Fresh lifecycle scope — every loop / handler that participates in
    // the cancellation contract reads `this._scope` and is automatically
    // aborted + drained by stop(). Recreated here so a stop()/start()
    // cycle (e.g. self-heal restart) gets a clean signal.
    this._scope = new LifecycleScope()

    try {
      // Bind every runtime (including direct embedders) to the exact storage
      // filesystem before any seeder/API can accept new state. A missing custom
      // path remains unresolved; Corestore may still open for recovery, but the
      // admission authority stays closed until a later correctly-mounted boot.
      // Only the built-in relative default is safe to create automatically.
      // Operator-designated paths must already exist so a missing mount cannot
      // be replaced by a newly-created directory on its ancestor filesystem.
      if (!this._storagePathExplicit) await mkdir(this.config.storage, { recursive: true })
      resolveStorageCap(this.config)
      const storageProof = getStorageCapProvenance(this.config)
      if (!storageProof || storageProof.status !== 'resolved') {
        const err = new Error('configured storage filesystem is unresolved: ' + (storageProof?.reason || 'unknown'))
        err.code = 'STORAGE_FILESYSTEM_UNRESOLVED'
        throw err
      }
      this.storageAdmission.setConfig(this.config)
      this.storageAdmission.beginRecovery(['drives', 'cores'])
      this.storageAdmission.refreshFilesystem()
      await this.storageAdmission.activatePhysicalEnforcement({ purpose: 'relay-startup' })

      // Re-create store if it was closed (e.g. after self-heal restart)
      if (!this.store || this.store.closed) {
        this.store = openCorestore(this.config.storage)
        // The registry's Hyperbee is backed by the OLD (now-closed) store.
        // Drop it so setStore()/load() below reopen the bee on the fresh
        // store; otherwise reseedFromRegistry reads a closed core, gets
        // SESSION_CLOSED, and silently repopulates nothing.
        this.appRegistry.detachStore()
      }
      await this.store.ready()

      // v0.8.25: attach the (now-ready) corestore to AppRegistry so its
      // persistence layer uses a Hyperbee sibling-core instead of the
      // JSON-blob file. Must be called BEFORE the first registry load
      // (which happens in _reseedFromRegistry). Safe on self-heal
      // restart: setStore is idempotent on the same store, and after a
      // store re-create we detached above so this re-attaches cleanly.
      try {
        this.appRegistry.setStore(this.store)
      } catch (_) {
        // Already attached + bee already opened (same-store restart path
        // can fall through here). Harmless.
      }

      // Restore the advertised catalog-bee pointer (persisted across restart;
      // the bee's core itself is re-seeded by the Seeder). config value, if
      // valid, was set in the constructor and is the fallback.
      await this._loadCatalogBeeKey()
      await this._loadIndexRoom()

      // Honest outbound (served) byte counting. Attached to the corestore
      // here — before the swarm exists, so no served block can slip past —
      // it sums uploads across EVERY core (registry log + every drive's
      // meta/blob cores), unlike seeder.totalBytesServed which only sees
      // Seeder.seedCore-routed cores and reads ~0 on registry-drive relays.
      // Re-created per start(); a self-heal restart recreates the store
      // above, so stop the old tracker first to drop its stale listener.
      if (this.servedAccounting) this.servedAccounting.stop()
      this.servedAccounting = new ServedAccounting({ store: this.store })
      this.servedAccounting.start()

      await this.bootstrapCache.load()
      const bootstrap = this.bootstrapCache.merge(this.config.bootstrapNodes)

      const keyPair = await this._loadOrCreateKeyPair()
      this.keyPair = keyPair
      this.publicKey = keyPair.publicKey

      // Build the connection-layer firewall. Composes allowlist, blocklist,
      // per-IP rate-limit, and (optional) reputation threshold. Hyperswarm
      // calls this BEFORE the noise handshake completes — rejected
      // connections cost nothing but a few CPU cycles.
      this.swarmFirewall = new SwarmFirewall({
        allowlist: this.config.swarmAllowlist || [],
        blocklist: this.config.swarmBlocklist || [],
        ipMaxConnects: this.config.swarmIpMaxConnects ?? 100,
        ipWindowMs: this.config.swarmIpWindowMs ?? 60_000,
        minReputation: this.config.swarmMinReputation ?? -1000,
        getReputationScore: (pubkeyHex) => {
          if (!this.reputation) return null
          const r = this.reputation.getRecord(pubkeyHex)
          return r ? r.score : null
        },
        onReject: ({ reason, pubkey, ip, score }) => {
          this.emit('swarm-firewall-reject', { reason, pubkey, ip, score })
        }
      })

      this.swarm = new Hyperswarm({
        bootstrap,
        keyPair,
        maxConnections: this.config.maxConnections,
        firewall: (remotePubKey, payload) => this.swarmFirewall.check(remotePubKey, payload)
      })

      await this._syncAccessControl()

      this.bootstrapCache.start(this.swarm)
      // Announce on the global discovery topic. (Region-sharded topics are
      // available via regionTopic(code) but not auto-joined at current scale —
      // splitting <10 relays across regions reduces discovery, not load.
      // Will revisit when N grows.)
      //
      // Epoch-rotated discovery (opt-in via config.privacy.rotateDiscoveryTopic):
      //   - 'additive' keeps the static topic (full back-compat) AND announces
      //     on the rotating epoch topics for privacy-aware peers.
      //   - 'strict' drops the static topic for maximum unlinkability.
      // Default (off) leaves behaviour identical to before.
      const rotateMode = this.config.privacy && this.config.privacy.rotateDiscoveryTopic
      if (rotateMode !== 'strict') {
        this._relayDiscoveryHandle = this.swarm.join(RELAY_DISCOVERY_TOPIC, { server: true, client: false })
      }
      if (rotateMode === 'additive' || rotateMode === 'strict') {
        this._joinEpochDiscoveryTopics()
        // Re-join current+next every half-epoch so the node is always announced
        // on the bucket clients are looking up, across the rollover boundary.
        this._epochDiscoveryTimer = setInterval(
          () => { try { this._joinEpochDiscoveryTopics() } catch (_) {} },
          Math.max(60_000, Math.floor(DISCOVERY_EPOCH_MS / 2))
        )
        if (this._epochDiscoveryTimer.unref) this._epochDiscoveryTimer.unref()
      }

      // Foundation relays (operator-of-last-resort) opt-in by setting
      // config.foundation = true — gives quorum-pinned clients a stable
      // floor to discover without scanning the full DHT.
      if (this.config.foundation === true) {
        this._foundationDiscoveryHandle = this.swarm.join(FOUNDATION_TOPIC, { server: true, client: false })
      }

      // Initialize subsystems in parallel where possible
      const startups = []

      const seederOpts = {
        maxStorageBytes: this.config.maxStorageBytes,
        announceInterval: this.config.announceInterval,
        storageAdmission: this.storageAdmission,
        // Persist bare-core pins (catalog bees + any /seed-core) so they
        // survive a restart. Null storage (tests) -> persistence is a no-op.
        storagePath: this.config.storage ? join(this.config.storage, 'seeded-cores.json') : null
      }

      if (this.config.enableSeeding) {
        this.seeder = new Seeder(this.store, this.swarm, seederOpts)
        const seederStartup = this.seeder.start()
        // Construction continues through several awaited setup steps before
        // Promise.all(startups). Attach a handler immediately so a concurrent
        // stop cannot turn an authority cancellation into an unhandled gap.
        seederStartup.catch(() => {})
        startups.push(seederStartup)

        if (this.config.enableDistributedDriveBridge !== false) {
          this.distributedDriveBridge = new DistributedDriveBridge({ enabled: true })
          this.distributedDriveBridge.on('warning', (details) => this.emit('distributed-drive-warning', details))
          startups.push(this.distributedDriveBridge.start())
        }
      } else {
        // Disabling serving does not erase durable bare-core promises. Recover
        // their bounds (or legacy unknown debt) into the shared authority and
        // seal the inventory without opening cores, joining topics, attaching
        // listeners, or starting download/announcement work.
        const inventoryRecovery = new Seeder(this.store, this.swarm, seederOpts)
        startups.push(inventoryRecovery.recoverInventoryOnly())
      }

      if (this.config.enableRelay) {
        this.relay = new Relay(this.swarm, {
          maxBandwidthMbps: this.config.maxRelayBandwidthMbps,
          maxConnections: this.config.maxConnections,
          maxCircuitDuration: this.config.maxCircuitDuration,
          maxCircuitBytes: this.config.maxCircuitBytes,
          maxCircuitsPerPeer: this.config.maxCircuitsPerPeer,
          maxCircuitRateBytesPerSecond: this.config.maxCircuitRateBytesPerSecond
        })
        startups.push(this.relay.start())
      }

      // Initialize protocol handlers for seed requests and circuit relay
      this._seedProtocol = new SeedProtocol(this.swarm, {
        keyPair: this.swarm.keyPair
      })
      this._seedProtocol.on('seed-request', (msg, channel) => {
        this._trackFireAndForget(this._onSeedRequest(msg, channel))
      })
      this._seedProtocol.on('unseed-request', (msg) => this._onUnseedRequest(msg))

      if (this.relay) {
        this._circuitRelay = new CircuitRelay(this.swarm, this.relay, {
          reservationTTL: this.config.reservationTTL,
          maxCircuitDuration: this.config.maxCircuitDuration,
          maxCircuitBytes: this.config.maxCircuitBytes,
          maxCircuitsPerPeer: this.config.maxCircuitsPerPeer,
          maxCircuitRateBytesPerSecond: this.config.maxCircuitRateBytesPerSecond
        })
      }

      // Forward relay (opt-in): demand-dialled relay TRANSPORT for apps behind
      // NAT / UDP-blocking, and the building block for onion routing. OFF
      // unless explicitly enabled by the operator (config.forwardRelay.enabled),
      // since it lets peers reach other DHT peers through this node (bounded by
      // per-peer + byte caps + the SwarmFirewall; never an internet proxy).
      if (this.config.forwardRelay && this.config.forwardRelay.enabled) {
        // Optional operator allowlist: if config.forwardRelay.allowTargets
        // is a non-empty array of hex pubkeys, the relay will only dial
        // those targets. Left unset, forward acts as a general transport
        // (any DHT peer) but is bounded by the per-peer concurrency + dial
        // rate caps below. Previously allowTarget was never wired, so an
        // enabled forward-relay would dial ANY 32-byte pubkey on demand.
        const allowList = Array.isArray(this.config.forwardRelay.allowTargets) && this.config.forwardRelay.allowTargets.length
          ? new Set(this.config.forwardRelay.allowTargets.map(k => String(k).toLowerCase()))
          : null
        this._forwardRelay = new ForwardRelay(this.swarm, {
          maxForwardsPerPeer: this.config.forwardRelay.maxForwardsPerPeer,
          maxForwardBytes: this.config.forwardRelay.maxForwardBytes,
          maxDialsPerMinPerPeer: this.config.forwardRelay.maxDialsPerMinPerPeer,
          allowTarget: allowList ? (targetHex) => allowList.has(String(targetHex).toLowerCase()) : null
        })
      }

      // Signed directory (opt-in): relay-hosted openly-writable registry
      // of signed records keyed by author pubkey. First consumer:
      // marketplace offer discovery (sellers publish a signed Offer;
      // buyers list + verify). Generic shape for any "signed record set
      // by author" use case. OFF by default — operators opt in via
      // config.signedDirectory.enabled. Trust model identical to the
      // topic-swarm (relay can omit/reorder; cannot forge). See issue
      // #33 + PRODUCTION.md "SignedDirectory" section.
      if (this.config.signedDirectory && this.config.signedDirectory.enabled) {
        this._signedDirectory = new SignedDirectory(this.swarm, {
          maxEntryBytes: this.config.signedDirectory.maxEntryBytes,
          ttlSeconds: this.config.signedDirectory.ttlSeconds,
          maxEntriesPerAuthor: this.config.signedDirectory.maxEntriesPerAuthor,
          publishRatePerMinute: this.config.signedDirectory.publishRatePerMinute,
          maxTotalEntries: this.config.signedDirectory.maxTotalEntries,
          clockSkewToleranceSeconds: this.config.signedDirectory.clockSkewToleranceSeconds
        })
      }

      // Initialize proof-of-relay challenge system
      this._proofOfRelay = new ProofOfRelay({
        maxLatencyMs: this.config.proofMaxLatencyMs || 5000,
        challengeInterval: this.config.proofChallengeInterval || 300000,
        maxPendingChallenges: this.config.proofMaxPendingChallenges || 2048,
        maxBatchSize: this.config.proofMaxBatchSize || 64
      })

      // Anchor proof channel — lets peers request our signed anchor proofs
      // over the existing Hyperswarm connection (no HTTPS dependency).
      // AutoHeal uses this to count peers as live replicas.
      this._anchorProtocol = new AnchorProtocol({
        proofProvider: async (appKey) => {
          try {
            const proof = await this.createAnchorProof(appKey)
            return { ok: true, proof }
          } catch (err) {
            return { ok: false, error: err.message || 'proof-error' }
          }
        }
      })

      // Feed proof results into reputation scoring
      this._proofOfRelay.on('proof-result', (result) => {
        this.reputation.recordChallenge(result.relayPubkey, result.passed, result.latencyMs)
      })

      // Load persisted reputation data
      const reputationPath = join(this.config.storage, 'reputation.json')
      try {
        this.reputation = await ReputationSystem.load(reputationPath)
      } catch (_) {
        this.reputation = new ReputationSystem()
      }

      // Daily reputation decay (run hourly, decay is multiplicative)
      this._reputationDecayInterval = setInterval(() => {
        this.reputation.applyDecay()
      }, 60 * 60 * 1000)
      if (this._reputationDecayInterval.unref) this._reputationDecayInterval.unref()

      // Periodic reputation save every 5 minutes
      this._reputationSaveInterval = setInterval(() => {
        this.reputation.save(reputationPath).catch(() => {})
      }, 5 * 60 * 1000)
      if (this._reputationSaveInterval.unref) this._reputationSaveInterval.unref()

      // Initialize bandwidth receipt tracking
      this._bandwidthReceipt = new BandwidthReceipt(this.swarm.keyPair, {
        maxReceipts: 10000,
        aggregateThresholdBytes: this.config.aggregateThresholdBytes || 10 * 1024 * 1024,
        aggregateWindowMs: this.config.aggregateWindowMs || 10000
      })

      // When a circuit closes, record the bandwidth in reputation
      if (this.relay) {
        this.relay.on('circuit-closed', ({ circuitId, bytesRelayed, durationMs }) => {
          if (bytesRelayed > 0 && this.reputation) {
            this.reputation.recordBandwidth(
              b4a.toString(this.swarm.keyPair.publicKey, 'hex'),
              bytesRelayed
            )
          }
        })
      }

      if (this.config.enableMetrics) {
        this.metrics = new Metrics(this)
      }

      if (this.config.enableAPI) {
        this.api = new RelayAPI(this, {
          apiPort: this.config.apiPort,
          apiHost: this.config.apiHost,
          corsOrigins: this.config.corsOrigins,
          apiKey: this.config.apiKey,
          // Operator credential for the OutboxLog takedown admin surface. When
          // unset here (and no HIVERELAY_OUTBOXLOG_ADMIN_KEY env), the admin
          // routes stay 404 (safe-by-default) — takedown is opt-in per operator.
          outboxLogAdminKey: this.config.outboxlog?.adminKey || null,
          trustProxy: this.config.trustProxy || false,
          uiExposeToken: this.config.ui?.exposeToken || false,
          uiSimple: this.config.ui?.simple || false
        })
        // Optional separate gateway server for data-plane traffic.
        // When gatewayPort is set AND different from apiPort, spin up a
        // dedicated HTTP server that only serves /v1/hyper/* and /catalog.json.
        // This prevents heavy file traffic from starving the management API.
        const gatewayPort = this.config.gatewayPort
        if (gatewayPort && gatewayPort !== (this.config.apiPort || 9100)) {
          const gatewayOptions = {
            gatewayPort,
            gatewayHost: this.config.gatewayHost || '127.0.0.1',
            corsOrigins: this.config.corsOrigins,
            trustProxy: this.config.gatewayTrustProxy === true,
            trustedProxyAddresses: this.config.gatewayTrustedProxyAddresses,
            requireForwardedSNI: this.config.gatewayRequireForwardedSNI === true,
            compatibilityHosts: this.config.gatewayCompatibilityHosts,
            maxInFlight: this.config.gatewayMaxInFlight,
            maxInFlightPerApp: this.config.gatewayMaxInFlightPerApp,
            hiveAppHostSuffix: this.config.hiveAppHostSuffix || null,
            hiveAppPublicKeys: this.config.hiveAppPublicKeys,
            hiveAppPublicVersions: this.config.hiveAppPublicVersions
          }
          // Production exact-host serving constructs its own trusted handler;
          // compatibility profiles may keep sharing RelayAPI's gateway state.
          if (this.config.productProfile !== 'public-t1-gateway') gatewayOptions.gateway = this.api._gateway
          this.gatewayServer = new GatewayServer(this, gatewayOptions)
          startups.push(this.gatewayServer.start())
        }
      }

      // Flush DHT + start subsystems concurrently. The flush is bounded so
      // local API/dashboard startup is not blocked for seconds by a slow DHT
      // bootstrap; the joined swarm continues discovering peers afterwards.
      startups.push(this._flushDhtForStartup())
      await Promise.all(startups)

      // Complete both durable storage inventories before any plugin/service
      // can create writable cores. Core recovery sealed in Seeder.start(); the
      // drive registry seals here. Slow drive replication remains deferred.
      let reseedEntries = []
      try {
        reseedEntries = await this.appLifecycle.loadRegistry()
      } catch (err) {
        if (!isAbortError(err)) this._emitSafely('reseed-error', { error: err })
        throw err
      }
      if (!this.storageAdmission.recoveryReady) {
        const err = new Error('storage recovery inventories did not seal before writable services')
        err.code = 'STORAGE_RECOVERY_INVENTORY_INCOMPLETE'
        throw err
      }
      if (this.storageAdmission.fatalReason) {
        const err = new Error('storage recovery authority is fail-closed: ' + this.storageAdmission.fatalReason)
        err.code = 'STORAGE_RECOVERY_AUTHORITY_FAILED'
        throw err
      }

      // No externally reachable storage-producing ingress exists before both
      // inventories seal. Attach the connection dispatcher and HTTP listeners
      // only after the shared authority is fully recovered.
      this._storageIngressReady = true
      this.swarm.on('connection', (conn, info) => this._onConnection(conn, info))
      const ingressStartups = []
      if (this.api) ingressStartups.push(this.api.start())
      if (this.gatewayServer) ingressStartups.push(this.gatewayServer.start())
      await Promise.all(ingressStartups)

      if (this.config.transports && this.config.transports.websocket) {
        this.wsTransport = new WebSocketTransport({
          port: this.config.wsPort || 8765,
          maxConnections: this.config.maxConnections
        })
        this.wsTransport.on('connection', (stream, info) => this._onConnection(stream, info))
        await this.wsTransport.start()
      }

      // DHT-relay WebSocket — lets browsers tunnel HyperDHT lookups through us.
      // Distinct from `wsTransport` above (which carries Hypercore replication).
      // Disabled by default — operator opts in via config.transports.dhtRelayWs.
      if (this.config.transports && this.config.transports.dhtRelayWs) {
        const dhtRelayWsCfg = this.config.dhtRelayWs || {}
        this.dhtRelayWs = new DHTRelayWS({
          dht: this.swarm.dht,
          port: this.config.dhtRelayWsPort || 8766,
          // Behind a TLS reverse proxy (the supported deploy), bind loopback
          // so the plaintext ws:// port is never publicly reachable; Caddy
          // owns public 443. Falls back to the transport default (0.0.0.0)
          // only when no host + no proxy is configured (bare/dev).
          host: this.config.dhtRelayWsHost || (dhtRelayWsCfg.trustProxy ? '127.0.0.1' : undefined),
          // Distinct from the Hyperswarm P2P maxConnections: the pipe's fd
          // ceiling should be sized against ulimit -n + per-conn buffers,
          // not tied to the swarm peer cap. Falls back to it if unset.
          maxConnections: dhtRelayWsCfg.maxConnections || this.config.maxConnections,
          trustProxy: dhtRelayWsCfg.trustProxy || false,
          // Pure-pipe prod bounds — all content-neutral (lengths/timings
          // only). Operators tune via config.dhtRelayWs.{rateLimit,
          // keepalive,flow}; defaults are safe for an unattended 24/7 pipe.
          rateLimit: dhtRelayWsCfg.rateLimit || undefined,
          keepalive: dhtRelayWsCfg.keepalive || undefined,
          flow: dhtRelayWsCfg.flow || undefined
        })
        this.dhtRelayWs.on('relay-error', (info) => this.emit('dht-relay-error', info))
        await this.dhtRelayWs.start()
      }

      if (this.config.transports && this.config.transports.tor) {
        const torOpts = this.config.tor || {}
        // Peer protocol plane (docs/TOR-ONION-TRANSPORT.md §2): loopback
        // Noise/Protomux endpoint the onion peer vport forwards to. On by
        // default with the transport; opt out via tor.peer.enabled = false.
        const torPeerCfg = torOpts.peer || {}
        const peerListener = torPeerCfg.enabled === false
          ? null
          : new OnionPeerListener({
            keyPair: this.swarm.keyPair,
            host: torPeerCfg.host,
            port: torPeerCfg.port,
            maxConnections: this.config.maxConnections
          })
        this.torTransport = new TorTransport({
          socksHost: torOpts.socksHost,
          socksPort: torOpts.socksPort,
          controlHost: torOpts.controlHost,
          controlPort: torOpts.controlPort,
          controlPassword: torOpts.controlPassword,
          cookieAuthFile: torOpts.cookieAuthFile,
          keyFile: torOpts.keyFile,
          minDaemonVersion: torOpts.minDaemonVersion,
          vports: torOpts.vports,
          clientAuthKeys: torOpts.clientAuthKeys,
          rosterFile: torOpts.rosterFile,
          endpointKeyId: torOpts.endpointKeyId,
          maxStreams: torOpts.maxStreams,
          pow: torOpts.pow,
          health: torOpts.health,
          localPort: this.config.apiPort || 9100,
          peerListener,
          peerVport: torPeerCfg.vport
        })

        this.torTransport.on('connection', (stream, info) => this._onConnection(stream, info))
        this.torTransport.on('hidden-service', ({ onionAddress }) => {
          this.emit('tor-ready', { onionAddress })
        })
        await this.torTransport.start()
      }

      if (this.config.transports && this.config.transports.holesail) {
        const holesailOpts = this.config.holesail || {}
        const seedBuf = b4a.alloc(32)
        sodium.crypto_generichash(seedBuf, b4a.concat([
          this.swarm.keyPair.secretKey,
          b4a.from('holesail-api-tunnel')
        ]))
        this.holesailTransport = new HolesailTransport({
          apiPort: this.config.apiPort || 9100,
          seed: b4a.toString(seedBuf, 'hex'),
          host: holesailOpts.host || '127.0.0.1'
        })
        this.holesailTransport.on('started', ({ connectionKey }) => {
          this.emit('holesail-ready', { connectionKey })
          if (this.networkDiscovery) {
            this.networkDiscovery.setLocalHolesailKey(connectionKey)
          }
        })
        await this.holesailTransport.start()
      }

      if (this.distributedDriveBridge && !this.distributedDriveBridge.running) {
        this.emit('distributed-drive-warning', {
          code: 'DISTRIBUTED_DRIVE_BRIDGE_DISABLED',
          message: 'distributed-drive bridge is configured but not active'
        })
      }

      if (this.config.payment && this.config.payment.enabled && this.config.paymentManager) {
        this.paymentManager = this.config.paymentManager
        const interval = this.config.payment.settlementInterval || 24 * 60 * 60 * 1000
        this.settlementInterval = setInterval(() => {
          this._runSettlements().catch((err) => {
            this.emit('settlement-error', { error: err })
          })
        }, interval)
      } else if (this.config.payment && this.config.payment.enabled) {
        this.emit('payment-warning', {
          enabled: true,
          active: false,
          reason: 'payment.enabled is true but no paymentManager was provided',
          experimental: true
        })
      }

      // ─── Services Layer ─────────────────────────────────────────────
      // Core ships only the framework (registry + protocol). Concrete services
      // live in p2p-hiveservices and are loaded at runtime via PluginLoader
      // when the operator opts in via config.plugins.
      //
      // Default: Core-only (no services). To enable Services, install
      // p2p-hiveservices and set config.plugins, e.g.:
      //   plugins: ['storage', 'identity', 'ai', 'zk', 'sla', 'schema', 'arbitration']
      // Operator opt-in persists in <storage>/services.json (set via the
      // Services tab; applied on this restart). Overrides config when present.
      await this._loadServicesOverride()
      if (this.config.enableServices !== false && this.config.plugins) {
        this.serviceRegistry = new ServiceRegistry()
        this.serviceProtocol = new ServiceProtocol(this.serviceRegistry, {
          defaultPeerRole: this.config.serviceDefaultPeerRole || 'anonymous'
        })
        this.pluginLoader = new PluginLoader()

        const providers = await this.pluginLoader.load(this.config.plugins, {
          constructorOpts: {
            policyGuard: this.policyGuard || null,
            getAppTier: (keyHex) => this.seededApps.get(keyHex)?.privacyTier || null,
            ai: this.config.ai || {}
          }
        })
        for (const provider of providers) {
          this.serviceRegistry.register(provider)
        }

        // Start all services (passes { node: this } as context)
        this._serviceContext = this._buildServiceContext()
        const startupResult = await this.serviceRegistry.startAll(this._serviceContext)
        if (startupResult.failed.length > 0 && this.config.servicesFailOpen !== true) {
          const names = startupResult.failed.map(s => s.name).join(', ')
          throw new Error(`SERVICE_START_FAILED: ${names}`)
        }
        this._startServiceSupervision()

        // Compose notify Mode-2 with the co-resident outboxlog: a
        // 'notify-feed-head' watch observes the outbox's signed head row via
        // the engine's own subscribe() — one event path, no parallel
        // observer machinery. Without outboxlog enabled, notify keeps
        // rejecting that source kind (SOURCE_UNAVAILABLE) instead of
        // accepting watches that can never fire. (#142/#145)
        const notifyEntry = this.serviceRegistry.services.get('notify')
        const outboxEntry = this.serviceRegistry.services.get('outboxlog')
        if (notifyEntry && outboxEntry && typeof notifyEntry.provider.attachWatchSource === 'function') {
          const outboxApp = outboxEntry.provider
          notifyEntry.provider.attachWatchSource('notify-feed-head', (source, onChange) => {
            return outboxApp.subscribe(source.key, {}, (event) => {
              if (event && event.key === 'head!' + source.key && !event.replay) onChange(event)
            })
          })
        }

        // Set up seeded apps callback for catalog broadcast
        this.serviceProtocol._getSeededApps = () => this.appRegistry.catalogForBroadcast()
        this.serviceProtocol._getCatalogEnvelope = (opts = {}) => {
          const apps = Array.isArray(opts.apps)
            ? opts.apps
            : this.appRegistry.catalogForBroadcast()
          const relayPubkey = this.swarm
            ? b4a.toString(this.swarm.keyPair.publicKey, 'hex')
            : null
          const catalogTimestamp = Date.now()
          if (!relayPubkey) {
            return { apps, relayPubkey: null, catalogTimestamp, signature: null }
          }
          const payload = b4a.from(JSON.stringify({ apps, relayPubkey, catalogTimestamp }))
          const signature = b4a.alloc(sodium.crypto_sign_BYTES)
          sodium.crypto_sign_detached(signature, payload, this.swarm.keyPair.secretKey)
          return {
            apps,
            relayPubkey,
            catalogTimestamp,
            signature: b4a.toString(signature, 'hex')
          }
        }

        this.emit('services-started', { count: this.serviceRegistry.services.size })

        // ─── Application-Layer Router ─────────────────────────────────
        if (this.config.enableRouter !== false) {
          this.router = new Router()
          this.router.registerFromRegistry(this.serviceRegistry)
          await this.router.start()

          // Wire router into service protocol for P2P dispatch
          this.serviceProtocol.router = this.router

          // Bridge relay events to pub/sub
          for (const evt of ['connection', 'connection-closed', 'seeding', 'unseeded', 'circuit-closed', 'seed-accepted']) {
            this.on(evt, (data) => this.router?.pubsub?.publish(`events/${evt}`, data))
          }

          // Broadcast app catalog to clients when apps change (debounced)
          this.on('seeding', () => this._scheduleCatalogBroadcast())
          this.on('unseeded', () => this._scheduleCatalogBroadcast())

          // Handle incoming app catalogs from other relays.
          //
          // Auto-syncing every catalog event made operators answer for content
          // they never approved. The new model: only auto-seed apps whose
          // *source relay* is on the operator's mirror list. For every other
          // peer, the catalog is funneled through the local accept-mode
          // (Review queues; Allowlist filters; Open auto-accepts; Closed drops).
          this.serviceProtocol.on('app-catalog', ({
            apps,
            remotePubkey,
            relayPubkey,
            catalogTimestamp,
            signature
          }) => {
            if (!this.config.enableSeeding || !apps || !Array.isArray(apps)) return
            const peerKey = remotePubkey || null

            if (!this._verifyCatalogEnvelope({
              apps,
              remotePubkey,
              relayPubkey,
              catalogTimestamp,
              signature
            })) {
              this.emit('catalog-sync-error', {
                source: remotePubkey,
                error: 'invalid or stale catalog signature'
              })
              return
            }

            // Per-peer throttle: max 1 catalog event per peer per 30 seconds
            if (peerKey) {
              const now = Date.now()
              const lastTime = this._catalogPeerThrottle.get(peerKey)
              if (lastTime && (now - lastTime) < 30_000) {
                this.emit('debug', { msg: 'catalog-sync throttled for peer', peerKey })
                return
              }
              this._catalogPeerThrottle.set(peerKey, now)
            }

            const isMirrored = !!this.federation && this.federation.isMirroredPubkey(relayPubkey || peerKey)
            const acceptMode = this._resolveAcceptMode()

            // Follow-anchored mode: when enabled, the relay treats anchored=true
            // entries from peers as if they came from a mirrored peer (auto-seed).
            // This makes the network behave as a converged cache — every drive
            // anchored anywhere gets pulled everywhere. Off by default because
            // it consumes storage from arbitrary peer claims; opt-in via config.
            const followAnchored = this.config.followAnchoredFromPeers === true
            const peerScore = (this.reputation && peerKey)
              ? (this.reputation.getRecord(peerKey)?.score ?? 0)
              : null
            const peerScoreOk = peerScore === null
              ? true
              : peerScore >= (this.config.followAnchoredMinReputation ?? 0)
            const storagePctUsed = (this.config.maxStorageBytes > 0)
              ? (this._storageUsedBytes() / this.config.maxStorageBytes)
              : 0
            const hasHeadroom = storagePctUsed < (this.config.followAnchoredStorageCeiling ?? 0.8)

            // Cap at max 10 new apps acted on per catalog event
            const MAX_NEW_APPS = 10
            let acted = 0
            const now = Date.now()
            for (const app of apps) {
              const appKey = app.appKey || app.driveKey
              if (!appKey) continue

              // Cross-relay self-heal: if the peer says they have this drive
              // anchored AND we have it (but unanchored), kick a targeted
              // repair pass. The peer is right there on the swarm — the pull
              // should succeed quickly.
              if (app.anchored === true && this.appRegistry.has(appKey)) {
                const existing = this.appRegistry.get(appKey)
                if (existing && existing.anchored !== true) {
                  this._scheduleTargetedRepair(appKey)
                }
              }

              if (this.appRegistry.has(appKey)) continue
              const appBound = positiveStorageBound(app.maxStorageBytes ?? app.maxStorage)
              if (appBound === null) {
                this.emit('catalog-sync-rejected', { appKey, source: 'remote-catalog', reason: 'storage-bound-invalid' })
                continue
              }
              if (app.seededAt && this.config.catalogMaxAppAgeMs > 0) {
                if ((now - app.seededAt) > this.config.catalogMaxAppAgeMs) continue
              }
              if (acted >= MAX_NEW_APPS) {
                this.emit('debug', { msg: 'catalog cap reached, skipping remaining apps', total: apps.length, acted })
                break
              }

              // Follow-anchored: peer claims to have blocks, we have storage,
              // peer's reputation is acceptable. Treat as mirror-grade trust
              // for this drive only. The repair loop will validate replication
              // worked; if it doesn't, the drive stays unanchored (and shows
              // up that way in our catalog and capability doc).
              const followThisAnchored = followAnchored && app.anchored === true && peerScoreOk && hasHeadroom

              if (isMirrored || followThisAnchored) {
                // Trusted partner OR auto-followed anchored content.
                acted++
                this._trackFireAndForget(this.seedApp(appKey, {
                  appId: app.id || app.appId || null,
                  name: app.name || null,
                  version: app.version || null,
                  type: app.type || 'app',
                  parentKey: app.parentKey || null,
                  mountPath: app.mountPath || null,
                  privacyTier: app.privacyTier || null,
                  blind: app.blind || false,
                  storageClass: app.storageClass || null,
                  availabilityClass: app.availabilityClass || null,
                  author: app.author || null,
                  description: app.description || '',
                  maxStorage: appBound
                }).then(() => {
                  this.emit('catalog-sync', {
                    appKey,
                    source: isMirrored ? 'mirror' : 'follow-anchored',
                    sourceRelay: relayPubkey
                  })
                }).catch((err) => {
                  if (isAbortError(err)) return
                  this.emit('catalog-sync-error', { appKey, error: err.message })
                }))
                continue
              }

              // Not mirrored — apply accept-mode.
              const synthRequest = {
                appKey,
                publisherPubkey: app.author || app.publisherPubkey || null,
                contentType: app.type || 'app',
                privacyTier: app.privacyTier || 'public',
                blind: app.blind === true,
                storageClass: app.storageClass || null,
                availabilityClass: app.availabilityClass || null,
                maxStorageBytes: appBound
              }
              const decision = this._decideAcceptance(synthRequest, acceptMode)
              if (decision === 'reject') {
                this.emit('catalog-sync-rejected', { appKey, source: 'remote-catalog', mode: acceptMode })
                continue
              }
              if (decision === 'accept') {
                acted++
                this._trackFireAndForget(this.seedApp(appKey, {
                  appId: app.id || app.appId || null,
                  name: app.name || null,
                  version: app.version || null,
                  type: synthRequest.contentType,
                  parentKey: app.parentKey || null,
                  mountPath: app.mountPath || null,
                  privacyTier: synthRequest.privacyTier,
                  blind: synthRequest.blind,
                  storageClass: synthRequest.storageClass,
                  availabilityClass: synthRequest.availabilityClass,
                  author: synthRequest.publisherPubkey,
                  description: app.description || '',
                  maxStorage: appBound
                }).then(() => {
                  this.emit('catalog-sync', { appKey, source: 'remote-catalog', mode: acceptMode })
                }).catch((err) => {
                  if (isAbortError(err)) return
                  this.emit('catalog-sync-error', { appKey, error: err.message })
                }))
                continue
              }
              // 'review' — queue for operator approval.
              const inserted = this._addPendingRequest(appKey, {
                ...synthRequest,
                source: 'remote-catalog',
                sourceRelay: relayPubkey || peerKey,
                discoveredAt: Date.now(),
                mode: acceptMode
              })
              if (inserted) {
                this.emit('registry-pending', { appKey, publisher: synthRequest.publisherPubkey, source: 'remote-catalog' })
              }
            }
          })

          this.emit('router-started', { routes: this.router.routes().length })
        }
      }

      // Periodic cleanup of stale catalog peer throttle entries
      this._catalogThrottleCleanup = setInterval(() => {
        const cutoff = Date.now() - 300_000
        for (const [key, time] of this._catalogPeerThrottle) {
          if (time < cutoff) this._catalogPeerThrottle.delete(key)
        }
      }, 60_000)
      if (this._catalogThrottleCleanup.unref) this._catalogThrottleCleanup.unref()

      this._startHealthChecks()

      // Start seeding registry
      if (this.config.enableSeeding) {
        try {
          // Registry uses its own Corestore namespace to avoid conflicts
          const registryStore = this.store.namespace('seeding-registry')
          this.seedingRegistry = new SeedingRegistry(registryStore, this.swarm, {
            registryKey: this.config.registryKey || null,
            // Pass the node's LifecycleScope so _indexLog can bail on
            // stop() instead of running against a freshly-closed log
            // (vector A3 in STALE-REF-INVENTORY.md).
            scope: this._scope
          })

          // Custody push channel — broadcasts new custody entries to every
          // connected peer over Protomux for real-time fan-out. The
          // registry's append-only log still handles durability + catch-up;
          // this channel is just the fast-path for already-connected peers.
          this._custodyProtocol = new CustodyProtocol({
            applyEntry: async (entry, fromPeer) => {
              return this.seedingRegistry._applyPushedEntry(entry, fromPeer)
            }
          })

          // Publisher submit channel (hiverelay-publish, v1) — lets external
          // publishers submit publisher-signed custody-pipeline entries over
          // Hyperswarm instead of HTTPS. Mirrors the /api/v1/custody/*
          // REST surface, request/response over Protomux. Per Pear manifesto
          // §5, this gets escrow-style apps off the HTTPS dependency.
          //
          // Authorisation is by the publisher signature embedded in the
          // submitted body (same trust model as the REST endpoints); the
          // channel itself adds no auth. Each registry method's pre-signed
          // path (`signature` truthy, second arg null) runs the same
          // verifyCustodyEntry path the HTTP route does — there is no shorter
          // route in, so a malicious caller cannot bypass signature checks
          // by submitting via Protomux instead.
          // Wrap each registry call so transient corestore/hypercore
          // lifecycle errors surface as `{ ok: false, error, retryable: true }`
          // — same convention as the seed handler below + the HTTPS
          // /api/v1/* routes. Without this, exceptions thrown by the
          // registry (e.g. "The corestore is closed", "Mutex has been
          // destroyed") bubble up to PublishProtocol's default catch
          // which converts them to `retryable: false` — making clients
          // give up on what is actually a recoverable relay-state issue.
          const wrapTransient = async (work) => {
            try {
              const entry = await work()
              return { ok: true, result: entry }
            } catch (err) {
              const msg = err && err.message ? err.message : String(err)
              if (isTransientCoreError(err)) {
                return { ok: false, error: msg, retryable: true }
              }
              return { ok: false, error: msg }
            }
          }
          this._publishProtocol = new PublishProtocol({
            onSubmitIntent: (body) => wrapTransient(() => this.seedingRegistry.publishCustodyIntent(body, null)),
            onSubmitCommit: (body) => wrapTransient(() => this.seedingRegistry.publishCustodyCommit(body, null)),
            onSubmitSourceRetired: (body) => wrapTransient(() => this.seedingRegistry.publishSourceRetired(body, null)),
            // Seed handler — runs the publisher-signed body through the
            // same shared builder the HTTPS /api/v1/seed route uses, so
            // both transports speak identical vocabulary. Validation
            // failures surface as { ok: false, error } with no retry
            // hint; transient core errors from seedApp surface with
            // retryable: true so the client can wait + retry the
            // submit (mirrors HTTPS 503 + Retry-After convention).
            onSubmitSeed: async (body) => {
              const built = buildPublisherSignedSeedOpts(body, {
                seedingRegistry: this.seedingRegistry
              })
              if (!built.ok) {
                return { ok: false, error: built.error }
              }
              // Paid pin-lease gate — SAME shared module as the HTTP route, so
              // this publisher-signed transport can't be a free back door.
              const gate = await evaluateSeedLease({
                leaseManager: this.leaseManager,
                seedingRegistry: this.seedingRegistry,
                appKey: built.appKey,
                opts: built.opts,
                body
              })
              if (gate.outcome === 'quote') {
                return { ok: false, error: gate.error, leaseRequired: true, ...(gate.quote || {}) }
              }
              if (gate.outcome === 'error') {
                return { ok: false, error: gate.error, leaseRequired: true }
              }
              if (gate.outcome === 'paid') {
                built.opts.retainUntil = gate.retainUntil
                built.opts.leaseManaged = true
              }
              if (!this._publisherSeedReplayCache) this._publisherSeedReplayCache = new Map()
              const replay = consumePublisherSeedReplayNonce(built.replay, this._publisherSeedReplayCache)
              if (!replay.ok) {
                return { ok: false, error: replay.error }
              }
              try {
                const result = await this.seedApp(built.appKey, built.opts)
                return { ok: true, result }
              } catch (err) {
                const msg = err && err.message ? err.message : String(err)
                if (isTransientCoreError(err)) {
                  return { ok: false, error: msg, retryable: true }
                }
                return { ok: false, error: msg }
              }
            }
          })

          // When the registry appends a new custody entry locally, push it
          // to all connected peers. Fire-and-forget; log replication backs
          // it up if the push doesn't reach.
          this.seedingRegistry.on('custody-entry-appended', ({ entry }) => {
            try {
              const sent = this._custodyProtocol.broadcast(entry)
              if (sent > 0) this.emit('custody-broadcast', { type: entry.type, peers: sent })
            } catch (err) {
              this.emit('custody-broadcast-error', { error: err.message })
            }
          })

          // Bubble custody pipeline events up to the node so the WS dashboard
          // feed can broadcast them to subscribers immediately rather than
          // waiting for the 2s tick. Each event maps to a normalized name on
          // the node (custody-intent / -receipt / -commit / -proof) — the
          // registry's internal names include verbs which dashboards don't
          // care about.
          const eventBubbleMap = {
            'custody-intent-published': 'custody-intent',
            'custody-receipt-recorded': 'custody-receipt',
            'custody-commit-published': 'custody-commit',
            'source-retired-published': 'custody-retired',
            'custody-proof-recorded': 'custody-proof',
            'custody-non-serving-proof-recorded': 'custody-non-serving-proof',
            'custody-expiry-witness-recorded': 'custody-expiry-witness'
          }
          for (const [from, to] of Object.entries(eventBubbleMap)) {
            this.seedingRegistry.on(from, (entry) => this.emit(to, entry))
          }
          await this.seedingRegistry.start()

          // Periodic scan for matching seed requests
          const scanInterval = this.config.registryScanInterval || 60_000 // 1 min default
          this._registryScanInterval = setInterval(() => {
            this._trackFireAndForget(this._scanRegistry().catch((err) => {
              if (isAbortError(err)) return
              this.emit('registry-error', { error: err })
            }))
          }, scanInterval)
          if (this._registryScanInterval.unref) this._registryScanInterval.unref()

          // Run initial scan after a short delay to let the registry sync
          this._setLifecycleTimer('_registryInitialScanTimer', 5000, () => {
            this._trackFireAndForget(this._scanRegistry().catch(() => {}))
          })

          this._startReplicationMonitor()
          this._startAnchorMonitor()
          this._startRepairMonitor()

          // Acceptance reconciliation (v0.15.3): boot-replay reseeds
          // never wrote seed-accept records, so the shared census
          // undercounted true replication — on the 2026-06-11 canary,
          // 547/961 entries had no census and 252 were floor-blocked
          // even though copies existed fleet-wide. Backfill "I hold
          // this" records for every entry we actually hold so eviction
          // and repair reason over real replica counts. Paced; safe to
          // re-run (skips entries already recorded).
          if (this.config.acceptanceReconcile !== false) {
            this._setLifecycleTimer('_acceptanceReconcileTimer', 15_000, () => {
              this._trackFireAndForget(this._reconcileAcceptances().catch(() => {}))
            })
          }

          // Cold-start primer — runs once after a brief delay so the
          // swarm has a chance to come up before we start fetching peer
          // catalogs over HTTPS. Fire-and-forget; failures don't block
          // start.
          if (Array.isArray(this.config.coldStartRelays) && this.config.coldStartRelays.length > 0) {
            this._setLifecycleTimer('_coldStartPrimerTimer', 15_000, () => {
              this._trackFireAndForget(this._runColdStartPrimer().catch((err) => {
                if (isAbortError(err)) return
                this.emit('cold-start-error', { error: err.message || String(err) })
              }))
            })
          }
        } catch (err) {
          this.emit('registry-error', { error: err })
          let teardownError = null
          try {
            await this._destroyProtocolHandlers(this.config.shutdownTimeoutMs || 30_000, [
              '_custodyProtocol',
              '_publishProtocol'
            ])
          } catch (stopErr) {
            teardownError = stopErr
          }
          const registry = this.seedingRegistry
          if (registry) {
            try {
              await registry.stop()
              if (this.seedingRegistry === registry) this.seedingRegistry = null
            } catch (stopErr) {
              if (!teardownError) teardownError = stopErr
            }
          }
          if (teardownError) {
            const failure = new Error('seeding registry startup teardown did not settle')
            failure.code = 'SEEDING_REGISTRY_START_TEARDOWN_FAILED'
            failure.cause = teardownError
            failure.startCause = err
            throw failure
          }
        }
      }

      this._startCustodyExpiryMonitor()

      // Load app registry from disk and reseed all persisted apps.
      // The load/hydrate half is AWAITED here so the registry's Hyperbee
      // is open before start() returns — otherwise an app seeded in the
      // gap before the (formerly fire-and-forget) reseed opened the bee
      // is set in memory but silently never persisted.
      // The drive re-seeding half is tracked fire-and-forget so a stop()
      // that fires while it fans out (each seedApp cascades into
      // eagerReplicate — see vector A1) drains every fan-out before
      // tearing down the corestore.
      this._trackFireAndForget(this.appLifecycle.reseedDrives(reseedEntries).catch((err) => {
        if (isAbortError(err)) return
        this._emitSafely('reseed-error', { error: err })
      }))

      // Start network discovery — shares this node's swarm to discover other
      // relays. The start promise participates in the lifecycle drain so stop
      // cannot race a late topic join, and the explicit false option is
      // honored by test/embedded runtimes that do not want this extra session.
      if (this.config.enableNetworkDiscovery !== false) {
        this.networkDiscovery = new NetworkDiscovery({ swarm: this.swarm })
        this._trackFireAndForget(this.networkDiscovery.start().catch((err) => {
          if (isAbortError(err)) return
          this._emitSafely('network-discovery-error', { error: err })
        }))
      }

      // Periodic revocation-store sweep — evict entries whose certs would
      // have naturally expired. Hour-level cadence is plenty; interval is
      // unref'd so it never blocks shutdown.
      this._revocationSweepInterval = setInterval(() => {
        this._sweepRevocations()
      }, 60 * 60 * 1000)
      if (this._revocationSweepInterval.unref) this._revocationSweepInterval.unref()

      // Hydrate the persisted gateway denylist before federation polls can
      // merge into it — a takedown must survive restart with the same
      // trusted-admin gate applied to replayed entries.
      try { await this.gatewayDenylist.load() } catch (err) { this.emit('gateway-denylist-error', err) }
      this.gatewayDenylist.on('persistence-error', (info) => this.emit('gateway-denylist-error', info))

      // Federation — opt-in cross-relay catalog sharing. Always-on as a manager
      // so /api/manage/federation can mutate it; the polling loop only runs
      // if the operator has actually followed any relays.
      this.federation = new Federation({
        node: this,
        followInterval: this.config.federation?.followInterval,
        followed: this.config.federation?.followed || [],
        mirrored: this.config.federation?.mirrored || [],
        trustedForkObservers: this.config.federation?.trustedForkObservers || [],
        storagePath: join(this.config.storage, 'federation.json')
      })
      // Hydrate persisted follow/mirror state. The bootstrap entries from
      // config above seed an empty file on first run; subsequent runs merge.
      try { await this.federation.load() } catch (err) { this.emit('federation-error', err) }
      if (this.config.federation?.enabled !== false) {
        this.federation.start()
      }
      this.federation.on('federation-error', (err) => this.emit('federation-error', err))
      this.federation.on('persistence-error', (info) => this.emit('federation-error', info))

      // AutoHeal — diversity-enforced replica maintenance for archive-tier
      // drives (durability=1). Off by default; opt in via config.autoHeal:
      //   { enabled: true, thresholds: { minReplicas: 7, minRegions: 4 } }
      // The scheduler reuses federation's peer-catalog data, so it adds no
      // new wire traffic — it just decides differently over the same data.
      if (this.config.autoHeal?.enabled === true) {
        this.autoHeal = new AutoHeal(this, {
          tickMs: this.config.autoHeal.tickMs,
          staleMs: this.config.autoHeal.staleMs,
          thresholds: this.config.autoHeal.thresholds,
          maxRecruitsPerTick: this.config.autoHeal.maxRecruitsPerTick,
          // Cryptographic peer verification — peers count as live replicas
          // only when their /api/anchors/<appKey>/proof endpoint produces a
          // recently-verified Ed25519 signature. Default ON for archive tier.
          verifyProofs: this.config.autoHeal.verifyProofs,
          proofFreshnessMs: this.config.autoHeal.proofFreshnessMs,
          proofGraceMs: this.config.autoHeal.proofGraceMs,
          // Per-tick proof-fetch budget. Bounds O(K·N) traffic on large
          // fleets; deferred peers are picked up on subsequent ticks.
          maxProofsPerTick: this.config.autoHeal.maxProofsPerTick,
          storageMargin: this.config.autoHeal.storageMargin,
          // Protomux anchor channel — preferred over HTTPS for proof
          // requests. Works on pure-swarm and NAT'd fleets where no HTTPS
          // endpoint is reachable. Falls back to HTTPS when the channel
          // isn't open for a given peer.
          anchorChannel: this._anchorProtocol
        })
        this.autoHeal.on('recruited', (info) => this.emit('auto-heal-recruited', info))
        this.autoHeal.on('recruit-error', (info) => this.emit('auto-heal-error', info))
        this.autoHeal.on('tick-error', (info) => this.emit('auto-heal-error', info))
        this.autoHeal.on('proof-failed', (info) => this.emit('auto-heal-proof-failed', info))
        this.autoHeal.on('proof-budget-throttled', (info) => this.emit('auto-heal-throttled', info))
        this.autoHeal.start()
      }

      // ManifestStore — caches author-signed seeding manifests.
      // Relays serve these over HTTP so clients can discover which relays an
      // author uses for seeding. Always-on since authoring is orthogonal to
      // federation / accept-mode.
      this.manifestStore = new ManifestStore({
        storagePath: join(this.config.storage, 'manifests.json'),
        maxAuthors: this.config.maxManifestAuthors || 10_000
      })
      try { await this.manifestStore.load() } catch (err) { this.emit('manifest-store-error', err) }
      this.manifestStore.on('stored', (info) => this.emit('manifest-stored', info))
      this.manifestStore.on('load-rejected', (info) => this.emit('manifest-store-error', info))

      if (this._stopRequested) throw new Error('START_CANCELLED_BY_STOP')
      this.running = true

      // Publish this relay's DHT-resolvable record (gatewayUrl + indexRoom) so
      // key-only clients can discover it, and republish periodically since DHT
      // mutable records expire. Best-effort; never blocks startup.
      this.publishRelayRecord()
      this._relayRecordTimer = setInterval(() => { this.publishRelayRecord() }, 30 * 60 * 1000)
      if (this._relayRecordTimer.unref) this._relayRecordTimer.unref()

      // Start health monitoring and self-healing
      this.healthMonitor = new HealthMonitor(this, this.config.healthMonitor)
      this.selfHeal = new SelfHeal(this, this.config.selfHeal)
      this.selfHeal.start(this.healthMonitor)
      this.healthMonitor.on('health-warning', (details) => this.emit('health-warning', details))
      this.healthMonitor.on('health-critical', (details) => this.emit('health-critical', details))
      this.selfHeal.on('self-heal-action', (action) => this.emit('self-heal-action', action))
      this.healthMonitor.start()

      // v0.8.28 (#27): operator-visible disk-usage signal. Surfaces via
      // /status (always) and optionally gates /health → 503 when over
      // criticalThreshold (config.diskHealthGate, default false to keep
      // existing /health semantics). milkyb-iad's 1 GB Fly volume
      // hitting 100% was the root cause of the v0.8.22 fire-drill;
      // this is the cheap signal that closes that observability gap.
      this.diskMonitor = new DiskMonitor(this.config.storage || '/data', {
        warnThreshold: this.config.diskWarnThreshold,
        criticalThreshold: this.config.diskCriticalThreshold,
        refreshIntervalMs: this.config.diskRefreshIntervalMs
      })
      this.diskMonitor.start()

      // Honest per-drive storage accounting (always on — it is the input
      // for the repair storage guard, the eviction ranking, and the
      // dashboard's Storage panel; the paced sweep keeps IO negligible).
      this.storageAccounting = new StorageAccounting({
        appRegistry: this.appRegistry,
        // Real on-disk corestore path — the authoritative footprint, immune to
        // bare/lazy cores the per-entry drive walk can't see (the miss that let
        // the adoption guard read ~0 and overfill, 2026-06).
        storagePath: this.config.storage,
        tickMs: this.config.storageAccounting?.tickMs,
        batchSize: this.config.storageAccounting?.batchSize,
        diskIntervalMs: this.config.storageAccounting?.diskIntervalMs
      })
      // An 'error' emit with no listener crashes the process — route to
      // a logged event instead (v0.15.6).
      this.storageAccounting.on('error', (err) => this.emit('accounting-error', { error: err && err.message }))
      if (this.seeder) {
        this.storageAccounting.registerExternalSource('seeded-cores', () => this.seeder.totalBytesStored || 0)
      }
      this.storageAccounting.start()

      // Over-replication eviction (Phase A). Off by default — sheds
      // surplus replicas under disk pressure. See eviction.js for the
      // policy contract.
      if (this.config.eviction?.enabled) {
        this._ensureEviction()
      }

      // Operator subsidy accrual (Phase 1, relay side). Off by default;
      // accrues a capped sats ESTIMATE for blind-peer work and exports a
      // signed claim the Phase-2 coordinator verifies + pays. Moves no
      // money. See incentive/subsidy/index.js + OPERATOR-INCENTIVES-Y1.md.
      if (this.config.subsidy?.enabled) {
        this.subsidyAccrual = new SubsidyAccrual({
          keyPair: this.swarm.keyPair,
          statsFn: () => this.getStats({ includeSecrets: false }),
          storagePath: join(this.config.storage, 'subsidy.json'),
          rateSatsPerDay: this.config.subsidy.rateSatsPerDay,
          epochMs: this.config.subsidy.epochMs,
          payoutDestination: this.config.subsidy.payoutDestination || undefined
        })
        await this.subsidyAccrual.start()
      }

      // Paid pin-lease (demand side). Off by default. When enabled, the
      // publisher-signed seed path charges a byte-days lease; funds settle to
      // the operator's OWN LN node (zero-custody) and the lease is enforced by
      // the custody-expiry sweep. Operator self-seeds (POST /seed) are free.
      // See incentive/lease/index.js + the payment-for-seeding design.
      if (this.config.lease?.enabled) {
        let provider = this.config.leaseProvider || null
        if (!provider) {
          // 'mock' (in-memory, for test/demo) is the default; 'lightning'
          // expects the operator to supply a connected provider via
          // config.leaseProvider (the LND gRPC proto is not bundled here).
          provider = new MockProvider()
        }
        // Fail loud if the wired provider can't VERIFY settlement — otherwise
        // every redemption would 503 and no lease could ever be granted.
        if (typeof provider.lookupInvoice !== 'function') {
          throw new Error('lease.enabled requires a payment provider with lookupInvoice() (got ' +
            ((provider.constructor && provider.constructor.name) || 'unknown') +
            '); supply one via config.leaseProvider or set lease.enabled=false')
        }
        const payTo = (this.subsidyAccrual && this.subsidyAccrual.payoutDestination
          ? this.subsidyAccrual.payoutDestination.value
          : null) ||
          (this.config.subsidy && this.config.subsidy.payoutDestination) ||
          this.config.lease.payTo || null
        this.leaseManager = new LeaseManager({
          keyPair: this.swarm.keyPair,
          provider,
          storagePath: join(this.config.storage, 'lease.json'),
          satsPerGiBDay: this.config.lease.satsPerGiBDay,
          quoteTtlMs: this.config.lease.quoteTtlMs,
          minDays: this.config.lease.minLeaseDays,
          maxDays: this.config.lease.maxLeaseDays,
          payTo
        })
        await this.leaseManager.start()
      }

      // Start alert manager (if configured) — wires to health monitor + subsystems
      if (this.config.alerts?.enabled) {
        this.alertManager = new AlertManager(this, this.config.alerts)
      }

      this._emitSafely('started', { publicKey: this.swarm.keyPair.publicKey })

      // Auto-enable holesail if API is not publicly reachable.
      // Tracked so the 15s setTimeout inside doesn't fire post-stop
      // and start a transport on a destroyed swarm (vector B13).
      if (this.config.enableHolesail !== false && !this.holesailTransport && this.config.enableAPI) {
        this._trackFireAndForget(this._autoEnableHolesail().catch(() => {}))
      }
    } catch (err) {
      this._ownerDeadline = Date.now() + (this.config.shutdownTimeoutMs || 30_000)
      this._storageIngressReady = false
      this._stopRequested = true
      this._clearLifecycleTimers()
      // Seal every storage-producing ingress immediately. Services can own
      // append timers independent of LifecycleScope, so quiesce them while
      // their final stop/flush can still use the authority, then seal + drain.
      let writerQuiesceError = null
      const stopRollbackOwner = async (field, method) => {
        const owner = this[field]
        if (!owner) return
        try {
          await this._awaitOwnerOperation(
            owner,
            `${field}.${method}`,
            () => owner[method](),
            this.config.shutdownTimeoutMs || 30_000
          )
          if (this[field] === owner) this[field] = null
        } catch (stopErr) {
          if (!writerQuiesceError) writerQuiesceError = stopErr
        }
      }
      if (this._serviceSupervisionInterval) { clearInterval(this._serviceSupervisionInterval); this._serviceSupervisionInterval = null }
      await stopRollbackOwner('router', 'stop')
      await stopRollbackOwner('serviceProtocol', 'destroy')
      try {
        await this._destroyProtocolHandlers(this.config.shutdownTimeoutMs || 30_000, [
          '_seedProtocol',
          '_circuitRelay',
          '_forwardRelay',
          '_signedDirectory',
          '_proofOfRelay',
          '_anchorProtocol',
          '_custodyProtocol',
          '_publishProtocol'
        ])
      } catch (stopErr) {
        writerQuiesceError = stopErr
      }
      if (this.serviceRegistry) {
        const registry = this.serviceRegistry
        try {
          await this._awaitOwnerOperation(
            registry,
            'serviceRegistry.stopAll',
            () => registry.stopAll({ throwOnError: true }),
            this.config.shutdownTimeoutMs || 30_000
          )
          if (this.serviceRegistry === registry) this.serviceRegistry = null
        } catch (stopErr) {
          writerQuiesceError = stopErr
        }
      }
      this._serviceContext = null

      await stopRollbackOwner('networkDiscovery', 'stop')
      await stopRollbackOwner('federation', 'stop')
      await stopRollbackOwner('autoHeal', 'stop')
      await stopRollbackOwner('subsidyAccrual', 'destroy')
      await stopRollbackOwner('leaseManager', 'destroy')
      await stopRollbackOwner('holesailTransport', 'stop')
      await stopRollbackOwner('torTransport', 'stop')
      await stopRollbackOwner('wsTransport', 'stop')
      await stopRollbackOwner('dhtRelayWs', 'stop')
      await stopRollbackOwner('gatewayServer', 'stop')
      await stopRollbackOwner('api', 'stop')
      await stopRollbackOwner('distributedDriveBridge', 'stop')
      await stopRollbackOwner('relay', 'stop')

      // Rollback in reverse order. Drain both contracts before tearing down
      // the corestore so no delayed ready()/append()/persist can outlive it.
      if (this._scope) {
        const scope = this._scope
        try {
          await this._awaitOwnerOperation(
            scope,
            'lifecycleScope.drain',
            () => scope.drain(),
            this.config.shutdownTimeoutMs || 30_000
          )
          if (this._scope === scope) this._scope = null
        } catch (stopErr) {
          if (!writerQuiesceError) writerQuiesceError = stopErr
        }
      }
      await stopRollbackOwner('seedingRegistry', 'stop')
      if (this.appLifecycle && typeof this.appLifecycle.drainRetiringDrives === 'function') {
        try {
          await this._awaitOwnerOperation(
            this.appLifecycle,
            'appLifecycle.drainRetiringDrives',
            () => this.appLifecycle.drainRetiringDrives(),
            this.config.shutdownTimeoutMs || 30_000
          )
        } catch (stopErr) {
          if (!writerQuiesceError) writerQuiesceError = stopErr
        }
      }
      if (this.seeder) {
        const seeder = this.seeder
        try {
          await this._awaitOwnerOperation(
            seeder,
            'seeder.stop',
            () => seeder.stop(),
            this.config.shutdownTimeoutMs || 30_000
          )
          if (this.seeder === seeder) this.seeder = null
        } catch (stopErr) {
          if (!writerQuiesceError) writerQuiesceError = stopErr
        }
      }
      if (this.appRegistry && this.store && !this.store.closed) {
        try {
          await this._awaitOwnerOperation(
            this.appRegistry,
            'appRegistry.flush',
            () => this.appRegistry.flush({ throwOnError: true }),
            this.config.shutdownTimeoutMs || 30_000
          )
        } catch (flushErr) {
          if (!writerQuiesceError) writerQuiesceError = flushErr
        }
      }
      if (this.storageAdmission) this.storageAdmission.closeMutations('storage-startup-rollback')
      if (this.storageAdmission) {
        try {
          await this.storageAdmission.drainMutations({
            timeoutMs: this._remainingOwnerBudget(this.config.shutdownTimeoutMs || 30_000)
          })
        } catch (rollbackErr) {
          // An unsettled writer may still commit. Do not tear down Corestore;
          // settle lifecycle waiters and surface a terminal rollback failure so
          // the supervisor can escalate/retry after real settlement.
          rollbackErr.cause = err
          this.running = false
          this._startupRollbackPending = true
          throw rollbackErr
        }
      }
      try {
        await this._destroyDiscoveryHandles(this.config.shutdownTimeoutMs || 30_000)
      } catch (discoveryErr) {
        if (!writerQuiesceError) writerQuiesceError = discoveryErr
      }
      if (writerQuiesceError) {
        if (this.storageAdmission) this.storageAdmission.failClosed('storage-writer-quiesce-failed')
        const rollbackErr = new Error('storage writer quiescence did not settle')
        rollbackErr.code = 'STORAGE_WRITER_QUIESCE_FAILED'
        rollbackErr.cause = writerQuiesceError
        rollbackErr.startCause = err
        this.running = false
        this._startupRollbackPending = true
        throw rollbackErr
      }
      this.bootstrapCache.stop()
      if (this._epochDiscoveryTimer) { clearInterval(this._epochDiscoveryTimer); this._epochDiscoveryTimer = null }
      if (this._catalogThrottleCleanup) { clearInterval(this._catalogThrottleCleanup); this._catalogThrottleCleanup = null }
      if (this._reputationSaveInterval) { clearInterval(this._reputationSaveInterval); this._reputationSaveInterval = null }
      if (this._reputationDecayInterval) { clearInterval(this._reputationDecayInterval); this._reputationDecayInterval = null }
      if (this._registryScanInterval) { clearInterval(this._registryScanInterval); this._registryScanInterval = null }
      if (this._replicationCheckInterval) { clearInterval(this._replicationCheckInterval); this._replicationCheckInterval = null }
      if (this._anchorCheckInterval) { clearInterval(this._anchorCheckInterval); this._anchorCheckInterval = null }
      if (this._repairInterval) { clearInterval(this._repairInterval); this._repairInterval = null }
      if (this._custodyExpiryInterval) { clearInterval(this._custodyExpiryInterval); this._custodyExpiryInterval = null }
      if (this.seedingRegistry) { try { await this.seedingRegistry.stop() } catch (_) {} this.seedingRegistry = null }
      if (this.settlementInterval) { clearInterval(this.settlementInterval); this.settlementInterval = null }
      if (this.holesailTransport) { try { await this.holesailTransport.stop() } catch (_) {} this.holesailTransport = null }
      if (this.torTransport) { try { await this.torTransport.stop() } catch (_) {} this.torTransport = null }
      if (this.wsTransport) { try { await this.wsTransport.stop() } catch (_) {} this.wsTransport = null }
      if (this.dhtRelayWs) { try { await this.dhtRelayWs.stop() } catch (_) {} this.dhtRelayWs = null }
      if (this.gatewayServer) { try { await this.gatewayServer.stop() } catch (_) {} this.gatewayServer = null }
      if (this.api) { try { await this.api.stop() } catch (_) {} this.api = null }
      if (this.metrics) { this.metrics.stop(); this.metrics = null }
      if (this.distributedDriveBridge) { try { await this.distributedDriveBridge.stop() } catch (_) {} this.distributedDriveBridge = null }
      if (this.relay) { try { await this.relay.stop() } catch (_) {} this.relay = null }
      if (this.seeder) { await this.seeder.stop(); this.seeder = null }
      if (this.swarm) {
        try {
          const swarm = this.swarm
          await this._awaitOwnerOperation(
            swarm,
            'swarm.destroy',
            () => swarm.destroy(),
            this.config.shutdownTimeoutMs || 30_000
          )
          if (this.swarm === swarm) this.swarm = null
        } catch (swarmErr) {
          if (this.storageAdmission) this.storageAdmission.failClosed('storage-writer-quiesce-failed')
          const rollbackErr = new Error('swarm teardown did not settle')
          rollbackErr.code = 'STORAGE_WRITER_QUIESCE_FAILED'
          rollbackErr.cause = swarmErr
          rollbackErr.startCause = err
          this.running = false
          this._startupRollbackPending = true
          throw rollbackErr
        }
      }
      if (this.swarmFirewall) { try { this.swarmFirewall.destroy() } catch (_) {} this.swarmFirewall = null }
      if (this.accessControl) { try { this.accessControl.disablePairing() } catch (_) {} this.accessControl = null }
      if (this.store && !this.store.closed) {
        const store = this.store
        try {
          await this._awaitOwnerOperation(
            store,
            'store.close',
            () => store.close(),
            this.config.shutdownTimeoutMs || 30_000
          )
        } catch (storeErr) {
          if (this.storageAdmission) this.storageAdmission.failClosed('storage-writer-quiesce-failed')
          const rollbackErr = new Error('corestore teardown did not settle')
          rollbackErr.code = 'STORAGE_WRITER_QUIESCE_FAILED'
          rollbackErr.cause = storeErr
          rollbackErr.startCause = err
          this.running = false
          this._startupRollbackPending = true
          throw rollbackErr
        }
      }
      if (this.appRegistry) {
        try { this.appRegistry.detachStore() } catch (_) {}
      }
      this.running = false
      this._startupRollbackPending = false
      this._ownerDeadline = null
      throw err
    }

    return this
  }

  async _reseedFromRegistry () {
    return this.appLifecycle.reseedFromRegistry()
  }

  /**
   * One-time migration from old seeded-apps.json → unified app-registry.json
   */
  async _migrateOldSeededApps () {
    return this.appLifecycle.migrateOldSeededApps()
  }

  async seedApp (appKeyHex, opts = {}) {
    return this.appLifecycle.seedApp(appKeyHex, opts)
  }

  async unseedApp (appKeyHex, opts = {}) {
    return this.appLifecycle.unseedApp(appKeyHex, opts)
  }

  verifyUnseedRequest (appKeyHex, publisherPubkeyHex, signatureHex, timestamp) {
    return this.appLifecycle.verifyUnseedRequest(appKeyHex, publisherPubkeyHex, signatureHex, timestamp)
  }

  broadcastUnseed (appKeyHex, publisherPubkeyHex, signatureHex, timestamp) {
    return this.appLifecycle.broadcastUnseed(appKeyHex, publisherPubkeyHex, signatureHex, timestamp)
  }

  /**
   * @param {object} [opts]
   * @param {boolean} [opts.includeSecrets=true] - when false, redact
   *   transport credentials and infra identifiers that must not be exposed
   *   to an unauthenticated caller: the holesail connectionKey (a leak of
   *   it lets a remote attacker tunnel to the API and ride the localhost
   *   auth fallback), the Tor onion address (defeats a stealth relay), the
   *   disk mountPath (server FS layout), and the seeding-registry key.
   *   Defaults to true so trusted in-process callers (CLI, metrics) are
   *   unchanged; HTTP /status, HTTP /api/overview, and the live dashboard
   *   WebSocket feed request the redacted shape at their own boundaries.
   */
  getStats (opts = {}) {
    const includeSecrets = opts.includeSecrets !== false
    const accessControlStats = this.accessControl
      ? {
          pairedDevices: this.accessControl.allowedDevices.size,
          rejectedConnections: this._rejectedConnections
        }
      : null
    const underReplicated = [...this._replicationHealth.values()].filter(v => v.state === 'under-replicated').length

    const stats = {
      running: this.running,
      mode: this.mode,
      publicKey: this.swarm ? b4a.toString(this.swarm.keyPair.publicKey, 'hex') : null,
      seededApps: this.seededApps.size,
      connections: this.swarm ? this.swarm.connections.size : 0,
      relay: this.relay ? this.relay.getStats() : null,
      seeder: this.seeder ? this.seeder.getStats() : null,
      tor: this.torTransport ? this.torTransport.getInfo() : null,
      holesail: this.holesailTransport ? this.holesailTransport.getInfo() : null,
      dhtRelayWs: this.dhtRelayWs ? this.dhtRelayWs.getStats() : null,
      reputation: {
        trackedRelays: this.reputation ? Object.keys(this.reputation.export()).length : 0
      },
      registry: {
        running: this.seedingRegistry ? this.seedingRegistry.running : false,
        key: this.seedingRegistry && this.seedingRegistry.key
          ? b4a.toString(this.seedingRegistry.key, 'hex')
          : null
      },
      replication: {
        trackedApps: this._replicationHealth.size,
        underReplicated,
        lastCheckedAt: this._lastReplicationCheckAt,
        repairEnabled: this.config.replicationRepairEnabled !== false
      },
      payment: {
        enabled: this.config.payment?.enabled === true,
        active: !!this.paymentManager,
        experimental: true,
        settlementIntervalMs: this.config.payment?.settlementInterval || null
      },
      accessControl: accessControlStats,
      disk: this.diskMonitor ? this.diskMonitor.getInfo() : null,
      storage: this.storageAccounting
        ? { ...this.storageAccounting.getSummary(), dedup: buildDedupReport(this.appRegistry, this.storageAccounting) }
        : null,
      // Honest served total measured at the replication layer (every core,
      // not just Seeder.seedCore-routed ones). The served-bytes twin of
      // `storage` above — see api.js /api/overview for how it's preferred
      // over the misleading seeder.totalBytesServed counter.
      served: this.servedAccounting ? this.servedAccounting.getSummary() : null,
      eviction: this.eviction ? this.eviction.getSummary() : null,
      subsidy: this.subsidyAccrual ? this.subsidyAccrual.getSummary() : null,
      signedDirectory: this._signedDirectory ? this._signedDirectory.getStats() : null,
      // v0.8.28 (#29): existing seeder.coresSeeded only counts the
      // seedingRegistry's local log core (it's the only thing routed
      // through Seeder.seedCore). The appRegistry-managed Hyperdrives
      // — meta + blob cores per entry — are missing from that count,
      // so a relay with 555 seeded apps still shows coresSeeded=1.
      // Expose the actual operator-visible counts here without
      // breaking existing dashboards that read seeder.coresSeeded.
      // Each Hyperdrive has 2 underlying hypercores (meta + blob);
      // anchored entries have both fully replicated.
      appRegistry: this.appRegistry
        ? (() => {
            const stats = typeof this.appRegistry.anchorStats === 'function'
              ? this.appRegistry.anchorStats()
              : { total: this.appRegistry.size || 0, anchored: 0, unanchored: 0 }
            return {
              entries: stats.total,
              anchored: stats.anchored,
              unanchored: stats.unanchored,
              // Each Hyperdrive is 2 cores (db + blob). Approximation —
              // see Hyperdrive._open() for the actual subcore graph.
              // This is the operator-visible "what's actually being
              // replicated" count that v0.8.21 #24 made meaningful.
              cores: stats.total * 2
            }
          })()
        : null,
      distributedDrive: this.distributedDriveBridge
        ? this.distributedDriveBridge.getStats()
        : {
            enabled: this.config.enableDistributedDriveBridge !== false,
            running: false,
            moduleAvailable: false,
            registeredDrives: 0,
            peers: 0,
            lastError: null
          }
    }

    if (!includeSecrets) {
      // Strip transport credentials / infra identifiers for unauthenticated
      // callers. Keep the running/enabled booleans so the dashboard still
      // shows transport state — only the secret value is removed.
      if (stats.holesail && stats.holesail.connectionKey != null) {
        stats.holesail = { ...stats.holesail, connectionKey: null }
      }
      if (stats.tor && stats.tor.onionAddress != null) {
        stats.tor = { ...stats.tor, onionAddress: null }
      }
      if (stats.disk && stats.disk.mountPath != null) {
        stats.disk = { ...stats.disk, mountPath: null }
      }
      if (stats.registry && stats.registry.key != null) {
        stats.registry = { ...stats.registry, key: null }
      }
      // The dedup report is operator-triage detail (per-version appKeys an
      // appId's catalog row deliberately hides). Keep the aggregate
      // storage.totalBytes on the unauthenticated /status, drop the breakdown.
      if (stats.storage && stats.storage.dedup != null) {
        stats.storage = { ...stats.storage, dedup: null }
      }
    }

    return stats
  }

  async createAccountingReceipt (opts = {}) {
    const keyPair = this.keyPair || (this.swarm && this.swarm.keyPair)
    if (!keyPair || !keyPair.publicKey || !keyPair.secretKey) {
      throw new Error('ACCOUNTING_RECEIPT_UNAVAILABLE: relay identity unavailable')
    }
    if (!this.storageAccounting || typeof this.storageAccounting.getSummary !== 'function') {
      throw new Error('ACCOUNTING_RECEIPT_UNAVAILABLE: storage accounting unavailable')
    }

    if (opts.refresh !== false && typeof this.storageAccounting.measureDisk === 'function') {
      await this.storageAccounting.measureDisk()
    }

    const summary = this.storageAccounting.getSummary()
    if (!Number.isSafeInteger(summary.diskBytes) || summary.diskBytes < 0) {
      throw new Error('ACCOUNTING_RECEIPT_UNAVAILABLE: OS disk measurement unavailable')
    }

    const served = this.servedAccounting && typeof this.servedAccounting.getSummary === 'function'
      ? this.servedAccounting.getSummary()
      : null
    const seeder = this.seeder && typeof this.seeder.getStats === 'function'
      ? this.seeder.getStats()
      : null
    const lease = this.leaseManager && typeof this.leaseManager.getSummary === 'function'
      ? this.leaseManager.getSummary()
      : null

    const fields = accountingFieldsFromStorageSummary(summary, {
      periodStart: opts.periodStart,
      periodEnd: opts.periodEnd,
      measuredAt: opts.measuredAt,
      bytesServed: receiptCounter(opts.bytesServed, served?.totalBytesServed ?? seeder?.totalBytesServed ?? 0, 'bytesServed'),
      bytesReceived: receiptCounter(opts.bytesReceived, 0, 'bytesReceived'),
      leaseCount: receiptCounter(opts.leaseCount, lease?.leaseCount ?? 0, 'leaseCount'),
      seededCount: receiptCounter(opts.seededCount, summary.measuredEntries || 0, 'seededCount')
    })

    return createAccountingReceipt(keyPair, { ...fields, nonce: opts.nonce })
  }

  listDevices () {
    if (!this.accessControl) return []
    return this.accessControl.listDevices()
  }

  enablePairing (opts = {}) {
    if (!this.accessControl) {
      throw new Error('Access control is only available in private/hybrid/homehive mode')
    }
    const pairing = this.accessControl.enablePairing(opts)
    return {
      ...pairing,
      relayPubkey: this.swarm ? b4a.toString(this.swarm.keyPair.publicKey, 'hex') : null
    }
  }

  async pairDevice (token, devicePubkeyHex, deviceName = 'unknown', extras = {}) {
    if (!this.accessControl) {
      throw new Error('Access control is only available in private/hybrid/homehive mode')
    }
    const paired = await this.accessControl.attemptPair(token, devicePubkeyHex, deviceName)
    // Legacy shape: callers that don't present an enrollment envelope keep
    // the plain boolean.
    if (!extras || extras.onionEnrollment === undefined) return paired
    if (!paired) return { paired: false, onionEnrollment: null }
    // Onion client-auth enrollment riding the pairing channel
    // (hiverelay.onion.authkey/1 — docs/TOR-ONION-TRANSPORT.md §4). Pairing
    // succeeds regardless; enrollment only completes when the Tor transport
    // is running in restricted-discovery mode.
    const onionEnrollment = await this.enrollOnionAuthClient(devicePubkeyHex, extras.onionEnrollment, { deviceName })
    return { paired: true, onionEnrollment }
  }

  /**
   * Enroll a just-paired device's onion client-auth key (pairing-channel
   * enrollment). Verifies the envelope against the stable relay identity,
   * adds the key to the client-auth roster (rebuild-in-place, persisted via
   * rosterFile) and returns the signed acceptance receipt. Clean no-op —
   * { enrolled: false, reason } — unless the Tor transport is running in
   * restricted-discovery mode.
   */
  async enrollOnionAuthClient (devicePubkeyHex, envelope, { deviceName = 'unknown' } = {}) {
    const result = await completeOnionEnrollment({
      torTransport: this.torTransport,
      relayKeyPair: this.swarm ? this.swarm.keyPair : null,
      devicePubkeyHex,
      envelope,
      deviceName
    })
    // Operator-local signal only: never carries the onion address, roster
    // keys, or the receipt (redaction gate — transports/tor/redaction.js).
    this.emit('tor-enrollment', { pubkey: devicePubkeyHex, enrolled: result.enrolled, reason: result.reason || null })
    return result
  }

  async addDevice (pubkeyHex, name = 'unknown') {
    if (!this.accessControl) {
      throw new Error('Access control is only available in private/hybrid/homehive mode')
    }
    return this.accessControl.addDevice(pubkeyHex, name)
  }

  async removeDevice (pubkeyHex) {
    if (!this.accessControl) {
      throw new Error('Access control is only available in private/hybrid/homehive mode')
    }
    return this.accessControl.removeDevice(pubkeyHex)
  }

  getLeaderboard (limit = 50) {
    return this.reputation ? this.reputation.getLeaderboard(limit) : []
  }

  getHealthStatus () {
    return this.healthMonitor ? this.healthMonitor.getStatus() : null
  }

  /**
   * Auto-enable holesail if the API port is not publicly reachable.
   * Waits for the first peer connection to learn our public IP, then
   * probes our own API. If unreachable, starts the holesail transport.
   */
  async _autoEnableHolesail () {
    // Wait a bit for connections and public IP discovery
    const scope = this._scope
    try {
      if (scope) await scope.sleep(15000)
      else await new Promise(resolve => setTimeout(resolve, 15000))
    } catch (err) {
      if (isAbortError(err)) return
      throw err
    }

    if (this.config.enableHolesail === false || this._stopRequested || scope?.aborted ||
        !this.running || this.holesailTransport) return

    // Find our public IP from a connected peer's perspective
    let publicIp = null
    for (const conn of this.swarm.connections) {
      if (conn.rawStream && conn.rawStream.remoteHost) {
        // Our public IP is what the DHT sees — check via swarm
        break
      }
    }

    // Use the swarm's remoteAddress if available
    if (this.swarm.keyPair) {
      try {
        const node = this.swarm.dht || this.swarm._discovery
        if (node && node.host) publicIp = node.host
      } catch {}
    }

    // Fallback: try a quick external IP check
    if (!publicIp) {
      try {
        const data = await new Promise((resolve, reject) => {
          const req = http.get('http://ifconfig.me/ip', { timeout: 5000 }, (res) => {
            let body = ''
            res.on('data', (c) => { body += c })
            res.on('end', () => resolve(body.trim()))
          })
          req.on('error', reject)
          req.on('timeout', () => { req.destroy(); reject(new Error('timeout')) })
        })
        if (data && /^\d+\.\d+\.\d+\.\d+$/.test(data)) publicIp = data
      } catch {}
    }

    if (!publicIp || this._stopRequested || scope?.aborted) return // can't determine or shutdown began

    // Try to reach our own API from the public IP
    const apiPort = this.config.apiPort || 9100
    const reachable = await new Promise((resolve) => {
      const req = http.get(`http://${publicIp}:${apiPort}/health`, { timeout: 5000 }, (res) => {
        let body = ''
        res.on('data', (c) => { body += c })
        res.on('end', () => {
          try {
            const d = JSON.parse(body)
            resolve(d.ok === true)
          } catch { resolve(false) }
        })
      })
      req.on('error', () => resolve(false))
      req.on('timeout', () => { req.destroy(); resolve(false) })
    })

    if (reachable) {
      this.emit('nat-check', { publicIp, reachable: true })
      return // API is publicly reachable, no need for holesail
    }

    if (this.config.enableHolesail === false || this._stopRequested || scope?.aborted ||
        !this.running || this.holesailTransport) return

    // API is behind NAT — auto-enable holesail
    this.emit('nat-check', { publicIp, reachable: false, action: 'enabling holesail' })

    const holesailOpts = this.config.holesail || {}
    const seedBuf = b4a.alloc(32)
    sodium.crypto_generichash(seedBuf, b4a.concat([
      this.swarm.keyPair.secretKey,
      b4a.from('holesail-api-tunnel')
    ]))
    this.holesailTransport = new HolesailTransport({
      apiPort,
      seed: b4a.toString(seedBuf, 'hex'),
      host: holesailOpts.host || '127.0.0.1'
    })
    this.holesailTransport.on('started', ({ connectionKey }) => {
      this.emit('holesail-ready', { connectionKey })
      if (this.networkDiscovery) {
        this.networkDiscovery.setLocalHolesailKey(connectionKey)
      }
    })
    await this.holesailTransport.start()
  }

  async _loadOrCreateKeyPair () {
    const keyPath = join(this.config.storage, 'relay-identity.json')
    try {
      const data = JSON.parse(await readFile(keyPath, 'utf8'))
      return {
        publicKey: b4a.from(data.publicKey, 'hex'),
        secretKey: b4a.from(data.secretKey, 'hex')
      }
    } catch (_) {
      // First run — generate and persist a new keypair
      const publicKey = b4a.alloc(32)
      const secretKey = b4a.alloc(64)
      sodium.crypto_sign_keypair(publicKey, secretKey)
      await mkdir(this.config.storage, { recursive: true })
      const tmpPath = identityTempPath(keyPath)
      try {
        await writeFile(tmpPath, JSON.stringify({
          publicKey: b4a.toString(publicKey, 'hex'),
          secretKey: b4a.toString(secretKey, 'hex')
        }, null, 2), { mode: 0o600 })
        await chmod(tmpPath, 0o600)
        await rename(tmpPath, keyPath)
      } catch (err) {
        try { await unlink(tmpPath) } catch (_) {}
        throw err
      }
      return { publicKey, secretKey }
    }
  }

  async _evictOldestApp () {
    let oldestKey = null
    let oldestTime = Infinity

    for (const [appKey, entry] of this.seededApps) {
      if (entry.startedAt < oldestTime) {
        oldestTime = entry.startedAt
        oldestKey = appKey
      }
    }

    if (!oldestKey) return null

    await this.unseedApp(oldestKey)
    this.emit('evicted', { appKey: oldestKey, reason: 'storage full' })
    return oldestKey
  }

  _onConnection (conn, info) {
    if (!this._storageIngressReady) {
      try { conn.destroy() } catch (_) {}
      return
    }
    const remotePubKeyBuf = conn.remotePublicKey || info?.publicKey || null
    const remotePubKeyHex = remotePubKeyBuf ? b4a.toString(remotePubKeyBuf, 'hex') : null

    if (this.accessControl) {
      if (!remotePubKeyHex || !this.accessControl.isAllowed(remotePubKeyHex)) {
        this._rejectedConnections++
        this.emit('connection-rejected', {
          reason: 'not in allowlist',
          remotePubKey: remotePubKeyHex,
          info
        })
        try { conn.destroy() } catch {}
        return
      }
      this.accessControl.recordActivity(remotePubKeyHex)
    }

    // Replicate all cores in our store over this connection
    this.store.replicate(conn)

    // Optional Ghost Drive-compatible drive RPC bridge
    if (this.distributedDriveBridge) {
      this.distributedDriveBridge.addPeer(conn, { remotePubKey: remotePubKeyHex })
    }

    // Attach protocol handlers so clients can negotiate seed/circuit channels
    if (this._seedProtocol) {
      try { this._seedProtocol.attach(conn) } catch (err) {
        this.emit('protocol-error', { protocol: 'seed', error: err })
      }
    }
    if (this._circuitRelay) {
      try { this._circuitRelay.attach(conn) } catch (err) {
        this.emit('protocol-error', { protocol: 'circuit', error: err })
      }
    }
    if (this._forwardRelay) {
      try { this._forwardRelay.attach(conn) } catch (err) {
        this.emit('protocol-error', { protocol: 'forward', error: err })
      }
    }
    if (this._signedDirectory) {
      try { this._signedDirectory.attach(conn) } catch (err) {
        this.emit('protocol-error', { protocol: 'signed-directory', error: err })
      }
    }
    if (this._proofOfRelay) {
      try { this._proofOfRelay.attach(conn) } catch (err) {
        this.emit('protocol-error', { protocol: 'proof', error: err })
      }
    }
    if (this._anchorProtocol && remotePubKeyHex) {
      try { this._anchorProtocol.attach(conn, remotePubKeyHex) } catch (err) {
        this.emit('protocol-error', { protocol: 'anchor', error: err })
      }
    }
    if (this._custodyProtocol && remotePubKeyHex) {
      try { this._custodyProtocol.attach(conn, remotePubKeyHex) } catch (err) {
        this.emit('protocol-error', { protocol: 'custody', error: err })
      }
    }
    if (this._publishProtocol && remotePubKeyHex) {
      try { this._publishProtocol.attach(conn, remotePubKeyHex) } catch (err) {
        this.emit('protocol-error', { protocol: 'publish', error: err })
      }
    }
    if (this.serviceProtocol) {
      try {
        if (remotePubKeyHex) {
          this.serviceProtocol.attach(conn, remotePubKeyHex)
          const role = this._resolveServicePeerRole(remotePubKeyHex)
          if (role) this.serviceProtocol.setPeerRole(remotePubKeyHex, role)
        }
      } catch (err) {
        this.emit('protocol-error', { protocol: 'services', error: err })
      }
    }

    const entry = { lastActivity: Date.now() }
    this.connections.set(conn, entry)

    conn.on('data', () => {
      entry.lastActivity = Date.now()
    })

    conn.on('error', (err) => {
      // Classify: benign P2P network drops are normal and should NOT pollute
      // the error counter. These happen constantly on the public DHT — mobile
      // clients, captive portals, NAT timeouts, rebooting peers, etc.
      const code = err && (err.code || err.message || '')
      const benign = /ECONNRESET|ETIMEDOUT|EPIPE|Duplicate connection|channel destroyed/i.test(code)
      if (benign) {
        // Emit a separate low-severity event for observability, but don't
        // increment the error counter or trigger health warnings.
        this.emit('connection-drop', { reason: err.code || err.message, info })
      } else {
        this.emit('connection-error', { error: err, info })
      }
    })

    conn.on('close', () => {
      this.connections.delete(conn)
      this.emit('connection-closed', { info })
    })

    this.emit('connection', { info, remotePubKey: remotePubKeyHex })
  }

  // Thin wrappers over the shared accept-mode module so legacy callers keep
  // working with the same instance-method API. Pure logic lives in
  // ../accept-mode.js so BareRelay can share it.
  _resolveAcceptMode () {
    return resolveAcceptMode(this.config)
  }

  _resolveServicePeerRole (remotePubKeyHex) {
    if (!remotePubKeyHex) return null
    const normalized = remotePubKeyHex.toLowerCase()

    const adminAllowlist = Array.isArray(this.config.serviceAdminAllowlist)
      ? this.config.serviceAdminAllowlist
      : []

    if (adminAllowlist.some(pk => typeof pk === 'string' && pk.toLowerCase() === normalized)) return 'relay-admin'
    return null
  }

  /**
   * Apply settings collected by the first-run setup wizard. Called by
   * the API when the operator clicks "Done" on the wizard's final step.
   * Mutates `this.config` so the relay's behavior changes immediately,
   * without requiring a restart.
   *
   * Settings handled here are intentionally narrow — only the four the
   * wizard actually collects. Anything else continues to come from the
   * config passed at constructor time.
   *
   * @param {object} cfg - Output of SetupWizard.toConfig()
   * @param {string} [cfg.name]        - operator-chosen relay name
   * @param {string} [cfg.acceptMode]  - 'open' | 'review' | 'allowlist' | 'closed'
   * @param {object} [cfg.subsidy]     - { payoutDestination } payout destination
   */
  // Construct + start the eviction manager (idempotent). Extracted from start()
  // so the storage-designation flow can turn eviction on at runtime. The
  // getStorageCap dep makes the sweep shed down to the operator-designated
  // maxStorageBytes even when the physical disk is nowhere near full.
  _ensureEviction () {
    if (this.eviction) return this.eviction
    this.eviction = new EvictionManager({
      appRegistry: this.appRegistry,
      seedingRegistry: this.seedingRegistry,
      storageAccounting: this.storageAccounting,
      diskMonitor: this.diskMonitor,
      getReplicationHealth: () => this._replicationHealth,
      myPubkeyHex: b4a.toString(this.swarm.keyPair.publicKey, 'hex'),
      unseed: (appKeyHex, opts) => this.unseedApp(appKeyHex, opts),
      getStorageCap: () => this.config.maxStorageBytes || 0,
      store: this.store
    }, { targetFloor: Math.max(1, Number(this.config.targetReplicaFloor) || 1), ...this.config.eviction })
    this.eviction.on('evicted', (e) => this.emit('eviction', e))
    this.eviction.on('evict-failed', (e) => this.emit('eviction-failed', e))
    this.eviction.on('error', (err) => this.emit('eviction-error', { error: err && err.message }))
    // Drive the shard-store's own disk-pressure eviction on the SAME periodic
    // cadence (STO-005). The EvictionManager sweeps app drives; the shard-store
    // owns a dedicated hypercore the app-eviction path never touches, so it must
    // shed its own expired/over-pressure shards or a filling box leaks shard
    // bytes. Reuses the sweep tick (no new timer); disk usage is read live so a
    // 'no-disk-signal' summary still gets an accurate reading (or is skipped).
    this.eviction.on('sweep', () => { this._trackFireAndForget(this._sweepShardStoreUnderPressure()) })
    this.eviction.start()
    return this.eviction
  }

  /** The started shard-store service provider, or null if the service is off. */
  _shardStoreProvider () {
    if (!this.serviceRegistry) return null
    const entry = this.serviceRegistry.services.get('shard-store')
    return entry && entry.provider && typeof entry.provider.evictUnderPressure === 'function'
      ? entry.provider
      : null
  }

  /**
   * Ask the shard-store to shed expired / over-pressure shards, using the live
   * disk reading. Best-effort and non-throwing: a filling disk must not be able
   * to crash the eviction loop. Below the shard-store's own pressure gate this
   * is a cheap no-op (returns skipped: 'below-pressure').
   */
  async _sweepShardStoreUnderPressure () {
    const svc = this._shardStoreProvider()
    if (!svc) return
    const disk = this.diskMonitor ? this.diskMonitor.getInfo() : null
    if (!disk || !Number.isFinite(disk.usedPct)) return
    try {
      const res = await svc.evictUnderPressure({ usedPct: disk.usedPct })
      if (res && res.evicted > 0) this.emit('shard-eviction', { usedPct: disk.usedPct, ...res })
    } catch (err) {
      this.emit('shard-eviction-error', { error: err && err.message })
    }
  }

  // Apply an operator storage designation live (no restart). Lowering a cap
  // below current usage blocks NEW adoption immediately, but never silently
  // enables eviction: serving, inspection, manual unseed and any explicitly
  // configured eviction policy remain available for operator-led recovery.
  async applyStorageDesignation (maxStorageBytes) {
    const cap = positiveStorageBound(maxStorageBytes)
    if (cap === null) return { ok: false, error: 'maxStorageBytes must be a positive safe integer' }
    if (!this.storageAdmission) return { ok: false, error: 'storage admission authority unavailable' }

    this.config.maxStorageBytes = cap
    markStorageCapExplicit(this.config, 'management-api')
    resolveStorageCap(this.config)
    this.storageAdmission.setConfig(this.config)
    this.storageAdmission.refreshFilesystem()
    // Live adoption cap: the seeder cached this at construction, so update it
    // in place — otherwise new content keeps being adopted against the old cap.
    if (this.seeder) this.seeder.maxStorageBytes = cap

    const usedBytes = this._storageUsedBytes()
    const admission = this._storageAdmission()

    return {
      ok: true,
      maxStorageBytes: cap,
      evictionEnabled: this.config.eviction?.enabled === true,
      usedBytes,
      overCap: usedBytes >= cap,
      adoptionBlocked: !admission.allowed,
      admissionReason: admission.reason,
      sweeping: false
    }
  }

  _applyWizardConfig (cfg) {
    if (!cfg || typeof cfg !== 'object') return
    if (typeof cfg.name === 'string' && cfg.name.length > 0) {
      this.config.name = cfg.name
    }
    if (typeof cfg.acceptMode === 'string') {
      this.config.acceptMode = cfg.acceptMode
      delete this.config.registryAutoAccept
    }
    if (cfg.subsidy && typeof cfg.subsidy === 'object' && Object.prototype.hasOwnProperty.call(cfg.subsidy, 'payoutDestination')) {
      const payoutDestination = typeof cfg.subsidy.payoutDestination === 'string' && cfg.subsidy.payoutDestination.length > 0
        ? cfg.subsidy.payoutDestination
        : null
      this.config.subsidy = { ...this.config.subsidy, payoutDestination }
      // If subsidy accrual is already running, update its destination live.
      if (this.subsidyAccrual && typeof this.subsidyAccrual.setPayoutDestination === 'function') {
        Promise.resolve(this.subsidyAccrual.setPayoutDestination(payoutDestination)).catch(() => {})
      }
    }
    this.emit('wizard-applied', { name: this.config.name, acceptMode: this.config.acceptMode })
  }

  /**
   * Submit a signed revocation to this relay's revocation store. The
   * revocation's signature must verify against the cert's primaryPubkey;
   * otherwise we reject (anyone else's "revocation" is a forgery).
   *
   * The revocation is indexed by the revoked cert's signature so
   * `_checkDelegation` can do O(1) lookup on every inbound seed-request.
   * Optionally supply `certExpiresAt` so the sweep can drop the entry once
   * the cert would have expired anyway; otherwise we fall back to a
   * generous default (30 days from revocation time).
   *
   * @param {object} rev - Revocation produced by createRevocation()
   * @param {object} [opts]
   * @param {number} [opts.certExpiresAt] - Original cert's expiresAt (ms epoch)
   * @returns {{ok: true, revokedCertSignature: string} | {ok: false, reason: string}}
   */
  submitRevocation (rev, opts = {}) {
    const result = verifyRevocation(rev)
    if (!result.valid) return { ok: false, reason: result.reason || 'invalid revocation' }
    const expiresAt = typeof opts.certExpiresAt === 'number' && opts.certExpiresAt > 0
      ? opts.certExpiresAt
      : Date.now() + 30 * 24 * 60 * 60 * 1000
    this._revokedCertSignatures.set(rev.revokedCertSignature, {
      revokedAt: rev.revokedAt,
      expiresAt,
      reason: rev.reason || '',
      primaryPubkey: rev.primaryPubkey
    })
    this.emit('delegation-revoked', {
      revokedCertSignature: rev.revokedCertSignature,
      primaryPubkey: rev.primaryPubkey,
      reason: rev.reason || ''
    })
    return { ok: true, revokedCertSignature: rev.revokedCertSignature }
  }

  /**
   * Snapshot of currently-held revocations (operator/admin UI).
   */
  listRevocations () {
    const out = []
    for (const [sig, entry] of this._revokedCertSignatures) {
      out.push({ revokedCertSignature: sig, ...entry })
    }
    return out
  }

  /**
   * Drop revocations whose underlying cert would already have expired on
   * its own — no point carrying weight for something nobody can use anyway.
   * Called automatically on an interval; also safe to call directly.
   */
  _sweepRevocations () {
    const now = Date.now()
    let dropped = 0
    for (const [sig, entry] of this._revokedCertSignatures) {
      if (entry.expiresAt && entry.expiresAt <= now) {
        this._revokedCertSignatures.delete(sig)
        dropped++
      }
    }
    if (dropped > 0) this.emit('revocations-swept', { dropped })
  }

  _decideAcceptance (req, mode) {
    return decideAcceptance(req, mode, this.config.acceptAllowlist || [])
  }

  /**
   * Verify a delegation cert attached to a registry seed request.
   *
   * Checks (all four must pass):
   *   1. The cert is well-formed and the cert payload signature is valid
   *      against `cert.primaryPubkey`.
   *   2. The cert names this signer (`cert.devicePubkey === req.publisherPubkey`).
   *   3. The cert has not expired (`cert.expiresAt > Date.now()`).
   *   4. The seed-request was actually signed by the device key
   *      (verifies `req.publisherSignature` against `cert.devicePubkey`).
   *
   * @param {object} req - The seed request (with `.delegationCert`)
   * @returns {{ok: true, primaryPubkey: string} | {ok: false, reason: string}}
   */
  _checkDelegation (req) {
    const cert = req.delegationCert
    const result = verifyDelegationCert(cert)
    if (!result.valid) return { ok: false, reason: result.reason || 'invalid cert' }

    // Revocation check — operator-held set keyed by cert signature. If the
    // primary identity has invalidated this cert early, reject regardless of
    // other checks passing.
    if (this._revokedCertSignatures && cert.signature &&
        this._revokedCertSignatures.has(cert.signature)) {
      return { ok: false, reason: 'revoked' }
    }

    // Whose signature appears on the request?
    const reqPublisher = typeof req.publisherPubkey === 'string'
      ? req.publisherPubkey.toLowerCase()
      : (req.publisherPubkey ? b4a.toString(req.publisherPubkey, 'hex') : null)
    if (!reqPublisher) return { ok: false, reason: 'missing request publisher' }

    if (reqPublisher !== cert.devicePubkey.toLowerCase()) {
      return { ok: false, reason: 'cert.devicePubkey mismatch' }
    }

    // Verify the seed request itself was signed by the device key. The
    // registry entry must carry a `publisherSignature` (hex string or Buffer)
    // for the chain to be verifiable. Without it we cannot bind the cert to
    // the request, so reject.
    const sigField = req.publisherSignature
    if (!sigField) return { ok: false, reason: 'missing request signature' }

    let sigBuf
    try {
      sigBuf = typeof sigField === 'string' ? b4a.from(sigField, 'hex') : sigField
    } catch (_) {
      return { ok: false, reason: 'malformed request signature' }
    }
    if (!sigBuf || sigBuf.length !== 64) {
      return { ok: false, reason: 'malformed request signature' }
    }

    const devicePk = b4a.from(cert.devicePubkey, 'hex')

    // Reconstruct the signed payload: appKey || hash(discoveryKeys) || meta(28)
    let appKeyBuf
    try {
      appKeyBuf = typeof req.appKey === 'string' ? b4a.from(req.appKey, 'hex') : req.appKey
    } catch (_) {
      return { ok: false, reason: 'malformed appKey' }
    }
    if (!appKeyBuf || appKeyBuf.length !== 32) {
      return { ok: false, reason: 'malformed appKey' }
    }

    const dkHash = b4a.alloc(32)
    const dks = Array.isArray(req.discoveryKeys) ? req.discoveryKeys : []
    if (dks.length > 0) {
      const dkBufs = dks.map(dk => typeof dk === 'string' ? b4a.from(dk, 'hex') : dk)
      sodium.crypto_generichash(dkHash, b4a.concat(dkBufs))
    }
    const meta = b4a.alloc(28)
    const view = new DataView(meta.buffer, meta.byteOffset)
    view.setUint8(0, req.replicationFactor || 0)
    view.setBigUint64(8, BigInt(req.maxStorageBytes || 0))
    view.setBigUint64(16, BigInt(req.ttlSeconds || 0))
    view.setUint32(24, req.bountyRate || 0)

    const payload = b4a.concat([appKeyBuf, dkHash, meta])
    const ok = sodium.crypto_sign_verify_detached(sigBuf, payload, devicePk)
    if (!ok) return { ok: false, reason: 'request signature mismatch' }

    return { ok: true, primaryPubkey: result.primaryPubkey }
  }

  /**
   * Bytes this relay currently stores, for ALL adoption guards. Prefers the
   * measured on-disk corestore footprint (StorageAccounting) — `seeder.
   * totalBytesStored` only counts Seeder.seedCore traffic (~0 on a registry-
   * driven relay), which is how the guard failed to bind and disks filled to
   * 100% (2026-06). Falls back to the seeder counter only before the first
   * disk measurement lands.
   */
  _storageUsedBytes () {
    // Admission cannot trust the paced StorageAccounting cache: during its
    // first walk it can contain one measured entry while omitting orphan,
    // service and registry bytes. Measure the exact configured tree for every
    // reservation. Any concurrent replacement/read failure returns NaN and
    // makes the authority fail closed.
    try {
      return measureProvenStorageTreeBytes(this.config)
    } catch (_) {
      return NaN
    }
  }

  _storageActualBytes (key) {
    if (typeof key !== 'string') return 0
    if (key.startsWith('drive:')) {
      const appKey = key.slice('drive:'.length)
      const measured = this.storageAccounting && typeof this.storageAccounting.getBytes === 'function'
        ? this.storageAccounting.getBytes(appKey)
        : null
      return Number.isSafeInteger(measured) && measured >= 0 ? measured : 0
    }
    if (key.startsWith('core:')) {
      const coreKey = key.slice('core:'.length)
      const entry = this.seeder && this.seeder.cores ? this.seeder.cores.get(coreKey) : null
      return Number.isSafeInteger(entry?.bytesStored) && entry.bytesStored >= 0 ? entry.bytesStored : 0
    }
    return 0
  }

  /**
   * Admission state for NEW storage only. Existing pins, serving, health and
   * unseed/config management do not pass through this gate, so a node that is
   * already over cap remains recoverable. The logical operator cap and the
   * live physical reserve are both enforced; neither path enables eviction.
   */
  _storageAdmission (additionalBytes = 0) {
    if (!this.storageAdmission) {
      return { allowed: false, reason: 'storage-admission-unavailable', availableBytes: 0 }
    }
    return this.storageAdmission.admission(additionalBytes, { refresh: true })
  }

  async _scanRegistry () {
    if (!this.seedingRegistry || !this.seeder) return

    const region = (this.config.regions && this.config.regions[0]) || null
    let admission = this._storageAdmission()
    let availableBytes = admission.availableBytes
    const acceptMode = this._resolveAcceptMode()

    const requests = await this.seedingRegistry.getActiveRequests({
      region,
      maxStorageBytes: availableBytes
    })

    const myPubkey = this.swarm ? b4a.toString(this.swarm.keyPair.publicKey, 'hex') : null

    for (const req of requests) {
      const requestBound = positiveStorageBound(req.maxStorageBytes)
      if (requestBound === null) {
        this.emit('registry-skipped-storage', { appKey: req.appKey, reason: 'storage-bound-invalid' })
        continue
      }
      admission = this._storageAdmission(requestBound)
      availableBytes = admission.availableBytes
      if (!admission.allowed) continue
      const reqTier = normalizePrivacyTier(req.privacyTier, 'public')

      // If a delegation cert is attached, verify the chain before accepting.
      // On success we override the request's effective publisher with the
      // primary identity (the device pubkey only signs the request; the
      // primary identity is the one we attribute the seed to). On failure we
      // emit 'delegation-rejected' and skip this request entirely.
      if (req.delegationCert) {
        const delegationCheck = this._checkDelegation(req)
        if (!delegationCheck.ok) {
          this.emit('delegation-rejected', {
            appKey: req.appKey,
            publisher: typeof req.publisherPubkey === 'string' ? req.publisherPubkey : null,
            reason: delegationCheck.reason
          })
          continue
        }
        // Override publisherPubkey on the request with the primary identity
        // so all downstream attribution (registry-seed-accepted events, the
        // app-lifecycle's stored publisherPubkey, etc.) reflects the primary.
        req.publisherPubkey = delegationCheck.primaryPubkey
      }

      if (this.config.strictSeedingPrivacy !== false && reqTier !== 'public') {
        this.emit('registry-skipped-policy', {
          appKey: req.appKey,
          privacyTier: reqTier,
          reason: 'strictSeedingPrivacy blocks non-public tiers on relay data path'
        })
        continue
      }

      // Skip if we already seed this app
      if (this.seededApps.has(req.appKey)) continue

      // Check if we already accepted this one
      const relays = await this.seedingRegistry.getRelaysForApp(req.appKey)
      const alreadyAccepted = relays.some(r => r.relayPubkey === myPubkey)
      if (alreadyAccepted) {
        // If we accepted before but aren't currently seeding (e.g. after restart), re-seed
        if (!this.seededApps.has(req.appKey)) {
          try {
            await this.seedApp(req.appKey, {
              publisherPubkey: typeof req.publisherPubkey === 'string' ? req.publisherPubkey : null,
              type: req.contentType || req.type || 'app',
              parentKey: req.parentKey || null,
              mountPath: req.mountPath || null,
              privacyTier: req.privacyTier || 'public',
              blind: req.blind === true,
              storageClass: req.storageClass || null,
              availabilityClass: req.availabilityClass || null,
              maxStorage: requestBound
            })
            this.emit('reseeded', { appKey: req.appKey, source: 'registry' })
          } catch (err) {
            this.emit('registry-error', { appKey: req.appKey, error: err })
          }
        }
        continue
      }

      // Check if replication factor is already met
      if (relays.length >= req.replicationFactor) continue

      // Check storage capacity
      if (req.maxStorageBytes > 0 && req.maxStorageBytes > availableBytes) continue

      const decision = this._decideAcceptance(req, acceptMode)

      if (decision === 'reject') {
        // 'closed' mode, or 'allowlist' miss — operator does not want this app.
        this.emit('registry-rejected', {
          appKey: req.appKey,
          publisher: req.publisherPubkey,
          mode: acceptMode,
          reason: acceptMode === 'closed' ? 'closed-mode' : 'not-on-allowlist'
        })
        continue
      }

      if (decision === 'accept') {
        const publisherHex = typeof req.publisherPubkey === 'string'
          ? req.publisherPubkey
          : (req.publisherPubkey ? b4a.toString(req.publisherPubkey, 'hex') : null)
        // Paid pin-lease: this registry auto-accept path carries no payment
        // proof, so a chargeable seed cannot settle here. Skip + route payers
        // to the gated HTTP / publish-channel path. Verified custody is exempt.
        if (this.leaseManager && !isLeaseExempt(
          { custodyIntentId: req.custodyIntentId || null, publisherPubkey: publisherHex },
          { seedingRegistry: this.seedingRegistry }
        )) {
          this.emit('registry-rejected', { appKey: req.appKey, publisher: req.publisherPubkey, mode: acceptMode, reason: 'payment-required' })
          continue
        }
        // Auto-accept: seed immediately ('open' or 'allowlist' hit)
        try {
          await this.seedApp(req.appKey, {
            publisherPubkey: publisherHex,
            type: req.contentType || req.type || 'app',
            parentKey: req.parentKey || null,
            mountPath: req.mountPath || null,
            privacyTier: req.privacyTier || 'public',
            blind: req.blind === true,
            storageClass: req.storageClass || null,
            availabilityClass: req.availabilityClass || null,
            maxStorage: requestBound
          })
          await this.seedingRegistry.recordAcceptance(
            req.appKey,
            myPubkey,
            region || 'unknown'
          )
          this.emit('registry-seed-accepted', {
            appKey: req.appKey,
            publisher: req.publisherPubkey,
            replicationFactor: req.replicationFactor,
            currentRelays: relays.length + 1,
            mode: acceptMode
          })
        } catch (err) {
          this.emit('registry-error', { appKey: req.appKey, error: err })
        }
      } else {
        // 'review' mode: queue for operator approval via dashboard / TUI
        const inserted = this._addPendingRequest(req.appKey, {
          ...req,
          currentRelays: relays.length,
          discoveredAt: Date.now(),
          mode: acceptMode
        })
        if (inserted) {
          this.emit('registry-pending', { appKey: req.appKey, publisher: req.publisherPubkey })
        }
      }
    }
  }

  // Insert into the pending-approval queue, enforcing `config.maxPendingRequests`.
  // No-op if `appKey` is already pending. When at capacity the oldest entry by
  // `discoveredAt` is evicted (Map iteration order is insertion order, but a
  // refreshed entry could outrank older ones, so we scan for the true minimum)
  // and a `'pending-evicted'` event fires with `{ appKey, reason }`.
  _addPendingRequest (appKey, entry) {
    if (this._pendingRequests.has(appKey)) return false
    const cap = this.config.maxPendingRequests
    if (typeof cap === 'number' && cap > 0 && this._pendingRequests.size >= cap) {
      let oldestKey = null
      let oldestAt = Infinity
      for (const [key, value] of this._pendingRequests) {
        const ts = value && typeof value.discoveredAt === 'number' ? value.discoveredAt : 0
        if (ts < oldestAt) {
          oldestAt = ts
          oldestKey = key
        }
      }
      if (oldestKey !== null) {
        this._pendingRequests.delete(oldestKey)
        this.emit('pending-evicted', { appKey: oldestKey, reason: 'queue-full' })
      }
    }
    this._pendingRequests.set(appKey, entry)
    return true
  }

  async approveRequest (appKeyHex) {
    const req = this._pendingRequests.get(appKeyHex)
    if (!req) throw new Error('No pending request for this app key')

    const region = (this.config.regions && this.config.regions[0]) || null
    const myPubkey = this.swarm ? b4a.toString(this.swarm.keyPair.publicKey, 'hex') : null
    const requestBound = positiveStorageBound(req.maxStorageBytes)
    if (requestBound === null) throw new Error('Pending request has no valid maxStorageBytes bound')

    await this.seedApp(appKeyHex, {
      publisherPubkey: typeof req.publisherPubkey === 'string' ? req.publisherPubkey : null,
      type: req.contentType || req.type || 'app',
      parentKey: req.parentKey || null,
      mountPath: req.mountPath || null,
      privacyTier: req.privacyTier || 'public',
      blind: req.blind === true,
      storageClass: req.storageClass || null,
      availabilityClass: req.availabilityClass || null,
      maxStorage: requestBound
    })
    if (this.seedingRegistry) {
      await this.seedingRegistry.recordAcceptance(appKeyHex, myPubkey, region || 'unknown')
    }
    this._pendingRequests.delete(appKeyHex)
    this.emit('registry-seed-accepted', { appKey: appKeyHex, publisher: req.publisherPubkey })
  }

  rejectRequest (appKeyHex) {
    this._pendingRequests.delete(appKeyHex)
  }

  _onUnseedRequest (msg) {
    const appKeyHex = b4a.toString(msg.appKey, 'hex')
    const publisherHex = b4a.toString(msg.publisherPubkey, 'hex')
    const sigHex = b4a.toString(msg.publisherSignature, 'hex')

    const result = this.verifyUnseedRequest(appKeyHex, publisherHex, sigHex, msg.timestamp)
    if (!result.ok) {
      this.emit('unseed-rejected', { appKey: appKeyHex, reason: result.error })
      return
    }

    this.unseedApp(appKeyHex).then(() => {
      this.emit('unseed-accepted', { appKey: appKeyHex, publisher: publisherHex })
    }).catch((err) => {
      this.emit('unseed-error', { appKey: appKeyHex, error: err })
    })
  }

  async _onSeedRequest (msg, channel = null, trackedMutation = false) {
    if (!trackedMutation && this.storageAdmission?.runMutation) {
      return this.storageAdmission.runMutation(() => this._onSeedRequest(msg, channel, true))
    }
    if (!this.seeder) return

    const appKeyHex = b4a.toString(msg.appKey, 'hex')

    // Reply with a wire-level deny so the publisher sees WHY instead of
    // timing out. Best-effort: channel may be null for in-process callers.
    const deny = (reasonCode, detail) => {
      if (channel && this._seedProtocol) {
        this._seedProtocol.denySeedRequest(channel, msg.appKey, reasonCode, detail)
      }
    }

    const maxStorageBytes = positiveStorageBound(msg.maxStorageBytes)
    if (maxStorageBytes === null) {
      this.emit('seed-rejected', { appKey: appKeyHex, reason: 'storage-bound-invalid' })
      deny('storage-bound-invalid', 'maxStorageBytes must be a positive safe integer')
      return
    }
    const existingApp = this.appRegistry?.has(appKeyHex) === true
    const admission = existingApp && this.storageAdmission?.recoveryReady && !this.storageAdmission?.fatalReason
      ? { allowed: true, availableBytes: this._storageAdmission(0).availableBytes }
      : this._storageAdmission(maxStorageBytes)
    const availableBytes = admission.availableBytes

    // Check capacity
    if (!admission.allowed) {
      this.emit('seed-rejected', { appKey: appKeyHex, reason: 'insufficient storage' })
      deny('insufficient-storage', 'relay has ' + Math.max(0, availableBytes) + ' bytes available, request asked for ' + msg.maxStorageBytes + ' (' + admission.reason + ')')
      return
    }

    const acceptMode = this._resolveAcceptMode()
    const decision = this._decideAcceptance(msg, acceptMode)
    if (decision === 'reject') {
      this.emit('seed-rejected', { appKey: appKeyHex, reason: 'acceptMode:' + acceptMode })
      deny('accept-mode:' + acceptMode, acceptMode === 'allowlist'
        ? 'publisher is not on this relay\'s accept allowlist'
        : 'relay is not accepting inbound seed requests')
      return
    }

    if (decision === 'queue') {
      const inserted = this._addPendingRequest(appKeyHex, {
        appKey: appKeyHex,
        publisherPubkey: msg.publisherPubkey
          ? (typeof msg.publisherPubkey === 'string' ? msg.publisherPubkey : b4a.toString(msg.publisherPubkey, 'hex'))
          : null,
        discoveryKeys: Array.isArray(msg.discoveryKeys)
          ? msg.discoveryKeys.map((dk) => (typeof dk === 'string' ? dk : b4a.toString(dk, 'hex')))
          : [],
        replicationFactor: msg.replicationFactor || 0,
        maxStorageBytes,
        ttlSeconds: msg.ttlSeconds || 0,
        bountyRate: msg.bountyRate || 0,
        publisherSignature: msg.publisherSignature
          ? (typeof msg.publisherSignature === 'string' ? msg.publisherSignature : b4a.toString(msg.publisherSignature, 'hex'))
          : null,
        delegationCert: msg.delegationCert || null,
        revocable: msg.revocable !== false,
        unseedFreezeMs: msg.unseedFreezeMs || 0,
        durability: msg.durability || 0,
        blind: msg.blind === true,
        storageClass: msg.storageClass || null,
        availabilityClass: msg.availabilityClass || null,
        discoveredAt: Date.now(),
        mode: acceptMode,
        source: 'seed-protocol'
      })
      if (inserted) {
        this.emit('seed-pending', {
          appKey: appKeyHex,
          publisher: msg.publisherPubkey
            ? (typeof msg.publisherPubkey === 'string' ? msg.publisherPubkey : b4a.toString(msg.publisherPubkey, 'hex'))
            : null
        })
      }
      // Non-terminal notice: tells the publisher to stop waiting for an
      // accept from this relay — the request is parked for the operator.
      deny('queued-for-review', 'request queued for operator approval; an accept may follow later')
      return
    }

    let effectivePublisher = msg.publisherPubkey
      ? (typeof msg.publisherPubkey === 'string' ? msg.publisherPubkey : b4a.toString(msg.publisherPubkey, 'hex'))
      : null
    if (msg.delegationCert) {
      const delegationCheck = this._checkDelegation({
        ...msg,
        appKey: appKeyHex,
        discoveryKeys: Array.isArray(msg.discoveryKeys)
          ? msg.discoveryKeys.map((dk) => (typeof dk === 'string' ? dk : b4a.toString(dk, 'hex')))
          : [],
        publisherSignature: msg.publisherSignature
          ? (typeof msg.publisherSignature === 'string' ? msg.publisherSignature : b4a.toString(msg.publisherSignature, 'hex'))
          : null
      })
      if (!delegationCheck.ok) {
        this.emit('delegation-rejected', {
          appKey: appKeyHex,
          publisher: effectivePublisher,
          reason: delegationCheck.reason
        })
        this.emit('seed-rejected', { appKey: appKeyHex, reason: 'delegation:' + delegationCheck.reason })
        deny('delegation:' + delegationCheck.reason, 'delegation certificate chain failed verification')
        return
      }
      effectivePublisher = delegationCheck.primaryPubkey
    }

    // Paid pin-lease: the binary seed-protocol carries no payment-proof field,
    // so a chargeable seed cannot be settled over this transport. Deny + route
    // paying publishers to the gated HTTP / publish-channel path rather than
    // seeding for free. A verified custody intent stays exempt.
    const custodyOpts = extractCustodySeedOpts(msg)
    if (this.leaseManager && !isLeaseExempt(
      { custodyIntentId: custodyOpts.custodyIntentId || null, publisherPubkey: effectivePublisher },
      { seedingRegistry: this.seedingRegistry }
    )) {
      this.emit('seed-rejected', { appKey: appKeyHex, reason: 'payment-required' })
      deny('payment-required', 'this relay charges to seed; submit via the publish channel or HTTPS /api/v1/seed with a paid lease')
      return
    }

    // Seed the app via AppRegistry (creates Hyperdrive + registers properly).
    // Propagate the publisher's revocability commitments — both fields are
    // signed into the seed request payload, so the publisher cannot lie about
    // them at unseed time. AppLifecycle records them on the registry entry
    // and verifyUnseedRequest enforces them.
    const publisherHex = msg.publisherPubkey
      ? (typeof msg.publisherPubkey === 'string' ? msg.publisherPubkey : b4a.toString(msg.publisherPubkey, 'hex'))
      : null
    // Propagate atomic-custody linkage when the request carries it, so a
    // custody seed accepted over the legacy seed-protocol path records the
    // SAME intent binding the publish-channel / HTTP path does (see
    // buildPublisherSignedSeedOpts). Without this, the registry entry would
    // carry no custodyIntentId/retainUntil and the expiry sweep could never
    // sign a non-serving-proof for it — i.e. anything seeded this way would
    // silently never attest.
    //
    // NOTE: the binary seedRequestEncoding does not yet carry these fields,
    // so over the wire they only arrive if a future encoding adds them (with
    // publisher-signature coverage) or an in-process caller supplies an
    // enriched msg. The authenticated, canonical custody path remains the
    // publish channel; this closes the latent drop so the two paths agree.
    let appResult = null
    const newCoreKeys = []
    try {
      appResult = await this.seedApp(appKeyHex, {
        publisherPubkey: effectivePublisher || publisherHex,
        maxStorage: maxStorageBytes,
        revocable: msg.revocable !== false,
        unseedFreezeMs: msg.unseedFreezeMs || 0,
        durability: msg.durability || 0,
        blind: msg.blind === true,
        storageClass: msg.storageClass || null,
        availabilityClass: msg.availabilityClass || null,
        ...custodyOpts
      })

      for (const dk of (msg.discoveryKeys || [])) {
        const keyHex = b4a.toString(dk, 'hex')
        if (keyHex === appKeyHex) continue
        const existed = this.seeder.cores.has(keyHex)
        await this.seeder.seedCore(keyHex, { maxStorageBytes })
        if (!existed) newCoreKeys.push(keyHex)
      }
    } catch (err) {
      for (const keyHex of newCoreKeys.reverse()) {
        try { await this.seeder.unseedCore(keyHex) } catch (_) {}
      }
      if (appResult && appResult.alreadySeeded !== true) {
        try { await this.unseedApp(appKeyHex) } catch (_) {}
      }
      this.emit('seed-error', { appKey: appKeyHex, error: err })
      deny('storage-admission-blocked', err && err.message ? err.message : 'durable storage admission failed')
      return
    }

    // Delivery is deliberately outside the storage rollback transaction.
    // Once this point is reached, retry may re-deliver an ACK but no delivery,
    // observer or partial-channel exception may revoke durable state.
    try {
      this._seedProtocol.acceptSeedRequest(
        msg.appKey,
        this.swarm.keyPair.publicKey,
        (this.config.regions && this.config.regions[0]) || 'unknown',
        this._storageAdmission(0).availableBytes
      )
    } catch (err) {
      try { this.emit('seed-ack-error', { appKey: appKeyHex, error: err }) } catch (_) {}
      return
    }
    try { this.emit('seed-accepted', { appKey: appKeyHex }) } catch (_) {}
  }

  async _runSettlements () {
    if (!this.paymentManager) return
    const minSats = (this.config.payment && this.config.payment.minSettlementSats) || 1000
    for (const [pubkey] of this.paymentManager.accounts) {
      const summary = this.paymentManager.getAccountSummary(pubkey)
      if (summary && summary.pendingPayout >= minSats) {
        try {
          await this.paymentManager.settle(pubkey)
        } catch (err) {
          this.emit('settlement-error', { relay: pubkey, error: err })
        }
      }
    }
  }

  _verifyCatalogEnvelope ({ apps, remotePubkey, relayPubkey, catalogTimestamp, signature }) {
    // Backward compatibility: unsigned catalogs can be accepted unless strict mode is enabled
    if (!signature || !relayPubkey || !catalogTimestamp) {
      return this.config.requireSignedCatalog !== true
    }

    if (!remotePubkey || relayPubkey !== remotePubkey) return false
    const ts = Number(catalogTimestamp)
    if (!Number.isFinite(ts) || ts <= 0) return false

    const maxAgeMs = this.config.catalogSignatureMaxAgeMs || (5 * 60 * 1000)
    const age = Math.abs(Date.now() - ts)
    if (age > maxAgeMs) return false

    if (!/^[0-9a-f]{64}$/i.test(relayPubkey)) return false
    if (!/^[0-9a-f]{128}$/i.test(signature)) return false

    try {
      const payload = b4a.from(JSON.stringify({ apps, relayPubkey, catalogTimestamp: ts }))
      return sodium.crypto_sign_verify_detached(
        b4a.from(signature, 'hex'),
        payload,
        b4a.from(relayPubkey, 'hex')
      )
    } catch {
      return false
    }
  }

  /**
   * Operator-initiated purge of a single entry (option-A disk recovery,
   * 2026-06-11): unseed + purge the drive's cores from disk + tombstone,
   * WITHOUT the sweep's replica-census checks — the operator is the
   * authorization. The sacred guard still applies: archive-tier and
   * custody-bound entries are refused even here (durability promises are
   * not housekeeping). Works regardless of eviction.enabled.
   */
  async manualPurge (appKeyHex) {
    if (!this.appRegistry) throw new Error('registry not ready')
    const entry = this.appRegistry.get(appKeyHex)
    assertPurgable(entry)
    let bytes = this.storageAccounting ? this.storageAccounting.getBytes(appKeyHex) : null
    if (bytes == null && this.storageAccounting) {
      try { bytes = await this.storageAccounting.measure(appKeyHex) } catch { bytes = null }
    }
    const evictedAt = Date.now()
    await this.unseedApp(appKeyHex, { evictedAt })
    // Tombstone before purging — even if the purge fails on a corrupt
    // core, repair must not re-adopt what the operator just removed.
    await this.appRegistry.markEvicted(appKeyHex, evictedAt)
    const method = await purgeDriveCores(this.store, appKeyHex)
    this.emit('eviction', { appKey: appKeyHex, bytes: bytes || 0, manual: true, method })
    return { appKey: appKeyHex, bytes: bytes || 0, method }
  }

  /**
   * Backfill seed-accept records for entries this relay holds but never
   * recorded (boot-replay adoption skipped recordAcceptance). Truth
   * repair, not policy: the census should reflect what is actually held.
   * Paced (~20/s) to keep autobase append pressure negligible.
   */
  async _reconcileAcceptances () {
    if (!this.seedingRegistry || !this.appRegistry || !this.swarm) return
    const myPubkey = b4a.toString(this.swarm.keyPair.publicKey, 'hex')
    const region = (this.config.regions && this.config.regions[0]) || 'unknown'
    let backfilled = 0
    for (const appKey of [...this.appRegistry.keys()]) {
      if (this._scope && this._scope.aborted) return
      try {
        const relays = await this.seedingRegistry.getRelaysForApp(appKey)
        const counted = (relays || []).some(r => r.relayPubkey === myPubkey)
        if (!counted) {
          await this.seedingRegistry.recordAcceptance(appKey, myPubkey, region)
          backfilled++
          if (backfilled % 20 === 0) await new Promise(resolve => setTimeout(resolve, 1000))
        }
      } catch {
        // registry closing / transient append failure — next boot retries
      }
    }
    if (backfilled > 0) this.emit('acceptance-reconciled', { backfilled })
  }

  _setLifecycleTimer (field, delayMs, run) {
    if (this._stopRequested || !this._scope || this._scope.aborted) return null
    if (this[field]) clearTimeout(this[field])
    const scope = this._scope
    const timer = setTimeout(() => {
      if (this[field] !== timer) return
      this[field] = null
      if (this._stopRequested || !this.running || !scope || scope.aborted || this._scope !== scope) return
      run()
    }, delayMs)
    this[field] = timer
    return timer
  }

  _clearLifecycleTimers () {
    for (const field of [
      '_registryInitialScanTimer',
      '_acceptanceReconcileTimer',
      '_coldStartPrimerTimer',
      '_anchorInitialTimer',
      '_repairInitialTimer',
      '_custodyExpiryInitialTimer',
      '_catalogBroadcastTimer'
    ]) {
      if (this[field]) clearTimeout(this[field])
      this[field] = null
    }
  }

  _scheduleCatalogBroadcast () {
    if (this._stopRequested || !this.running || !this._scope) return
    this._setLifecycleTimer('_catalogBroadcastTimer', 5000, () => {
      this.serviceProtocol?.broadcastAppCatalog()
    })
  }

  _startReplicationMonitor () {
    if (this._replicationCheckInterval) {
      clearInterval(this._replicationCheckInterval)
      this._replicationCheckInterval = null
    }

    const intervalMs = Math.max(10_000, Number(this.config.replicationCheckInterval) || 60_000)
    this._replicationCheckInterval = setInterval(() => {
      this._trackFireAndForget(this._checkReplicationHealth().catch((err) => {
        if (isAbortError(err)) return
        this.emit('replication-error', { error: err.message || String(err) })
      }))
    }, intervalMs)
    if (this._replicationCheckInterval.unref) this._replicationCheckInterval.unref()

    this._trackFireAndForget(this._checkReplicationHealth().catch(() => {}))
  }

  _startAnchorMonitor () {
    if (this._anchorCheckInterval) {
      clearInterval(this._anchorCheckInterval)
      this._anchorCheckInterval = null
    }
    // Default 5 min — anchor state changes slowly. Run once on startup
    // (5s after start to give the seeder time to attach) so the registry
    // gets its first honest verification right away.
    const intervalMs = Math.max(30_000, Number(this.config.anchorCheckInterval) || 300_000)
    this._anchorCheckInterval = setInterval(() => {
      this._trackFireAndForget(this._runAnchorCheck().catch((err) => {
        if (isAbortError(err)) return
        this.emit('anchor-check-error', { error: err.message || String(err) })
      }))
    }, intervalMs)
    if (this._anchorCheckInterval.unref) this._anchorCheckInterval.unref()

    this._setLifecycleTimer('_anchorInitialTimer', 5000, () => {
      this._trackFireAndForget(this._runAnchorCheck().catch(() => {}))
    })
  }

  // ─── Self-heal repair loop ────────────────────────────────────
  //
  // Periodically attempt to pull blocks for unanchored drives. This is
  // the cross-relay replication primitive: even if the original
  // publisher went offline, ANY relay (or returning publisher) that has
  // the data will fulfill our pull. Eventually consistent — drives
  // converge to "anchored on every relay that accepted them" as long
  // as at least one node has a copy.
  _startRepairMonitor () {
    if (this._repairInterval) {
      clearInterval(this._repairInterval)
      this._repairInterval = null
    }
    // Default 5 min. Lower bound 60s to avoid hammering the swarm. The
    // eager-replicate retry loop in app-lifecycle covers the first ~2
    // min after seedApp; this monitor takes over for the long tail.
    const intervalMs = Math.max(60_000, Number(this.config.repairInterval) || 300_000)
    this._repairInterval = setInterval(() => {
      this._trackFireAndForget(this._runRepairPass().catch((err) => {
        if (isAbortError(err)) return
        this.emit('repair-error', { error: err.message || String(err) })
      }))
    }, intervalMs)
    if (this._repairInterval.unref) this._repairInterval.unref()

    // First pass shortly after startup so we attempt to recover ghost
    // entries from the previous run.
    this._setLifecycleTimer('_repairInitialTimer', 30_000, () => {
      this._trackFireAndForget(this._runRepairPass().catch(() => {}))
    })
  }

  async _runRepairPass () {
    if (!this.appLifecycle || typeof this.appLifecycle.runRepairPass !== 'function') return
    if (!this.config.enableRepair && this.config.enableRepair !== undefined) return
    const result = await this.appLifecycle.runRepairPass({
      maxConcurrent: Number(this.config.repairMaxConcurrent) || 3
    })
    this._lastRepairAt = Date.now()
    this.emit('repair-pass', { ...result, at: this._lastRepairAt })
  }

  // ─── Lightweight service supervision ─────────────────────────────
  //
  // Services are part of the persistent availability plane. If a service
  // provider reports a runtime failure or fails a health check, RPC dispatch
  // fails closed and this monitor attempts a bounded restart.
  _startServiceSupervision () {
    if (this._serviceSupervisionInterval) {
      clearInterval(this._serviceSupervisionInterval)
      this._serviceSupervisionInterval = null
    }
    const cfg = this.config.serviceSupervision || {}
    if (cfg.enabled === false || !this.serviceRegistry) return

    const intervalMs = Math.max(5_000, Number(cfg.intervalMs) || 30_000)
    this._serviceSupervisionInterval = setInterval(() => {
      this._trackFireAndForget(this._runServiceSupervisionPass().catch((err) => {
        this.emit('service-supervision-error', { error: err.message || String(err) })
      }))
    }, intervalMs)
    if (this._serviceSupervisionInterval.unref) this._serviceSupervisionInterval.unref()
  }

  async _runServiceSupervisionPass () {
    const registry = this.serviceRegistry
    const scope = this._scope
    if (!registry || scope?.aborted) return { checked: 0, restarted: 0, failed: 0, skipped: 0 }

    const cfg = this.config.serviceSupervision || {}
    const maxRestarts = Number.isFinite(cfg.maxRestarts) ? Math.max(0, Math.floor(cfg.maxRestarts)) : 3
    let checked = 0
    let restarted = 0
    let failed = 0
    let skipped = 0

    for (const [name, entry] of registry.services) {
      if (scope?.aborted || this.serviceRegistry !== registry || registry.services.get(name) !== entry) break
      checked++

      if (entry.status === 'running') {
        const healthy = await this._checkServiceHealth(entry)
        if (scope?.aborted || this.serviceRegistry !== registry || registry.services.get(name) !== entry) break
        if (healthy) continue
        registry.markFailed(name, new Error('health check failed'))
      }

      if (entry.status !== 'failed') {
        skipped++
        continue
      }

      if ((entry.restartCount || 0) >= maxRestarts) {
        failed++
        this.emit('service-supervision-giveup', { name, restartCount: entry.restartCount || 0, maxRestarts })
        continue
      }

      try {
        if (scope?.aborted || this.serviceRegistry !== registry || registry.services.get(name) !== entry) break
        await registry.restart(name, this._serviceContext || this._buildServiceContext())
        restarted++
      } catch (err) {
        failed++
        this.emit('service-supervision-restart-error', { name, error: err.message || String(err) })
      }
    }

    const result = { checked, restarted, failed, skipped }
    this.emit('service-supervision-pass', { ...result, at: Date.now() })
    return result
  }

  // Resolve a custody-shard assignment for the blind shard store's PUT auth.
  // Given a custody intent this relay has indexed, return THIS relay's assigned
  // { shareIndex, shard } — binding relayPubkey -> shareIndex (shareAssignments)
  // -> shard hash (shareManifest), both signed into the intent. Returns null
  // when this relay was not assigned a share, so a relay can only pin the exact
  // share the dealer committed to it. Read-only; never throws.
  _resolveShardCustodyAssignment (custodyIntentId, relayPubkey) {
    const reg = this.seedingRegistry
    if (!reg || typeof reg.getCustodyIntent !== 'function') return null
    const intent = reg.getCustodyIntent(custodyIntentId)
    if (!intent || !Array.isArray(intent.shareAssignments) || !Array.isArray(intent.shareManifest)) return null
    const mine = intent.shareAssignments.find(a => a && a.relayPubkey === relayPubkey)
    if (!mine) return null
    const share = intent.shareManifest.find(m => m && m.shareIndex === mine.shareIndex)
    if (!share) return null
    return { shareIndex: mine.shareIndex, shard: share.shard }
  }

  // Service start context. Adds the shard-store authorization seam: a custody
  // assignment resolver (backed by the seeding registry) plus the operator's
  // enforceable pin reasons (custody-only by default; payment needs per-pinner
  // quota that does not exist relay-side yet). Services that don't read these
  // keys ignore them.
  _buildServiceContext () {
    return {
      node: this,
      store: this.store,
      config: this.config,
      // Let the shard-store register its bytes with StorageAccounting so its
      // dedicated-hypercore footprint is visible to the adoption/eviction
      // guards (STO-005) — otherwise valid long-retain pins fill the disk
      // unaccounted, re-opening the disk-full failure this fleet hit.
      storageAccounting: this.storageAccounting || null,
      resolveCustodyAssignment: (custodyIntentId, relayPubkey) =>
        this._resolveShardCustodyAssignment(custodyIntentId, relayPubkey),
      shardPutAuth: (this.config.shardStore && Array.isArray(this.config.shardStore.putAuth))
        ? this.config.shardStore.putAuth
        : ['custody']
    }
  }

  async _checkServiceHealth (entry) {
    const provider = entry?.provider
    if (!provider) return false
    const context = this._serviceContext || this._buildServiceContext()
    if (typeof provider.healthCheck === 'function') {
      const result = await provider.healthCheck(context)
      return result !== false && result?.ok !== false
    }
    if (typeof provider.health === 'function') {
      const result = await provider.health(context)
      return result !== false && result?.ok !== false
    }
    return true
  }

  // ─── Temporary custody expiry loop ────────────────────────────────
  //
  // The availability plane and atomic custody plane have opposite defaults:
  // apps/services should be kept online, while blind handoff payloads should
  // self-remove after their signed retain-until window. This loop enforces the
  // local storage side of that promise. It does not claim forensic disk erasure;
  // it removes active swarm serving, closes the drive, and drops registry state.
  _startCustodyExpiryMonitor () {
    if (this._custodyExpiryInterval) {
      clearInterval(this._custodyExpiryInterval)
      this._custodyExpiryInterval = null
    }
    if (this.config.custody?.enabled === false) return

    const intervalMs = Math.max(10_000, Number(this.config.custodyExpiryInterval) || 60_000)
    const runBoth = async () => {
      // Expiry pass first — unseeds locally-owned expired entries and
      // auto-emits non-serving-proofs about our own deletions.
      try { await this._runCustodyExpiryPass() } catch (err) {
        if (!isAbortError(err)) {
          this.emit('custody-expiry-error', { error: err.message || String(err) })
        }
      }
      // Witness pass second — observes peer relays' non-serving-proofs
      // and signs independent witness attestations. Disabled via
      // config.custodyWitnessEnabled = false.
      if (this.config.custodyWitnessEnabled === false) return
      try { await this._runCustodyExpiryWitnessPass() } catch (err) {
        if (!isAbortError(err)) {
          this.emit('custody-witness-error', { error: err.message || String(err) })
        }
      }
    }
    this._custodyExpiryInterval = setInterval(() => {
      this._trackFireAndForget(runBoth())
    }, intervalMs)
    if (this._custodyExpiryInterval.unref) this._custodyExpiryInterval.unref()

    this._setLifecycleTimer('_custodyExpiryInitialTimer', 5000, () => {
      this._trackFireAndForget(runBoth())
    })
  }

  _isTemporaryCustodyEntry (entry) {
    if (!entry) return false
    const storageClass = normalizeStorageClass(entry.storageClass, entry.blind ? 'temporary' : 'persistent')
    const availabilityClass = normalizeAvailabilityClass(entry.availabilityClass, entry.blind ? 'atomic-handoff' : 'always-on')
    return storageClass === 'temporary' ||
      availabilityClass === 'atomic-handoff' ||
      (entry.blind === true && Number.isFinite(entry.retainUntil)) ||
      // Paid pin-lease: retainUntil is an enforced lease deadline. Gated
      // STRICTLY on leaseManaged so operator self-pins and custody intents
      // (which set retainUntil for other reasons) are never swept here.
      (entry.leaseManaged === true && Number.isFinite(entry.retainUntil))
  }

  /**
   * Write a custody intent's binding onto an already-seeded appRegistry entry
   * that was registered without it (seed-request channel drops custody fields).
   * Copies custodyIntentId plus retainUntil/blindContentId from the signed
   * intent when the entry is missing them, and persists so the linkage survives
   * restart + shows on GET /api/anchors?detailed=1. Best-effort + non-throwing.
   */
  _backfillCustodyLinkage (appKey, entry, intentId) {
    if (!entry || !intentId) return
    const intent = this.seedingRegistry && typeof this.seedingRegistry.getCustodyIntent === 'function'
      ? this.seedingRegistry.getCustodyIntent(intentId)
      : null
    entry.custodyIntentId = intentId
    if (entry.retainUntil == null && intent && Number.isFinite(intent.retainUntil)) {
      entry.retainUntil = intent.retainUntil
    }
    if (!entry.blindContentId && intent && intent.blindContentId) {
      entry.blindContentId = intent.blindContentId
    }
    try {
      if (this.appRegistry && typeof this.appRegistry.update === 'function') {
        this.appRegistry.update(appKey, {
          custodyIntentId: entry.custodyIntentId,
          retainUntil: entry.retainUntil,
          blindContentId: entry.blindContentId
        })
      }
    } catch (_) { /* persistence is best-effort; in-memory linkage already set */ }
  }

  async _runCustodyExpiryPass (now = Date.now()) {
    if (!this.appRegistry) return { checked: 0, expired: 0, skipped: 0, attested: 0 }

    const graceMs = Math.max(0, Number(this.config.custodyExpiryGraceMs) || 0)
    const expiredKeys = []
    let checked = 0
    let skipped = 0

    for (const [appKey, entry] of this.appRegistry.apps) {
      if (!this._isTemporaryCustodyEntry(entry)) {
        skipped++
        continue
      }
      checked++
      let custodyIntentId = entry.custodyIntentId || null
      // Content seeded over the seed-request channel carries no custody fields
      // (the binary seedRequestEncoding drops them — see _onSeedRequest), so a
      // temporary custody entry can lack custodyIntentId even though a signed
      // intent for its addressKey exists in the registry. Recover the linkage
      // by addressKey and backfill the entry — otherwise the sweep can never
      // attest a non-serving-proof for it (the gap Drop hit: committed +
      // source-retired, but proofCount 0).
      if (!custodyIntentId && this.seedingRegistry &&
          typeof this.seedingRegistry.getCustodyIntentIdByAddressKey === 'function') {
        const resolved = this.seedingRegistry.getCustodyIntentIdByAddressKey(appKey)
        if (resolved) {
          custodyIntentId = resolved
          this._backfillCustodyLinkage(appKey, entry, resolved)
        }
      }
      const retainUntil = Number(entry.retainUntil)
      const retainElapsed = Number.isFinite(retainUntil) && retainUntil > 0 &&
        (retainUntil + graceMs) <= now

      // Claim-path erasure witness. The retainUntil deadline only covers
      // the UNCLAIMED-expiry path: content sat untouched until its retain
      // window lapsed. A *claimed* drop — where the publisher has signed a
      // source-retired entry ("I deleted the original; the handoff is
      // complete") — should be burned + attested immediately, not held for
      // the (often weeks-long) retain window. Without this, a recipient who
      // claimed a drop has no third-party-provable destruction until
      // retainUntil, which is the exact gap dmc flagged. Reuses the same
      // unseed + non-serving-proof machinery; the only change is the
      // trigger condition.
      let retired = false
      if (custodyIntentId && this.seedingRegistry) {
        try {
          const status = this.seedingRegistry.getCustodyStatus(custodyIntentId)
          retired = !!status?.sourceRetirement
        } catch (_) { /* status lookup is best-effort */ }
      }

      if (!retainElapsed && !retired) {
        skipped++
        continue
      }

      // Capture the custody linkage BEFORE unseedApp removes the entry —
      // we need it to sign a custody-non-serving-proof afterward. The
      // reason distinguishes the claim path (source-retired) from the
      // time path (expired-unseeded) in the signed proof.
      expiredKeys.push({
        appKey,
        retainUntil: Number.isFinite(retainUntil) && retainUntil > 0 ? retainUntil : null,
        custodyIntentId,
        blindContentId: entry.blindContentId || null,
        notServingReason: retired && !retainElapsed ? 'source-retired' : 'expired-unseeded'
      })
    }

    let expired = 0
    let attested = 0
    for (const { appKey, retainUntil, custodyIntentId, blindContentId, notServingReason } of expiredKeys) {
      try {
        await this.unseedApp(appKey)
        expired++
        this.emit('custody-expired', { appKey, retainUntil, reason: notServingReason, at: now })
      } catch (err) {
        this.emit('custody-expiry-error', { appKey, error: err.message || String(err) })
        // Don't attempt to sign a non-serving-proof if we couldn't even
        // unseed — createCustodyNonServingProof would throw STILL_SERVING
        // and we'd be lying about what we cleaned up.
        continue
      }

      // Auto-emit a custody-non-serving-proof so recipients probing for
      // BURNED don't need an out-of-band orchestrator to ask each relay
      // to attest. The proof closes the "K is gone" cryptographic loop
      // alongside source-retired: source-retired = publisher signs "I
      // deleted K"; non-serving-proof = relay signs "I deleted my copy".
      // Together with ≥ threshold such proofs, the recipient gets
      // provable destruction.
      if (!custodyIntentId || !this.seedingRegistry) continue
      try {
        await this.createCustodyNonServingProof(custodyIntentId, {
          appKey,
          blindContentId,
          retainUntil,
          notServingReason
        })
        attested++
        this.emit('custody-non-serving-attested', {
          appKey, custodyIntentId, retainUntil, reason: notServingReason, at: now
        })
      } catch (err) {
        // Don't fail the pass — the entry is unseeded either way. Surface
        // the attestation failure for observability. Common causes:
        // intent not in this relay's registry (federation hasn't gossiped
        // it back), STILL_SERVING race (another concurrent reseed put it
        // back), missing relay keypair.
        this.emit('custody-non-serving-attest-error', {
          appKey, custodyIntentId, error: err.message || String(err)
        })
      }
    }

    this._lastCustodyExpiryAt = now
    const result = { checked, expired, skipped, attested }
    this.emit('custody-expiry-pass', { ...result, at: now })
    return result
  }

  /**
   * Build a signed anchor proof for one of our locally-seeded apps.
   *
   * Used by both the HTTP `/api/anchors/<appKey>/proof` endpoint and the
   * Protomux anchor channel. Returns the canonical proof shape that
   * `verifyAnchorProof()` accepts.
   *
   * @param {string} appKey hex-encoded
   * @returns {Promise<object>} signed proof
   */
  async createAnchorProof (appKey) {
    if (!isValidHexKey(appKey, 64)) throw new Error('invalid appKey')
    if (!this.appRegistry || typeof this.appRegistry.get !== 'function') {
      throw new Error('registry unavailable')
    }
    if (!this.swarm?.keyPair) throw new Error('no relay identity')

    const entry = this.appRegistry.get(appKey)
    const anchored = !!(entry && entry.anchored === true)
    const version = entry?.anchoredLength || 0
    const anchoredAt = entry?.anchoredAt || null
    const attestedAt = Date.now()

    const sodium = await import('sodium-universal').then(m => m.default)
    const b4a = await import('b4a').then(m => m.default)
    const tag = b4a.from('hiverelay-anchor-proof-v1')
    const keyBuf = b4a.from(appKey, 'hex')
    const versionBuf = b4a.alloc(8)
    new DataView(versionBuf.buffer, versionBuf.byteOffset).setBigUint64(0, BigInt(version), false)
    const tsBuf = b4a.alloc(8)
    new DataView(tsBuf.buffer, tsBuf.byteOffset).setBigUint64(0, BigInt(attestedAt), false)
    const flagBuf = b4a.from([anchored ? 1 : 0])
    const payload = b4a.concat([tag, keyBuf, versionBuf, tsBuf, flagBuf])
    const sig = b4a.alloc(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(sig, payload, this.swarm.keyPair.secretKey)

    return {
      schemaVersion: 1,
      appKey,
      anchored,
      version,
      anchoredAt,
      attestedAt,
      relayPubkey: b4a.toString(this.swarm.keyPair.publicKey, 'hex'),
      signature: b4a.toString(sig, 'hex')
    }
  }

  /**
   * Return a valid 64-hex challengeNonce, generating a random one when the
   * caller supplies none. Non-serving-proof + expiry-witness signing both
   * require a 64-hex nonce; the auto-attestation paths (the expiry sweep and
   * the periodic witness scan) have no challenger to provide one, so without a
   * default every auto-attest threw "challengeNonce must be 64 hex characters"
   * — which is why Fix #1's claim-path witness never actually emitted a proof
   * through the sweep. A self-generated nonce is correct here: the proof is
   * already relay-signed; the nonce only needs to be unique, not challenger-
   * issued. Explicit challenge-response callers still pass their own.
   */
  _resolveChallengeNonce (provided) {
    if (typeof provided === 'string' && /^[0-9a-f]{64}$/i.test(provided)) return provided
    const nonce = b4a.alloc(32)
    sodium.randombytes_buf(nonce)
    return b4a.toString(nonce, 'hex')
  }

  async createCustodyNonServingProof (intentId, opts = {}) {
    if (!this.seedingRegistry) throw new Error('Registry not running')
    if (!this.swarm?.keyPair) throw new Error('Relay keypair unavailable')
    if (!isValidHexKey(intentId, 64)) throw new Error('intentId must be 64 hex characters')

    const intent = this.seedingRegistry.getCustodyIntent(intentId)
    if (!intent) throw new Error('Custody intent not found')

    const appKey = opts.appKey || intent.addressKey
    if (!isValidHexKey(appKey, 64)) throw new Error('appKey/addressKey unavailable for non-serving proof')

    const entry = this.appRegistry?.get(appKey) || null
    const catalogPresent = !!entry
    const activeSwarmServing = !!(entry?.drive && !entry.drive.closed && !entry.drive.closing)
    if (catalogPresent || activeSwarmServing) {
      throw new Error('STILL_SERVING: relay still has active registry or drive state for this content')
    }

    return this.seedingRegistry.recordCustodyNonServingProof({
      intentId,
      addressKey: appKey,
      blindContentId: opts.blindContentId || intent.blindContentId,
      challengeNonce: this._resolveChallengeNonce(opts.challengeNonce),
      retainUntil: opts.retainUntil ?? intent.retainUntil,
      notServing: true,
      notServingReason: opts.notServingReason || 'expired-unseeded',
      catalogPresent,
      activeSwarmServing
    }, this.swarm.keyPair)
  }

  /**
   * Sign and record a custody-expiry-witness attestation about a peer
   * relay we observed having posted a custody-non-serving-proof for
   * this intent. This is the third-party-confirmation primitive that
   * closes the BURNED loop for recipients: relay-X signs "I deleted
   * my copy" (custody-non-serving-proof), then independent relay-Y
   * signs "I observed relay-X's signed deletion" (custody-expiry-
   * witness referring by nonServingProofHash). ≥ threshold of these
   * witnesses gives recipients cryptographic confirmation that's
   * resistant to a single relay self-attesting falsely.
   *
   * Refuses to witness our own proofs — only peer relays.
   */
  async createCustodyExpiryWitness (intentId, subjectRelayPubkey, opts = {}) {
    if (!this.seedingRegistry) throw new Error('Registry not running')
    if (!this.swarm?.keyPair) throw new Error('Relay keypair unavailable')
    if (!isValidHexKey(intentId, 64)) throw new Error('intentId must be 64 hex characters')
    if (!isValidHexKey(subjectRelayPubkey, 64)) throw new Error('subjectRelayPubkey must be 64 hex characters')

    const myPubkey = b4a.toString(this.swarm.keyPair.publicKey, 'hex')
    if (subjectRelayPubkey === myPubkey) {
      throw new Error('SELF_WITNESS_REFUSED: cannot witness own non-serving-proof; use createCustodyNonServingProof instead')
    }

    const intent = this.seedingRegistry.getCustodyIntent(intentId)
    if (!intent) throw new Error('Custody intent not found')

    return this.seedingRegistry.recordCustodyExpiryWitness({
      intentId,
      blindContentId: opts.blindContentId || intent.blindContentId,
      relayPubkey: subjectRelayPubkey,
      challengeNonce: this._resolveChallengeNonce(opts.challengeNonce),
      nonServingProofHash: opts.nonServingProofHash || null,
      catalogPresent: opts.catalogPresent === true,
      gatewayServing: opts.gatewayServing === true,
      activeSwarmObserved: opts.activeSwarmObserved === true
    }, this.swarm.keyPair)
  }

  /**
   * Periodically scan custody intents whose retainUntil has passed and
   * — for every peer relay's published custody-non-serving-proof we
   * haven't already witnessed — sign + push an independent
   * custody-expiry-witness attestation.
   *
   * This is the v1 cross-relay witness pass: "I observed relay-X's
   * signed deletion." Active swarm/HTTP probing (verifying the relay
   * is reachable but no longer serves) is a follow-up — see
   * docs/CUSTODY-WITNESS-NEXT.md when written.
   *
   * Manifesto-pure: pure P2P, no central witness role, no required
   * infrastructure. Every relay automatically witnesses every other
   * relay's deletions. Threshold-many witnesses = strong BURNED
   * guarantee for recipients.
   */
  async _runCustodyExpiryWitnessPass (now = Date.now()) {
    if (!this.seedingRegistry) return { checked: 0, witnessed: 0, skipped: 0 }
    if (!this.swarm?.keyPair) return { checked: 0, witnessed: 0, skipped: 0 }

    const myPubkey = b4a.toString(this.swarm.keyPair.publicKey, 'hex')
    const graceMs = Math.max(0, Number(this.config.custodyExpiryGraceMs) || 0)
    let checked = 0
    let witnessed = 0
    let skipped = 0
    let errors = 0

    // Enumerate all known intents (replicated via registry gossip).
    // Direct access to _custodyIntents is the only enumeration path
    // today — a public iterator on SeedingRegistry would be nicer but
    // adding one is out of scope for this pass.
    const intentIds = this.seedingRegistry._custodyIntents
      ? [...this.seedingRegistry._custodyIntents.keys()]
      : []

    for (const intentId of intentIds) {
      const status = this.seedingRegistry.getCustodyStatus(intentId)
      if (!status?.intent) { skipped++; continue }

      const retainUntil = Number(status.intent.retainUntil)
      const retainElapsed = Number.isFinite(retainUntil) && (retainUntil + graceMs) <= now
      // Claim path: an intent whose source the publisher has retired can be
      // witnessed before retainUntil, mirroring _runCustodyExpiryPass. This
      // is what lets a peer relay's "I observed relay-X delete its copy"
      // attestation materialize for a *claimed* drop instead of waiting for
      // the (often weeks-long) retain window. Outside it, nothing to witness
      // until the window lapses.
      if (!retainElapsed && !status.sourceRetirement) {
        skipped++
        continue
      }

      checked++

      for (const proof of status.nonServingProofs || []) {
        // Skip our own proofs; we'd just be witnessing ourselves.
        if (proof.relayPubkey === myPubkey) continue
        // Skip if we've already witnessed this (intent, relay) pair.
        const alreadyWitnessed = (status.expiryWitnesses || []).some(w =>
          w.witnessPubkey === myPubkey &&
          w.relayPubkey === proof.relayPubkey &&
          w.intentId === intentId
        )
        if (alreadyWitnessed) continue

        try {
          await this.createCustodyExpiryWitness(intentId, proof.relayPubkey, {
            blindContentId: status.intent.blindContentId,
            nonServingProofHash: hashHex(proof),
            catalogPresent: false,
            gatewayServing: false,
            activeSwarmObserved: false
          })
          witnessed++
          this.emit('custody-witness-attested', {
            intentId, relayPubkey: proof.relayPubkey, at: now
          })
        } catch (err) {
          errors++
          this.emit('custody-witness-attest-error', {
            intentId, relayPubkey: proof.relayPubkey, error: err.message || String(err)
          })
        }
      }
    }

    this._lastCustodyWitnessPassAt = now
    const result = { checked, witnessed, skipped, errors }
    this.emit('custody-witness-pass', { ...result, at: now })
    return result
  }

  // ─── Cold-start primer ────────────────────────────────────────
  //
  // When a fresh relay (or one with empty/lost registry) boots, it has
  // no idea what content other relays are serving. Without this, it
  // would only learn via P2P catalog broadcasts after peers connect —
  // which can take minutes or longer in the worst case. The primer
  // fetches capability docs + catalogs from a configured list of
  // existing relays over HTTPS and optionally auto-seeds anchored
  // entries (gated by config.followAnchoredFromPeers).
  async _runColdStartPrimer () {
    const urls = Array.isArray(this.config.coldStartRelays) ? this.config.coldStartRelays : []
    if (urls.length === 0) return
    if (!this.config.enableSeeding || !this.appRegistry) return
    if (this.config.followAnchoredFromPeers !== true) {
      // Without follow-anchored we don't auto-accept anything; primer is a no-op
      return
    }

    let primed = 0
    let skipped = 0
    let failed = 0
    const MAX_PER_PEER = Number(this.config.coldStartMaxPerPeer) || 50

    for (const url of urls) {
      try {
        const ctrl = new AbortController()
        const t = setTimeout(() => ctrl.abort(), 10_000)
        const res = await fetch(url.replace(/\/+$/, '') + '/catalog.json?pageSize=' + MAX_PER_PEER, {
          signal: ctrl.signal
        }).finally(() => clearTimeout(t))
        if (!res.ok) { failed++; continue }
        const data = await res.json()
        const entries = (data && Array.isArray(data.apps))
          ? data.apps
          : (Array.isArray(data) ? data : [])

        for (const e of entries) {
          if (e.anchored !== true) { skipped++; continue }
          const appKey = e.appKey || e.driveKey
          if (!appKey || this.appRegistry.has(appKey)) { skipped++; continue }
          const appBound = positiveStorageBound(e.maxStorageBytes ?? e.maxStorage)
          if (appBound === null) { skipped++; continue }
          try {
            await this.seedApp(appKey, {
              appId: e.id || e.appId || null,
              name: e.name || null,
              version: e.version || null,
              type: e.type || 'app',
              parentKey: e.parentKey || null,
              mountPath: e.mountPath || null,
              privacyTier: e.privacyTier || null,
              blind: e.blind || false,
              storageClass: e.storageClass || null,
              availabilityClass: e.availabilityClass || null,
              author: e.author || null,
              description: e.description || '',
              maxStorage: appBound
            })
            primed++
          } catch (_) { failed++ }
          // Soft cap so we don't block startup forever
          if (primed >= MAX_PER_PEER) break
        }
      } catch (err) {
        this.emit('cold-start-error', { url, error: err.message })
        failed++
      }
    }
    this.emit('cold-start-complete', { urls: urls.length, primed, skipped, failed })
  }

  /**
   * Triggered when a peer relay's catalog tells us they have anchored a
   * drive that we have unanchored. Kick a repair attempt for that
   * specific drive immediately rather than waiting for the next pass.
   */
  _scheduleTargetedRepair (appKeyHex) {
    if (!this.appLifecycle || typeof this.appLifecycle.repairUnanchored !== 'function') return
    if (!this.appRegistry) return
    if (this.appRegistry.physicalReadOnly === true) return
    const entry = this.appRegistry.get(appKeyHex)
    if (!entry || entry.anchored === true) return
    // Fire-and-forget; runRepairPass will retry if this one fails.
    // Tracked so stop() drains an in-flight targeted repair before
    // closing the corestore (vector B18 in STALE-REF-INVENTORY.md).
    this._trackFireAndForget(this.appLifecycle.repairUnanchored(appKeyHex).catch(() => {}))
  }

  async _checkReplicationHealth () {
    if (!this.seedingRegistry) return

    const requests = await this.seedingRegistry.getActiveRequests()
    const targetFloor = Math.max(1, Number(this.config.targetReplicaFloor) || 1)
    const nextHealth = new Map()
    let underReplicated = 0

    for (const req of requests) {
      const relays = await this.seedingRegistry.getRelaysForApp(req.appKey)
      const target = Math.max(targetFloor, req.replicationFactor || 1)
      const current = relays.length
      const missing = Math.max(0, target - current)
      const state = missing > 0 ? 'under-replicated' : 'healthy'
      if (state === 'under-replicated') underReplicated++

      nextHealth.set(req.appKey, {
        state,
        current,
        target,
        missing,
        updatedAt: Date.now()
      })

      if (missing > 0 && this.config.replicationRepairEnabled !== false) {
        await this._attemptReplicationRepair(req, { relays, current, target, missing })
      }
    }

    this._replicationHealth = nextHealth
    this._lastReplicationCheckAt = Date.now()
    this.emit('replication-health', {
      trackedApps: nextHealth.size,
      underReplicated,
      checkedAt: this._lastReplicationCheckAt
    })
  }

  // ─── Anchor verification ───────────────────────────────────────
  //
  // For every app in the registry, check if the underlying Hyperdrive
  // actually has blocks (drive.version > 0). Mark anchored vs not. This
  // catches the failure mode where a relay accepts a seed request but
  // never gets the data — historically these stayed in the registry as
  // ghosts that the catalog claimed to serve. Now they get flagged.
  async _runAnchorCheck () {
    if (!this.appRegistry) return
    if (this.appRegistry.physicalReadOnly === true) return
    const driveMap = (this.appRegistry.apps && typeof this.appRegistry.apps.values === 'function')
      ? this.appRegistry.apps
      : null
    if (!driveMap) return

    let anchored = 0
    let unanchored = 0
    let checked = 0
    for (const [appKey, entry] of driveMap) {
      const drive = entry.drive
      if (!drive) continue
      checked++
      try {
        // 2026-05-22: anchored now means "every blob block present",
        // not just "drive.version > 0". The metadata-only check used
        // to rubber-stamp partial-pin entries (metadata replicates
        // long before blob content does), which then made
        // runRepairPass skip them indefinitely. The full-replication
        // check is delegated to AppLifecycle._isDriveFullyReplicated
        // so the contract lives in one place. See
        // docs/AUTO-HEAL-ROOT-CAUSE-2026-05-22.md.
        const length = drive.version || 0
        const fullyReplicated = length > 0 &&
          this.appLifecycle &&
          typeof this.appLifecycle._isDriveFullyReplicated === 'function' &&
          await this.appLifecycle._isDriveFullyReplicated(drive)
        if (fullyReplicated) {
          // A completeness scan alone is not a durable storage proof. Fresh
          // anchors must pass repairUnanchored(), which pins both core forks,
          // checks the capacity bound, persists the complete tuple, and only
          // then makes the entry ACK-eligible.
          if (entry.anchored === true && Number.isSafeInteger(entry.storageProvedDriveVersion)) {
            anchored++
          } else if (this.appLifecycle && typeof this.appLifecycle.repairUnanchored === 'function' &&
              await this.appLifecycle.repairUnanchored(appKey)) {
            anchored++
          } else {
            unanchored++
          }
        } else {
          // Not fully replicated — clear anchored if it was set so the
          // repair monitor picks the entry back up.
          if (entry.anchored === true) {
            this.appRegistry.clearAnchored(appKey, length > 0
              ? 'partial-pin detected on periodic check (blob blocks missing)'
              : 'length=0 on periodic check')
          } else {
            this.appRegistry.recordAnchorCheck(appKey)
          }
          unanchored++
        }
      } catch (err) {
        this.emit('anchor-check-error', { appKey, error: err.message })
      }
    }
    this._lastAnchorCheckAt = Date.now()
    this.emit('anchor-health', {
      checked,
      anchored,
      unanchored,
      checkedAt: this._lastAnchorCheckAt
    })
  }

  async _attemptReplicationRepair (request, status) {
    if (!this.config.enableSeeding || !this.seeder || !this.seedingRegistry || !this.swarm) return false
    const reqTier = normalizePrivacyTier(request.privacyTier, 'public')
    if (this.config.strictSeedingPrivacy !== false && reqTier !== 'public') return false

    const acceptMode = this._resolveAcceptMode()
    let effectivePublisher = typeof request.publisherPubkey === 'string' ? request.publisherPubkey : null
    if (request.delegationCert) {
      const delegationCheck = this._checkDelegation(request)
      if (!delegationCheck.ok) {
        this.emit('delegation-rejected', {
          appKey: request.appKey,
          publisher: effectivePublisher,
          reason: delegationCheck.reason
        })
        return false
      }
      effectivePublisher = delegationCheck.primaryPubkey
    }

    const decision = this._decideAcceptance({
      ...request,
      publisherPubkey: effectivePublisher
    }, acceptMode)
    if (decision === 'reject') return false
    if (decision === 'queue') {
      this._addPendingRequest(request.appKey, {
        ...request,
        publisherPubkey: effectivePublisher,
        currentRelays: status.current,
        discoveredAt: Date.now(),
        mode: acceptMode,
        source: 'replication-repair'
      })
      return false
    }

    const myPubkey = b4a.toString(this.swarm.keyPair.publicKey, 'hex')
    const alreadyAccepted = status.relays.some(r => r.relayPubkey === myPubkey)
    const alreadySeeding = this.seededApps.has(request.appKey)
    if (alreadyAccepted && alreadySeeding) return false

    // Eviction tombstone gate (Phase A): an entry this relay deliberately
    // shed is only re-adopted when the network has actually fallen under
    // the replica floor — otherwise every sweep would be undone by the
    // next repair pass and the fleet re-converges on union-of-catalogs.
    const floor = Math.max(1, Number(this.config.targetReplicaFloor) || 1)
    if (this.appRegistry && typeof this.appRegistry.isEvicted === 'function' && this.appRegistry.isEvicted(request.appKey)) {
      if (status.current >= floor) return false
      await this.appRegistry.clearEvicted(request.appKey) // genuinely under floor — we're needed again
    }

    // Storage guard on REAL bytes (Phase 0), via _storageUsedBytes() — the
    // measured on-disk corestore footprint. seeder.totalBytesStored only counts
    // Seeder.seedCore traffic (~0 on registry-driven relays), so the old guard
    // never bound and adoption was effectively uncapped (how the fleet's disks
    // filled, 2026-06). Also reject when the budget is simply exhausted, not
    // only when the request declares a size.
    const requestBound = positiveStorageBound(request.maxStorageBytes)
    if (requestBound === null) return false
    const admission = this._storageAdmission(requestBound)
    if (!admission.allowed) return false

    // Paid pin-lease: don't auto-adopt a non-exempt publisher's registry
    // request for free here. The MVP charges each relay individually (no
    // free cross-relay mirroring), so a chargeable drive we're not already
    // seeding must come through the gated HTTP/publish path, not the
    // replication-repair monitor. Verified custody intents stay exempt; this
    // never fires for drives we already seed (caught by alreadySeeding above).
    if (this.leaseManager && !isLeaseExempt(
      { custodyIntentId: request.custodyIntentId || null, publisherPubkey: effectivePublisher },
      { seedingRegistry: this.seedingRegistry }
    )) {
      this.emit('replication-repair-skipped', { appKey: request.appKey, reason: 'payment-required' })
      return false
    }

    try {
      await this.seedApp(request.appKey, {
        publisherPubkey: effectivePublisher,
        type: request.contentType || request.type || 'app',
        parentKey: request.parentKey || null,
        mountPath: request.mountPath || null,
        privacyTier: request.privacyTier || 'public',
        maxStorage: requestBound
      })
      if (!alreadyAccepted) {
        const region = (this.config.regions && this.config.regions[0]) || 'unknown'
        await this.seedingRegistry.recordAcceptance(request.appKey, myPubkey, region)
      }
      this.emit('replication-repaired', {
        appKey: request.appKey,
        current: status.current,
        target: status.target
      })
      return true
    } catch (err) {
      this.emit('replication-repair-error', {
        appKey: request.appKey,
        error: err.message || String(err)
      })
      return false
    }
  }

  _startHealthChecks () {
    const HEALTH_CHECK_INTERVAL = 60_000
    const STALE_THRESHOLD = 5 * 60 * 1000

    this._healthCheckInterval = setInterval(() => {
      const now = Date.now()
      for (const [conn, entry] of this.connections) {
        if (now - entry.lastActivity > STALE_THRESHOLD) {
          this.emit('connection-stale', { conn, lastActivity: entry.lastActivity })
        }
      }
    }, HEALTH_CHECK_INTERVAL)
    if (this._healthCheckInterval.unref) this._healthCheckInterval.unref()
  }

  async _flushDhtForStartup () {
    if (!this.swarm || typeof this.swarm.flush !== 'function') return false
    const timeoutMs = Number.isFinite(this.config.dhtFlushTimeoutMs)
      ? Math.max(0, Math.floor(this.config.dhtFlushTimeoutMs))
      : DEFAULT_CONFIG.dhtFlushTimeoutMs

    const flush = this.swarm.flush().then(
      () => ({ ok: true }),
      (err) => ({ ok: false, error: err })
    )

    if (timeoutMs === 0) {
      flush.then((result) => {
        if (!result.ok) this.emit('dht-flush-error', { error: result.error?.message || String(result.error) })
      })
      return false
    }

    let timer
    const timeout = new Promise(resolve => {
      timer = setTimeout(() => resolve({ ok: false, timedOut: true }), timeoutMs)
    })
    const result = await Promise.race([flush, timeout])
    clearTimeout(timer)

    if (result.timedOut) {
      this.emit('dht-flush-timeout', { timeoutMs })
      return false
    }
    if (!result.ok) {
      this.emit('dht-flush-error', { error: result.error?.message || String(result.error) })
      return false
    }
    return true
  }

  /**
   * Announce on the current + next epoch discovery buckets. Idempotent:
   * swarm.join() on an already-joined topic is a no-op, so calling this on a
   * timer simply rolls the announcement forward across epoch boundaries.
   */
  _joinEpochDiscoveryTopics () {
    if (!this.swarm) return
    this._epochDiscoveryTopics = syncEpochDiscoveryTopics(
      this._epochDiscoveryTopics,
      this.swarm,
      { server: true, client: false },
      null,
      DISCOVERY_EPOCH_MS,
      (handle) => this._queueEpochDiscoveryDestroy(handle)
    )
  }

  _queueEpochDiscoveryDestroy (handle) {
    if (!handle || typeof handle.destroy !== 'function') return
    const entry = { handle, promise: null }
    this._retiringEpochDiscoveryHandles.add(entry)
    const run = Promise.resolve().then(() => handle.destroy())
    entry.promise = run
    run.then(
      () => this._retiringEpochDiscoveryHandles.delete(entry),
      () => { entry.promise = null }
    )
  }

  async _destroyDiscoveryHandles (timeout) {
    const destroy = async (handle, label) => {
      if (!handle || typeof handle.destroy !== 'function') return
      await this._awaitOwnerOperation(handle, label, () => handle.destroy(), timeout)
    }

    for (const entry of [...this._retiringEpochDiscoveryHandles]) {
      if (entry.promise) {
        await this._awaitOwnerOperation(
          entry,
          'retiringEpochDiscovery.destroy',
          () => entry.promise,
          timeout
        )
      } else {
        await destroy(entry.handle, 'retiringEpochDiscovery.destroy')
      }
      this._retiringEpochDiscoveryHandles.delete(entry)
    }
    for (const [key, handle] of this._epochDiscoveryTopics) {
      await destroy(handle, `epochDiscovery(${key.slice(0, 8)}).destroy`)
      this._epochDiscoveryTopics.delete(key)
    }
    if (this._foundationDiscoveryHandle) {
      await destroy(this._foundationDiscoveryHandle, 'foundationDiscovery.destroy')
      this._foundationDiscoveryHandle = null
    }
    if (this._relayDiscoveryHandle) {
      await destroy(this._relayDiscoveryHandle, 'relayDiscovery.destroy')
      this._relayDiscoveryHandle = null
    }
  }

  _ownerOperation (owner, label, run) {
    const existing = this._ownerOperations.get(owner)
    if (existing) {
      if (existing.label === label) return existing.operation
      return existing.operation.catch(() => {}).then(() => this._ownerOperation(owner, label, run))
    }
    const operation = Promise.resolve().then(run)
    const entry = { label, operation }
    this._ownerOperations.set(owner, entry)
    operation.then(
      () => { if (this._ownerOperations.get(owner) === entry) this._ownerOperations.delete(owner) },
      () => { if (this._ownerOperations.get(owner) === entry) this._ownerOperations.delete(owner) }
    )
    return operation
  }

  _awaitOwnerOperation (owner, label, run, timeout) {
    const budget = this._remainingOwnerBudget(timeout)
    return withTimeout(this._ownerOperation(owner, label, run), budget, label)
  }

  _remainingOwnerBudget (timeout) {
    let budget = timeout || 30_000
    if (this._ownerDeadline) budget = Math.max(1, Math.min(budget, this._ownerDeadline - Date.now()))
    return budget
  }

  async _quiesceStorageWriters (timeout) {
    if (!this._ownerDeadline) this._ownerDeadline = Date.now() + (timeout || 30_000)
    let firstError = null
    this._clearLifecycleTimers()
    const settle = async (run) => {
      try { await run() } catch (err) { if (!firstError) firstError = err }
    }
    const stopAsync = async (field, label) => {
      const value = this[field]
      if (!value) return
      await settle(async () => {
        await this._awaitOwnerOperation(value, label, () => value.stop(), timeout)
        if (this[field] === value) this[field] = null
      })
    }

    // First make every public ingress unreachable while the storage authority
    // is still open for provider shutdown/flush work already in progress.
    await stopAsync('holesailTransport', 'holesailTransport.stop')
    await stopAsync('torTransport', 'torTransport.stop')
    await stopAsync('wsTransport', 'wsTransport.stop')
    await stopAsync('dhtRelayWs', 'dhtRelayWs.stop')
    await stopAsync('gatewayServer', 'gatewayServer.stop')
    await stopAsync('api', 'api.stop')
    await stopAsync('router', 'router.stop')
    if (this.serviceProtocol) {
      await settle(async () => { this.serviceProtocol.destroy(); this.serviceProtocol = null })
    }
    if (this._seedProtocol) {
      await settle(async () => { this._seedProtocol.destroy(); this._seedProtocol = null })
    }
    await settle(() => this._destroyProtocolHandlers(timeout, [
      '_circuitRelay',
      '_forwardRelay',
      '_signedDirectory',
      '_proofOfRelay',
      '_anchorProtocol',
      '_custodyProtocol',
      '_publishProtocol'
    ]))

    // Quiesce timer-driven producers before taking the mutation gate away.
    for (const field of [
      '_relayRecordTimer', '_catalogBroadcastTimer', '_catalogThrottleCleanup',
      '_healthCheckInterval', 'settlementInterval', '_replicationCheckInterval',
      '_anchorCheckInterval', '_anchorInitialTimer',
      '_repairInterval', '_repairInitialTimer',
      '_custodyExpiryInterval', '_custodyExpiryInitialTimer',
      '_serviceSupervisionInterval', '_registryScanInterval',
      '_registryInitialScanTimer', '_acceptanceReconcileTimer',
      '_coldStartPrimerTimer',
      '_revocationSweepInterval', '_reputationSaveInterval',
      '_reputationDecayInterval', '_epochDiscoveryTimer'
    ]) {
      if (!this[field]) continue
      clearInterval(this[field])
      clearTimeout(this[field])
      this[field] = null
    }
    if (this.eviction) { this.eviction.stop(); this.eviction = null }
    if (this.storageAccounting) { this.storageAccounting.stop(); this.storageAccounting = null }
    if (this.servedAccounting) { this.servedAccounting.stop(); this.servedAccounting = null }

    // Abort and settle contract-aware loops, then stop every provider that can
    // own an append handle. stopAll(strict) retains failed providers so a
    // supervisor retry still has the object needed to reach settlement.
    const scope = this._scope
    if (scope) {
      await settle(async () => {
        await this._awaitOwnerOperation(scope, 'lifecycleScope.drain', () => scope.drain(), timeout)
        if (this._scope === scope) this._scope = null
      })
    }
    if (this.appLifecycle && typeof this.appLifecycle.drainRetiringDrives === 'function') {
      const lifecycle = this.appLifecycle
      await settle(() => this._awaitOwnerOperation(
        lifecycle,
        'appLifecycle.drainRetiringDrives',
        () => lifecycle.drainRetiringDrives(),
        timeout
      ))
    }
    if (this.serviceRegistry) {
      const registry = this.serviceRegistry
      await settle(async () => {
        await this._awaitOwnerOperation(
          registry,
          'serviceRegistry.stopAll',
          () => registry.stopAll({ throwOnError: true }),
          timeout
        )
        if (this.serviceRegistry === registry) this.serviceRegistry = null
      })
    }
    this._serviceContext = null
    if (this.seedingRegistry) {
      const registry = this.seedingRegistry
      await settle(async () => {
        await this._awaitOwnerOperation(registry, 'seedingRegistry.stop', () => registry.stop(), timeout)
        if (this.seedingRegistry === registry) this.seedingRegistry = null
      })
    }
    if (this.networkDiscovery) {
      const discovery = this.networkDiscovery
      await settle(async () => {
        await this._awaitOwnerOperation(discovery, 'networkDiscovery.stop', () => discovery.stop(), timeout)
        if (this.networkDiscovery === discovery) this.networkDiscovery = null
      })
    }
    if (this.autoHeal) {
      const autoHeal = this.autoHeal
      await settle(async () => {
        await this._awaitOwnerOperation(autoHeal, 'autoHeal.stop', () => autoHeal.stop(), timeout)
        if (this.autoHeal === autoHeal) this.autoHeal = null
      })
    }
    if (this.federation) {
      const federation = this.federation
      await settle(async () => {
        await this._awaitOwnerOperation(federation, 'federation.stop', () => federation.stop(), timeout)
        if (this.federation === federation) this.federation = null
      })
    }
    if (this.subsidyAccrual) {
      const subsidy = this.subsidyAccrual
      await settle(async () => {
        await this._awaitOwnerOperation(subsidy, 'subsidyAccrual.destroy', () => subsidy.destroy(), timeout)
        if (this.subsidyAccrual === subsidy) this.subsidyAccrual = null
      })
    }
    if (this.leaseManager) {
      const leases = this.leaseManager
      await settle(async () => {
        await this._awaitOwnerOperation(leases, 'leaseManager.destroy', () => leases.destroy(), timeout)
        if (this.leaseManager === leases) this.leaseManager = null
      })
    }
    if (this.manifestStore) {
      const manifest = this.manifestStore
      await settle(() => this._awaitOwnerOperation(manifest, 'manifestStore.save', () => manifest.save(), timeout))
    }
    if (this.reputation) {
      const reputation = this.reputation
      await settle(() => this._awaitOwnerOperation(
        reputation,
        'reputation.save',
        () => reputation.save(join(this.config.storage, 'reputation.json')),
        timeout
      ))
    }
    if (this.bootstrapCache) {
      const cache = this.bootstrapCache
      cache.stop()
      await settle(() => this._awaitOwnerOperation(cache, 'bootstrapCache.save', () => cache.save(), timeout))
    }
    if (this.appRegistry) {
      const registry = this.appRegistry
      await settle(() => this._awaitOwnerOperation(
        registry,
        'appRegistry.flush',
        () => registry.flush({ throwOnError: true }),
        timeout
      ))
    }
    if (this.seeder) {
      const seeder = this.seeder
      await settle(async () => {
        await this._awaitOwnerOperation(seeder, 'seeder.stop', () => seeder.stop(), timeout)
        if (this.seeder === seeder) this.seeder = null
      })
    }

    if (firstError) {
      this._ownerDeadline = null
      const failure = new Error('storage writer quiescence did not settle')
      failure.code = 'STORAGE_WRITER_QUIESCE_FAILED'
      failure.cause = firstError
      throw failure
    }
  }

  async _destroyProtocolHandlers (timeout, fields) {
    let firstError = null
    for (const field of fields) {
      const protocol = this[field]
      if (!protocol) continue
      try {
        if (typeof protocol.destroy === 'function') {
          await this._awaitOwnerOperation(
            protocol,
            `${field}.destroy`,
            () => protocol.destroy(),
            timeout || 30_000
          )
        }
        // Null only after exact teardown settles. A rejected destroy keeps the
        // owner reachable so startup rollback / stop can retry it.
        if (this[field] === protocol) this[field] = null
      } catch (err) {
        if (!firstError) firstError = err
      }
    }
    if (firstError) throw firstError
  }

  stop () {
    if (this._stopping) return this._stopping
    const operation = this._stop()
    const stopping = operation.finally(() => {
      if (this._stopping === stopping) this._stopping = null
      this._ownerDeadline = null
    })
    this._stopping = stopping
    return stopping
  }

  async _stop () {
    if (!this.running && !this._starting && !this._startupRollbackPending) return
    this._stopRequested = true
    this._storageIngressReady = false
    const timeout = this.config.shutdownTimeoutMs
    this._ownerDeadline = Date.now() + (timeout || 30_000)

    // A concurrent start cannot safely finish accepting mutations, so seal it
    // immediately. A normally-running relay instead quiesces ingress, timers,
    // and providers first, while their final flush/stop work can still use the
    // authority, then seals and drains below.
    if (this._starting && this.storageAdmission) this.storageAdmission.closeMutations()
    if (this._starting && this._startCompletion) {
      const scopeDuringStart = this._scope
      if (scopeDuringStart) scopeDuringStart.abort()
      try {
        await withTimeout(
          this._startCompletion,
          this._remainingOwnerBudget(timeout),
          'relay start completion'
        )
      } catch (cause) {
        if (cause?.code !== 'OPERATION_TIMEOUT') {
          if (this._startupRollbackPending) throw cause
          return
        }
        const failure = new Error('relay startup settlement is still pending')
        failure.code = 'STORAGE_START_TEARDOWN_PENDING'
        failure.cause = cause
        throw failure
      }
      if (scopeDuringStart && this._scope === scopeDuringStart) {
        try {
          await withTimeout(
            scopeDuringStart.drain(),
            this._remainingOwnerBudget(timeout),
            'startup lifecycleScope.drain'
          )
          if (this._scope === scopeDuringStart) this._scope = null
        } catch (cause) {
          const failure = new Error('relay startup lifecycle teardown is still pending')
          failure.code = 'STORAGE_START_TEARDOWN_PENDING'
          failure.cause = cause
          throw failure
        }
      }
      if (!this.running) {
        return
      }
    }

    try {
      await this._quiesceStorageWriters(timeout)
    } catch (err) {
      if (this.storageAdmission) {
        this.storageAdmission.closeMutations('storage-writer-quiesce-failed')
        this.storageAdmission.failClosed('storage-writer-quiesce-failed')
      }
      throw err
    }
    if (this.storageAdmission) this.storageAdmission.closeMutations()

    // Cancellation contract: fire the abort signal FIRST and drain every
    // fire-and-forget that participates in the LifecycleScope before
    // touching any subsystem. By the time we reach swarm.destroy() and
    // store.close() below, no captured-reference closure is still
    // running against the corestore. This is the fix for the
    // "Mutex has been destroyed" / "corestore is closed" leaks (see
    // STALE-REF-INVENTORY.md + CANCELLATION-CONTRACT.md).
    //
    // Drain is bounded by shutdownTimeoutMs * each tracked promise's
    // own timeout; in practice every contract-aware loop exits within
    // a few hundred ms of the abort.
    if (this.storageAdmission) {
      await this.storageAdmission.drainMutations({ timeoutMs: this._remainingOwnerBudget(timeout) })
    }

    // Stop the relay-record republish timer.
    if (this._relayRecordTimer) {
      clearInterval(this._relayRecordTimer)
      this._relayRecordTimer = null
    }

    // Clean up catalog broadcast debounce timer and peer throttle map
    if (this._catalogBroadcastTimer) {
      clearTimeout(this._catalogBroadcastTimer)
      this._catalogBroadcastTimer = null
    }
    if (this._catalogThrottleCleanup) {
      clearInterval(this._catalogThrottleCleanup)
      this._catalogThrottleCleanup = null
    }
    this._catalogPeerThrottle.clear()
    if (this._publisherSeedReplayCache) this._publisherSeedReplayCache.clear()

    // Bootstrap persistence was quiesced before admission closed.
    this.bootstrapCache.stop()

    // Stop health checks, settlement, WebSocket, API, and metrics first
    if (this.selfHeal) { this.selfHeal.stop(); this.selfHeal = null }
    if (this.alertManager) { this.alertManager.stop(); this.alertManager = null }
    if (this.healthMonitor) { this.healthMonitor.stop(); this.healthMonitor = null }
    if (this.diskMonitor) { this.diskMonitor.stop(); this.diskMonitor = null }
    if (this.eviction) { this.eviction.stop(); this.eviction = null }
    if (this.storageAccounting) { this.storageAccounting.stop(); this.storageAccounting = null }
    if (this.servedAccounting) { this.servedAccounting.stop(); this.servedAccounting = null }
    if (this.subsidyAccrual) { await this.subsidyAccrual.destroy(); this.subsidyAccrual = null }
    if (this.leaseManager) { await this.leaseManager.destroy(); this.leaseManager = null }
    if (this._healthCheckInterval) { clearInterval(this._healthCheckInterval); this._healthCheckInterval = null }
    if (this.settlementInterval) { clearInterval(this.settlementInterval); this.settlementInterval = null }
    if (this._replicationCheckInterval) { clearInterval(this._replicationCheckInterval); this._replicationCheckInterval = null }
    this._replicationHealth.clear()
    this._lastReplicationCheckAt = null
    if (this._anchorCheckInterval) { clearInterval(this._anchorCheckInterval); this._anchorCheckInterval = null }
    this._lastAnchorCheckAt = null
    if (this._repairInterval) { clearInterval(this._repairInterval); this._repairInterval = null }
    this._lastRepairAt = null
    if (this._custodyExpiryInterval) { clearInterval(this._custodyExpiryInterval); this._custodyExpiryInterval = null }
    this._lastCustodyExpiryAt = null
    if (this.holesailTransport) {
      try { await withTimeout(this.holesailTransport.stop(), timeout, 'holesailTransport.stop') } catch (_) {}
      this.holesailTransport = null
    }
    if (this.torTransport) {
      try { await withTimeout(this.torTransport.stop(), timeout, 'torTransport.stop') } catch (_) {}
      this.torTransport = null
    }
    if (this.wsTransport) {
      try { await withTimeout(this.wsTransport.stop(), timeout, 'wsTransport.stop') } catch (_) {}
      this.wsTransport = null
    }
    if (this.dhtRelayWs) {
      try { await withTimeout(this.dhtRelayWs.stop(), timeout, 'dhtRelayWs.stop') } catch (_) {}
      this.dhtRelayWs = null
    }
    if (this.gatewayServer) {
      try { await withTimeout(this.gatewayServer.stop(), timeout, 'gatewayServer.stop') } catch (_) {}
      this.gatewayServer = null
    }
    if (this.api) {
      try { await withTimeout(this.api.stop(), timeout, 'api.stop') } catch (_) {}
      this.api = null
    }
    if (this.metrics) { this.metrics.stop(); this.metrics = null }

    // Stop services layer
    if (this.router) {
      try { await withTimeout(this.router.stop(), timeout, 'router.stop') } catch (_) {}
      this.router = null
    }
    if (this.serviceProtocol) {
      try { this.serviceProtocol.destroy() } catch (_) {}
      this.serviceProtocol = null
    }
    if (this._serviceSupervisionInterval) { clearInterval(this._serviceSupervisionInterval); this._serviceSupervisionInterval = null }
    this._serviceContext = null
    if (this.serviceRegistry) {
      await this.serviceRegistry.stopAll({ throwOnError: true })
      this.serviceRegistry = null
    }
    if (this.accessControl) {
      try { this.accessControl.disablePairing() } catch (_) {}
      this.accessControl = null
    }

    // Destroy protocol handlers
    if (this._seedProtocol) { this._seedProtocol.destroy(); this._seedProtocol = null }
    if (this._circuitRelay) {
      if (this._circuitRelay.destroy) this._circuitRelay.destroy()
      this._circuitRelay = null
    }
    if (this._forwardRelay) {
      if (this._forwardRelay.destroy) this._forwardRelay.destroy()
      this._forwardRelay = null
    }
    if (this._signedDirectory) {
      if (this._signedDirectory.destroy) this._signedDirectory.destroy()
      this._signedDirectory = null
    }
    if (this._registryScanInterval) { clearInterval(this._registryScanInterval); this._registryScanInterval = null }
    if (this.seedingRegistry) { try { await this.seedingRegistry.stop() } catch (_) {} this.seedingRegistry = null }
    if (this.networkDiscovery) { try { await this.networkDiscovery.stop() } catch (_) {} this.networkDiscovery = null }
    if (this.autoHeal) { try { await this.autoHeal.stop() } catch (_) {} this.autoHeal = null }
    if (this.federation) { try { await this.federation.stop() } catch (_) {} this.federation = null }
    if (this.manifestStore) {
      // Unsaved manifest updates were flushed before admission closed.
      this.manifestStore.removeAllListeners()
      this.manifestStore = null
    }
    if (this._revocationSweepInterval) { clearInterval(this._revocationSweepInterval); this._revocationSweepInterval = null }
    if (this._proofOfRelay) { if (this._proofOfRelay.destroy) this._proofOfRelay.destroy(); this._proofOfRelay = null }
    if (this._bandwidthReceipt) { this._bandwidthReceipt.stop(); this._bandwidthReceipt = null }
    if (this._reputationSaveInterval) { clearInterval(this._reputationSaveInterval); this._reputationSaveInterval = null }
    if (this._reputationDecayInterval) { clearInterval(this._reputationDecayInterval); this._reputationDecayInterval = null }
    // AppRegistry and reputation were flushed before admission closed.

    // Tear down all apps' live resources WITHOUT forgetting them. A clean
    // shutdown must not erase the registry — the entries are reloaded by
    // reseedFromRegistry on the next start() (operator restart, SIGTERM,
    // or in-process self-heal). Using forget:true here was a data-loss bug
    // that wiped all seeded content on every restart.
    for (const appKeyHex of this.seededApps.keys()) {
      await withTimeout(
        this.unseedApp(appKeyHex, { forget: false }),
        this._remainingOwnerBudget(timeout),
        `unseedApp(${appKeyHex.slice(0, 8)})`
      )
    }

    if (this.distributedDriveBridge) {
      const bridge = this.distributedDriveBridge
      await this._awaitOwnerOperation(
        bridge,
        'distributedDriveBridge.stop',
        () => bridge.stop(),
        timeout
      )
      if (this.distributedDriveBridge === bridge) this.distributedDriveBridge = null
    }

    if (this.relay) {
      const relay = this.relay
      await this._awaitOwnerOperation(relay, 'relay.stop', () => relay.stop(), timeout)
      if (this.relay === relay) this.relay = null
    }
    if (this.seeder) {
      const seeder = this.seeder
      await this._awaitOwnerOperation(seeder, 'seeder.stop', () => seeder.stop(), timeout)
      if (this.seeder === seeder) this.seeder = null
    }
    await this._destroyDiscoveryHandles(timeout)
    if (this.swarm) {
      const swarm = this.swarm
      await this._awaitOwnerOperation(swarm, 'swarm.destroy', () => swarm.destroy(), timeout)
      if (this.swarm === swarm) this.swarm = null
    }
    if (this.swarmFirewall) {
      try { this.swarmFirewall.destroy() } catch (_) {}
      this.swarmFirewall = null
    }
    if (this.store) {
      const store = this.store
      await this._awaitOwnerOperation(store, 'store.close', () => store.close(), timeout)
    }

    this.running = false
    this._startupRollbackPending = false
    this._ownerDeadline = null
    this.emit('stopped')
  }
}
