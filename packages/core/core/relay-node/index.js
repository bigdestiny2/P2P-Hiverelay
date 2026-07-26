import Hyperswarm from 'hyperswarm'
import Corestore from 'corestore'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { EventEmitter } from 'events'
import { readFile, writeFile, mkdir, chmod } from 'fs/promises'
import { join } from 'path'
import { Seeder } from './seeder.js'
import { Relay } from './relay.js'
import { Metrics } from './metrics.js'
import { RelayAPI } from './api.js'
import { DistributedDriveBridge } from './distributed-drive-bridge.js'
import { WebSocketTransport } from '../../transports/websocket/index.js'
import { DHTRelayWS } from '../../transports/dht-relay-ws/index.js'
import { TorTransport } from '../../transports/tor/index.js'
import { HolesailTransport } from '../../transports/holesail/index.js'
import http from 'http'
import { BootstrapCache } from '../bootstrap-cache.js'
import { Federation } from '../federation.js'
import { AutoHeal } from '../auto-heal.js'
import { ManifestStore } from '../manifest-store.js'
import { resolveAcceptMode, decideAcceptance } from '../accept-mode.js'
import { SeedProtocol } from '../protocol/seed-request.js'
import { AnchorProtocol } from '../protocol/anchor-channel.js'
import { CustodyProtocol } from '../protocol/custody-channel.js'
import { PublishProtocol } from '../protocol/publish-channel.js'
import { verifyDelegationCert, verifyRevocation } from '../delegation.js'
import { CircuitRelay } from '../protocol/relay-circuit.js'
import { ProofOfRelay } from '../protocol/proof-of-relay.js'
import { BandwidthReceipt } from '../protocol/bandwidth-receipt.js'
import { ReputationSystem } from '../../incentive/reputation/index.js'
import { NetworkDiscovery } from '../network-discovery.js'
import { HealthMonitor } from './health-monitor.js'
import { AlertManager } from './alert-manager.js'
import { SelfHeal } from './self-heal.js'
import { AccessControl } from './access-control.js'
import { SeedingRegistry } from '../registry/index.js'
import { ServiceRegistry, ServiceProtocol } from '../services/index.js'
// Builtin services live in the p2p-hiveservices package and are loaded at
// runtime via PluginLoader when an operator opts in (config.plugins).
// Core no longer hardcodes Services constructors.
import { PluginLoader } from '../plugin-loader.js'
import { Router } from '../router/index.js'
import { AppRegistry } from '../app-registry.js'
import {
  RELAY_DISCOVERY_TOPIC,
  FOUNDATION_TOPIC,
  isValidHexKey,
  normalizeAvailabilityClass,
  normalizePrivacyTier,
  normalizeStorageClass
} from '../constants.js'
import { SwarmFirewall } from './swarm-firewall.js'
import { PolicyGuard } from '../policy-guard.js'
import { AppLifecycle } from './app-lifecycle.js'
import { GatewayServer } from './gateway-server.js'

const DEFAULT_CONFIG = {
  productProfile: 'relay-core',
  storage: './storage',
  maxStorageBytes: 50 * 1024 * 1024 * 1024, // 50 GB
  maxConnections: 256,
  maxRelayBandwidthMbps: 100,
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
  requireSignedCatalog: false,
  catalogSignatureMaxAgeMs: 5 * 60 * 1000,
  catalogMaxAppAgeMs: 30 * 24 * 60 * 60 * 1000,
  // Catalog accept-mode controls how inbound seed requests are handled.
  //   'open'      — auto-accept every signed seed request (legacy behaviour)
  //   'review'    — queue seed requests for operator approval (default)
  //   'allowlist' — auto-accept only requests from publishers in acceptAllowlist
  //   'closed'    — reject all inbound seed requests; operator-initiated seeds only
  // Left undefined here so deprecated `registryAutoAccept` can still be honored
  // when callers haven't migrated. Default mode is decided in `_resolveAcceptMode`.
  acceptMode: undefined,
  acceptAllowlist: [], // array of publisher pubkeys (hex) — only used when acceptMode === 'allowlist'
  // P2P service auth defaults. Noise-session peers are treated as authenticated
  // users by default; operators can promote selected pubkeys to relay-admin.
  serviceDefaultPeerRole: 'authenticated-user',
  serviceAdminAllowlist: [],
  enableServices: false,
  plugins: [],
  serviceSupervision: {
    enabled: true,
    intervalMs: 30_000,
    maxRestarts: 3
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
  shutdownTimeoutMs: 10_000,
  enableEviction: true,
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

  return {
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
    }
  }
}

function withTimeout (promise, ms, label) {
  let timer
  return Promise.race([
    promise.finally(() => clearTimeout(timer)),
    new Promise((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms)
    })
  ])
}

export class RelayNode extends EventEmitter {
  constructor (opts = {}) {
    super()
    this.mode = opts.mode || opts.productProfile || 'relay-core'
    this.config = buildConfig(this.mode, opts)
    this._operatingMode = this.mode
    this.store = new Corestore(this.config.storage)
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
    this.appRegistry = new AppRegistry(this.config.storage)
    this.appLifecycle = new AppLifecycle(this)
    // Forward lifecycle events so existing listeners on RelayNode keep working
    for (const ev of ['seeding', 'unseeded', 'reseeded', 'reseed-error', 'app-replaced', 'app-version-rejected']) {
      this.appLifecycle.on(ev, (payload) => this.emit(ev, payload))
    }
    this.connections = new Map() // conn -> { lastActivity }
    this._healthCheckInterval = null
    this.bootstrapCache = new BootstrapCache(this.config.storage, {
      enabled: this.config.bootstrapCacheEnabled !== false,
      maxPeers: this.config.bootstrapCachePeers || 50
    })
    this.reputation = new ReputationSystem()
    this._proofOfRelay = null
    this._bandwidthReceipt = null
    this._reputationDecayInterval = null
    this._reputationSaveInterval = null
    this.networkDiscovery = null
    this.healthMonitor = null
    this.alertManager = null
    this.selfHeal = null
    this.seedingRegistry = null
    this.distributedDriveBridge = null
    this._registryScanInterval = null
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
    this._lastAnchorCheckAt = null
    this._repairInterval = null
    this._lastRepairAt = null
    this._custodyExpiryInterval = null
    this._lastCustodyExpiryAt = null
    this.running = false
  }

  // Backwards compat: expose the seeded apps Map owned by AppLifecycle.
  get seededApps () {
    return this.appLifecycle.seededApps
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
      'pairing'
    ]) {
      delete carry[key]
    }

    const nextConfig = buildConfig(mode, {
      ...carry,
      ...overrides,
      mode
    })

    this.mode = mode
    this._operatingMode = mode
    this.config = nextConfig

    if (this.running) {
      await this._syncAccessControl()
    }

    return this.config
  }

  async start () {
    if (this.running) return

    try {
      // Re-create store if it was closed (e.g. after self-heal restart)
      if (this.store.closed) {
        this.store = new Corestore(this.config.storage)
      }
      await this.store.ready()

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
      this.swarm.on('connection', (conn, info) => this._onConnection(conn, info))

      // Announce on the global discovery topic. (Region-sharded topics are
      // available via regionTopic(code) but not auto-joined at current scale —
      // splitting <10 relays across regions reduces discovery, not load.
      // Will revisit when N grows.)
      this.swarm.join(RELAY_DISCOVERY_TOPIC, { server: true, client: false })

      // Foundation relays (operator-of-last-resort) opt-in by setting
      // config.foundation = true — gives quorum-pinned clients a stable
      // floor to discover without scanning the full DHT.
      if (this.config.foundation === true) {
        this.swarm.join(FOUNDATION_TOPIC, { server: true, client: false })
      }

      // Initialize subsystems in parallel where possible
      const startups = []

      if (this.config.enableSeeding) {
        this.seeder = new Seeder(this.store, this.swarm, {
          maxStorageBytes: this.config.maxStorageBytes,
          announceInterval: this.config.announceInterval
        })
        startups.push(this.seeder.start())

        if (this.config.enableDistributedDriveBridge !== false) {
          this.distributedDriveBridge = new DistributedDriveBridge({ enabled: true })
          this.distributedDriveBridge.on('warning', (details) => this.emit('distributed-drive-warning', details))
          startups.push(this.distributedDriveBridge.start())
        }
      }

      if (this.config.enableRelay) {
        this.relay = new Relay(this.swarm, {
          maxBandwidthMbps: this.config.maxRelayBandwidthMbps,
          maxConnections: this.config.maxConnections
        })
        startups.push(this.relay.start())
      }

      // Initialize protocol handlers for seed requests and circuit relay
      this._seedProtocol = new SeedProtocol(this.swarm, {
        keyPair: this.swarm.keyPair
      })
      this._seedProtocol.on('seed-request', (msg) => this._onSeedRequest(msg))
      this._seedProtocol.on('unseed-request', (msg) => this._onUnseedRequest(msg))

      if (this.relay) {
        this._circuitRelay = new CircuitRelay(this.swarm, this.relay, {
          maxCircuitsPerPeer: this.config.maxCircuitsPerPeer || 5
        })
      }

      // Initialize proof-of-relay challenge system
      this._proofOfRelay = new ProofOfRelay({
        maxLatencyMs: this.config.proofMaxLatencyMs || 5000,
        challengeInterval: this.config.proofChallengeInterval || 300000
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
          trustProxy: this.config.trustProxy || false
        })
        startups.push(this.api.start())

        // Optional separate gateway server for data-plane traffic.
        // When gatewayPort is set AND different from apiPort, spin up a
        // dedicated HTTP server that only serves /v1/hyper/* and /catalog.json.
        // This prevents heavy file traffic from starving the management API.
        const gatewayPort = this.config.gatewayPort
        if (gatewayPort && gatewayPort !== (this.config.apiPort || 9100)) {
          this.gatewayServer = new GatewayServer(this, {
            gatewayPort,
            gatewayHost: this.config.gatewayHost || '0.0.0.0',
            corsOrigins: this.config.corsOrigins,
            trustProxy: this.config.trustProxy || false,
            // Share the HyperGateway instance with RelayAPI to avoid duplicate state
            gateway: this.api._gateway
          })
          startups.push(this.gatewayServer.start())
        }
      }

      // Flush DHT + start subsystems concurrently
      startups.push(this.swarm.flush())
      await Promise.all(startups)

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
        this.dhtRelayWs = new DHTRelayWS({
          dht: this.swarm.dht,
          port: this.config.dhtRelayWsPort || 8766,
          host: this.config.dhtRelayWsHost,
          maxConnections: this.config.maxConnections
        })
        this.dhtRelayWs.on('relay-error', (info) => this.emit('dht-relay-error', info))
        await this.dhtRelayWs.start()
      }

      if (this.config.transports && this.config.transports.tor) {
        const torOpts = this.config.tor || {}
        this.torTransport = new TorTransport({
          socksHost: torOpts.socksHost,
          socksPort: torOpts.socksPort,
          controlHost: torOpts.controlHost,
          controlPort: torOpts.controlPort,
          controlPassword: torOpts.controlPassword,
          cookieAuthFile: torOpts.cookieAuthFile,
          localPort: this.config.apiPort || 9100
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
      if (this.config.enableServices !== false && this.config.plugins) {
        this.serviceRegistry = new ServiceRegistry()
        this.serviceProtocol = new ServiceProtocol(this.serviceRegistry, {
          defaultPeerRole: this.config.serviceDefaultPeerRole || 'authenticated-user'
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
        this._serviceContext = { node: this, store: this.store, config: this.config }
        const startupResult = await this.serviceRegistry.startAll(this._serviceContext)
        if (startupResult.failed.length > 0 && this.config.servicesFailOpen !== true) {
          const names = startupResult.failed.map(s => s.name).join(', ')
          throw new Error(`SERVICE_START_FAILED: ${names}`)
        }
        this._startServiceSupervision()

        // Set up seeded apps callback for catalog broadcast
        this.serviceProtocol._getSeededApps = () => this.appRegistry.catalogForBroadcast()
        this.serviceProtocol._getCatalogEnvelope = () => {
          const apps = this.appRegistry.catalogForBroadcast()
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
            const storagePctUsed = (this.seeder && this.config.maxStorageBytes > 0)
              ? (this.seeder.totalBytesStored / this.config.maxStorageBytes)
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
                this.seedApp(appKey, {
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
                  description: app.description || ''
                }).then(() => {
                  this.emit('catalog-sync', {
                    appKey,
                    source: isMirrored ? 'mirror' : 'follow-anchored',
                    sourceRelay: relayPubkey
                  })
                }).catch((err) => {
                  this.emit('catalog-sync-error', { appKey, error: err.message })
                })
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
                availabilityClass: app.availabilityClass || null
              }
              const decision = this._decideAcceptance(synthRequest, acceptMode)
              if (decision === 'reject') {
                this.emit('catalog-sync-rejected', { appKey, source: 'remote-catalog', mode: acceptMode })
                continue
              }
              if (decision === 'accept') {
                acted++
                this.seedApp(appKey, {
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
                  description: app.description || ''
                }).then(() => {
                  this.emit('catalog-sync', { appKey, source: 'remote-catalog', mode: acceptMode })
                }).catch((err) => {
                  this.emit('catalog-sync-error', { appKey, error: err.message })
                })
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
            registryKey: this.config.registryKey || null
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
          this._publishProtocol = new PublishProtocol({
            onSubmitIntent: async (body) => {
              const entry = await this.seedingRegistry.publishCustodyIntent(body, null)
              return { ok: true, result: entry }
            },
            onSubmitCommit: async (body) => {
              const entry = await this.seedingRegistry.publishCustodyCommit(body, null)
              return { ok: true, result: entry }
            },
            onSubmitSourceRetired: async (body) => {
              const entry = await this.seedingRegistry.publishSourceRetired(body, null)
              return { ok: true, result: entry }
            }
            // onSubmitSeed: intentionally omitted in v1 — the seed-request
            // validation + seedApp opts assembly currently lives inline in
            // api.js's /api/v1/seed handler. A follow-up extracts that into
            // a shared helper so both transports use the same code path.
            // Until then, the channel returns a typed
            //   { ok: false, error: "submit kind 'seed' not configured ..." }
            // so clients fail fast instead of waiting on a timeout.
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
            this._scanRegistry().catch((err) => {
              this.emit('registry-error', { error: err })
            })
          }, scanInterval)
          if (this._registryScanInterval.unref) this._registryScanInterval.unref()

          // Run initial scan after a short delay to let the registry sync
          setTimeout(() => {
            this._scanRegistry().catch(() => {})
          }, 5000)

          this._startReplicationMonitor()
          this._startAnchorMonitor()
          this._startRepairMonitor()

          // Cold-start primer — runs once after a brief delay so the
          // swarm has a chance to come up before we start fetching peer
          // catalogs over HTTPS. Fire-and-forget; failures don't block
          // start.
          if (Array.isArray(this.config.coldStartRelays) && this.config.coldStartRelays.length > 0) {
            setTimeout(() => {
              this._runColdStartPrimer().catch((err) => {
                this.emit('cold-start-error', { error: err.message || String(err) })
              })
            }, 15_000)
          }
        } catch (err) {
          this.emit('registry-error', { error: err })
          this.seedingRegistry = null
        }
      }

      this._startCustodyExpiryMonitor()

      // Load app registry from disk and reseed all persisted apps
      this._reseedFromRegistry().catch((err) => {
        this.emit('reseed-error', { error: err })
      })

      // Start network discovery — shares this node's swarm to discover other relays
      this.networkDiscovery = new NetworkDiscovery({ swarm: this.swarm })
      this.networkDiscovery.start().catch(() => {})

      // Periodic revocation-store sweep — evict entries whose certs would
      // have naturally expired. Hour-level cadence is plenty; interval is
      // unref'd so it never blocks shutdown.
      this._revocationSweepInterval = setInterval(() => {
        this._sweepRevocations()
      }, 60 * 60 * 1000)
      if (this._revocationSweepInterval.unref) this._revocationSweepInterval.unref()

      // Federation — opt-in cross-relay catalog sharing. Always-on as a manager
      // so /api/manage/federation can mutate it; the polling loop only runs
      // if the operator has actually followed any relays.
      this.federation = new Federation({
        node: this,
        followInterval: this.config.federation?.followInterval,
        followed: this.config.federation?.followed || [],
        mirrored: this.config.federation?.mirrored || [],
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

      this.running = true

      // Start health monitoring and self-healing
      this.healthMonitor = new HealthMonitor(this, this.config.healthMonitor)
      this.selfHeal = new SelfHeal(this, this.config.selfHeal)
      this.selfHeal.start(this.healthMonitor)
      this.healthMonitor.on('health-warning', (details) => this.emit('health-warning', details))
      this.healthMonitor.on('health-critical', (details) => this.emit('health-critical', details))
      this.selfHeal.on('self-heal-action', (action) => this.emit('self-heal-action', action))
      this.healthMonitor.start()

      // Start alert manager (if configured) — wires to health monitor + subsystems
      if (this.config.alerts?.enabled) {
        this.alertManager = new AlertManager(this, this.config.alerts)
      }

      this.emit('started', { publicKey: this.swarm.keyPair.publicKey })

      // Auto-enable holesail if API is not publicly reachable
      if (!this.holesailTransport && this.config.enableAPI) {
        this._autoEnableHolesail().catch(() => {})
      }
    } catch (err) {
      // Rollback in reverse order
      this.bootstrapCache.stop()
      if (this._catalogThrottleCleanup) { clearInterval(this._catalogThrottleCleanup); this._catalogThrottleCleanup = null }
      if (this._reputationSaveInterval) { clearInterval(this._reputationSaveInterval); this._reputationSaveInterval = null }
      if (this._reputationDecayInterval) { clearInterval(this._reputationDecayInterval); this._reputationDecayInterval = null }
      if (this._registryScanInterval) { clearInterval(this._registryScanInterval); this._registryScanInterval = null }
      if (this._replicationCheckInterval) { clearInterval(this._replicationCheckInterval); this._replicationCheckInterval = null }
      if (this._anchorCheckInterval) { clearInterval(this._anchorCheckInterval); this._anchorCheckInterval = null }
      if (this._repairInterval) { clearInterval(this._repairInterval); this._repairInterval = null }
      if (this._custodyExpiryInterval) { clearInterval(this._custodyExpiryInterval); this._custodyExpiryInterval = null }
      if (this._serviceSupervisionInterval) { clearInterval(this._serviceSupervisionInterval); this._serviceSupervisionInterval = null }
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
      if (this.seeder) { try { await this.seeder.stop() } catch (_) {} this.seeder = null }
      if (this.swarm) { try { await this.swarm.destroy() } catch (_) {} this.swarm = null }
      if (this.swarmFirewall) { try { this.swarmFirewall.destroy() } catch (_) {} this.swarmFirewall = null }
      if (this.accessControl) { try { this.accessControl.disablePairing() } catch (_) {} this.accessControl = null }
      this.running = false
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

  async unseedApp (appKeyHex) {
    return this.appLifecycle.unseedApp(appKeyHex)
  }

  verifyUnseedRequest (appKeyHex, publisherPubkeyHex, signatureHex, timestamp) {
    return this.appLifecycle.verifyUnseedRequest(appKeyHex, publisherPubkeyHex, signatureHex, timestamp)
  }

  broadcastUnseed (appKeyHex, publisherPubkeyHex, signatureHex, timestamp) {
    return this.appLifecycle.broadcastUnseed(appKeyHex, publisherPubkeyHex, signatureHex, timestamp)
  }

  getStats () {
    const accessControlStats = this.accessControl
      ? {
          pairedDevices: this.accessControl.allowedDevices.size,
          rejectedConnections: this._rejectedConnections
        }
      : null
    const underReplicated = [...this._replicationHealth.values()].filter(v => v.state === 'under-replicated').length

    return {
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

  async pairDevice (token, devicePubkeyHex, deviceName = 'unknown') {
    if (!this.accessControl) {
      throw new Error('Access control is only available in private/hybrid/homehive mode')
    }
    return this.accessControl.attemptPair(token, devicePubkeyHex, deviceName)
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
    await new Promise(resolve => setTimeout(resolve, 15000))

    if (!this.running || this.holesailTransport) return

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

    if (!publicIp) return // can't determine, skip auto-detect

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
      await writeFile(keyPath, JSON.stringify({
        publicKey: b4a.toString(publicKey, 'hex'),
        secretKey: b4a.toString(secretKey, 'hex')
      }, null, 2))
      await chmod(keyPath, 0o600)
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
   * @param {object} [cfg.lnbits]      - { url, adminKey } for the LNbits payment provider
   */
  _applyWizardConfig (cfg) {
    if (!cfg || typeof cfg !== 'object') return
    if (typeof cfg.name === 'string' && cfg.name.length > 0) {
      this.config.name = cfg.name
    }
    if (typeof cfg.acceptMode === 'string') {
      this.config.acceptMode = cfg.acceptMode
    }
    if (cfg.lnbits && typeof cfg.lnbits === 'object') {
      this.config.lnbits = {
        url: cfg.lnbits.url || null,
        adminKey: cfg.lnbits.adminKey || null
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

  async _scanRegistry () {
    if (!this.seedingRegistry || !this.seeder) return

    const region = (this.config.regions && this.config.regions[0]) || null
    let availableBytes = this.config.maxStorageBytes - (this.seeder.totalBytesStored || 0)
    const acceptMode = this._resolveAcceptMode()

    const requests = await this.seedingRegistry.getActiveRequests({
      region,
      maxStorageBytes: availableBytes
    })

    const myPubkey = this.swarm ? b4a.toString(this.swarm.keyPair.publicKey, 'hex') : null

    for (const req of requests) {
      availableBytes = this.config.maxStorageBytes - (this.seeder.totalBytesStored || 0)
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
              availabilityClass: req.availabilityClass || null
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
        // Auto-accept: seed immediately ('open' or 'allowlist' hit)
        try {
          const publisherHex = typeof req.publisherPubkey === 'string'
            ? req.publisherPubkey
            : (req.publisherPubkey ? b4a.toString(req.publisherPubkey, 'hex') : null)
          await this.seedApp(req.appKey, {
            publisherPubkey: publisherHex,
            type: req.contentType || req.type || 'app',
            parentKey: req.parentKey || null,
            mountPath: req.mountPath || null,
            privacyTier: req.privacyTier || 'public',
            blind: req.blind === true,
            storageClass: req.storageClass || null,
            availabilityClass: req.availabilityClass || null
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

    await this.seedApp(appKeyHex, {
      publisherPubkey: typeof req.publisherPubkey === 'string' ? req.publisherPubkey : null,
      type: req.contentType || req.type || 'app',
      parentKey: req.parentKey || null,
      mountPath: req.mountPath || null,
      privacyTier: req.privacyTier || 'public',
      blind: req.blind === true,
      storageClass: req.storageClass || null,
      availabilityClass: req.availabilityClass || null
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

  _onSeedRequest (msg) {
    if (!this.seeder) return

    const appKeyHex = b4a.toString(msg.appKey, 'hex')
    const availableBytes = this.config.maxStorageBytes - this.seeder.totalBytesStored

    // Check capacity
    if (availableBytes < msg.maxStorageBytes) {
      this.emit('seed-rejected', { appKey: appKeyHex, reason: 'insufficient storage' })
      return
    }

    const acceptMode = this._resolveAcceptMode()
    const decision = this._decideAcceptance(msg, acceptMode)
    if (decision === 'reject') {
      this.emit('seed-rejected', { appKey: appKeyHex, reason: 'acceptMode:' + acceptMode })
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
        maxStorageBytes: msg.maxStorageBytes || 0,
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
        return
      }
      effectivePublisher = delegationCheck.primaryPubkey
    }

    // Accept and start seeding
    this._seedProtocol.acceptSeedRequest(
      msg.appKey,
      this.swarm.keyPair.publicKey,
      (this.config.regions && this.config.regions[0]) || 'unknown',
      availableBytes
    )

    // Seed the app via AppRegistry (creates Hyperdrive + registers properly).
    // Propagate the publisher's revocability commitments — both fields are
    // signed into the seed request payload, so the publisher cannot lie about
    // them at unseed time. AppLifecycle records them on the registry entry
    // and verifyUnseedRequest enforces them.
    const publisherHex = msg.publisherPubkey
      ? (typeof msg.publisherPubkey === 'string' ? msg.publisherPubkey : b4a.toString(msg.publisherPubkey, 'hex'))
      : null
    this.seedApp(appKeyHex, {
      publisherPubkey: effectivePublisher || publisherHex,
      revocable: msg.revocable !== false,
      unseedFreezeMs: msg.unseedFreezeMs || 0,
      durability: msg.durability || 0,
      blind: msg.blind === true,
      storageClass: msg.storageClass || null,
      availabilityClass: msg.availabilityClass || null
    }).catch((err) => {
      this.emit('seed-error', { appKey: appKeyHex, error: err })
    })

    // Also seed any additional discovery keys
    for (const dk of (msg.discoveryKeys || [])) {
      const keyHex = b4a.toString(dk, 'hex')
      if (keyHex !== appKeyHex) {
        this.seeder.seedCore(keyHex).catch((err) => {
          this.emit('seed-error', { appKey: appKeyHex, core: keyHex, error: err })
        })
      }
    }

    this.emit('seed-accepted', { appKey: appKeyHex })
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

  _scheduleCatalogBroadcast () {
    if (this._catalogBroadcastTimer) clearTimeout(this._catalogBroadcastTimer)
    this._catalogBroadcastTimer = setTimeout(() => {
      this._catalogBroadcastTimer = null
      this.serviceProtocol?.broadcastAppCatalog()
    }, 5000)
  }

  _startReplicationMonitor () {
    if (this._replicationCheckInterval) {
      clearInterval(this._replicationCheckInterval)
      this._replicationCheckInterval = null
    }

    const intervalMs = Math.max(10_000, Number(this.config.replicationCheckInterval) || 60_000)
    this._replicationCheckInterval = setInterval(() => {
      this._checkReplicationHealth().catch((err) => {
        this.emit('replication-error', { error: err.message || String(err) })
      })
    }, intervalMs)
    if (this._replicationCheckInterval.unref) this._replicationCheckInterval.unref()

    this._checkReplicationHealth().catch(() => {})
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
      this._runAnchorCheck().catch((err) => {
        this.emit('anchor-check-error', { error: err.message || String(err) })
      })
    }, intervalMs)
    if (this._anchorCheckInterval.unref) this._anchorCheckInterval.unref()

    setTimeout(() => {
      this._runAnchorCheck().catch(() => {})
    }, 5000)
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
      this._runRepairPass().catch((err) => {
        this.emit('repair-error', { error: err.message || String(err) })
      })
    }, intervalMs)
    if (this._repairInterval.unref) this._repairInterval.unref()

    // First pass shortly after startup so we attempt to recover ghost
    // entries from the previous run.
    setTimeout(() => {
      this._runRepairPass().catch(() => {})
    }, 30_000)
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
      this._runServiceSupervisionPass().catch((err) => {
        this.emit('service-supervision-error', { error: err.message || String(err) })
      })
    }, intervalMs)
    if (this._serviceSupervisionInterval.unref) this._serviceSupervisionInterval.unref()
  }

  async _runServiceSupervisionPass () {
    if (!this.serviceRegistry) return { checked: 0, restarted: 0, failed: 0, skipped: 0 }

    const cfg = this.config.serviceSupervision || {}
    const maxRestarts = Number.isFinite(cfg.maxRestarts) ? Math.max(0, Math.floor(cfg.maxRestarts)) : 3
    let checked = 0
    let restarted = 0
    let failed = 0
    let skipped = 0

    for (const [name, entry] of this.serviceRegistry.services) {
      checked++

      if (entry.status === 'running') {
        const healthy = await this._checkServiceHealth(entry)
        if (healthy) continue
        this.serviceRegistry.markFailed(name, new Error('health check failed'))
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
        await this.serviceRegistry.restart(name, this._serviceContext || { node: this, store: this.store, config: this.config })
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

  async _checkServiceHealth (entry) {
    const provider = entry?.provider
    if (!provider) return false
    const context = this._serviceContext || { node: this, store: this.store, config: this.config }
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
    this._custodyExpiryInterval = setInterval(() => {
      this._runCustodyExpiryPass().catch((err) => {
        this.emit('custody-expiry-error', { error: err.message || String(err) })
      })
    }, intervalMs)
    if (this._custodyExpiryInterval.unref) this._custodyExpiryInterval.unref()

    setTimeout(() => {
      this._runCustodyExpiryPass().catch(() => {})
    }, 5000)
  }

  _isTemporaryCustodyEntry (entry) {
    if (!entry) return false
    const storageClass = normalizeStorageClass(entry.storageClass, entry.blind ? 'temporary' : 'persistent')
    const availabilityClass = normalizeAvailabilityClass(entry.availabilityClass, entry.blind ? 'atomic-handoff' : 'always-on')
    return storageClass === 'temporary' ||
      availabilityClass === 'atomic-handoff' ||
      (entry.blind === true && Number.isFinite(entry.retainUntil))
  }

  async _runCustodyExpiryPass (now = Date.now()) {
    if (!this.appRegistry) return { checked: 0, expired: 0, skipped: 0 }

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
      const retainUntil = Number(entry.retainUntil)
      if (!Number.isFinite(retainUntil) || retainUntil <= 0) {
        skipped++
        continue
      }
      if ((retainUntil + graceMs) <= now) {
        expiredKeys.push({ appKey, retainUntil })
      }
    }

    let expired = 0
    for (const { appKey, retainUntil } of expiredKeys) {
      try {
        await this.unseedApp(appKey)
        expired++
        this.emit('custody-expired', { appKey, retainUntil, at: now })
      } catch (err) {
        this.emit('custody-expiry-error', { appKey, error: err.message || String(err) })
      }
    }

    this._lastCustodyExpiryAt = now
    const result = { checked, expired, skipped }
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
      challengeNonce: opts.challengeNonce,
      retainUntil: opts.retainUntil ?? intent.retainUntil,
      notServing: true,
      notServingReason: opts.notServingReason || 'expired-unseeded',
      catalogPresent,
      activeSwarmServing
    }, this.swarm.keyPair)
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
              description: e.description || ''
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
    const entry = this.appRegistry.get(appKeyHex)
    if (!entry || entry.anchored === true) return
    // Fire-and-forget; runRepairPass will retry if this one fails
    this.appLifecycle.repairUnanchored(appKeyHex).catch(() => {})
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
        const length = drive.version || 0
        if (length > 0) {
          const wasAnchored = entry.anchored === true
          this.appRegistry.setAnchored(appKey, length)
          if (!wasAnchored && this.appLifecycle && typeof this.appLifecycle._recordCustodyReceipt === 'function') {
            await this.appLifecycle._recordCustodyReceipt(appKey, entry, length)
          }
          anchored++
        } else {
          // No blocks — clear anchored if it was set, record the check
          if (entry.anchored === true) {
            this.appRegistry.clearAnchored(appKey, 'length=0 on periodic check')
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

    const availableBytes = this.config.maxStorageBytes - (this.seeder.totalBytesStored || 0)
    if (request.maxStorageBytes > 0 && request.maxStorageBytes > availableBytes) return false

    try {
      await this.seedApp(request.appKey, {
        publisherPubkey: effectivePublisher,
        type: request.contentType || request.type || 'app',
        parentKey: request.parentKey || null,
        mountPath: request.mountPath || null,
        privacyTier: request.privacyTier || 'public'
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

  async stop () {
    if (!this.running) return

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

    const timeout = this.config.shutdownTimeoutMs

    // Stop bootstrap cache and persist peers
    this.bootstrapCache.stop()
    try { await this.bootstrapCache.save() } catch (_) {}

    // Stop health checks, settlement, WebSocket, API, and metrics first
    if (this.selfHeal) { this.selfHeal.stop(); this.selfHeal = null }
    if (this.alertManager) { this.alertManager.stop(); this.alertManager = null }
    if (this.healthMonitor) { this.healthMonitor.stop(); this.healthMonitor = null }
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
      try { await this.serviceRegistry.stopAll() } catch (_) {}
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
    if (this._registryScanInterval) { clearInterval(this._registryScanInterval); this._registryScanInterval = null }
    if (this.seedingRegistry) { try { await this.seedingRegistry.stop() } catch (_) {} this.seedingRegistry = null }
    if (this.networkDiscovery) { try { await this.networkDiscovery.stop() } catch (_) {} this.networkDiscovery = null }
    if (this.autoHeal) { try { await this.autoHeal.stop() } catch (_) {} this.autoHeal = null }
    if (this.federation) { try { await this.federation.stop() } catch (_) {} this.federation = null }
    if (this.manifestStore) {
      // Persist any unsaved manifest updates before dropping the reference.
      try { await this.manifestStore.save() } catch (_) {}
      this.manifestStore.removeAllListeners()
      this.manifestStore = null
    }
    if (this._revocationSweepInterval) { clearInterval(this._revocationSweepInterval); this._revocationSweepInterval = null }
    if (this._proofOfRelay) { if (this._proofOfRelay.destroy) this._proofOfRelay.destroy(); this._proofOfRelay = null }
    if (this._bandwidthReceipt) { this._bandwidthReceipt.stop(); this._bandwidthReceipt = null }
    if (this._reputationSaveInterval) { clearInterval(this._reputationSaveInterval); this._reputationSaveInterval = null }
    if (this._reputationDecayInterval) { clearInterval(this._reputationDecayInterval); this._reputationDecayInterval = null }
    // Persist app registry before shutdown (flush debounced save)
    if (this.appRegistry) {
      try { await this.appRegistry.flush() } catch (_) {}
    }
    // Persist reputation before shutdown
    if (this.reputation) {
      try { await this.reputation.save(join(this.config.storage, 'reputation.json')) } catch (_) {}
    }

    // Unseed all apps
    for (const appKeyHex of this.seededApps.keys()) {
      try {
        await withTimeout(this.unseedApp(appKeyHex), timeout, `unseedApp(${appKeyHex.slice(0, 8)})`)
      } catch (_) {}
    }

    if (this.distributedDriveBridge) {
      try { await this.distributedDriveBridge.stop() } catch (_) {}
      this.distributedDriveBridge = null
    }

    if (this.relay) {
      try { await withTimeout(this.relay.stop(), timeout, 'relay.stop') } catch (_) {}
    }
    if (this.seeder) {
      try { await withTimeout(this.seeder.stop(), timeout, 'seeder.stop') } catch (_) {}
    }
    if (this.swarm) {
      try { await withTimeout(this.swarm.destroy(), timeout, 'swarm.destroy') } catch (_) {}
    }
    if (this.swarmFirewall) {
      try { this.swarmFirewall.destroy() } catch (_) {}
      this.swarmFirewall = null
    }
    if (this.store) {
      try { await withTimeout(this.store.close(), timeout, 'store.close') } catch (_) {}
    }

    this.running = false
    this.emit('stopped')
  }
}
