/**
 * Default configuration for HiveRelay nodes
 */

export default {
  productProfile: 'relay-core',

  // Node identity
  storage: './hiverelay-storage',

  // Network
  // When null, uses HyperDHT defaults (node1-3.hyperdht.org:49737).
  // The bootstrap cache merges cached peers with these nodes so that
  // new nodes can still join the network if the hardcoded bootstrap
  // nodes are unreachable.
  bootstrapNodes: null,
  // Bound the initial DHT announcement flush so the local API/dashboard can
  // come up even when public bootstrap is slow; the joined swarm continues
  // discovery after startup.
  dhtFlushTimeoutMs: 1000,
  maxConnections: 256,

  // Bootstrap cache — persists DHT peers to disk so nodes can rejoin
  // the network even when the default bootstrap servers are down.
  bootstrapCacheEnabled: true,
  bootstrapCachePeers: 50,

  // Seeding
  enableSeeding: true,
  // Legacy ceiling for an unset cap. CLI startup resolves an unset value
  // against exact-filesystem available bytes + reserve; explicit values keep
  // their exact operator designation even when equal to 50 GiB.
  maxStorageBytes: 50 * 1024 * 1024 * 1024,
  announceInterval: 15 * 60 * 1000, // 15 minutes

  // Circuit relay
  enableRelay: true,
  maxRelayBandwidthMbps: 100,
  maxCircuitDuration: 10 * 60 * 1000, // 10 minutes
  maxCircuitBytes: 64 * 1024 * 1024, // 64 MB per circuit
  maxCircuitsPerPeer: 5,
  maxCircuitRateBytesPerSecond: 1024 * 1024, // 1 MiB/s per circuit
  reservationTTL: 60 * 60 * 1000, // 1 hour

  // Proof of relay
  proofMaxLatencyMs: 5000,
  proofChallengeInterval: 5 * 60 * 1000, // 5 minutes
  proofMaxPendingChallenges: 2048,
  proofMaxBatchSize: 64,

  // Reputation
  reputationDecayRate: 0.995, // Daily
  minChallengesForRanking: 10,

  // Metrics & API
  enableMetrics: true,
  enableAPI: true,
  apiPort: 9100,
  apiHost: '0.0.0.0',
  corsOrigins: [],
  strictSeedingPrivacy: true,
  enableDistributedDriveBridge: false,

  // Management UI authentication.
  //
  // When `exposeToken` is true, the relay embeds its management token
  // into the dashboard/wizard HTML it serves, and the browser UI sends
  // it back as `Authorization: Bearer <token>`. This lets the UI
  // authenticate when it is reached through a trusted, authenticating
  // reverse proxy (e.g. Umbrel's app_proxy) — where the localhost check
  // can never apply, because the proxy connects from its own address.
  //
  // SECURITY: only enable this when the API port is reachable *solely*
  // through such a proxy and is NEVER published to the host/LAN. Any
  // client that can load the page can read the token. Off by default so
  // direct/localhost and reverse-proxy-without-this-mode deployments are
  // entirely unaffected.
  ui: {
    exposeToken: false,
    // Simple mode serves a single-page, appliance-style dashboard
    // (dashboard/blindspark.html) instead of the full multi-tab operator
    // UI — no Docs/GitHub, no payments/calculator/leaderboard tabs, just
    // identity + live status. Enabled for the Blindspark Umbrel packaging
    // via HIVERELAY_UI_SIMPLE; off by default so PC node operators and
    // devs get the full dashboard.
    simple: false
  },

  // Operator subsidy (Phase 1 — accrual + signed claims only; no money
  // moves through the relay). When enabled, the node accrues a capped
  // sats ESTIMATE for blind-peer work and exports an Ed25519-signed
  // claim the subsidy coordinator independently verifies and pays to
  // `payoutDestination` (lightning address, BOLT12 offer, or on-chain
  // address — the operator's own; the relay never holds funds). See
  // incentive/subsidy/index.js + docs/OPERATOR-INCENTIVES-Y1.md Prong 2.
  subsidy: {
    enabled: false,
    rateSatsPerDay: 500, // cap ≈ $180/yr at $100k/BTC; coordinator-gated
    epochMs: 10 * 60 * 1000,
    payoutDestination: null
  },

  // Paid pin-lease (demand side). Off by default — self-host never charges.
  // When enabled, publisher-signed seeds (POST /api/v1/seed, NOT operator
  // POST /seed) must pay a byte-days lease; funds settle to the operator's
  // OWN LN node (zero-custody) and the lease is enforced by the existing
  // custody-expiry sweep. Custody/social-recovery seeds are exempt. See
  // incentive/lease/index.js + the payment-for-seeding design.
  lease: {
    enabled: false,
    satsPerGiBDay: 10, // price = ceil(maxStorageBytes/GiB) * leaseDays * this
    maxSatsPerGiBDay: 1_000_000, // ceiling for the runtime-settable rate
    quoteTtlMs: 60 * 60 * 1000, // 1h to pay; aligned with invoice expiry
    minLeaseDays: 1,
    maxLeaseDays: 3650,
    provider: 'mock' // 'mock' (test/demo) | 'lightning' (operator's own node)
  },

  // Blind custody is the default relay posture. Relays may mirror public
  // content, but custody receipts/proofs must be for encrypted material unless
  // an operator explicitly enables transparent custody.
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

  // Storage accounting — always-on paced measurement of real per-drive
  // on-disk bytes (the input for the repair storage guard, eviction
  // ranking, and the dashboard Storage panel). ~batchSize drives are
  // stat()ed every tickMs; defaults walk ~1,200 drives in ~4 minutes.
  storageAccounting: {
    tickMs: 5000,
    batchSize: 25
  },

  // Over-replication eviction (Phase A). OFF by default. Under disk
  // pressure, sheds entries the network holds ≥ floorMargin replicas
  // above their target — never archive-tier (durability ≥ 1), never
  // custody-bound, never younger than minAgeMs, never below the floor
  // (deterministic stagger prevents simultaneous shedding). Bytes are
  // actually reclaimed via drive purge; tombstones stop boot-replay and
  // repair from resurrecting shed entries unless the network falls under
  // floor. See core/relay-node/eviction.js.
  eviction: {
    enabled: false,
    diskPressurePct: 80,
    resumePct: 70,
    floorMargin: 1,
    minAgeMs: 3 * 24 * 60 * 60 * 1000,
    sweepIntervalMs: 10 * 60 * 1000,
    maxEvictionsPerSweep: 20
  },

  // Seeding registry
  registryKey: null, // null = create new autobase
  registryScanInterval: 60_000, // 1 minute
  registryAutoAccept: true, // Auto-accept matching seed requests (false = approval mode)
  targetReplicaFloor: 2,
  replicationCheckInterval: 60_000,
  replicationRepairEnabled: true,

  // Catalog and gateway trust policy
  gatewayPublicOnlyPrivacyTier: true,
  gatewayPort: null,
  // A public HTTPS edge terminates TLS and talks to this loopback-only data
  // plane. Never expose the plaintext compatibility listener directly.
  gatewayHost: '127.0.0.1',
  gatewayTrustProxy: false,
  gatewayTrustedProxyAddresses: ['127.0.0.1', '::1', '::ffff:127.0.0.1'],
  gatewayRequireForwardedSNI: false,
  gatewayCompatibilityHosts: ['127.0.0.1', 'localhost', '[::1]'],
  gatewayMaxInFlight: 256,
  gatewayMaxInFlightPerApp: 32,
  // V-GW1 finite production policy. Public HTTPS preflight additionally
  // requires these exact values to be present explicitly in config.json so a
  // deployment never relies on constructor fallback behavior.
  gatewayMaxResponseBytes: 64 * 1024 * 1024,
  gatewayMaxTransformBytes: 4 * 1024 * 1024,
  gatewayEgressBytesPerWindow: 256 * 1024 * 1024,
  gatewayEgressWindowMs: 60 * 1000,
  gatewayMaxResponseLifetimeMs: 15 * 60 * 1000,
  // Optional DNS suffix for origin-isolated public app hosts on the dedicated
  // data-plane gateway, e.g. `hive.relay.example`. A 52-char z-base-32 app key
  // becomes `<key>.hive.relay.example`. Disabled until explicitly configured.
  hiveAppHostSuffix: null,
  // Transitional local T1 provenance gate. Only exact 64-hex app keys listed
  // here can use key-derived HTTPS hosts; registry defaults never grant access.
  // The blind-substrate role predicate replaces this scaffold allowlist.
  hiveAppPublicKeys: [],
  // Optional immutable Hyperdrive version per admitted app key. Production
  // public-gateway preflight requires an exact pin for every public origin.
  hiveAppPublicVersions: {},
  requireSignedCatalog: false,
  catalogSignatureMaxAgeMs: 5 * 60 * 1000,
  catalogMaxAppAgeMs: 30 * 24 * 60 * 60 * 1000,

  // Discovery / access mode controls
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
  serviceDefaultPeerRole: 'authenticated-user',
  serviceAdminAllowlist: [],
  enableServices: false,
  plugins: [],
  serviceSupervision: {
    enabled: true,
    intervalMs: 30_000,
    maxRestarts: 3
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
  federation: {
    enabled: false,
    followInterval: 5 * 60 * 1000,
    followed: [],
    mirrored: []
  },

  // Metadata-privacy controls. The relay is already blind to CONTENT; these
  // shrink the remaining CONNECTION-metadata surface. All default to the
  // privacy-preserving-but-non-degrading setting.
  privacy: {
    // Redact peer pubkeys in the public /api/peers payload to a per-process
    // salted digest. Authenticated operator views can still request raw keys.
    redactPeerIdentifiers: true,
    // Epoch-rotating discovery topics so a passive DHT observer can't
    // enumerate the relay set indefinitely from one vantage point.
    //   false      — static topic only (unchanged behaviour)
    //   'additive' — announce on BOTH static + rotating topics (back-compat +
    //                partial privacy; recommended transitional setting)
    //   'strict'   — rotating topics only (max unlinkability; legacy peers that
    //                only know the static topic won't discover this relay)
    rotateDiscoveryTopic: false
  },

  // Regions
  regions: [], // Empty = accept from all regions

  // Transports
  transports: {
    udp: true, // Always on (HyperDHT default)
    tor: false,
    i2p: false,
    websocket: false,
    holesail: false
  },
  wsPort: 8765,

  // Holesail API tunnel (for relays behind NAT)
  holesail: {
    host: '127.0.0.1'
  },

  // Tor hidden service
  tor: {
    socksHost: '127.0.0.1',
    socksPort: 9050,
    controlHost: '127.0.0.1',
    controlPort: 9051,
    controlPassword: null,
    cookieAuthFile: '/var/lib/tor/control_auth_cookie'
  },

  // Lightning payments
  lightning: {
    enabled: false,
    rpcUrl: 'localhost:10009',
    macaroonPath: null,
    certPath: null,
    network: 'mainnet'
  },

  // Payment settlement
  payment: {
    enabled: false,
    settlementInterval: 24 * 60 * 60 * 1000, // daily
    minSettlementSats: 1000
  },

  // Shutdown
  shutdownTimeoutMs: 10_000
}
