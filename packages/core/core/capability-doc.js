/**
 * HiveRelay capability advertisement.
 *
 * Returns a machine-readable JSON document describing this relay's identity,
 * version, accept policy, federation state, and operational limits. Clients
 * scan many relays' capability docs to pick which to talk to, without having
 * to speak Hypercore first. Served at:
 *
 *   GET /.well-known/hiverelay.json
 *
 * Shape is additive — unknown fields MUST be ignored by clients. Bump
 * `schemaVersion` only for breaking changes.
 *
 *   schemaVersion: 1  →  initial shape (v0.5.1)
 *
 * Depends only on b4a and which-runtime (both Bare-safe Holepunch modules)
 * so this helper imports cleanly under both Node and Bare runtimes.
 */

import b4a from 'b4a'
import { isBare } from 'which-runtime'
import sodium from 'sodium-universal'
import { resolveAcceptMode } from './accept-mode.js'
import {
  RELAYKERNEL_CIRCUIT_BYTES_HARD_CAP,
  RELAYKERNEL_CIRCUIT_FRAME_HARD_CAP,
  RELAYKERNEL_CIRCUIT_MAX_PER_PEER_HARD_CAP,
  RELAYKERNEL_CIRCUIT_RECOMMENDED_RATE_CAP_BPS,
  RELAYKERNEL_CIRCUIT_SESSION_HARD_CAP_MS,
  evaluateRelayKernelCircuitLimitsProfile
} from './protocol/relaykernel-circuit-limits-profile.js'

const PRIVACY_TRANSPORTS_FEATURE = 'privacy-transports-v1'
const ONION_ENDPOINT_ROTATION_MS = 90 * 24 * 60 * 60 * 1000

/**
 * privacyTransports — health-gated, signed advertisement of location-hidden
 * endpoints (hiverelay.onion/1). The entry exists ONLY while the transport
 * reports verified-ready health: a failed endpoint is removed, not annotated
 * (ONION-INV-003). The containing document is signed by the stable relay
 * identity, which is what binds the onion endpoint to this relay.
 */
function buildPrivacyTransports ({ relay, config, custodyEnabled }) {
  const tt = relay && relay.torTransport
  if (!tt || !tt.running || !tt.onionAddress) return []
  if (tt.health !== 'ready') return []

  const torCfg = (config && config.tor) || {}
  const supports = ['capabilities.get', 'catalog.read', 'replication.sync']
  if (hasRunningService(relay, 'notify')) supports.push('notify.send')
  if (hasRunningService(relay, 'outboxlog')) supports.push('outbox.wake', 'outbox.read')
  if (custodyEnabled) supports.push('custody.intent', 'custody.commit', 'custody.status', 'custody.proof.challenge')
  if (relay && relay._publishProtocol) supports.push('seed.publish')

  const notBefore = tt.startedAtMs || Date.now()
  const restrictedDiscovery = typeof tt.isRestrictedDiscoveryActive === 'function'
    ? tt.isRestrictedDiscoveryActive()
    : !!((tt.clientAuthKeys && tt.clientAuthKeys.length > 0) || tt.rosterFile)
  const authMode = restrictedDiscovery ? 'client-auth-v3' : 'none'
  const vports = typeof tt._effectiveVports === 'function' ? tt._effectiveVports() : [{ vport: 80 }]
  const vportRoles = {}
  if (vports[0]) vportRoles.readPlane = vports[0].vport
  if (vports[1]) vportRoles.peer = vports[1].vport

  return [{
    id: 'tor-v3-onion-v1',
    network: 'tor',
    protocol: 'hiverelay.onion/1',
    mode: 'hidden-service',
    addresses: [{
      address: tt.onionAddress,
      keyId: tt.endpointKeyId || torCfg.endpointKeyId || 'onion-endpoint-a',
      notBefore,
      notAfter: notBefore + ONION_ENDPOINT_ROTATION_MS,
      priority: 10
    }],
    vports: vports.map((v) => v.vport),
    vportRoles,
    auth: { mode: authMode, enrollment: authMode === 'client-auth-v3' ? ['pairing-channel'] : [] },
    pow: { enabled: !!(tt.pow && tt.pow.enabled) },
    exposure: torCfg.exposure || 'dual',
    relayLocation: 'hidden-onion',
    bootstrapModes: ['bundled', 'cached', 'protected-channel', 'bootstrap-linkable'],
    supports
  }]
}

const SCHEMA_VERSION = 1

// Signature envelope version, bumped independently of schemaVersion.
// Adding signing in v0.6.0 doesn't change the doc shape — clients that
// don't verify still parse the doc fine — so we don't bump schemaVersion.
const SIGNATURE_VERSION = 1
const CIRCUIT_LIMITS_PROFILE_FEATURE = 'circuit-limits-profile-v1'
const CORE_RETRIEVABILITY_HTTP_FEATURE = 'retrievability-proof-http'
const RETRIEVABILITY_PROOF_DOMAIN_FEATURE = 'retrievability-proof-domain-v1'
const SEED_SIGNATURE_DOMAIN_V3_FEATURE = 'seed-signature-domain-v3'
const SEED_REQUEST_REPLAY_FEATURE = 'seed-request-replay-v1'
const SEED_REQUEST_SIGNATURE_DOMAIN_V3 = 'hiverelay.seed-request.v3'
const SEED_REQUEST_REPLAY_DOMAIN_V1 = 'hiverelay.seed-request.replay-v1'
const RETRIEVABILITY_PROOF_DOMAIN_V1 = 'hiverelay.retrievability-proof.v1'
const DEFAULT_CIRCUIT_MAX_PENDING_CONNECTS = 100
const DEFAULT_CIRCUIT_MAX_RESERVES_PER_MINUTE = 5
const DEFAULT_CAPABILITY_DOC_MAX_AGE_MS = 24 * 60 * 60 * 1000
const DEFAULT_CAPABILITY_DOC_MAX_FUTURE_SKEW_MS = 5 * 60 * 1000
const DEFAULT_SEED_REPLAY_WINDOW_MS = 60 * 60 * 1000
const DEFAULT_SEED_REPLAY_FUTURE_SKEW_MS = 60 * 1000

/**
 * Build the capability document from relay state.
 *
 * All inputs are optional — missing state is advertised as null/absent rather
 * than throwing. Designed to be cheap: called per HTTP request, returns in
 * <1ms even on a busy relay. Don't put expensive aggregations in here.
 *
 * @param {object} opts
 * @param {object} [opts.relay]       The RelayNode / BareRelay instance
 * @param {string} [opts.version]     Software version (e.g. '0.5.1')
 * @param {string} [opts.software]    Software URL
 * @param {string} [opts.name]        Operator-chosen relay name
 * @param {string} [opts.description] Operator-chosen blurb
 * @param {string} [opts.contact]     Operator contact (mailto:, https:, ...)
 * @param {string} [opts.termsOfService] URL to ToS document
 * @param {string} [opts.icon]        URL to an icon image
 * @param {string} [opts.runtime]     'node' | 'bare' — autodetected if absent
 * @returns {object} JSON-serializable capability document
 */
export function buildCapabilityDoc (opts = {}) {
  const relay = opts.relay || null
  const config = (relay && relay.config) || {}
  const runtime = opts.runtime || (isBare ? 'bare' : 'node')

  // Identity ─ prefer explicit node identity, fall back to swarm keypair.
  const identity = extractIdentity(relay)

  // Accept policy ─ cheap, pure function over config.
  const acceptMode = resolveAcceptMode(config)
  const relayKernelProfile = isRelayKernelProfile(relay, config)
  const federationEnabled = !!(relay && relay.federation) &&
    !relayKernelProfile &&
    !moduleDisabled(config.federation)
  const paymentEnabled = !!(relay && relay.paymentManager && relay.paymentManager.paymentProvider) &&
    !relayKernelProfile &&
    !moduleDisabled(config.payment)
  const servicesEnabled = !!(relay && relay.serviceRegistry) &&
    !relayKernelProfile &&
    config.enableServices !== false
  const custodyEnabled = !relayKernelProfile && moduleEnabled(config.custody)
  const signedDirectoryEnabled = !!(relay && relay._signedDirectory) &&
    !relayKernelProfile &&
    !moduleDisabled(config.signedDirectory)
  const retrievabilityHttpEnabled = runtime === 'node' &&
    !!(relay && relay.appRegistry) &&
    hasRelaySigningKey(relay)
  const circuitRelayEnabled = !!(relay && config.enableRelay !== false)
  const circuitLimitsProfile = circuitRelayEnabled
    ? buildCircuitLimitsProfile({ relay, config })
    : null

  // Transports actually enabled right now, not just compiled in.
  const transports = []
  if (config.discovery && config.discovery.dht !== false) transports.push('hyperswarm')
  if (config.discovery && config.discovery.mdns) transports.push('mdns')
  if (relay && relay.dhtRelayWs && relay.dhtRelayWs.running) transports.push('dht-relay-ws')
  if (relay && relay.torTransport && relay.torTransport.running) transports.push('tor')
  if (relay && relay.holesailTransport) transports.push('holesail')

  // Federation — snapshot is a pure read, no I/O.
  let federation = null
  if (federationEnabled) {
    try {
      const snap = relay.federation.snapshot()
      federation = {
        followed: Array.isArray(snap.followed) ? snap.followed.length : 0,
        mirrored: Array.isArray(snap.mirrored) ? snap.mirrored.length : 0,
        republished: Array.isArray(snap.republished) ? snap.republished.length : 0
      }
    } catch (_) {
      federation = null
    }
  }

  // Limitation block — standardized names where semantics align with common
  // relay-info conventions, plus HiveRelay-specific fields. Clients SHOULD
  // treat all as informational; actual enforcement lives on the relay.
  const limitation = {
    accept_mode: acceptMode,
    max_pending_requests: numberOr(config.maxPendingRequests, null),
    max_connections: numberOr(config.maxConnections, null),
    max_storage_bytes: numberOr(config.maxStorageBytes, null),
    max_relay_bandwidth_mbps: numberOr(config.maxRelayBandwidthMbps, null),
    delegation_required: booleanOr(config.delegationRequired, false),
    payment_required: paymentEnabled,
    auth_required: booleanOr(config.authRequired, false)
  }

  // Supported feature flags, advertised so clients can branch. Names map
  // 1:1 to what the SDK checks.
  const features = []
  if (federationEnabled) features.push('federation')
  if (relay && relay._checkDelegation) features.push('delegation-certs')
  if (relay && relay._revokedCertSignatures) features.push('delegation-revocation')
  if (relay && relay.dhtRelayWs) features.push('dht-relay-ws')
  if (relay && relay.seedingRegistry) features.push('seeding-registry')
  if (relay && relay.alertManager) features.push('alerts')
  if (relay && relay.selfHeal) features.push('self-heal')
  if (relay && relay.torTransport) features.push('tor-transport')
  if (relay && relay._bandwidthReceipt) features.push('bandwidth-receipts')
  if (relay && relay.reputation) features.push('reputation')
  if (retrievabilityHttpEnabled) {
    features.push(CORE_RETRIEVABILITY_HTTP_FEATURE)
    features.push(RETRIEVABILITY_PROOF_DOMAIN_FEATURE)
  }
  if (circuitRelayEnabled) features.push('circuit-relay')
  if (circuitLimitsProfile && circuitLimitsProfile.verdict && circuitLimitsProfile.verdict.valid) {
    features.push(CIRCUIT_LIMITS_PROFILE_FEATURE)
  }
  if (relay && typeof relay.createAccountingReceipt === 'function') features.push('accounting-receipts')
  if (servicesEnabled && hasRunningService(relay, 'notify')) features.push('notify-v1')
  if (servicesEnabled && hasRunningService(relay, 'outboxlog')) features.push('outboxlog-v1')
  features.push('capability-doc') // we're advertising this doc, so always set
  // Revocability — this build understands and enforces the v0.8 seed-request
  // revocability fields (revocable + unseedFreezeMs). Clients querying the
  // capability doc can rely on this signal to decide whether their
  // non-revocable seed will actually be honored by this relay.
  features.push('seed-revocability')
  // Seed signature domain-v3 — this build verifies the preferred
  // domain-separated preimage while retaining legacy v2/v1 compatibility.
  features.push(SEED_SIGNATURE_DOMAIN_V3_FEATURE)
  features.push(SEED_REQUEST_REPLAY_FEATURE)
  // AutoHeal — this relay actively maintains diversity-enforced replication
  // for archive-tier drives (durability=1). Clients publishing to archive
  // tier can prefer relays advertising this feature, since they're the only
  // ones whose participation actually moves the diversity-threshold needle.
  if (relay && relay.autoHeal) features.push('auto-heal')
  // hiverelay-publish v1 — publisher-signed Protomux channel for
  // submitting custody-pipeline entries (intent, commit, source-retired)
  // over Hyperswarm instead of HTTPS. Publishers should prefer this when
  // available; falls back to /api/v1/* REST when not.
  if (!relayKernelProfile && relay && relay._publishProtocol) features.push('publish-channel-v1')

  // privacyTransports — health-gated signed advertisement of location-hidden
  // endpoints (currently the tor-v3-onion-v1 entry). Omitted entirely unless
  // a transport is running AND verified ready — this preserves the canonical
  // signable shape for relays without a privacy transport (fixture-stable).
  const privacyTransports = buildPrivacyTransports({ relay, config, custodyEnabled })
  if (privacyTransports.length > 0) features.push(PRIVACY_TRANSPORTS_FEATURE)

  // Fees block — only populated if a paymentManager is configured AND the
  // operator has set a fee schedule.
  let fees = null
  if (paymentEnabled && config.fees && typeof config.fees === 'object') {
    fees = config.fees
  }

  // Counts — cheap. More detailed telemetry lives on /api/overview.
  let catalog = null
  if (relay && relay.appRegistry && typeof relay.appRegistry.catalog === 'function') {
    try {
      const entries = relay.appRegistry.catalog() || []
      const anchored = entries.filter(e => e.anchored === true).length
      catalog = {
        total: entries.length,
        anchored,
        // legacy field kept for backward-compat consumers; equals 'total'
        accepted: entries.length,
        apps: entries.filter(e => e.type === 'app').length,
        drives: entries.filter(e => e.type === 'drive' && !e.parentKey).length,
        resources: entries.filter(e => e.type === 'drive' && !!e.parentKey).length,
        datasets: entries.filter(e => e.type === 'dataset').length,
        media: entries.filter(e => e.type === 'media').length
      }
    } catch (_) { catalog = null }
  }

  // Region — operators configure via regions[]. First entry is canonical.
  const region = (Array.isArray(config.regions) && config.regions[0]) || null

  // onionGatewayUrl — when the Tor transport is running with a hidden service,
  // the .onion forwards to the relay's HTTP API/gateway port, so the read plane
  // (/catalog.json, /v1/hyper/:key, /.well-known/hiverelay.json) is reachable
  // over Tor. Advertising it lets a privacy-seeking consumer fetch content
  // WITHOUT revealing its IP to the relay — a genuine Tor-grade property on the
  // HTTP read path, additive to (not a replacement for) the fast UDX path.
  let onionGatewayUrl = null
  const readyOnionTransport = privacyTransports.find((transport) => transport.network === 'tor')
  const onionReadVport = readyOnionTransport &&
    readyOnionTransport.vportRoles &&
    readyOnionTransport.vportRoles.readPlane
  const onionAddress = readyOnionTransport && readyOnionTransport.addresses[0] && readyOnionTransport.addresses[0].address
  if (onionAddress && Number.isSafeInteger(onionReadVport)) {
    const portSuffix = onionReadVport === 80 ? '' : ':' + onionReadVport
    onionGatewayUrl = 'http://' + onionAddress + portSuffix
  }

  const gatewayUrl = (typeof opts.gatewayUrl === 'string' && opts.gatewayUrl) ||
    (typeof config.gatewayUrl === 'string' && config.gatewayUrl) ||
    (typeof config.publicUrl === 'string' && config.publicUrl) || null
  const indexRoom = (relay && typeof relay.indexRoom === 'string' && relay.indexRoom) ||
    (typeof opts.indexRoom === 'string' && opts.indexRoom) || null
  const catalogPublic = !!(relay && relay.appRegistry && config.enableAPI !== false)

  const doc = {
    schemaVersion: SCHEMA_VERSION,
    name: opts.name || config.name || null,
    description: opts.description || config.description || null,
    icon: opts.icon || config.icon || null,
    pubkey: identity,
    software: opts.software || 'https://github.com/bigdestiny2/p2p-hiverelay',
    version: opts.version || null,
    runtime,
    region,
    contact: opts.contact || config.contact || null,
    terms_of_service: opts.termsOfService || config.termsOfService || null,
    supported_transports: transports,
    features: features.sort(),
    protocol_profile: buildProtocolProfile({
      config,
      relayKernelProfile,
      retrievabilityHttpEnabled,
      servicesEnabled,
      custodyEnabled,
      federationEnabled,
      signedDirectoryEnabled,
      paymentEnabled,
      circuitRelayEnabled,
      circuitLimitsProfile,
      relay
    }),
    directory_privacy: buildDirectoryPrivacy({
      relayKernelProfile,
      signedDirectoryEnabled,
      catalogPublic,
      gatewayUrl,
      indexRoom
    }),
    limitation,
    federation,
    catalog,
    fees,
    // gatewayUrl — the relay's public HTTP base URL, advertised so a directory
    // index (and clients) can reach this relay without a hardcoded address.
    // Additive (schemaVersion stays 1). null when the operator hasn't set a
    // public URL — such relays simply won't appear in /index/relays.
    gatewayUrl,
    // onionGatewayUrl — Tor read-plane ingress (.onion → HTTP API/gateway port).
    // Additive; null unless the Tor hidden service is up. See note above.
    onionGatewayUrl,
    // privacyTransports — signed, health-gated location-hidden endpoint
    // advertisements (hiverelay.onion/1). Omitted unless verified ready
    // (added below only when non-empty, preserving the signable shape).
    ...(privacyTransports.length > 0 ? { privacyTransports } : {}),
    // indexRoom — z32 link to this relay's schema-sheets index room, if a
    // sidecar has published one. Additive: clients that don't understand it
    // ignore it and fall back to catalogBeeKey / /catalog.json. schemaVersion
    // stays 1 — the canonical signer covers whatever keys are present, so old
    // verifiers still validate (see canonicalSignablePayload).
    indexRoom,
    // attestedAt — closes the stale-doc replay attack stub. The
    // signed payload covers this timestamp, so a relay's old doc
    // can't be replayed (clients can detect it's stale via the field).
    // Test override accepted via opts.attestedAt for deterministic tests.
    attestedAt: typeof opts.attestedAt === 'number' ? opts.attestedAt : Date.now()
  }

  // Sign the doc with the relay's identity secret key, if available.
  // The signature covers a canonical serialization of all fields above
  // (sorted keys, no signature field). Clients verify against the
  // pubkey IN the doc — TOFU model. A future revision should support
  // operator-pinned pubkey verification (out-of-band trust on first
  // contact, then verify the SAME pubkey on every subsequent fetch).
  const secretKey = opts.identitySecretKey ||
    (relay && relay.identityKeyPair && relay.identityKeyPair.secretKey) ||
    (relay && relay.swarm && relay.swarm.keyPair && relay.swarm.keyPair.secretKey) ||
    null
  if (secretKey && identity) {
    try {
      const payload = canonicalSignablePayload(doc)
      const sig = b4a.alloc(64)
      sodium.crypto_sign_detached(sig, payload, secretKey)
      doc.signature = {
        v: SIGNATURE_VERSION,
        sig: b4a.toString(sig, 'hex')
      }
    } catch (_) {
      // If signing fails, ship the unsigned doc rather than 500-ing —
      // unsigned is still better than no doc at all, and the signature
      // is additive defense.
    }
  }
  return doc
}

function buildProtocolProfile ({
  config,
  relayKernelProfile,
  retrievabilityHttpEnabled,
  servicesEnabled,
  custodyEnabled,
  federationEnabled,
  signedDirectoryEnabled,
  paymentEnabled,
  circuitRelayEnabled,
  circuitLimitsProfile,
  relay
}) {
  const kernelSurfaces = ['capability-doc']
  if (relay && config.enableSeeding !== false) kernelSurfaces.push('seed-control')
  if (circuitRelayEnabled) kernelSurfaces.push('circuit-relay')
  if (retrievabilityHttpEnabled) kernelSurfaces.push('proof-of-retrievability')
  if (relay && typeof relay.createAccountingReceipt === 'function') kernelSurfaces.push('accounting-receipts')
  if (relay && config.enableAPI !== false) {
    kernelSurfaces.push('http-gateway')
    kernelSurfaces.push('catalog')
  }

  const appSurfaces = []
  if (servicesEnabled) appSurfaces.push('services')
  if (custodyEnabled) appSurfaces.push('custody')
  if (federationEnabled) appSurfaces.push('federation')
  if (signedDirectoryEnabled) appSurfaces.push('signed-directory')
  if (paymentEnabled) appSurfaces.push('payment')
  if (moduleEnabled(config.lease)) appSurfaces.push('lease')
  if (moduleEnabled(config.subsidy)) appSurfaces.push('subsidy')

  return {
    name: typeof config.productProfile === 'string'
      ? config.productProfile
      : (relayKernelProfile ? 'relaykernel' : 'hiverelay'),
    relaykernel_compatible: relayKernelProfile,
    kernel_surfaces: kernelSurfaces.sort(),
    app_surfaces: appSurfaces.sort(),
    circuit_limits: circuitLimitsProfile,
    signature_domains: {
      seed_request: {
        preferred: SEED_REQUEST_SIGNATURE_DOMAIN_V3,
        accepted: [
          SEED_REQUEST_SIGNATURE_DOMAIN_V3,
          SEED_REQUEST_REPLAY_DOMAIN_V1,
          'legacy-v2',
          'legacy-v1'
        ],
        legacy_accepted: true,
        replay_protection: {
          domain: SEED_REQUEST_REPLAY_DOMAIN_V1,
          nonce_bytes: 16,
          replay_window_ms: DEFAULT_SEED_REPLAY_WINDOW_MS,
          future_skew_ms: DEFAULT_SEED_REPLAY_FUTURE_SKEW_MS,
          transports: [
            'https-api-v1-seed',
            'hiverelay-publish'
          ]
        }
      },
      retrievability_proof: {
        preferred: RETRIEVABILITY_PROOF_DOMAIN_V1,
        accepted: [
          RETRIEVABILITY_PROOF_DOMAIN_V1,
          'storage-proof-legacy-v1'
        ],
        signature_profiles: [
          'retrievability-proof-v1',
          'storage-proof-legacy-v1'
        ],
        legacy_accepted: true,
        http_opt_in: retrievabilityHttpEnabled
      }
    },
    services: buildServicesProtocolProfile(relay, servicesEnabled)
  }
}

function buildServicesProtocolProfile (relay, servicesEnabled) {
  if (!servicesEnabled || !relay || !relay.serviceRegistry || !relay.serviceRegistry.services) return null
  const services = relay.serviceRegistry.services
  const profile = {}
  if (hasRunningService(relay, 'notify')) {
    profile.notify = {
      version: '0.1.0',
      providers: ['runtime', 'apns', 'fcm', 'webpush'],
      credential_modes: ['runtime-owned', 'app-owned'],
      modes: ['direct', 'watch', 'presence-fallback'],
      payload: {
        max_ciphertext_bytes: 3072,
        plaintext_allowed: false,
        privacy_profiles: ['generic', 'local-template']
      },
      limits: {
        max_ttl_seconds: 604800,
        max_devices_per_user_app: 32,
        max_watches_per_receive_cap: 128,
        default_channel_per_hour: 30
      }
    }
  }
  if (hasRunningService(relay, 'outboxlog')) {
    profile.outboxlog = {
      version: serviceVersion(services.get('outboxlog')) || '0.1.0',
      model: 'single-writer-signed-outbox',
      plaintext_allowed: false,
      bridge: 'peerit-compatible-http-sse',
      capabilities: ['outboxlog.sync', 'outboxlog.directory', 'outboxlog.events']
    }
  }
  return Object.keys(profile).length ? profile : null
}

function buildCircuitLimitsProfile ({ relay, config }) {
  const circuitRelay = relay && relay._circuitRelay
  const relayCore = relay && relay.relay
  const maxSessionMs = hardCappedPositiveInteger(
    circuitRelay && circuitRelay.maxCircuitDuration,
    hardCappedPositiveInteger(
      relayCore && relayCore.maxCircuitDuration,
      hardCappedPositiveInteger(config.maxCircuitDuration, RELAYKERNEL_CIRCUIT_SESSION_HARD_CAP_MS, RELAYKERNEL_CIRCUIT_SESSION_HARD_CAP_MS),
      RELAYKERNEL_CIRCUIT_SESSION_HARD_CAP_MS
    ),
    RELAYKERNEL_CIRCUIT_SESSION_HARD_CAP_MS
  )
  const maxBytes = hardCappedPositiveInteger(
    circuitRelay && circuitRelay.maxCircuitBytes,
    hardCappedPositiveInteger(
      relayCore && relayCore.maxCircuitBytes,
      hardCappedPositiveInteger(config.maxCircuitBytes, RELAYKERNEL_CIRCUIT_BYTES_HARD_CAP, RELAYKERNEL_CIRCUIT_BYTES_HARD_CAP),
      RELAYKERNEL_CIRCUIT_BYTES_HARD_CAP
    ),
    RELAYKERNEL_CIRCUIT_BYTES_HARD_CAP
  )
  const maxCircuitsPerPeer = hardCappedPositiveInteger(
    circuitRelay && circuitRelay.maxCircuitsPerPeer,
    hardCappedPositiveInteger(
      relayCore && relayCore.maxCircuitsPerPeer,
      hardCappedPositiveInteger(config.maxCircuitsPerPeer, RELAYKERNEL_CIRCUIT_MAX_PER_PEER_HARD_CAP, RELAYKERNEL_CIRCUIT_MAX_PER_PEER_HARD_CAP),
      RELAYKERNEL_CIRCUIT_MAX_PER_PEER_HARD_CAP
    ),
    RELAYKERNEL_CIRCUIT_MAX_PER_PEER_HARD_CAP
  )
  const maxFrameBytes = hardCappedPositiveInteger(
    circuitRelay && circuitRelay.maxDataMsgBytes,
    RELAYKERNEL_CIRCUIT_FRAME_HARD_CAP,
    RELAYKERNEL_CIRCUIT_FRAME_HARD_CAP
  )
  const rateCapBytesPerSecond = hardCappedPositiveInteger(
    circuitRelay && circuitRelay.maxCircuitRateBytesPerSecond,
    hardCappedPositiveInteger(
      relayCore && relayCore.maxCircuitRateBytesPerSecond,
      hardCappedPositiveInteger(
        config.maxCircuitRateBytesPerSecond,
        RELAYKERNEL_CIRCUIT_RECOMMENDED_RATE_CAP_BPS,
        RELAYKERNEL_CIRCUIT_RECOMMENDED_RATE_CAP_BPS
      ),
      RELAYKERNEL_CIRCUIT_RECOMMENDED_RATE_CAP_BPS
    ),
    RELAYKERNEL_CIRCUIT_RECOMMENDED_RATE_CAP_BPS
  )

  return evaluateRelayKernelCircuitLimitsProfile({
    channels: ['hiverelay-circuit'],
    limits: {
      maxSessionMs,
      maxBytes,
      maxCircuitsPerPeer,
      maxFrameBytes,
      maxPendingConnects: positiveIntegerOr(
        circuitRelay && circuitRelay._maxPendingConnects,
        DEFAULT_CIRCUIT_MAX_PENDING_CONNECTS
      ),
      maxReservePerMinute: positiveIntegerOr(
        circuitRelay && circuitRelay._maxReservesPerMin,
        DEFAULT_CIRCUIT_MAX_RESERVES_PER_MINUTE
      ),
      rateCapBytesPerSecond
    },
    runtime: {
      reserveAuthBindsRemoteKey: true,
      connectAuthBindsRemoteKey: true,
      endpointOnlyData: true,
      closeOnFrameTooLarge: true,
      closeOnByteCap: true,
      silentDropUnknownCircuit: true,
      relayAccountingEnabled: !!(relayCore && typeof relayCore.recordCircuitBytes === 'function'),
      relayMaxCircuitDurationMs: positiveIntegerOr(
        relayCore && relayCore.maxCircuitDuration,
        maxSessionMs
      ),
      circuitRelayCleanupMs: maxSessionMs,
      perCircuitRateCapBytesPerSecond: rateCapBytesPerSecond
    }
  })
}

function buildDirectoryPrivacy ({
  relayKernelProfile,
  signedDirectoryEnabled,
  catalogPublic,
  gatewayUrl,
  indexRoom
}) {
  const globalEnumerable = signedDirectoryEnabled
  let mode = 'private'
  if (globalEnumerable) mode = 'global-directory-opt-in'
  else if (catalogPublic || gatewayUrl || indexRoom) mode = 'catalog-public'
  if (relayKernelProfile && !globalEnumerable) mode = 'relaykernel-private'

  return {
    mode,
    relaykernel_private_by_default: relayKernelProfile && !globalEnumerable,
    global_enumerable: globalEnumerable,
    global_enumerable_reason: globalEnumerable ? 'signed-directory-enabled' : null,
    signed_directory_enabled: signedDirectoryEnabled,
    catalog_public: catalogPublic,
    gateway_url_advertised: !!gatewayUrl,
    index_room_advertised: !!indexRoom
  }
}

function isRelayKernelProfile (relay, config) {
  return !!(
    (relay && relay.mode === 'relaykernel') ||
    (config && config.productProfile === 'relaykernel')
  )
}

function moduleDisabled (value) {
  return !!(value && typeof value === 'object' && value.enabled === false)
}

function moduleEnabled (value) {
  return !!(value && typeof value === 'object' && value.enabled === true)
}

function hasRelaySigningKey (relay) {
  return !!(
    (relay && relay.keyPair && relay.keyPair.secretKey) ||
    (relay && relay.identityKeyPair && relay.identityKeyPair.secretKey) ||
    (relay && relay.swarm && relay.swarm.keyPair && relay.swarm.keyPair.secretKey)
  )
}

function hasRunningService (relay, name) {
  const entry = serviceEntry(relay, name)
  return !!entry && (!entry.status || entry.status === 'running')
}

function serviceEntry (relay, name) {
  const services = relay && relay.serviceRegistry && relay.serviceRegistry.services
  return services && typeof services.get === 'function' ? services.get(name) : null
}

function serviceVersion (entry) {
  if (!entry) return null
  if (typeof entry.version === 'string' && entry.version) return entry.version
  const provider = entry.provider || entry
  if (provider && typeof provider.manifest === 'function') {
    try {
      const manifest = provider.manifest()
      if (manifest && typeof manifest.version === 'string') return manifest.version
    } catch (_) {}
  }
  return null
}

/**
 * Verify a capability doc's signature against the pubkey contained in
 * the doc itself (TOFU model). Returns { valid, reason }.
 *
 * The verification is over the canonical signable payload — the same
 * function buildCapabilityDoc uses to construct the signed bytes —
 * so JSON re-encoding between server and client doesn't break it.
 *
 * @param {object} doc
 * @param {object} [opts]
 * @param {boolean} [opts.requireFresh=false] require a bounded attestedAt window
 * @param {number} [opts.maxAgeMs] max signed attestation age when freshness is required
 * @param {number} [opts.maxFutureSkewMs] allowed clock skew for future attestedAt values
 * @param {number} [opts.now] deterministic current time override for tests
 * @returns {{valid: boolean, reason?: string}}
 */
export function verifyCapabilityDoc (doc, opts = {}) {
  if (!doc || typeof doc !== 'object') return { valid: false, reason: 'not an object' }
  if (!doc.signature) return { valid: false, reason: 'no signature on doc' }
  if (doc.signature.v !== SIGNATURE_VERSION) {
    return { valid: false, reason: 'unsupported signature version: ' + doc.signature.v }
  }
  if (typeof doc.pubkey !== 'string' || !/^[0-9a-f]{64}$/i.test(doc.pubkey)) {
    return { valid: false, reason: 'no valid pubkey on doc' }
  }
  if (typeof doc.signature.sig !== 'string' || !/^[0-9a-f]{128}$/i.test(doc.signature.sig)) {
    return { valid: false, reason: 'malformed signature' }
  }
  try {
    const payload = canonicalSignablePayload(doc)
    const sig = b4a.from(doc.signature.sig, 'hex')
    const pub = b4a.from(doc.pubkey, 'hex')
    const ok = sodium.crypto_sign_verify_detached(sig, payload, pub)
    if (!ok) return { valid: false, reason: 'signature verification failed' }
    const freshness = verifyCapabilityDocFreshness(doc, opts)
    return freshness || { valid: true }
  } catch (err) {
    return { valid: false, reason: 'verify error: ' + err.message }
  }
}

export function capabilityDocSignablePayload (doc) {
  return canonicalSignablePayload(doc)
}

/**
 * Canonical serialization for signing. Excludes the signature field
 * (chicken-and-egg) and serializes all other fields with sorted keys
 * so two encoders that differ on key order still produce identical
 * bytes for the same doc.
 */
function canonicalSignablePayload (doc) {
  const clone = {}
  for (const k of Object.keys(doc).sort()) {
    if (k === 'signature') continue
    clone[k] = sortKeysDeep(doc[k])
  }
  return b4a.from(JSON.stringify(clone), 'utf8')
}

function sortKeysDeep (val) {
  if (Array.isArray(val)) return val.map(sortKeysDeep)
  if (val && typeof val === 'object') {
    const out = {}
    for (const k of Object.keys(val).sort()) out[k] = sortKeysDeep(val[k])
    return out
  }
  return val
}

function verifyCapabilityDocFreshness (doc, opts) {
  const requiresFreshness = opts && (
    opts.requireFresh === true ||
    opts.requireFreshCapabilityDoc === true ||
    typeof opts.maxAgeMs === 'number' ||
    typeof opts.maxFutureSkewMs === 'number'
  )
  if (!requiresFreshness) return null

  const maxAgeMs = typeof opts.maxAgeMs === 'number'
    ? opts.maxAgeMs
    : DEFAULT_CAPABILITY_DOC_MAX_AGE_MS
  const maxFutureSkewMs = typeof opts.maxFutureSkewMs === 'number'
    ? opts.maxFutureSkewMs
    : DEFAULT_CAPABILITY_DOC_MAX_FUTURE_SKEW_MS
  const now = typeof opts.now === 'number' ? opts.now : Date.now()

  if (!Number.isFinite(now)) return { valid: false, reason: 'invalid freshness clock' }
  if (!Number.isFinite(maxAgeMs) || maxAgeMs < 0) return { valid: false, reason: 'invalid freshness maxAgeMs' }
  if (!Number.isFinite(maxFutureSkewMs) || maxFutureSkewMs < 0) {
    return { valid: false, reason: 'invalid freshness maxFutureSkewMs' }
  }
  if (!Number.isSafeInteger(doc.attestedAt) || doc.attestedAt <= 0) {
    return { valid: false, reason: 'missing attestedAt' }
  }
  if (doc.attestedAt > now + maxFutureSkewMs) {
    return { valid: false, reason: 'capability doc attestation too far in future' }
  }
  if (now - doc.attestedAt > maxAgeMs) {
    return { valid: false, reason: 'capability doc attestation expired' }
  }
  return null
}

function extractIdentity (relay) {
  if (!relay) return null
  if (typeof relay.getIdentityPublicKey === 'function') {
    try {
      const pk = relay.getIdentityPublicKey()
      if (pk) return typeof pk === 'string' ? pk : b4a.toString(pk, 'hex')
    } catch (_) {}
  }
  if (relay.publicKey) {
    try { return b4a.toString(relay.publicKey, 'hex') } catch (_) {}
  }
  if (relay.swarm && relay.swarm.keyPair && relay.swarm.keyPair.publicKey) {
    try { return b4a.toString(relay.swarm.keyPair.publicKey, 'hex') } catch (_) {}
  }
  return null
}

function numberOr (v, fallback) {
  return typeof v === 'number' && Number.isFinite(v) ? v : fallback
}

function positiveIntegerOr (v, fallback) {
  return Number.isSafeInteger(v) && v > 0 ? v : fallback
}

function hardCappedPositiveInteger (v, fallback, hardCap) {
  return Math.min(positiveIntegerOr(v, fallback), hardCap)
}

function booleanOr (v, fallback) {
  return typeof v === 'boolean' ? v : fallback
}

export { SCHEMA_VERSION as CAPABILITY_DOC_SCHEMA_VERSION }
