/**
 * Gateway Server — data-plane HTTP server for Hyperdrive content serving.
 *
 * Separated from the control-plane RelayAPI so heavy file traffic cannot
 * starve management endpoints. Serves:
 *   - GET /v1/hyper/:key/*  — HTTP gateway for Hyperdrive content
 *   - GET /catalog.json     — public content catalog (typed)
 *   - GET /health           — simple liveness check for load balancers
 *
 * No auth required — all routes are public, read-only. Privacy tiers are
 * still enforced by the HyperGateway itself.
 *
 * The compatibility-only listener can still bind publicly when explicitly
 * configured. Enabling key-derived app hosts requires a dedicated loopback
 * listener behind a strict TLS edge; it may never share the control port.
 */

import { createServer } from 'http'
import { EventEmitter } from 'events'
import { isIP } from 'net'
import { HyperGateway, selectExactByteRepresentation } from '../../gateway/hyper-gateway.js'
import { normalizeHiveAppHostSuffix, resolveHiveAppHost } from '../../gateway/hive-host.js'
import {
  issueExactAppContext,
  registerActiveExactGateway,
  unregisterActiveExactGateway
} from '../../gateway/exact-app-context.js'
import {
  admitPublicHiveAppEntry,
  PUBLIC_HIVE_GATEWAY_ADMISSION_CAPABILITY,
  normalizeHiveAppPublicKeys,
  normalizeHiveAppPublicVersions
} from '../../gateway/public-app-admission.js'
import { PUBLIC_T1_GATEWAY_FINITE_LIMITS } from '../../config/public-hive-gateway-env.js'
import { buildGatewayCatalogPayload } from './api-catalog-read.js'
import { writeJson } from './api-response.js'

const DEFAULT_GATEWAY_PORT = 9200

// Gateway rate limit — higher than the control plane (file serving is bursty).
const RATE_LIMIT_WINDOW_MS = 60_000
const RATE_LIMIT_MAX = 600 // 10 req/sec sustained per IP
const RATE_LIMIT_MAX_BUCKETS = 50_000
const HIVE_APP_DOCUMENT_PATH = '/.well-known/hiverelay-app.json'
const DEFAULT_MAX_IN_FLIGHT = 256
const DEFAULT_MAX_IN_FLIGHT_PER_APP = 32
const DEFAULT_MAX_RESPONSE_LIFETIME_MS = 15 * 60_000
const DEFAULT_EGRESS_BYTES_PER_WINDOW = 256 * 1024 * 1024
const MAX_EGRESS_BYTES_PER_WINDOW = 1024 * 1024 * 1024 * 1024
const DEFAULT_EGRESS_WINDOW_MS = 60_000
const DEFAULT_COMPATIBILITY_HOSTS = ['127.0.0.1', 'localhost', '[::1]']
const DEFAULT_TRUSTED_PROXY_ADDRESSES = ['127.0.0.1', '::1', '::ffff:127.0.0.1']
const MAX_HOST_ALLOWLIST_ENTRIES = 64
const MAX_REQUEST_HEADER_BYTES = 16 * 1024
const MAX_REQUEST_HEADERS = 64

function readSingleHostHeader (req) {
  const distinct = req.headersDistinct?.host
  if (Array.isArray(distinct)) {
    if (distinct.length !== 1) return { ok: false, value: null }
    return { ok: true, value: distinct[0] }
  }

  let count = 0
  for (let i = 0; i < (req.rawHeaders?.length || 0); i += 2) {
    if (String(req.rawHeaders[i]).toLowerCase() === 'host') count++
  }
  if (count > 1) return { ok: false, value: null }
  return { ok: true, value: req.headers.host }
}

export function assertHiveAppGatewayIsolation ({
  hiveAppHostSuffix,
  hiveAppPublicKeys = [],
  hiveAppPublicVersions = {},
  gatewayPort,
  gatewayHost = '127.0.0.1',
  gatewayCompatibilityHosts = DEFAULT_COMPATIBILITY_HOSTS,
  gatewayTrustedProxyAddresses = DEFAULT_TRUSTED_PROXY_ADDRESSES,
  gatewayTrustProxy = false,
  gatewayRequireForwardedSNI = false,
  gatewayMaxResponseBytes,
  gatewayMaxTransformBytes,
  gatewayEgressBytesPerWindow,
  gatewayEgressWindowMs,
  gatewayMaxResponseLifetimeMs,
  apiPort = 9100,
  apiHost = '0.0.0.0',
  enableAPI = true,
  enableSeeding = true,
  enableRelay = false,
  enableServices = false,
  plugins = [],
  signedDirectory = { enabled: false },
  federation = { enabled: false, followed: [], mirrored: [] },
  lease = { enabled: false },
  payment = { enabled: false },
  subsidy = { enabled: false },
  shardStore,
  custody,
  requirePhysicalEnforcement,
  mode,
  productProfile,
  enforceCompiledAdmission = true
} = {}) {
  const normalizedMode = String(mode || '').trim().toLowerCase()
  const normalizedProfile = String(productProfile || '').trim().toLowerCase()
  const productionT1Selected = normalizedMode === 'public-t1-gateway' || normalizedProfile === 'public-t1-gateway'
  if (productionT1Selected && (mode !== 'public-t1-gateway' || productProfile !== 'public-t1-gateway')) {
    throw new Error('public-t1-gateway requires exact canonical matching mode and productProfile')
  }
  const productionT1 = productionT1Selected
  if (hiveAppHostSuffix == null || hiveAppHostSuffix === '') {
    if (productionT1) throw new Error('public-t1-gateway requires hiveAppHostSuffix')
    return null
  }

  const suffix = normalizeHiveAppHostSuffix(hiveAppHostSuffix)
  if (!suffix) throw new Error('hiveAppHostSuffix must be a valid DNS suffix')
  if (enableAPI === false) throw new Error('hiveAppHostSuffix requires enableAPI')
  const publicKeys = normalizeHiveAppPublicKeys(hiveAppPublicKeys)
  if (!publicKeys) {
    throw new Error('hiveAppPublicKeys must contain only 64-character hex app keys')
  }
  const publicVersions = normalizeHiveAppPublicVersions(hiveAppPublicVersions)
  if (!publicVersions) throw new Error('hiveAppPublicVersions must map 64-character hex app keys to non-negative safe integer versions')
  if ([...publicVersions.keys()].some(key => !publicKeys.has(key))) {
    throw new Error('hiveAppPublicVersions must not contain keys outside hiveAppPublicKeys')
  }
  if (!isLoopbackHost(gatewayHost)) {
    throw new Error('hiveAppHostSuffix requires gatewayHost to bind loopback')
  }
  if (!normalizeCompatibilityHosts(gatewayCompatibilityHosts)) {
    throw new Error('gatewayCompatibilityHosts must contain bounded canonical hosts')
  }
  if (!normalizeTrustedProxyAddresses(gatewayTrustedProxyAddresses)) {
    throw new Error('gatewayTrustedProxyAddresses must contain bounded IP addresses')
  }
  if (enableSeeding === false) throw new Error('hiveAppHostSuffix requires seeding to be enabled')
  if (['custody-relay', 'private', 'homehive', 'stealth', 'relay-only'].includes(normalizedMode) || normalizedProfile === 'custody-relay') {
    throw new Error('hiveAppHostSuffix is forbidden for custody or restricted relay profiles')
  }

  const port = gatewayPort
  const controlPort = apiPort ?? 9100
  const ephemeralLoopbackPort = !productionT1 && port === 0 && isLoopbackHost(gatewayHost)
  if ((!isStrictPort(port) && !ephemeralLoopbackPort) || !isStrictPort(controlPort) || port === controlPort) {
    throw new Error('hiveAppHostSuffix requires a distinct dedicated gatewayPort')
  }

  if (productionT1) {
    if (requirePhysicalEnforcement !== true) {
      throw new Error('public-t1-gateway requires requirePhysicalEnforcement to be true')
    }
    if (!isLoopbackHost(apiHost)) throw new Error('public-t1-gateway requires apiHost to bind loopback')
    if (gatewayTrustProxy !== true) throw new Error('public-t1-gateway requires gatewayTrustProxy')
    if (gatewayRequireForwardedSNI !== true) throw new Error('public-t1-gateway requires gatewayRequireForwardedSNI')
    if (custody?.enabled !== false) throw new Error('public-t1-gateway requires custody.enabled to be false')
    if (enableServices !== false || !Array.isArray(plugins) || plugins.length !== 0) {
      throw new Error('public-t1-gateway requires services and plugins to be disabled')
    }
    if (enableRelay !== false || enableSeeding !== true || enableAPI !== true) {
      throw new Error('public-t1-gateway requires relay off with seeding and API enabled')
    }
    if (signedDirectory?.enabled !== false || federation?.enabled !== false ||
        (federation?.followed?.length || 0) !== 0 || (federation?.mirrored?.length || 0) !== 0 ||
        lease?.enabled !== false || payment?.enabled !== false || subsidy?.enabled !== false ||
        (shardStore && Object.keys(shardStore).length !== 0)) {
      throw new Error('public-t1-gateway requires directory, federation, economy, and shard service planes disabled')
    }
    if (publicKeys.size !== 1) throw new Error('public-t1-gateway requires exactly one hiveAppPublicKeys entry')
    const appKey = [...publicKeys][0]
    if (publicVersions.size !== 1 || !publicVersions.has(appKey)) {
      throw new Error('public-t1-gateway requires exactly one matching immutable hiveAppPublicVersions pin')
    }
    const finiteConfig = {
      gatewayMaxResponseBytes,
      gatewayMaxTransformBytes,
      gatewayEgressBytesPerWindow,
      gatewayEgressWindowMs,
      gatewayMaxResponseLifetimeMs
    }
    for (const [field, expected] of Object.entries(PUBLIC_T1_GATEWAY_FINITE_LIMITS)) {
      if (finiteConfig[field] !== expected) {
        throw new Error(`public-t1-gateway requires ${field} to equal ${expected}`)
      }
    }
    if (enforceCompiledAdmission) {
      const capability = PUBLIC_HIVE_GATEWAY_ADMISSION_CAPABILITY
      if (
        capability?.kind !== 'public-hive-gateway-admission-capability' ||
        capability?.version !== 1 ||
        capability?.fleetReady !== true ||
        typeof capability?.profile !== 'string' ||
        capability.profile.startsWith('transitional-')
      ) {
        throw new Error('public-t1-gateway requires a compiled fleet-ready non-transitional admission capability')
      }
    }
  }
  if (!productionT1 && custody?.enabled === true) {
    throw new Error('hiveAppHostSuffix forbids an enabled custody plane')
  }
  return suffix
}

export class GatewayServer extends EventEmitter {
  constructor (relayNode, opts = {}) {
    super()
    this.node = relayNode
    const nodeConfig = relayNode.config || {}
    const publicT1 = String(nodeConfig.productProfile || '').toLowerCase() === 'public-t1-gateway'
    if (publicT1) {
      assertPublicT1GatewayOverridesMatchConfig(opts, nodeConfig)
      if (opts.gateway) throw new Error('public-t1-gateway forbids an injected Gateway handler')
    }
    this.port = opts.gatewayPort ?? nodeConfig.gatewayPort ?? DEFAULT_GATEWAY_PORT
    this.host = opts.gatewayHost ?? nodeConfig.gatewayHost ?? '0.0.0.0'
    if (!Number.isSafeInteger(this.port) || this.port < 0 || this.port > 65535) {
      throw new Error('gatewayPort must be an integer from 0 to 65535')
    }
    this.corsOrigins = normalizeCorsOrigins(opts.corsOrigins ?? [])
    if (!this.corsOrigins) throw new Error('corsOrigins must contain bounded canonical HTTP(S) origins')
    this.trustProxy = opts.trustProxy !== undefined
      ? opts.trustProxy === true
      : nodeConfig.gatewayTrustProxy === true
    this.trustedProxyAddresses = normalizeTrustedProxyAddresses(
      opts.trustedProxyAddresses ?? relayNode.config?.gatewayTrustedProxyAddresses ?? DEFAULT_TRUSTED_PROXY_ADDRESSES
    )
    if (!this.trustedProxyAddresses) {
      throw new Error('gatewayTrustedProxyAddresses must contain bounded IP addresses')
    }
    this.requireForwardedSNI = opts.requireForwardedSNI !== undefined
      ? opts.requireForwardedSNI === true
      : nodeConfig.gatewayRequireForwardedSNI === true
    const configuredHostSuffix = opts.hiveAppHostSuffix !== undefined
      ? opts.hiveAppHostSuffix
      : nodeConfig.hiveAppHostSuffix
    this.hiveAppHostSuffix = normalizeHiveAppHostSuffix(configuredHostSuffix)
    if (configuredHostSuffix != null && !this.hiveAppHostSuffix) {
      throw new Error('hiveAppHostSuffix must be a valid DNS suffix')
    }
    if (this.hiveAppHostSuffix && !isLoopbackHost(this.host)) {
      throw new Error('hiveAppHostSuffix requires gatewayHost to bind loopback')
    }
    this.compatibilityHosts = normalizeCompatibilityHosts(
      opts.compatibilityHosts ?? relayNode.config?.gatewayCompatibilityHosts ?? DEFAULT_COMPATIBILITY_HOSTS
    )
    if (!this.compatibilityHosts) {
      throw new Error('gatewayCompatibilityHosts must contain bounded canonical hosts')
    }
    this.hiveAppPublicKeys = normalizeHiveAppPublicKeys(
      opts.hiveAppPublicKeys ?? relayNode.config?.hiveAppPublicKeys ?? []
    )
    if (!this.hiveAppPublicKeys) {
      throw new Error('hiveAppPublicKeys must contain only 64-character hex app keys')
    }
    this.hiveAppPublicVersions = normalizeHiveAppPublicVersions(
      opts.hiveAppPublicVersions ?? relayNode.config?.hiveAppPublicVersions ?? {}
    )
    if (!this.hiveAppPublicVersions) {
      throw new Error('hiveAppPublicVersions must map 64-character hex app keys to non-negative safe integer versions')
    }
    if ([...this.hiveAppPublicVersions.keys()].some(key => !this.hiveAppPublicKeys.has(key))) {
      throw new Error('hiveAppPublicVersions must not contain keys outside hiveAppPublicKeys')
    }
    this.server = null
    this._gateway = opts.gateway || new HyperGateway(relayNode, {
      store: relayNode.store,
      requireLifecycleDriveAuthority: true
    })
    this._ownsGateway = !opts.gateway
    this._rateLimits = new Map()
    this._egressLimits = new Map()
    this._maxRateLimitBuckets = strictPositiveInteger(opts.maxRateLimitBuckets, RATE_LIMIT_MAX_BUCKETS, 'maxRateLimitBuckets', 1_000_000)
    const configuredEgressBytes = opts.egressBytesPerWindow !== undefined
      ? opts.egressBytesPerWindow
      : relayNode.config?.gatewayEgressBytesPerWindow
    if (configuredEgressBytes === null) throw new Error('gatewayEgressBytesPerWindow must be finite and non-null')
    this._egressBytesPerWindow = strictPositiveInteger(
      configuredEgressBytes,
      DEFAULT_EGRESS_BYTES_PER_WINDOW,
      'gatewayEgressBytesPerWindow',
      MAX_EGRESS_BYTES_PER_WINDOW
    )
    const configuredEgressWindow = opts.egressWindowMs !== undefined
      ? opts.egressWindowMs
      : relayNode.config?.gatewayEgressWindowMs
    if (configuredEgressWindow === null) throw new Error('gatewayEgressWindowMs must be finite and non-null')
    this._egressWindowMs = strictPositiveInteger(
      configuredEgressWindow,
      DEFAULT_EGRESS_WINDOW_MS,
      'gatewayEgressWindowMs',
      60 * 60_000
    )
    this._rateLimitCleanup = null
    this._activeSockets = new Set()
    this._stopPromise = null
    this._activeRequests = 0
    this._activeRequestsByApp = new Map()
    this._maxInFlight = strictPositiveInteger(opts.maxInFlight, DEFAULT_MAX_IN_FLIGHT, 'gatewayMaxInFlight', 4096)
    this._maxInFlightPerApp = strictPositiveInteger(opts.maxInFlightPerApp, DEFAULT_MAX_IN_FLIGHT_PER_APP, 'gatewayMaxInFlightPerApp', 4096)
    const configuredResponseLifetime = opts.maxResponseLifetimeMs !== undefined
      ? opts.maxResponseLifetimeMs
      : relayNode.config?.gatewayMaxResponseLifetimeMs
    if (configuredResponseLifetime === null) throw new Error('gatewayMaxResponseLifetimeMs must be finite and non-null')
    this._maxResponseLifetimeMs = strictPositiveInteger(
      configuredResponseLifetime,
      DEFAULT_MAX_RESPONSE_LIFETIME_MS,
      'gatewayMaxResponseLifetimeMs',
      60 * 60_000
    )
    if (this._maxInFlightPerApp > this._maxInFlight) {
      throw new Error('gatewayMaxInFlightPerApp must not exceed gatewayMaxInFlight')
    }
    // Bound sockets that have connected but have not completed headers yet.
    // Request concurrency alone cannot contain a distributed slow-header load.
    this._maxConnections = Math.min(4096, Math.max(64, this._maxInFlight * 2))

    // GatewayServer is also a public constructor. Enforce the same topology,
    // role and compiled-admission contract that RelayNode enforces so callers
    // cannot bypass it by instantiating the data plane directly.
    this._assertIsolationContract()
    if (this.hiveAppHostSuffix) {
      this.hiveAppPublicKeys = readonlySet(this.hiveAppPublicKeys)
      this.hiveAppPublicVersions = readonlyMap(this.hiveAppPublicVersions)
    }
  }

  get gateway () {
    return this._gateway
  }

  updateHiveAppPublicKeys (value) {
    if (this.hiveAppHostSuffix) {
      throw new Error('Exact app-host admission is immutable for the GatewayServer lifetime; stop and reconstruct it')
    }
    const next = normalizeHiveAppPublicKeys(value)
    if (!next) throw new Error('hiveAppPublicKeys must contain only bounded 64-character hex app keys')
    if ([...this.hiveAppPublicVersions.keys()].some(key => !next.has(key))) {
      throw new Error('hiveAppPublicKeys cannot remove an app with a configured public drive version')
    }
    this.hiveAppPublicKeys = next
    return next.size
  }

  async start () {
    if (this.server) throw new Error('GatewayServer is already started or starting')

    // RelayNode configuration is mutable (for example through applyMode).
    // Re-read it immediately before binding so a safe construction followed
    // by a role/custody/profile mutation cannot start an unsafe exact host.
    this._assertIsolationContract()

    const server = createServer({
      maxHeaderSize: MAX_REQUEST_HEADER_BYTES,
      insecureHTTPParser: false,
      requireHostHeader: true,
      joinDuplicateHeaders: false
    }, (req, res) => {
      this._handle(req, res).catch(err => this._handleRequestError(res, err))
    })
    this.server = server
    server.headersTimeout = 10_000
    server.requestTimeout = 60_000
    server.keepAliveTimeout = 5_000
    server.timeout = 65_000
    server.maxRequestsPerSocket = 100
    server.maxHeadersCount = MAX_REQUEST_HEADERS
    server.maxConnections = this._maxConnections
    server.dropMaxConnection = true
    server.on('connection', (socket) => {
      this._activeSockets.add(socket)
      socket.on('close', () => this._activeSockets.delete(socket))
    })
    server.on('clientError', (err, socket) => {
      this.emit('client-error', { code: err?.code || null })
      if (!socket.destroyed && socket.writable) {
        try { socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n') } catch (_) {}
      }
      try { socket.destroy() } catch (_) {}
    })
    const rejectProtocolSwitch = (req, socket) => {
      if (!socket.destroyed && socket.writable) {
        try { socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n') } catch (_) {}
      }
      try { socket.destroy() } catch (_) {}
    }
    server.on('upgrade', rejectProtocolSwitch)
    server.on('connect', rejectProtocolSwitch)
    server.on('checkContinue', (req, res) => {
      res.shouldKeepAlive = false
      writeJson(res, { error: 'Expect/continue is not supported' }, 417, { Connection: 'close' })
    })
    server.on('checkExpectation', (req, res) => {
      res.shouldKeepAlive = false
      writeJson(res, { error: 'Request expectation is not supported' }, 417, { Connection: 'close' })
    })

    this._rateLimitCleanup = setInterval(() => {
      this._sweepRateLimits()
    }, 120_000)
    if (this._rateLimitCleanup.unref) this._rateLimitCleanup.unref()

    return new Promise((resolve, reject) => {
      const onStartupError = (err) => {
        server.removeListener('listening', onListening)
        if (this.hiveAppHostSuffix) unregisterActiveExactGateway(this.node, this)
        if (this._rateLimitCleanup) {
          clearInterval(this._rateLimitCleanup)
          this._rateLimitCleanup = null
        }
        if (this.server === server) this.server = null
        try { server.close() } catch (_) {}
        reject(err)
      }
      const onListening = () => {
        try {
          this._assertIsolationContract()
        } catch (err) {
          onStartupError(err)
          return
        }
        server.removeListener('error', onStartupError)
        server.on('error', err => {
          this.emit('server-error', { error: err?.message || String(err) })
        })
        this.emit('started', { port: this.port })
        resolve()
      }
      server.once('error', onStartupError)
      server.once('listening', onListening)
      if (this.hiveAppHostSuffix) registerActiveExactGateway(this.node, this)
      try {
        server.listen(this.port, this.host)
      } catch (err) {
        onStartupError(err)
      }
    })
  }

  _assertIsolationContract () {
    const config = this.node.config || {}
    return assertHiveAppGatewayIsolation({
      hiveAppHostSuffix: this.hiveAppHostSuffix,
      hiveAppPublicKeys: [...this.hiveAppPublicKeys],
      hiveAppPublicVersions: Object.fromEntries(this.hiveAppPublicVersions),
      gatewayPort: this.port,
      gatewayHost: this.host,
      gatewayCompatibilityHosts: [...this.compatibilityHosts],
      gatewayTrustedProxyAddresses: [...this.trustedProxyAddresses],
      gatewayTrustProxy: this.trustProxy,
      gatewayRequireForwardedSNI: this.requireForwardedSNI,
      gatewayMaxResponseBytes: this._gateway?._maxResponseBytes ?? config.gatewayMaxResponseBytes,
      gatewayMaxTransformBytes: this._gateway?._maxTransformBytes ?? config.gatewayMaxTransformBytes,
      gatewayEgressBytesPerWindow: this._egressBytesPerWindow,
      gatewayEgressWindowMs: this._egressWindowMs,
      gatewayMaxResponseLifetimeMs: this._maxResponseLifetimeMs,
      apiPort: config.apiPort,
      apiHost: config.apiHost,
      enableAPI: config.enableAPI,
      enableSeeding: config.enableSeeding,
      enableRelay: config.enableRelay,
      enableServices: config.enableServices,
      plugins: config.plugins,
      signedDirectory: config.signedDirectory,
      federation: config.federation,
      lease: config.lease,
      payment: config.payment,
      subsidy: config.subsidy,
      shardStore: config.shardStore,
      custody: config.custody,
      requirePhysicalEnforcement: config.requirePhysicalEnforcement,
      mode: this.node.mode ?? config.mode,
      productProfile: config.productProfile
    })
  }

  async stop () {
    if (this._stopPromise) return this._stopPromise
    const pending = this._stop()
    this._stopPromise = pending
    try {
      await pending
    } finally {
      if (this._stopPromise === pending) this._stopPromise = null
    }
  }

  async _stop () {
    if (this._rateLimitCleanup) {
      clearInterval(this._rateLimitCleanup)
      this._rateLimitCleanup = null
    }
    this._rateLimits.clear()
    this._egressLimits.clear()
    if (this.server) {
      const server = this.server
      await new Promise(resolve => {
        if (typeof server.closeIdleConnections === 'function') {
          try { server.closeIdleConnections() } catch (_) {}
        }
        if (typeof server.closeAllConnections === 'function') {
          try { server.closeAllConnections() } catch (_) {}
          setImmediate(() => {
            try { server.closeAllConnections() } catch (_) {}
          })
        }
        for (const socket of this._activeSockets) {
          try { socket.destroy() } catch (_) {}
        }
        server.close(() => resolve())
      })
      if (this.server === server) this.server = null
    }
    this._activeSockets.clear()
    // Every accepted response releases its slot on finish/close. Clear only
    // after all server sockets are gone so a stale close event from the old
    // generation cannot decrement counters belonging to a restart.
    this._activeRequests = 0
    this._activeRequestsByApp.clear()

    // Stop accepting/streaming requests before closing gateway-owned drive
    // sessions. Closing storage first can truncate an in-flight response.
    if (this._ownsGateway && this._gateway && typeof this._gateway.close === 'function') {
      try { await this._gateway.close() } catch (err) {
        this.emit('gateway-close-error', { error: err && err.message ? err.message : String(err) })
      }
    }
    if (this.hiveAppHostSuffix) unregisterActiveExactGateway(this.node, this)
  }

  _getClientIP (req) {
    const remoteAddress = normalizeIpAddress(req.socket.remoteAddress)
    if (this.trustProxy && remoteAddress && this.trustedProxyAddresses.has(remoteAddress)) {
      const forwarded = normalizeSingleForwardedIp(req.headers['x-forwarded-for'])
      if (forwarded) return forwarded
      const realIP = normalizeSingleForwardedIp(req.headers['x-real-ip'])
      if (realIP) return realIP
    }
    return remoteAddress || 'unknown'
  }

  _isTrustedProxyRequest (req) {
    const remoteAddress = normalizeIpAddress(req.socket.remoteAddress)
    return this.trustProxy && !!remoteAddress && this.trustedProxyAddresses.has(remoteAddress)
  }

  _checkRateLimit (ip) {
    const now = Date.now()
    let entry = this._rateLimits.get(ip)
    if (!entry || !Number.isFinite(entry.count) || !Number.isFinite(entry.resetAt) || now > entry.resetAt) {
      if (!entry && this._rateLimits.size >= this._maxRateLimitBuckets) {
        this._sweepRateLimits(now)
        if (this._rateLimits.size >= this._maxRateLimitBuckets) return false
      }
      entry = { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS }
      this._rateLimits.set(ip, entry)
    }
    if (entry.count >= RATE_LIMIT_MAX) return false
    entry.count++
    return true
  }

  _sweepRateLimits (now = Date.now()) {
    let removed = 0

    for (const [ip, entry] of this._rateLimits) {
      if (!entry || !Number.isFinite(entry.count) || !Number.isFinite(entry.resetAt) || now > entry.resetAt) {
        this._rateLimits.delete(ip)
        removed++
      }
    }
    for (const [key, entry] of this._egressLimits) {
      if (!entry || !Number.isSafeInteger(entry.bytes) || !Number.isFinite(entry.resetAt) || now > entry.resetAt) {
        this._egressLimits.delete(key)
        removed++
      }
    }

    return removed
  }

  _reserveEgress (ip, bucket, bytes) {
    if (!Number.isSafeInteger(bytes) || bytes < 0) return false
    if (bytes === 0) return true
    const now = Date.now()
    const key = `${ip}\x00${bucket}`
    let entry = this._egressLimits.get(key)
    if (!entry || !Number.isSafeInteger(entry.bytes) || !Number.isFinite(entry.resetAt) || now > entry.resetAt) {
      if (!entry && this._egressLimits.size >= this._maxRateLimitBuckets) {
        this._sweepRateLimits(now)
        if (this._egressLimits.size >= this._maxRateLimitBuckets) return false
      }
      entry = { bytes: 0, resetAt: now + this._egressWindowMs }
      this._egressLimits.set(key, entry)
    }
    if (bytes > this._egressBytesPerWindow - entry.bytes) return false
    entry.bytes += bytes
    return true
  }

  _getAllowedOrigin (origin) {
    if (!origin) return null
    if (this.corsOrigins.has('*')) return '*'
    if (this.corsOrigins.has(origin)) return origin
    return null
  }

  _acquireRequestSlot (bucket) {
    const current = this._activeRequestsByApp.get(bucket) || 0
    if (this._activeRequests >= this._maxInFlight || current >= this._maxInFlightPerApp) return null

    this._activeRequests++
    this._activeRequestsByApp.set(bucket, current + 1)
    let released = false
    return () => {
      if (released) return
      released = true
      this._activeRequests = Math.max(0, this._activeRequests - 1)
      const remaining = (this._activeRequestsByApp.get(bucket) || 1) - 1
      if (remaining <= 0) this._activeRequestsByApp.delete(bucket)
      else this._activeRequestsByApp.set(bucket, remaining)
    }
  }

  _handleRequestError (res, err) {
    this.emit('request-error', {
      error: err && err.message ? err.message : String(err)
    })
    if (res.destroyed || res.writableEnded) return
    if (res.headersSent) {
      res.destroy()
      return
    }
    if (res.hasHeader('X-Hive-App-Key')) {
      res.setHeader('X-Hive-Byte-Mode', 'generated')
      res.setHeader('Cache-Control', 'no-store, max-age=0')
    }
    writeJson(res, { error: 'Internal error' }, 500)
  }

  _setHiveAppOriginHeaders (res, hiveHost) {
    res.setHeader('X-Hive-App-Key', hiveHost.appKey)
    // Generated denials, metadata and policy errors are the default app-host
    // representation. HyperGateway overwrites this with `exact` only after it
    // has selected immutable stored file bytes.
    res.setHeader('X-Hive-Byte-Mode', 'generated')
    res.setHeader('Vary', 'Host')
    res.setHeader('Origin-Agent-Cluster', '?1')
    res.setHeader('Cache-Control', 'no-store, max-age=0')
  }

  async _handle (req, res) {
    if (this.hiveAppHostSuffix) this._assertIsolationContract()
    const ip = this._getClientIP(req) || '127.0.0.1'
    if (!this._checkRateLimit(ip)) {
      const requestHost = readSingleHostHeader(req)
      if (requestHost.ok) {
        const hiveHost = resolveHiveAppHost(requestHost.value, this.hiveAppHostSuffix)
        if (hiveHost.kind === 'app') this._setHiveAppOriginHeaders(res, hiveHost)
      }
      writeJson(res, { error: 'Too many requests' }, 429, { 'Retry-After': '60' })
      return
    }

    const requestOrigin = req.headers.origin
    const requestHost = readSingleHostHeader(req)
    if (!requestHost.ok) {
      writeJson(res, { error: 'duplicate Host header' }, 400)
      return
    }
    const hiveHost = resolveHiveAppHost(requestHost.value, this.hiveAppHostSuffix)

    if (hiveHost.kind === 'invalid') {
      writeJson(res, { error: hiveHost.reason }, 400)
      return
    }

    if (this.hiveAppHostSuffix && hiveHost.kind === 'none') {
      const compatibilityHost = normalizeCompatibilityHost(requestHost.value)
      if (!compatibilityHost || !this.compatibilityHosts.has(compatibilityHost)) {
        writeJson(res, { error: 'Misdirected request' }, 421)
        return
      }
    }

    if (hiveHost.kind === 'app' && this.requireForwardedSNI) {
      const forwardedSNI = req.headers['x-hive-forwarded-sni']
      const sniHost = typeof forwardedSNI === 'string'
        ? resolveHiveAppHost(forwardedSNI, this.hiveAppHostSuffix)
        : { kind: 'invalid' }
      if (!this._isTrustedProxyRequest(req) || sniHost.kind !== 'app' || sniHost.host !== hiveHost.host) {
        writeJson(res, { error: 'TLS SNI and Host must match' }, 421)
        return
      }
    }

    // App-key subdomains are isolated origins. Never inherit the data-plane's
    // broad compatibility CORS setting (including `*`) onto an app origin.
    const allowedOrigin = hiveHost.kind === 'app' ? null : this._getAllowedOrigin(requestOrigin)
    if (allowedOrigin) {
      res.setHeader('Access-Control-Allow-Origin', allowedOrigin)
      if (allowedOrigin !== '*') res.setHeader('Vary', 'Origin')
    }
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type')
    if (hiveHost.kind === 'app') this._setHiveAppOriginHeaders(res, hiveHost)

    if (hasRequestBodyFraming(req)) {
      res.shouldKeepAlive = false
      writeJson(res, { error: 'Request body is not allowed' }, 400, { Connection: 'close' })
      return
    }

    if (typeof req.url !== 'string' || !req.url.startsWith('/') || req.url.startsWith('//')) {
      res.shouldKeepAlive = false
      writeJson(res, { error: 'Invalid request target' }, 400, { Connection: 'close' })
      return
    }

    if (hiveHost.kind === 'app' && requestsProofMode(req)) {
      writeJson(res, { error: 'Proof-carrying HTTP mode is not available' }, 406)
      return
    }

    const requestBucket = hiveHost.kind === 'app' ? hiveHost.appKey : 'compatibility'
    const releaseRequest = this._acquireRequestSlot(requestBucket)
    if (!releaseRequest) {
      writeJson(res, { error: 'Gateway busy' }, 503, { 'Retry-After': '1' })
      return
    }
    let lifetimeTimer = setTimeout(() => {
      lifetimeTimer = null
      this.emit('request-timeout', { bucket: requestBucket })
      if (!res.destroyed && !res.writableEnded) {
        try { res.destroy(new Error('Gateway response lifetime exceeded')) } catch (_) {}
      }
    }, this._maxResponseLifetimeMs)
    if (lifetimeTimer.unref) lifetimeTimer.unref()
    const settleRequest = () => {
      if (lifetimeTimer) {
        clearTimeout(lifetimeTimer)
        lifetimeTimer = null
      }
      releaseRequest()
    }
    res.once('finish', settleRequest)
    res.once('close', settleRequest)

    if (req.method === 'OPTIONS') {
      res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS')
      res.writeHead(204)
      res.end()
      return
    }

    let path = ''
    try {
      path = new URL(req.url, `http://0.0.0.0:${this.port}`).pathname
    } catch {
      writeJson(res, { error: 'Invalid URL' }, 400)
      return
    }

    try {
      if (hiveHost.kind === 'app') {
        if ((req.method === 'GET' || req.method === 'HEAD') && path === HIVE_APP_DOCUMENT_PATH) {
          return this._serveHiveAppDocument(
            req,
            res,
            hiveHost,
            bytes => this._reserveEgress(ip, requestBucket, bytes),
            Math.ceil(this._egressWindowMs / 1000)
          )
        }
        await this._gateway.handle(req, res, issueExactAppContext({
          appKey: hiveHost.appKey,
          path,
          publicAppKeys: this.hiveAppPublicKeys,
          driveVersion: this.hiveAppPublicVersions.get(hiveHost.appKey) ?? null,
          reserveResponseBytes: bytes => this._reserveEgress(ip, requestBucket, bytes),
          egressRetryAfterSeconds: Math.ceil(this._egressWindowMs / 1000)
        }))
        return
      }

      // Hyperdrive gateway — the primary data-plane route
      if (path.startsWith('/v1/hyper/')) {
        await this._gateway.handle(req, res)
        return
      }

      // Public catalog — safe to serve on the data plane
      if (req.method === 'GET' && path === '/catalog.json') {
        return this._serveCatalog(req, res)
      }

      // Simple liveness check for load balancers
      if (req.method === 'GET' && (path === '/health' || path === '/')) {
        writeJson(res, { ok: true, service: 'gateway' })
        return
      }

      writeJson(res, { error: 'Not found' }, 404)
    } catch (err) {
      this._handleRequestError(res, err)
    }
  }

  _serveCatalog (req, res) {
    const url = new URL(req.url, `http://0.0.0.0:${this.port}`)
    const result = buildGatewayCatalogPayload({ node: this.node, url })
    if (!result.ok) {
      writeJson(res, result.payload, result.status || 400)
      return
    }

    writeJson(res, result.payload, 200, { 'Cache-Control': 'public, max-age=30' })
  }

  _serveHiveAppDocument (req, res, hiveHost, reserveResponseBytes = null, retryAfterSeconds = 60) {
    const entry = this.node.seededApps?.get(hiveHost.appKey)
    if (!admitPublicHiveAppEntry(entry, {
      appKey: hiveHost.appKey,
      publicAppKeys: this.hiveAppPublicKeys
    }).allowed) {
      writeJson(res, { error: 'App unavailable through public Hive gateway' }, 403)
      return
    }
    const pinnedVersion = this.hiveAppPublicVersions.get(hiveHost.appKey)
    if (!Number.isSafeInteger(pinnedVersion) || pinnedVersion <= 0 ||
        entry.storageProvedDriveVersion !== pinnedVersion ||
        !this.node.appLifecycle || typeof this.node.appLifecycle.acquireDriveReadLease !== 'function') {
      writeJson(res, { error: 'App unavailable through public Hive gateway' }, 403)
      return
    }
    let lease = null
    try {
      lease = this.node.appLifecycle.acquireDriveReadLease(hiveHost.appKey)
    } catch {}
    if (!lease || lease.drive !== entry.drive || typeof lease.release !== 'function') {
      try {
        if (lease && typeof lease.release === 'function') lease.release()
      } catch {}
      writeJson(res, { error: 'App unavailable through public Hive gateway' }, 403)
      return
    }
    try {
      lease.release()
    } catch {
      writeJson(res, { error: 'App unavailable through public Hive gateway' }, 403)
      return
    }

    const payload = Buffer.from(JSON.stringify({
      type: 'hiverelay-public-app-v1',
      appKey: hiveHost.appKey,
      gatewayHost: hiveHost.host,
      byteMode: 'exact',
      privacyTier: 'public',
      storageClass: 'persistent',
      availabilityClass: String(entry.availabilityClass).toLowerCase(),
      signed: false,
      limitation: 'HTTPS transport does not prove Hypercore content provenance'
    }) + '\n')

    const representation = selectExactByteRepresentation(payload, req.headers && req.headers.range)
    res.setHeader('Accept-Ranges', 'bytes')
    if (!representation.ok) {
      res.setHeader('Content-Range', representation.contentRange)
      writeJson(res, { error: 'Range Not Satisfiable' }, 416)
      return
    }
    if (representation.contentRange) res.setHeader('Content-Range', representation.contentRange)

    if (
      req.method !== 'HEAD' &&
      typeof reserveResponseBytes === 'function' &&
      reserveResponseBytes(representation.payload.byteLength) !== true
    ) {
      writeJson(res, { error: 'Gateway byte-rate limit exceeded' }, 429, { 'Retry-After': String(retryAfterSeconds) })
      return
    }

    res.setHeader('Content-Type', 'application/json; charset=utf-8')
    res.setHeader('Content-Length', representation.payload.byteLength)
    res.setHeader('Cache-Control', 'no-store, max-age=0')
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('X-Hive-App-Key', hiveHost.appKey)
    res.setHeader('X-Hive-Byte-Mode', 'generated')
    res.setHeader('Vary', 'Host')
    res.setHeader('Origin-Agent-Cluster', '?1')
    res.writeHead(representation.status)
    res.end(req.method === 'HEAD' ? null : representation.payload)
  }
}

function assertPublicT1GatewayOverridesMatchConfig (opts, config) {
  const mappings = [
    ['gatewayPort', 'gatewayPort'],
    ['gatewayHost', 'gatewayHost'],
    ['trustProxy', 'gatewayTrustProxy'],
    ['trustedProxyAddresses', 'gatewayTrustedProxyAddresses'],
    ['requireForwardedSNI', 'gatewayRequireForwardedSNI'],
    ['compatibilityHosts', 'gatewayCompatibilityHosts'],
    ['hiveAppHostSuffix', 'hiveAppHostSuffix'],
    ['hiveAppPublicKeys', 'hiveAppPublicKeys'],
    ['hiveAppPublicVersions', 'hiveAppPublicVersions'],
    ['egressBytesPerWindow', 'gatewayEgressBytesPerWindow'],
    ['egressWindowMs', 'gatewayEgressWindowMs'],
    ['maxResponseLifetimeMs', 'gatewayMaxResponseLifetimeMs'],
    ['maxInFlight', 'gatewayMaxInFlight'],
    ['maxInFlightPerApp', 'gatewayMaxInFlightPerApp']
  ]
  for (const [optionName, configName] of mappings) {
    if (!Object.prototype.hasOwnProperty.call(opts, optionName)) continue
    if (!deepEqualJson(opts[optionName], config[configName])) {
      throw new Error(`public-t1-gateway ${optionName} override must exactly match node config`)
    }
  }
}

function deepEqualJson (left, right) {
  if (left === right) return true
  if (Array.isArray(left) && Array.isArray(right)) {
    return left.length === right.length && left.every((value, index) => deepEqualJson(value, right[index]))
  }
  if (!left || !right || typeof left !== 'object' || typeof right !== 'object' ||
      Array.isArray(left) || Array.isArray(right)) return false
  const leftKeys = Object.keys(left).sort()
  const rightKeys = Object.keys(right).sort()
  return leftKeys.length === rightKeys.length && leftKeys.every((key, index) =>
    key === rightKeys[index] && deepEqualJson(left[key], right[key]))
}

function readonlySet (set) {
  return new Proxy(set, {
    get (target, property) {
      if (property === 'add' || property === 'delete' || property === 'clear') {
        return () => { throw new Error('Exact app-host admission set is immutable') }
      }
      const value = Reflect.get(target, property, target)
      return typeof value === 'function' ? value.bind(target) : value
    }
  })
}

function readonlyMap (map) {
  return new Proxy(map, {
    get (target, property) {
      if (property === 'set' || property === 'delete' || property === 'clear') {
        return () => { throw new Error('Exact app-host version pins are immutable') }
      }
      const value = Reflect.get(target, property, target)
      return typeof value === 'function' ? value.bind(target) : value
    }
  })
}

function strictPositiveInteger (value, fallback, label, max) {
  if (value === undefined || value === null) return fallback
  if (!Number.isSafeInteger(value) || value < 1 || value > max) {
    throw new Error(`${label} must be an integer from 1 to ${max}`)
  }
  return value
}

function isStrictPort (value) {
  return Number.isSafeInteger(value) && value > 0 && value <= 65535
}

function isLoopbackHost (value) {
  if (typeof value !== 'string') return false
  const host = value.trim().toLowerCase()
  if (host === 'localhost' || host === '::1' || host === '[::1]') return true
  if (isIP(host) !== 4) return false
  return host.startsWith('127.')
}

function normalizeIpAddress (value) {
  if (typeof value !== 'string' || value.length > 64) return null
  let address = value.trim().toLowerCase()
  if (address.startsWith('::ffff:')) {
    const mapped = address.slice(7)
    if (isIP(mapped) === 4) address = mapped
  }
  return isIP(address) ? address : null
}

function normalizeSingleForwardedIp (value) {
  if (Array.isArray(value) || typeof value !== 'string' || value.length > 64 || value.includes(',')) return null
  return normalizeIpAddress(value)
}

function normalizeTrustedProxyAddresses (value) {
  if (!Array.isArray(value) || value.length > MAX_HOST_ALLOWLIST_ENTRIES) return null
  const addresses = new Set()
  for (const candidate of value) {
    const normalized = normalizeIpAddress(candidate)
    if (!normalized) return null
    addresses.add(normalized)
  }
  return addresses
}

function normalizeCompatibilityHosts (value) {
  if (!Array.isArray(value) || value.length > MAX_HOST_ALLOWLIST_ENTRIES) return null
  const hosts = new Set()
  for (const candidate of value) {
    const normalized = normalizeCompatibilityHost(candidate)
    if (!normalized) return null
    hosts.add(normalized)
  }
  return hosts
}

function normalizeCompatibilityHost (value) {
  if (typeof value !== 'string' || !value || value !== value.trim() || value.includes(',')) return null

  if (value.startsWith('[')) {
    const match = /^\[([0-9a-f:.]+)\](?::([0-9]{1,5}))?$/i.exec(value)
    if (!match || isIP(match[1]) !== 6 || !validOptionalPort(match[2])) return null
    return `[${match[1].toLowerCase()}]`
  }

  const match = /^([a-z0-9.-]+)(?::([0-9]{1,5}))?$/i.exec(value)
  if (!match || !validOptionalPort(match[2])) return null
  let host = match[1].toLowerCase()
  if (host.endsWith('.')) host = host.slice(0, -1)
  if (!host || host.includes('..')) return null
  if (isIP(host)) return host
  if (!host.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return null
  return host
}

function normalizeCorsOrigins (value) {
  if (!Array.isArray(value) || value.length > MAX_HOST_ALLOWLIST_ENTRIES) return null
  const origins = new Set()
  for (const candidate of value) {
    if (candidate === '*') {
      origins.add(candidate)
      continue
    }
    if (typeof candidate !== 'string' || candidate.length > 2048 || candidate !== candidate.trim()) return null
    let parsed
    try { parsed = new URL(candidate) } catch { return null }
    if ((parsed.protocol !== 'http:' && parsed.protocol !== 'https:') || parsed.origin !== candidate) return null
    origins.add(candidate)
  }
  if (origins.has('*') && origins.size !== 1) return null
  return origins
}

function hasRequestBodyFraming (req) {
  const transferEncoding = req.headersDistinct?.['transfer-encoding'] ?? req.headers['transfer-encoding']
  if (Array.isArray(transferEncoding) ? transferEncoding.length > 0 : transferEncoding != null) return true

  const contentLength = req.headersDistinct?.['content-length'] ?? req.headers['content-length']
  const values = Array.isArray(contentLength) ? contentLength : (contentLength == null ? [] : [contentLength])
  if (values.length === 0) return false
  if (values.length !== 1) return true
  return values[0] !== '0'
}

function requestsProofMode (req) {
  const accept = req.headersDistinct?.accept ?? req.headers.accept
  const values = Array.isArray(accept) ? accept : (accept == null ? [] : [accept])
  return values.some(value => typeof value === 'string' && /(?:^|,)\s*application\/vnd\.hiverelay\.proof\+/i.test(value))
}

function validOptionalPort (value) {
  if (value === undefined) return true
  const port = Number(value)
  return Number.isSafeInteger(port) && port > 0 && port <= 65535
}
