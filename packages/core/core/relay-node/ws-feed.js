/**
 * WebSocket live feed for dashboard clients
 *
 * Pushes real-time stats to connected dashboards instead of
 * requiring them to poll HTTP every 5-10 seconds.
 *
 * Attaches to the existing HTTP server via the upgrade path `/ws`.
 * Broadcasts overview stats every 2 seconds and immediately pushes
 * updates on relay node events (debounced to max 1/sec).
 */

import { timingSafeEqual } from 'node:crypto'
import { WebSocketServer } from 'ws'
import { detailedNetworkState, publicNetworkState } from './api-network-state.js'
import { buildOperatorAutoHealPayload } from './api-operator-telemetry.js'
import { buildReputationLeaderboardPayload } from './api-reputation-read.js'

const BROADCAST_INTERVAL_MS = 2000
const EVENT_DEBOUNCE_MS = 1000
const DEFAULT_AUTH_TIMEOUT_MS = 5000
const MAX_AUTH_MESSAGE_BYTES = 2048
const MAX_DASHBOARD_AUTO_HEAL_DRIVES = 50
const MAX_DASHBOARD_PAYMENT_ACCOUNTS = 25
const DASHBOARD_CUSTODY_COUNTERS = [
  'intents',
  'withQuorum',
  'committed',
  'retired',
  'withProof',
  'withNonServingProof',
  'withWitnessTombstone',
  'totalReceipts',
  'totalProofs',
  'totalNonServingProofs',
  'totalWitnessTombstones'
]

export class DashboardFeed {
  constructor (opts = {}) {
    this.server = opts.server
    this.node = opts.node
    this.corsOrigins = opts.corsOrigins || '*'
    this._apiKey = opts.apiKey || null
    this._authTimeoutMs = opts.authTimeoutMs || DEFAULT_AUTH_TIMEOUT_MS
    this.wss = null
    this._broadcastTimer = null
    this._eventDebounceTimer = null
    this._eventListeners = []
    this.clientCount = 0
  }

  start () {
    this.wss = new WebSocketServer({ noServer: true })

    // Handle upgrade requests on path /ws
    // We only handle our own path and return silently otherwise so other
    // upgrade listeners can route their own paths from the same HTTP server.
    this._upgradeHandler = (req, socket, head) => {
      const url = new URL(req.url, 'http://localhost')
      if (url.pathname !== '/ws') return

      // Validate Origin header when CORS is restricted. Same-origin browser
      // dashboard sockets are allowed even with the default empty CORS list;
      // cross-origin dashboards still need an explicit allowlist entry.
      if (this.corsOrigins !== '*') {
        if (!isAllowedDashboardOrigin(req, this.corsOrigins)) {
          socket.write('HTTP/1.1 403 Forbidden\r\n\r\n')
          socket.destroy()
          return
        }
      }

      // Never accept management credentials in the WebSocket URL. URLs are
      // easy to leak through logs, browser history, and proxy diagnostics; the
      // browser client authenticates with an immediate in-band auth frame.
      if (url.searchParams.has('token') || url.searchParams.has('api_key')) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n')
        socket.destroy()
        this._emitAuthFailure('query-token')
        return
      }

      this.wss.handleUpgrade(req, socket, head, (ws) => {
        this.wss.emit('connection', ws, req)
      })
    }
    this.server.on('upgrade', this._upgradeHandler)

    this.wss.on('connection', (ws) => {
      ws.on('error', () => {
        // Swallow client errors — the close event will clean up
      })

      if (this._apiKey) {
        this._awaitClientAuth(ws)
      } else {
        this._acceptClient(ws)
      }
    })

    // Periodic broadcast every 2 seconds
    this._broadcastTimer = setInterval(() => {
      if (this.clientCount === 0) return
      const payload = this._buildPayload()
      if (payload) this._broadcast(payload)
    }, BROADCAST_INTERVAL_MS)
    if (this._broadcastTimer.unref) this._broadcastTimer.unref()

    // Listen for relay node events and push immediate updates
    const events = [
      'connection', 'connection-closed', 'seeding', 'unseeded', 'circuit-closed',
      // AutoHeal events — push immediately so dashboards can show fresh
      // recruitment activity without waiting for the 2s tick.
      'auto-heal-recruited', 'auto-heal-error',
      'auto-heal-proof-failed', 'auto-heal-throttled',
      // Custody pipeline events — emitted by the registry as intents are
      // created, receipts arrive, and quorums commit. Bubbled up from
      // SeedingRegistry by relay-node/index.js with normalized names.
      'custody-intent', 'custody-receipt', 'custody-commit',
      'custody-proof', 'custody-retired', 'custody-non-serving-proof',
      'custody-expiry-witness'
    ]
    for (const evt of events) {
      const handler = () => this._debouncedEventBroadcast()
      this.node.on(evt, handler)
      this._eventListeners.push({ event: evt, handler })
    }

    // Also listen on relay sub-emitter for circuit-closed
    if (this.node.relay) {
      const handler = () => this._debouncedEventBroadcast()
      this.node.relay.on('circuit-closed', handler)
      this._eventListeners.push({ emitter: this.node.relay, event: 'circuit-closed', handler })
    }
  }

  async stop () {
    // Clear timers
    if (this._broadcastTimer) {
      clearInterval(this._broadcastTimer)
      this._broadcastTimer = null
    }
    if (this._eventDebounceTimer) {
      clearTimeout(this._eventDebounceTimer)
      this._eventDebounceTimer = null
    }

    // Remove event listeners
    for (const { emitter, event, handler } of this._eventListeners) {
      const target = emitter || this.node
      removeEventListener(target, event, handler)
    }
    this._eventListeners = []

    // Detach the upgrade handler so the HTTP server can be reused
    if (this._upgradeHandler && this.server) {
      this.server.removeListener('upgrade', this._upgradeHandler)
      this._upgradeHandler = null
    }

    // Close all connected clients
    if (this.wss) {
      const wss = this.wss
      for (const ws of this.wss.clients) {
        try { ws.terminate() } catch {}
      }
      this.wss = null
      await new Promise((resolve) => {
        try { wss.close(resolve) } catch (_) { resolve() }
      })
    }

    this.clientCount = 0
  }

  _broadcast (data) {
    if (!this.wss) return
    const msg = JSON.stringify(data)
    for (const ws of this.wss.clients) {
      if (ws._hiverelayReady === true && ws.readyState === 1) { // WebSocket.OPEN
        try { ws.send(msg) } catch {}
      }
    }
  }

  _awaitClientAuth (ws) {
    let finished = false
    const timer = setTimeout(() => {
      if (finished) return
      finished = true
      this._emitAuthFailure('timeout')
      try { ws.close(1008, 'auth-required') } catch {}
    }, this._authTimeoutMs)
    if (timer.unref) timer.unref()

    const finish = () => {
      if (finished) return false
      finished = true
      clearTimeout(timer)
      return true
    }

    ws.once('message', (data) => {
      if (!finish()) return
      const token = parseAuthToken(data)
      if (!safeTokenEqual(token, this._apiKey)) {
        this._emitAuthFailure('invalid')
        try { ws.close(1008, 'auth-failed') } catch {}
        return
      }
      this._acceptClient(ws)
    })

    ws.once('close', () => {
      finish()
    })
  }

  _acceptClient (ws) {
    if (ws._hiverelayReady === true) return
    ws._hiverelayReady = true
    this.clientCount++

    ws.on('close', () => {
      if (ws._hiverelayReady !== true) return
      ws._hiverelayReady = false
      this.clientCount = Math.max(0, this.clientCount - 1)
    })

    // Send an immediate snapshot to newly authenticated clients.
    const snapshot = this._buildPayload()
    if (snapshot) {
      try { ws.send(JSON.stringify(snapshot)) } catch {}
    }
  }

  _emitAuthFailure (reason) {
    if (this.node && typeof this.node.emit === 'function') {
      this.node.emit('dashboard-ws-auth-failed', { reason })
    }
  }

  _debouncedEventBroadcast () {
    if (this._eventDebounceTimer) return
    this._eventDebounceTimer = setTimeout(() => {
      this._eventDebounceTimer = null
      if (this.clientCount === 0) return
      const payload = this._buildPayload()
      if (payload) this._broadcast(payload)
    }, EVENT_DEBOUNCE_MS)
    if (this._eventDebounceTimer.unref) this._eventDebounceTimer.unref()
  }

  _buildPayload () {
    const node = this.node
    if (!node || !node.running) return null

    const stats = node.getStats({ includeSecrets: false })
    const mem = process.memoryUsage()
    const uptimeMs = node.metrics ? Date.now() - node.metrics.startedAt : 0
    const days = Math.floor(uptimeMs / 86400000)
    const h = Math.floor((uptimeMs % 86400000) / 3600000)
    const m = Math.floor((uptimeMs % 3600000) / 60000)
    const parts = []
    if (days > 0) parts.push(`${days}d`)
    if (h > 0) parts.push(`${h}h`)
    parts.push(`${m}m`)

    const config = node.config || {}
    const maxStorage = config.maxStorageBytes || 5368709120
    // Honest bytes (Phase 0): measured corestore total first, then the
    // legacy cached-disk / seeder-counter fallbacks.
    const measuredStored = stats.storage && stats.storage.totalBytes > 0 ? stats.storage.totalBytes : null
    const bytesStored = measuredStored != null
      ? measuredStored
      : (node._cachedStorageUsed || (stats.seeder ? stats.seeder.totalBytesStored : 0))
    // Honest served bytes — measured across every replicated core, with the
    // legacy seeder counter as the fallback (see api.js /api/overview).
    const measuredServed = stats.served ? stats.served.totalBytesServed : null
    const bytesServed = measuredServed != null ? measuredServed : (stats.seeder ? stats.seeder.totalBytesServed : 0)

    const payload = {
      type: 'update',
      timestamp: Date.now(),
      overview: {
        uptime: { ms: uptimeMs, human: parts.join(' ') },
        publicKey: stats.publicKey,
        region: (config.regions && config.regions[0]) || null,
        connections: stats.connections,
        seededApps: stats.seededApps,
        storage: {
          used: bytesStored,
          max: maxStorage,
          pct: maxStorage > 0 ? Math.round(bytesStored / maxStorage * 10000) / 10000 : 0
        },
        served: {
          bytes: bytesServed,
          blocks: stats.served ? stats.served.totalBlocksServed : null,
          measured: measuredServed != null
        },
        relay: sanitizeDashboardRelayStats(stats.relay),
        seeder: sanitizeDashboardSeederStats(stats.seeder, measuredServed),
        memory: { heapUsed: mem.heapUsed, rss: mem.rss },
        errors: node.metrics ? node.metrics._errorCount : 0,
        reputation: sanitizeDashboardReputationOverview(node.reputation),
        tor: sanitizeDashboardTransportInfo(stats.tor),
        bandwidth: sanitizeDashboardBandwidthOverview(node._bandwidthReceipt),
        credits: sanitizeDashboardCreditStats(readDashboardStats(node.creditManager)),
        metering: sanitizeDashboardMeteringStats(readDashboardStats(node.serviceMeter)),
        invoices: sanitizeDashboardInvoiceStats(readDashboardStats(node.invoiceManager)),
        payment: sanitizeDashboardPaymentOverview(node.paymentManager, stats.payment),
        holesail: sanitizeDashboardTransportInfo(stats.holesail)
      },
      dashboardClients: this.clientCount
    }

    // Include network discovery state if available
    if (node.networkDiscovery) {
      try {
        const state = node.networkDiscovery.getNetworkState()
        payload.network = this._apiKey ? detailedNetworkState(state) : publicNetworkState(state)
      } catch {}
    }

    // ─── AutoHeal: replica-durability scheduler state ───
    // Surfaces per-drive diversity (replicas / regions / operators), threshold
    // status, recruit backoffs, and proof-cache size. Dashboards use this to
    // alert on archive-tier drives that have fallen below the SLO floor.
    if (node.autoHeal && typeof node.autoHeal.snapshot === 'function') {
      try {
        const snap = buildOperatorAutoHealPayload(node.autoHeal.snapshot())
        payload.autoHeal = {
          enabled: snap.enabled,
          running: snap.running,
          tickMs: snap.tickMs,
          thresholds: snap.thresholds,
          tracked: snap.tracked,
          below: snap.below,
          backoffs: snap.backoffs,
          verifyProofs: snap.verifyProofs,
          proofCacheSize: snap.proofCacheSize,
          // Drive list capped to keep payload bounded — relays seeding 10K+
          // archive drives shouldn't blow up every WS frame. Dashboards
          // requesting full detail can hit GET /api/auto-heal.
          drives: snap.drives.slice(0, MAX_DASHBOARD_AUTO_HEAL_DRIVES)
        }
      } catch {}
    }

    // ─── Atomic custody: registry snapshot ───
    // Aggregate custody state — intent count, quorum-met, committed,
    // proofs received, non-serving-proofs outstanding. Lets dashboards
    // visualize whether the trust pipeline is converging.
    const registry = node.seedingRegistry || node.registry
    if (registry && typeof registry.custodySnapshot === 'function') {
      try {
        payload.custody = sanitizeDashboardCustodySnapshot(registry.custodySnapshot())
      } catch {}
    }

    return payload
  }
}

function isAllowedDashboardOrigin (req, corsOrigins) {
  const origin = req.headers.origin
  if (!origin) return false

  const allowed = Array.isArray(corsOrigins)
    ? corsOrigins
    : [corsOrigins]
  if (allowed.includes(origin)) return true

  return isSameOriginHost(origin, req.headers.host)
}

function isSameOriginHost (origin, host) {
  if (!host || typeof origin !== 'string') return false
  try {
    const url = new URL(origin)
    return (url.protocol === 'http:' || url.protocol === 'https:') && url.host === host
  } catch {
    return false
  }
}

function removeEventListener (target, event, handler) {
  if (target && typeof target.removeListener === 'function') {
    target.removeListener(event, handler)
    return
  }
  if (target && typeof target.off === 'function') {
    target.off(event, handler)
  }
}

function sanitizeDashboardCustodySnapshot (snapshot) {
  const payload = {}
  const source = snapshot && typeof snapshot === 'object' && !Array.isArray(snapshot)
    ? snapshot
    : {}

  for (const field of DASHBOARD_CUSTODY_COUNTERS) {
    payload[field] = safeDashboardCounter(source[field])
  }
  payload.commitRate = safeDashboardRatio(source.commitRate)

  return payload
}

function sanitizeDashboardTransportInfo (info) {
  const source = info && typeof info === 'object' && !Array.isArray(info)
    ? info
    : null
  if (!source) return null

  const payload = {}
  if (typeof source.running === 'boolean') payload.running = source.running
  if (typeof source.enabled === 'boolean') payload.enabled = source.enabled
  if (typeof source.connected === 'boolean') payload.connected = source.connected
  if (Number.isFinite(source.activeConnections)) {
    payload.activeConnections = safeDashboardCounter(source.activeConnections)
  }
  if (Number.isFinite(source.connections)) {
    payload.connections = safeDashboardCounter(source.connections)
  }

  return Object.keys(payload).length > 0 ? payload : null
}

function sanitizeDashboardRelayStats (stats) {
  const source = safeDashboardObject(stats) || {}
  return {
    activeCircuits: safeDashboardCounter(source.activeCircuits),
    totalCircuitsServed: safeDashboardCounter(source.totalCircuitsServed),
    totalBytesRelayed: safeDashboardCounter(source.totalBytesRelayed),
    capacityUsedPct: safeDashboardPercent(source.capacityUsedPct),
    peersWithCircuits: safeDashboardCounter(source.peersWithCircuits)
  }
}

function sanitizeDashboardSeederStats (stats, measuredServed) {
  const source = safeDashboardObject(stats) || {}
  return {
    coresSeeded: safeDashboardCounter(source.coresSeeded),
    totalBytesStored: safeDashboardCounter(source.totalBytesStored),
    totalBytesServed: safeDashboardCounter(source.totalBytesServed),
    capacityUsedPct: safeDashboardPercent(source.capacityUsedPct),
    totalBytesServedMeasured: measuredServed == null ? null : safeDashboardCounter(measuredServed)
  }
}

function sanitizeDashboardReputationOverview (reputation) {
  if (!reputation || typeof reputation !== 'object') return null
  let trackedRelays = 0
  try {
    const exported = typeof reputation.export === 'function' ? reputation.export() : null
    trackedRelays = exported && typeof exported === 'object' && !Array.isArray(exported)
      ? Object.keys(exported).length
      : 0
  } catch {}

  let topRelay = null
  try {
    const result = buildReputationLeaderboardPayload({ reputation, maxEntries: 1 })
    topRelay = Array.isArray(result.payload) && result.payload.length > 0
      ? result.payload[0]
      : null
  } catch {}

  return {
    trackedRelays: safeDashboardCounter(trackedRelays),
    topRelay
  }
}

function sanitizeDashboardBandwidthOverview (tracker) {
  if (!tracker) return null
  let totalProvenBytes = 0
  try {
    totalProvenBytes = typeof tracker.getTotalProvenBandwidth === 'function'
      ? tracker.getTotalProvenBandwidth()
      : 0
  } catch {}

  return {
    totalProvenBytes: safeDashboardCounter(totalProvenBytes),
    receiptsIssued: Array.isArray(tracker._issuedReceipts)
      ? safeDashboardCounter(tracker._issuedReceipts.length)
      : 0
  }
}

function sanitizeDashboardCreditStats (stats) {
  const source = safeDashboardObject(stats)
  if (!source) return null
  return {
    totalWallets: safeDashboardCounter(source.totalWallets),
    totalBalance: safeDashboardCounter(source.totalBalance),
    totalDeposited: safeDashboardCounter(source.totalDeposited),
    totalSpent: safeDashboardCounter(source.totalSpent),
    totalWelcomeCredits: safeDashboardCounter(source.totalWelcomeCredits),
    welcomeCreditsPerWallet: safeDashboardCounter(source.welcomeCreditsPerWallet),
    frozenWallets: safeDashboardCounter(source.frozenWallets),
    avgBalance: safeDashboardCounter(source.avgBalance)
  }
}

function sanitizeDashboardMeteringStats (stats) {
  const source = safeDashboardObject(stats)
  if (!source) return null
  return {
    totalApps: safeDashboardCounter(source.totalApps),
    totalCalls: safeDashboardCounter(source.totalCalls),
    totalRevenue: safeDashboardCounter(source.totalRevenue),
    windowStart: safeDashboardTimestamp(source.windowStart)
  }
}

function sanitizeDashboardInvoiceStats (stats) {
  const source = safeDashboardObject(stats)
  if (!source) return null
  return {
    total: safeDashboardCounter(source.total),
    pending: safeDashboardCounter(source.pending),
    settled: safeDashboardCounter(source.settled),
    expired: safeDashboardCounter(source.expired),
    cancelled: safeDashboardCounter(source.cancelled),
    totalSettledSats: safeDashboardCounter(source.totalSettledSats)
  }
}

function sanitizeDashboardPaymentOverview (paymentManager, paymentStats) {
  const stats = safeDashboardObject(paymentStats)
  if (!paymentManager && !stats) return null

  return {
    enabled: stats ? stats.enabled === true : !!paymentManager,
    active: stats ? stats.active === true : !!paymentManager,
    experimental: stats ? stats.experimental === true : true,
    settlementIntervalMs: stats ? safeDashboardTimestamp(stats.settlementIntervalMs) : null,
    provider: safeDashboardLabel(paymentManager && paymentManager.paymentProvider && paymentManager.paymentProvider.constructor
      ? paymentManager.paymentProvider.constructor.name
      : null, 'none'),
    accounts: sanitizeDashboardPaymentAccounts(paymentManager)
  }
}

function sanitizeDashboardPaymentAccounts (paymentManager) {
  if (!paymentManager || !paymentManager.accounts || typeof paymentManager.accounts[Symbol.iterator] !== 'function') return []

  const accounts = []
  for (const [pubkey] of paymentManager.accounts) {
    let raw = null
    try {
      raw = typeof paymentManager.getAccountSummary === 'function'
        ? paymentManager.getAccountSummary(pubkey)
        : null
    } catch {}
    const clean = sanitizeDashboardPaymentAccount(raw)
    if (clean) accounts.push(clean)
    if (accounts.length >= MAX_DASHBOARD_PAYMENT_ACCOUNTS) break
  }
  return accounts
}

function sanitizeDashboardPaymentAccount (account) {
  const source = safeDashboardObject(account)
  if (!source) return null
  return {
    monthsActive: safeDashboardCounter(source.monthsActive),
    heldPercentage: safeDashboardPercent(source.heldPercentage),
    totalEarned: safeDashboardCounter(source.totalEarned),
    totalPaid: safeDashboardCounter(source.totalPaid),
    currentlyHeld: safeDashboardCounter(source.currentlyHeld),
    pendingPayout: safeDashboardCounter(source.pendingPayout),
    lastSettlement: safeDashboardTimestamp(source.lastSettlement)
  }
}

function readDashboardStats (manager) {
  if (!manager || typeof manager.stats !== 'function') return null
  try {
    return manager.stats()
  } catch {
    return null
  }
}

function safeDashboardObject (value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null
}

function safeDashboardLabel (value, fallback = null) {
  if (typeof value !== 'string') return fallback
  const trimmed = value.trim()
  if (!trimmed || Buffer.byteLength(trimmed, 'utf8') > 64) return fallback
  for (let i = 0; i < trimmed.length; i++) {
    const code = trimmed.charCodeAt(i)
    if (code < 32 || code === 127) return fallback
  }
  return trimmed
}

function safeDashboardCounter (value) {
  if (!Number.isFinite(value) || value < 0) return 0
  return Math.min(Math.floor(value), Number.MAX_SAFE_INTEGER)
}

function safeDashboardPercent (value) {
  if (!Number.isFinite(value)) return 0
  return Math.min(100, Math.max(0, Math.floor(value)))
}

function safeDashboardTimestamp (value) {
  if (!Number.isFinite(value) || value < 0) return null
  return Math.min(Math.floor(value), Number.MAX_SAFE_INTEGER)
}

function safeDashboardRatio (value) {
  if (value === null || value === undefined) return null
  if (!Number.isFinite(value) || value < 0 || value > 1) return null
  return value
}

function parseAuthToken (data) {
  const size = typeof data === 'string'
    ? Buffer.byteLength(data)
    : (Buffer.isBuffer(data) ? data.length : (data && data.byteLength) || 0)
  if (size <= 0 || size > MAX_AUTH_MESSAGE_BYTES) return null

  let msg
  try {
    const text = typeof data === 'string' ? data : Buffer.from(data).toString('utf8')
    msg = JSON.parse(text)
  } catch {
    return null
  }
  if (!msg || msg.type !== 'auth' || typeof msg.token !== 'string') return null
  return msg.token
}

function safeTokenEqual (actual, expected) {
  if (typeof actual !== 'string' || typeof expected !== 'string') return false
  const actualBuf = Buffer.from(actual)
  const expectedBuf = Buffer.from(expected)
  if (actualBuf.length !== expectedBuf.length) return false
  return timingSafeEqual(actualBuf, expectedBuf)
}
