import { buildReputationLeaderboardPayload } from './api-reputation-read.js'
import { sanitizeGatewayStats } from './api-gateway-stats.js'
import { redactTorInfo } from '../../transports/tor/redaction.js'

export const DEFAULT_MAX_STORAGE_BYTES = 5368709120
export const MAX_OVERVIEW_STRING_BYTES = 128

const OVERVIEW_ROUTES = Object.freeze({
  'GET /api/overview': Object.freeze({ kind: 'overview' })
})

const OVERVIEW_HEALTH_CHECKS = ['memory', 'connections', 'swarm', 'errors', 'disk']
const OVERVIEW_HEALTH_FIELDS = {
  memory: ['heapPct', 'rssMB'],
  connections: ['zeroFor', 'staleCount', 'totalConns', 'stalePct'],
  swarm: [],
  errors: ['errorRate'],
  disk: ['usedPct', 'freeGB', 'totalGB']
}

export function resolveOverviewRoute (method, path) {
  const route = OVERVIEW_ROUTES[`${method} ${path}`]
  if (!route) return null
  return { ...route }
}

function objectRecord (value) {
  return !!value && typeof value === 'object' && !Array.isArray(value)
}

function safeOverviewString (value, maxBytes = MAX_OVERVIEW_STRING_BYTES) {
  if (typeof value !== 'string') return null
  const text = value.trim()
  if (!text || Buffer.byteLength(text, 'utf8') > maxBytes) return null
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i)
    if (code < 32 || code === 127) return null
  }
  return text
}

function safeOverviewCounter (value) {
  const n = Number(value)
  if (!Number.isFinite(n) || n <= 0) return 0
  return Math.floor(n)
}

function safeOverviewMetric (value) {
  const n = Number(value)
  if (!Number.isFinite(n) || n < 0) return null
  return Math.min(n, Number.MAX_SAFE_INTEGER)
}

function safeOverviewBoolean (value) {
  if (value === true) return true
  if (value === false) return false
  return null
}

function safeOverviewTimestamp (value) {
  const n = safeOverviewMetric(value)
  return n === null ? null : Math.floor(n)
}

function assignOverviewMetric (target, key, value) {
  const n = safeOverviewMetric(value)
  if (n !== null) target[key] = n
}

function safeOverviewPositiveCounter (value, fallback) {
  const n = Number(value)
  if (!Number.isFinite(n) || n <= 0) return fallback
  return Math.floor(n)
}

function safeOverviewPercent (value) {
  const n = Number(value)
  if (!Number.isFinite(n) || n <= 0) return 0
  return Math.round(n * 100) / 100
}

function safeOverviewRatio (value) {
  const n = Number(value)
  if (!Number.isFinite(n) || n <= 0) return 0
  return Math.round(n * 10000) / 10000
}

export function formatOverviewUptime (uptimeMs) {
  const ms = Number.isFinite(uptimeMs) && uptimeMs > 0 ? uptimeMs : 0
  const hours = Math.round(ms / 3600000 * 100) / 100
  const days = Math.floor(ms / 86400000)
  const h = Math.floor((ms % 86400000) / 3600000)
  const m = Math.floor((ms % 3600000) / 60000)
  const parts = []
  if (days > 0) parts.push(`${days}d`)
  if (h > 0) parts.push(`${h}h`)
  parts.push(`${m}m`)
  return { ms, hours, human: parts.join(' ') }
}

export function overviewStorage (stats = {}, config = {}) {
  const maxStorage = safeOverviewPositiveCounter(config.maxStorageBytes, DEFAULT_MAX_STORAGE_BYTES)
  const storage = objectRecord(stats.storage) ? stats.storage : null
  const seeder = objectRecord(stats.seeder) ? stats.seeder : null
  const measuredStored = storage && storage.totalBytes != null
    ? safeOverviewCounter(storage.totalBytes)
    : null
  const bytesStored = measuredStored != null && measuredStored > 0
    ? measuredStored
    : safeOverviewCounter(seeder && seeder.totalBytesStored)

  return {
    used: bytesStored,
    max: maxStorage,
    pct: maxStorage > 0 ? safeOverviewRatio(bytesStored / maxStorage) : 0
  }
}

export function overviewServed (stats = {}) {
  const served = objectRecord(stats.served) ? stats.served : null
  const seeder = objectRecord(stats.seeder) ? stats.seeder : null
  const measuredServed = served && served.totalBytesServed != null
    ? safeOverviewCounter(served.totalBytesServed)
    : null
  const bytesServed = measuredServed != null
    ? measuredServed
    : safeOverviewCounter(seeder && seeder.totalBytesServed)

  return {
    bytes: bytesServed,
    blocks: served && served.totalBlocksServed != null ? safeOverviewCounter(served.totalBlocksServed) : null,
    measured: measuredServed != null
  }
}

export function overviewRelay (stats = {}) {
  const source = objectRecord(stats.relay) ? stats.relay : {}
  return {
    activeCircuits: safeOverviewCounter(source.activeCircuits),
    totalCircuitsServed: safeOverviewCounter(source.totalCircuitsServed),
    totalBytesRelayed: safeOverviewCounter(source.totalBytesRelayed),
    capacityUsedPct: safeOverviewPercent(source.capacityUsedPct),
    peersWithCircuits: safeOverviewCounter(source.peersWithCircuits)
  }
}

export function overviewSeeder (stats = {}) {
  const served = objectRecord(stats.served) ? stats.served : null
  const source = objectRecord(stats.seeder) ? stats.seeder : {}
  const measuredServed = served && served.totalBytesServed != null
    ? safeOverviewCounter(served.totalBytesServed)
    : null
  return {
    coresSeeded: safeOverviewCounter(source.coresSeeded),
    totalBytesStored: safeOverviewCounter(source.totalBytesStored),
    totalBytesServed: safeOverviewCounter(source.totalBytesServed),
    capacityUsedPct: safeOverviewPercent(source.capacityUsedPct),
    totalBytesServedMeasured: measuredServed
  }
}

export function reputationOverview (reputation) {
  if (!reputation) return null
  const leaderboard = buildReputationLeaderboardPayload({ reputation, maxEntries: 1 }).payload
  let trackedRelays = 0
  try {
    const exported = typeof reputation.export === 'function' ? reputation.export() : {}
    trackedRelays = objectRecord(exported) ? Object.keys(exported).length : 0
  } catch {
    trackedRelays = 0
  }
  return {
    trackedRelays,
    topRelay: leaderboard.length ? leaderboard[0] : null
  }
}

export function bandwidthOverview (tracker) {
  if (!tracker) return null
  let totalProvenBytes = 0
  try {
    totalProvenBytes = typeof tracker.getTotalProvenBandwidth === 'function'
      ? tracker.getTotalProvenBandwidth()
      : 0
  } catch {
    totalProvenBytes = 0
  }
  return {
    totalProvenBytes: safeOverviewCounter(totalProvenBytes),
    receiptsIssued: Array.isArray(tracker._issuedReceipts) ? safeOverviewCounter(tracker._issuedReceipts.length) : 0
  }
}

export function registryOverview (seedingRegistry, config = {}) {
  if (!seedingRegistry) return null
  return {
    running: seedingRegistry.running === true,
    autoAccept: config.registryAutoAccept !== false
  }
}

export function overviewTorInfo (tor) {
  if (!objectRecord(tor)) return null
  const out = {
    running: tor.running === true,
    onionAddress: safeOverviewString(tor.onionAddress, 128),
    activeConnections: safeOverviewCounter(tor.activeConnections)
  }
  // Coarse health for operator UI when present (never invent values).
  if (typeof tor.health === 'string') {
    const h = safeOverviewString(tor.health, 32)
    if (h) out.health = h
  }
  return out
}

/**
 * Role posture for operator dashboards.
 * T1 ≈ public availability/seeding; T2 ≈ custody (shard-store); gateway is separate.
 */
export function overviewRoles (config = {}, node = {}, gateway = null) {
  const enableSeeding = config.enableSeeding !== false
  const enableRelay = config.enableRelay !== false
  const hasOutbox = !!serviceProvider(node, 'outboxlog')
  const hasShard = !!serviceProvider(node, 'shard-store')
  const gatewayOn = !!(gateway) ||
    !!(node && node.gatewayServer) ||
    (Number.isFinite(Number(config.gatewayPort)) && Number(config.gatewayPort) > 0)
  return {
    t1: enableSeeding === true || enableRelay === true,
    t2: hasShard,
    gateway: gatewayOn === true,
    outboxlog: hasOutbox,
    witness: config.witness === true || config.enableWitness === true
  }
}

/** Top-level disk pulse from health monitor (duplicate of checks.disk for UI). */
export function overviewDisk (health) {
  if (!objectRecord(health) || !objectRecord(health.checks) || !objectRecord(health.checks.disk)) {
    return null
  }
  const d = health.checks.disk
  const out = {}
  const ok = safeOverviewBoolean(d.ok)
  const critical = safeOverviewBoolean(d.critical)
  if (ok !== null) out.ok = ok
  if (critical !== null) out.critical = critical
  assignOverviewMetric(out, 'usedPct', d.usedPct)
  assignOverviewMetric(out, 'freeGB', d.freeGB)
  assignOverviewMetric(out, 'totalGB', d.totalGB)
  // status string for canary-style health payloads
  if (typeof d.status === 'string') {
    const s = safeOverviewString(d.status, 32)
    if (s) out.status = s
  } else if (out.critical === true) out.status = 'critical'
  else if (out.ok === false) out.status = 'warn'
  else if (out.ok === true) out.status = 'ok'
  return Object.keys(out).length ? out : null
}

/**
 * Public privacy-transport advertisement: coarse health only (no onion addresses).
 * Safe for both public and management overview payloads.
 * Includes negativeProbe when the transport reports it (authorized-client gate bit).
 */
export function overviewPrivacyTransports (node = {}) {
  const list = []
  try {
    if (node && node.torTransport && typeof node.torTransport.getInfo === 'function') {
      const raw = node.torTransport.getInfo()
      const redacted = redactTorInfo(raw, { operator: false })
      if (redacted) {
        const entry = {
          id: 'tor-v3-onion-v1',
          running: redacted.running === true,
          health: typeof redacted.health === 'string' ? redacted.health : 'unknown',
          activeConnections: safeOverviewCounter(redacted.activeConnections)
        }
        // Prefer redacted, fall back to raw for optional coarse bits only.
        const np = safeOverviewBoolean(
          redacted.negativeProbe != null ? redacted.negativeProbe : raw.negativeProbe
        )
        if (np !== null) entry.negativeProbe = np
        list.push(entry)
      }
    }
  } catch {
    /* ignore transport probe failures */
  }
  return list
}

function serviceProvider (node, name) {
  try {
    const entry = node && node.serviceRegistry && node.serviceRegistry.services
      ? node.serviceRegistry.services.get(name)
      : null
    return entry && entry.provider ? entry.provider : null
  } catch {
    return null
  }
}

/** OutboxLog namespace + suppression pulse (management-oriented; counts only). */
export function overviewNamespaces (node = {}, authed = false) {
  if (authed !== true) return null
  const provider = serviceProvider(node, 'outboxlog')
  if (!provider || typeof provider.operatorStats !== 'function') return null
  let stats
  try { stats = provider.operatorStats() } catch { return null }
  if (!objectRecord(stats)) return null
  const namespaces = Array.isArray(stats.namespaces)
    ? stats.namespaces.map((ns) => {
      if (!objectRecord(ns)) return null
      const name = safeOverviewString(ns.name, 64)
      if (!name) return null
      const row = {
        name,
        blind: ns.blind === true,
        writers: safeOverviewCounter(ns.writers),
        bytes24h: safeOverviewCounter(ns.bytes24h)
      }
      if (ns.capBytes24h != null) assignOverviewMetric(row, 'capBytes24h', ns.capBytes24h)
      return row
    }).filter(Boolean)
    : []
  return {
    groups: safeOverviewCounter(stats.groups),
    totalBytes: safeOverviewCounter(stats.totalBytes),
    suppressedCount: safeOverviewCounter(stats.suppressedCount),
    namespaces
  }
}

/** DO-NOT-SERVE / admin-armed compliance pulse. */
export function overviewCompliance (node = {}, config = {}, authed = false) {
  if (authed !== true) return null
  const adminKey = (config.outboxlog && config.outboxlog.adminKey) ||
    process.env.HIVERELAY_OUTBOXLOG_ADMIN_KEY ||
    null
  const adminArmed = typeof adminKey === 'string' && adminKey.length >= 16
  const provider = serviceProvider(node, 'outboxlog')
  let suppressedKeys = 0
  if (provider && typeof provider.takedowns === 'function') {
    try {
      const t = provider.takedowns()
      suppressedKeys = safeOverviewCounter(t && t.count)
    } catch {
      suppressedKeys = 0
    }
  } else if (provider && typeof provider.operatorStats === 'function') {
    try {
      const s = provider.operatorStats()
      suppressedKeys = safeOverviewCounter(s && s.suppressedCount)
    } catch {
      suppressedKeys = 0
    }
  }
  return {
    adminArmed,
    suppressedKeys,
    // HiveRelay OutboxLog suppresses by opaque (appId,key); appId-wide suppress
    // is a peerit-relay concept — keep the field for dashboard parity.
    suppressedAppIds: 0,
    takedownCount: suppressedKeys
  }
}

/** Shard-store aggregate counters for custody role (no per-hash detail). */
export function overviewShardStore (node = {}, authed = false) {
  if (authed !== true) return null
  let provider = null
  try {
    if (typeof node._shardStoreProvider === 'function') provider = node._shardStoreProvider()
  } catch {
    provider = null
  }
  if (!provider) provider = serviceProvider(node, 'shard-store')
  if (!provider) return null
  const m = objectRecord(provider._metrics) ? provider._metrics : {}
  const out = {
    put: safeOverviewCounter(m.put),
    get: safeOverviewCounter(m.get),
    proof: safeOverviewCounter(m.proof),
    rejected: safeOverviewCounter(m.rejected),
    evicted: safeOverviewCounter(m.evicted),
    sweep: safeOverviewCounter(m.sweep)
  }
  // Synchronous byte/held gauges when the provider caches them (Prometheus-aligned).
  if (provider._cachedBytes != null) assignOverviewMetric(out, 'bytes', provider._cachedBytes)
  if (provider._cachedShards != null) assignOverviewMetric(out, 'held', provider._cachedShards)
  else if (m.held != null) assignOverviewMetric(out, 'held', m.held)
  return out
}

/**
 * Normalize a raw WAL / journal stats object into the dashboard contract.
 * Never includes keys, core ids, or record bodies.
 */
export function sanitizeWalStats (raw, source = null) {
  if (!objectRecord(raw)) return null
  const out = {}
  if (typeof source === 'string') {
    const s = safeOverviewString(source, 48)
    if (s) out.source = s
  } else if (typeof raw.source === 'string') {
    const s = safeOverviewString(raw.source, 48)
    if (s) out.source = s
  }
  if (raw.pruningSupported === true || raw.pruningSupported === false) {
    out.pruningSupported = raw.pruningSupported
  }
  if (raw.healthy === true || raw.healthy === false) out.healthy = raw.healthy
  assignOverviewMetric(out, 'framesPerSec', raw.framesPerSec)
  assignOverviewMetric(out, 'fsyncP50Ms', raw.fsyncP50Ms)
  assignOverviewMetric(out, 'fsyncP99Ms', raw.fsyncP99Ms)
  assignOverviewMetric(out, 'spendReplay24h', raw.spendReplay24h)
  assignOverviewMetric(out, 'sizeBytes', raw.sizeBytes)
  assignOverviewMetric(out, 'length', raw.length)
  assignOverviewMetric(out, 'buffered', raw.buffered)
  assignOverviewMetric(out, 'errors', raw.errors)
  assignOverviewMetric(out, 'opsSinceSnapshot', raw.opsSinceSnapshot)
  assignOverviewMetric(out, 'entries', raw.entries)
  if (typeof raw.mode === 'string') {
    const mode = safeOverviewString(raw.mode, 48)
    if (mode) out.mode = mode
  }
  return Object.keys(out).length ? out : null
}

/**
 * Map OutboxLog journalInfo() into WAL-adjacent durability pulse (no core keys).
 */
export function walFromJournalInfo (info) {
  if (!objectRecord(info)) return null
  const length = info.length != null
    ? info.length
    : (objectRecord(info.index) ? info.index.length : null)
  const errors = info.errors != null ? info.errors : 0
  return sanitizeWalStats({
    source: 'outboxlog-journal',
    mode: typeof info.mode === 'string' ? info.mode : 'outboxlog-journal',
    length,
    buffered: info.buffered,
    errors,
    healthy: Number(errors) === 0,
    pruningSupported: false
  }, 'outboxlog-journal')
}

/**
 * WAL / durability pulse (management-only).
 * Probes, in order: node.getWalStats → blind-daemon/shard-store →
 * OutboxLog journalInfo → PersistentStore.getWalStats.
 */
export function overviewWal (node = {}, authed = false) {
  if (authed !== true) return null

  // 1) Explicit node hook (blind cell / production runtime may attach this).
  if (node && typeof node.getWalStats === 'function') {
    try {
      const s = sanitizeWalStats(node.getWalStats(), 'node')
      if (s) return s
    } catch { /* fall through */ }
  }

  // 2) Service providers with getWalStats / walStats.
  for (const name of ['blind-daemon', 'shard-store']) {
    const provider = serviceProvider(node, name)
    const getter = provider && (
      (typeof provider.getWalStats === 'function' && provider.getWalStats) ||
      (typeof provider.walStats === 'function' && provider.walStats)
    )
    if (!getter) continue
    try {
      const s = sanitizeWalStats(getter.call(provider), name)
      if (s) return s
    } catch { /* try next */ }
  }

  // 3) OutboxLog journal durability (mainline HiveRelay).
  const outbox = serviceProvider(node, 'outboxlog')
  if (outbox && typeof outbox.journalInfo === 'function') {
    try {
      const s = walFromJournalInfo(outbox.journalInfo())
      if (s) return s
    } catch { /* fall through */ }
  }

  // 4) Core PersistentStore (JSONL WAL + snapshot prune).
  const store = node && (node.persistentStore || node._persistentStore)
  if (store && typeof store.getWalStats === 'function') {
    try {
      const s = sanitizeWalStats(store.getWalStats(), 'persistent-store')
      if (s) return s
    } catch { /* ignore */ }
  }

  return null
}

/**
 * T1 HTTPS gateway panel for overview (coarse; no drive keys / paths).
 * Additive fields on top of sanitizeGatewayStats counters.
 */
export function overviewGatewayDetail (gateway = null, config = {}, roles = null) {
  let rawStats = null
  if (gateway && typeof gateway.getStats === 'function') {
    try { rawStats = gateway.getStats() } catch { rawStats = null }
  } else if (objectRecord(gateway) && (gateway.totalRequests != null || gateway.cachedDrives != null)) {
    rawStats = gateway
  }
  const stats = rawStats ? sanitizeGatewayStats(rawStats) : null

  const portFromConfig = Number(config && config.gatewayPort)
  const portFromGw = gateway && Number.isFinite(Number(gateway.port)) ? Number(gateway.port) : null
  const enabled = !!(gateway) ||
    (roles && roles.gateway === true) ||
    (Number.isFinite(portFromConfig) && portFromConfig > 0)

  if (!enabled && !stats) return null

  const out = {
    enabled: enabled === true,
    ...(stats || { cachedDrives: 0, totalRequests: 0, totalBytesServed: 0 })
  }
  const port = Number.isFinite(portFromGw) && portFromGw > 0
    ? Math.floor(portFromGw)
    : (Number.isFinite(portFromConfig) && portFromConfig > 0 ? Math.floor(portFromConfig) : null)
  if (port != null) out.port = port

  const hostRaw = (gateway && gateway.host) || (config && config.gatewayHost) || null
  const host = safeOverviewString(hostRaw, 64)
  if (host) out.host = host

  if (objectRecord(rawStats) && (rawStats.verifyFails != null || rawStats.verifyFailTotal != null)) {
    assignOverviewMetric(
      out,
      'verifyFails',
      rawStats.verifyFails != null ? rawStats.verifyFails : rawStats.verifyFailTotal
    )
  }

  const t2 = roles && roles.t2 === true
  out.roleConflict = t2 === true && out.enabled === true
  return out
}

export function overviewHealth (health) {
  if (!objectRecord(health)) return null

  const out = {}
  const healthy = safeOverviewBoolean(health.healthy)
  const lastCheck = safeOverviewTimestamp(health.lastCheck)
  const consecutiveFailures = safeOverviewTimestamp(health.consecutiveFailures)
  const checks = overviewHealthChecks(health.checks)

  if (healthy !== null) out.healthy = healthy
  if (lastCheck !== null) out.lastCheck = lastCheck
  if (consecutiveFailures !== null) out.consecutiveFailures = consecutiveFailures
  if (checks) out.checks = checks

  return Object.keys(out).length > 0 ? out : null
}

function overviewHealthChecks (checks) {
  if (!objectRecord(checks)) return null

  const out = {}
  for (const check of OVERVIEW_HEALTH_CHECKS) {
    const summary = overviewHealthCheck(checks[check], OVERVIEW_HEALTH_FIELDS[check] || [])
    if (summary) out[check] = summary
  }

  return Object.keys(out).length > 0 ? out : null
}

function overviewHealthCheck (entry, numericFields) {
  if (!objectRecord(entry)) return null

  const out = {}
  const ok = safeOverviewBoolean(entry.ok)
  const critical = safeOverviewBoolean(entry.critical)

  if (ok !== null) out.ok = ok
  if (critical !== null) out.critical = critical
  for (const field of numericFields) assignOverviewMetric(out, field, entry[field])

  return Object.keys(out).length > 0 ? out : null
}

export function buildOverviewPayload ({
  stats = {},
  config = {},
  memory = {},
  uptimeMs = 0,
  errors = 0,
  health = null,
  reputation = null,
  tor = null,
  holesailKey = null,
  bandwidth = null,
  registry = null,
  gateway = null,
  roles = null,
  disk = null,
  privacyTransports = null,
  namespaces = null,
  compliance = null,
  shardStore = null,
  wal = null,
  gatewayDetail = null
} = {}) {
  const payload = {
    uptime: formatOverviewUptime(uptimeMs),
    publicKey: safeOverviewString(stats.publicKey, 128),
    region: safeOverviewString(config.regions && config.regions[0], 64),
    connections: safeOverviewCounter(stats.connections),
    seededApps: safeOverviewCounter(stats.seededApps),
    storage: overviewStorage(stats, config),
    served: overviewServed(stats),
    relay: overviewRelay(stats),
    seeder: overviewSeeder(stats),
    memory: { heapUsed: safeOverviewCounter(memory.heapUsed), rss: safeOverviewCounter(memory.rss) },
    errors: safeOverviewCounter(errors),
    reputation,
    tor: overviewTorInfo(tor),
    holesailKey: safeOverviewString(holesailKey, 128),
    health: overviewHealth(health),
    bandwidth,
    registry,
    gateway
  }
  // Operator data-layer upgrade (v0–v2): always attach roles + privacyTransports
  // (coarse); disk when health has it. Management-only blocks are always keys
  // (null when unauthenticated) so dashboard clients can feature-detect stably.
  if (roles) payload.roles = roles
  if (disk) payload.disk = disk
  if (Array.isArray(privacyTransports)) payload.privacyTransports = privacyTransports
  payload.namespaces = namespaces || null
  payload.compliance = compliance || null
  payload.shardStore = shardStore || null
  payload.wal = wal || null
  // v2: richer gateway panel (enabled/port/roleConflict) when assembled.
  payload.gatewayDetail = gatewayDetail || null
  return payload
}

export function buildOverviewRoutePayload ({
  node = {},
  authed = false,
  gateway = null,
  memory = {},
  now = Date.now()
} = {}) {
  const stats = node && typeof node.getStats === 'function'
    ? node.getStats({ includeSecrets: authed === true })
    : {}
  const config = objectRecord(node && node.config) ? node.config : {}
  const metrics = objectRecord(node && node.metrics) ? node.metrics : null
  const uptimeMs = metrics && Number.isFinite(metrics.startedAt) ? now - metrics.startedAt : 0
  const tor = authed === true && node && node.torTransport && typeof node.torTransport.getInfo === 'function'
    ? node.torTransport.getInfo()
    : null
  const holesailKey = authed === true && node && node.holesailTransport
    ? node.holesailTransport.connectionKey
    : null

  const health = node && typeof node.getHealthStatus === 'function' ? node.getHealthStatus() : null
  const gw = gateway || (node && node.gatewayServer) || null
  const gatewayStats = gw && typeof gw.getStats === 'function'
    ? sanitizeGatewayStats(gw.getStats())
    : null
  const roles = overviewRoles(config, node, gw)

  return buildOverviewPayload({
    stats,
    config,
    memory,
    uptimeMs,
    errors: metrics ? metrics._errorCount : 0,
    reputation: reputationOverview(node && node.reputation),
    tor,
    holesailKey,
    health,
    bandwidth: bandwidthOverview(node && node._bandwidthReceipt),
    registry: registryOverview(node && node.seedingRegistry, config),
    gateway: gatewayStats,
    roles,
    disk: overviewDisk(health),
    privacyTransports: overviewPrivacyTransports(node),
    namespaces: overviewNamespaces(node, authed),
    compliance: overviewCompliance(node, config, authed),
    shardStore: overviewShardStore(node, authed),
    wal: overviewWal(node, authed),
    gatewayDetail: overviewGatewayDetail(gw, config, roles)
  })
}

export function buildOverviewRouteResponse ({
  route,
  node = {},
  authed = false,
  gateway = null,
  memory = {},
  now = Date.now()
} = {}) {
  if (!route || route.kind !== 'overview') {
    return {
      ok: false,
      status: 404,
      payload: { error: 'unknown overview route' }
    }
  }

  return {
    ok: true,
    payload: buildOverviewRoutePayload({ node, authed, gateway, memory, now })
  }
}
