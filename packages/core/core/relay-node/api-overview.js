import { buildReputationLeaderboardPayload } from './api-reputation-read.js'
import { sanitizeGatewayStats } from './api-gateway-stats.js'

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
  return {
    running: tor.running === true,
    onionAddress: safeOverviewString(tor.onionAddress, 128),
    activeConnections: safeOverviewCounter(tor.activeConnections)
  }
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
  gateway = null
} = {}) {
  return {
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

  return buildOverviewPayload({
    stats,
    config,
    memory,
    uptimeMs,
    errors: metrics ? metrics._errorCount : 0,
    reputation: reputationOverview(node && node.reputation),
    tor,
    holesailKey,
    health: node && typeof node.getHealthStatus === 'function' ? node.getHealthStatus() : null,
    bandwidth: bandwidthOverview(node && node._bandwidthReceipt),
    registry: registryOverview(node && node.seedingRegistry, config),
    gateway: gateway && typeof gateway.getStats === 'function' ? sanitizeGatewayStats(gateway.getStats()) : null
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
