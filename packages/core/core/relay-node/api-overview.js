import { buildReputationLeaderboardPayload } from './api-reputation-read.js'

export const DEFAULT_MAX_STORAGE_BYTES = 5368709120
export const MAX_OVERVIEW_STRING_BYTES = 128

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
    health,
    bandwidth,
    registry,
    gateway
  }
}
