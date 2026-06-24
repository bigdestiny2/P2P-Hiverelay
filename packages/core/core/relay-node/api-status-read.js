import b4a from 'b4a'
import {
  sanitizeServiceCatalogEntries,
  serviceCatalogTotal
} from '../services/service-catalog.js'

export const MAX_STATUS_STRING_BYTES = 128
export const MAX_STATUS_ERROR_BYTES = 512
export const MAX_STATUS_SERVICES = 128

const HEX_64 = /^[0-9a-f]{64}$/i
const DISK_STATUS = new Set(['ok', 'warn', 'critical'])

function isObject (value) {
  return !!value && typeof value === 'object' && !Array.isArray(value)
}

function hasControlChar (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code <= 0x1f || code === 0x7f) return true
  }
  return false
}

function truncateUtf8 (value, maxBytes) {
  if (b4a.byteLength(value) <= maxBytes) return value
  let out = ''
  let used = 0
  for (const ch of value) {
    const size = b4a.byteLength(ch)
    if (used + size > maxBytes) break
    out += ch
    used += size
  }
  return out
}

export function statusString (value, opts = {}) {
  if (typeof value !== 'string') return null
  const maxBytes = Number.isInteger(opts.maxBytes) && opts.maxBytes > 0
    ? opts.maxBytes
    : MAX_STATUS_STRING_BYTES
  const trimmed = opts.trim === false ? value : value.trim()
  if (!trimmed) return null
  if (hasControlChar(trimmed)) return null
  if (b4a.byteLength(trimmed) > maxBytes) {
    if (opts.truncate === true) return truncateUtf8(trimmed, maxBytes)
    return null
  }
  return trimmed
}

function statusHexKey (value) {
  const clean = statusString(value, { maxBytes: 64 })
  return clean && HEX_64.test(clean) ? clean.toLowerCase() : null
}

function bool (value) {
  return value === true
}

function count (value) {
  if (!Number.isFinite(value) || value < 0) return 0
  return Math.min(Math.floor(value), Number.MAX_SAFE_INTEGER)
}

function numberOrZero (value) {
  if (!Number.isFinite(value) || value < 0) return 0
  return Math.min(value, Number.MAX_SAFE_INTEGER)
}

function timestampOrNull (value) {
  if (!Number.isFinite(value) || value < 0) return null
  return Math.min(Math.floor(value), Number.MAX_SAFE_INTEGER)
}

function boolOrNull (value) {
  if (value === true) return true
  if (value === false) return false
  return null
}

export function sanitizeRelayStats (relay) {
  if (!isObject(relay)) return null
  return {
    activeCircuits: count(relay.activeCircuits),
    totalCircuitsServed: count(relay.totalCircuitsServed),
    totalBytesRelayed: count(relay.totalBytesRelayed),
    capacityUsedPct: numberOrZero(relay.capacityUsedPct),
    peersWithCircuits: count(relay.peersWithCircuits)
  }
}

export function sanitizeSeederStats (seeder) {
  if (!isObject(seeder)) return null
  return {
    coresSeeded: count(seeder.coresSeeded),
    totalBytesStored: count(seeder.totalBytesStored),
    totalBytesServed: count(seeder.totalBytesServed),
    capacityUsedPct: numberOrZero(seeder.capacityUsedPct)
  }
}

export function sanitizeStorageSummary (storage) {
  if (!isObject(storage)) return null
  return {
    totalBytes: count(storage.totalBytes),
    measuredEntries: count(storage.measuredEntries),
    fullSweeps: count(storage.fullSweeps),
    lastFullSweepAt: timestampOrNull(storage.lastFullSweepAt)
  }
}

export function sanitizeServedSummary (served) {
  if (!isObject(served)) return null
  return {
    totalBytesServed: count(served.totalBytesServed),
    totalBlocksServed: count(served.totalBlocksServed),
    trackedCores: count(served.trackedCores)
  }
}

export function sanitizeDiskInfo (disk) {
  if (!isObject(disk)) return null
  const status = statusString(disk.status, { maxBytes: 16 })
  return {
    totalBytes: count(disk.totalBytes),
    usedBytes: count(disk.usedBytes),
    availableBytes: count(disk.availableBytes),
    usedPct: numberOrZero(disk.usedPct),
    status: status && DISK_STATUS.has(status) ? status : null,
    checkedAt: timestampOrNull(disk.checkedAt),
    error: statusString(disk.error, {
      maxBytes: MAX_STATUS_ERROR_BYTES,
      truncate: true
    })
  }
}

export function sanitizeReplicationSummary (replication) {
  if (!isObject(replication)) return null
  return {
    trackedApps: count(replication.trackedApps),
    underReplicated: count(replication.underReplicated),
    lastCheckedAt: timestampOrNull(replication.lastCheckedAt),
    repairEnabled: bool(replication.repairEnabled)
  }
}

export function sanitizePaymentSummary (payment) {
  if (!isObject(payment)) return null
  return {
    enabled: bool(payment.enabled),
    active: bool(payment.active),
    experimental: bool(payment.experimental),
    settlementIntervalMs: timestampOrNull(payment.settlementIntervalMs)
  }
}

export function sanitizeTransportSummary (stats) {
  return {
    tor: isObject(stats.tor)
      ? {
          running: bool(stats.tor.running),
          activeConnections: count(stats.tor.activeConnections)
        }
      : null,
    holesail: isObject(stats.holesail)
      ? {
          running: bool(stats.holesail.running)
        }
      : null,
    dhtRelayWs: isObject(stats.dhtRelayWs)
      ? {
          running: bool(stats.dhtRelayWs.running),
          activeConnections: count(stats.dhtRelayWs.activeConnections),
          totalConnectionsServed: count(stats.dhtRelayWs.totalConnectionsServed),
          totalRateLimited: count(stats.dhtRelayWs.totalRateLimited),
          maxConnections: count(stats.dhtRelayWs.maxConnections),
          rateLimit: isObject(stats.dhtRelayWs.rateLimit)
            ? {
                connectionsPerMinutePerIp: count(stats.dhtRelayWs.rateLimit.connectionsPerMinutePerIp),
                maxConcurrentPerIp: count(stats.dhtRelayWs.rateLimit.maxConcurrentPerIp)
              }
            : null
        }
      : null
  }
}

export function sanitizeAppRegistrySummary (appRegistry) {
  if (!isObject(appRegistry)) return null
  return {
    entries: count(appRegistry.entries),
    anchored: count(appRegistry.anchored),
    unanchored: count(appRegistry.unanchored),
    cores: count(appRegistry.cores)
  }
}

export function sanitizeDistributedDriveSummary (distributedDrive) {
  if (!isObject(distributedDrive)) return null
  return {
    enabled: bool(distributedDrive.enabled),
    running: bool(distributedDrive.running),
    moduleAvailable: bool(distributedDrive.moduleAvailable),
    registeredDrives: count(distributedDrive.registeredDrives),
    peers: count(distributedDrive.peers),
    lastError: statusString(distributedDrive.lastError, {
      maxBytes: MAX_STATUS_ERROR_BYTES,
      truncate: true
    })
  }
}

export function sanitizeSignedDirectorySummary (signedDirectory) {
  if (!isObject(signedDirectory)) return null
  return {
    enabled: bool(signedDirectory.enabled),
    entries: count(signedDirectory.entries),
    maxTotalEntries: count(signedDirectory.maxTotalEntries),
    attachedChannels: count(signedDirectory.attachedChannels),
    ttlSeconds: count(signedDirectory.ttlSeconds),
    totalPublished: count(signedDirectory.totalPublished),
    totalRejected: count(signedDirectory.totalRejected),
    totalReplicated: count(signedDirectory.totalReplicated),
    totalEvicted: count(signedDirectory.totalEvicted)
  }
}

export function buildStatusServicesSummary (serviceRegistry) {
  if (!serviceRegistry || typeof serviceRegistry.catalog !== 'function') return null
  try {
    const raw = serviceRegistry.catalog()
    const services = sanitizeServiceCatalogEntries(raw, { maxEntries: MAX_STATUS_SERVICES })
    return {
      count: services.length,
      total: serviceCatalogTotal(raw),
      truncated: serviceCatalogTotal(raw) > services.length,
      services
    }
  } catch (_) {
    return {
      count: 0,
      total: 0,
      truncated: false,
      services: []
    }
  }
}

export function buildStatusPayload ({ node, now = Date.now() } = {}) {
  const stats = node && typeof node.getStats === 'function'
    ? node.getStats({ includeSecrets: false })
    : {}
  const config = (node && node.config) || {}
  const uptimeMs = node && node.metrics && Number.isFinite(node.metrics.startedAt)
    ? Math.max(0, now - node.metrics.startedAt)
    : null
  const health = node && typeof node.getHealthStatus === 'function'
    ? node.getHealthStatus()
    : null

  return {
    status: 200,
    payload: {
      running: bool(stats.running),
      mode: statusString(stats.mode),
      publicKey: statusHexKey(stats.publicKey),
      region: Array.isArray(config.regions) ? statusString(config.regions[0]) : null,
      uptimeMs,
      seededApps: count(stats.seededApps),
      connections: count(stats.connections),
      health: isObject(health)
        ? {
            healthy: boolOrNull(health.healthy),
            reason: statusString(health.reason, {
              maxBytes: MAX_STATUS_ERROR_BYTES,
              truncate: true
            })
          }
        : null,
      relay: sanitizeRelayStats(stats.relay),
      seeder: sanitizeSeederStats(stats.seeder),
      storage: sanitizeStorageSummary(stats.storage),
      served: sanitizeServedSummary(stats.served),
      disk: sanitizeDiskInfo(stats.disk),
      registry: isObject(stats.registry)
        ? {
            running: bool(stats.registry.running)
          }
        : null,
      replication: sanitizeReplicationSummary(stats.replication),
      payment: sanitizePaymentSummary(stats.payment),
      transports: sanitizeTransportSummary(stats),
      reputation: isObject(stats.reputation)
        ? {
            trackedRelays: count(stats.reputation.trackedRelays)
          }
        : null,
      appRegistry: sanitizeAppRegistrySummary(stats.appRegistry),
      distributedDrive: sanitizeDistributedDriveSummary(stats.distributedDrive),
      signedDirectory: sanitizeSignedDirectorySummary(stats.signedDirectory),
      services: buildStatusServicesSummary(node ? node.serviceRegistry : null)
    }
  }
}
