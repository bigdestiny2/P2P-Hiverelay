export const MAX_HEALTH_DISK_ERROR_BYTES = 256
export const MAX_HEALTH_FATAL_REASON_BYTES = 128

const DISK_STATUSES = new Set(['ok', 'warn', 'critical'])

export function resolveHealthRoute (method, path) {
  if (method !== 'GET') return null
  if (path === '/health') return { kind: 'health' }
  return null
}

function hasControlChar (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code <= 0x1f || code === 0x7f) return true
  }
  return false
}

function truncateUtf8 (value, maxBytes) {
  if (Buffer.byteLength(value, 'utf8') <= maxBytes) return value
  let out = ''
  let used = 0
  for (const ch of value) {
    const size = Buffer.byteLength(ch, 'utf8')
    if (used + size > maxBytes) break
    out += ch
    used += size
  }
  return out
}

function safeHealthString (value, opts = {}) {
  if (typeof value !== 'string') return null
  const text = value.trim()
  if (!text || hasControlChar(text)) return null
  const maxBytes = Number.isInteger(opts.maxBytes) && opts.maxBytes > 0
    ? opts.maxBytes
    : MAX_HEALTH_DISK_ERROR_BYTES
  if (Buffer.byteLength(text, 'utf8') > maxBytes) {
    return opts.truncate === true ? truncateUtf8(text, maxBytes) : null
  }
  return text
}

function safeHealthNumber (value) {
  const n = Number(value)
  if (!Number.isFinite(n) || n < 0) return 0
  return Math.min(n, Number.MAX_SAFE_INTEGER)
}

function safeDiskStatus (value) {
  const status = safeHealthString(value, { maxBytes: 16 })
  return status && DISK_STATUSES.has(status) ? status : null
}

function resourceDiagnosticsSnapshot (node) {
  if (!node || typeof node.getResourceDiagnostics !== 'function') return null
  try {
    const snapshot = node.getResourceDiagnostics()
    if (!snapshot || snapshot.kind !== 'HiveRelayResourceDiagnosticsV1' || snapshot.version !== 1) return null
    return snapshot
  } catch {
    return null
  }
}

function formatUptime (ms) {
  if (!Number.isSafeInteger(ms) || ms < 0) return null
  const days = Math.floor(ms / 86400000)
  const hours = Math.floor((ms % 86400000) / 3600000)
  const minutes = Math.floor((ms % 3600000) / 60000)
  const parts = []
  if (days > 0) parts.push(`${days}d`)
  if (hours > 0) parts.push(`${hours}h`)
  parts.push(`${minutes}m`)
  return {
    ms,
    hours: Math.round(ms / 3600000 * 100) / 100,
    human: parts.join(' ')
  }
}

function healthUptime (node, diagnostics) {
  const sampled = diagnostics?.process?.uptimeMs
  if (Number.isSafeInteger(sampled) && sampled >= 0) return formatUptime(sampled)
  const startedAt = node?.metrics?.startedAt
  if (!Number.isSafeInteger(startedAt) || startedAt < 0) return null
  return formatUptime(Math.max(0, Date.now() - startedAt))
}

export function diskHealthSummary (disk) {
  if (!disk) return null
  const error = safeHealthString(disk.error, {
    maxBytes: MAX_HEALTH_DISK_ERROR_BYTES,
    truncate: true
  })
  if (error) return { error }
  return {
    usedPct: safeHealthNumber(disk.usedPct),
    status: safeDiskStatus(disk.status)
  }
}

export function buildHealthResponse ({ node, version }) {
  const disk = node && node.diskMonitor ? node.diskMonitor.getInfo() : null
  const diskSummary = diskHealthSummary(disk)
  const resourceDiagnostics = resourceDiagnosticsSnapshot(node)
  const uptime = healthUptime(node, resourceDiagnostics)
  const running = node ? node.running : false
  const storageGeneration = node && typeof node.getStorageGenerationStatus === 'function'
    ? node.getStorageGenerationStatus()
    : null
  const storageFatal = node && node.storageAdmission ? node.storageAdmission.fatalReason : null
  const storageFatalReason = safeHealthString(storageFatal, {
    maxBytes: MAX_HEALTH_FATAL_REASON_BYTES,
    truncate: true
  })

  // A fail-closed storage authority is a terminal state that used to be
  // invisible everywhere: failClosed() sets _fatalReason with no emit, log or
  // metric, and nothing reads the snapshot. Worse than silent — canAcknowledge()
  // then returns false, so every gateway drive read 404s as "still replicating",
  // which actively misdirects whoever is debugging it.
  //
  // Report it before the disk gate: if storage has failed closed, that is the
  // more fundamental fact, and unlike a disk drain a restart will not clear it.
  if (storageFatal) {
    return {
      status: 503,
      payload: {
        ok: false,
        reason: 'storage-fail-closed',
        reasons: [{ code: 'storage-fail-closed', detail: storageFatalReason }],
        storageFatalReason,
        version,
        uptime,
        running,
        disk: diskSummary,
        storageGeneration,
        resourceDiagnostics
      }
    }
  }

  if (
    node &&
    node.config?.diskHealthGate === true &&
    disk &&
    disk.status === 'critical'
  ) {
    return {
      status: 503,
      payload: {
        ok: false,
        reason: 'disk-critical',
        reasons: [{ code: 'disk-critical', status: 'critical' }],
        version,
        uptime,
        running,
        disk: diskSummary,
        storageGeneration,
        resourceDiagnostics
      }
    }
  }

  return {
    status: 200,
    payload: {
      ok: true,
      version,
      uptime,
      running,
      disk: diskSummary,
      storageGeneration,
      resourceDiagnostics
    }
  }
}
