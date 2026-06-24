export const MAX_HEALTH_DISK_ERROR_BYTES = 256

const DISK_STATUSES = new Set(['ok', 'warn', 'critical'])

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
  const uptime = node && node.metrics ? node.metrics.getSummary().uptime : null
  const running = node ? node.running : false

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
        version,
        uptime,
        running,
        disk: diskSummary
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
      disk: diskSummary
    }
  }
}
