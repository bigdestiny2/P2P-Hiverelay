export const MAX_POKER_USAGE_TABLE_ROWS = 100
export const MAX_POKER_USAGE_TABLE_KEY_LENGTH = 128
export const USAGE_DIGEST_NOTE = 'verified = counterparty-signed receipts (payout-eligible). Per-service registry stats are self-reported (statsVerified:false) and are NOT payout-eligible.'
export const USAGE_TELEMETRY_AUTH_ERROR = 'Unauthorized — management API requires API key or localhost access'

const USAGE_TELEMETRY_ROUTES = Object.freeze({
  'GET /api/poker/usage': Object.freeze({
    kind: 'poker-usage',
    authMessage: USAGE_TELEMETRY_AUTH_ERROR
  }),
  'POST /api/usage/receipt': Object.freeze({
    kind: 'receipt-submit'
  }),
  'GET /api/usage': Object.freeze({
    kind: 'usage-digest',
    authMessage: USAGE_TELEMETRY_AUTH_ERROR
  })
})

export function resolveUsageTelemetryRoute (method, path) {
  const route = USAGE_TELEMETRY_ROUTES[`${method} ${path}`]
  if (!route) return null
  return { ...route }
}

export function exportBandwidthReceipts (tracker) {
  if (!tracker || typeof tracker.exportReceipts !== 'function') return []
  try {
    const receipts = tracker.exportReceipts()
    return Array.isArray(receipts) ? receipts : []
  } catch (_) {
    return []
  }
}

export function sumReceiptBytes (receipts) {
  const list = Array.isArray(receipts) ? receipts : []
  return list.reduce((sum, receipt) => {
    const n = Number(receipt && receipt.bytesTransferred)
    return Number.isFinite(n) && n > 0 ? sum + n : sum
  }, 0)
}

export function latestReceiptTimestamp (receipts) {
  const list = Array.isArray(receipts) ? receipts : []
  return list.reduce((latest, receipt) => {
    const ts = Number(receipt && receipt.timestamp) || 0
    return ts > latest ? ts : latest
  }, 0)
}

export function measuredServedBytes (stats) {
  return stats && stats.served && Number.isFinite(stats.served.totalBytesServed)
    ? stats.served.totalBytesServed
    : null
}

export function usageTelemetryPayload (tracker, stats = {}) {
  const receipts = exportBandwidthReceipts(tracker)
  const totalBytes = sumReceiptBytes(receipts)
  const latestAt = latestReceiptTimestamp(receipts)

  return {
    enabled: !!tracker,
    verified: {
      count: receipts.length,
      bytes: totalBytes,
      latestAt: latestAt || null,
      totals: {
        bandwidthBytes: totalBytes
      }
    },
    measured: {
      servedBytes: measuredServedBytes(stats)
    }
  }
}

export function recordUsageReceiptPayload (usageLedger, body) {
  if (!usageLedger || typeof usageLedger.record !== 'function') {
    return {
      status: 503,
      payload: { error: 'metering unavailable' }
    }
  }

  const result = usageLedger.record(body)
  return {
    status: result && result.ok ? 200 : 400,
    payload: result
  }
}

export function usageLedgerDigestPayload (usageLedger) {
  const verified = usageLedger && typeof usageLedger.digest === 'function'
    ? usageLedger.digest()
    : { count: 0, totals: {}, receiptRoot: null }

  return {
    status: 200,
    payload: {
      verified,
      note: USAGE_DIGEST_NOTE
    }
  }
}

export function buildUsageTelemetryRoutePayload ({
  route,
  usageLedger = null,
  body = null,
  pokerProvider = null,
  bandwidthReceiptPayload = null
} = {}) {
  if (!route) return unknownUsageTelemetryRoute()

  switch (route.kind) {
    case 'poker-usage':
      return {
        status: 200,
        payload: pokerUsageTelemetryPayload(pokerProvider)
      }
    case 'receipt-submit':
      return recordUsageReceiptPayload(usageLedger, body)
    case 'usage-digest':
      if (bandwidthReceiptPayload) {
        return {
          status: 200,
          payload: bandwidthReceiptPayload
        }
      }
      return usageLedgerDigestPayload(usageLedger)
    default:
      return unknownUsageTelemetryRoute()
  }
}

export function tableWriterCount (writers) {
  if (Array.isArray(writers)) return writers.length
  if (writers && typeof writers === 'object') return Object.keys(writers).length
  const n = Number(writers)
  return safeCount(n)
}

export function pokerUsageTelemetryPayload (pokerApp) {
  if (!pokerApp || typeof pokerApp.listTables !== 'function') {
    return emptyPokerUsagePayload()
  }

  let tables = []
  try {
    const out = pokerApp.listTables()
    tables = Array.isArray(out) ? out : []
  } catch (_) {
    return emptyPokerUsagePayload()
  }

  let appends = 0
  let seats = 0
  const perTable = []

  for (const table of tables) {
    const tableAppends = safeCount(table && table.length)
    const writers = tableWriterCount(table && table.writers)
    appends += tableAppends
    seats += writers

    if (perTable.length >= MAX_POKER_USAGE_TABLE_ROWS) continue
    const tableKey = safeTableKey(table && table.tableKey)
    if (!tableKey) continue
    perTable.push({
      tableKey,
      appends: tableAppends,
      writers,
      lastTs: safeTimestamp(table && table.lastTs)
    })
  }

  return {
    enabled: true,
    service: 'poker',
    tables: tables.length,
    appends,
    seats,
    perTable,
    note: pokerUsageNote()
  }
}

function emptyPokerUsagePayload () {
  return {
    enabled: false,
    service: 'poker',
    tables: 0,
    appends: 0,
    seats: 0,
    perTable: [],
    note: pokerUsageNote()
  }
}

function pokerUsageNote () {
  return 'appends = player-signed log entries (the relay cannot forge them). Counts only — no card/hole/payload data.'
}

function unknownUsageTelemetryRoute () {
  return {
    status: 404,
    payload: { error: 'unknown usage telemetry route' }
  }
}

function safeCount (value) {
  const n = Number(value)
  return Number.isFinite(n) && n > 0 ? Math.min(Math.floor(n), Number.MAX_SAFE_INTEGER) : 0
}

function safeTimestamp (value) {
  const n = Number(value)
  return Number.isFinite(n) && n > 0 ? Math.min(Math.floor(n), Number.MAX_SAFE_INTEGER) : null
}

function safeTableKey (value) {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  if (!trimmed || trimmed.length > MAX_POKER_USAGE_TABLE_KEY_LENGTH) return null
  for (let i = 0; i < trimmed.length; i++) {
    const code = trimmed.charCodeAt(i)
    if (code <= 0x1f || code === 0x7f) return null
  }
  return trimmed
}
