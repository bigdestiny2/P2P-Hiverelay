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

export function tableWriterCount (writers) {
  if (Array.isArray(writers)) return writers.length
  if (writers && typeof writers === 'object') return Object.keys(writers).length
  const n = Number(writers)
  return Number.isFinite(n) && n > 0 ? n : 0
}

export function pokerUsageTelemetryPayload (pokerApp) {
  if (!pokerApp || typeof pokerApp.listTables !== 'function') {
    return { enabled: false, tables: 0, appends: 0, seats: 0 }
  }

  let tables = []
  try {
    const out = pokerApp.listTables()
    tables = Array.isArray(out) ? out : []
  } catch (_) {
    return { enabled: false, tables: 0, appends: 0, seats: 0 }
  }

  let appends = 0
  let seats = 0
  for (const table of tables) {
    const length = Number(table && table.length)
    if (Number.isFinite(length) && length > 0) appends += length
    seats += tableWriterCount(table && table.writers)
  }

  return {
    enabled: true,
    tables: tables.length,
    appends,
    seats
  }
}
