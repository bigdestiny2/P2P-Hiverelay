import test from 'brittle'
import {
  exportBandwidthReceipts,
  latestReceiptTimestamp,
  measuredServedBytes,
  pokerUsageTelemetryPayload,
  sumReceiptBytes,
  tableWriterCount,
  usageTelemetryPayload
} from 'p2p-hiverelay/core/relay-node/api-usage-telemetry.js'

test('api usage telemetry: exports bounded receipt lists and tolerates tracker failures', (t) => {
  const receipts = [{ bytesTransferred: 100, timestamp: 10 }]

  t.alike(exportBandwidthReceipts({ exportReceipts: () => receipts }), receipts)
  t.alike(exportBandwidthReceipts({ exportReceipts: () => ({ not: 'array' }) }), [])
  t.alike(exportBandwidthReceipts({ exportReceipts: () => { throw new Error('store unavailable') } }), [])
  t.alike(exportBandwidthReceipts(null), [])
})

test('api usage telemetry: sums positive finite receipt bytes and latest timestamps', (t) => {
  const receipts = [
    { bytesTransferred: 100, timestamp: 1000 },
    { bytesTransferred: '25', timestamp: '3000' },
    { bytesTransferred: -10, timestamp: -1 },
    { bytesTransferred: Infinity, timestamp: 'not-a-time' },
    { bytesTransferred: 0, timestamp: 2000 }
  ]

  t.is(sumReceiptBytes(receipts), 125)
  t.is(sumReceiptBytes(null), 0)
  t.is(latestReceiptTimestamp(receipts), 3000)
  t.is(latestReceiptTimestamp(null), 0)
})

test('api usage telemetry: builds dashboard payload from verified and measured counters', (t) => {
  const tracker = {
    exportReceipts () {
      return [
        { bytesTransferred: 100, timestamp: 1000 },
        { bytesTransferred: 250, timestamp: 2000 }
      ]
    }
  }

  t.alike(usageTelemetryPayload(tracker, { served: { totalBytesServed: 512 } }), {
    enabled: true,
    verified: {
      count: 2,
      bytes: 350,
      latestAt: 2000,
      totals: {
        bandwidthBytes: 350
      }
    },
    measured: {
      servedBytes: 512
    }
  })

  t.is(usageTelemetryPayload(null, {}).enabled, false)
  t.is(usageTelemetryPayload(null, {}).verified.latestAt, null)
  t.is(measuredServedBytes({ served: { totalBytesServed: 0 } }), 0)
  t.is(measuredServedBytes({ served: { totalBytesServed: NaN } }), null)
})

test('api usage telemetry: poker usage counts tables, appends, and seats defensively', (t) => {
  const pokerApp = {
    listTables () {
      return [
        { tableKey: 'alpha', writers: 2, length: 5 },
        { tableKey: 'beta', writers: { a: true, b: true, c: true }, length: 8 },
        { tableKey: 'gamma', writers: ['a', 'b'], length: -4 },
        { tableKey: 'delta', writers: 'bad', length: '3' }
      ]
    }
  }

  t.alike(pokerUsageTelemetryPayload(pokerApp), {
    enabled: true,
    tables: 4,
    appends: 16,
    seats: 7
  })

  t.is(tableWriterCount(['a', 'b']), 2)
  t.is(tableWriterCount({ a: true }), 1)
  t.is(tableWriterCount(3), 3)
  t.is(tableWriterCount(-1), 0)
  t.alike(pokerUsageTelemetryPayload(null), { enabled: false, tables: 0, appends: 0, seats: 0 })
  t.alike(pokerUsageTelemetryPayload({ listTables: () => { throw new Error('boom') } }), { enabled: false, tables: 0, appends: 0, seats: 0 })
  t.alike(pokerUsageTelemetryPayload({ listTables: () => 'not-array' }), { enabled: true, tables: 0, appends: 0, seats: 0 })
})
