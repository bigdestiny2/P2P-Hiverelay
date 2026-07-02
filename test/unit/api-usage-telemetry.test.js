import test from 'brittle'
import {
  buildUsageTelemetryRoutePayload,
  exportBandwidthReceipts,
  latestReceiptTimestamp,
  measuredServedBytes,
  MAX_POKER_USAGE_TABLE_ROWS,
  pokerUsageTelemetryPayload,
  recordUsageReceiptPayload,
  resolveUsageTelemetryRoute,
  sumReceiptBytes,
  tableWriterCount,
  USAGE_TELEMETRY_AUTH_ERROR,
  usageLedgerDigestPayload,
  usageTelemetryPayload
} from 'p2p-hiverelay/core/relay-node/api-usage-telemetry.js'

test('api usage telemetry: route helper maps exact usage routes', (t) => {
  t.alike(resolveUsageTelemetryRoute('GET', '/api/poker/usage'), {
    kind: 'poker-usage',
    authMessage: USAGE_TELEMETRY_AUTH_ERROR
  })
  t.alike(resolveUsageTelemetryRoute('POST', '/api/usage/receipt'), {
    kind: 'receipt-submit'
  })
  t.alike(resolveUsageTelemetryRoute('GET', '/api/usage'), {
    kind: 'usage-digest',
    authMessage: USAGE_TELEMETRY_AUTH_ERROR
  })

  t.is(resolveUsageTelemetryRoute('POST', '/api/usage'), null)
  t.is(resolveUsageTelemetryRoute('GET', '/api/usage/receipt'), null)
  t.is(resolveUsageTelemetryRoute('GET', '/api/poker/usage/extra'), null)
})

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

test('api usage telemetry: records signed usage receipts through a bounded helper', (t) => {
  const calls = []
  const ledger = {
    record (body) {
      calls.push(body)
      return body && body.ok ? { ok: true, id: 'receipt-1' } : { ok: false, reason: 'bad-signature' }
    }
  }

  t.alike(recordUsageReceiptPayload(null, { ok: true }), {
    status: 503,
    payload: { error: 'metering unavailable' }
  })
  t.alike(recordUsageReceiptPayload(ledger, { ok: true }), {
    status: 200,
    payload: { ok: true, id: 'receipt-1' }
  })
  t.alike(recordUsageReceiptPayload(ledger, { ok: false }), {
    status: 400,
    payload: { ok: false, reason: 'bad-signature' }
  })
  t.alike(calls, [{ ok: true }, { ok: false }])
})

test('api usage telemetry: builds payout-eligible ledger digest payload', (t) => {
  const digest = {
    count: 2,
    totals: { 'poker.append.appends': 8 },
    receiptRoot: 'root'
  }
  const payload = usageLedgerDigestPayload({ digest: () => digest })
  t.is(payload.status, 200)
  t.alike(payload.payload.verified, digest)
  t.ok(payload.payload.note.includes('counterparty-signed receipts'))
  t.ok(payload.payload.note.includes('NOT payout-eligible'))

  t.alike(usageLedgerDigestPayload(null).payload.verified, {
    count: 0,
    totals: {},
    receiptRoot: null
  })
})

test('api usage telemetry: route payload helper dispatches usage reads and receipt writes', (t) => {
  const poker = buildUsageTelemetryRoutePayload({
    route: resolveUsageTelemetryRoute('GET', '/api/poker/usage'),
    pokerProvider: {
      listTables () {
        return [{ tableKey: 'alpha', writers: 2, length: 3 }]
      }
    }
  })
  t.is(poker.status, 200)
  t.is(poker.payload.enabled, true)
  t.is(poker.payload.tables, 1)
  t.is(poker.payload.appends, 3)
  t.is(poker.payload.seats, 2)

  const receiptCalls = []
  const receipt = buildUsageTelemetryRoutePayload({
    route: resolveUsageTelemetryRoute('POST', '/api/usage/receipt'),
    usageLedger: {
      record (body) {
        receiptCalls.push(body)
        return { ok: true, id: 'receipt-1' }
      }
    },
    body: { signed: true }
  })
  t.alike(receipt, {
    status: 200,
    payload: { ok: true, id: 'receipt-1' }
  })
  t.alike(receiptCalls, [{ signed: true }])

  const bandwidth = {
    enabled: true,
    verified: { count: 1, bytes: 42, latestAt: 1000, totals: { bandwidthBytes: 42 } },
    measured: { servedBytes: 5 }
  }
  t.alike(buildUsageTelemetryRoutePayload({
    route: resolveUsageTelemetryRoute('GET', '/api/usage'),
    bandwidthReceiptPayload: bandwidth,
    usageLedger: {
      digest () {
        throw new Error('bandwidth receipt path should not query usage ledger')
      }
    }
  }), {
    status: 200,
    payload: bandwidth
  })

  const digest = buildUsageTelemetryRoutePayload({
    route: resolveUsageTelemetryRoute('GET', '/api/usage'),
    usageLedger: { digest: () => ({ count: 3, totals: { calls: 9 }, receiptRoot: 'root' }) }
  })
  t.is(digest.status, 200)
  t.alike(digest.payload.verified, { count: 3, totals: { calls: 9 }, receiptRoot: 'root' })
  t.ok(digest.payload.note.includes('counterparty-signed receipts'))

  t.alike(buildUsageTelemetryRoutePayload({ route: null }), {
    status: 404,
    payload: { error: 'unknown usage telemetry route' }
  })
})

test('api usage telemetry: poker usage counts tables, appends, and seats defensively', (t) => {
  const pokerApp = {
    listTables () {
      return [
        { tableKey: 'alpha', writers: 2, length: 5 },
        { tableKey: 'beta', writers: { a: true, b: true, c: true }, length: 8 },
        { tableKey: 'gamma', writers: ['a', 'b'], length: -4 },
        { tableKey: 'delta', writers: 'bad', length: '3', lastTs: '42' },
        { tableKey: 'bad\nkey', writers: 1, length: 1, payload: 'should-not-leak' }
      ]
    }
  }

  const payload = pokerUsageTelemetryPayload(pokerApp)
  t.is(payload.enabled, true)
  t.is(payload.service, 'poker')
  t.is(payload.tables, 5)
  t.is(payload.appends, 17)
  t.is(payload.seats, 8)
  t.alike(payload.perTable, [
    { tableKey: 'alpha', appends: 5, writers: 2, lastTs: null },
    { tableKey: 'beta', appends: 8, writers: 3, lastTs: null },
    { tableKey: 'gamma', appends: 0, writers: 2, lastTs: null },
    { tableKey: 'delta', appends: 3, writers: 0, lastTs: 42 }
  ])
  t.absent(JSON.stringify(payload.perTable).includes('payload'), 'per-table rows never expose raw table payload fields')
  t.ok(payload.note.includes('player-signed log entries'))

  t.is(tableWriterCount(['a', 'b']), 2)
  t.is(tableWriterCount({ a: true }), 1)
  t.is(tableWriterCount(3.9), 3)
  t.is(tableWriterCount(-1), 0)
  t.alike(pokerUsageTelemetryPayload(null), {
    enabled: false,
    service: 'poker',
    tables: 0,
    appends: 0,
    seats: 0,
    perTable: [],
    note: payload.note
  })
  t.alike(pokerUsageTelemetryPayload({ listTables: () => { throw new Error('boom') } }), {
    enabled: false,
    service: 'poker',
    tables: 0,
    appends: 0,
    seats: 0,
    perTable: [],
    note: payload.note
  })
  t.alike(pokerUsageTelemetryPayload({ listTables: () => 'not-array' }), {
    enabled: true,
    service: 'poker',
    tables: 0,
    appends: 0,
    seats: 0,
    perTable: [],
    note: payload.note
  })
})

test('api usage telemetry: poker usage caps per-table rows while preserving totals', (t) => {
  const out = pokerUsageTelemetryPayload({
    listTables () {
      return Array.from({ length: MAX_POKER_USAGE_TABLE_ROWS + 5 }, (_, i) => ({
        tableKey: `table-${i}`,
        writers: 1,
        length: 1
      }))
    }
  })

  t.is(out.tables, MAX_POKER_USAGE_TABLE_ROWS + 5)
  t.is(out.appends, MAX_POKER_USAGE_TABLE_ROWS + 5)
  t.is(out.seats, MAX_POKER_USAGE_TABLE_ROWS + 5)
  t.is(out.perTable.length, MAX_POKER_USAGE_TABLE_ROWS)
})
