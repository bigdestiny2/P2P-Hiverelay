import test from 'brittle'
import {
  OUTBOXLOG_RELEASE_BUDGET_PROFILE,
  buildOutboxLogBenchReport
} from '../../scripts/bench-outboxlog.mjs'

test('outboxlog benchmark reports append, range, directory, HTTP SSE, event, and RSS metrics', async (t) => {
  const report = await buildOutboxLogBenchReport({
    outboxes: 8,
    recordsPerOutbox: 3,
    rangeIterations: 5,
    rangeLimit: 20,
    directoryIterations: 3,
    headsIterations: 3,
    eventAppends: 5,
    httpEventAppends: 3,
    // This test verifies report plumbing, not release performance — the
    // strict OUTBOXLOG_RELEASE_BUDGET defaults gate scripts/bench-outboxlog
    // standalone. Under a shared-process suite run, a single GC pause blows
    // the 2ms append p50 and flakes the whole suite, so give latency budgets
    // co-run headroom here while keeping the shape/count assertions exact.
    budget: {
      maxAppendP50Ms: 100,
      maxAppendP99Ms: 500,
      maxAppendEventP99Ms: 500,
      maxHttpPublishToSseP99Ms: 2000,
      maxRangeP99Ms: 2000,
      minRangeRowsPerSecond: 10,
      maxDirectoryP99Ms: 2000,
      // RSS is process-global: co-run suites' heaps land in this number.
      maxRssPer1kOutboxesBytes: 64 * 1024 * 1024 * 1024
    }
  })

  t.is(report.kind, 'hiverelay-outboxlog-benchmark')
  t.is(report.status, 'pass')
  t.is(report.failures.length, 0)
  t.is(report.budget.profile, OUTBOXLOG_RELEASE_BUDGET_PROFILE)
  t.is(report.invariantFailures.length, 0)
  t.is(report.budgetFailures.length, 0)
  t.is(report.results.append.count, 32)
  t.is(report.results.appendEvents.count, 5)
  t.is(report.results.httpPublishToSse.count, 3)
  t.is(report.results.directory.count, 8)
  t.ok(report.results.range.rows >= 15)
  t.ok(finiteMetric(report.results.append.latencyMs.p50))
  t.ok(finiteMetric(report.results.append.latencyMs.p99))
  t.ok(finiteMetric(report.results.range.rangeRowsPerSecond))
  t.ok(finiteMetric(report.results.appendEvents.appendEventLatencyMs.p99))
  t.ok(finiteMetric(report.results.httpPublishToSse.publishToSseLatencyMs.p99))
  t.ok(finiteMetric(report.results.directory.directoryPayloadBytes.p50))
  t.ok(finiteMetric(report.results.rss.rssPer1kOutboxesBytes))
  t.ok(finiteMetric(report.budgetResults.directoryPayloadBytesPerOutbox))
})

test('outboxlog benchmark blocks explicit release budget regressions', async (t) => {
  const report = await buildOutboxLogBenchReport({
    outboxes: 2,
    recordsPerOutbox: 1,
    rangeIterations: 1,
    rangeLimit: 10,
    directoryIterations: 1,
    headsIterations: 1,
    eventAppends: 1,
    httpEventAppends: 1,
    budget: {
      minRangeRowsPerSecond: Number.MAX_SAFE_INTEGER
    }
  })

  t.is(report.kind, 'hiverelay-outboxlog-benchmark')
  t.is(report.status, 'blocked')
  t.is(report.invariantFailures.length, 0)
  t.is(report.budgetFailures.length, 1)
  t.is(report.budgetFailures[0].metric, 'rangeRowsPerSecond')
  t.ok(report.failures[0].includes('budget rangeRowsPerSecond'))
})

function finiteMetric (value) {
  return Number.isFinite(value)
}
