#!/usr/bin/env node

import { createHash } from 'node:crypto'
import http from 'node:http'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { performance } from 'node:perf_hooks'
import { pathToFileURL } from 'node:url'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  DEFAULT_OUTBOXLOG_NAMESPACE,
  canonicalOutboxRecord,
  createOutboxLog
} from '../packages/services/builtin/outboxlog/index.js'
import {
  createOutboxLogHttpHandler,
  createOutboxLogTokenAuth
} from '../packages/services/builtin/outboxlog/http-adapter.js'

const DEFAULTS = {
  outboxes: 1000,
  recordsPerOutbox: 3,
  rangeIterations: 100,
  rangeLimit: 1000,
  directoryIterations: 25,
  headsIterations: 25,
  eventAppends: 100,
  httpEventAppends: 20
}

export const OUTBOXLOG_RELEASE_BUDGET_PROFILE = 'release-local-v1'
export const OUTBOXLOG_RELEASE_BUDGET = Object.freeze({
  maxAppendP50Ms: 2,
  maxAppendP99Ms: 10,
  maxAppendEventP99Ms: 10,
  maxHttpPublishToSseP99Ms: 100,
  maxRangeP99Ms: 50,
  minRangeRowsPerSecond: 1000,
  maxDirectoryP99Ms: 100,
  maxDirectoryPayloadBytesPerOutbox: 2048,
  maxRssPer1kOutboxesBytes: 512 * 1024 * 1024
})

export async function buildOutboxLogBenchReport (opts = {}) {
  const params = normalizeOptions(opts)
  const budget = normalizeBudget(opts)
  const generatedAt = new Date().toISOString()
  const rssStart = process.memoryUsage().rss
  const log = createOutboxLog()
  const writers = Array.from({ length: params.outboxes }, (_, i) => keyPair(i))
  const appIds = writers.map(writer => writer.publicKeyHex)
  const targetWriter = writers[0]
  const targetAppId = targetWriter.publicKeyHex

  const initialOps = []
  for (let i = 0; i < writers.length; i++) {
    const writer = writers[i]
    log.sync.create(writer.publicKeyHex)

    for (let n = 0; n < params.recordsPerOutbox; n++) {
      initialOps.push({
        appId: writer.publicKeyHex,
        op: {
          type: 'post',
          data: signRecord(writer, 'post', {
            id: `${i}-${n}`,
            seq: n,
            body: {
              text: `outboxlog-bench-${i}-${n}`,
              digest: digestHex(`${writer.publicKeyHex}:${n}`)
            }
          })
        }
      })
    }

    initialOps.push({
      appId: writer.publicKeyHex,
      op: {
        type: 'head',
        data: signRecord(writer, 'head', {
          id: writer.publicKeyHex,
          version: params.recordsPerOutbox,
          count: params.recordsPerOutbox,
          root: digestHex(`head:${writer.publicKeyHex}:${params.recordsPerOutbox}`)
        })
      }
    })
  }

  const appendLatencyMs = []
  const appendStart = performance.now()
  for (const entry of initialOps) {
    const opStart = performance.now()
    log.sync.append(entry.appId, entry.op)
    appendLatencyMs.push(performance.now() - opStart)
  }
  const appendTotalMs = performance.now() - appendStart

  const appendEventLatencyMs = []
  const pendingEvents = new Map()
  const unsubscribe = log.subscribe(targetAppId, (event) => {
    const started = pendingEvents.get(event.key)
    if (started != null) appendEventLatencyMs.push(performance.now() - started)
  })

  for (let i = 0; i < params.eventAppends; i++) {
    const id = `event-${i}`
    const key = `post!${id}`
    const data = signRecord(targetWriter, 'post', {
      id,
      seq: params.recordsPerOutbox + i,
      body: { text: `event-latency-${i}` }
    })
    pendingEvents.set(key, performance.now())
    log.sync.append(targetAppId, { type: 'post', data })
    pendingEvents.delete(key)
  }
  unsubscribe()

  const publishToSseLatencyMs = await measureHttpPublishToSseLatency({
    log,
    writer: targetWriter,
    appId: targetAppId,
    iterations: params.httpEventAppends,
    seqStart: params.recordsPerOutbox + params.eventAppends
  })

  const rangeLatencyMs = []
  let rangeRows = 0
  const rangeStart = performance.now()
  for (let i = 0; i < params.rangeIterations; i++) {
    const opStart = performance.now()
    const rows = log.sync.range(targetAppId, {
      gte: 'post!',
      lt: 'post!\xff',
      limit: params.rangeLimit
    })
    rangeLatencyMs.push(performance.now() - opStart)
    rangeRows += rows.length
  }
  const rangeTotalMs = performance.now() - rangeStart

  const headsLatencyMs = []
  for (let i = 0; i < params.headsIterations; i++) {
    const opStart = performance.now()
    log.sync.heads(appIds)
    headsLatencyMs.push(performance.now() - opStart)
  }

  const directoryLatencyMs = []
  const directoryPayloadBytes = []
  let directoryCount = 0
  for (let i = 0; i < params.directoryIterations; i++) {
    const opStart = performance.now()
    const directory = log.sync.directory({ limit: params.outboxes })
    directoryLatencyMs.push(performance.now() - opStart)
    directoryPayloadBytes.push(Buffer.byteLength(JSON.stringify(directory)))
    directoryCount = directory.count
  }

  const rssEnd = process.memoryUsage().rss
  const rssDelta = rssEnd - rssStart
  const report = {
    kind: 'hiverelay-outboxlog-benchmark',
    version: 1,
    generatedAt,
    status: 'pass',
    params,
    budget,
    results: {
      append: {
        count: initialOps.length,
        totalMs: round(appendTotalMs),
        rowsPerSecond: round(perSecond(initialOps.length, appendTotalMs)),
        latencyMs: summarize(appendLatencyMs)
      },
      appendEvents: {
        count: appendEventLatencyMs.length,
        expected: params.eventAppends,
        appendEventLatencyMs: summarize(appendEventLatencyMs)
      },
      httpPublishToSse: {
        count: publishToSseLatencyMs.length,
        expected: params.httpEventAppends,
        publishToSseLatencyMs: summarize(publishToSseLatencyMs)
      },
      range: {
        iterations: params.rangeIterations,
        rows: rangeRows,
        rangeRowsPerSecond: round(perSecond(rangeRows, rangeTotalMs)),
        latencyMs: summarize(rangeLatencyMs)
      },
      heads: {
        iterations: params.headsIterations,
        appIds: appIds.length,
        latencyMs: summarize(headsLatencyMs)
      },
      directory: {
        iterations: params.directoryIterations,
        count: directoryCount,
        directoryPayloadBytes: summarize(directoryPayloadBytes),
        latencyMs: summarize(directoryLatencyMs)
      },
      rss: {
        startBytes: rssStart,
        endBytes: rssEnd,
        deltaBytes: rssDelta,
        rssPer1kOutboxesBytes: round(rssDelta / (params.outboxes / 1000))
      }
    },
    budgetResults: null,
    invariantFailures: [],
    budgetFailures: [],
    failures: []
  }

  report.budgetResults = calculateBudgetResults(report)
  report.invariantFailures = findInvariantFailures(report)
  report.budgetFailures = findBudgetFailures(report)
  report.failures = [
    ...report.invariantFailures,
    ...report.budgetFailures.map(formatBudgetFailure)
  ]
  if (report.failures.length) report.status = 'blocked'
  return report
}

function normalizeOptions (opts) {
  return {
    outboxes: positiveInteger(opts.outboxes ?? DEFAULTS.outboxes, 'outboxes'),
    recordsPerOutbox: positiveInteger(opts.recordsPerOutbox ?? DEFAULTS.recordsPerOutbox, 'records-per-outbox'),
    rangeIterations: positiveInteger(opts.rangeIterations ?? DEFAULTS.rangeIterations, 'range-iterations'),
    rangeLimit: positiveInteger(opts.rangeLimit ?? DEFAULTS.rangeLimit, 'range-limit'),
    directoryIterations: positiveInteger(opts.directoryIterations ?? DEFAULTS.directoryIterations, 'directory-iterations'),
    headsIterations: positiveInteger(opts.headsIterations ?? DEFAULTS.headsIterations, 'heads-iterations'),
    eventAppends: positiveInteger(opts.eventAppends ?? DEFAULTS.eventAppends, 'event-appends'),
    httpEventAppends: positiveInteger(opts.httpEventAppends ?? DEFAULTS.httpEventAppends, 'http-event-appends')
  }
}

function normalizeBudget (opts) {
  if (opts.budget === false) return null
  const overrides = opts.budget && typeof opts.budget === 'object' ? opts.budget : opts
  return {
    profile: OUTBOXLOG_RELEASE_BUDGET_PROFILE,
    maxAppendP50Ms: nonNegativeNumber(overrides.maxAppendP50Ms ?? OUTBOXLOG_RELEASE_BUDGET.maxAppendP50Ms, 'max-append-p50-ms'),
    maxAppendP99Ms: nonNegativeNumber(overrides.maxAppendP99Ms ?? OUTBOXLOG_RELEASE_BUDGET.maxAppendP99Ms, 'max-append-p99-ms'),
    maxAppendEventP99Ms: nonNegativeNumber(overrides.maxAppendEventP99Ms ?? OUTBOXLOG_RELEASE_BUDGET.maxAppendEventP99Ms, 'max-append-event-p99-ms'),
    maxHttpPublishToSseP99Ms: nonNegativeNumber(overrides.maxHttpPublishToSseP99Ms ?? OUTBOXLOG_RELEASE_BUDGET.maxHttpPublishToSseP99Ms, 'max-http-publish-to-sse-p99-ms'),
    maxRangeP99Ms: nonNegativeNumber(overrides.maxRangeP99Ms ?? OUTBOXLOG_RELEASE_BUDGET.maxRangeP99Ms, 'max-range-p99-ms'),
    minRangeRowsPerSecond: nonNegativeNumber(overrides.minRangeRowsPerSecond ?? OUTBOXLOG_RELEASE_BUDGET.minRangeRowsPerSecond, 'min-range-rows-per-second'),
    maxDirectoryP99Ms: nonNegativeNumber(overrides.maxDirectoryP99Ms ?? OUTBOXLOG_RELEASE_BUDGET.maxDirectoryP99Ms, 'max-directory-p99-ms'),
    maxDirectoryPayloadBytesPerOutbox: nonNegativeNumber(overrides.maxDirectoryPayloadBytesPerOutbox ?? OUTBOXLOG_RELEASE_BUDGET.maxDirectoryPayloadBytesPerOutbox, 'max-directory-payload-bytes-per-outbox'),
    maxRssPer1kOutboxesBytes: nonNegativeNumber(overrides.maxRssPer1kOutboxesBytes ?? OUTBOXLOG_RELEASE_BUDGET.maxRssPer1kOutboxesBytes, 'max-rss-per-1k-outboxes-bytes')
  }
}

function positiveInteger (value, name) {
  const n = Number(value)
  if (!Number.isInteger(n) || n < 1) throw new Error(`${name} must be a positive integer`)
  return n
}

function nonNegativeNumber (value, name) {
  const n = Number(value)
  if (!Number.isFinite(n) || n < 0) throw new Error(`${name} must be a non-negative number`)
  return n
}

function keyPair (index) {
  const seed = createHash('sha256').update(`hiverelay-outboxlog-bench:${index}`).digest()
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)
  return {
    publicKey,
    secretKey,
    publicKeyHex: b4a.toString(publicKey, 'hex')
  }
}

function signRecord (writer, type, fields = {}) {
  const data = {
    id: fields.id || digestHex(writer.publicKeyHex).slice(0, 16),
    author: writer.publicKeyHex,
    ...fields,
    _k: writer.publicKeyHex,
    _dk: fields._dk || digestHex(`drive:${writer.publicKeyHex}`),
    _ns: fields._ns || DEFAULT_OUTBOXLOG_NAMESPACE,
    _alg: 'ed25519'
  }
  const signed = `pear.app.${data._dk}:${data._ns}:${canonicalOutboxRecord(type, data)}`
  const signature = b4a.alloc(64)
  sodium.crypto_sign_detached(signature, b4a.from(signed, 'utf8'), writer.secretKey)
  return { ...data, _sig: b4a.toString(signature, 'hex') }
}

function digestHex (value) {
  return createHash('sha256').update(String(value)).digest('hex')
}

function summarize (values) {
  const sorted = [...values].sort((a, b) => a - b)
  if (sorted.length === 0) {
    return {
      count: 0,
      min: 0,
      p50: 0,
      p95: 0,
      p99: 0,
      max: 0,
      mean: 0
    }
  }

  const total = sorted.reduce((sum, value) => sum + value, 0)
  return {
    count: sorted.length,
    min: round(sorted[0]),
    p50: round(percentile(sorted, 0.50)),
    p95: round(percentile(sorted, 0.95)),
    p99: round(percentile(sorted, 0.99)),
    max: round(sorted[sorted.length - 1]),
    mean: round(total / sorted.length)
  }
}

function percentile (sorted, q) {
  const index = Math.min(sorted.length - 1, Math.ceil(sorted.length * q) - 1)
  return sorted[Math.max(0, index)]
}

function perSecond (count, ms) {
  if (ms <= 0) return count
  return count / (ms / 1000)
}

function round (n) {
  return Number(n.toFixed(6))
}

function findInvariantFailures (report) {
  const failures = []
  const expectedAppends = report.params.outboxes * (report.params.recordsPerOutbox + 1)

  if (report.results.append.count !== expectedAppends) failures.push(`append count ${report.results.append.count} !== ${expectedAppends}`)
  if (report.results.appendEvents.count !== report.params.eventAppends) failures.push(`append event count ${report.results.appendEvents.count} !== ${report.params.eventAppends}`)
  if (report.results.httpPublishToSse.count !== report.params.httpEventAppends) failures.push(`HTTP publish-to-SSE count ${report.results.httpPublishToSse.count} !== ${report.params.httpEventAppends}`)
  if (report.results.directory.count !== report.params.outboxes) failures.push(`directory count ${report.results.directory.count} !== ${report.params.outboxes}`)
  if (report.results.range.rows < report.params.rangeIterations * report.params.recordsPerOutbox) failures.push('range returned fewer rows than the seeded target outbox')

  for (const [name, value] of flattenNumbers(report.results)) {
    if (!Number.isFinite(value)) failures.push(`${name} is not finite`)
  }

  return failures
}

function calculateBudgetResults (report) {
  const outboxes = Math.max(1, report.results.directory.count || report.params.outboxes)
  return {
    appendP50Ms: report.results.append.latencyMs.p50,
    appendP99Ms: report.results.append.latencyMs.p99,
    appendRowsPerSecond: report.results.append.rowsPerSecond,
    appendEventP99Ms: report.results.appendEvents.appendEventLatencyMs.p99,
    httpPublishToSseP99Ms: report.results.httpPublishToSse.publishToSseLatencyMs.p99,
    rangeP99Ms: report.results.range.latencyMs.p99,
    rangeRowsPerSecond: report.results.range.rangeRowsPerSecond,
    directoryP99Ms: report.results.directory.latencyMs.p99,
    directoryPayloadBytesPerOutbox: round(report.results.directory.directoryPayloadBytes.p50 / outboxes),
    rssPer1kOutboxesBytes: report.results.rss.rssPer1kOutboxesBytes
  }
}

function findBudgetFailures (report) {
  if (!report.budget) return []
  const budget = report.budget
  const results = report.budgetResults
  const failures = []

  pushMaxFailure(failures, 'appendP50Ms', results.appendP50Ms, budget.maxAppendP50Ms, 'ms')
  pushMaxFailure(failures, 'appendP99Ms', results.appendP99Ms, budget.maxAppendP99Ms, 'ms')
  pushMaxFailure(failures, 'appendEventP99Ms', results.appendEventP99Ms, budget.maxAppendEventP99Ms, 'ms')
  pushMaxFailure(failures, 'httpPublishToSseP99Ms', results.httpPublishToSseP99Ms, budget.maxHttpPublishToSseP99Ms, 'ms')
  pushMaxFailure(failures, 'rangeP99Ms', results.rangeP99Ms, budget.maxRangeP99Ms, 'ms')
  pushMinFailure(failures, 'rangeRowsPerSecond', results.rangeRowsPerSecond, budget.minRangeRowsPerSecond, 'rows/s')
  pushMaxFailure(failures, 'directoryP99Ms', results.directoryP99Ms, budget.maxDirectoryP99Ms, 'ms')
  pushMaxFailure(failures, 'directoryPayloadBytesPerOutbox', results.directoryPayloadBytesPerOutbox, budget.maxDirectoryPayloadBytesPerOutbox, 'bytes/outbox')
  pushMaxFailure(failures, 'rssPer1kOutboxesBytes', results.rssPer1kOutboxesBytes, budget.maxRssPer1kOutboxesBytes, 'bytes/1k-outboxes')

  return failures
}

function pushMaxFailure (failures, metric, actual, budget, unit) {
  if (actual > budget) failures.push({ metric, actual, budget, operator: '<=', unit })
}

function pushMinFailure (failures, metric, actual, budget, unit) {
  if (actual < budget) failures.push({ metric, actual, budget, operator: '>=', unit })
}

function formatBudgetFailure (failure) {
  return `budget ${failure.metric} ${failure.actual}${failure.unit ? ' ' + failure.unit : ''} must be ${failure.operator} ${failure.budget}`
}

function flattenNumbers (value, prefix = 'results') {
  const found = []
  if (typeof value === 'number') return [[prefix, value]]
  if (!value || typeof value !== 'object') return found
  for (const [key, child] of Object.entries(value)) {
    found.push(...flattenNumbers(child, `${prefix}.${key}`))
  }
  return found
}

function parseArgs (argv) {
  const opts = {}
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--json') opts.json = true
    else if (arg === '--assert') opts.assert = true
    else if (arg === '--no-budget') opts.budget = false
    else if (arg === '--out') opts.out = needValue(argv, ++i, arg)
    else if (arg.startsWith('--out=')) opts.out = arg.slice('--out='.length)
    else if (arg === '--outboxes') opts.outboxes = needValue(argv, ++i, arg)
    else if (arg.startsWith('--outboxes=')) opts.outboxes = arg.slice('--outboxes='.length)
    else if (arg === '--records-per-outbox') opts.recordsPerOutbox = needValue(argv, ++i, arg)
    else if (arg.startsWith('--records-per-outbox=')) opts.recordsPerOutbox = arg.slice('--records-per-outbox='.length)
    else if (arg === '--range-iterations') opts.rangeIterations = needValue(argv, ++i, arg)
    else if (arg.startsWith('--range-iterations=')) opts.rangeIterations = arg.slice('--range-iterations='.length)
    else if (arg === '--range-limit') opts.rangeLimit = needValue(argv, ++i, arg)
    else if (arg.startsWith('--range-limit=')) opts.rangeLimit = arg.slice('--range-limit='.length)
    else if (arg === '--directory-iterations') opts.directoryIterations = needValue(argv, ++i, arg)
    else if (arg.startsWith('--directory-iterations=')) opts.directoryIterations = arg.slice('--directory-iterations='.length)
    else if (arg === '--heads-iterations') opts.headsIterations = needValue(argv, ++i, arg)
    else if (arg.startsWith('--heads-iterations=')) opts.headsIterations = arg.slice('--heads-iterations='.length)
    else if (arg === '--event-appends') opts.eventAppends = needValue(argv, ++i, arg)
    else if (arg.startsWith('--event-appends=')) opts.eventAppends = arg.slice('--event-appends='.length)
    else if (arg === '--http-event-appends') opts.httpEventAppends = needValue(argv, ++i, arg)
    else if (arg.startsWith('--http-event-appends=')) opts.httpEventAppends = arg.slice('--http-event-appends='.length)
    else if (arg === '--max-append-p50-ms') setBudget(opts, 'maxAppendP50Ms', needValue(argv, ++i, arg))
    else if (arg.startsWith('--max-append-p50-ms=')) setBudget(opts, 'maxAppendP50Ms', arg.slice('--max-append-p50-ms='.length))
    else if (arg === '--max-append-p99-ms') setBudget(opts, 'maxAppendP99Ms', needValue(argv, ++i, arg))
    else if (arg.startsWith('--max-append-p99-ms=')) setBudget(opts, 'maxAppendP99Ms', arg.slice('--max-append-p99-ms='.length))
    else if (arg === '--max-append-event-p99-ms') setBudget(opts, 'maxAppendEventP99Ms', needValue(argv, ++i, arg))
    else if (arg.startsWith('--max-append-event-p99-ms=')) setBudget(opts, 'maxAppendEventP99Ms', arg.slice('--max-append-event-p99-ms='.length))
    else if (arg === '--max-http-publish-to-sse-p99-ms') setBudget(opts, 'maxHttpPublishToSseP99Ms', needValue(argv, ++i, arg))
    else if (arg.startsWith('--max-http-publish-to-sse-p99-ms=')) setBudget(opts, 'maxHttpPublishToSseP99Ms', arg.slice('--max-http-publish-to-sse-p99-ms='.length))
    else if (arg === '--max-range-p99-ms') setBudget(opts, 'maxRangeP99Ms', needValue(argv, ++i, arg))
    else if (arg.startsWith('--max-range-p99-ms=')) setBudget(opts, 'maxRangeP99Ms', arg.slice('--max-range-p99-ms='.length))
    else if (arg === '--min-range-rows-per-second') setBudget(opts, 'minRangeRowsPerSecond', needValue(argv, ++i, arg))
    else if (arg.startsWith('--min-range-rows-per-second=')) setBudget(opts, 'minRangeRowsPerSecond', arg.slice('--min-range-rows-per-second='.length))
    else if (arg === '--max-directory-p99-ms') setBudget(opts, 'maxDirectoryP99Ms', needValue(argv, ++i, arg))
    else if (arg.startsWith('--max-directory-p99-ms=')) setBudget(opts, 'maxDirectoryP99Ms', arg.slice('--max-directory-p99-ms='.length))
    else if (arg === '--max-directory-payload-bytes-per-outbox') setBudget(opts, 'maxDirectoryPayloadBytesPerOutbox', needValue(argv, ++i, arg))
    else if (arg.startsWith('--max-directory-payload-bytes-per-outbox=')) setBudget(opts, 'maxDirectoryPayloadBytesPerOutbox', arg.slice('--max-directory-payload-bytes-per-outbox='.length))
    else if (arg === '--max-rss-per-1k-outboxes-bytes') setBudget(opts, 'maxRssPer1kOutboxesBytes', needValue(argv, ++i, arg))
    else if (arg.startsWith('--max-rss-per-1k-outboxes-bytes=')) setBudget(opts, 'maxRssPer1kOutboxesBytes', arg.slice('--max-rss-per-1k-outboxes-bytes='.length))
    else throw new Error(`unknown argument ${arg}`)
  }
  return opts
}

function setBudget (opts, key, value) {
  if (!opts.budget || opts.budget === false) opts.budget = {}
  opts.budget[key] = value
}

function needValue (argv, index, flag) {
  if (index >= argv.length || argv[index].startsWith('--')) throw new Error(`${flag} requires a value`)
  return argv[index]
}

async function main (argv = process.argv.slice(2)) {
  const opts = parseArgs(argv)
  const report = await buildOutboxLogBenchReport(opts)

  if (opts.out) {
    await mkdir(path.dirname(opts.out), { recursive: true })
    await writeFile(opts.out, JSON.stringify(report, null, 2) + '\n')
  }

  if (opts.json) console.log(JSON.stringify(report))
  else printSummary(report, opts.out)

  if (opts.assert && report.status !== 'pass') process.exitCode = 1
}

function printSummary (report, outFile) {
  console.log(`hiverelay-outboxlog-benchmark ${report.status}`)
  console.log(`outboxes=${report.params.outboxes} recordsPerOutbox=${report.params.recordsPerOutbox} appends=${report.results.append.count}`)
  console.log(`append p50=${report.results.append.latencyMs.p50}ms p99=${report.results.append.latencyMs.p99}ms rows/s=${report.results.append.rowsPerSecond}`)
  console.log(`range p50=${report.results.range.latencyMs.p50}ms p99=${report.results.range.latencyMs.p99}ms rows/s=${report.results.range.rangeRowsPerSecond}`)
  console.log(`events p50=${report.results.appendEvents.appendEventLatencyMs.p50}ms p99=${report.results.appendEvents.appendEventLatencyMs.p99}ms count=${report.results.appendEvents.count}`)
  console.log(`http publish->sse p50=${report.results.httpPublishToSse.publishToSseLatencyMs.p50}ms p99=${report.results.httpPublishToSse.publishToSseLatencyMs.p99}ms count=${report.results.httpPublishToSse.count}`)
  console.log(`directory count=${report.results.directory.count} payloadP50=${report.results.directory.directoryPayloadBytes.p50}B`)
  console.log(`rss delta=${report.results.rss.deltaBytes}B per1k=${report.results.rss.rssPer1kOutboxesBytes}B`)
  if (report.budget) console.log(`budget profile=${report.budget.profile} failures=${report.budgetFailures.length}`)
  if (outFile) console.log(`wrote ${outFile}`)
  if (report.failures.length) {
    for (const failure of report.failures) console.log(`failure: ${failure}`)
  }
}

async function measureHttpPublishToSseLatency ({ log, writer, appId, iterations, seqStart }) {
  const auth = createOutboxLogTokenAuth()
  const token = auth.issue()
  const handler = createOutboxLogHttpHandler({
    outboxLogApp: log,
    auth,
    rateLimit: { max: false },
    ssePingMs: 60 * 1000
  })
  const server = http.createServer((req, res) => {
    Promise.resolve(handler(req, res)).then((handled) => {
      if (!handled && !res.headersSent) {
        res.writeHead(404)
        res.end()
      }
    }, () => {
      if (!res.headersSent) res.writeHead(500)
      res.end()
    })
  })
  await listen(server)

  const port = server.address().port
  const pending = new Map()
  const since = log.sync.events(appId).watermark
  const stream = await openSseStream({ port, token, appId, since, pending })
  const latencies = []

  try {
    for (let i = 0; i < iterations; i++) {
      const id = `http-event-${i}`
      const key = `post!${id}`
      const wait = waitForSseKey(pending, key)
      const response = await postJson({
        port,
        token,
        path: '/api/sync/append',
        body: {
          appId,
          op: {
            type: 'post',
            data: signRecord(writer, 'post', {
              id,
              seq: seqStart + i,
              body: { text: `http-publish-to-sse-${i}` }
            })
          }
        }
      })
      if (response.statusCode !== 200 || !response.body || response.body.key !== key) {
        throw new Error(`HTTP append failed for ${key}: ${response.statusCode}`)
      }
      latencies.push(await wait)
    }
  } finally {
    stream.close()
    rejectPending(pending, new Error('HTTP publish-to-SSE benchmark closed'))
    await closeServer(server)
  }

  return latencies
}

function waitForSseKey (pending, key) {
  return new Promise((resolve, reject) => {
    const started = performance.now()
    const timer = setTimeout(() => {
      pending.delete(key)
      reject(new Error(`timed out waiting for SSE marker ${key}`))
    }, 5000)
    if (timer.unref) timer.unref()
    pending.set(key, {
      started,
      resolve: (latency) => {
        clearTimeout(timer)
        resolve(latency)
      },
      reject: (err) => {
        clearTimeout(timer)
        reject(err)
      }
    })
  })
}

function openSseStream ({ port, token, appId, since, pending }) {
  return new Promise((resolve, reject) => {
    let response = null
    let buffer = ''
    let ready = false
    const readyTimer = setTimeout(() => {
      req.destroy()
      reject(new Error('timed out opening OutboxLog SSE stream'))
    }, 5000)
    if (readyTimer.unref) readyTimer.unref()

    const req = http.request({
      hostname: '127.0.0.1',
      port,
      method: 'GET',
      path: `/api/sync/events?appId=${encodeURIComponent(appId)}&since=${since}&limit=1&stream=1&token=${encodeURIComponent(token)}`,
      headers: { accept: 'text/event-stream' }
    }, (res) => {
      response = res
      if (res.statusCode !== 200) {
        clearTimeout(readyTimer)
        reject(new Error(`OutboxLog SSE stream returned ${res.statusCode}`))
        res.resume()
        return
      }
      res.setEncoding('utf8')
      res.on('data', (chunk) => {
        buffer += chunk
        let index = buffer.indexOf('\n\n')
        while (index !== -1) {
          const block = buffer.slice(0, index)
          buffer = buffer.slice(index + 2)
          if (!ready && block.includes(': ok')) {
            ready = true
            clearTimeout(readyTimer)
            resolve({
              close () {
                req.destroy()
                if (response) response.destroy()
              }
            })
          }
          handleSseBlock(block, pending)
          index = buffer.indexOf('\n\n')
        }
      })
    })

    req.on('error', (err) => {
      clearTimeout(readyTimer)
      if (!ready) reject(err)
    })
    req.end()
  })
}

function handleSseBlock (block, pending) {
  const line = String(block).split('\n').find(line => line.startsWith('data: '))
  if (!line) return
  let event
  try {
    event = JSON.parse(line.slice('data: '.length))
  } catch {
    return
  }
  const key = event && event.key
  const waiter = pending.get(key)
  if (!waiter) return
  pending.delete(key)
  waiter.resolve(performance.now() - waiter.started)
}

function postJson ({ port, token, path, body }) {
  return new Promise((resolve, reject) => {
    const text = JSON.stringify(body)
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      method: 'POST',
      path,
      headers: {
        'content-type': 'application/json',
        'content-length': String(Buffer.byteLength(text)),
        'x-pear-token': token
      }
    }, (res) => {
      let data = ''
      res.setEncoding('utf8')
      res.on('data', (chunk) => { data += chunk })
      res.on('end', () => {
        let parsed = null
        try {
          parsed = data ? JSON.parse(data) : null
        } catch {}
        resolve({ statusCode: res.statusCode, body: parsed })
      })
    })
    req.on('error', reject)
    req.end(text)
  })
}

function rejectPending (pending, err) {
  for (const [key, waiter] of pending) {
    pending.delete(key)
    waiter.reject(err)
  }
}

function listen (server) {
  return new Promise((resolve, reject) => {
    const onError = (err) => reject(err)
    server.once('error', onError)
    server.listen(0, '127.0.0.1', () => {
      server.off('error', onError)
      resolve()
    })
  })
}

function closeServer (server) {
  return new Promise((resolve, reject) => {
    server.close((err) => err ? reject(err) : resolve())
  })
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error(err && err.stack ? err.stack : err)
    process.exitCode = 1
  })
}
