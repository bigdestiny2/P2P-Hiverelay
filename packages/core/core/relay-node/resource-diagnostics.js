import { open, opendir } from 'fs/promises'
import { monitorEventLoopDelay } from 'perf_hooks'
import { getHeapSpaceStatistics } from 'v8'
import { sharedOperationFlights } from '../shared-flight-registry.js'

export const RESOURCE_DIAGNOSTICS_KIND = 'HiveRelayResourceDiagnosticsV1'
export const RESOURCE_DIAGNOSTICS_VERSION = 1
export const DEFAULT_RESOURCE_SAMPLE_INTERVAL_MS = 5_000
export const MAX_RESOURCE_SAMPLE_INTERVAL_MS = 60_000
export const DEFAULT_DIAGNOSTIC_FILE_BYTES = 32 * 1024
export const MAX_DIAGNOSTIC_FILE_BYTES = 64 * 1024
export const DEFAULT_FD_SCAN_LIMIT = 4_096
export const MAX_FD_SCAN_LIMIT = 16_384
export const DEFAULT_HEAP_SPACE_LIMIT = 32
export const MAX_HEAP_SPACE_LIMIT = 64
export const DEFAULT_HEALTH_LATENCY_SAMPLES = 256
export const MAX_HEALTH_LATENCY_SAMPLES = 1_024
export const DEFAULT_SCHEDULER_LIMIT = 16
export const MAX_SCHEDULER_LIMIT = 32

const PROC_CGROUP = '/proc/self/cgroup'
const PROC_IO = '/proc/self/io'
const PROC_STAT = '/proc/self/stat'
const PROC_FD = '/proc/self/fd'
const CGROUP_ROOT = '/sys/fs/cgroup'
const CGROUP_V1_MEMORY_ROOT = '/sys/fs/cgroup/memory'
const MAX_COUNTER = Number.MAX_SAFE_INTEGER
const MAX_HEALTH_LATENCY_MS = 60_000
const CGROUP_EVENT_KEYS = Object.freeze([
  'low', 'high', 'max', 'oom', 'oom_kill', 'oom_group_kill', 'failcnt'
])

function strictBound (value, fallback, min, max, label) {
  const candidate = value === undefined ? fallback : value
  if (!Number.isSafeInteger(candidate) || candidate < min || candidate > max) {
    throw new RangeError(`${label} must be a safe integer in [${min},${max}]`)
  }
  return candidate
}

function safeInteger (value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null
}

function safeCount (value) {
  const count = value && Number.isSafeInteger(value.size) ? value.size : value
  return safeInteger(count)
}

function increment (value) {
  return value >= MAX_COUNTER ? MAX_COUNTER : value + 1
}

function safeName (value, fallback = 'unknown') {
  if (typeof value !== 'string' || value.length < 1 || value.length > 64) return fallback
  return /^[a-zA-Z0-9._:-]+$/.test(value) ? value : fallback
}

function unavailable (source, observedAt, reason) {
  return {
    supported: false,
    source,
    observedAt,
    reason
  }
}

function deepFreeze (value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value
  Object.freeze(value)
  for (const child of Object.values(value)) deepFreeze(child)
  return value
}

function classifyReadError (err) {
  if (err && err.code === 'ENOENT') return 'absent'
  if (err && (err.code === 'EACCES' || err.code === 'EPERM')) return 'denied'
  if (err && err.code === 'EISDIR') return 'not-file'
  return 'read-error'
}

function parseUnsigned (value) {
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(value)) return null
  if (value.length > 16) return null
  return safeInteger(Number(value))
}

function parseMemoryValue (value, source, observedAt) {
  const text = typeof value === 'string' ? value.trim() : ''
  if (text === 'max') {
    return { supported: true, source, observedAt, value: null, unlimited: true }
  }
  if (!/^(?:0|[1-9][0-9]*)$/.test(text)) return unavailable(source, observedAt, 'malformed')
  try {
    const amount = BigInt(text)
    if (amount > BigInt(MAX_COUNTER)) {
      return { supported: true, source, observedAt, value: null, unlimited: true }
    }
    return { supported: true, source, observedAt, value: Number(amount), unlimited: false }
  } catch {
    return unavailable(source, observedAt, 'malformed')
  }
}

function fileUnavailable (result, source, observedAt) {
  return unavailable(source, observedAt, result && result.reason ? result.reason : 'unavailable')
}

function percentile (sorted, fraction) {
  if (sorted.length === 0) return null
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * fraction) - 1))
  return sorted[index]
}

export class BoundedProcfsReader {
  async readText (path, maxBytes) {
    let handle = null
    try {
      handle = await open(path, 'r')
      const buffer = Buffer.alloc(maxBytes + 1)
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0)
      if (bytesRead > maxBytes) return { available: false, reason: 'too-large' }
      return {
        available: true,
        bytes: bytesRead,
        text: buffer.subarray(0, bytesRead).toString('utf8')
      }
    } catch (err) {
      return { available: false, reason: classifyReadError(err) }
    } finally {
      if (handle) await handle.close().catch(() => {})
    }
  }

  async countFileDescriptors (limit) {
    let directory = null
    try {
      directory = await opendir(PROC_FD)
      let count = 0
      while (count < limit) {
        const entry = await directory.read()
        if (entry === null) return { available: true, value: count, truncated: false }
        count++
      }
      // Do not read entry limit+1 merely to distinguish "exactly at the
      // ceiling" from "larger than the ceiling". At the ceiling the count is
      // deliberately conservative and marked truncated; procfs work never
      // exceeds the configured inspection cap.
      return { available: true, value: limit, truncated: true }
    } catch (err) {
      return { available: false, reason: classifyReadError(err) }
    } finally {
      if (directory) await directory.close().catch(() => {})
    }
  }
}

export function parseProcIo (text) {
  if (typeof text !== 'string') return null
  const values = Object.create(null)
  let lines = 0
  for (const line of text.split('\n')) {
    if (!line) continue
    lines++
    if (lines > 32) return null
    const match = /^([a-z_]+):[ \t]+([0-9]+)$/.exec(line)
    if (!match) return null
    if (match[1] === 'read_bytes' || match[1] === 'rchar' || match[1] === 'syscr') {
      const value = parseUnsigned(match[2])
      if (value === null) return null
      values[match[1]] = value
    }
  }
  if (values.read_bytes === undefined || values.syscr === undefined) return null
  return {
    readBytes: values.read_bytes,
    readCharacters: values.rchar ?? null,
    readOperations: values.syscr
  }
}

export function parseProcMajorFaults (text) {
  if (typeof text !== 'string' || text.length < 4) return null
  const close = text.lastIndexOf(')')
  if (close < 2 || close + 2 >= text.length) return null
  const fields = text.slice(close + 2).trim().split(/[ \t]+/)
  // The suffix begins at proc(5) field 3 (state); majflt is field 12.
  if (fields.length < 10) return null
  return parseUnsigned(fields[9])
}

export function parseCgroupMembership (text) {
  if (typeof text !== 'string' || text.length < 1) return null
  let v1Memory = null
  let lines = 0
  for (const line of text.trim().split('\n')) {
    lines++
    if (lines > 64) return null
    const match = /^([0-9]+):([^:]*):(\/[\x20-\x7e]*)$/.exec(line)
    if (!match) return null
    if (match[1] === '0' && match[2] === '') {
      return safeCgroupMembership('v2', match[3])
    }
    if (match[2].split(',').includes('memory')) v1Memory = safeCgroupMembership('v1', match[3])
  }
  return v1Memory
}

function safeCgroupMembership (version, path) {
  if (path.length > 4_096 || path.includes('\0')) return null
  const segments = path.split('/').filter(Boolean)
  if (segments.some(segment => segment === '.' || segment === '..' || segment.length > 255)) return null
  return { version, segments }
}

export function parseEventCounters (text) {
  if (typeof text !== 'string') return null
  const values = {}
  let lines = 0
  for (const line of text.trim().split('\n')) {
    if (!line) continue
    lines++
    if (lines > 32) return null
    const match = /^([a-z_]+)[ \t]+([0-9]+)$/.exec(line)
    if (!match) return null
    if (!CGROUP_EVENT_KEYS.includes(match[1])) continue
    const value = parseUnsigned(match[2])
    if (value === null) return null
    values[match[1]] = value
  }
  return values
}

export function parsePressure (text) {
  if (typeof text !== 'string') return null
  const result = {}
  let lines = 0
  for (const line of text.trim().split('\n')) {
    if (!line) continue
    lines++
    if (lines > 2) return null
    const match = /^(some|full) avg10=([0-9]+(?:\.[0-9]+)?) avg60=([0-9]+(?:\.[0-9]+)?) avg300=([0-9]+(?:\.[0-9]+)?) total=([0-9]+)$/.exec(line)
    if (!match) return null
    const averages = match.slice(2, 5).map(Number)
    const total = parseUnsigned(match[5])
    if (total === null || averages.some(value => !Number.isFinite(value) || value < 0 || value > 100)) return null
    result[match[1]] = {
      avg10Pct: averages[0],
      avg60Pct: averages[1],
      avg300Pct: averages[2],
      totalMicros: total
    }
  }
  return result.some || result.full ? result : null
}

export class MonotonicCounterTracker {
  constructor () {
    this._previous = new Map()
  }

  observe (name, value, { source, observedAt }) {
    if (safeInteger(value) === null) return this.unsupported(source, observedAt, 'malformed')
    const previous = this._previous.get(name)
    this._previous.set(name, { value, observedAt })
    if (!previous) {
      return {
        supported: true,
        source,
        observedAt,
        value,
        delta: null,
        ratePerSecond: null,
        reset: false,
        baseline: true
      }
    }
    if (value < previous.value) {
      return {
        supported: true,
        source,
        observedAt,
        value,
        delta: null,
        ratePerSecond: null,
        reset: true,
        baseline: false
      }
    }
    const elapsedMs = observedAt - previous.observedAt
    const delta = value - previous.value
    return {
      supported: true,
      source,
      observedAt,
      value,
      delta,
      ratePerSecond: elapsedMs > 0 ? delta * 1000 / elapsedMs : null,
      reset: false,
      baseline: false
    }
  }

  unsupported (source, observedAt, reason) {
    return {
      ...unavailable(source, observedAt, reason),
      value: null,
      delta: null,
      ratePerSecond: null,
      reset: false,
      baseline: false
    }
  }
}

function pressureUnavailable (source, observedAt, reason) {
  return unavailable(source, observedAt, reason)
}

function pressureSnapshot (parsed, name, source, observedAt, counters) {
  if (!parsed) return pressureUnavailable(source, observedAt, 'malformed')
  const snapshot = {
    supported: true,
    source,
    observedAt,
    some: null,
    full: null
  }
  for (const kind of ['some', 'full']) {
    const row = parsed[kind]
    if (!row) continue
    snapshot[kind] = {
      avg10Pct: row.avg10Pct,
      avg60Pct: row.avg60Pct,
      avg300Pct: row.avg300Pct,
      totalMicros: counters.observe(`psi:${source}:${name}:${kind}`, row.totalMicros, {
        source,
        observedAt
      })
    }
  }
  return snapshot
}

function schedulerSnapshot (node, limit) {
  const schedulers = node && node._completionSchedulers
  if (!schedulers || typeof schedulers[Symbol.iterator] !== 'function') {
    return { count: 0, limit, truncated: false, entries: [] }
  }
  const count = safeCount(schedulers) ?? 0
  const entries = []
  for (const [name, scheduler] of schedulers) {
    if (entries.length >= limit) break
    let state = null
    try { state = scheduler && typeof scheduler.snapshot === 'function' ? scheduler.snapshot() : null } catch {}
    entries.push({
      name: safeName(name),
      running: state?.running === true,
      scheduled: state?.scheduled === true,
      dirty: state?.dirty === true,
      passes: safeInteger(state?.passes) ?? 0,
      failures: safeInteger(state?.failures) ?? 0,
      skippedTriggers: safeInteger(state?.skippedTriggers) ?? 0,
      coalescedTriggers: safeInteger(state?.coalescedTriggers) ?? 0,
      lastDurationMs: safeInteger(state?.lastDurationMs)
    })
  }
  return { count, limit, truncated: count > entries.length, entries }
}

function lifecycleSnapshot (node) {
  const lifecycle = node && node.appLifecycle
  if (lifecycle && typeof lifecycle.getResourceCounters === 'function') {
    try {
      const value = lifecycle.getResourceCounters()
      return {
        driveReadOwners: safeInteger(value?.driveReadOwners),
        activeDriveReadLeases: safeInteger(value?.activeDriveReadLeases),
        retiringDrives: safeInteger(value?.retiringDrives),
        repairFlights: safeInteger(value?.repairFlights),
        transientDownloadRanges: safeInteger(value?.transientDownloadRanges),
        persistentDownloadRanges: safeInteger(value?.persistentDownloadRanges),
        auxiliaryShareBundles: safeInteger(value?.auxiliaryShareBundles),
        auxiliaryRangeTrackers: safeInteger(value?.auxiliaryRangeTrackers)
      }
    } catch {}
  }
  return {
    driveReadOwners: safeCount(lifecycle?._driveReadLeaseStates),
    activeDriveReadLeases: null,
    retiringDrives: safeCount(lifecycle?._retiringDrives),
    repairFlights: safeCount(lifecycle?._repairFlights),
    transientDownloadRanges: null,
    persistentDownloadRanges: null,
    auxiliaryShareBundles: safeCount(lifecycle?._auxShareBundleResources),
    auxiliaryRangeTrackers: null
  }
}

function accountingSnapshot (node) {
  const accounting = node && node.storageAccounting
  if (!accounting || typeof accounting.getResourceDiagnostics !== 'function') {
    return {
      available: false,
      epochActive: false,
      state: 'unavailable',
      waiters: 0,
      measuredEntries: 0,
      operationsInFlight: 0,
      queuedPaths: 0,
      queuedPathBytes: 0,
      bookkeepingBytes: 0,
      observedAt: null,
      completedAt: null,
      ageMs: null,
      lastDurationMs: null,
      incompleteReason: null,
      nextDueAt: null,
      epochsStarted: 0,
      epochsCompleted: 0,
      epochsFailed: 0,
      coalesced: 0,
      waiterTimeouts: 0,
      waiterOverflow: 0
    }
  }
  let value = null
  try { value = accounting.getResourceDiagnostics() } catch {}
  return {
    available: value?.available === true,
    epochActive: value?.epochActive === true,
    state: safeName(value?.state, 'unknown'),
    waiters: safeInteger(value?.waiters) ?? 0,
    measuredEntries: safeInteger(value?.measuredEntries) ?? 0,
    operationsInFlight: safeInteger(value?.operationsInFlight) ?? 0,
    queuedPaths: safeInteger(value?.queuedPaths) ?? 0,
    queuedPathBytes: safeInteger(value?.queuedPathBytes) ?? 0,
    bookkeepingBytes: safeInteger(value?.bookkeepingBytes) ?? 0,
    observedAt: safeInteger(value?.observedAt),
    completedAt: safeInteger(value?.completedAt),
    ageMs: safeInteger(value?.ageMs),
    lastDurationMs: safeInteger(value?.lastDurationMs),
    incompleteReason: safeName(value?.incompleteReason, null),
    nextDueAt: safeInteger(value?.nextDueAt),
    epochsStarted: safeInteger(value?.epochsStarted) ?? 0,
    epochsCompleted: safeInteger(value?.epochsCompleted) ?? 0,
    epochsFailed: safeInteger(value?.epochsFailed) ?? 0,
    coalesced: safeInteger(value?.coalesced) ?? 0,
    waiterTimeouts: safeInteger(value?.waiterTimeouts) ?? 0,
    waiterOverflow: safeInteger(value?.waiterOverflow) ?? 0
  }
}

export function boundedRelayResourceCounters (node, opts = {}) {
  const schedulerLimit = strictBound(
    opts.schedulerLimit,
    DEFAULT_SCHEDULER_LIMIT,
    1,
    MAX_SCHEDULER_LIMIT,
    'schedulerLimit'
  )
  let flights = null
  try { flights = sharedOperationFlights.getStats() } catch {}
  const storeCores = node?.servedAccounting && safeInteger(node.servedAccounting._coreCount)
  return {
    open: {
      storeCores,
      seederCores: safeCount(node?.seeder?.cores),
      hyperdrives: safeInteger(node?.appRegistry?.size) ?? safeCount(node?.seededApps),
      swarmConnections: safeCount(node?.swarm?.connections),
      relaySessions: safeCount(node?.connections),
      relayCircuits: safeCount(node?.relay?.circuits)
    },
    lifecycle: lifecycleSnapshot(node),
    schedulers: schedulerSnapshot(node, schedulerLimit),
    cursors: {
      appRegistry: safeInteger(node?.appRegistry?._appPopulation?.consumerCount),
      seedingRequests: safeInteger(node?.seedingRegistry?._requestPopulation?.consumerCount),
      custodyIntents: safeInteger(node?.seedingRegistry?._custodyIntentPopulation?.consumerCount),
      custodyWitnessProofs: safeCount(node?._custodyWitnessProofCursor)
    },
    accounting: accountingSnapshot(node),
    storageAuthority: {
      commitments: safeCount(node?.storageAdmission?._records),
      recoveryPending: safeCount(node?.storageAdmission?._recoveryPending),
      activeMutations: safeCount(node?.storageAdmission?._mutations),
      activePhysicalMutations: safeCount(node?.storageAdmission?._physicalMutations)
    },
    flights: {
      pending: safeInteger(flights?.pending),
      waiters: safeInteger(flights?.waiters),
      orphanedPending: safeInteger(flights?.orphanedPending),
      started: safeInteger(flights?.started),
      settled: safeInteger(flights?.settled),
      timeouts: safeInteger(flights?.timeouts),
      overflow: safeInteger(flights?.overflow),
      lateSuppressed: safeInteger(flights?.lateSuppressed)
    }
  }
}

function initialSnapshot () {
  return deepFreeze({
    kind: RESOURCE_DIAGNOSTICS_KIND,
    version: RESOURCE_DIAGNOSTICS_VERSION,
    observedAt: null,
    sample: {
      available: false,
      reason: 'not-sampled',
      durationMs: null,
      failures: 0,
      coalesced: 0
    },
    process: {
      memory: unavailable('process.memoryUsage', null, 'not-sampled'),
      heapSpaces: unavailable('v8.getHeapSpaceStatistics', null, 'not-sampled'),
      uptimeMs: null,
      io: unavailable('procfs', null, 'not-sampled'),
      majorFaults: unavailable('procfs', null, 'not-sampled'),
      fileDescriptors: unavailable('procfs', null, 'not-sampled')
    },
    cgroup: unavailable('cgroup', null, 'not-sampled'),
    pressure: {
      memory: unavailable('psi', null, 'not-sampled'),
      io: unavailable('psi', null, 'not-sampled'),
      cpu: unavailable('psi', null, 'not-sampled')
    },
    latency: {
      eventLoop: unavailable('perf_hooks.monitorEventLoopDelay', null, 'not-sampled'),
      health: {
        source: 'relay-api',
        observedAt: null,
        retainedSamples: 0,
        sampleLimit: 0,
        p50Ms: null,
        p99Ms: null,
        maxMs: null,
        requests: 0,
        status2xx: 0,
        status4xx: 0,
        status5xx: 0,
        emptyResponses: 0,
        timeouts: 0,
        errors: 0,
        cappedSamples: 0
      }
    },
    resources: boundedRelayResourceCounters(null)
  })
}

function cgroupPath (membership, leaf) {
  const root = membership.version === 'v2' ? CGROUP_ROOT : CGROUP_V1_MEMORY_ROOT
  return [root, ...membership.segments, leaf].join('/').replace(/\/{2,}/g, '/')
}

export class ResourceDiagnostics {
  constructor (node, opts = {}) {
    this.node = node || null
    this.sampleIntervalMs = strictBound(
      opts.sampleIntervalMs,
      DEFAULT_RESOURCE_SAMPLE_INTERVAL_MS,
      1_000,
      MAX_RESOURCE_SAMPLE_INTERVAL_MS,
      'resourceDiagnostics.sampleIntervalMs'
    )
    this.fileReadBytes = strictBound(
      opts.fileReadBytes,
      DEFAULT_DIAGNOSTIC_FILE_BYTES,
      1_024,
      MAX_DIAGNOSTIC_FILE_BYTES,
      'resourceDiagnostics.fileReadBytes'
    )
    this.fdScanLimit = strictBound(
      opts.fdScanLimit,
      DEFAULT_FD_SCAN_LIMIT,
      32,
      MAX_FD_SCAN_LIMIT,
      'resourceDiagnostics.fdScanLimit'
    )
    this.heapSpaceLimit = strictBound(
      opts.heapSpaceLimit,
      DEFAULT_HEAP_SPACE_LIMIT,
      1,
      MAX_HEAP_SPACE_LIMIT,
      'resourceDiagnostics.heapSpaceLimit'
    )
    this.healthSampleLimit = strictBound(
      opts.healthSampleLimit,
      DEFAULT_HEALTH_LATENCY_SAMPLES,
      16,
      MAX_HEALTH_LATENCY_SAMPLES,
      'resourceDiagnostics.healthSampleLimit'
    )
    this.schedulerLimit = strictBound(
      opts.schedulerLimit,
      DEFAULT_SCHEDULER_LIMIT,
      1,
      MAX_SCHEDULER_LIMIT,
      'resourceDiagnostics.schedulerLimit'
    )

    const runtime = opts.runtime || {}
    this._platform = runtime.platform ?? process.platform
    this._now = typeof runtime.now === 'function' ? runtime.now : () => Date.now()
    this._memoryUsage = typeof runtime.memoryUsage === 'function'
      ? runtime.memoryUsage
      : () => process.memoryUsage()
    this._uptimeMs = typeof runtime.uptimeMs === 'function'
      ? runtime.uptimeMs
      : () => Math.floor(process.uptime() * 1000)
    this._heapSpaces = typeof runtime.heapSpaces === 'function'
      ? runtime.heapSpaces
      : () => getHeapSpaceStatistics()
    this._reader = runtime.reader || new BoundedProcfsReader()
    this._eventLoop = this._createEventLoopMonitor(runtime)
    this._counters = new MonotonicCounterTracker()
    this._healthSamples = new Array(this.healthSampleLimit)
    this._healthHead = 0
    this._healthSize = 0
    this._healthCounters = {
      requests: 0,
      status2xx: 0,
      status4xx: 0,
      status5xx: 0,
      emptyResponses: 0,
      timeouts: 0,
      errors: 0,
      cappedSamples: 0
    }
    this._snapshot = initialSnapshot()
    this._timer = null
    this._flight = null
    this._started = false
    this._failures = 0
    this._coalesced = 0
  }

  _createEventLoopMonitor (runtime) {
    if (Object.prototype.hasOwnProperty.call(runtime, 'eventLoopMonitor')) {
      return runtime.eventLoopMonitor
    }
    try { return monitorEventLoopDelay({ resolution: 20 }) } catch { return null }
  }

  async start () {
    if (this._started) return this.sample()
    this._started = true
    try { this._eventLoop?.enable?.() } catch {}
    const snapshot = await this.sample()
    if (this._started && !this._timer) {
      this._timer = setInterval(() => { this.sample().catch(() => {}) }, this.sampleIntervalMs)
      if (typeof this._timer.unref === 'function') this._timer.unref()
    }
    return snapshot
  }

  async stop () {
    this._started = false
    if (this._timer) clearInterval(this._timer)
    this._timer = null
    if (this._flight) await this._flight.catch(() => {})
    try { this._eventLoop?.disable?.() } catch {}
  }

  snapshot () {
    return this._snapshot
  }

  recordHealthRequest ({ durationMs, status, bytes, timeout = false, error = false } = {}) {
    if (!Number.isFinite(durationMs) || durationMs < 0) return false
    let sample = durationMs
    if (sample > MAX_HEALTH_LATENCY_MS) {
      sample = MAX_HEALTH_LATENCY_MS
      this._healthCounters.cappedSamples = increment(this._healthCounters.cappedSamples)
    }
    this._healthSamples[this._healthHead] = sample
    this._healthHead = (this._healthHead + 1) % this.healthSampleLimit
    if (this._healthSize < this.healthSampleLimit) this._healthSize++
    this._healthCounters.requests = increment(this._healthCounters.requests)
    if (Number.isSafeInteger(status) && status >= 200 && status <= 299) {
      this._healthCounters.status2xx = increment(this._healthCounters.status2xx)
    } else if (Number.isSafeInteger(status) && status >= 400 && status <= 499) {
      this._healthCounters.status4xx = increment(this._healthCounters.status4xx)
    } else if (Number.isSafeInteger(status) && status >= 500 && status <= 599) {
      this._healthCounters.status5xx = increment(this._healthCounters.status5xx)
    }
    if (safeInteger(bytes) === 0) this._healthCounters.emptyResponses = increment(this._healthCounters.emptyResponses)
    if (timeout === true) this._healthCounters.timeouts = increment(this._healthCounters.timeouts)
    if (error === true) this._healthCounters.errors = increment(this._healthCounters.errors)
    return true
  }

  sample () {
    if (this._flight) {
      this._coalesced = increment(this._coalesced)
      return this._flight
    }
    const startedAt = this._safeNow()
    const flight = this._sample(startedAt).catch(() => {
      this._failures = increment(this._failures)
      return this._snapshot
    }).finally(() => {
      if (this._flight === flight) this._flight = null
    })
    this._flight = flight
    return flight
  }

  _safeNow () {
    try {
      const value = this._now()
      return safeInteger(value) ?? Date.now()
    } catch {
      return Date.now()
    }
  }

  async _sample (startedAt) {
    const observedAt = this._safeNow()
    const processSnapshot = this._processSnapshot(observedAt)
    const linux = await this._linuxSnapshot(observedAt)
    const completedAt = this._safeNow()
    this._snapshot = deepFreeze({
      kind: RESOURCE_DIAGNOSTICS_KIND,
      version: RESOURCE_DIAGNOSTICS_VERSION,
      observedAt,
      sample: {
        available: true,
        reason: null,
        durationMs: Math.max(0, completedAt - startedAt),
        failures: this._failures,
        coalesced: this._coalesced
      },
      process: {
        ...processSnapshot,
        io: linux.processIo,
        majorFaults: linux.majorFaults,
        fileDescriptors: linux.fileDescriptors
      },
      cgroup: linux.cgroup,
      pressure: linux.pressure,
      latency: {
        eventLoop: this._eventLoopSnapshot(observedAt),
        health: this._healthSnapshot(observedAt)
      },
      resources: boundedRelayResourceCounters(this.node, { schedulerLimit: this.schedulerLimit })
    })
    return this._snapshot
  }

  _processSnapshot (observedAt) {
    let rawMemory = null
    try { rawMemory = this._memoryUsage() } catch {}
    const memory = rawMemory && typeof rawMemory === 'object'
      ? {
          supported: true,
          source: 'process.memoryUsage',
          observedAt,
          rssBytes: safeInteger(rawMemory.rss),
          heapTotalBytes: safeInteger(rawMemory.heapTotal),
          heapUsedBytes: safeInteger(rawMemory.heapUsed),
          externalBytes: safeInteger(rawMemory.external),
          arrayBuffersBytes: safeInteger(rawMemory.arrayBuffers)
        }
      : unavailable('process.memoryUsage', observedAt, 'unavailable')
    let spaces = null
    try { spaces = this._heapSpaces() } catch {}
    const heapSpaces = this._heapSpaceSnapshot(spaces, observedAt)
    let uptimeMs = null
    try { uptimeMs = safeInteger(this._uptimeMs()) } catch {}
    return { memory, heapSpaces, uptimeMs }
  }

  _heapSpaceSnapshot (raw, observedAt) {
    if (!Array.isArray(raw)) return unavailable('v8.getHeapSpaceStatistics', observedAt, 'unsupported')
    const spaces = []
    let invalidEntries = 0
    const length = Math.min(raw.length, this.heapSpaceLimit)
    for (let i = 0; i < length; i++) {
      const item = raw[i]
      const name = safeName(item?.space_name, null)
      const sizeBytes = safeInteger(item?.space_size)
      const usedBytes = safeInteger(item?.space_used_size)
      const availableBytes = safeInteger(item?.space_available_size)
      const physicalBytes = safeInteger(item?.physical_space_size)
      if (!name || sizeBytes === null || usedBytes === null || availableBytes === null || physicalBytes === null) {
        invalidEntries++
        continue
      }
      spaces.push({ name, sizeBytes, usedBytes, availableBytes, physicalBytes })
    }
    return {
      supported: true,
      source: 'v8.getHeapSpaceStatistics',
      observedAt,
      totalSpaces: safeInteger(raw.length),
      limit: this.heapSpaceLimit,
      truncated: raw.length > this.heapSpaceLimit,
      invalidEntries,
      spaces
    }
  }

  _eventLoopSnapshot (observedAt) {
    const monitor = this._eventLoop
    if (!monitor || typeof monitor.percentile !== 'function') {
      return unavailable('perf_hooks.monitorEventLoopDelay', observedAt, 'unsupported')
    }
    try {
      const p50 = Number(monitor.percentile(50)) / 1e6
      const p99 = Number(monitor.percentile(99)) / 1e6
      const max = Number(monitor.max) / 1e6
      const snapshot = {
        supported: [p50, p99, max].every(Number.isFinite),
        source: 'perf_hooks.monitorEventLoopDelay',
        observedAt,
        p50Ms: Number.isFinite(p50) ? Math.min(MAX_HEALTH_LATENCY_MS, Math.max(0, p50)) : null,
        p99Ms: Number.isFinite(p99) ? Math.min(MAX_HEALTH_LATENCY_MS, Math.max(0, p99)) : null,
        maxMs: Number.isFinite(max) ? Math.min(MAX_HEALTH_LATENCY_MS, Math.max(0, max)) : null
      }
      if (!snapshot.supported) snapshot.reason = 'malformed'
      monitor.reset?.()
      return snapshot
    } catch {
      return unavailable('perf_hooks.monitorEventLoopDelay', observedAt, 'unavailable')
    }
  }

  _healthSnapshot (observedAt) {
    const samples = []
    for (let i = 0; i < this._healthSize; i++) {
      const index = (this._healthHead - this._healthSize + i + this.healthSampleLimit) % this.healthSampleLimit
      samples.push(this._healthSamples[index])
    }
    samples.sort((a, b) => a - b)
    return {
      source: 'relay-api',
      observedAt,
      retainedSamples: samples.length,
      sampleLimit: this.healthSampleLimit,
      p50Ms: percentile(samples, 0.5),
      p99Ms: percentile(samples, 0.99),
      maxMs: samples.length > 0 ? samples[samples.length - 1] : null,
      ...this._healthCounters
    }
  }

  async _linuxSnapshot (observedAt) {
    if (this._platform !== 'linux') return this._unsupportedPlatformSnapshot(observedAt)
    const [membershipFile, ioFile, statFile, fdResult, globalMemory, globalIo, globalCpu] = await Promise.all([
      this._read(PROC_CGROUP),
      this._read(PROC_IO),
      this._read(PROC_STAT),
      this._countFds(),
      this._read('/proc/pressure/memory'),
      this._read('/proc/pressure/io'),
      this._read('/proc/pressure/cpu')
    ])
    const processIo = this._processIoSnapshot(ioFile, observedAt)
    const majorFaults = this._majorFaultSnapshot(statFile, observedAt)
    const fileDescriptors = fdResult.available
      ? {
          supported: true,
          source: 'procfs',
          observedAt,
          value: safeInteger(fdResult.value),
          limit: this.fdScanLimit,
          truncated: fdResult.truncated === true
        }
      : fileUnavailable(fdResult, 'procfs', observedAt)
    const membership = membershipFile.available ? parseCgroupMembership(membershipFile.text) : null
    const cgroup = membership
      ? await this._cgroupSnapshot(membership, observedAt)
      : {
          ...fileUnavailable(membershipFile, 'cgroup', observedAt),
          reason: membershipFile.available ? 'malformed-membership' : membershipFile.reason,
          version: null,
          memory: {
            current: unavailable('cgroup', observedAt, 'unavailable'),
            max: unavailable('cgroup', observedAt, 'unavailable'),
            peak: unavailable('cgroup', observedAt, 'unavailable')
          },
          events: unavailable('cgroup', observedAt, 'unavailable')
        }
    const cgroupPressure = cgroup.pressure || {}
    return {
      processIo,
      majorFaults,
      fileDescriptors,
      cgroup,
      pressure: {
        memory: cgroupPressure.memory?.supported
          ? cgroupPressure.memory
          : this._pressureFileSnapshot(globalMemory, 'memory', 'procfs-system-psi', observedAt),
        io: cgroupPressure.io?.supported
          ? cgroupPressure.io
          : this._pressureFileSnapshot(globalIo, 'io', 'procfs-system-psi', observedAt),
        cpu: cgroupPressure.cpu?.supported
          ? cgroupPressure.cpu
          : this._pressureFileSnapshot(globalCpu, 'cpu', 'procfs-system-psi', observedAt)
      }
    }
  }

  _unsupportedPlatformSnapshot (observedAt) {
    return {
      processIo: unavailable('procfs', observedAt, 'unsupported-platform'),
      majorFaults: unavailable('procfs', observedAt, 'unsupported-platform'),
      fileDescriptors: unavailable('procfs', observedAt, 'unsupported-platform'),
      cgroup: {
        ...unavailable('cgroup', observedAt, 'unsupported-platform'),
        version: null,
        memory: {
          current: unavailable('cgroup', observedAt, 'unsupported-platform'),
          max: unavailable('cgroup', observedAt, 'unsupported-platform'),
          peak: unavailable('cgroup', observedAt, 'unsupported-platform')
        },
        events: unavailable('cgroup', observedAt, 'unsupported-platform')
      },
      pressure: {
        memory: unavailable('psi', observedAt, 'unsupported-platform'),
        io: unavailable('psi', observedAt, 'unsupported-platform'),
        cpu: unavailable('psi', observedAt, 'unsupported-platform')
      }
    }
  }

  async _read (path) {
    try { return await this._reader.readText(path, this.fileReadBytes) } catch { return { available: false, reason: 'read-error' } }
  }

  async _countFds () {
    try { return await this._reader.countFileDescriptors(this.fdScanLimit) } catch { return { available: false, reason: 'read-error' } }
  }

  _processIoSnapshot (file, observedAt) {
    const parsed = file.available ? parseProcIo(file.text) : null
    if (!parsed) return fileUnavailable(file, 'procfs-self-io', observedAt)
    return {
      supported: true,
      source: 'procfs-self-io',
      observedAt,
      readBytes: this._counters.observe('process:read-bytes', parsed.readBytes, {
        source: 'procfs-self-io',
        observedAt
      }),
      readCharacters: parsed.readCharacters === null
        ? this._counters.unsupported('procfs-self-io', observedAt, 'absent')
        : this._counters.observe('process:read-characters', parsed.readCharacters, {
          source: 'procfs-self-io',
          observedAt
        }),
      readOperations: this._counters.observe('process:read-operations', parsed.readOperations, {
        source: 'procfs-self-io',
        observedAt
      })
    }
  }

  _majorFaultSnapshot (file, observedAt) {
    const value = file.available ? parseProcMajorFaults(file.text) : null
    return value === null
      ? fileUnavailable(file, 'procfs-self-stat', observedAt)
      : this._counters.observe('process:major-faults', value, {
        source: 'procfs-self-stat',
        observedAt
      })
  }

  _pressureFileSnapshot (file, name, source, observedAt) {
    if (!file.available) return fileUnavailable(file, source, observedAt)
    return pressureSnapshot(parsePressure(file.text), name, source, observedAt, this._counters)
  }

  async _cgroupSnapshot (membership, observedAt) {
    if (membership.version === 'v2') return this._cgroupV2Snapshot(membership, observedAt)
    return this._cgroupV1Snapshot(membership, observedAt)
  }

  async _cgroupV2Snapshot (membership, observedAt) {
    const [current, max, peak, events, memoryPressure, ioPressure, cpuPressure] = await Promise.all([
      this._read(cgroupPath(membership, 'memory.current')),
      this._read(cgroupPath(membership, 'memory.max')),
      this._read(cgroupPath(membership, 'memory.peak')),
      this._read(cgroupPath(membership, 'memory.events')),
      this._read(cgroupPath(membership, 'memory.pressure')),
      this._read(cgroupPath(membership, 'io.pressure')),
      this._read(cgroupPath(membership, 'cpu.pressure'))
    ])
    return {
      supported: true,
      source: 'cgroup-v2',
      observedAt,
      reason: null,
      version: 'v2',
      memory: {
        current: current.available
          ? parseMemoryValue(current.text, 'cgroup-v2-memory-current', observedAt)
          : fileUnavailable(current, 'cgroup-v2-memory-current', observedAt),
        max: max.available
          ? parseMemoryValue(max.text, 'cgroup-v2-memory-max', observedAt)
          : fileUnavailable(max, 'cgroup-v2-memory-max', observedAt),
        peak: peak.available
          ? parseMemoryValue(peak.text, 'cgroup-v2-memory-peak', observedAt)
          : fileUnavailable(peak, 'cgroup-v2-memory-peak', observedAt)
      },
      events: this._eventSnapshot(events, 'cgroup-v2-memory-events', observedAt),
      pressure: {
        memory: this._pressureFileSnapshot(memoryPressure, 'memory', 'cgroup-v2-psi', observedAt),
        io: this._pressureFileSnapshot(ioPressure, 'io', 'cgroup-v2-psi', observedAt),
        cpu: this._pressureFileSnapshot(cpuPressure, 'cpu', 'cgroup-v2-psi', observedAt)
      }
    }
  }

  async _cgroupV1Snapshot (membership, observedAt) {
    const [current, max, peak, failcnt] = await Promise.all([
      this._read(cgroupPath(membership, 'memory.usage_in_bytes')),
      this._read(cgroupPath(membership, 'memory.limit_in_bytes')),
      this._read(cgroupPath(membership, 'memory.max_usage_in_bytes')),
      this._read(cgroupPath(membership, 'memory.failcnt'))
    ])
    const failValue = failcnt.available ? parseUnsigned(failcnt.text.trim()) : null
    return {
      supported: true,
      source: 'cgroup-v1',
      observedAt,
      reason: null,
      version: 'v1',
      memory: {
        current: current.available
          ? parseMemoryValue(current.text, 'cgroup-v1-memory-current', observedAt)
          : fileUnavailable(current, 'cgroup-v1-memory-current', observedAt),
        max: max.available
          ? parseMemoryValue(max.text, 'cgroup-v1-memory-max', observedAt)
          : fileUnavailable(max, 'cgroup-v1-memory-max', observedAt),
        peak: peak.available
          ? parseMemoryValue(peak.text, 'cgroup-v1-memory-peak', observedAt)
          : fileUnavailable(peak, 'cgroup-v1-memory-peak', observedAt)
      },
      events: failValue === null
        ? fileUnavailable(failcnt, 'cgroup-v1-memory-events', observedAt)
        : {
            supported: true,
            source: 'cgroup-v1-memory-events',
            observedAt,
            counters: {
              failcnt: this._counters.observe('cgroup-v1:event:failcnt', failValue, {
                source: 'cgroup-v1-memory-events',
                observedAt
              })
            }
          },
      pressure: {
        memory: unavailable('cgroup-v1-psi', observedAt, 'unsupported'),
        io: unavailable('cgroup-v1-psi', observedAt, 'unsupported'),
        cpu: unavailable('cgroup-v1-psi', observedAt, 'unsupported')
      }
    }
  }

  _eventSnapshot (file, source, observedAt) {
    if (!file.available) return fileUnavailable(file, source, observedAt)
    const parsed = parseEventCounters(file.text)
    if (!parsed) return unavailable(source, observedAt, 'malformed')
    const counters = {}
    for (const key of CGROUP_EVENT_KEYS) {
      if (parsed[key] === undefined) continue
      counters[key] = this._counters.observe(`${source}:${key}`, parsed[key], { source, observedAt })
    }
    return { supported: true, source, observedAt, counters }
  }
}
