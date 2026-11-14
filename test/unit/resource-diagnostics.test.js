import test from 'brittle'
import { AppLifecycle } from '../../packages/core/core/relay-node/app-lifecycle.js'
import { StorageAccounting } from '../../packages/core/core/relay-node/storage-accounting.js'
import {
  boundedRelayResourceCounters,
  MAX_DIAGNOSTIC_FILE_BYTES,
  MAX_FD_SCAN_LIMIT,
  MAX_HEALTH_LATENCY_SAMPLES,
  MAX_HEAP_SPACE_LIMIT,
  MAX_RESOURCE_SAMPLE_INTERVAL_MS,
  MonotonicCounterTracker,
  parseCgroupMembership,
  parseEventCounters,
  parsePressure,
  parseProcIo,
  parseProcMajorFaults,
  ResourceDiagnostics,
  RESOURCE_DIAGNOSTICS_KIND
} from '../../packages/core/core/relay-node/resource-diagnostics.js'

class FixtureReader {
  constructor (files = {}, fd = { available: true, value: 12, truncated: false }) {
    this.files = new Map(Object.entries(files))
    this.fd = fd
    this.calls = []
    this.pending = null
  }

  async readText (path, maxBytes) {
    this.calls.push({ kind: 'read', path, maxBytes })
    if (this.pending) await this.pending
    if (!this.files.has(path)) return { available: false, reason: 'absent' }
    const value = this.files.get(path)
    if (value && typeof value === 'object') return value
    if (Buffer.byteLength(value) > maxBytes) return { available: false, reason: 'too-large' }
    return { available: true, bytes: Buffer.byteLength(value), text: value }
  }

  async countFileDescriptors (limit) {
    this.calls.push({ kind: 'fds', limit })
    if (this.pending) await this.pending
    return this.fd
  }
}

function procStat (majorFaults) {
  const suffix = ['S', '1', '2', '3', '4', '5', '6', '7', '8', String(majorFaults), '10', '11']
  return `123 (relay worker) ${suffix.join(' ')}\n`
}

function pressure (someTotal, fullTotal = null) {
  const lines = [`some avg10=0.10 avg60=0.20 avg300=0.30 total=${someTotal}`]
  if (fullTotal !== null) lines.push(`full avg10=0.01 avg60=0.02 avg300=0.03 total=${fullTotal}`)
  return lines.join('\n') + '\n'
}

function v2Files () {
  const root = '/sys/fs/cgroup/relay.slice'
  return {
    '/proc/self/cgroup': '0::/relay.slice\n',
    '/proc/self/io': 'rchar: 200\nsyscr: 20\nread_bytes: 100\nwrite_bytes: 9\n',
    '/proc/self/stat': procStat(4),
    '/proc/pressure/memory': pressure(900, 100),
    '/proc/pressure/io': pressure(800, 80),
    '/proc/pressure/cpu': pressure(700),
    [`${root}/memory.current`]: '4096\n',
    [`${root}/memory.max`]: '8192\n',
    [`${root}/memory.peak`]: '6144\n',
    [`${root}/memory.events`]: 'low 1\nhigh 2\nmax 3\noom 4\noom_kill 5\nunknown_future 99\n',
    [`${root}/memory.pressure`]: pressure(1000, 200),
    [`${root}/io.pressure`]: pressure(2000, 300),
    [`${root}/cpu.pressure`]: pressure(3000)
  }
}

function fakeEventLoop () {
  return {
    max: 9_000_000,
    enabled: 0,
    disabled: 0,
    resets: 0,
    enable () { this.enabled++ },
    disable () { this.disabled++ },
    reset () { this.resets++ },
    percentile (value) { return value === 50 ? 2_000_000 : 7_000_000 }
  }
}

function fixture (opts = {}) {
  const reader = opts.reader || new FixtureReader(v2Files())
  const eventLoopMonitor = opts.eventLoopMonitor === undefined ? fakeEventLoop() : opts.eventLoopMonitor
  let now = opts.now ?? 1_000
  const diagnostics = new ResourceDiagnostics(opts.node || null, {
    sampleIntervalMs: 1_000,
    fileReadBytes: 2_048,
    fdScanLimit: 32,
    heapSpaceLimit: 2,
    healthSampleLimit: 16,
    schedulerLimit: 2,
    runtime: {
      platform: opts.platform || 'linux',
      reader,
      eventLoopMonitor,
      now: () => now,
      uptimeMs: () => 12_345,
      memoryUsage: () => ({
        rss: 10,
        heapTotal: 20,
        heapUsed: 15,
        external: 4,
        arrayBuffers: 3
      }),
      heapSpaces: () => [
        { space_name: 'old_space', space_size: 10, space_used_size: 8, space_available_size: 2, physical_space_size: 10 },
        { space_name: 'new_space', space_size: 20, space_used_size: 12, space_available_size: 8, physical_space_size: 20 },
        { space_name: 'code_space', space_size: 30, space_used_size: 20, space_available_size: 10, physical_space_size: 30 }
      ]
    }
  })
  return {
    diagnostics,
    reader,
    eventLoopMonitor,
    setNow (value) { now = value }
  }
}

test('resource diagnostics: strict parsers accept canonical kernel shapes only', (t) => {
  t.alike(parseProcIo('rchar: 10\nsyscr: 2\nread_bytes: 8\n'), {
    readBytes: 8,
    readCharacters: 10,
    readOperations: 2
  })
  t.is(parseProcIo('read_bytes: -1\nsyscr: 2\n'), null)
  t.is(parseProcMajorFaults(procStat(17)), 17)
  t.is(parseProcMajorFaults('bad'), null)
  t.alike(parseCgroupMembership('0::/relay.slice\n'), {
    version: 'v2',
    segments: ['relay.slice']
  })
  t.alike(parseCgroupMembership('4:cpu:/x\n5:memory:/relay\n'), {
    version: 'v1',
    segments: ['relay']
  })
  t.is(parseCgroupMembership('0::/../../escape\n'), null)
  t.alike(parseEventCounters('low 1\noom 2\nfuture 999\n'), { low: 1, oom: 2 })
  t.is(parseEventCounters('oom nope\n'), null)
  t.alike(parsePressure(pressure(123, 45)), {
    some: { avg10Pct: 0.1, avg60Pct: 0.2, avg300Pct: 0.3, totalMicros: 123 },
    full: { avg10Pct: 0.01, avg60Pct: 0.02, avg300Pct: 0.03, totalMicros: 45 }
  })
  t.is(parsePressure('some avg10=101 avg60=0 avg300=0 total=1\n'), null)
})

test('resource diagnostics: v2 sample is bounded, allowlisted and JSON-safe', async (t) => {
  const { diagnostics, reader, eventLoopMonitor } = fixture({
    reader: new FixtureReader(v2Files(), { available: true, value: 32, truncated: true })
  })
  const snapshot = await diagnostics.sample()

  t.is(snapshot.kind, RESOURCE_DIAGNOSTICS_KIND)
  t.is(snapshot.version, 1)
  t.alike(snapshot.process.memory, {
    supported: true,
    source: 'process.memoryUsage',
    observedAt: 1000,
    rssBytes: 10,
    heapTotalBytes: 20,
    heapUsedBytes: 15,
    externalBytes: 4,
    arrayBuffersBytes: 3
  })
  t.is(snapshot.process.heapSpaces.spaces.length, 2)
  t.is(snapshot.process.heapSpaces.totalSpaces, 3)
  t.is(snapshot.process.heapSpaces.truncated, true)
  t.is(snapshot.process.fileDescriptors.value, 32)
  t.is(snapshot.process.fileDescriptors.truncated, true)
  t.is(snapshot.cgroup.version, 'v2')
  t.is(snapshot.cgroup.memory.current.value, 4096)
  t.is(snapshot.cgroup.memory.max.value, 8192)
  t.is(snapshot.cgroup.memory.peak.value, 6144)
  t.is(snapshot.cgroup.events.counters.oom_kill.value, 5)
  t.absent(snapshot.cgroup.events.counters.unknown_future)
  t.is(snapshot.pressure.memory.source, 'cgroup-v2-psi')
  t.is(snapshot.pressure.io.some.totalMicros.value, 2000)
  t.is(snapshot.process.io.readBytes.baseline, true)
  t.is(snapshot.process.majorFaults.value, 4)
  t.is(snapshot.latency.eventLoop.p50Ms, 2)
  t.is(snapshot.latency.eventLoop.p99Ms, 7)
  t.is(snapshot.latency.eventLoop.maxMs, 9)
  t.is(eventLoopMonitor.resets, 1)
  t.ok(reader.calls.every(call => call.kind !== 'read' || call.maxBytes === 2048))
  t.is(reader.calls.filter(call => call.kind === 'read').length, 13, 'fixed read-source count')
  const json = JSON.stringify(snapshot)
  t.absent(json.includes('relay.slice'), 'cgroup membership path is redacted')
  t.absent(json.includes('unknown_future'), 'unknown event fields are not dumped')
  t.ok(Object.isFrozen(snapshot))
  t.ok(Object.isFrozen(snapshot.process.memory))
})

test('resource diagnostics: deltas, rates and reset markers are explicit', async (t) => {
  const { diagnostics, reader, setNow } = fixture()
  const first = await diagnostics.sample()
  t.is(first.process.io.readBytes.delta, null)
  t.is(first.process.io.readBytes.baseline, true)

  setNow(2_000)
  reader.files.set('/proc/self/io', 'rchar: 500\nsyscr: 25\nread_bytes: 300\n')
  reader.files.set('/proc/self/stat', procStat(7))
  reader.files.set('/sys/fs/cgroup/relay.slice/memory.events', 'low 3\nhigh 2\nmax 3\noom 4\noom_kill 6\n')
  reader.files.set('/sys/fs/cgroup/relay.slice/memory.pressure', pressure(1500, 250))
  const second = await diagnostics.sample()
  t.is(second.process.io.readBytes.delta, 200)
  t.is(second.process.io.readBytes.ratePerSecond, 200)
  t.is(second.process.io.readOperations.delta, 5)
  t.is(second.process.majorFaults.delta, 3)
  t.is(second.cgroup.events.counters.low.delta, 2)
  t.is(second.pressure.memory.some.totalMicros.delta, 500)

  setNow(3_000)
  reader.files.set('/proc/self/io', 'rchar: 1\nsyscr: 1\nread_bytes: 1\n')
  reader.files.set('/proc/self/stat', procStat(1))
  const third = await diagnostics.sample()
  t.is(third.process.io.readBytes.reset, true)
  t.is(third.process.io.readBytes.delta, null)
  t.is(third.process.io.readBytes.ratePerSecond, null)
  t.is(third.process.majorFaults.reset, true)
})

test('resource diagnostics: cgroup v1 uses fixed memory files and global PSI fallback', async (t) => {
  const root = '/sys/fs/cgroup/memory/legacy'
  const reader = new FixtureReader({
    '/proc/self/cgroup': '4:cpu:/legacy\n5:memory:/legacy\n',
    '/proc/self/io': 'rchar: 10\nsyscr: 2\nread_bytes: 8\n',
    '/proc/self/stat': procStat(1),
    '/proc/pressure/memory': pressure(20, 2),
    '/proc/pressure/io': pressure(30, 3),
    '/proc/pressure/cpu': pressure(40),
    [`${root}/memory.usage_in_bytes`]: '1024\n',
    [`${root}/memory.limit_in_bytes`]: '9223372036854771712\n',
    [`${root}/memory.max_usage_in_bytes`]: '2048\n',
    [`${root}/memory.failcnt`]: '3\n'
  })
  const { diagnostics } = fixture({ reader })
  const snapshot = await diagnostics.sample()

  t.is(snapshot.cgroup.version, 'v1')
  t.is(snapshot.cgroup.memory.current.value, 1024)
  t.is(snapshot.cgroup.memory.max.value, null)
  t.is(snapshot.cgroup.memory.max.unlimited, true)
  t.is(snapshot.cgroup.memory.peak.value, 2048)
  t.is(snapshot.cgroup.events.counters.failcnt.value, 3)
  t.is(snapshot.cgroup.pressure.memory.supported, false)
  t.is(snapshot.pressure.memory.source, 'procfs-system-psi')
  t.is(snapshot.pressure.cpu.some.totalMicros.value, 40)
  t.is(reader.calls.filter(call => call.kind === 'read').length, 10)
})

test('resource diagnostics: missing, malformed and non-Linux sources are never reported as zero', async (t) => {
  const missing = fixture({ reader: new FixtureReader({}) })
  const missingSnapshot = await missing.diagnostics.sample()
  t.is(missingSnapshot.cgroup.supported, false)
  t.is(missingSnapshot.cgroup.version, null)
  t.is(missingSnapshot.cgroup.memory.current.supported, false)
  t.is(missingSnapshot.process.io.supported, false)
  t.is(missingSnapshot.process.fileDescriptors.supported, true)
  t.is(missingSnapshot.pressure.memory.supported, false)

  const malformedReader = new FixtureReader(v2Files())
  malformedReader.files.set('/proc/self/cgroup', 'malformed\n')
  malformedReader.files.set('/proc/self/io', 'read_bytes: nope\n')
  const malformed = fixture({ reader: malformedReader })
  const malformedSnapshot = await malformed.diagnostics.sample()
  t.is(malformedSnapshot.cgroup.reason, 'malformed-membership')
  t.is(malformedSnapshot.process.io.supported, false)

  const other = fixture({ platform: 'darwin' })
  const otherSnapshot = await other.diagnostics.sample()
  t.is(otherSnapshot.process.io.reason, 'unsupported-platform')
  t.is(otherSnapshot.process.fileDescriptors.reason, 'unsupported-platform')
  t.is(otherSnapshot.cgroup.reason, 'unsupported-platform')
  t.is(other.reader.calls.length, 0, 'unsupported platform performs no procfs reads')
})

test('resource diagnostics: health latency ring has fixed capacity and bounded values', async (t) => {
  const { diagnostics } = fixture()
  for (let i = 0; i < 20; i++) {
    diagnostics.recordHealthRequest({
      durationMs: i === 19 ? 99_999 : i,
      status: i % 3 === 0 ? 503 : 200,
      bytes: i === 7 ? 0 : 10,
      timeout: i === 8,
      error: i === 9
    })
  }
  t.is(diagnostics.recordHealthRequest({ durationMs: -1 }), false)
  const snapshot = await diagnostics.sample()
  const health = snapshot.latency.health
  t.is(health.retainedSamples, 16)
  t.is(health.sampleLimit, 16)
  t.is(health.requests, 20)
  t.is(health.status2xx, 13)
  t.is(health.status5xx, 7)
  t.is(health.emptyResponses, 1)
  t.is(health.timeouts, 1)
  t.is(health.errors, 1)
  t.is(health.cappedSamples, 1)
  t.is(health.maxMs, 60_000)
  t.ok(health.p50Ms >= 4 && health.p50Ms <= 19)
})

test('resource diagnostics: concurrent samples coalesce and lifecycle drains one flight', async (t) => {
  let release
  const reader = new FixtureReader(v2Files())
  reader.pending = new Promise(resolve => { release = resolve })
  const { diagnostics, eventLoopMonitor } = fixture({ reader })
  const first = diagnostics.sample()
  const second = diagnostics.sample()
  t.is(first, second)
  release()
  await first
  t.is(diagnostics.snapshot().sample.coalesced, 1)

  await diagnostics.start()
  t.is(eventLoopMonitor.enabled, 1)
  await diagnostics.stop()
  t.is(eventLoopMonitor.disabled, 1)
})

test('resource diagnostics: relay counters are O(1), capped and allowlisted', (t) => {
  const forbidden = () => { throw new Error('full snapshot forbidden') }
  const schedulers = new Map()
  for (let i = 0; i < 3; i++) {
    schedulers.set(`pass-${i}`, {
      snapshot () {
        return { running: i === 0, scheduled: true, passes: i, failures: 0, privateState: { secret: true } }
      }
    })
  }
  const node = {
    getStats: forbidden,
    seededApps: new Map([['a', {}]]),
    appRegistry: { size: 1, snapshot: forbidden, _appPopulation: { consumerCount: 4 } },
    seedingRegistry: {
      snapshot: forbidden,
      _requestPopulation: { consumerCount: 2 },
      _custodyIntentPopulation: { consumerCount: 1 }
    },
    seeder: { cores: new Map([['a', {}]]) },
    swarm: { connections: new Set([{}]) },
    connections: new Map([[{}, {}]]),
    relay: { circuits: new Map([['c', {}]]) },
    servedAccounting: { _coreCount: 7 },
    appLifecycle: {
      getResourceCounters () {
        return {
          driveReadOwners: 2,
          activeDriveReadLeases: 3,
          retiringDrives: 1,
          repairFlights: 1,
          transientDownloadRanges: 2,
          persistentDownloadRanges: 4,
          auxiliaryShareBundles: 1,
          auxiliaryRangeTrackers: 1
        }
      }
    },
    storageAccounting: {
      getSummary: forbidden,
      getResourceDiagnostics () {
        return { available: true, state: 'running', epochActive: true, waiters: 1, measuredEntries: 9 }
      }
    },
    _completionSchedulers: schedulers,
    _custodyWitnessProofCursor: new Map([['x', 1]])
  }
  const snapshot = boundedRelayResourceCounters(node, { schedulerLimit: 2 })
  t.is(snapshot.open.storeCores, 7)
  t.is(snapshot.open.hyperdrives, 1)
  t.is(snapshot.lifecycle.activeDriveReadLeases, 3)
  t.is(snapshot.accounting.measuredEntries, 9)
  t.is(snapshot.schedulers.count, 3)
  t.is(snapshot.schedulers.entries.length, 2)
  t.is(snapshot.schedulers.truncated, true)
  t.absent(JSON.stringify(snapshot).includes('privateState'))
  t.is(snapshot.cursors.appRegistry, 4)
})

test('resource diagnostics: numeric caps and counter reset semantics are strict', async (t) => {
  for (const opts of [
    { sampleIntervalMs: 999 },
    { sampleIntervalMs: MAX_RESOURCE_SAMPLE_INTERVAL_MS + 1 },
    { fileReadBytes: MAX_DIAGNOSTIC_FILE_BYTES + 1 },
    { fdScanLimit: MAX_FD_SCAN_LIMIT + 1 },
    { heapSpaceLimit: MAX_HEAP_SPACE_LIMIT + 1 },
    { healthSampleLimit: MAX_HEALTH_LATENCY_SAMPLES + 1 },
    { schedulerLimit: 0 }
  ]) {
    await t.exception.all(() => new ResourceDiagnostics(null, opts), /safe integer/)
  }

  const tracker = new MonotonicCounterTracker()
  const first = tracker.observe('x', 10, { source: 'test', observedAt: 1000 })
  const second = tracker.observe('x', 15, { source: 'test', observedAt: 2000 })
  const reset = tracker.observe('x', 2, { source: 'test', observedAt: 3000 })
  t.is(first.baseline, true)
  t.is(second.delta, 5)
  t.is(second.ratePerSecond, 5)
  t.is(reset.reset, true)
  t.is(reset.delta, null)
  t.is(tracker.unsupported('test', 4000, 'absent').value, null)
})

test('resource diagnostics: AppLifecycle owns exact O(1) lease and range counters', async (t) => {
  const drive = { closed: false, closing: false }
  const entry = { drive }
  const apps = new Map([['app', entry]])
  const lifecycle = new AppLifecycle({
    appRegistry: {
      apps,
      get (key) { return apps.get(key) }
    }
  })
  const firstLease = lifecycle.acquireDriveReadLease('app')
  const secondLease = lifecycle.acquireDriveReadLease('app')
  t.is(lifecycle.getResourceCounters().driveReadOwners, 1)
  t.is(lifecycle.getResourceCounters().activeDriveReadLeases, 2)
  firstLease.release()
  secondLease.release()
  t.is(lifecycle.getResourceCounters().driveReadOwners, 0)
  t.is(lifecycle.getResourceCounters().activeDriveReadLeases, 0)

  const trackers = []
  const core = (length, byteLength) => ({
    fork: 0,
    length,
    byteLength,
    download () {
      const tracker = { destroy () {}, done: async () => {} }
      trackers.push(tracker)
      return tracker
    },
    async close () {}
  })
  await lifecycle._downloadProvedDriveRanges(drive, {
    metaCoreSnapshot: core(1, 10),
    blobCoreSnapshot: core(1, 20),
    metaLength: 1,
    blobLength: 1
  })
  t.is(lifecycle.getResourceCounters().transientDownloadRanges, 0)

  const proof = {
    driveVersion: 1,
    metaLength: 1,
    blobLength: 1,
    metaFork: 0,
    blobFork: 0,
    totalBytes: 30,
    metaCoreSnapshot: core(1, 10),
    blobCoreSnapshot: core(1, 20)
  }
  t.is(await lifecycle._installPersistentDownloadProof('app', drive, proof), true)
  t.is(lifecycle.getResourceCounters().persistentDownloadRanges, 2)
  t.is(entry.downloadRanges.length, 2)
})

test('resource diagnostics: StorageAccounting diagnostics never sum per-drive state', (t) => {
  let now = 2_000
  const accounting = new StorageAccounting({ appRegistry: {}, now: () => now })
  accounting._bytes.set('a', { bytes: 10 })
  accounting._bytes.set('b', { bytes: 20 })
  accounting._lastDiskAttempt = {
    observedAt: 1_000,
    completedAt: 1_500,
    durationMs: 500,
    incompleteReason: null
  }
  accounting._diskMeasurementComplete = true
  accounting._diskStats.epochsStarted = 2
  accounting._diskStats.epochsCompleted = 1
  accounting._diskStats.coalesced = 3
  accounting._diskEpoch = {
    getProgress () {
      return {
        state: 'running',
        operationsInFlight: 1,
        queuedPaths: 2,
        queuedPathBytes: 30,
        bookkeepingBytes: 40,
        cursor: { path: '/secret/storage/path' }
      }
    }
  }
  accounting._diskEpochPromise = Promise.resolve()
  accounting._sources.set('forbidden', () => { throw new Error('source walk forbidden') })
  const snapshot = accounting.getResourceDiagnostics()

  t.is(snapshot.measuredEntries, 2)
  t.is(snapshot.state, 'running')
  t.is(snapshot.epochActive, true)
  t.is(snapshot.operationsInFlight, 1)
  t.is(snapshot.queuedPathBytes, 30)
  t.is(snapshot.ageMs, 1_000)
  t.is(snapshot.epochsStarted, 2)
  t.is(snapshot.epochsCompleted, 1)
  t.is(snapshot.coalesced, 3)
  t.absent(JSON.stringify(snapshot).includes('/secret'))
  now = 3_000
  t.is(accounting.getResourceDiagnostics().ageMs, 2_000)
})
