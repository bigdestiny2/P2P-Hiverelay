import test from 'brittle'
import { spawnSync } from 'child_process'
import { lstat, mkdtemp, opendir, rm } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import {
  STORAGE_ACCOUNTING_EPOCH_HARD_LIMITS,
  StorageAccountingEpoch,
  StorageAccountingOperationBudget,
  parseStorageAccountingEpochLimits,
  runStorageAccountingEpoch
} from '../../packages/core/core/relay-node/storage-accounting-epoch.js'

class FakeClock {
  constructor (now = 0) {
    this.time = now
    this.nextTimer = 1
    this.timers = new Map()
  }

  now () {
    return this.time
  }

  setTimeout (fn, ms) {
    const timer = {
      id: this.nextTimer++,
      due: this.time + Math.max(0, ms),
      fn,
      unref () {}
    }
    this.timers.set(timer.id, timer)
    return timer
  }

  clearTimeout (timer) {
    if (timer) this.timers.delete(timer.id)
  }

  async sleep (ms) {
    this.advance(ms)
  }

  consume (ms) {
    this.advance(ms)
  }

  advance (ms) {
    const target = this.time + Math.max(0, ms)
    while (true) {
      let next = null
      for (const timer of this.timers.values()) {
        if (timer.due > target) continue
        if (!next || timer.due < next.due || (timer.due === next.due && timer.id < next.id)) next = timer
      }
      if (!next) break
      this.timers.delete(next.id)
      this.time = Math.max(this.time, next.due)
      next.fn()
    }
    this.time = Math.max(this.time, target)
  }
}

function directoryStat (ino, options = {}) {
  let charged = false
  return {
    dev: options.dev ?? 1,
    ino,
    blocks: 0,
    size: 0,
    isSymbolicLink: () => false,
    isDirectory: () => {
      if (!charged && options.jsCost) {
        charged = true
        options.clock.consume(options.jsCost)
      }
      return true
    },
    isFile: () => false
  }
}

function fileStat (ino, options = {}) {
  return {
    dev: options.dev ?? 1,
    ino,
    blocks: options.blocks ?? 0,
    size: options.size ?? 0,
    isSymbolicLink: () => false,
    isDirectory: () => false,
    isFile: () => true
  }
}

function symlinkStat (ino) {
  return {
    dev: 1,
    ino,
    blocks: 0,
    size: 0,
    isSymbolicLink: () => true,
    isDirectory: () => false,
    isFile: () => false
  }
}

function ioError (code, message = code) {
  const err = new Error(message)
  err.code = code
  return err
}

async function waitFor (predicate, label) {
  for (let attempt = 0; attempt < 1_000; attempt++) {
    if (predicate()) return
    await Promise.resolve()
  }
  throw new Error(`timed out waiting for ${label}`)
}

function emptyFs (clock, options = {}) {
  const starts = []
  let lstatCalls = 0
  let reads = 0
  let closes = 0
  const record = (name) => starts.push({ name, at: clock.now() })
  const fs = {
    async lstat (path) {
      record('lstat')
      lstatCalls++
      if (options.onLstat) {
        const value = options.onLstat({ path, call: lstatCalls, clock })
        if (value) return value
      }
      return directoryStat(1, lstatCalls === 1 ? options.initialStatOptions : {})
    },
    async opendir (path, openOptions) {
      record('opendir')
      if (openOptions.bufferSize !== 1) throw new Error('bufferSize must be one')
      return {
        async read () {
          record('read')
          reads++
          if (options.readError) throw options.readError
          return null
        },
        async close () {
          record('close')
          closes++
          if (options.onClose) await options.onClose({ path, call: closes, clock })
        }
      }
    }
  }
  return { fs, starts, counts: () => ({ lstatCalls, reads, closes }) }
}

function generatedMaximumFs ({ directoryEntries = 49_999, fileEntries = 200_001 } = {}) {
  const root = '/root'
  return {
    async lstat (path) {
      if (path === root) return directoryStat(1)
      const name = path.slice(root.length + 1)
      if (name[0] === 'd') return directoryStat(Number(name.slice(1)) + 2)
      return fileStat(Number(name.slice(1)) + 100_002)
    },
    async opendir (path, options) {
      if (options.bufferSize !== 1) throw new Error('bufferSize must be one')
      if (path !== root) {
        return { read: async () => null, close: async () => {} }
      }
      let index = 0
      return {
        async read () {
          if (index < directoryEntries) return { name: `d${index++}` }
          if (index < directoryEntries + fileEntries) return { name: `f${index++ - directoryEntries}` }
          return null
        },
        async close () {}
      }
    }
  }
}

function nestedFailureFs (depth, closeMode = 'retry-success') {
  const closeCalls = new Map()
  const pathDepth = path => path.split('/').filter(Boolean).length - 1
  return {
    closeCalls,
    fs: {
      async lstat (path) {
        return directoryStat(pathDepth(path) + 1)
      },
      async opendir (path, options) {
        if (options.bufferSize !== 1) throw new Error('bufferSize must be one')
        const currentDepth = pathDepth(path)
        let yielded = false
        return {
          async read () {
            if (currentDepth === depth - 1) throw ioError('EIO')
            if (!yielded) {
              yielded = true
              return { name: 'd' }
            }
            return null
          },
          async close () {
            const calls = (closeCalls.get(path) || 0) + 1
            closeCalls.set(path, calls)
            if (closeMode === 'always-fail' || calls === 1) throw ioError('ECLOSE')
          }
        }
      }
    }
  }
}

test('accounting epoch limits are exact, strict, and clamp safe integers', async (t) => {
  const hard = STORAGE_ACCOUNTING_EPOCH_HARD_LIMITS
  t.is(hard.operationCap, 800_000)
  t.is(hard.cleanupReserve, 129)
  t.is(hard.ordinaryOperationLimit, 799_871)
  t.is(hard.normalDeadlineMs, 28_800_000)
  t.is(hard.cleanupDeadlineMs, 900_000)

  const clamped = parseStorageAccountingEpochLimits({
    operationsPerSecond: 33,
    javascriptSliceMs: 11,
    maxOpenDirectories: 65,
    maxEntries: 250_001,
    maxDirectories: 50_001
  })
  t.is(clamped.operationsPerSecond, 32)
  t.is(clamped.javascriptSliceMs, 10)
  t.is(clamped.maxOpenDirectories, 64)
  t.is(clamped.maxEntries, 250_000)
  t.is(clamped.maxDirectories, 50_000)

  for (const value of ['32', 1.5, 0, -1, NaN, Infinity]) {
    await t.exception.all(() => parseStorageAccountingEpochLimits({ operationsPerSecond: value }))
  }
})

test('operation buckets preserve the exact 700001 + 99870 + 129 arithmetic', async (t) => {
  const budget = new StorageAccountingOperationBudget()
  for (let i = 0; i < 700_001; i++) budget.chargeOrdinary()
  for (let i = 0; i < 99_870; i++) budget.chargeOrdinary()
  t.is(budget.snapshot().ordinary, 799_871)
  await t.exception(() => budget.chargeOrdinary(), /ordinary operation limit/)

  for (let i = 0; i < 129; i++) budget.chargeCleanup()
  const snapshot = budget.snapshot()
  t.is(snapshot.cleanup, 129)
  t.is(snapshot.total, 800_000)
  await t.exception(() => budget.chargeCleanup(), /cleanup operation limit/)
})

test('completed accounting operations release fence subscriptions before the epoch ends', (t) => {
  const moduleUrl = new URL('../../packages/core/core/relay-node/storage-accounting-epoch.js', import.meta.url)
  const script = `
    import { StorageAccountingEpoch } from ${JSON.stringify(moduleUrl.href)}
    let now = 0
    const clock = {
      now: () => now,
      sleep: async ms => { now += ms },
      setTimeout: () => ({ unref () {} }),
      clearTimeout: () => {}
    }
    const epoch = new StorageAccountingEpoch('/constant-operation-probe', { clock })
    epoch.observedAt = 0
    epoch._jsSliceStartedAt = 0
    epoch._normalDeadlineAt = epoch.limits.normalDeadlineMs
    const constantOperation = async () => 1
    global.gc()
    const before = process.memoryUsage().heapUsed
    for (let i = 0; i < 100_000; i++) {
      await epoch._ordinaryOperation('constant result', constantOperation)
    }
    global.gc()
    const retainedBytes = process.memoryUsage().heapUsed - before
    console.log(JSON.stringify({ retainedBytes, operations: epoch.budget.ordinary,
      bookkeepingBytes: epoch.getProgress().bookkeepingBytes,
      operationsInFlight: epoch.getProgress().operationsInFlight,
      fence: epoch.getProgress().fence }))
    epoch._installFence('success', null, now)
  `
  const child = spawnSync(process.execPath, [
    '--expose-gc', '--max-old-space-size=128', '--input-type=module', '-e', script
  ], { encoding: 'utf8', timeout: 30_000 })
  t.absent(child.error)
  t.is(child.signal, null)
  t.is(child.status, 0, child.stderr)
  if (child.status !== 0) return
  const result = JSON.parse(child.stdout)
  t.is(result.operations, 100_000)
  t.is(result.bookkeepingBytes, 0)
  t.is(result.operationsInFlight, 0)
  t.is(result.fence, null, 'measure completed work while the shared fence is still pending')
  t.ok(result.retainedBytes < 8 * 1024 * 1024,
    `100000 constant operations retain ${result.retainedBytes} bytes, below the 8 MiB guard`)
})

test('maximum E/T tree charges exactly 700001 ordinary and one terminal operation', async (t) => {
  const clock = new FakeClock()
  const result = await runStorageAccountingEpoch('/root', {
    clock,
    fs: generatedMaximumFs()
  })

  t.ok(result.complete)
  t.is(result.bytes, 0)
  t.is(result.progress.entries, 250_000)
  t.is(result.progress.directories, 50_000)
  t.is(result.operations.ordinary, 700_001)
  t.is(result.operations.cleanup, 1)
  t.is(result.operations.total, 700_002)
  t.ok(result.durationMs < STORAGE_ACCOUNTING_EPOCH_HARD_LIMITS.normalDeadlineMs)
  t.is(result.progress.peakOperationsInFlight, 1)
  t.ok(Object.isFrozen(result))
  t.ok(Object.isFrozen(result.progress))
})

test('the 50000th yielded directory cannot become an uncounted 50001st traversal', async (t) => {
  const clock = new FakeClock()
  const result = await runStorageAccountingEpoch('/root', {
    clock,
    fs: generatedMaximumFs({ directoryEntries: 50_000, fileEntries: 0 })
  })

  t.absent(result.complete)
  t.is(result.bytes, null)
  t.is(result.progress.entries, 50_000)
  t.is(result.progress.directories, 50_000)
  t.is(result.incompleteReason, 'EACCOUNTINGDIRECTORIES')
})

test('metadata starts stay serial and at least 32ms apart', async (t) => {
  const clock = new FakeClock()
  const fixture = emptyFs(clock)
  const result = await runStorageAccountingEpoch('/root', {
    clock,
    fs: fixture.fs
  })

  t.ok(result.complete)
  t.is(result.operations.ordinary, 5)
  t.is(result.operations.cleanup, 1)
  t.is(result.progress.peakOperationsInFlight, 1)
  for (let i = 1; i < fixture.starts.length; i++) {
    t.ok(fixture.starts[i].at - fixture.starts[i - 1].at >= 32, `operation ${i} obeys the rate gap`)
  }
})

test('ten milliseconds of synchronous work yields until the next one-second slice', async (t) => {
  const clock = new FakeClock()
  const fixture = emptyFs(clock, {
    initialStatOptions: { clock, jsCost: 10 }
  })
  const result = await runStorageAccountingEpoch('/root', {
    clock,
    fs: fixture.fs
  })

  t.ok(result.complete)
  t.is(fixture.starts[0].at, 0)
  t.ok(fixture.starts[1].at >= 1000, 'the next operation waits for a fresh JS slice')
})

test('the normal deadline fences before another ordinary operation starts', async (t) => {
  const clock = new FakeClock()
  const fixture = emptyFs(clock, {
    onLstat ({ call, clock }) {
      if (call === 1) clock.consume(STORAGE_ACCOUNTING_EPOCH_HARD_LIMITS.normalDeadlineMs)
      return directoryStat(1)
    }
  })
  const result = await runStorageAccountingEpoch('/root', { clock, fs: fixture.fs })

  t.absent(result.complete)
  t.is(result.incompleteReason, 'EACCOUNTINGDEADLINE')
  t.is(result.operations.ordinary, 1)
  t.is(fixture.starts.length, 1, 'no opendir starts at or after the fence')
})

test('an unresolved metadata call returns a failed drain at cleanup expiry', async (t) => {
  const clock = new FakeClock()
  const epoch = new StorageAccountingEpoch('/root', {
    clock,
    fs: {
      lstat: async () => await new Promise(() => {}),
      opendir: async () => { throw new Error('must not open') }
    }
  })
  const running = epoch.run()
  await Promise.resolve()
  await Promise.resolve()
  clock.advance(
    STORAGE_ACCOUNTING_EPOCH_HARD_LIMITS.normalDeadlineMs +
    STORAGE_ACCOUNTING_EPOCH_HARD_LIMITS.cleanupDeadlineMs
  )
  const result = await running
  t.absent(result.complete)
  t.ok(result.failedDrain)
  t.is(result.incompleteReason, 'EACCOUNTINGDEADLINE')
  t.is(result.operations.ordinary, 1, 'the unresolved start remains charged')
  t.is(result.progress.operationsInFlight, 1, 'ownership remains visible after the bounded drain')
})

test('a directory handle returned after the stop fence is owned and closed before completion', async (t) => {
  const clock = new FakeClock()
  let releaseOpen
  let opened = 0
  let closed = 0
  const openResult = new Promise(resolve => { releaseOpen = resolve })
  const epoch = new StorageAccountingEpoch('/root', {
    clock,
    fs: {
      async lstat () { return directoryStat(1) },
      async opendir () {
        opened++
        return await openResult
      }
    }
  })

  const running = epoch.run()
  await waitFor(() => opened > 0, 'deferred directory open')
  epoch.stop()
  releaseOpen({
    async read () { return null },
    async close () { closed++ }
  })
  const result = await running

  t.is(opened, 1)
  t.is(closed, 1, 'the post-fence opendir result is disposed exactly once')
  t.absent(result.complete)
  t.is(result.incompleteReason, 'EACCOUNTINGSTOPPED')
  t.absent(result.failedDrain, 'proved late-handle disposal does not poison a successor')
  t.is(result.operations.cleanup, 1, 'late handle close consumes one cleanup operation')
  t.is(result.progress.operationsInFlight, 0)
  t.is(result.progress.unreleasedLateResources, 0)
})

test('an unsettled late directory close remains a failed drain and visible owner', async (t) => {
  const clock = new FakeClock()
  let releaseOpen
  let opened = 0
  let closeStarted = 0
  const openResult = new Promise(resolve => { releaseOpen = resolve })
  const epoch = new StorageAccountingEpoch('/root', {
    clock,
    fs: {
      async lstat () { return directoryStat(1) },
      async opendir () {
        opened++
        return await openResult
      }
    }
  })

  const running = epoch.run()
  await waitFor(() => opened > 0, 'deferred directory open')
  epoch.stop()
  releaseOpen({
    async read () { return null },
    async close () {
      closeStarted++
      return await new Promise(() => {})
    }
  })
  await waitFor(() => closeStarted > 0, 'late directory close')
  clock.advance(STORAGE_ACCOUNTING_EPOCH_HARD_LIMITS.cleanupDeadlineMs)
  const result = await running

  t.absent(result.complete)
  t.is(result.incompleteReason, 'EACCOUNTINGSTOPPED')
  t.ok(result.failedDrain, 'successor remains fenced while late disposal is unproved')
  t.is(result.operations.cleanup, 1)
  t.is(result.progress.operationsInFlight, 1)
  t.is(result.progress.unreleasedLateResources, 1)
})

test('a failed late directory disposal can never publish a complete epoch', async (t) => {
  const clock = new FakeClock()
  let releaseOpen
  let opened = 0
  const openResult = new Promise(resolve => { releaseOpen = resolve })
  const epoch = new StorageAccountingEpoch('/root', {
    clock,
    fs: {
      async lstat () { return directoryStat(1) },
      async opendir () {
        opened++
        return await openResult
      }
    }
  })

  const running = epoch.run()
  await waitFor(() => opened > 0, 'deferred directory open')
  epoch.stop()
  releaseOpen({
    async read () { return null },
    async close () {
      const err = new Error('injected late close failure')
      err.code = 'EIO'
      throw err
    }
  })
  const result = await running

  t.absent(result.complete, 'failed late-resource disposal is never complete')
  t.ok(result.failedDrain, 'failed disposal fences the successor epoch')
  t.is(result.incompleteReason, 'EIO', 'the disposal failure is the primary incomplete diagnosis')
  t.is(result.progress.unreleasedLateResources, 1)
})

test('a late successful normal close releases the real Node Dir exactly once', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'hiverelay-accounting-late-close-'))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  let releaseClose
  let signalCloseStarted
  let closeCalls = 0
  const closeGate = new Promise(resolve => { releaseClose = resolve })
  const closeStartedGate = new Promise(resolve => { signalCloseStarted = resolve })
  const epoch = new StorageAccountingEpoch(root, {
    fs: {
      lstat,
      async opendir (path, options) {
        const dir = await opendir(path, options)
        return {
          read: () => dir.read(),
          async close () {
            closeCalls++
            signalCloseStarted()
            await closeGate
            return dir.close()
          }
        }
      }
    }
  })

  const running = epoch.run()
  await closeStartedGate
  epoch.stop()
  releaseClose()
  const result = await running

  t.is(closeCalls, 1, 'the underlying Node Dir receives one close total')
  t.is(result.operations.cleanup, 0, 'cleanup never issues a duplicate close')
  t.is(result.progress.openDirectories, 0, 'late success releases the exact owned frame')
  t.absent(result.failedDrain, 'proved close settlement leaves no owner debt')
})

test('late-result pacing cannot start a close after crossing the cleanup deadline', async (t) => {
  const clock = new FakeClock()
  let releaseOpen
  let opened = 0
  let closed = 0
  const openResult = new Promise(resolve => { releaseOpen = resolve })
  const epoch = new StorageAccountingEpoch('/root', {
    clock,
    fs: {
      async lstat () { return directoryStat(1) },
      async opendir () {
        opened++
        return await openResult
      }
    }
  })

  const running = epoch.run()
  await waitFor(() => opened > 0, 'deferred directory open')
  epoch.stop()
  clock.advance(STORAGE_ACCOUNTING_EPOCH_HARD_LIMITS.cleanupDeadlineMs - 1)
  // Force the accepted 32/s pacing rule to cross the hard cleanup fence.
  epoch._lastOperationStartedAt = clock.now()
  releaseOpen({
    async read () { return null },
    async close () { closed++ }
  })
  const result = await running

  t.is(closed, 0, 'no filesystem operation starts beyond the cleanup deadline')
  t.ok(result.failedDrain)
  t.is(result.operations.cleanup, 0, 'an operation that cannot start is not charged')
  t.is(result.progress.unreleasedLateResources, 1)
})

test('success fenced before eight hours may finish terminal cleanup after eight hours', async (t) => {
  const clock = new FakeClock()
  const normalDeadline = STORAGE_ACCOUNTING_EPOCH_HARD_LIMITS.normalDeadlineMs
  const fixture = emptyFs(clock, {
    async onClose ({ clock }) {
      clock.consume(normalDeadline - 1 - clock.now())
    },
    onLstat ({ call, clock }) {
      if (call === 3) clock.consume(2)
      return directoryStat(1)
    }
  })
  const result = await runStorageAccountingEpoch('/root', { clock, fs: fixture.fs })

  t.ok(result.complete)
  t.ok(result.completedAt > result.observedAt + normalDeadline)
  t.ok(result.completedAt <= result.observedAt + normalDeadline + STORAGE_ACCOUNTING_EPOCH_HARD_LIMITS.cleanupDeadlineMs)
  t.is(result.operations.cleanup, 1)
})

test('terminal cleanup settling after fifteen minutes never publishes a sample', async (t) => {
  const clock = new FakeClock()
  const cleanupDeadline = STORAGE_ACCOUNTING_EPOCH_HARD_LIMITS.cleanupDeadlineMs
  const fixture = emptyFs(clock, {
    onLstat ({ call, clock }) {
      if (call === 3) clock.consume(cleanupDeadline + 1)
      return directoryStat(1)
    }
  })
  const result = await runStorageAccountingEpoch('/root', { clock, fs: fixture.fs })

  t.absent(result.complete)
  t.is(result.bytes, null)
  t.is(result.incompleteReason, 'EACCOUNTINGCLEANUPDEADLINE')
  t.ok(result.failedDrain)
  t.is(result.operations.cleanup, 1, 'the timed-out terminal check still consumes its token')
})

test('failure cleanup uses all 64 first closes and at most one retry each', async (t) => {
  const clock = new FakeClock()
  const fixture = nestedFailureFs(64)
  const result = await runStorageAccountingEpoch('/root', {
    clock,
    fs: fixture.fs,
    canRetryClose: () => true
  })

  t.absent(result.complete)
  t.is(result.incompleteReason, 'EIO')
  t.is(result.progress.peakOpenDirectories, 64)
  t.is(result.operations.cleanup, 128)
  t.absent(result.failedDrain, 'all handles proved closed on their one permitted retry')
  t.is([...fixture.closeCalls.values()].reduce((sum, calls) => sum + calls, 0), 128)
  for (const calls of fixture.closeCalls.values()) t.is(calls, 2)
})

test('a second post-fence close failure is a failed drain with no free retry', async (t) => {
  const clock = new FakeClock()
  const fixture = nestedFailureFs(1, 'always-fail')
  const result = await runStorageAccountingEpoch('/root', {
    clock,
    fs: fixture.fs,
    canRetryClose: () => true
  })

  t.absent(result.complete)
  t.ok(result.failedDrain)
  t.is(result.progress.openDirectories, 1)
  t.is(result.operations.cleanup, 2)
  t.is([...fixture.closeCalls.values()][0], 2)
})

test('symlink, cross-device, identity swap, and integer overflow publish no bytes', async (t) => {
  const cases = [
    {
      reason: 'ESTORAGESYMLINK',
      makeFs: () => ({
        lstat: async () => symlinkStat(1),
        opendir: async () => { throw new Error('must not open') }
      })
    },
    {
      reason: 'EXDEV',
      makeFs: () => singleEntryFs(fileStat(2, { dev: 2 }))
    },
    {
      reason: 'ESTORAGEIDENTITY',
      makeFs: clock => emptyFs(clock, {
        onLstat ({ call }) { return directoryStat(call === 1 ? 1 : 2) }
      }).fs
    },
    {
      reason: 'EACCOUNTINGINTEGER',
      makeFs: () => singleEntryFs(fileStat(2, { blocks: Number.MAX_SAFE_INTEGER }))
    }
  ]

  for (const fixture of cases) {
    const clock = new FakeClock()
    const result = await runStorageAccountingEpoch('/root', { clock, fs: fixture.makeFs(clock) })
    t.absent(result.complete)
    t.is(result.bytes, null)
    t.is(result.incompleteReason, fixture.reason)
  }
})

test('path, depth, queue, and bookkeeping caps fail closed', async (t) => {
  const pathClock = new FakeClock()
  const tooLong = await runStorageAccountingEpoch('/root', {
    clock: pathClock,
    fs: emptyFs(pathClock).fs,
    limits: { maxPathBytes: 2 }
  })
  t.is(tooLong.incompleteReason, 'EACCOUNTINGPATH')

  const depthClock = new FakeClock()
  const depthFixture = nestedFailureFs(3)
  const depth = await runStorageAccountingEpoch('/root', {
    clock: depthClock,
    fs: depthFixture.fs,
    limits: { maxDepth: 1 }
  })
  t.is(depth.incompleteReason, 'EACCOUNTINGDEPTH')

  const queueClock = new FakeClock()
  const queue = await runStorageAccountingEpoch('/root', {
    clock: queueClock,
    fs: singleEntryFs(directoryStat(2)),
    limits: { maxOpenDirectories: 1, maxQueuedPathBytes: 1 }
  })
  t.is(queue.incompleteReason, 'EACCOUNTINGQUEUE')

  const bookkeepingClock = new FakeClock()
  const bookkeeping = await runStorageAccountingEpoch('/root', {
    clock: bookkeepingClock,
    fs: emptyFs(bookkeepingClock).fs,
    limits: { maxBookkeepingBytes: 1 }
  })
  t.is(bookkeeping.incompleteReason, 'EACCOUNTINGBOOKKEEPING')
})

test('run and stop are idempotent and a stopped epoch cannot publish', async (t) => {
  const clock = new FakeClock()
  const fixture = emptyFs(clock)
  const epoch = new StorageAccountingEpoch('/root', { clock, fs: fixture.fs })
  const first = epoch.stop()
  const second = epoch.stop()
  t.is(first, second)
  const result = await first
  t.absent(result.complete)
  t.is(result.incompleteReason, 'EACCOUNTINGSTOPPED')
  t.is(result.operations.total, 0)
})

function singleEntryFs (entryStat) {
  let read = false
  return {
    async lstat (path) {
      return path === '/root' ? directoryStat(1) : entryStat
    },
    async opendir () {
      return {
        async read () {
          if (!read) {
            read = true
            return { name: 'entry' }
          }
          return null
        },
        async close () {}
      }
    }
  }
}
