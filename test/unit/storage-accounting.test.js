/**
 * StorageAccounting must report the REAL on-disk corestore footprint, not the
 * per-entry drive walk. On a registry-driven relay most entries are bare seeded
 * cores or lazily-unloaded drives with no live `entry.drive`, so the per-entry
 * walk measured ~0 while the disk held 19 GB — and the adoption guard
 * (maxStorageBytes - used) never bound, filling disks to 100% (sing-1, 2026-06).
 *
 * It must also count ALLOCATED blocks, not apparent size: relay block files are
 * sparse (partial replicas have holes), so st.size overcounts badly.
 */
import test from 'brittle'
import { mkdtemp, writeFile, mkdir, rm, open, chmod } from 'fs/promises'
import { join } from 'path'
import { tmpdir } from 'os'
import { StorageAccounting, dirBytes } from 'p2p-hiverelay/core/relay-node/storage-accounting.js'

// Block-aligned (multiples of 4096) so allocated bytes == apparent on the 4K-block
// filesystems CI (ext4) and dev (APFS) use.
async function tmpTree () {
  const dir = await mkdtemp(join(tmpdir(), 'hr-acct-'))
  await writeFile(join(dir, 'a.bin'), Buffer.alloc(4096))
  await mkdir(join(dir, 'cores'))
  await writeFile(join(dir, 'cores', 'b.bin'), Buffer.alloc(8192))
  await mkdir(join(dir, 'cores', 'sub'))
  await writeFile(join(dir, 'cores', 'sub', 'c.bin'), Buffer.alloc(12288))
  return { dir, apparent: 4096 + 8192 + 12288 } // 24576
}

function deferredEpoch () {
  let settle
  const promise = new Promise(resolve => { settle = resolve })
  let stops = 0
  return {
    run: () => promise,
    stop: () => { stops++; return promise },
    settle,
    get stops () { return stops },
    getProgress: () => ({ state: 'running' })
  }
}

function completeEpochResult (bytes, observedAt = 1_000, completedAt = 2_000) {
  return {
    complete: true,
    bytes,
    observedAt,
    completedAt,
    durationMs: completedAt - observedAt,
    incompleteReason: null,
    progress: { state: 'complete' },
    operations: { ordinary: 1, cleanup: 1, total: 2 }
  }
}

test('dirBytes sums nested allocated bytes; safe on missing/null', async (t) => {
  const { dir, apparent } = await tmpTree()
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  t.is(await dirBytes(dir), apparent, 'recursive sum of allocated bytes (aligned files)')
  t.is(await dirBytes(join(dir, 'does-not-exist')), 0, 'missing dir -> 0')
  t.is(await dirBytes(null), 0, 'null -> 0')
})

test('dirBytes counts ALLOCATED blocks, not apparent size (sparse files)', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'hr-sparse-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  // 1 MB apparent, but a pure hole — ~0 blocks actually allocated.
  const fh = await open(join(dir, 'sparse.bin'), 'w')
  await fh.truncate(1024 * 1024)
  await fh.close()
  const measured = await dirBytes(dir)
  t.ok(measured < 64 * 1024, 'sparse 1 MB file counts ~0 on disk, not its apparent length (got ' + measured + ')')
})

test('getSummary reports real disk bytes when the per-entry walk is blind (the bug)', async (t) => {
  const { dir, apparent } = await tmpTree()
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const appRegistry = { keys: () => ['aa', 'bb', 'cc'], get: () => ({ drive: null }) }
  const acct = new StorageAccounting({ appRegistry, storagePath: dir })
  await acct.measureDisk()
  const s = acct.getSummary()
  t.is(s.perEntryBytes, 0, 'per-entry walk sees nothing — the original failure')
  t.is(s.diskBytes, apparent, 'disk footprint measured')
  t.is(s.totalBytes, apparent, 'authoritative total = real disk footprint (guard now binds)')
  t.ok(Number.isSafeInteger(s.diskMeasuredAt), 'summary timestamps the whole-tree measurement')
  t.ok(s.diskMeasurementComplete, 'successful traversal is marked complete')
})

test('getSummary prefers the disk footprint over a smaller per-entry sum', async (t) => {
  const { dir, apparent } = await tmpTree()
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const acct = new StorageAccounting({ appRegistry: { keys: () => [], get: () => null }, storagePath: dir })
  acct._bytes.set('x', { bytes: 10, measuredAt: 1 }) // stale/partial undercount
  await acct.measureDisk()
  t.is(acct.getSummary().totalBytes, apparent, 'disk wins over the 10-byte per-entry undercount')
})

test('no storagePath -> falls back to the per-entry sum (back-compat)', (t) => {
  const acct = new StorageAccounting({ appRegistry: { keys: () => [], get: () => null } })
  acct._bytes.set('x', { bytes: 42, measuredAt: 1 })
  const s = acct.getSummary()
  t.is(s.diskBytes, null, 'no disk measurement attempted')
  t.is(s.diskMeasuredAt, null, 'missing measurement has no freshness timestamp')
  t.absent(s.diskMeasurementComplete)
  t.is(s.totalBytes, 42, 'per-entry sum used when no storagePath configured')
})

test('an unreadable or missing root never becomes complete capacity evidence', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'hr-missing-root-'))
  await rm(dir, { recursive: true, force: true })
  const acct = new StorageAccounting({ appRegistry: { keys: () => [], get: () => null }, storagePath: dir })

  await t.exception(acct.measureDisk(), /epoch was incomplete/)
  const summary = acct.getSummary()
  t.absent(summary.diskMeasurementComplete, 'failed root traversal is explicit')
  t.is(summary.diskMeasuredAt, null, 'an incomplete attempt never publishes a sample timestamp')
  t.is(summary.diskIncompleteReason, 'ENOENT', 'the bounded failure reason remains observable')
})

test('measureDisk is latched and returns the measured value', async (t) => {
  const { dir, apparent } = await tmpTree()
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const acct = new StorageAccounting({ appRegistry: { keys: () => [], get: () => null }, storagePath: dir })
  const [a, b] = await Promise.all([acct.measureDisk(), acct.measureDisk()])
  t.is(a, apparent)
  t.is(b, apparent, 'concurrent callers attach to the same epoch')
})

test('a file deleted mid-walk does not make the measurement incomplete', async (t) => {
  // Corestore deletes files constantly (compaction, truncation, unseed), so a
  // readdir/stat race is the steady state on a busy relay — not an anomaly.
  // Treating it as incomplete evidence fail-closed the entire capacity surface.
  const { dir } = await tmpTree()
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  let acct = new StorageAccounting({ appRegistry: { keys: () => [], get: () => null }, storagePath: dir })

  const vanishing = join(dir, 'cores', 'sub', 'c.bin')
  const missingDir = join(dir, 'cores', 'sub')
  await rm(vanishing)
  await acct.measureDisk()
  let summary = acct.getSummary()
  t.ok(summary.diskMeasurementComplete, 'a vanished file contributes zero bytes, so the total stays exact')
  t.is(summary.diskBytes, 4096 + 8192)

  await rm(missingDir, { recursive: true, force: true })
  acct = new StorageAccounting({ appRegistry: { keys: () => [], get: () => null }, storagePath: dir })
  await acct.measureDisk()
  summary = acct.getSummary()
  t.ok(summary.diskMeasurementComplete, 'a vanished subdirectory is the same benign race')
  t.is(summary.diskBytes, 4096 + 8192)
})

test('an unreadable subtree still fails the completeness claim', async (t) => {
  const { dir } = await tmpTree()
  t.teardown(async () => {
    await chmod(join(dir, 'cores'), 0o755).catch(() => {})
    await rm(dir, { recursive: true, force: true })
  })
  const acct = new StorageAccounting({ appRegistry: { keys: () => [], get: () => null }, storagePath: dir })

  await chmod(join(dir, 'cores'), 0o000)
  let denied = null
  try {
    await acct.measureDisk()
  } catch (err) {
    denied = err
  }
  const summary = acct.getSummary()
  if (summary.diskBytes === 4096 + 8192 + 12288) {
    t.pass('running as a user that bypasses directory permissions; race coverage is unaffected')
    return
  }
  t.is(denied?.code, 'STORAGE_ACCOUNTING_INCOMPLETE')
  t.absent(summary.diskMeasurementComplete, 'hidden bytes are never reported as complete evidence')
})

test('measurement duration is observable so consumers can size a freshness window', async (t) => {
  const { dir } = await tmpTree()
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const acct = new StorageAccounting({
    appRegistry: { keys: () => [], get: () => null },
    storagePath: dir,
    diskIntervalMs: 90_000
  })

  t.is(acct.getSummary().diskMeasureDurationMs, null, 'no duration before the first walk')
  await acct.measureDisk()
  const summary = acct.getSummary()
  t.ok(Number.isSafeInteger(summary.diskMeasureDurationMs) && summary.diskMeasureDurationMs >= 0)
  t.is(summary.diskIntervalMs, 33 * 60 * 1000, 'the frozen completion cadence travels with the sample')
})

test('measureDisk coalesces one epoch, caps waiters, and does not bypass the completion gap', async (t) => {
  const epoch = deferredEpoch()
  let starts = 0
  const acct = new StorageAccounting({
    appRegistry: { keys: () => [], get: () => null },
    storagePath: '/fake',
    now: () => 2_000,
    random: () => 0,
    epochFactory: () => { starts++; return epoch }
  })
  const waiters = []
  for (let i = 0; i < 32; i++) waiters.push(acct.measureDisk({ timeoutMs: 30_000 }))
  await t.exception(acct.measureDisk({ timeoutMs: 30_000 }), /waiter limit/)
  t.is(starts, 1, 'all accepted waiters share one epoch')
  epoch.settle(completeEpochResult(42))
  t.alike(await Promise.all(waiters), new Array(32).fill(42))

  await t.exception(acct.measureDisk({ timeoutMs: 10 }), /deadline elapsed/)
  t.is(starts, 1, 'a manual trigger cannot launch inside the 30m+jitter gap')
})

test('a failed epoch retains but invalidates the last complete sample', async (t) => {
  let now = 0
  const epochs = [deferredEpoch(), deferredEpoch()]
  let starts = 0
  const acct = new StorageAccounting({
    appRegistry: { keys: () => [], get: () => null },
    storagePath: '/fake',
    now: () => now,
    random: () => 0,
    epochFactory: () => epochs[starts++]
  })
  const first = acct.measureDisk({ timeoutMs: 30_000 })
  epochs[0].settle(completeEpochResult(77, 100, 200))
  t.is(await first, 77)
  now = 2_000_000
  const second = acct.measureDisk({ timeoutMs: 30_000 })
  epochs[1].settle({
    complete: false,
    bytes: null,
    observedAt: now,
    completedAt: null,
    finishedAt: now + 1,
    incompleteReason: 'EIO',
    error: { code: 'EIO', message: 'injected' },
    progress: { state: 'incomplete' },
    operations: { ordinary: 1, cleanup: 0, total: 1 },
    failedDrain: false
  })
  await t.exception(second, /epoch was incomplete/)
  const summary = acct.getSummary()
  t.is(summary.diskBytes, 77, 'last complete bytes remain atomic and private from partial work')
  t.is(summary.diskObservedAt, 100)
  t.is(summary.diskCompletedAt, 200)
  t.absent(summary.diskMeasurementComplete, 'latest failure blocks capacity and receipts')
  t.is(summary.diskIncompleteReason, 'EIO')
})

test('stop is idempotent and drains the active accounting epoch', async (t) => {
  const epoch = deferredEpoch()
  const acct = new StorageAccounting({
    appRegistry: { keys: () => [], get: () => null },
    storagePath: '/fake',
    epochFactory: () => epoch
  })
  const waiter = acct.measureDisk({ timeoutMs: 30_000 })
  const a = acct.stop()
  const b = acct.stop()
  t.is(a, b, 'duplicate stop returns the same drain promise')
  await t.exception(waiter, /stopped/)
  epoch.settle({
    complete: false,
    bytes: null,
    observedAt: 1,
    completedAt: null,
    finishedAt: 2,
    incompleteReason: 'stopped',
    error: { code: 'ESTOPPED', message: 'stopped' },
    progress: { state: 'incomplete' },
    operations: { ordinary: 1, cleanup: 1, total: 2 },
    failedDrain: false
  })
  await a
  t.is(epoch.stops, 1, 'active epoch stop/drain is invoked once')
})
