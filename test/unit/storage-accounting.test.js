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
import { mkdtemp, writeFile, mkdir, rm, open } from 'fs/promises'
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

  t.is(await acct.measureDisk(), 0, 'best-effort dashboard count remains backward compatible')
  const summary = acct.getSummary()
  t.absent(summary.diskMeasurementComplete, 'failed root traversal is explicit')
  t.ok(Number.isSafeInteger(summary.diskMeasuredAt), 'failed scan time remains observable')
})

test('measureDisk is latched and returns the measured value', async (t) => {
  const { dir, apparent } = await tmpTree()
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const acct = new StorageAccounting({ appRegistry: { keys: () => [], get: () => null }, storagePath: dir })
  const [a, b] = await Promise.all([acct.measureDisk(), acct.measureDisk()])
  t.ok(a === apparent || b === apparent, 'at least one concurrent call returns the measured total')
})
