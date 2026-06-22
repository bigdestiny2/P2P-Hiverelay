/**
 * StorageAccounting must report the REAL on-disk corestore footprint, not just
 * the per-entry drive walk. On a registry-driven relay most entries are bare
 * seeded cores or lazily-unloaded drives with no live `entry.drive`, so the
 * per-entry walk measured ~0 while the disk held 19 GB — and the adoption guard
 * (maxStorageBytes - used) never bound, filling disks to 100% (sing-1, 2026-06).
 */
import test from 'brittle'
import { mkdtemp, writeFile, mkdir, rm } from 'fs/promises'
import { join } from 'path'
import { tmpdir } from 'os'
import { StorageAccounting, dirBytes } from 'p2p-hiverelay/core/relay-node/storage-accounting.js'

async function tmpTree () {
  const dir = await mkdtemp(join(tmpdir(), 'hr-acct-'))
  await writeFile(join(dir, 'a.bin'), Buffer.alloc(1000))
  await mkdir(join(dir, 'cores'))
  await writeFile(join(dir, 'cores', 'b.bin'), Buffer.alloc(2000))
  await mkdir(join(dir, 'cores', 'sub'))
  await writeFile(join(dir, 'cores', 'sub', 'c.bin'), Buffer.alloc(3000))
  return dir // 6000 bytes total, nested
}

test('dirBytes sums nested file bytes; safe on missing/null', async (t) => {
  const dir = await tmpTree()
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  t.is(await dirBytes(dir), 6000, 'recursive sum of all files')
  t.is(await dirBytes(join(dir, 'does-not-exist')), 0, 'missing dir -> 0')
  t.is(await dirBytes(null), 0, 'null -> 0')
})

test('getSummary reports real disk bytes when the per-entry walk is blind (the bug)', async (t) => {
  const dir = await tmpTree()
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  // Every registry entry is a bare/lazy core: no measurable .drive.
  const appRegistry = { keys: () => ['aa', 'bb', 'cc'], get: () => ({ drive: null }) }
  const acct = new StorageAccounting({ appRegistry, storagePath: dir })
  await acct.measureDisk()
  const s = acct.getSummary()
  t.is(s.perEntryBytes, 0, 'per-entry walk sees nothing — the original failure')
  t.is(s.diskBytes, 6000, 'disk footprint measured')
  t.is(s.totalBytes, 6000, 'authoritative total = real disk footprint (guard now binds)')
})

test('getSummary prefers the disk footprint over a smaller per-entry sum', async (t) => {
  const dir = await tmpTree()
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const acct = new StorageAccounting({ appRegistry: { keys: () => [], get: () => null }, storagePath: dir })
  acct._bytes.set('x', { bytes: 10, measuredAt: 1 }) // stale/partial undercount
  await acct.measureDisk()
  t.is(acct.getSummary().totalBytes, 6000, 'disk (6000) wins over the 10-byte per-entry undercount')
})

test('no storagePath -> falls back to the per-entry sum (back-compat)', (t) => {
  const acct = new StorageAccounting({ appRegistry: { keys: () => [], get: () => null } })
  acct._bytes.set('x', { bytes: 42, measuredAt: 1 })
  const s = acct.getSummary()
  t.is(s.diskBytes, null, 'no disk measurement attempted')
  t.is(s.totalBytes, 42, 'per-entry sum used when no storagePath configured')
})

test('measureDisk is latched (no piling up) and returns the measured value', async (t) => {
  const dir = await tmpTree()
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const acct = new StorageAccounting({ appRegistry: { keys: () => [], get: () => null }, storagePath: dir })
  const [a, b] = await Promise.all([acct.measureDisk(), acct.measureDisk()])
  // one of the concurrent calls is short-circuited by the latch; both resolve
  t.ok(a === 6000 || b === 6000, 'at least one returns the measured total')
})
