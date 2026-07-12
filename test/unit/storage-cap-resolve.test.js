import test from 'brittle'
import { resolveStorageCap } from '../../packages/core/config/loader.js'
import defaults from '../../packages/core/config/default.js'

const GiB = 1024 ** 3
// statfsSync-shaped mock: blocks*bsize = total volume bytes.
const mockStatfs = (totalBytes) => () => ({ blocks: totalBytes, bsize: 1 })
// '/' always exists, so existingAncestor() resolves; the mocked statfs makes
// the actual path irrelevant to the numbers.
const storagePath = '/'

test('resolveStorageCap: an unset cap scales to 75% of the disk (not the fixed 50 GB)', (t) => {
  const cfg = { maxStorageBytes: defaults.maxStorageBytes, storage: storagePath }
  resolveStorageCap(cfg, { statfs: mockStatfs(100 * GiB), storagePath })
  t.is(cfg.maxStorageBytes, Math.floor(100 * GiB * 0.75), 'unset → 75% of the volume')
  t.absent(cfg._maxStorageBytesClampedFrom, 'no clamp marker when scaling a default')
})

test('resolveStorageCap: a small disk is protected — 58 GB box no longer defaults to a 50 GB cap', (t) => {
  const cfg = { maxStorageBytes: defaults.maxStorageBytes, storage: storagePath }
  resolveStorageCap(cfg, { statfs: mockStatfs(58 * GiB), storagePath })
  t.is(cfg.maxStorageBytes, Math.floor(58 * GiB * 0.75), '58 GB box caps at ~43.5 GiB, leaving real headroom')
  t.ok(cfg.maxStorageBytes < defaults.maxStorageBytes, 'strictly smaller than the old 50 GB default')
})

test('resolveStorageCap: an explicit cap over 90% of disk is clamped down', (t) => {
  const cfg = { maxStorageBytes: 200 * GiB, storage: storagePath }
  resolveStorageCap(cfg, { statfs: mockStatfs(100 * GiB), storagePath })
  t.is(cfg.maxStorageBytes, Math.floor(100 * GiB * 0.90), 'clamped to 90% ceiling')
  t.is(cfg._maxStorageBytesClampedFrom, 200 * GiB, 'records the original for the CLI warning')
})

test('resolveStorageCap: an explicit cap under the ceiling is respected untouched', (t) => {
  const cfg = { maxStorageBytes: 40 * GiB, storage: storagePath }
  resolveStorageCap(cfg, { statfs: mockStatfs(100 * GiB), storagePath })
  t.is(cfg.maxStorageBytes, 40 * GiB, 'operator value kept')
  t.absent(cfg._maxStorageBytesClampedFrom, 'no clamp marker')
})

test('resolveStorageCap: an unmeasurable disk leaves the cap unchanged (safe fallback)', (t) => {
  const cfg = { maxStorageBytes: defaults.maxStorageBytes, storage: storagePath }
  resolveStorageCap(cfg, { statfs: () => { throw new Error('statfs unavailable') }, storagePath })
  t.is(cfg.maxStorageBytes, defaults.maxStorageBytes, 'never makes the cap worse than the merged value')
})

test('resolveStorageCap: a zero-size statfs is ignored', (t) => {
  const cfg = { maxStorageBytes: 40 * GiB, storage: storagePath }
  resolveStorageCap(cfg, { statfs: () => ({ blocks: 0, bsize: 4096 }), storagePath })
  t.is(cfg.maxStorageBytes, 40 * GiB, 'unchanged when total resolves to 0')
})
