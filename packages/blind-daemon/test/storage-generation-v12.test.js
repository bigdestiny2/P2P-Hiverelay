import b4a from 'b4a'
import test from 'brittle'
import { mkdtemp, rm } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import {
  BLIND_STORE_READER_MODE,
  createBlindStoreMigrationPlan,
  openBlindStoreGenerationFloor
} from '../storage-generation-v12.js'
import { deriveBlindVirtualBucket } from '../virtual-bucket.js'

test('1.2 migration plan replaces keyed buckets with deterministic public buckets', t => {
  const locator = b4a.alloc(32, 0x44)
  const plan = createBlindStoreMigrationPlan([{
    serviceTag: 2,
    primaryLocator: locator,
    legacyVirtualBucket: 0x1234,
    objectHash: b4a.alloc(32, 0x55),
    byteLength: 4096
  }])
  t.is(plan.fromFormatVersion, '1.1')
  t.is(plan.toFormatVersion, '1.2')
  t.is(plan.copyVerifyBeforeCommit, true)
  t.is(plan.entries[0].publicVirtualBucket, deriveBlindVirtualBucket(2, locator))
  t.is(plan.entries[0].legacyVirtualBucket, 0x1234)
  t.is(plan.planHashHex.length, 64)
  t.exception(() => createBlindStoreMigrationPlan([planInput(locator), planInput(locator)]), /duplicate migration locator/)
})

test('D7 rollback floor survives restart and rejects legacy-only recovery', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'blind-store-generation-'))
  t.teardown(() => rm(root, { recursive: true, force: true }))

  const initial = await openBlindStoreGenerationFloor(root)
  t.is(initial.firstBlindOnlyWriteAcknowledged, false)
  t.ok(initial.assertReaderMode(BLIND_STORE_READER_MODE.LEGACY_ONLY))
  t.is(await initial.acknowledgeBlindOnlyWrite(), true)
  t.is(await initial.acknowledgeBlindOnlyWrite(), false)

  const restarted = await openBlindStoreGenerationFloor(root)
  t.is(restarted.firstBlindOnlyWriteAcknowledged, true)
  t.exception(() => restarted.assertReaderMode(BLIND_STORE_READER_MODE.LEGACY_ONLY), /D7 rollback floor/)
  t.ok(restarted.assertReaderMode(BLIND_STORE_READER_MODE.BLIND_PLUS_LEGACY))
  t.ok(restarted.assertReaderMode(BLIND_STORE_READER_MODE.BLIND_ONLY))
})

function planInput (locator) {
  return {
    serviceTag: 2,
    primaryLocator: locator,
    legacyVirtualBucket: 1,
    objectHash: b4a.alloc(32, 0x55),
    byteLength: 1
  }
}
