import b4a from 'b4a'
import test from 'brittle'
import { mkdir, mkdtemp, readFile, rm, unlink, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import {
  BLIND_STORE_READER_MODE,
  createBlindStoreMigrationPlan,
  executeBlindStoreMigration,
  openBlindStoreGenerationFloor
} from '../storage-generation-v12.js'
import { deriveBlindVirtualBucket } from '../virtual-bucket.js'
import { blake2b256 } from '@hiverelay/blind-protocol'

const MANIFEST_KEY = b4a.alloc(32, 0xa1)
const STORE_IDENTITY = b4a.from('authenticated-runtime-store-binding')

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

  const options = { manifestKey: MANIFEST_KEY, storeIdentity: STORE_IDENTITY, allowCreate: true }
  const initial = await openBlindStoreGenerationFloor(root, options)
  t.is(initial.firstBlindOnlyWriteAcknowledged, false)
  t.ok(initial.assertReaderMode(BLIND_STORE_READER_MODE.LEGACY_ONLY))
  t.is(await initial.acknowledgeBlindOnlyWrite(), true)
  t.is(await initial.acknowledgeBlindOnlyWrite(), false)

  const restarted = await openBlindStoreGenerationFloor(root, { ...options, allowCreate: false })
  t.is(restarted.firstBlindOnlyWriteAcknowledged, true)
  t.exception(() => restarted.assertReaderMode(BLIND_STORE_READER_MODE.LEGACY_ONLY), /D7 rollback floor/)
  t.ok(restarted.assertReaderMode(BLIND_STORE_READER_MODE.BLIND_PLUS_LEGACY))
  t.ok(restarted.assertReaderMode(BLIND_STORE_READER_MODE.BLIND_ONLY))

  const marker = path.join(root, 'blind-store-generation-floor-v1.json')
  const original = await readFile(marker)
  const tampered = JSON.parse(original)
  tampered.firstBlindOnlyWriteAcknowledged = false
  await writeFile(marker, JSON.stringify(tampered))
  await t.exception.all(() => openBlindStoreGenerationFloor(root, { ...options, allowCreate: false }), /invalid/)
  await writeFile(marker, original)
  await unlink(marker)
  await t.exception.all(() => openBlindStoreGenerationFloor(root, { ...options, allowCreate: false }), /missing/)
})

test('migration copy/hash/commit/finalize resumes after every crash boundary and preserves legacy', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'blind-store-migration-'))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const legacyPath = path.join(root, 'legacy', 'body')
  const targetPath = path.join(root, 'public', 'body')
  const body = b4a.from('opaque legacy body')
  await mkdir(path.dirname(legacyPath), { recursive: true })
  await writeFile(legacyPath, body)
  const input = {
    serviceTag: 2,
    primaryLocator: b4a.alloc(32, 7),
    legacyVirtualBucket: 9,
    objectHash: blake2b256(body),
    byteLength: body.byteLength
  }
  const plan = createBlindStoreMigrationPlan([input])
  for (const crashAt of ['inventory', 'copy', 'hash-verify', 'commit']) {
    let crashed = false
    await t.exception.all(() => executeBlindStoreMigration({
      root,
      plan,
      manifestKey: MANIFEST_KEY,
      storeIdentity: STORE_IDENTITY,
      files: [{ legacyPath, targetPath, objectHashHex: b4a.toString(input.objectHash, 'hex'), byteLength: body.byteLength }],
      faultInjector (phase) { if (!crashed && phase === crashAt) { crashed = true; throw new Error(`crash:${phase}`) } }
    }), new RegExp(`crash:${crashAt}`))
  }
  const result = await executeBlindStoreMigration({
    root,
    plan,
    manifestKey: MANIFEST_KEY,
    storeIdentity: STORE_IDENTITY,
    files: [{ legacyPath, targetPath, objectHashHex: b4a.toString(input.objectHash, 'hex'), byteLength: body.byteLength }]
  })
  t.is(result.phase, 'finalize')
  t.is(result.legacySourcesPreserved, true)
  t.alike(await readFile(legacyPath), body)
  t.alike(await readFile(targetPath), body)
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
