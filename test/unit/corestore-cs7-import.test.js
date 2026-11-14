import test from 'brittle'
import Corestore from 'corestore'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, unlinkSync, writeFileSync } from 'fs'
import { rm } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import {
  corestoreGenerationOpenOptions,
  corestoreGenerationStatus,
  importLegacyCorestoreCopyIntoEnvelope,
  importRawCs7CorestoreCopyIntoEnvelope,
  initializeCorestoreGenerationEnvelope,
  inventoryCorestoreGenerationTree,
  openCorestore
} from '../../packages/core/core/persistence/storage-root-restore.js'

async function fixture (t, sidecars = ['relay-identity.json']) {
  const base = realpathSync(mkdtempSync(join(tmpdir(), 'corestore-cs7-import-')))
  chmodSync(base, 0o700)
  t.teardown(() => rm(base, { recursive: true, force: true }))
  const source = join(base, 'source')
  const target = join(base, 'target')
  mkdirSync(source, { mode: 0o700 })
  mkdirSync(target, { mode: 0o700 })
  const original = new Corestore(source)
  const core = original.get({ name: 'retained-history', valueEncoding: 'utf8' })
  await core.ready()
  await core.append(['one', 'two'])
  const key = core.key.toString('hex')
  await original.close()
  writeFileSync(join(source, 'relay-identity.json'), '{"fixture":"unchanged-identity"}\n', { mode: 0o600 })
  const ceremony = initializeCorestoreGenerationEnvelope(target, { participants: ['test-runtime'], topLevelSidecars: sidecars })
  const args = { sourceRoot: source, envelopeRoot: target, ceremony }
  const options = { hiverelayGeneration: corestoreGenerationOpenOptions(ceremony, { participant: 'test-runtime' }) }
  return { source, target, key, args, options }
}

test('raw CS7 importer preserves all portable bytes and identity with an explicit fresh device marker', async t => {
  const { source, target, key, args, options } = await fixture(t)
  const before = inventoryCorestoreGenerationTree(source).contentSha256
  const marker = readFileSync(join(source, 'CORESTORE'))
  t.exception(() => importLegacyCorestoreCopyIntoEnvelope(args), /legacy CS6/)
  const receipt = await importRawCs7CorestoreCopyIntoEnvelope(args)
  t.is(receipt.schema, 'hiverelay-corestore-cs7-import-receipt-v1')
  t.is(receipt.exactCopyVerified, undefined, 'does not claim the inode marker was copied')
  t.is(receipt.exactPortablePayloadCopyVerified, true)
  t.is(receipt.sourceDeviceMarker.path, 'CORESTORE')
  t.is(existsSync(join(target, 'generations/hc11-v1/CORESTORE')), false)
  t.is((await importRawCs7CorestoreCopyIntoEnvelope(args)).receiptSha256, receipt.receiptSha256)
  t.alike(readFileSync(join(target, 'relay-identity.json')), readFileSync(join(source, 'relay-identity.json')))
  const store = openCorestore(target, options)
  await store.ready()
  const core = store.get({ name: 'retained-history', valueEncoding: 'utf8' })
  await core.ready()
  t.is(core.key.toString('hex'), key)
  t.is(await core.get(0), 'one')
  t.is(await core.get(1), 'two')
  await core.append('three')
  const status = corestoreGenerationStatus(store)
  t.is(status.receipt.verifiedReaderState, 'imported-raw-cs7-hc11')
  t.is(status.receipt.pearMigrateCandidateWriterMode, null)
  await store.close()
  t.not(readFileSync(join(target, 'generations/hc11-v1/CORESTORE')).toString(), marker.toString())
  const reopened = openCorestore(target, options)
  await reopened.ready()
  const persisted = reopened.get({ name: 'retained-history', valueEncoding: 'utf8' })
  await persisted.ready()
  t.is(await persisted.get(2), 'three')
  await reopened.close()
  t.is(inventoryCorestoreGenerationTree(source).contentSha256, before)
  await t.exception.all(() => importRawCs7CorestoreCopyIntoEnvelope(args), /activation trigger/)
})

test('raw CS7 importer blocks active writers and leaves target unpopulated', async t => {
  const { source, target, args } = await fixture(t)
  const writer = new Corestore(source)
  await writer.ready()
  try {
    await t.exception.all(() => importRawCs7CorestoreCopyIntoEnvelope(args), /locked/)
    t.is(existsSync(join(target, '.hiverelay-generation/legacy-import-intent.v1.json')), false)
  } finally {
    await writer.close()
  }
  t.ok((await importRawCs7CorestoreCopyIntoEnvelope(args)).sourceUnchanged)
})

test('raw CS7 interrupted copy remains blocked until exact resume closes its intent', async t => {
  const { source, target, args, options } = await fixture(t)
  // Mixed roots retain the predecessor's legacy material; import never deletes it.
  mkdirSync(join(source, 'cores'), { mode: 0o700 })
  writeFileSync(join(source, 'cores/retained'), 'legacy retained bytes', { mode: 0o600 })
  writeFileSync(join(source, 'primary-key'), Buffer.alloc(32, 1), { mode: 0o600 })
  await t.exception.all(() => importRawCs7CorestoreCopyIntoEnvelope({
    ...args,
    faultInjector (phase) {
      if (phase === 'corestore-generation:after-import-corestore-copy-sync') throw new Error('injected interrupted import')
    }
  }), /injected interrupted import/)
  t.exception(() => openCorestore(target, options), /import is incomplete/)
  const receipt = await importRawCs7CorestoreCopyIntoEnvelope(args)
  t.is(receipt.exactPortablePayloadCopyVerified, true)
  t.is(readFileSync(join(target, 'generations/hc11-v1/cores/retained'), 'utf8'), 'legacy retained bytes')
  t.alike(readFileSync(join(target, 'generations/hc11-v1/primary-key')), Buffer.alloc(32, 1))
})

test('raw CS7 importer rejects undeclared entries, incomplete legacy pairs and unidentified databases', async t => {
  const { source, args } = await fixture(t)
  writeFileSync(join(source, 'unknown'), 'must not disappear')
  await t.exception.all(() => importRawCs7CorestoreCopyIntoEnvelope(args), /unclassified/)
  unlinkSync(join(source, 'unknown'))
  writeFileSync(join(source, 'primary-key'), Buffer.alloc(32))
  await t.exception.all(() => importRawCs7CorestoreCopyIntoEnvelope(args), /both or neither/)
  unlinkSync(join(source, 'primary-key'))
  unlinkSync(join(source, 'db/IDENTITY'))
  await t.exception.all(() => importRawCs7CorestoreCopyIntoEnvelope(args), /identified database/)
})

test('raw CS7 importer refuses changed source after signed intent and bounded inventory overflow', async t => {
  const { source, args } = await fixture(t)
  await t.exception.all(() => importRawCs7CorestoreCopyIntoEnvelope({ ...args, limits: { maxBytes: 1 } }), /byte bound/)
  await t.exception.all(() => importRawCs7CorestoreCopyIntoEnvelope({
    ...args,
    faultInjector (phase) {
      if (phase === 'corestore-generation:after-import-intent-sync') throw new Error('injected interrupted import')
    }
  }), /injected interrupted import/)
  writeFileSync(join(source, 'relay-identity.json'), '{"changed":true}\n')
  await t.exception.all(() => importRawCs7CorestoreCopyIntoEnvelope(args), /does not match its expected authority/)
})

test('raw CS7 importer rejects opaque fake markers and incomplete databases before signing', async t => {
  const { source, target, args } = await fixture(t)
  const marker = readFileSync(join(source, 'CORESTORE'))
  writeFileSync(join(source, 'CORESTORE'), 'arbitrary bytes\n')
  await t.exception.all(() => importRawCs7CorestoreCopyIntoEnvelope(args), /unrecognized metadata/)
  writeFileSync(join(source, 'CORESTORE'), marker)
  const current = readFileSync(join(source, 'db/CURRENT'))
  unlinkSync(join(source, 'db/CURRENT'))
  await t.exception.all(() => importRawCs7CorestoreCopyIntoEnvelope(args), /CURRENT record/)
  writeFileSync(join(source, 'db/CURRENT'), 'MANIFEST-999999999999\n')
  await t.exception.all(() => importRawCs7CorestoreCopyIntoEnvelope(args), /existing nonempty manifest/)
  writeFileSync(join(source, 'db/CURRENT'), '../outside\n')
  await t.exception.all(() => importRawCs7CorestoreCopyIntoEnvelope(args), /existing nonempty manifest/)
  t.is(existsSync(join(target, '.hiverelay-generation/legacy-import-intent.v1.json')), false)
  writeFileSync(join(source, 'db/CURRENT'), current)
  t.ok((await importRawCs7CorestoreCopyIntoEnvelope(args)).sourceUnchanged)
})
