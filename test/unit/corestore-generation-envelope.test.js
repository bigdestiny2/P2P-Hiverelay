import test from 'brittle'
import Corestore from 'corestore'
import {
  chmodSync,
  closeSync,
  existsSync,
  ftruncateSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  statSync,
  writeFileSync
} from 'fs'
import { rm } from 'fs/promises'
import { gunzipSync } from 'zlib'
import { tmpdir } from 'os'
import { dirname, join } from 'path'
import {
  corestoreGenerationOpenOptions,
  corestoreGenerationParticipantOptions,
  corestoreGenerationStatus,
  createContentAddressedCorestoreBackup,
  importLegacyCorestoreCopyIntoEnvelope,
  initializeCorestoreGenerationEnvelope,
  inventoryCorestoreGenerationTree,
  openCorestore,
  rebindRestoredCorestoreDevice,
  restoreContentAddressedCorestoreBackup
} from '../../packages/core/core/persistence/storage-root-restore.js'
import { prepareCorestoreGenerationOpen } from '../../packages/core/core/persistence/corestore-generation-envelope.js'

const CS6_FIXTURE_GZIP_BASE64 = 'H4sIAAAAAAAAE+3aOa+rOBQH8O+SljfCLA7wpFuYAAFCwhIDgS5glsuShSQQMprvPpn6veJeaTTT+FdYLo7/8pG7I/+5yM9DcWMLmS2l91pKRCQKhGVWgkwGYsZzSrbkC5FAkedAwR9BQXiylAhQ+JwosihAKQM5L0Ailyw53o+Ln4uMhx0xybj48e/Gny/duXrnc7tGYXRfQwipamdsVyn2Noxty9tVHpYnktjacp1IRVhY0E05UbBCfAzZO/LfJ3wd+SF+XLDZVkrkaioGc99UqS5zIfDYTL55yLCQuH8dAvkeYNSHr3n83JcaOhkmFOKVz9S9K3Tmp4t7UuxmQ+c7T9qrX68NNU5K8ruEk7V8u8vRMxaHcoiOTMD3yRONap9s9bwCoM6H7/RHURRFURRFURRFURRFURT1O+65M5VCQdN776dfn2X6+vuAriLd0KVr+ISWF+FqCpXt5SyuA28X7TSWZx1tUvfI1W8cKJ0wnOxuKw9ie5om+xkwhKta75w2dxiITQtPhyavg90FM6D6ei2HlII3nQLw6ug4pZFHj42w5OKxJZd+6ztT2muqae121mEDv9Ofm/DKnB52IBPszuFhncWhm62jUxLvoBPXl1wIxvzU/t8vSFEURVEURVEURVEURVHUf0prZqHO+X/+nSId/zpHjF752mjS/Xcyzc0yvSqoeqdXW4ReuOZgTrBnGNJ9rB6rtEyNGfBsl3VXZolFN+Oq9UZ17hWqdtvh1iQHfW1HXitN5Ga0ZzNdPoTDc1QYYD/ttZY9ggY7eaWvo6q5etzMEa2YTFGfcnCZZn8fC/GVvJY6CsoqZPg6gzB/38tGYRT7F36OBONxBYEuZOb2xca91QwjmWIPw9M7iOHmtllJ5Hm8GxpWZtyy12zYV8998npZgpKPDvQAWzTWUhNrTX33iaqPj8WPxWX47I/D/EdbzIufC/lmshPQFLjCqvspV/xLVVc3r91Xt5ycBJRcz7gv5KnWrY/FX38DMg1PKeksAAA='

function temporaryDirectory (t, prefix) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), prefix)))
  chmodSync(root, 0o700)
  t.teardown(() => {
    makeTreeOwnerWritable(root)
    return rm(root, { recursive: true, force: true })
  })
  return root
}

function makeTreeOwnerWritable (root) {
  if (!existsSync(root)) return
  const stat = statSync(root)
  if (!stat.isDirectory()) return
  chmodSync(root, stat.mode | 0o700)
  for (const name of readdirSync(root)) makeTreeOwnerWritable(join(root, name))
}

function generationOptions (ceremony, participant = 'test-runtime', faultInjector = null) {
  return {
    hiverelayGeneration: corestoreGenerationOpenOptions(ceremony, {
      participant,
      ...(faultInjector ? { faultInjector } : {})
    })
  }
}

function materializeCs6Fixture (root) {
  const files = JSON.parse(gunzipSync(Buffer.from(CS6_FIXTURE_GZIP_BASE64, 'base64')).toString('utf8'))
  for (const [relative, encoded] of Object.entries(files)) {
    const target = join(root, ...relative.split('/'))
    mkdirSync(dirname(target), { recursive: true, mode: 0o700 })
    writeFileSync(target, Buffer.from(encoded, 'base64'), { mode: 0o600 })
  }
}

function containsCopyTemporary (root) {
  for (const name of readdirSync(root)) {
    const target = join(root, name)
    if (/^\..+\.hiverelay-copy-[0-9a-f]{32}\.tmp$/.test(name)) return true
    if (statSync(target).isDirectory() && containsCopyTemporary(target)) return true
  }
  return false
}

function addDuplicateJsonMember (file, key, shadow) {
  const canonical = readFileSync(file, 'utf8')
  writeFileSync(file, `{${JSON.stringify(key)}:${JSON.stringify(shadow)},${canonical.slice(1)}`)
}

test('HC11 envelope fences old configured paths and recovers sentinel-before-floor crash', async t => {
  const root = temporaryDirectory(t, 'corestore-generation-fresh-')
  const ceremony = initializeCorestoreGenerationEnvelope(root, {
    participants: ['test-runtime'],
    topLevelSidecars: ['app-registry.json']
  })
  t.ok(ceremony.manifestSha256.startsWith('sha256:'))
  t.ok(existsSync(join(root, 'CORESTORE')))
  t.ok(existsSync(join(root, 'primary-key')))
  await t.exception.all(() => corestoreGenerationParticipantOptions({
    ...corestoreGenerationOpenOptions(ceremony, { participant: 'test-runtime' }),
    authorityKey: 'must-not-forward',
    nestedSecret: { token: 'must-not-forward-either' }
  }, 'test-runtime'), /unknown fields: authorityKey, nestedSecret/)

  await t.exception.all(async () => {
    const oldD40 = new Corestore(root)
    try { await oldD40.ready() } finally { await oldD40.close().catch(() => {}) }
  }, /EISDIR|directory/i, 'the d40/CS7 configured-path writer rejects the poison directory')

  await t.exception.all(() => openCorestore(root, {
    hiverelayGeneration: {
      ...corestoreGenerationOpenOptions(ceremony, { participant: 'test-runtime' }),
      expectedInstallationId: '00'.repeat(32)
    }
  }), /external|configured installation authority/)
  await t.exception.all(() => openCorestore(root, {
    hiverelayGeneration: { mode: 'hc11-envelope-v1', participant: 'test-runtime' }
  }), /expectedInstallationId/)
  await t.exception.all(() => openCorestore(root, {
    ...generationOptions(ceremony),
    allowBackup: true
  }), /allowBackup is forbidden/)
  await t.exception.all(() => openCorestore(root, {
    ...generationOptions(ceremony),
    readOnly: true
  }), /offline verification API/)

  let crashed = false
  const first = openCorestore(root, generationOptions(ceremony, 'test-runtime', phase => {
    if (phase === 'corestore-generation:after-activation-sentinel-sync' && !crashed) {
      crashed = true
      throw new Error('simulated sentinel-before-floor crash')
    }
  }))
  await t.exception.all(() => first.ready(), /simulated sentinel-before-floor crash/)
  t.absent(existsSync(join(root, '.hiverelay-generation', 'hc11-trigger.v1.json')))
  await first.close()

  let observerPrepared = false
  const restarted = openCorestore(root, generationOptions(ceremony, 'test-runtime', phase => {
    if (phase !== 'corestore-generation:after-trigger-temp-sync') return
    const prepared = prepareCorestoreGenerationOpen(root,
      corestoreGenerationOpenOptions(ceremony, { participant: 'test-runtime' }))
    observerPrepared = prepared.storage.endsWith('/generations/hc11-v1')
  }))
  await restarted.ready()
  t.ok(observerPrepared, 'a concurrent binding read cannot unlink the active signed trigger temp')
  const status = corestoreGenerationStatus(restarted)
  t.is(status.ready, true)
  t.is(status.receipt.kind, 'hc11-only-write')
  t.is(status.receipt.verifiedReaderState, 'fresh-hc11-only')
  t.is(status.receipt.migrationRecordCompatible, false)
  const receiptDigest = status.receipt.triggerRecordSha256
  await restarted.close()

  const reopened = openCorestore(root, generationOptions(ceremony))
  await reopened.ready()
  t.is(corestoreGenerationStatus(reopened).receipt.triggerRecordSha256, receiptDigest)
  await reopened.close()
})

test('reviewed CS6 copy imports exactly, resumes after a copy crash, and keeps old plus HC11 history', async t => {
  const source = temporaryDirectory(t, 'corestore-generation-cs6-')
  materializeCs6Fixture(source)
  writeFileSync(join(source, 'app-registry.json'), '{"fixture":true}\n', { mode: 0o600 })
  mkdirSync(join(source, 'relay-readonly'), { mode: 0o700 })
  writeFileSync(join(source, 'relay-readonly', 'state'), 'preserved\n', { mode: 0o400 })
  chmodSync(join(source, 'relay-readonly'), 0o500)
  const envelope = temporaryDirectory(t, 'corestore-generation-import-')
  const ceremony = initializeCorestoreGenerationEnvelope(envelope, {
    participants: ['test-runtime'],
    topLevelSidecars: ['app-registry.json', 'relay-readonly']
  })

  let copyCrash = false
  await t.exception.all(() => importLegacyCorestoreCopyIntoEnvelope({
    sourceRoot: source,
    envelopeRoot: envelope,
    ceremony,
    faultInjector (phase) {
      if (phase === 'corestore-generation:after-copy-file-chunk' && !copyCrash) {
        copyCrash = true
        throw new Error('simulated import mid-file crash')
      }
    }
  }), /simulated import mid-file crash/)
  t.ok(containsCopyTemporary(join(envelope, 'generations', 'hc11-v1')))

  const receipt = importLegacyCorestoreCopyIntoEnvelope({ sourceRoot: source, envelopeRoot: envelope, ceremony })
  const rerun = importLegacyCorestoreCopyIntoEnvelope({ sourceRoot: source, envelopeRoot: envelope, ceremony })
  t.is(rerun.receiptSha256, receipt.receiptSha256)
  t.absent(containsCopyTemporary(join(envelope, 'generations', 'hc11-v1')))
  t.alike(readFileSync(join(envelope, 'app-registry.json')), readFileSync(join(source, 'app-registry.json')))
  t.is(statSync(join(envelope, 'relay-readonly')).mode & 0o777, 0o500)
  t.is(statSync(join(envelope, 'relay-readonly', 'state')).mode & 0o777, 0o400)

  const store = openCorestore(envelope, generationOptions(ceremony))
  await store.ready()
  const history = store.get({ name: 'legacy-history' })
  await history.ready()
  t.is(history.length, 2)
  t.is((await history.get(0)).toString(), 'one')
  t.is((await history.get(1)).toString(), 'two')
  await history.append(Buffer.from('three'))
  t.is(corestoreGenerationStatus(store).receipt.verifiedReaderState, 'imported-cs6-plus-hc11')
  t.is(corestoreGenerationStatus(store).receipt.pearMigrateCandidateWriterMode, 'dual-read')
  await store.close()

  const reopened = openCorestore(envelope, generationOptions(ceremony))
  await reopened.ready()
  const persisted = reopened.get({ name: 'legacy-history' })
  await persisted.ready()
  t.is(persisted.length, 3)
  t.is((await persisted.get(0)).toString(), 'one')
  t.is((await persisted.get(2)).toString(), 'three')
  await reopened.close()
})

test('default 0755 legacy root requires explicit offline owner hardening before import', async t => {
  const source = temporaryDirectory(t, 'corestore-generation-legacy-preflight-')
  materializeCs6Fixture(source)
  chmodSync(source, 0o755)
  const envelope = temporaryDirectory(t, 'corestore-generation-preflight-envelope-')
  const ceremony = initializeCorestoreGenerationEnvelope(envelope, { participants: ['test-runtime'] })
  await t.exception.all(() => importLegacyCorestoreCopyIntoEnvelope({
    sourceRoot: source,
    envelopeRoot: envelope,
    ceremony
  }), /verify offline ownership, then chmod 0700/)
  t.is(statSync(source).mode & 0o777, 0o755, 'failed preflight never mutates the legacy source')
  t.absent(existsSync(join(envelope, '.hiverelay-generation', 'legacy-import-intent.v1.json')))
  chmodSync(source, 0o700)
  const receipt = importLegacyCorestoreCopyIntoEnvelope({ sourceRoot: source, envelopeRoot: envelope, ceremony })
  t.is(receipt.exactCopyVerified, true)
})

test('content-addressed backup restores exact isolated envelope state', async t => {
  const source = temporaryDirectory(t, 'corestore-generation-backup-source-')
  const ceremony = initializeCorestoreGenerationEnvelope(source, { participants: ['test-runtime'] })
  const store = openCorestore(source, generationOptions(ceremony))
  await store.ready()
  const core = store.get({ name: 'preserved' })
  await core.append([Buffer.from('alpha'), Buffer.from('beta')])
  await store.close()

  const backupBase = temporaryDirectory(t, 'corestore-generation-backups-')
  const backup = createContentAddressedCorestoreBackup({ sourceRoot: source, backupBase })
  t.ok(backup.backupRoot.endsWith(backup.contentSha256.slice(7)))
  const restoredRoot = temporaryDirectory(t, 'corestore-generation-restored-')
  const restored = restoreContentAddressedCorestoreBackup({
    backupRoot: backup.backupRoot,
    restoreRoot: restoredRoot,
    expectedContentSha256: backup.contentSha256
  })
  t.is(restored.contentSha256, backup.contentSha256)
  t.is(inventoryCorestoreGenerationTree(restoredRoot).contentSha256, backup.contentSha256)

  // Byte copies intentionally retain Corestore's authenticated device marker,
  // so direct startup at another path fails until an externally pinned,
  // signed offline rebind closes the restore intent.
  const movedCopy = openCorestore(restoredRoot, generationOptions(ceremony))
  await t.exception.all(() => movedCopy.ready(), /device file|moved unsafely/i)
  await movedCopy.close().catch(() => {})
  // A failed ready() schedules Corestore's internal close. Let that teardown
  // release its descriptors before the rebind exercise opens its own marker.
  await new Promise(resolve => setTimeout(resolve, 25))

  await t.exception.all(() => rebindRestoredCorestoreDevice({
    restoreRoot: restoredRoot,
    ceremony,
    participant: 'test-runtime',
    expectedContentSha256: backup.contentSha256,
    faultInjector (phase) {
      if (phase === 'corestore-generation:after-old-device-marker-remove') throw new Error('simulated rebind crash')
    }
  }), /simulated rebind crash/)
  await t.exception.all(() => openCorestore(restoredRoot, generationOptions(ceremony)), /restore is incomplete/)

  const rebind = await rebindRestoredCorestoreDevice({
    restoreRoot: restoredRoot,
    ceremony,
    participant: 'test-runtime',
    expectedContentSha256: backup.contentSha256
  })
  t.is(rebind.operationalWriterRestoreImplemented, true)
  t.not(rebind.originalCorestoreMarkerSha256, rebind.restoredCorestoreMarkerSha256)

  const restoredStore = openCorestore(restoredRoot, generationOptions(ceremony))
  await restoredStore.ready()
  const read = restoredStore.get({ name: 'preserved' })
  await read.ready()
  t.is(read.length, 2)
  t.is((await read.get(1)).toString(), 'beta')
  t.ok(corestoreGenerationStatus(restoredStore).receipt.deviceRestoreReceiptSha256.startsWith('sha256:'))
  await restoredStore.close()

  const secondBackupBase = temporaryDirectory(t, 'corestore-generation-second-backups-')
  const secondBackup = createContentAddressedCorestoreBackup({ sourceRoot: restoredRoot, backupBase: secondBackupBase })
  const secondRoot = temporaryDirectory(t, 'corestore-generation-second-restore-')
  restoreContentAddressedCorestoreBackup({
    backupRoot: secondBackup.backupRoot,
    restoreRoot: secondRoot,
    expectedContentSha256: secondBackup.contentSha256
  })
  let lockWasHeld = false
  const secondRebind = await rebindRestoredCorestoreDevice({
    restoreRoot: secondRoot,
    ceremony,
    participant: 'test-runtime',
    expectedContentSha256: secondBackup.contentSha256,
    async faultInjector (phase) {
      if (phase !== 'corestore-generation:before-device-restore-receipt') return
      const contender = new Corestore(join(secondRoot, 'generations', 'hc11-v1'))
      try {
        await contender.ready()
        t.fail('normal Corestore acquired the device marker during restore receipt publication')
      } catch (error) {
        lockWasHeld = /lock|busy|resource/i.test(error.message)
      } finally {
        await contender.close().catch(() => {})
      }
    }
  })
  t.is(secondRebind.sequence, 2)
  t.ok(secondRebind.previousRestoreReceiptSha256)
  t.ok(lockWasHeld, 'exclusive DeviceFile lock is held through receipt publication')

  const secondStore = openCorestore(secondRoot, generationOptions(ceremony))
  await secondStore.ready()
  const secondRead = secondStore.get({ name: 'preserved' })
  await secondRead.ready()
  t.is(secondRead.length, 2)
  await secondStore.close()

  const thirdBackupBase = temporaryDirectory(t, 'corestore-generation-third-backups-')
  const thirdBackup = createContentAddressedCorestoreBackup({ sourceRoot: secondRoot, backupBase: thirdBackupBase })
  const thirdRoot = temporaryDirectory(t, 'corestore-generation-third-restore-')
  restoreContentAddressedCorestoreBackup({
    backupRoot: thirdBackup.backupRoot,
    restoreRoot: thirdRoot,
    expectedContentSha256: thirdBackup.contentSha256
  })
  const thirdRebind = await rebindRestoredCorestoreDevice({
    restoreRoot: thirdRoot,
    ceremony,
    participant: 'test-runtime',
    expectedContentSha256: thirdBackup.contentSha256
  })
  t.is(thirdRebind.sequence, 3)
  t.is(thirdRebind.previousRestoreReceiptSha256, secondRebind.receiptSha256)
  const thirdStore = openCorestore(thirdRoot, generationOptions(ceremony))
  await thirdStore.ready()
  const thirdRead = thirdStore.get({ name: 'preserved' })
  await thirdRead.ready()
  t.is((await thirdRead.get(0)).toString(), 'alpha')
  await thirdStore.close()
})

test('restore intent refuses an allowBackup payload mutation before receipt', async t => {
  const source = temporaryDirectory(t, 'corestore-generation-tamper-source-')
  const ceremony = initializeCorestoreGenerationEnvelope(source, { participants: ['test-runtime'] })
  const store = openCorestore(source, generationOptions(ceremony))
  await store.ready()
  const core = store.get({ name: 'tamper-history' })
  await core.append(Buffer.from('accepted'))
  await store.close()

  const backupBase = temporaryDirectory(t, 'corestore-generation-tamper-backup-')
  const backup = createContentAddressedCorestoreBackup({ sourceRoot: source, backupBase })
  const target = temporaryDirectory(t, 'corestore-generation-tamper-restore-')
  restoreContentAddressedCorestoreBackup({
    backupRoot: backup.backupRoot,
    restoreRoot: target,
    expectedContentSha256: backup.contentSha256
  })
  await t.exception.all(() => rebindRestoredCorestoreDevice({
    restoreRoot: target,
    ceremony,
    participant: 'test-runtime',
    expectedContentSha256: backup.contentSha256,
    faultInjector (phase) {
      if (phase === 'corestore-generation:after-restore-intent-sync') throw new Error('intent crash')
    }
  }), /intent crash/)

  const bypass = new Corestore(join(target, 'generations', 'hc11-v1'), { allowBackup: true })
  await bypass.ready()
  const changed = bypass.get({ name: 'tamper-history' })
  await changed.ready()
  await changed.append(Buffer.from('must-not-be-ratified'))
  await bypass.close()

  await t.exception.all(() => rebindRestoredCorestoreDevice({
    restoreRoot: target,
    ceremony,
    participant: 'test-runtime',
    expectedContentSha256: backup.contentSha256
  }), /restored payload changed/)
  await t.exception.all(() => openCorestore(target, generationOptions(ceremony)), /restore is incomplete/)
})

test('concurrent rebinders serialize one sequence and idempotent reruns recheck marker and payload', async t => {
  const source = temporaryDirectory(t, 'corestore-generation-concurrent-source-')
  const ceremony = initializeCorestoreGenerationEnvelope(source, { participants: ['test-runtime'] })
  const store = openCorestore(source, generationOptions(ceremony))
  await store.ready()
  const core = store.get({ name: 'concurrent-history' })
  await core.append(Buffer.from('stable'))
  await store.close()
  const backupBase = temporaryDirectory(t, 'corestore-generation-concurrent-backup-')
  const backup = createContentAddressedCorestoreBackup({ sourceRoot: source, backupBase })
  const target = temporaryDirectory(t, 'corestore-generation-concurrent-restore-')
  restoreContentAddressedCorestoreBackup({
    backupRoot: backup.backupRoot,
    restoreRoot: target,
    expectedContentSha256: backup.contentSha256
  })

  let enterReceipt
  let releaseReceipt
  const entered = new Promise(resolve => { enterReceipt = resolve })
  const release = new Promise(resolve => { releaseReceipt = resolve })
  const first = rebindRestoredCorestoreDevice({
    restoreRoot: target,
    ceremony,
    participant: 'test-runtime',
    expectedContentSha256: backup.contentSha256,
    async faultInjector (phase) {
      if (phase !== 'corestore-generation:before-device-restore-receipt') return
      enterReceipt()
      await release
    }
  })
  await entered
  let secondSettled = false
  const second = rebindRestoredCorestoreDevice({
    restoreRoot: target,
    ceremony,
    participant: 'test-runtime',
    expectedContentSha256: backup.contentSha256
  }).finally(() => { secondSettled = true })
  await new Promise(resolve => setTimeout(resolve, 25))
  t.absent(secondSettled, 'second rebind waits on the stable authority-directory lock')
  releaseReceipt()
  const [firstReceipt, secondReceipt] = await Promise.all([first, second])
  t.is(firstReceipt.sequence, 1)
  t.is(secondReceipt.sequence, 1)
  t.is(secondReceipt.receiptSha256, firstReceipt.receiptSha256)

  const bypass = new Corestore(join(target, 'generations', 'hc11-v1'), { allowBackup: true })
  await bypass.ready()
  const changed = bypass.get({ name: 'concurrent-history' })
  await changed.ready()
  await changed.append(Buffer.from('post-receipt-tamper'))
  await bypass.close()
  await t.exception.all(() => rebindRestoredCorestoreDevice({
    restoreRoot: target,
    ceremony,
    participant: 'test-runtime',
    expectedContentSha256: backup.contentSha256
  }), /restored payload changed/)

  const marker = join(target, 'generations', 'hc11-v1', 'CORESTORE')
  writeFileSync(marker, Buffer.concat([readFileSync(marker), Buffer.from('\n')]))
  await t.exception.all(() => rebindRestoredCorestoreDevice({
    restoreRoot: target,
    ceremony,
    participant: 'test-runtime',
    expectedContentSha256: backup.contentSha256
  }), /latest signed device rebind receipt/)
})

test('atomic copies resume at chunk, temp-sync, and link crashes and preserve read-only modes', async t => {
  const source = temporaryDirectory(t, 'corestore-generation-copy-source-')
  mkdirSync(join(source, 'readonly'), { mode: 0o700 })
  writeFileSync(join(source, 'readonly', 'segment'), Buffer.alloc(192 * 1024, 0x5a), { mode: 0o400 })
  chmodSync(join(source, 'readonly'), 0o500)
  mkdirSync(join(source, 'world-writable'), { mode: 0o700 })
  writeFileSync(join(source, 'world-writable', 'segment'), Buffer.alloc(96 * 1024, 0x33), { mode: 0o600 })
  chmodSync(join(source, 'world-writable'), 0o777)
  const sourceInventory = inventoryCorestoreGenerationTree(source)

  let completedBackup = null
  for (const phase of [
    'corestore-generation:after-copy-file-chunk',
    'corestore-generation:after-copy-file-temp-sync',
    'corestore-generation:after-copy-file-link'
  ]) {
    const backupBase = temporaryDirectory(t, `corestore-generation-copy-${phase.split(':').pop()}-`)
    const partial = join(backupBase, `sha256-${sourceInventory.contentSha256.slice(7)}`)
    let injected = false
    await t.exception.all(() => createContentAddressedCorestoreBackup({
      sourceRoot: source,
      backupBase,
      faultInjector (seen, context) {
        if (phase === 'corestore-generation:after-copy-file-chunk' &&
            context.path !== 'world-writable/segment') return
        if (!injected && seen === phase) {
          injected = true
          if (phase === 'corestore-generation:after-copy-file-chunk') {
            t.is(statSync(join(partial, 'world-writable')).mode & 0o777, 0o700,
              'world-writable source directory is private while staged')
          }
          throw new Error(`copy crash ${phase}`)
        }
      }
    }), new RegExp(`copy crash ${phase}`))
    t.ok(containsCopyTemporary(partial), `${phase} leaves only a recognized resumable temp`)
    completedBackup = createContentAddressedCorestoreBackup({ sourceRoot: source, backupBase })
    t.absent(containsCopyTemporary(completedBackup.backupRoot), `${phase} retry removes its temp`)
    t.is(statSync(join(completedBackup.backupRoot, 'readonly')).mode & 0o777, 0o500)
    t.is(statSync(join(completedBackup.backupRoot, 'readonly', 'segment')).mode & 0o777, 0o400)
    t.is(statSync(join(completedBackup.backupRoot, 'world-writable')).mode & 0o777, 0o777)
  }

  const restored = temporaryDirectory(t, 'corestore-generation-copy-restored-')
  let restoreCrash = false
  await t.exception.all(() => restoreContentAddressedCorestoreBackup({
    backupRoot: completedBackup.backupRoot,
    restoreRoot: restored,
    expectedContentSha256: completedBackup.contentSha256,
    faultInjector (phase) {
      if (!restoreCrash && phase === 'corestore-generation:after-copy-file-chunk') {
        restoreCrash = true
        throw new Error('restore mid-file crash')
      }
    }
  }), /restore mid-file crash/)
  t.ok(containsCopyTemporary(restored))
  const receipt = restoreContentAddressedCorestoreBackup({
    backupRoot: completedBackup.backupRoot,
    restoreRoot: restored,
    expectedContentSha256: completedBackup.contentSha256
  })
  t.is(receipt.contentSha256, sourceInventory.contentSha256)
  t.absent(containsCopyTemporary(restored))
  t.is(statSync(join(restored, 'readonly')).mode & 0o777, 0o500)
})

test('inventory rejects non-traversable directory modes before creating a partial copy', async t => {
  const source = temporaryDirectory(t, 'corestore-generation-nontraversable-source-')
  mkdirSync(join(source, 'restricted'), { mode: 0o700 })
  writeFileSync(join(source, 'restricted', 'state'), 'state\n', { mode: 0o600 })
  chmodSync(join(source, 'restricted'), 0o400)
  await t.exception.all(() => inventoryCorestoreGenerationTree(source), /owner read and execute permission/)
  const backupBase = temporaryDirectory(t, 'corestore-generation-nontraversable-backup-')
  await t.exception.all(() => createContentAddressedCorestoreBackup({ sourceRoot: source, backupBase }),
    /owner read and execute permission/)
  t.alike(readdirSync(backupBase), [], 'mode preflight fails before any content-addressed target is created')
})

test('authority files reject duplicate JSON members despite a parse-equivalent valid MAC', async t => {
  const envelopeRoot = temporaryDirectory(t, 'corestore-generation-canonical-envelope-')
  const envelopeCeremony = initializeCorestoreGenerationEnvelope(envelopeRoot, { participants: ['test-runtime'] })
  addDuplicateJsonMember(join(envelopeRoot, '.hiverelay-generation', 'envelope.v1.json'), 'schema', 'shadow')
  await t.exception.all(() => openCorestore(envelopeRoot, generationOptions(envelopeCeremony)), /unique canonical signed encoding/)

  const triggerRoot = temporaryDirectory(t, 'corestore-generation-canonical-trigger-')
  const triggerCeremony = initializeCorestoreGenerationEnvelope(triggerRoot, { participants: ['test-runtime'] })
  const triggerStore = openCorestore(triggerRoot, generationOptions(triggerCeremony))
  await triggerStore.ready()
  await triggerStore.close()
  addDuplicateJsonMember(join(triggerRoot, '.hiverelay-generation', 'hc11-trigger.v1.json'), 'kind', 'shadow')
  const triggerReopen = openCorestore(triggerRoot, generationOptions(triggerCeremony))
  await t.exception.all(() => triggerReopen.ready(), /unique canonical signed encoding/)
  await triggerReopen.close().catch(() => {})

  const source = temporaryDirectory(t, 'corestore-generation-canonical-source-')
  const ceremony = initializeCorestoreGenerationEnvelope(source, { participants: ['test-runtime'] })
  const sourceStore = openCorestore(source, generationOptions(ceremony))
  await sourceStore.ready()
  await sourceStore.close()
  const backupBase = temporaryDirectory(t, 'corestore-generation-canonical-backup-')
  const backup = createContentAddressedCorestoreBackup({ sourceRoot: source, backupBase })

  const intentRoot = temporaryDirectory(t, 'corestore-generation-canonical-intent-')
  restoreContentAddressedCorestoreBackup({
    backupRoot: backup.backupRoot,
    restoreRoot: intentRoot,
    expectedContentSha256: backup.contentSha256
  })
  await t.exception.all(() => rebindRestoredCorestoreDevice({
    restoreRoot: intentRoot,
    ceremony,
    participant: 'test-runtime',
    expectedContentSha256: backup.contentSha256,
    faultInjector (phase) {
      if (phase === 'corestore-generation:after-restore-intent-sync') throw new Error('intent pending')
    }
  }), /intent pending/)
  addDuplicateJsonMember(join(intentRoot, '.hiverelay-generation',
    'device-restore-intent.0000000000000001.v1.json'), 'sequence', 999)
  await t.exception.all(() => openCorestore(intentRoot, generationOptions(ceremony)), /unique canonical signed encoding/)

  const receiptRoot = temporaryDirectory(t, 'corestore-generation-canonical-receipt-')
  restoreContentAddressedCorestoreBackup({
    backupRoot: backup.backupRoot,
    restoreRoot: receiptRoot,
    expectedContentSha256: backup.contentSha256
  })
  await rebindRestoredCorestoreDevice({
    restoreRoot: receiptRoot,
    ceremony,
    participant: 'test-runtime',
    expectedContentSha256: backup.contentSha256
  })
  addDuplicateJsonMember(join(receiptRoot, '.hiverelay-generation',
    'device-restore-receipt.0000000000000001.v1.json'), 'sequence', 999)
  await t.exception.all(() => openCorestore(receiptRoot, generationOptions(ceremony)), /unique canonical signed encoding/)
})

test('deterministic inventory hashes a large sparse segment with bounded buffer memory', async t => {
  const root = temporaryDirectory(t, 'corestore-generation-sparse-')
  const file = join(root, 'large-segment')
  const descriptor = openSync(file, 'wx', 0o600)
  try { ftruncateSync(descriptor, 128 * 1024 * 1024) } finally { closeSync(descriptor) }
  const beforeExternal = process.memoryUsage().external
  const inventory = inventoryCorestoreGenerationTree(root, { maxBytes: 129 * 1024 * 1024 })
  const externalGrowth = process.memoryUsage().external - beforeExternal
  t.is(inventory.totalBytes, 128n * 1024n * 1024n)
  t.ok(inventory.contentSha256.startsWith('sha256:'))
  t.ok(externalGrowth < 32 * 1024 * 1024, 'inventory does not allocate the segment size')
})
