import b4a from 'b4a'
import test from 'brittle'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { createHash, createHmac } from 'node:crypto'
import { chmod, link, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, stat, symlink, unlink, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import {
  BLIND_STORE_GENERATION,
  BLIND_STORE_GENERATION_CAPABILITIES,
  BLIND_STORE_READER_MODE,
  openBlindStoreGenerationFloor
} from '../storage-generation-v12.js'

const KEY = b4a.alloc(32, 0xa1)
const IDENTITY = b4a.from('authenticated-runtime-store-binding')
const first = { walSequence: 1n, walHash: b4a.alloc(32, 1) }
const second = { walSequence: 2n, walHash: b4a.alloc(32, 2) }
const third = { walSequence: 3n, walHash: b4a.alloc(32, 3) }
const fourth = { walSequence: 4n, walHash: b4a.alloc(32, 4) }

async function privateTemp (prefix) { return realpath(await mkdtemp(prefix)) }

function stableValue (value) {
  if (Array.isArray(value)) return value.map(stableValue)
  if (value == null || typeof value !== 'object') return value
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, stableValue(value[key])]))
}

function canonicalBytes (value) { return Buffer.from(JSON.stringify(stableValue(value)) + '\n') }

function signedBytes (body) {
  const mac = createHmac('sha256', KEY).update(canonicalBytes(body)).digest('hex')
  return canonicalBytes({ ...body, mac })
}

async function readSignedBody (file) {
  const value = JSON.parse(await readFile(file))
  delete value.mac
  return value
}

async function freshFloorRoot (t, prefix = 'blind-generation-hardening-') {
  const root = await privateTemp(path.join(os.tmpdir(), prefix))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const options = {
    manifestKey: KEY,
    storeIdentity: IDENTITY,
    storeEvidence: first,
    creationProof: { freshStoreBindingCreated: true }
  }
  await openBlindStoreGenerationFloor(root, { ...options, allowCreate: true })
  return { root, options }
}

function recordFile (root, sequence) {
  return path.join(root, `blind-store-generation-record-${String(sequence).padStart(16, '0')}-v2.json`)
}

test('fresh installation floor advances only after a newer acknowledged blind write', async t => {
  const root = await privateTemp(path.join(os.tmpdir(), 'blind-store-generation-'))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const options = {
    manifestKey: KEY,
    storeIdentity: IDENTITY,
    storeEvidence: first,
    creationProof: { freshStoreBindingCreated: true }
  }
  const floor = await openBlindStoreGenerationFloor(root, { ...options, allowCreate: true })
  t.is(floor.firstIrreversibleWriteAcknowledged, false)
  t.ok(floor.assertReaderMode(BLIND_STORE_READER_MODE.BLIND_ONLY))
  t.exception(() => floor.assertReaderMode('legacy-only'), /blind-only|dual-read/)
  t.exception(() => floor.assertReaderMode('blind-plus-legacy-dual-read'), /dual-read/)
  await t.exception.all(() => floor.acknowledgeBlindOnlyWrite(first), /newer durable WAL write/)
  t.is(await floor.acknowledgeBlindOnlyWrite(second), true)
  const restarted = await openBlindStoreGenerationFloor(root, { ...options, storeEvidence: second })
  t.is(restarted.firstIrreversibleWriteAcknowledged, true)
  t.is(restarted.trigger.role, 'cell')
  t.is(restarted.trigger.kind, 'blind-only-write')
})

test('missing, tampered, replayed-false, transplanted, and partial evidence fail closed', async t => {
  const root = await privateTemp(path.join(os.tmpdir(), 'blind-store-generation-'))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const options = {
    manifestKey: KEY,
    storeIdentity: IDENTITY,
    storeEvidence: first,
    creationProof: { freshStoreBindingCreated: true }
  }
  const floor = await openBlindStoreGenerationFloor(root, { ...options, allowCreate: true })
  const oldHead = await readFile(path.join(root, BLIND_STORE_GENERATION.headFile))
  await floor.acknowledgeBlindOnlyWrite(second)

  const triggerRecord = (await readdir(root)).find(name => name.includes('0000000000000002'))
  await unlink(path.join(root, triggerRecord))
  await writeFile(path.join(root, BLIND_STORE_GENERATION.headFile), oldHead)
  const recoveredTrigger = await openBlindStoreGenerationFloor(root, {
    ...options,
    storeEvidence: second,
    hasIrreversibleState: true
  })
  t.is(recoveredTrigger.firstIrreversibleWriteAcknowledged, true)
  t.is(recoveredTrigger.trigger.recoveryConservative, true)

  const fresh = await privateTemp(path.join(os.tmpdir(), 'blind-store-generation-'))
  t.teardown(() => rm(fresh, { recursive: true, force: true }))
  await openBlindStoreGenerationFloor(fresh, { ...options, allowCreate: true })
  const head = path.join(fresh, BLIND_STORE_GENERATION.headFile)
  const tampered = JSON.parse(await readFile(head))
  tampered.sequence = 9
  await writeFile(head, JSON.stringify(tampered))
  await t.exception.all(() => openBlindStoreGenerationFloor(fresh, options), /invalid/)
  await unlink(head)
  const missingHeadRecovered = await openBlindStoreGenerationFloor(fresh, options)
  t.is(missingHeadRecovered.firstIrreversibleWriteAcknowledged, false)
  t.ok((await readdir(fresh)).includes(BLIND_STORE_GENERATION.headFile))

  const partial = path.join(fresh, `.blind-store-generation-head.tmp-${'ab'.repeat(16)}`)
  await writeFile(partial, '{', { mode: 0o600 })
  const partialRecovered = await openBlindStoreGenerationFloor(fresh, options)
  t.is(partialRecovered.firstIrreversibleWriteAcknowledged, false)
  t.ok((await readdir(fresh)).includes(path.basename(partial)), 'orphan temp is tolerated but never opportunistically unlinked')

  const other = await privateTemp(path.join(os.tmpdir(), 'blind-store-generation-'))
  t.teardown(() => rm(other, { recursive: true, force: true }))
  await openBlindStoreGenerationFloor(other, { ...options, storeIdentity: b4a.from('other'), allowCreate: true })
  await t.exception.all(() => openBlindStoreGenerationFloor(other, options), /another store|installation|invalid/)
})

test('process kill between append-only record and head rename recovers monotonically', async t => {
  const root = await privateTemp(path.join(os.tmpdir(), 'blind-store-generation-kill-'))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  await openBlindStoreGenerationFloor(root, {
    manifestKey: KEY,
    storeIdentity: IDENTITY,
    storeEvidence: first,
    allowCreate: true,
    creationProof: { freshStoreBindingCreated: true }
  })
  const child = spawn(process.execPath, [
    new URL('storage-generation-kill-fixture.mjs', import.meta.url).pathname, root
  ], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'] })
  await once(child, 'message')
  const exited = once(child, 'exit')
  child.kill('SIGKILL')
  await exited
  const recovered = await openBlindStoreGenerationFloor(root, {
    manifestKey: KEY, storeIdentity: IDENTITY, storeEvidence: second
  })
  t.is(recovered.firstIrreversibleWriteAcknowledged, true)
})

test('concurrent first acknowledgments serialize at one deterministic boundary', async t => {
  const root = await privateTemp(path.join(os.tmpdir(), 'blind-store-generation-concurrent-'))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const floor = await openBlindStoreGenerationFloor(root, {
    manifestKey: KEY,
    storeIdentity: IDENTITY,
    storeEvidence: first,
    allowCreate: true,
    creationProof: { freshStoreBindingCreated: true }
  })
  t.alike(await Promise.all([
    floor.acknowledgeBlindOnlyWrite(second),
    floor.acknowledgeBlindOnlyWrite(third)
  ]), [true, true])
  const records = (await readdir(root)).filter(name => name.includes('generation-record')).sort()
  t.is(records.length, 3)
  const headPath = path.join(root, BLIND_STORE_GENERATION.headFile)
  const head = JSON.parse(await readFile(headPath))
  t.is(head.sequence, 2)
  const trigger = JSON.parse(await readFile(path.join(root, records.at(-1))))
  t.is(trigger.trigger.storeEvidence.walSequence, '2')
  const beforeNames = await readdir(root)
  const beforeHead = await readFile(headPath)
  const beforeHeadStat = await stat(headPath)
  t.is(await floor.acknowledgeBlindOnlyWrite(fourth), false)
  t.alike(await readdir(root), beforeNames)
  t.alike(await readFile(headPath), beforeHead)
  t.is((await stat(headPath)).mtimeMs, beforeHeadStat.mtimeMs)
})

test('record fsync linearizes the floor before recoverable head publication', async t => {
  const root = await privateTemp(path.join(os.tmpdir(), 'blind-store-generation-linearization-'))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  let follower = null
  let floor = null
  floor = await openBlindStoreGenerationFloor(root, {
    manifestKey: KEY,
    storeIdentity: IDENTITY,
    storeEvidence: first,
    allowCreate: true,
    creationProof: { freshStoreBindingCreated: true },
    async faultInjector (phase) {
      if (phase === 'after-record-sync') follower = await floor.acknowledgeBlindOnlyWrite(third)
    }
  })
  t.is(await floor.acknowledgeBlindOnlyWrite(second), true)
  t.is(follower, false)
  const records = (await readdir(root)).filter(name => name.includes('generation-record')).sort()
  t.is(records.length, 3)
  const trueRecord = JSON.parse(await readFile(path.join(root, records.at(-1))))
  t.is(trueRecord.trigger.storeEvidence.walSequence, '2')
  const restarted = await openBlindStoreGenerationFloor(root, {
    manifestKey: KEY, storeIdentity: IDENTITY, storeEvidence: third
  })
  t.is(restarted.firstIrreversibleWriteAcknowledged, true)
})

test('one installation floor serializes blind and HC11 triggers across store roots', async t => {
  const root = await privateTemp(path.join(os.tmpdir(), 'blind-installation-generation-'))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const identities = {
    cell: b4a.from('cell-store'),
    inbox: b4a.from('inbox-store'),
    core: b4a.from('core-store'),
    hc11: b4a.from('hc11-server-store')
  }
  const floor = await openBlindStoreGenerationFloor(root, {
    manifestKey: KEY,
    installationIdentity: IDENTITY,
    allowCreate: true,
    creationProof: { freshStoreBindingCreated: true },
    currentStores: [
      { role: 'cell', storeIdentity: identities.cell, storeEvidence: first },
      { role: 'inbox', storeIdentity: identities.inbox, storeEvidence: first },
      { role: 'core', storeIdentity: identities.core, storeEvidence: first },
      { role: 'hc11', storeIdentity: identities.hc11, storeEvidence: first }
    ]
  })
  t.is(BLIND_STORE_GENERATION_CAPABILITIES.authorityScope, 'installation')
  t.is(BLIND_STORE_GENERATION_CAPABILITIES.dualReadRollbackImplemented, false)
  t.is(BLIND_STORE_GENERATION_CAPABILITIES.targetLegacyRuntimeRestartFenceImplemented, true)
  t.is(BLIND_STORE_GENERATION_CAPABILITIES.permanentArbitraryLegacyWriterFenceImplemented, false)
  t.is(BLIND_STORE_GENERATION_CAPABILITIES.crossRuntimeBlindHc11AuthorityImplemented, false)
  t.alike(await Promise.all([
    floor.acknowledgeWrite({ role: 'hc11', kind: 'hc11-only-write', storeEvidence: fourth }),
    floor.acknowledgeWrite({ role: 'core', kind: 'blind-only-write', storeEvidence: second }),
    floor.acknowledgeWrite({ role: 'cell', kind: 'blind-only-write', storeEvidence: second })
  ]), [true, true, true])
  t.is(floor.trigger.role, 'cell', 'deterministic role ordering selects one global boundary')
  const receipt = floor.triggerReceipt()
  t.is(receipt.schema, 'hiverelay-blind-generation-trigger-receipt-v1')
  t.is(receipt.migrationRecordCompatible, false)
  t.is(receipt.crossRuntimeBlindHc11AuthorityImplemented, false)
  t.absent(receipt.writer_mode)
  const triggerRecordFile = path.join(root,
    `blind-store-generation-record-${String(receipt.generationSequence).padStart(16, '0')}-v2.json`)
  t.is(receipt.recordSha256, createHash('sha256').update(await readFile(triggerRecordFile)).digest('hex'))

  const restarted = await openBlindStoreGenerationFloor(root, {
    manifestKey: KEY,
    installationIdentity: IDENTITY,
    currentStores: [
      { role: 'cell', storeIdentity: identities.cell, storeEvidence: second, hasIrreversibleState: true },
      { role: 'inbox', storeIdentity: identities.inbox, storeEvidence: first },
      { role: 'core', storeIdentity: identities.core, storeEvidence: second, hasIrreversibleState: true },
      { role: 'hc11', storeIdentity: identities.hc11, storeEvidence: fourth, hasIrreversibleState: true }
    ]
  })
  t.is(restarted.firstIrreversibleWriteAcknowledged, true)
  t.is(restarted.trigger.role, 'cell')

  await t.exception.all(() => openBlindStoreGenerationFloor(root, {
    manifestKey: KEY,
    installationIdentity: IDENTITY,
    currentStores: [
      { role: 'cell', storeIdentity: identities.cell, storeEvidence: second, hasIrreversibleState: true },
      { role: 'inbox', storeIdentity: identities.inbox, storeEvidence: { walSequence: 0n, walHash: b4a.alloc(32) } },
      { role: 'core', storeIdentity: identities.core, storeEvidence: second, hasIrreversibleState: true },
      { role: 'hc11', storeIdentity: identities.hc11, storeEvidence: fourth, hasIrreversibleState: true }
    ]
  }), /registered inbox store evidence.*rolled back/)

  await t.exception.all(() => openBlindStoreGenerationFloor(root, {
    manifestKey: KEY,
    installationIdentity: IDENTITY,
    currentStores: [
      { role: 'cell', storeIdentity: identities.cell, storeEvidence: second, hasIrreversibleState: true },
      { role: 'core', storeIdentity: identities.core, storeEvidence: second, hasIrreversibleState: true },
      { role: 'hc11', storeIdentity: identities.hc11, storeEvidence: fourth, hasIrreversibleState: true }
    ]
  }), /every registered store role/)
})

test('generation evidence creation requires an explicit pristine proof and rejects populated state', async t => {
  const missingProof = await privateTemp(path.join(os.tmpdir(), 'blind-generation-no-proof-'))
  t.teardown(() => rm(missingProof, { recursive: true, force: true }))
  await t.exception.all(() => openBlindStoreGenerationFloor(missingProof, {
    manifestKey: KEY,
    storeIdentity: IDENTITY,
    storeEvidence: first,
    allowCreate: true
  }), /explicit pristine-store proof/)

  const populated = await privateTemp(path.join(os.tmpdir(), 'blind-generation-populated-'))
  t.teardown(() => rm(populated, { recursive: true, force: true }))
  await t.exception.all(() => openBlindStoreGenerationFloor(populated, {
    manifestKey: KEY,
    storeIdentity: IDENTITY,
    storeEvidence: first,
    hasIrreversibleState: true,
    allowCreate: true,
    creationProof: { sealedGenesisValidated: true }
  }), /cannot be created over irreversible store state/)
})

test('post-trigger restart requires the trigger role and v1 evidence hard-stops', async t => {
  const root = await privateTemp(path.join(os.tmpdir(), 'blind-installation-role-'))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const floor = await openBlindStoreGenerationFloor(root, {
    manifestKey: KEY,
    installationIdentity: IDENTITY,
    allowCreate: true,
    creationProof: { freshStoreBindingCreated: true },
    currentStores: [{ role: 'hc11', storeIdentity: IDENTITY, storeEvidence: first }]
  })
  await floor.acknowledgeWrite({ role: 'hc11', kind: 'hc11-only-write', storeEvidence: second })
  await t.exception.all(() => openBlindStoreGenerationFloor(root, {
    manifestKey: KEY,
    installationIdentity: IDENTITY,
    currentStores: [{ role: 'cell', storeIdentity: IDENTITY, storeEvidence: first }]
  }), /post-trigger installation cannot add|trigger store role/)

  const predecessor = await privateTemp(path.join(os.tmpdir(), 'blind-generation-v1-'))
  t.teardown(() => rm(predecessor, { recursive: true, force: true }))
  await writeFile(path.join(predecessor, 'blind-store-generation-head-v1.json'), '{}\n')
  await t.exception.all(() => openBlindStoreGenerationFloor(predecessor, {
    manifestKey: KEY,
    storeIdentity: IDENTITY,
    storeEvidence: first,
    allowCreate: true
  }), /reviewed offline migration/)
})

test('record publication resumes after partial, fsynced-temp, and link-before-head faults', async t => {
  for (const phase of ['after-record-temp-partial', 'after-record-temp-sync', 'after-record-link']) {
    const { root, options } = await freshFloorRoot(t, `blind-generation-${phase}-`)
    const floor = await openBlindStoreGenerationFloor(root, {
      ...options,
      faultInjector (seen, context) {
        if (seen === phase && context.sequence === 2) throw new Error(`injected ${phase}`)
      }
    })
    await t.exception.all(() => floor.acknowledgeBlindOnlyWrite(second), new RegExp(`injected ${phase}`))
    const temporaries = (await readdir(root)).filter(name => name.startsWith('.blind-store-generation-record.tmp-'))
    t.is(temporaries.length, 1, `${phase} leaves one operation-owned random temp`)
    t.is((await stat(path.join(root, temporaries[0]))).mode & 0o777, 0o600)
    const recovered = await openBlindStoreGenerationFloor(root, {
      ...options,
      storeEvidence: second,
      hasIrreversibleState: true
    })
    t.is(recovered.firstIrreversibleWriteAcknowledged, true)
    t.is(recovered.trigger.walSequence, 2n)
    t.is((await readdir(root)).filter(name => isRecordName(name)).length, 3)
  }
})

test('missing initial and registration heads rebuild only from a valid contiguous chain', async t => {
  for (const sequence of [0, 1]) {
    const root = await privateTemp(path.join(os.tmpdir(), `blind-generation-head-missing-${sequence}-`))
    t.teardown(() => rm(root, { recursive: true, force: true }))
    const options = {
      manifestKey: KEY,
      storeIdentity: IDENTITY,
      storeEvidence: first,
      creationProof: { freshStoreBindingCreated: true },
      allowCreate: true,
      faultInjector (phase, context) {
        if (phase === 'after-record-link' && context.sequence === sequence) throw new Error(`head gap ${sequence}`)
      }
    }
    await t.exception.all(() => openBlindStoreGenerationFloor(root, options), new RegExp(`head gap ${sequence}`))
    const recovered = await openBlindStoreGenerationFloor(root, {
      manifestKey: KEY,
      storeIdentity: IDENTITY,
      storeEvidence: first,
      allowCreate: true,
      creationProof: { freshStoreBindingCreated: true }
    })
    t.is(recovered.firstIrreversibleWriteAcknowledged, false)
    const head = JSON.parse(await readFile(path.join(root, BLIND_STORE_GENERATION.headFile)))
    t.is(head.sequence, 1)
  }

  const collision = await privateTemp(path.join(os.tmpdir(), 'blind-generation-head-temp-random-'))
  t.teardown(() => rm(collision, { recursive: true, force: true }))
  const collisionOptions = {
    manifestKey: KEY,
    storeIdentity: IDENTITY,
    storeEvidence: first,
    allowCreate: true,
    creationProof: { freshStoreBindingCreated: true },
    faultInjector (phase, context) {
      if (phase === 'after-head-temp-sync' && context.sequence === 0) throw new Error('head temp staged')
    }
  }
  await t.exception.all(() => openBlindStoreGenerationFloor(collision, collisionOptions), /head temp staged/)
  await t.exception.all(() => openBlindStoreGenerationFloor(collision, collisionOptions), /head temp staged/)
  const headTemps = (await readdir(collision)).filter(name => name.startsWith('.blind-store-generation-head.tmp-'))
  t.is(headTemps.length, 2, 'random wx head temps do not collide within one process')
  const recovered = await openBlindStoreGenerationFloor(collision, {
    manifestKey: KEY,
    storeIdentity: IDENTITY,
    storeEvidence: first
  })
  t.is(recovered.firstIrreversibleWriteAcknowledged, false)
})

test('record filenames, generation namespace, head-without-chain, and control directory fail closed', async t => {
  const mismatch = await freshFloorRoot(t, 'blind-generation-filename-mismatch-')
  await writeFile(recordFile(mismatch.root, 0), await readFile(recordFile(mismatch.root, 1)))
  await t.exception.all(() => openBlindStoreGenerationFloor(mismatch.root, mismatch.options), /filename does not match/)

  const gap = await freshFloorRoot(t, 'blind-generation-filename-gap-')
  await rename(recordFile(gap.root, 1), recordFile(gap.root, 2))
  await t.exception.all(() => openBlindStoreGenerationFloor(gap.root, gap.options), /filenames must be contiguous/)

  const malformed = await freshFloorRoot(t, 'blind-generation-malformed-name-')
  await writeFile(path.join(malformed.root, 'blind-store-generation-record-bad-v2.json'), '{}\n')
  await t.exception.all(() => openBlindStoreGenerationFloor(malformed.root, malformed.options), /malformed.*namespace/)

  const headOnly = await privateTemp(path.join(os.tmpdir(), 'blind-generation-head-only-'))
  t.teardown(() => rm(headOnly, { recursive: true, force: true }))
  await writeFile(path.join(headOnly, BLIND_STORE_GENERATION.headFile), '{}\n', { mode: 0o600 })
  await t.exception.all(() => openBlindStoreGenerationFloor(headOnly, {
    manifestKey: KEY,
    storeIdentity: IDENTITY,
    storeEvidence: first,
    allowCreate: true,
    creationProof: { freshStoreBindingCreated: true }
  }), /head exists without a valid record chain/)

  const publicRoot = await privateTemp(path.join(os.tmpdir(), 'blind-generation-public-control-'))
  t.teardown(() => rm(publicRoot, { recursive: true, force: true }))
  await chmod(publicRoot, 0o755)
  await t.exception.all(() => openBlindStoreGenerationFloor(publicRoot, {
    manifestKey: KEY,
    storeIdentity: IDENTITY,
    storeEvidence: first,
    allowCreate: true,
    creationProof: { freshStoreBindingCreated: true }
  }), /canonical, private, owner-controlled/)
  t.is((await stat(publicRoot)).mode & 0o777, 0o755, 'floor never silently tightens an existing control directory')

  const symlinkTarget = await privateTemp(path.join(os.tmpdir(), 'blind-generation-symlink-target-'))
  const symlinkRoot = `${symlinkTarget}-link`
  t.teardown(() => rm(symlinkRoot, { force: true }))
  t.teardown(() => rm(symlinkTarget, { recursive: true, force: true }))
  await symlink(symlinkTarget, symlinkRoot)
  await t.exception.all(() => openBlindStoreGenerationFloor(symlinkRoot, {
    manifestKey: KEY,
    storeIdentity: IDENTITY,
    storeEvidence: first,
    allowCreate: true,
    creationProof: { freshStoreBindingCreated: true }
  }), /canonical, private, owner-controlled/)

  const parentBase = await privateTemp(path.join(os.tmpdir(), 'blind-generation-symlink-parent-'))
  t.teardown(() => rm(parentBase, { recursive: true, force: true }))
  const realParent = path.join(parentBase, 'real-parent')
  const linkedParent = path.join(parentBase, 'linked-parent')
  await mkdir(realParent, { mode: 0o700 })
  await symlink(realParent, linkedParent)
  const escapedChild = path.join(linkedParent, 'must-not-create')
  await t.exception.all(() => openBlindStoreGenerationFloor(escapedChild, {
    manifestKey: KEY,
    storeIdentity: IDENTITY,
    storeEvidence: first,
    allowCreate: true,
    creationProof: { freshStoreBindingCreated: true }
  }), /ENOENT|no such file/i)
  await t.exception.all(() => stat(path.join(realParent, 'must-not-create')), /ENOENT/)
})

test('records, heads, registrations, and triggers require closed schemas and canonical raw bytes', async t => {
  const duplicateRecord = await freshFloorRoot(t, 'blind-generation-duplicate-record-')
  const recordPath = recordFile(duplicateRecord.root, 1)
  const canonicalRecord = (await readFile(recordPath)).toString('utf8')
  await writeFile(recordPath, `{"sequence":999,${canonicalRecord.slice(1)}`)
  await t.exception.all(() => openBlindStoreGenerationFloor(duplicateRecord.root, duplicateRecord.options), /not canonical/)

  const duplicateHead = await freshFloorRoot(t, 'blind-generation-duplicate-head-')
  const headPath = path.join(duplicateHead.root, BLIND_STORE_GENERATION.headFile)
  const canonicalHead = (await readFile(headPath)).toString('utf8')
  await writeFile(headPath, `{"sequence":999,${canonicalHead.slice(1)}`)
  await t.exception.all(() => openBlindStoreGenerationFloor(duplicateHead.root, duplicateHead.options), /not canonical/)

  const outer = await freshFloorRoot(t, 'blind-generation-outer-field-')
  const outerPath = recordFile(outer.root, 1)
  const outerBody = await readSignedBody(outerPath)
  outerBody.unknown = true
  await writeFile(outerPath, signedBytes(outerBody))
  await t.exception.all(() => openBlindStoreGenerationFloor(outer.root, outer.options), /invalid.*chain/)

  const registration = await freshFloorRoot(t, 'blind-generation-registration-field-')
  const registrationPath = recordFile(registration.root, 1)
  const registrationBody = await readSignedBody(registrationPath)
  registrationBody.registrationUpdates[0].unknown = true
  await writeFile(registrationPath, signedBytes(registrationBody))
  await t.exception.all(() => openBlindStoreGenerationFloor(registration.root, registration.options), /invalid store registration/)

  const trigger = await freshFloorRoot(t, 'blind-generation-trigger-field-')
  const triggerFloor = await openBlindStoreGenerationFloor(trigger.root, trigger.options)
  await triggerFloor.acknowledgeBlindOnlyWrite(second)
  const triggerPath = recordFile(trigger.root, 2)
  const triggerBody = await readSignedBody(triggerPath)
  triggerBody.trigger.unknown = true
  await writeFile(triggerPath, signedBytes(triggerBody))
  await t.exception.all(() => openBlindStoreGenerationFloor(trigger.root, {
    ...trigger.options,
    storeEvidence: second
  }), /invalid generation trigger/)

  const head = await freshFloorRoot(t, 'blind-generation-head-field-')
  const strictHeadPath = path.join(head.root, BLIND_STORE_GENERATION.headFile)
  const headBody = await readSignedBody(strictHeadPath)
  headBody.unknown = true
  await writeFile(strictHeadPath, signedBytes(headBody))
  await t.exception.all(() => openBlindStoreGenerationFloor(head.root, head.options), /invalid.*head/)
})

test('final authority files reject symlinks, oversized content, and unrelated hardlinks', async t => {
  const recordSymlink = await freshFloorRoot(t, 'blind-generation-record-symlink-')
  const record = recordFile(recordSymlink.root, 1)
  const recordTarget = path.join(recordSymlink.root, 'record-target')
  await rename(record, recordTarget)
  await symlink(recordTarget, record)
  await t.exception.all(() => openBlindStoreGenerationFloor(recordSymlink.root, recordSymlink.options), /invalid.*record/)

  const headSymlink = await freshFloorRoot(t, 'blind-generation-head-symlink-')
  const head = path.join(headSymlink.root, BLIND_STORE_GENERATION.headFile)
  const headTarget = path.join(headSymlink.root, 'head-target')
  await rename(head, headTarget)
  await symlink(headTarget, head)
  await t.exception.all(() => openBlindStoreGenerationFloor(headSymlink.root, headSymlink.options), /invalid.*head/)

  const oversized = await freshFloorRoot(t, 'blind-generation-oversized-record-')
  await writeFile(recordFile(oversized.root, 1), Buffer.alloc(1024 * 1024 + 1, 0x20))
  await t.exception.all(() => openBlindStoreGenerationFloor(oversized.root, oversized.options), /invalid.*record/)

  const multiLink = await freshFloorRoot(t, 'blind-generation-multilink-head-')
  const multiHead = path.join(multiLink.root, BLIND_STORE_GENERATION.headFile)
  await link(multiHead, path.join(multiLink.root, 'unrelated-head-hardlink'))
  await t.exception.all(() => openBlindStoreGenerationFloor(multiLink.root, multiLink.options), /invalid.*head/)
})

function isRecordName (name) { return /^blind-store-generation-record-[0-9]{16}-v2\.json$/.test(name) }
