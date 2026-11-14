import test from 'brittle'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { chmod, link, mkdtemp, readFile, readdir, realpath, rename, rm, symlink, unlink, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import {
  BLIND_GENERATION_INSPECTION_LIMITS,
  BLIND_STORE_GENERATION,
  BLIND_STORE_GENERATION_CAPABILITIES,
  inspectBlindStoreGenerationFloor,
  openBlindStoreGenerationFloor
} from '../storage-generation-v12.js'
import { KEY, IDENTITY, first, second, floorOptions, recordFile, canonicalBytes, digest, signedBytes, signedBody, inventory } from './generation-inspection-fixture.mjs'

async function privateRoot (t) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'generation-inspection-')))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  return root
}

async function fresh (t, options = floorOptions()) {
  const root = await privateRoot(t)
  const floor = await openBlindStoreGenerationFloor(root, { ...options, allowCreate: true, creationProof: { freshStoreBindingCreated: true } })
  return { root, floor, options }
}

async function unchanged (t, name, root, run) {
  const before = await inventory(root)
  let result
  try {
    result = await run()
  } finally {
    const after = await inventory(root)
    t.alike(after, before, `${name}: exact content, entries and metadata unchanged`)
    t.comment(JSON.stringify({ fixture: name, beforeSha256: digest(canonicalBytes(before)), afterSha256: digest(canonicalBytes(after)), entries: before.entries.length, before, after }))
  }
  return result
}

function frozen (value) {
  if (!value || typeof value !== 'object') return true
  return Object.isFrozen(value) && Object.values(value).every(frozen)
}

test('inspection observes pre/post-trigger authority without granting a writer or durability receipt', async t => {
  const { root, floor, options } = await fresh(t)
  const capabilities = JSON.stringify(BLIND_STORE_GENERATION_CAPABILITIES)
  const before = await unchanged(t, 'valid-pre-trigger', root, () => inspectBlindStoreGenerationFloor(root, options))
  t.is(before.observed.firstIrreversibleWriteAcknowledged, false)
  t.is(before.observed.sequence, 1)
  t.is(before.observed.registrations.length, 1)
  t.alike(before.requiredRecoveryActions, [])
  t.ok(frozen(before))
  await t.exception.all(() => { before.observed.registrations[0].storeEvidence.walHash = 'changed' }, /read only/)
  await t.exception.all(() => before.requiredRecoveryActions.push({ kind: 'create' }), /extensible/)
  t.is(before.writerAuthority, false)
  t.is(before.durabilityProven, false)
  t.is(before.requiresOwnershipRevalidation, true)
  t.is(before.storeEvidenceSource, 'caller-supplied')
  for (const name of ['acknowledgeWrite', 'assertWritable', 'triggerReceipt']) t.absent(before[name])

  await floor.acknowledgeBlindOnlyWrite(second)
  const current = floorOptions({ storeEvidence: second })
  const after = await unchanged(t, 'valid-post-trigger', root, () => inspectBlindStoreGenerationFloor(root, current))
  const opened = await openBlindStoreGenerationFloor(root, current)
  t.is(after.observed.firstIrreversibleWriteAcknowledged, opened.firstIrreversibleWriteAcknowledged)
  t.is(after.observed.sequence, opened.trigger.generationSequence)
  t.is(after.observed.trigger.role, opened.trigger.role)
  t.ok(frozen(after))
  t.is(JSON.stringify(BLIND_STORE_GENERATION_CAPABILITIES), capabilities)
})

test('inspection copies asynchronous inputs and returns no secret or mutable byte buffers', async t => {
  const { root } = await fresh(t)
  const key = Buffer.from(KEY)
  const identity = Buffer.from(IDENTITY)
  const hash = Buffer.from(first.walHash)
  const promise = inspectBlindStoreGenerationFloor(root, floorOptions({ manifestKey: key, storeIdentity: identity, storeEvidence: { walSequence: 1n, walHash: hash } }))
  key.fill(0)
  identity.fill(0)
  hash.fill(0)
  const snapshot = await promise
  t.is(snapshot.observed.sequence, 1)
  t.ok(frozen(snapshot))
  t.absent(snapshot.manifestKey)
  t.absent(snapshot.storeIdentity)
  t.ok(JSON.stringify(snapshot).length > 0, 'snapshot contains ordinary immutable data only')
})

test('missing evidence and creation options never create a floor', async t => {
  const root = await privateRoot(t)
  await unchanged(t, 'missing-authority', root, async () => {
    await t.exception.all(() => inspectBlindStoreGenerationFloor(root, floorOptions()), { code: 'BLIND_STORE_GENERATION_MISSING' })
    await t.exception.all(() => inspectBlindStoreGenerationFloor(root, floorOptions({ allowCreate: true, creationProof: { freshStoreBindingCreated: true } })), /unknown generation inspection option/)
  })
  t.alike(await readdir(root), [])
})

test('missing and lagging heads and orphan temps are described without repair', async t => {
  for (const kind of ['missing-head', 'lagging-head', 'partial-orphan']) {
    const { root, floor, options } = await fresh(t)
    const head = path.join(root, BLIND_STORE_GENERATION.headFile)
    let inspectOptions = options
    if (kind === 'missing-head') await unlink(head)
    if (kind === 'lagging-head') {
      const prior = await readFile(head)
      await floor.acknowledgeBlindOnlyWrite(second)
      await writeFile(head, prior)
      inspectOptions = floorOptions({ storeEvidence: second })
    }
    const temporary = `.blind-store-generation-head.tmp-${'ab'.repeat(16)}`
    if (kind === 'partial-orphan') await writeFile(path.join(root, temporary), '{', { mode: 0o600 })
    const inspected = await unchanged(t, kind, root, () => inspectBlindStoreGenerationFloor(root, inspectOptions))
    if (kind === 'partial-orphan') {
      t.alike(inspected.requiredRecoveryActions, [])
      t.alike(inspected.observed.retainedTemporaries, [temporary])
    } else {
      t.is(inspected.requiredRecoveryActions[0].kind, 'repair-head')
      t.is(inspected.requiredRecoveryActions[0].reason, kind === 'missing-head' ? 'missing' : 'lagging')
    }
    const reopened = await openBlindStoreGenerationFloor(root, inspectOptions)
    t.is(reopened.firstIrreversibleWriteAcknowledged, inspected.observed.firstIrreversibleWriteAcknowledged)
    t.is((await inspectBlindStoreGenerationFloor(root, inspectOptions)).requiredRecoveryActions.length, 0)
  }
})

test('published record hardlink temp is retained until the separate mutable opener recovers', async t => {
  const { root, options } = await fresh(t)
  const temporary = `.blind-store-generation-record.tmp-${'bc'.repeat(16)}`
  await link(recordFile(root, 1), path.join(root, temporary))
  const observed = await unchanged(t, 'record-linked-temporary', root, () => inspectBlindStoreGenerationFloor(root, options))
  t.alike(observed.requiredRecoveryActions, [{ kind: 'remove-linked-record-temporary', name: temporary, record: path.basename(recordFile(root, 1)) }])
  t.ok(frozen(observed.requiredRecoveryActions))
  await openBlindStoreGenerationFloor(root, options)
  t.absent((await readdir(root)).includes(temporary))
})

test('pre-trigger proposed registrations and conservative trigger never change observed history', async t => {
  const cell = { role: 'cell', storeIdentity: Buffer.from('cell'), storeEvidence: first }
  const inbox = { role: 'inbox', storeIdentity: Buffer.from('inbox'), storeEvidence: second, hasIrreversibleState: true }
  const options = { manifestKey: KEY, installationIdentity: IDENTITY, currentStores: [cell] }
  const { root } = await fresh(t, options)
  const current = { ...options, currentStores: [inbox, { ...cell, storeEvidence: second, hasIrreversibleState: true }] }
  const observed = await unchanged(t, 'proposed-role-and-trigger', root, () => inspectBlindStoreGenerationFloor(root, current))
  t.alike(observed.requiredRecoveryActions.map(action => action.kind), ['register-store', 'record-conservative-trigger'])
  t.is(observed.requiredRecoveryActions[1].trigger.role, 'cell', 'the same deterministic role ordering as mutable recovery')
  t.is(observed.observed.registrations.length, 1)
  t.is(observed.observed.firstIrreversibleWriteAcknowledged, false)
  t.is(observed.observed.trigger, null)
  const opened = await openBlindStoreGenerationFloor(root, current)
  t.is(opened.firstIrreversibleWriteAcknowledged, true)
  t.is(opened.trigger.role, 'cell')
  const settled = await inspectBlindStoreGenerationFloor(root, current)
  t.is(settled.observed.registrations.length, 2)
  t.alike(settled.requiredRecoveryActions, [])
})

test('baseline advance and pre-trigger subset match mutable validation', async t => {
  const stores = ['cell', 'inbox'].map(role => ({ role, storeIdentity: Buffer.from(role), storeEvidence: first }))
  const options = { manifestKey: KEY, installationIdentity: IDENTITY, currentStores: stores }
  const { root } = await fresh(t, options)
  const subset = { ...options, currentStores: [{ ...stores[0], storeEvidence: second }] }
  const observed = await unchanged(t, 'baseline-advance-subset', root, () => inspectBlindStoreGenerationFloor(root, subset))
  t.alike(observed.requiredRecoveryActions.map(action => action.kind), ['advance-registrations'])
  await openBlindStoreGenerationFloor(root, subset)
  t.alike((await inspectBlindStoreGenerationFloor(root, subset)).requiredRecoveryActions, [])
})

test('foreign authority and malformed persistent evidence reject without cleanup', async t => {
  const cases = [
    ['foreign-key', async () => floorOptions({ manifestKey: Buffer.alloc(32, 9) })],
    ['foreign-installation', async () => floorOptions({ storeIdentity: Buffer.from('foreign') })],
    ['wrong-mac', async root => { const file = recordFile(root, 1); const body = JSON.parse(await readFile(file)); body.mac = '00'.repeat(32); await writeFile(file, canonicalBytes(body)) }],
    ['noncanonical', async root => { const file = recordFile(root, 1); await writeFile(file, JSON.stringify(JSON.parse(await readFile(file)), null, 2) + '\n') }],
    ['extra-field', async root => { const file = recordFile(root, 1); await writeFile(file, signedBytes({ ...await signedBody(file), extra: true })) }],
    ['gapped-records', root => rename(recordFile(root, 1), recordFile(root, 3))],
    ['malformed-name', root => writeFile(path.join(root, 'blind-store-generation-record-bad-v2.json'), '{}', { mode: 0o600 })],
    ['predecessor', root => writeFile(path.join(root, 'blind-store-generation-head-v1.json'), '{}', { mode: 0o600 })],
    ['unsafe-mode', root => chmod(recordFile(root, 1), 0o644)],
    ['head-only', async root => { await unlink(recordFile(root, 0)); await unlink(recordFile(root, 1)) }],
    ['head-ahead', async root => { const file = path.join(root, BLIND_STORE_GENERATION.headFile); await writeFile(file, signedBytes({ ...await signedBody(file), sequence: 9 })) }],
    ['wrong-link', root => link(recordFile(root, 1), path.join(root, 'not-a-record-temporary'))],
    ['final-symlink', async root => { await rename(recordFile(root, 1), path.join(root, 'saved')); await symlink('saved', recordFile(root, 1)) }],
    ['unsafe-temporary', async root => { await writeFile(path.join(root, `.blind-store-generation-head.tmp-${'aa'.repeat(16)}`), '{', { mode: 0o644 }) }]
  ]
  for (const [name, prepare] of cases) {
    const { root, options } = await fresh(t)
    const replacement = await prepare(root)
    const current = replacement && typeof replacement === 'object' ? replacement : options
    await unchanged(t, name, root, () => t.exception.all(() => inspectBlindStoreGenerationFloor(root, current)))
    await t.exception.all(() => openBlindStoreGenerationFloor(root, current), undefined, `${name}: existing opener also refuses`)
  }
})

test('post-trigger role and WAL evidence must match the existing validation contract', async t => {
  const stores = ['cell', 'inbox'].map(role => ({ role, storeIdentity: Buffer.from(role), storeEvidence: first }))
  const options = { manifestKey: KEY, installationIdentity: IDENTITY, currentStores: stores }
  const { root, floor } = await fresh(t, options)
  await floor.acknowledgeWrite({ role: 'cell', storeEvidence: second })
  const current = [{ ...stores[0], storeEvidence: second }, stores[1]]
  const variants = [
    ['missing-role', [current[0]]],
    ['added-role', [...current, { role: 'core', storeIdentity: Buffer.from('core'), storeEvidence: first }]],
    ['changed-store', [{ ...current[0], storeIdentity: Buffer.from('changed') }, current[1]]],
    ['rollback', stores],
    ['equal-sequence-wrong-hash', [{ ...current[0], storeEvidence: { walSequence: 2n, walHash: Buffer.alloc(32, 3) } }, current[1]]]
  ]
  for (const [name, currentStores] of variants) {
    const input = { ...options, currentStores }
    await unchanged(t, name, root, () => t.exception.all(() => inspectBlindStoreGenerationFloor(root, input)))
    await t.exception.all(() => openBlindStoreGenerationFloor(root, input))
  }
})

test('inspection enforces entry, record, individual-file and total-read budgets before expansion', async t => {
  const { root, options } = await fresh(t)
  await writeFile(path.join(root, 'unrelated-control-entry'), 'unrelated')
  const orphan = `.blind-store-generation-record.tmp-${'ef'.repeat(16)}`
  await writeFile(path.join(root, orphan), '{', { mode: 0o600 })
  const snapshot = await inspectBlindStoreGenerationFloor(root, options)
  const exact = { maxEntries: snapshot.usage.entries, maxRecords: snapshot.usage.records, maxFileBytes: Math.max(...snapshot.observed.files.map(file => file.bytes)), maxTotalBytes: snapshot.usage.bytesRead }
  const bounded = await unchanged(t, 'exact-budgets', root, () => inspectBlindStoreGenerationFloor(root, { ...options, limits: exact }))
  t.is(bounded.usage.entries, 5, 'unrelated entries and partial temps count toward the namespace ceiling')
  for (const key of Object.keys(exact)) {
    await unchanged(t, `limit-${key}`, root, () => t.exception.all(() => inspectBlindStoreGenerationFloor(root, { ...options, limits: { ...exact, [key]: exact[key] - 1 } }), { code: 'BLIND_STORE_GENERATION_INSPECTION_LIMIT' }))
  }
  for (const limits of [{ maxEntries: 0 }, { maxRecords: Infinity }, { maxTotalBytes: 1.5 }, { maxEntries: BLIND_GENERATION_INSPECTION_LIMITS.maxEntries + 1 }, { surprise: 1 }]) {
    await t.exception.all(() => inspectBlindStoreGenerationFloor('/not-opened', { ...options, limits }), /inspection/)
  }
  const beforeHandles = (await readdir('/dev/fd')).length
  for (let index = 0; index < 40; index++) {
    await t.exception.all(() => inspectBlindStoreGenerationFloor(root, { ...options, limits: { maxEntries: 1 } }))
    await inspectBlindStoreGenerationFloor(root, options)
  }
  const afterHandles = (await readdir('/dev/fd')).length
  t.is(afterHandles, beforeHandles, 'success and early overflow paths release their filesystem handles')
  t.comment(JSON.stringify({ fixture: 'handles', beforeHandles, afterHandles, iterations: 40, maxOpenHandles: snapshot.usage.maxOpenHandles }))
})

test('real process interruption leaves inspectable evidence without publication or cleanup', async t => {
  for (const phase of ['after-record-temp-partial', 'after-record-temp-sync', 'before-record-directory-sync', 'after-record-link', 'after-record-sync', 'after-head-temp-sync']) {
    const { root } = await fresh(t)
    const child = spawn(process.execPath, [new URL('generation-inspection-fixture.mjs', import.meta.url).pathname, 'kill-at-phase', root, phase], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] })
    let stderr = ''
    child.stderr.on('data', bytes => { stderr += bytes })
    const exit = once(child, 'exit')
    let timer
    try {
      const reached = await Promise.race([
        once(child, 'message').then(([message]) => message),
        exit.then(() => { throw new Error(`fixture exited before ${phase}: ${stderr}`) }),
        new Promise((resolve, reject) => { timer = setTimeout(() => reject(new Error(`fixture timed out: ${phase}`)), 10000) })
      ])
      t.is(reached.point, phase)
    } finally {
      clearTimeout(timer)
      child.kill('SIGKILL')
      await exit
    }
    const published = (await readdir(root)).includes(path.basename(recordFile(root, 2)))
    const options = floorOptions({ storeEvidence: second, hasIrreversibleState: true })
    const observed = await unchanged(t, `kill-${phase}`, root, () => inspectBlindStoreGenerationFloor(root, options))
    t.is(observed.observed.firstIrreversibleWriteAcknowledged, published)
    if (!published) t.ok(observed.requiredRecoveryActions.some(action => action.kind === 'record-conservative-trigger'))
    const restarted = await openBlindStoreGenerationFloor(root, options)
    t.is(restarted.firstIrreversibleWriteAcknowledged, true)
  }
})
