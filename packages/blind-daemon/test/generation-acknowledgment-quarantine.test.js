import test from 'brittle'
import b4a from 'b4a'
import fs from 'node:fs/promises'
import path from 'node:path'
import os from 'node:os'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import {
  FAMILY, OPERATION, FRAME_KIND, TRANSPORT_ID, TRANSPORT_SUPPORT,
  allocationCommitment, blake2b256, cellPutRequestCommitment, cellStorageSlot,
  coreMirrorRequestV1, decodeDispatchFrame, encodeCanonical,
  inboxCreateCommitment, inboxCreateRequestCommitment
} from '@hiverelay/blind-protocol'
import { operationBit } from '@hiverelay/blind-protocol/wire-runtime-authority'
import { openBlindStoreGenerationFloor } from '../storage-generation-v12.js'
import { loadDaemonBootstrapConfig } from '../bootstrap-config.js'
import {
  assembleProductionBlindDaemon, loadProductionRuntimeConfig,
  productionGenerationReadyOperationBits, productionStorageOperationalIntegrity,
  PRODUCTION_DESCRIBE_CELL_INBOX_CORE_OPERATION_BITS
} from '../production-runtime.js'
import { coreMirrorFixture, runtimeCoreFixture } from './production-runtime-core-fixture.js'
import { inboxCreateFixture } from './production-runtime-inbox-fixture.js'
import { removeBlindBoundaryScratch } from '../../../test/blind-boundary-scratch.js'

const KEY = b4a.alloc(32, 0xa1)
const IDENTITY = b4a.from('authenticated-runtime-store-binding')
const evidence = n => ({ walSequence: BigInt(n), walHash: b4a.alloc(32, n) })
const digest = bytes => createHash('sha256').update(bytes).digest('hex')
const turn = () => new Promise(resolve => setImmediate(resolve))

async function floorFixture (t) {
  const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'generation-quarantine-')))
  t.teardown(() => fs.rm(root, { recursive: true, force: true }))
  const options = { manifestKey: KEY, storeIdentity: IDENTITY, storeEvidence: evidence(1) }
  await openBlindStoreGenerationFloor(root, { ...options, allowCreate: true, creationProof: { freshStoreBindingCreated: true } })
  return { root, options }
}

async function generationFiles (root) {
  return Promise.all((await fs.readdir(root)).sort().map(async name => ({ name, sha256: digest(await fs.readFile(path.join(root, name))) })))
}

for (const phase of ['before-record-publication', 'after-record-temp-partial', 'before-record-file-sync', 'after-record-temp-sync', 'before-record-directory-sync']) {
  test(`generation quarantine latches uncertain ${phase} and only reopen may recover`, async t => {
    const { root, options } = await floorFixture(t)
    const floor = await openBlindStoreGenerationFloor(root, {
      ...options,
      faultInjector (seen, context) {
        if (seen === phase && context.sequence === 2) throw new Error(`injected ${phase}`)
      }
    })
    await t.exception.all(() => floor.acknowledgeBlindOnlyWrite(evidence(2)), /reopen required/)
    t.is(floor.writerQuarantineReason, 'BLIND_GENERATION_ACKNOWLEDGMENT_FAILED')
    t.is(floor.firstIrreversibleWriteAcknowledged, false, 'uncertain publication cannot become an acknowledgment')
    t.is(floor.triggerReceipt(), null)
    const before = await generationFiles(root)
    await t.exception.all(() => floor.acknowledgeBlindOnlyWrite(evidence(3)), /reopen required/)
    t.exception(() => floor.assertWritable(), /reopen required/)
    t.alike(await generationFiles(root), before, 'latched retry publishes no record or head')
    const reopened = await openBlindStoreGenerationFloor(root, { ...options, storeEvidence: evidence(2), hasIrreversibleState: true })
    t.is(reopened.firstIrreversibleWriteAcknowledged, true)
    t.is(reopened.writerQuarantineReason, null)
    t.is(reopened.trigger.walSequence, 2n, 'recovery binds the already durable WAL obligation')
  })
}

for (const phase of ['after-record-link', 'after-record-sync', 'after-head-temp-sync']) {
  test(`generation durable record remains acknowledged across recoverable ${phase}`, async t => {
    const { root, options } = await floorFixture(t)
    const floor = await openBlindStoreGenerationFloor(root, {
      ...options,
      faultInjector (seen, context) {
        if (seen === phase && (context == null || context.sequence === 2)) throw new Error(`injected ${phase}`)
      }
    })
    t.is(await floor.acknowledgeBlindOnlyWrite(evidence(2)), true)
    t.is(floor.writerQuarantineReason, null, 'known durable record is distinct from an uncertain publication')
    t.ok(floor.triggerReceipt())
    const reopened = await openBlindStoreGenerationFloor(root, { ...options, storeEvidence: evidence(2), hasIrreversibleState: true })
    t.is(reopened.trigger.walSequence, 2n)
  })
}

test('generation failure rejects both the in-flight batch and later queued acknowledgments', async t => {
  const { root, options } = await floorFixture(t)
  let release
  const blocked = new Promise(resolve => { release = resolve })
  let entered
  const started = new Promise(resolve => { entered = resolve })
  const floor = await openBlindStoreGenerationFloor(root, {
    ...options,
    async faultInjector (phase, context) {
      if (phase === 'before-record-file-sync' && context.sequence === 2) {
        entered()
        await blocked
        throw new Error('injected sync failure')
      }
    }
  })
  const first = floor.acknowledgeBlindOnlyWrite(evidence(2)).catch(error => error)
  await started
  const second = floor.acknowledgeBlindOnlyWrite(evidence(3)).catch(error => error)
  release()
  const errors = await Promise.all([first, second])
  t.is(errors[0].code, 'BLIND_GENERATION_ACKNOWLEDGMENT_FAILED')
  t.is(errors[1], errors[0], 'one latched failure settles later queued acknowledgments too')
  t.is(floor.firstIrreversibleWriteAcknowledged, false)
})

for (const phase of ['after-record-temp-partial', 'after-record-temp-sync', 'before-record-directory-sync', 'after-record-link', 'after-record-sync', 'after-head-temp-sync']) {
  test(`generation kill at ${phase} reopens from exact published evidence`, async t => {
    const { root, options } = await floorFixture(t)
    const child = spawn(process.execPath, [new URL('storage-generation-kill-fixture.mjs', import.meta.url).pathname, root, phase], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'] })
    t.teardown(() => { if (child.exitCode == null) child.kill('SIGKILL') })
    await once(child, 'message')
    const exited = once(child, 'exit')
    child.kill('SIGKILL')
    await exited
    const before = await generationFiles(root)
    t.ok(before.length >= 3, 'kill retains the generation evidence rather than erasing it')
    const reopened = await openBlindStoreGenerationFloor(root, { ...options, storeEvidence: evidence(2), hasIrreversibleState: true })
    t.is(reopened.firstIrreversibleWriteAcknowledged, true)
    t.is(reopened.trigger.walSequence, 2n)
    for (const file of before.filter(file => /generation-record-[0-9]/.test(file.name))) {
      t.is(digest(await fs.readFile(path.join(root, file.name))), file.sha256, 'existing committed record bytes remain exact')
    }
  })
}

for (const role of ['cell', 'inbox', 'core']) {
  test(`shared quarantine fences already queued ${role} WAL admission after another family fails`, async t => {
    const fixture = await runtimeCoreFixture()
    t.teardown(() => removeBlindBoundaryScratch(fixture.directory))
    const runtime = await assemble(fixture)
    t.teardown(() => runtime.close())
    const binding = runtime.descriptorState.resultBinding(runtime.descriptorState.state().snapshot)
    const cell = cellInput(fixture, binding)
    const inbox = inboxInput(fixture, binding)
    const core = mirrorFrame(fixture)
    const engine = { cell: runtime.storage, inbox: runtime.inboxStorage, core: runtime.coreStorage }[role]
    let release
    let entered
    const held = new Promise(resolve => { release = resolve })
    const enteredBarrier = new Promise(resolve => { entered = resolve })
    const barrier = engine.transactionStore.withWalBarrier(async () => { entered(); await held })
    await enteredBarrier
    let enqueued
    const queued = new Promise(resolve => { enqueued = resolve })
    const append = engine.transactionStore.appendAndApply
    engine.transactionStore.appendAndApply = function (...args) {
      const pending = append.apply(this, args)
      enqueued()
      return pending
    }
    const pending = (role === 'cell'
      ? runtime.storage.putCell(cell)
      : role === 'inbox'
        ? runtime.inboxStorage.createInbox(inbox)
        : runtime.coordinator.dispatch(core, context())).catch(error => error)
    await queued
    await fs.writeFile(path.join(runtime.storage.transactionStore.controlDirectory,
      'blind-store-generation-invalid-test-evidence'), 'owned failure fixture\n', { mode: 0o600 })
    if (role === 'cell') await t.exception.all(() => runtime.inboxStorage.createInbox(inbox), /reopen required/)
    else await t.exception.all(() => runtime.storage.putCell(cell), /reopen required/)
    const atFailure = await walSnapshot(runtime)
    release()
    await barrier
    const result = await pending
    if (role === 'core') t.is(decodeDispatchFrame(result.dispatch).frameKind, FRAME_KIND.ERROR)
    else t.is(result.code, 'BLIND_GENERATION_ACKNOWLEDGMENT_FAILED')
    t.alike(await walSnapshot(runtime), atFailure, 'queued writer crossed no WAL boundary after the shared failure')
    t.is(engine.transactionStore.poisoned, false, 'prewrite refusal leaves the verified WAL intact')
  })
}

for (const phase of ['before-floor-acknowledgment', 'after-floor-acknowledgment']) {
  test(`real CELL process kill ${phase} retains committed payload and monotone floor on reopen`, async t => {
    const fixture = await runtimeCoreFixture()
    t.teardown(() => removeBlindBoundaryScratch(fixture.directory))
    let runtime = await assemble(fixture)
    const binding = runtime.descriptorState.resultBinding(runtime.descriptorState.state().snapshot)
    const cell = cellInput(fixture, binding)
    const before = await walSnapshot(runtime)
    await runtime.close()
    const child = spawn(process.execPath, [new URL('storage-generation-kill-fixture.mjs', import.meta.url).pathname,
      '--production-cell', phase], { stdio: ['ignore', 'ignore', 'inherit', 'ipc'], serialization: 'advanced' })
    t.teardown(() => { if (child.exitCode == null) child.kill('SIGKILL') })
    const ready = once(child, 'message')
    child.send({ environment: Object.fromEntries(Object.entries(fixture.environment).filter(([key]) => key.startsWith('HIVERELAY_'))), cell })
    await ready
    const exited = once(child, 'exit')
    child.kill('SIGKILL')
    await exited
    runtime = await assemble(fixture)
    t.teardown(() => runtime.close())
    t.ok(BigInt((await walSnapshot(runtime))[0].sequence) > BigInt(before[0].sequence), 'real CELL WAL committed before process death')
    t.alike((await runtime.storage.readCell(cell.request.storageSlot)).cellBlob, cell.source)
    t.is(runtime.storage.status().writerQuarantineReason, null)
    const records = await generationFiles(runtime.storage.transactionStore.controlDirectory)
    t.ok(records.some(file => /generation-record-/.test(file.name)))
    const replay = await runtime.storage.putCell(cell)
    t.is(replay.replay, true, 'reopened validated floor authorizes the exact committed replay')
  })
}

function admissionAdapter () {
  const preflights = new WeakSet()
  const prepared = input => Object.freeze({ spendTag: blake2b256(input.admission.token), requestCommitment: b4a.from(input.requestCommitment), costClass: { ...input.costClass }, walCommitRecord: b4a.from(input.admission.token), profileId: input.admission.profileId, schemeId: input.admission.schemeId, parameterHash: b4a.from(input.admission.parameterHash) })
  return {
    async prepare (input) { return prepared(input) },
    async preparePreflight () { const token = {}; preflights.add(token); return token },
    async confirmAfterEof (input) {
      if (!preflights.delete(input.adapterPreflight)) throw new Error('unknown test admission preflight')
      return prepared(input)
    }
  }
}

async function assemble (fixture) {
  // These tests assemble the daemon without listening. Keep the unused socket
  // addresses portable even when the owned worktree path is very long.
  const socketRoot = `/tmp/gq-${digest(fixture.directory).slice(0, 12)}`
  const environment = {
    ...fixture.environment,
    HIVERELAY_BLIND_UNARY_SOCKET: `${socketRoot}/unary.sock`,
    HIVERELAY_BLIND_STREAM_SOCKET: `${socketRoot}/stream.sock`
  }
  const bootstrap = loadDaemonBootstrapConfig(environment)
  return assembleProductionBlindDaemon({
    bootstrap: { ...bootstrap, expectedPeerUid: process.getuid() },
    runtimeConfig: loadProductionRuntimeConfig(environment, bootstrap.endpointIds),
    enableCellRuntime: true,
    enableInboxRuntime: true,
    enableCoreRuntime: true,
    resolveAdmissionAdapter: async () => admissionAdapter(),
    releaseGate: async () => {}
  })
}

function keyPair () {
  const pair = generateKeyPairSync('ed25519')
  const encoded = pair.publicKey.export({ format: 'der', type: 'spki' })
  return { privateKey: pair.privateKey, publicKey: b4a.from(encoded.subarray(-32)) }
}

function prepared (requestCommitment, byte, leaseClass) {
  return { spendTag: b4a.alloc(32, byte), requestCommitment, profileId: 7, schemeId: 9, parameterHash: b4a.alloc(32, 0x92), costClass: { resourceClass: 1, leaseClass, costUnits: 1n }, walCommitRecord: b4a.alloc(32, 0x93) }
}

function cellInput (fixture, resultBinding) {
  const keys = { create: keyPair(), renew: keyPair(), drop: keyPair() }
  const cellBlob = b4a.alloc(4096, 0x81)
  const request = { version: 1, allocationEpoch: fixture.currentEpoch, sizeClass: 1, leaseClass: 1, clientNonce: b4a.alloc(32, 0x82), createPublicKey: keys.create.publicKey, renewPublicKey: keys.renew.publicKey, dropPublicKey: keys.drop.publicKey, declaredBlobHash: blake2b256(cellBlob) }
  request.storageSlot = cellStorageSlot(request)
  const allocation = allocationCommitment({ ...request, relayPublicKey: fixture.relayPublicKey, declaredCellBlobHash: request.declaredBlobHash })
  request.createSignature = sign(null, allocation, keys.create.privateKey)
  const commitment = cellPutRequestCommitment({ allocationCommitment: allocation, clientNonce: request.clientNonce })
  return { request, source: cellBlob, preparedAdmission: prepared(commitment, 0x84, request.leaseClass), resultBinding }
}

function inboxInput (fixture, resultBinding) {
  const { request } = inboxCreateFixture(fixture.relayPublicKey, fixture.parameterHash, fixture.currentEpoch)
  const commitment = inboxCreateRequestCommitment({ inboxCreateCommitment: inboxCreateCommitment({ ...request, relayPublicKey: fixture.relayPublicKey }), clientNonce: request.clientNonce })
  return { request, requestCommitment: commitment, preparedAdmission: prepared(commitment, 0x85, request.leaseClass), resultBinding }
}

function mirrorFrame (fixture) {
  return { frameKind: FRAME_KIND.REQUEST, familyId: FAMILY.CORE, operationId: OPERATION.CORE.MIRROR, requestId: b4a.alloc(16, 0x89), body: encodeCanonical(coreMirrorRequestV1, coreMirrorFixture(fixture.parameterHash)) }
}

function context () {
  const now = process.hrtime.bigint() / 1_000_000n
  return { endpointId: 1, transportId: TRANSPORT_ID.HTTPS_DIRECT, transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP, outerClass: null, acceptedMonotonicMillis: now, absoluteDeadlineMonotonicMillis: now + 15000n }
}

async function walSnapshot (runtime) {
  return Promise.all([runtime.storage, runtime.inboxStorage, runtime.coreStorage].map(async engine => ({ sequence: String(engine.transactionStore.walSequence), sha256: digest(await fs.readFile(engine.transactionStore.walPath)) })))
}

test('cached charged CELL result queued behind a lock cannot replay after a shared INBOX failure', async t => {
  const fixture = await runtimeCoreFixture()
  t.teardown(() => removeBlindBoundaryScratch(fixture.directory))
  const runtime = await assemble(fixture)
  t.teardown(() => runtime.close())
  const resultBinding = runtime.descriptorState.resultBinding(runtime.descriptorState.state().snapshot)
  const requestCommitment = b4a.alloc(32, 0x97)
  const read = {
    operationId: OPERATION.CELL.BATCH_GET,
    request: { slots: [b4a.alloc(32, 0x98)] },
    requestCommitment,
    preparedAdmission: prepared(requestCommitment, 0x99, 0),
    resultBinding
  }
  const pinned = await runtime.storage.chargedCellRead(read)
  const finalize = { spendTag: pinned.spendTag, requestCommitment, resultCommitment: b4a.alloc(32, 0x9a) }
  await runtime.storage.finalizeChargedCellRead(finalize)
  t.is((await runtime.storage.chargedCellRead(read)).replay, true, 'fixture has a genuine durable charged result')
  let release
  let entered
  const held = new Promise(resolve => { release = resolve })
  const enteredLock = new Promise(resolve => { entered = resolve })
  const lock = runtime.storage.transactionStore.withLocks([`spend:${b4a.toString(pinned.spendTag, 'hex')}`], async () => { entered(); await held })
  await enteredLock
  const replay = runtime.storage.chargedCellRead(read).catch(error => error)
  const finalReplay = runtime.storage.finalizeChargedCellRead(finalize).catch(error => error)
  await turn()
  await fs.writeFile(path.join(runtime.storage.transactionStore.controlDirectory,
    'blind-store-generation-invalid-test-evidence'), 'owned failure fixture\n', { mode: 0o600 })
  await t.exception.all(() => runtime.inboxStorage.createInbox(inboxInput(fixture, resultBinding)), /reopen required/)
  const atFailure = await walSnapshot(runtime)
  release()
  await lock
  t.is((await replay).code, 'BLIND_GENERATION_ACKNOWLEDGMENT_FAILED')
  t.is((await finalReplay).code, 'BLIND_GENERATION_ACKNOWLEDGMENT_FAILED')
  await t.exception.all(() => runtime.storage.chargedCellReadState(read), /reopen required/)
  t.alike(await walSnapshot(runtime), atFailure)
})

test('concurrent real CELL INBOX CORE admission cannot return success after the first shared publication failure', async t => {
  const fixture = await runtimeCoreFixture()
  t.teardown(() => removeBlindBoundaryScratch(fixture.directory))
  const runtime = await assemble(fixture)
  t.teardown(() => runtime.close())
  const binding = runtime.descriptorState.resultBinding(runtime.descriptorState.state().snapshot)
  const cell = cellInput(fixture, binding)
  const inbox = inboxInput(fixture, binding)
  const core = mirrorFrame(fixture)
  await fs.writeFile(path.join(runtime.storage.transactionStore.controlDirectory,
    'blind-store-generation-invalid-test-evidence'), 'owned failure fixture\n', { mode: 0o600 })
  const results = await Promise.all([
    runtime.storage.putCell(cell).catch(error => error),
    runtime.inboxStorage.createInbox(inbox).catch(error => error),
    runtime.coordinator.dispatch(core, context())
  ])
  t.is(results[0].code, 'BLIND_GENERATION_ACKNOWLEDGMENT_FAILED')
  t.is(results[1].code, 'BLIND_GENERATION_ACKNOWLEDGMENT_FAILED')
  t.is(decodeDispatchFrame(results[2].dispatch).frameKind, FRAME_KIND.ERROR)
  const atFailure = await walSnapshot(runtime)
  await t.exception.all(() => runtime.storage.putCell(cell), /reopen required/)
  await t.exception.all(() => runtime.inboxStorage.createInbox(inbox), /reopen required/)
  await t.exception.all(() => runtime.coreStorage.acceptMirror({}), /reopen required/)
  t.alike(await walSnapshot(runtime), atFailure)
})

for (const role of ['cell', 'inbox', 'core']) {
  test(`actual production assembly quarantines every writer after ${role} acknowledgment failure`, async t => {
    const fixture = await runtimeCoreFixture()
    t.teardown(() => removeBlindBoundaryScratch(fixture.directory))
    let runtime = await assemble(fixture)
    t.teardown(() => runtime.close())
    const binding = runtime.descriptorState.resultBinding(runtime.descriptorState.state().snapshot)
    const cell = cellInput(fixture, binding)
    const inbox = inboxInput(fixture, binding)
    const core = mirrorFrame(fixture)
    const invalid = path.join(runtime.storage.transactionStore.controlDirectory, 'blind-store-generation-invalid-test-evidence')
    await fs.writeFile(invalid, 'owned failure fixture\n', { mode: 0o600 })
    const before = await walSnapshot(runtime)
    if (role === 'cell') await t.exception.all(() => runtime.storage.putCell(cell), /reopen required/)
    if (role === 'inbox') await t.exception.all(() => runtime.inboxStorage.createInbox(inbox), /reopen required/)
    if (role === 'core') t.is(decodeDispatchFrame((await runtime.coordinator.dispatch(core, context())).dispatch).frameKind, FRAME_KIND.ERROR)
    const failed = await walSnapshot(runtime)
    const index = ['cell', 'inbox', 'core'].indexOf(role)
    t.ok(BigInt(failed[index].sequence) > BigInt(before[index].sequence), 'real family WAL committed before the acknowledgment failed')
    for (const engine of [runtime.storage, runtime.inboxStorage, runtime.coreStorage]) {
      t.is(engine.status().writerQuarantineReason, 'BLIND_GENERATION_ACKNOWLEDGMENT_FAILED')
    }
    await t.exception.all(() => runtime.storage.putCell(cell), /reopen required/)
    await t.exception.all(() => runtime.inboxStorage.createInbox(inbox), /reopen required/)
    await t.exception.all(() => runtime.coreStorage.acceptMirror({}), /reopen required/)
    await t.exception.all(() => runtime.storage.renewCell({}), /reopen required/)
    await t.exception.all(() => runtime.inboxStorage.renewInbox({}), /reopen required/)
    await t.exception.all(() => runtime.storage.preparedCellOperationState({}), /reopen required/)
    t.exception(() => runtime.inboxStorage.preparedInboxOperationState({}), /reopen required/)
    t.is(decodeDispatchFrame((await runtime.coordinator.dispatch(core, context())).dispatch).frameKind, FRAME_KIND.ERROR, 'no positive cached CORE replay through the real coordinator')
    t.alike(await walSnapshot(runtime), failed, 'all three WAL digests remain exact after rejected later writes and replays')
    t.ok(productionStorageOperationalIntegrity(runtime.storage.status()).fullStoreVerified, 'writer uncertainty does not claim verified payload corruption')
    const ready = productionGenerationReadyOperationBits(runtime.storage.status(), PRODUCTION_DESCRIBE_CELL_INBOX_CORE_OPERATION_BITS)
    for (const [family, operation] of [[FAMILY.CELL, OPERATION.CELL.PUT], [FAMILY.CELL, OPERATION.CELL.RENEW], [FAMILY.INBOX, OPERATION.INBOX.CREATE], [FAMILY.INBOX, OPERATION.INBOX.APPEND], [FAMILY.CORE, OPERATION.CORE.MIRROR]]) t.is(ready & operationBit(family, operation), 0)
    t.ok(ready & operationBit(FAMILY.CELL, OPERATION.CELL.GET), 'verified free reader capability remains available')
    if (role === 'cell') t.alike((await runtime.storage.readCell(cell.request.storageSlot)).cellBlob, cell.source, 'already committed payload remains readable under existing verification')
    await runtime.close()
    await t.exception.all(() => assemble(fixture), /generation/, 'reopen refuses the exact invalid floor evidence')
    await fs.unlink(invalid)
    runtime = await assemble(fixture)
    t.is(runtime.storage.status().writerQuarantineReason, null, 'fresh runtime validates persisted evidence and recovers floor')
    t.is([runtime.storage.cells.size, runtime.inboxStorage.inboxes.size, runtime.coreStorage.mirrorAttempts.size][index], 1, 'accepted family obligation survives reopen')
    await turn()
  })
}
