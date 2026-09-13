import test from 'node:test'
import fs from 'node:fs/promises'
import path from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import assert from 'node:assert/strict'
import { OPERATION, ERROR_CODE, coreServeResultV1, coreServeChallengeV1, encodeCanonical, decodeCanonical } from '../../blind-protocol/index.js'
import { setup, cloneRequest } from './fixture.mjs'

test('real coordinator replays exact paid proof after append and restart without charge or pre-admission retired read', { timeout: 25000 }, async t => {
  const h = await setup(t)
  const original = await h.mirror(51)
  const request = h.prove(original, 61)
  const first = await h.dispatch(OPERATION.CORE.PROVE, request, Buffer.alloc(16, 4))
  assert.equal(await h.upstream.verifyProofBundle({ request, proof: decodeCanonical(coreServeResultV1, first.body).proofsAndBlocks }), true)
  const oldCorpus = h.storage.inspectCore(h.writer.key).corpus.objectId.toString('hex')
  await h.writer.append(Buffer.from('later encrypted block')); const active = await h.mirror(52)
  await h.writerStore.close(); await h.restart()
  const before = h.stats(); h.reads.length = 0; h.events.length = 0; h.lookupInputs.length = 0
  const replay = await h.dispatch(OPERATION.CORE.PROVE, request, Buffer.alloc(16, 4))
  assert.deepEqual(replay, first)
  assert.equal(h.stats().preparedCount, before.preparedCount + 1, 'admission is revalidated')
  for (const key of ['proofPins', 'proofSpendTombstones', 'walSequence', 'connections']) assert.equal(h.stats()[key], before[key], key)
  assert.deepEqual(h.stats().walHash, before.walHash)
  assert.equal(h.lookupInputs.length, 0, 'retry does not estimate from active corpus')
  assert.ok(h.reads.length > 0)
  assert.ok(h.reads.every(read => read.objectId === oldCorpus && read.reserved > 0), 'retired body is read only after actual coordinator reservation')
  assert.deepEqual(h.events.slice(0, 2), ['cheap', 'admission'])
  assert.equal(h.budget.items, 0)
  const fresh = h.prove(active, 62)
  const current = await h.dispatch(OPERATION.CORE.PROVE, fresh)
  assert.equal(await h.upstream.verifyProofBundle({ request: fresh, proof: decodeCanonical(coreServeResultV1, current.body).proofsAndBlocks }), true)
  assert.equal(h.stats().proofPins, before.proofPins + 1)
  const free = h.prove(active, 63, false)
  await h.dispatch(OPERATION.CORE.PROVE, free)
  assert.equal(h.stats().proofPins, before.proofPins + 1)
})

test('unknown or mismatched old requests never read retired corpus', { timeout: 25000 }, async t => {
  const h = await setup(t); const original = await h.mirror(71); const request = h.prove(original, 72)
  await h.dispatch(OPERATION.CORE.PROVE, request)
  await h.writer.append(Buffer.from('newer head')); await h.mirror(73)
  const mutations = [
    ['token', r => { r.admission.token.fill(250) }],
    ['parameter', r => { r.admission.parameterHash.fill(251) }],
    ['profile', r => { r.admission.profileId++ }],
    ['scheme', r => { r.admission.schemeId++ }],
    ['key', r => { r.corePublicKey.fill(252) }],
    ['fork', r => { r.fork++ }],
    ['length', r => { r.length++ }],
    ['head', r => { r.signedHeadHash.fill(253) }],
    ['sample', r => { r.blockIndices = [0n] }],
    ['nonce', r => { r.clientNonce.fill(254) }],
    ['free', r => { r.admission = null }]
  ]
  for (const [name, mutate] of mutations) {
    const changed = cloneRequest(request); mutate(changed); h.reads.length = 0
    await assert.rejects(h.dispatch(OPERATION.CORE.PROVE, changed), undefined, name)
    assert.equal(h.reads.length, 0, name + ' refused before body access')
  }
  for (const mutate of [i => i.requestCommitment.fill(1), i => i.preparedAdmission.spendTag.fill(1), i => i.preparedAdmission.requestCommitment.fill(1), i => i.request.admission.token.fill(2), i => { i.preparedAdmission.profileId++ }, i => { i.preparedAdmission.schemeId++ }, i => { i.preparedAdmission.parameterHash = Buffer.alloc(32, 3) }, i => { i.profile.familyId = 1 }]) {
    const raw = h.input(cloneRequest(request)); mutate(raw); h.reads.length = 0
    await assert.rejects(h.runtime.operationExecutor.execute(raw)); assert.equal(h.reads.length, 0)
  }
})

test('retry pin expiry refuses before retained body access', { timeout: 25000 }, async t => {
  const h = await setup(t); const original = await h.mirror(81); const request = h.prove(original, 82)
  await h.dispatch(OPERATION.CORE.PROVE, request)
  await h.writer.append(Buffer.from('new')); await h.mirror(83)
  h.advanceMillis(15n * 60n * 1000n + 1n); h.reads.length = 0
  await assert.rejects(h.dispatch(OPERATION.CORE.PROVE, request), { code: ERROR_CODE.RETRY_TERMINAL })
  assert.equal(h.reads.length, 0)
  await h.storage.sweepProofPins(); assert.equal(h.storage.proofPins.size, 0)
  h.reads.length = 0
  await assert.rejects(h.runtime.execute(h.input(request)), { code: 'RETRY_TERMINAL' }); assert.equal(h.reads.length, 0)
})

test('caller byte mutation, conflicting reservation and owner/close fences cannot change retry authority', { timeout: 25000 }, async t => {
  const h = await setup(t); const original = await h.mirror(91); const request = h.prove(original, 92)
  const first = await h.dispatch(OPERATION.CORE.PROVE, request)
  await h.writer.append(Buffer.from('new')); await h.mirror(93)
  const raw = h.input(cloneRequest(request)); const pending = h.runtime.operationExecutor.execute(raw)
  raw.request.admission.token.fill(4); raw.request.signedHeadHash.fill(5); raw.requestCommitment.fill(6); raw.preparedAdmission.spendTag.fill(7)
  assert.deepEqual((await pending).body, first.body)
  h.reads.length = 0
  const wrongBudget = { ...h.input(request), authenticatedState: { coreProofBytes: 1 } }
  await assert.rejects(h.runtime.execute(wrongBudget), { code: 'INTERNAL' }); assert.equal(h.reads.length, 0)
  h.loseOwner()
  await assert.rejects(h.runtime.execute(h.input(request)), { code: 'OWNER_FENCE' }); assert.equal(h.reads.length, 0)
  await h.storage.close()
  await assert.rejects(h.runtime.execute(h.input(request)), { code: 'INTERNAL' }); assert.equal(h.reads.length, 0)
})

test('concurrent paid retries coalesce through real coordinator while a later head activates', { timeout: 25000 }, async t => {
  const h = await setup(t); const original = await h.mirror(101); const request = h.prove(original, 102)
  const first = await h.dispatch(OPERATION.CORE.PROVE, request)
  await h.writer.append(Buffer.from('second')); await h.mirror(103)
  let release; let entered
  const held = new Promise(resolve => { release = resolve }); const started = new Promise(resolve => { entered = resolve })
  const serve = h.upstream.serveProof.bind(h.upstream); let serves = 0
  h.upstream.serveProof = async input => { serves++; entered(); await held; return serve(input) }
  const before = h.stats()
  const pending = Array.from({ length: 6 }, () => h.dispatch(OPERATION.CORE.PROVE, request))
  await started
  await h.writer.append(Buffer.from('third')); await h.mirror(104)
  release()
  for (const result of await Promise.all(pending)) assert.deepEqual(result.body, first.body)
  assert.equal(serves, 1)
  assert.equal(h.stats().proofPins, before.proofPins)
  assert.equal(h.budget.items, 0)
  assert.equal(h.storage.inspectCore(h.writer.key).length, 4n)
})

test('expiry between cheap inspection and prepared admission refuses without materializing a retired proof', { timeout: 25000 }, async t => {
  const h = await setup(t); const original = await h.mirror(111); const request = h.prove(original, 112)
  await h.dispatch(OPERATION.CORE.PROVE, request)
  await h.writer.append(Buffer.from('later')); await h.mirror(113)
  h.beforePrepare = () => h.advanceMillis(15n * 60n * 1000n + 1n)
  h.reads.length = 0
  await assert.rejects(h.dispatch(OPERATION.CORE.PROVE, request), { code: ERROR_CODE.RETRY_TERMINAL })
  assert.equal(h.reads.length, 0); assert.equal(h.budget.items, 0)
})

test('fresh offline Node process replays an older paid proof through the real coordinator', { timeout: 25000 }, async t => {
  const h = await setup(t); const original = await h.mirror(121); const request = h.prove(original, 122)
  const first = await h.dispatch(OPERATION.CORE.PROVE, request, Buffer.alloc(16, 9))
  await h.writer.append(Buffer.from('newer')); await h.mirror(123)
  await h.writerStore.close(); await h.upstream.close(); await h.storage.close()
  const config = path.join(h.root, 'offline-retry.json')
  await fs.writeFile(config, JSON.stringify({ root: h.root, corePublicKey: h.writer.key.toString('hex'), request: encodeCanonical(coreServeChallengeV1, request).toString('hex'), expectedDispatch: first.dispatch.toString('hex') }), { mode: 0o600 })
  const { stdout } = await promisify(execFile)(process.execPath, [new URL('./offline-retry-child.mjs', import.meta.url).pathname, config], { timeout: 15000, maxBuffer: 8192 })
  const result = JSON.parse(stdout)
  assert.equal(result.identicalDispatch, true); assert.equal(result.sourceConnections, 0)
  assert.equal(result.newWalRecords, 0); assert.equal(result.newProofPins, 0)
  assert.equal(result.activeCorpusEstimates, 0); assert.equal(result.allRetiredReadsReserved, true)
})

test('higher-fork lower-length activation preserves the exact older paid retry', { timeout: 25000 }, async t => {
  const h = await setup(t); const original = await h.mirror(131); const request = h.prove(original, 132)
  const first = await h.dispatch(OPERATION.CORE.PROVE, request)
  await h.writer.truncate(1); const forked = await h.mirror(133)
  assert.equal(forked.fork, original.fork + 1n); assert.equal(forked.length, 1n)
  await h.restart()
  const replay = await h.dispatch(OPERATION.CORE.PROVE, request)
  assert.deepEqual(replay.body, first.body)
  const free = h.prove(forked, 134, false)
  const current = await h.dispatch(OPERATION.CORE.PROVE, free)
  assert.equal(await h.upstream.verifyProofBundle({ request: free, proof: decodeCanonical(coreServeResultV1, current.body).proofsAndBlocks }), true)
})

test('retained proof hash and actual coordinator capacity remain mandatory', { timeout: 25000 }, async t => {
  const h = await setup(t); const original = await h.mirror(141); const request = h.prove(original, 142)
  const first = await h.dispatch(OPERATION.CORE.PROVE, request)
  await h.writer.append(Buffer.from('later')); await h.mirror(143)
  const before = h.stats(); const held = []
  try {
    for (let i = 0; i < h.budget.generalItemLimit; i++) held.push(h.budget.acquire({ familyId: 4, operationId: 2, requestBytes: 1, responseBytes: 1, stagingBytes: 0, critical: false }))
    h.reads.length = 0
    await assert.rejects(h.dispatch(OPERATION.CORE.PROVE, request), { code: ERROR_CODE.BUSY })
    assert.equal(h.reads.length, 0); assert.equal(h.stats().walSequence, before.walSequence)
  } finally { for (const reservation of held) reservation.release() }
  const serve = h.upstream.serveProof.bind(h.upstream)
  h.upstream.serveProof = async input => { const proof = await serve(input); proof[proof.length - 1] ^= 1; return proof }
  await assert.rejects(h.runtime.execute(h.input(request)), /no longer reproduces exact bytes/)
  h.upstream.serveProof = serve
  assert.deepEqual((await h.dispatch(OPERATION.CORE.PROVE, request)).body, first.body)
  assert.equal(h.stats().walSequence, before.walSequence)
})

test('abort while a retired proof is being materialized returns no result', { timeout: 25000 }, async t => {
  const h = await setup(t); const original = await h.mirror(151); const request = h.prove(original, 152)
  await h.dispatch(OPERATION.CORE.PROVE, request)
  await h.writer.append(Buffer.from('later')); await h.mirror(153)
  let release; let entered
  const held = new Promise(resolve => { release = resolve }); const started = new Promise(resolve => { entered = resolve })
  const serve = h.upstream.serveProof.bind(h.upstream)
  h.upstream.serveProof = async input => { entered(); await held; return serve(input) }
  const controller = new AbortController(); const before = h.stats()
  const pending = h.runtime.execute({ ...h.input(request), signal: controller.signal })
  await started; controller.abort(); release()
  await assert.rejects(pending, { code: 'CORE_ABORTED' })
  assert.equal(h.stats().walSequence, before.walSequence)
  assert.equal(h.stats().proofPins, before.proofPins)
})
