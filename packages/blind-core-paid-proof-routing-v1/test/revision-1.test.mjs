import test from 'node:test'
import assert from 'node:assert/strict'
import { setup, cloneRequest } from './fixture.mjs'
import { OPERATION } from '../../blind-protocol/index.js'
import { isCommittedCoreResult } from '../../blind-daemon/core-runtime-adapter.js'

function latch () {
  let release; let enter
  const held = new Promise(resolve => { release = resolve })
  const entered = new Promise(resolve => { enter = resolve })
  return { held, entered, release, enter }
}

async function committedOldProof (t, seed) {
  const h = await setup(t)
  const head = await h.mirror(seed)
  const request = h.prove(head, seed + 1)
  const first = await h.dispatch(OPERATION.CORE.PROVE, request)
  await h.writer.append(Buffer.from('new head after charged proof'))
  await h.mirror(seed + 2)
  await h.restart()
  h.reads.length = 0
  h.lookupInputs.length = 0
  return { h, request, first }
}

for (const field of ['coreProofBytes', 'canonicalResultBytes', 'predictedResultBodyBytes']) {
  test('R1 rejects independently stale ' + field + ' before retained reads', { timeout: 25000 }, async t => {
    const { h, request, first } = await committedOldProof(t, 91)
    const measured = await h.runtime.inspectCheapState(h.input(request))
    const before = h.stats()
    // Under-reservations, stale over-reservations and non-numeric sizes all
    // disagree with exact committed metadata, even when the other fields match.
    for (const value of [measured[field] - 1, measured[field] + 1, String(measured[field])]) {
      const authenticatedState = { ...measured, [field]: value }
      await assert.rejects(h.runtime.execute({ ...h.input(request), authenticatedState }), { code: 'INTERNAL' })
      assert.equal(h.reads.length, 0)
      assert.equal(h.stats().walSequence, before.walSequence)
      assert.deepEqual(h.stats().walHash, before.walHash)
    }
    const valid = await h.runtime.execute({ ...h.input(request), authenticatedState: measured })
    assert.deepEqual(valid.body, first.body)
    assert.equal(isCommittedCoreResult(valid), true)
    assert.ok(h.reads.length > 0)
    assert.equal(h.stats().proofPins, before.proofPins)
    assert.equal(h.stats().walSequence, before.walSequence)
  })
}

test('R1 direct hook retains missing size support and exact parent result brand', { timeout: 25000 }, async t => {
  const { h, request, first } = await committedOldProof(t, 101)
  const measured = await h.runtime.inspectCheapState(h.input(request))
  const before = h.stats()
  for (const authenticatedState of [undefined, null, {}, { coreProofBytes: measured.coreProofBytes }, { canonicalResultBytes: measured.canonicalResultBytes }, { predictedResultBodyBytes: measured.predictedResultBodyBytes }, { coreProofBytes: null, canonicalResultBytes: null, predictedResultBodyBytes: null }]) {
    const result = await h.runtime.execute({ ...h.input(request), authenticatedState })
    assert.deepEqual(result.body, first.body)
    assert.equal(isCommittedCoreResult(result), true)
    assert.equal(Object.isFrozen(result), true)
  }
  assert.equal(h.stats().walSequence, before.walSequence)
  assert.equal(h.stats().proofPins, before.proofPins)
  assert.equal(h.stats().connections, before.connections)
  assert.equal(h.lookupInputs.length, 0)
})

for (const initiallyStale of [true, false]) {
  test('R1 captures size metadata before lookup wait: initially ' + (initiallyStale ? 'stale' : 'valid'), { timeout: 25000 }, async t => {
    const { h, request, first } = await committedOldProof(t, 111)
    const measured = await h.runtime.inspectCheapState(h.input(request))
    const authenticatedState = { ...measured, predictedResultBodyBytes: measured.predictedResultBodyBytes - (initiallyStale ? 1 : 0) }
    const gate = latch()
    const inspect = h.storage.inspectPreparedProofRetry.bind(h.storage)
    let firstLookup = true
    h.storage.inspectPreparedProofRetry = async input => {
      if (firstLookup) { firstLookup = false; gate.enter(); await gate.held }
      return inspect(input)
    }
    const pending = h.runtime.execute({ ...h.input(request), authenticatedState })
    const checked = initiallyStale ? assert.rejects(pending, { code: 'INTERNAL' }) : pending
    await gate.entered
    authenticatedState.predictedResultBodyBytes = measured.predictedResultBodyBytes - (initiallyStale ? 0 : 1)
    gate.release()
    if (initiallyStale) { await checked; assert.equal(h.reads.length, 0) } else assert.deepEqual((await checked).body, first.body)
  })
}

test('R1 cancelled coalesced follower refuses while leader and live follower preserve proof', { timeout: 25000 }, async t => {
  const { h, request, first } = await committedOldProof(t, 121)
  const gate = latch(); const joined = latch()
  const serve = h.upstream.serveProof.bind(h.upstream)
  let materializations = 0; let joins = 0
  h.upstream.serveProof = async input => { materializations++; gate.enter(); await gate.held; return serve(input) }
  const coalesce = h.runtime.coalesce.bind(h.runtime)
  h.runtime.coalesce = (flights, key, binding, operation) => {
    const existing = flights.has(key)
    const result = coalesce(flights, key, binding, operation)
    if (flights === h.runtime.proofFlights && existing && ++joins === 2) joined.enter()
    return result
  }
  const before = h.stats()
  const leader = h.runtime.execute(h.input(request))
  await gate.entered
  const controller = new AbortController()
  const input = { ...h.input(cloneRequest(request)), signal: controller.signal }
  const follower = h.runtime.execute(input)
  const cancelled = assert.rejects(follower, { code: 'CORE_ABORTED' })
  const live = h.runtime.execute(h.input(cloneRequest(request)))
  await joined.entered
  // Replacing the caller's signal property cannot replace its captured signal.
  input.signal = new AbortController().signal
  controller.abort()
  gate.release()
  const results = await Promise.all([leader, live])
  await cancelled
  for (const result of results) { assert.deepEqual(result.body, first.body); assert.equal(isCommittedCoreResult(result), true) }
  assert.equal(materializations, 1)
  assert.equal(h.runtime.proofFlights.size, 0)
  assert.equal(h.stats().walSequence, before.walSequence)
  assert.equal(h.stats().proofPins, before.proofPins)
  assert.equal(h.stats().connections, before.connections)
  assert.equal(h.budget.items, 0)
})
