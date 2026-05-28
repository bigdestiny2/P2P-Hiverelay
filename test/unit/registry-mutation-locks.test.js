// registry-mutation-locks: v0.8.24 regression tests for the
// per-key _withMutationLock pattern in SeedingRegistry.
//
// The pattern serializes async mutations that share a key while
// leaving different keys parallel. Without this lock, concurrent
// custody mutations for the same intentId could both observe the
// same stale status, both pass `validateCustodyTransition`, and both
// append — producing duplicate entries that conflict in the in-memory
// indexes.
//
// We test the lock contract directly here without standing up a real
// Hyperswarm + Corestore. The SeedingRegistry instance is constructed
// with stub deps; only the _withKeyLock + per-key behavior is exercised.

import test from 'brittle'
import { SeedingRegistry } from 'p2p-hiverelay/core/registry/index.js'

// Minimal Corestore stub — _withKeyLock doesn't touch the store.
function stubStore () {
  return {
    get () { return null },
    ready () { return Promise.resolve() }
  }
}

function makeRegistry () {
  // We don't start() it — the lock methods don't need swarm/log to exercise.
  return new SeedingRegistry(stubStore(), null, {})
}

function deferred () {
  let release
  const promise = new Promise((resolve) => { release = resolve })
  return { promise, resolve: release }
}

test('_withKeyLock serializes operations on the same key', async (t) => {
  const reg = makeRegistry()
  const events = []

  const gateA = deferred()
  const gateB = deferred()

  const opA = reg._withKeyLock('k1', async () => {
    events.push('A:start')
    await gateA.promise
    events.push('A:end')
    return 'a'
  })

  const opB = reg._withKeyLock('k1', async () => {
    events.push('B:start')
    await gateB.promise
    events.push('B:end')
    return 'b'
  })

  // Give A time to start; B should be queued behind it.
  await new Promise(resolve => setImmediate(resolve))
  t.alike(events, ['A:start'], 'B has not started yet — waiting on A')

  gateA.resolve()
  await new Promise(resolve => setImmediate(resolve))
  t.alike(events, ['A:start', 'A:end', 'B:start'], 'B started only after A finished')

  gateB.resolve()
  const [a, b] = await Promise.all([opA, opB])
  t.is(a, 'a')
  t.is(b, 'b')
  t.alike(events, ['A:start', 'A:end', 'B:start', 'B:end'])
})

test('_withKeyLock allows operations on DIFFERENT keys to run in parallel', async (t) => {
  const reg = makeRegistry()
  const events = []

  const gateA = deferred()
  const gateB = deferred()

  reg._withKeyLock('k1', async () => {
    events.push('A:start')
    await gateA.promise
    events.push('A:end')
  })

  reg._withKeyLock('k2', async () => {
    events.push('B:start')
    await gateB.promise
    events.push('B:end')
  })

  // Both should start without waiting.
  await new Promise(resolve => setImmediate(resolve))
  t.alike(events.sort(), ['A:start', 'B:start'].sort(), 'both started — different keys do not block each other')

  gateB.resolve()
  await new Promise(resolve => setImmediate(resolve))
  t.ok(events.includes('B:end'), 'B finished while A is still running')

  gateA.resolve()
  await new Promise(resolve => setImmediate(resolve))
  t.ok(events.includes('A:end'), 'A finished after B (or in any order)')
})

test('_withKeyLock cleans up its slot after the last waiter resolves', async (t) => {
  const reg = makeRegistry()

  await reg._withKeyLock('cleanup-key', async () => 'done')
  t.absent(reg._keyLocks.has('cleanup-key'),
    'lock map entry was cleared when no one was queued behind')
})

test('_withKeyLock keeps a chain when subsequent ops queue mid-flight', async (t) => {
  const reg = makeRegistry()
  const gate1 = deferred()
  const gate2 = deferred()

  const p1 = reg._withKeyLock('chain', async () => {
    await gate1.promise
    return 1
  })

  // Queue p2 while p1 is still in flight
  const p2 = reg._withKeyLock('chain', async () => {
    await gate2.promise
    return 2
  })

  // At this point, the map should hold p2's tail — not be empty
  t.ok(reg._keyLocks.has('chain'), 'lock chained correctly while ops pending')

  gate1.resolve()
  gate2.resolve()
  const [r1, r2] = await Promise.all([p1, p2])
  t.is(r1, 1)
  t.is(r2, 2)
  t.absent(reg._keyLocks.has('chain'), 'lock cleaned up after both resolved')
})

test('_withKeyLock survives a failing operation — releases the lock on throw', async (t) => {
  const reg = makeRegistry()
  let errCaught = null

  try {
    await reg._withKeyLock('fail-key', async () => {
      throw new Error('intentional')
    })
  } catch (err) {
    errCaught = err
  }

  t.ok(errCaught, 'error propagated to caller')
  t.is(errCaught.message, 'intentional')
  t.absent(reg._keyLocks.has('fail-key'), 'lock cleaned up even after throw')

  // Next op on the same key should run immediately (not blocked)
  let ran = false
  await reg._withKeyLock('fail-key', async () => { ran = true })
  t.ok(ran, 'next op on the same key ran fine after failure')
})

test('_withKeyLock chained failures: one failed op does not block subsequent ones', async (t) => {
  const reg = makeRegistry()
  const events = []

  const p1 = reg._withKeyLock('chain-fail', async () => {
    events.push('A')
    throw new Error('first failed')
  }).catch(err => err.message)

  const p2 = reg._withKeyLock('chain-fail', async () => {
    events.push('B')
    return 'ok'
  })

  const [r1, r2] = await Promise.all([p1, p2])
  t.is(r1, 'first failed', 'first op rejected')
  t.is(r2, 'ok', 'second op ran after first failed')
  t.alike(events, ['A', 'B'], 'second op ran AFTER first, not concurrently')
})
