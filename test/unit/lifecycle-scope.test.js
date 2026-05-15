/**
 * LifecycleScope unit tests — verify the cancellation contract primitive
 * the v0.8.13 Reliability v2 work uses to drain fire-and-forget loops at
 * stop() time. See CANCELLATION-CONTRACT.md.
 *
 * No real swarm / corestore needed — these tests exercise the primitive
 * in isolation.
 */

import test from 'brittle'
import { LifecycleScope, isAbortError } from 'p2p-hiverelay/core/relay-node/lifecycle-scope.js'

test('LifecycleScope: signal starts non-aborted, aborts on drain', async (t) => {
  const scope = new LifecycleScope()
  t.is(scope.aborted, false, 'fresh scope is not aborted')
  t.is(scope.signal.aborted, false, 'fresh signal is not aborted')
  await scope.drain()
  t.is(scope.aborted, true, 'aborted after drain')
  t.is(scope.signal.aborted, true, 'signal aborted after drain')
})

test('LifecycleScope: tracked() awaits pending promises before drain returns', async (t) => {
  const scope = new LifecycleScope()
  let resolved = false
  const p = new Promise((resolve) => {
    setTimeout(() => {
      resolved = true
      resolve('done')
    }, 50)
  })
  scope.tracked(p)

  const drainStart = Date.now()
  await scope.drain()
  const drainMs = Date.now() - drainStart

  t.is(resolved, true, 'tracked promise resolved before drain returned')
  t.ok(drainMs >= 40, 'drain blocked until the tracked promise settled (' + drainMs + 'ms)')
})

test('LifecycleScope: race() rejects with AbortError when signal fires first', async (t) => {
  const scope = new LifecycleScope()
  const slow = new Promise((resolve) => setTimeout(() => resolve('too late'), 1000))
  const racePromise = scope.race(slow)

  setTimeout(() => scope.drain(), 10) // fire abort early

  try {
    await racePromise
    t.fail('race should have rejected')
  } catch (err) {
    t.ok(isAbortError(err), 'race rejected with AbortError (name=' + err.name + ', code=' + err.code + ')')
  }
})

test('LifecycleScope: race() resolves normally when inner promise wins', async (t) => {
  const scope = new LifecycleScope()
  const fast = new Promise((resolve) => setTimeout(() => resolve('ok'), 5))
  const result = await scope.race(fast)
  t.is(result, 'ok')
  await scope.drain()
})

test('LifecycleScope: race() rejects immediately if scope already aborted', async (t) => {
  const scope = new LifecycleScope()
  await scope.drain()
  let innerEverEvaluated = false
  const inner = new Promise(() => { innerEverEvaluated = true })
  try {
    await scope.race(inner)
    t.fail('race should have rejected synchronously')
  } catch (err) {
    t.ok(isAbortError(err), 'race rejected with AbortError')
    t.is(innerEverEvaluated, true, 'inner promise constructor still ran (expected — Promise body is synchronous), but resolver never fired')
  }
})

test('LifecycleScope: sleep() rejects with AbortError when signal fires mid-sleep', async (t) => {
  const scope = new LifecycleScope()
  const sleepPromise = scope.sleep(1000)
  setTimeout(() => scope.drain(), 10)

  const start = Date.now()
  try {
    await sleepPromise
    t.fail('sleep should have rejected')
  } catch (err) {
    const ms = Date.now() - start
    t.ok(isAbortError(err), 'sleep rejected with AbortError')
    t.ok(ms < 500, 'sleep bailed promptly (' + ms + 'ms < 500ms)')
  }
})

test('LifecycleScope: sleep() resolves after the requested delay if not aborted', async (t) => {
  const scope = new LifecycleScope()
  const start = Date.now()
  await scope.sleep(40)
  const ms = Date.now() - start
  t.ok(ms >= 30, 'sleep waited (' + ms + 'ms)')
  await scope.drain()
})

test('LifecycleScope: drain() is idempotent', async (t) => {
  const scope = new LifecycleScope()
  scope.tracked(Promise.resolve('once'))
  await scope.drain()
  // Second call should be a no-op, not hang.
  await scope.drain()
  t.is(scope.aborted, true)
})

test('LifecycleScope: tracked() after drain() is a no-op (does not block second drain)', async (t) => {
  const scope = new LifecycleScope()
  await scope.drain()
  const p = new Promise(() => {}) // never resolves
  scope.tracked(p) // should not be added to a now-closed inflight set
  // If tracked() incorrectly added p to inflight, this second drain would hang forever.
  const start = Date.now()
  await scope.drain()
  const ms = Date.now() - start
  t.ok(ms < 100, 'second drain returned quickly (' + ms + 'ms) — post-drain tracked() was a no-op')
})

test('LifecycleScope: drain() waits for ALL tracked promises (allSettled, not first)', async (t) => {
  const scope = new LifecycleScope()
  const slowOk = new Promise((resolve) => setTimeout(() => resolve('slow ok'), 80))
  const fastReject = new Promise((_resolve, reject) => setTimeout(() => reject(new Error('fast fail')), 10))
  scope.tracked(slowOk)
  scope.tracked(fastReject.catch(() => {})) // standard fire-and-forget pattern: swallow with .catch

  const start = Date.now()
  await scope.drain()
  const ms = Date.now() - start
  t.ok(ms >= 70, 'drain waited for the slow promise too (' + ms + 'ms)')
})

test('LifecycleScope: throwIfAborted throws AbortError when aborted', async (t) => {
  const scope = new LifecycleScope()
  scope.throwIfAborted() // pre-abort: no throw
  await scope.drain()
  try {
    scope.throwIfAborted()
    t.fail('throwIfAborted should have thrown')
  } catch (err) {
    t.ok(isAbortError(err))
  }
})

test('LifecycleScope: realistic retry loop scenario — sleep + race wrapping a long await', async (t) => {
  const scope = new LifecycleScope()
  let iterations = 0
  let bailedCleanly = false

  // Simulate _eagerReplicate's loop shape: retry up to 6 times, each
  // attempt wraps a "long await" in scope.race() and uses scope.sleep()
  // between attempts. The "long await" is a 200ms timer; abort fires
  // at 50ms, so iteration 0 should bail mid-await.
  const loop = (async () => {
    for (let attempt = 0; attempt < 6; attempt++) {
      if (scope.aborted) return
      iterations++
      try {
        const slowOp = new Promise((resolve) => setTimeout(resolve, 200))
        await scope.race(slowOp)
      } catch (err) {
        if (isAbortError(err)) { bailedCleanly = true; return }
        throw err
      }
      if (attempt < 5) {
        try {
          await scope.sleep(5000)
        } catch (err) {
          if (isAbortError(err)) { bailedCleanly = true; return }
          throw err
        }
      }
    }
  })()
  scope.tracked(loop)

  setTimeout(() => scope.drain(), 50)
  const start = Date.now()
  await loop
  const ms = Date.now() - start

  t.ok(bailedCleanly, 'loop exited via AbortError, not by completing all retries')
  t.is(iterations, 1, 'loop bailed during the first iteration')
  t.ok(ms < 500, 'loop bailed promptly (' + ms + 'ms) — no waiting through the 200ms slowOp or 5s sleep')
})

test('isAbortError: recognizes scope-thrown AbortErrors', async (t) => {
  const scope = new LifecycleScope()
  await scope.drain()
  try {
    await scope.race(Promise.resolve())
    t.fail('should have rejected')
  } catch (err) {
    t.ok(isAbortError(err))
  }

  // Also recognizes the duck-typed form (no scope dependency).
  const e = new Error('abort')
  e.name = 'AbortError'
  t.ok(isAbortError(e))

  const e2 = new Error('abort')
  e2.code = 'ABORT_ERR'
  t.ok(isAbortError(e2))

  t.is(isAbortError(new Error('something else')), false)
  t.is(isAbortError(null), false)
  t.is(isAbortError(undefined), false)
})
