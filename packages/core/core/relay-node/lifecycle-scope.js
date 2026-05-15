/**
 * LifecycleScope — cancellation contract for the relay's fire-and-forget
 * loops and event handlers.
 *
 * Background. Several long-running async paths in this codebase capture
 * references to Hyperdrives, Hypercores, or appRegistry entries and then
 * run for tens of seconds or minutes against them — eagerReplicate's retry
 * loop (~2 min), _indexLog from localLog.on('append'), _reconcileSeedOptsOnRepin's
 * .finally write, runRepairPass's drive.update/download cycle, the catalog-sync
 * seedApp fan-out, cold-start primer, _autoEnableHolesail, etc.
 *
 * Each of those participants is a stale-reference hazard the moment
 * `RelayNode.stop()` runs: stop() closes the swarm and corestore, but the
 * in-flight loop is still holding closeable hyper objects from before. The
 * next `swarm.flush()` / `drive.update()` / `core.get(i)` then throws
 * "Mutex has been destroyed" / "The corestore is closed" / SESSION_CLOSED.
 *
 * Plugging each leak individually is a losing fight — every new
 * fire-and-forget added later opens a fresh hole. Instead this class
 * captures the one missing primitive: a cancellation **signal** that loops
 * poll at every await point, paired with a **drain** that lets stop()
 * await every fire-and-forget before tearing down state.
 *
 * Usage:
 *
 *   // In RelayNode.start(), first action:
 *   this._scope = new LifecycleScope()
 *
 *   // Long-running loop:
 *   for (;;) {
 *     if (scope.aborted) return
 *     try {
 *       await scope.race(node.swarm.flush())
 *       await scope.race(updateWithTimeout(drive, { timeoutMs: 30_000 }))
 *     } catch (err) {
 *       if (err && err.name === 'AbortError') return
 *       // ... other errors
 *     }
 *     try { await scope.sleep(5000) } catch (_) { return }
 *   }
 *
 *   // Fire-and-forget call site:
 *   scope.tracked(eagerReplicate(...).catch(() => {}))
 *
 *   // In RelayNode.stop(), first action:
 *   const scope = this._scope
 *   this._scope = null
 *   if (scope) await scope.drain()
 *   // ... existing teardown ...
 *
 * The drain() snapshots the inflight set, aborts the signal, then waits
 * for every snapshotted promise to settle (allSettled, so a rejection
 * doesn't poison the drain). By the time drain() returns, no participating
 * closure is still running against the corestore.
 */

export class LifecycleScope {
  constructor () {
    this._ac = new AbortController()
    this._inflight = new Set()
    this._closed = false
  }

  /** AbortSignal that loops poll. */
  get signal () { return this._ac.signal }

  /** True once stop()/drain() has begun. */
  get aborted () { return this._ac.signal.aborted }

  /**
   * Register a fire-and-forget promise so drain() can await it. The
   * promise auto-removes itself from the inflight set on settle. Returns
   * the same promise so call sites read naturally:
   *
   *   scope.tracked(eagerReplicate(...).catch(() => {}))
   *
   * Calling tracked() after drain() has begun is a no-op (the promise is
   * returned unchanged — it's already too late to participate in the
   * drain, which is correct: the caller is in a teardown-race anyway).
   */
  tracked (promise) {
    if (this._closed) return promise
    this._inflight.add(promise)
    const cleanup = () => this._inflight.delete(promise)
    promise.then(cleanup, cleanup)
    return promise
  }

  /**
   * Race a promise against the abort signal. Resolves/rejects with
   * whatever the inner promise does, OR rejects with AbortError if the
   * signal fires first. Throws AbortError immediately (without awaiting
   * the inner promise) when already aborted, so callers exit fast.
   */
  race (promise) {
    if (this._ac.signal.aborted) return Promise.reject(abortError())
    return new Promise((resolve, reject) => {
      const onAbort = () => {
        this._ac.signal.removeEventListener('abort', onAbort)
        reject(abortError())
      }
      this._ac.signal.addEventListener('abort', onAbort, { once: true })
      promise.then(
        (v) => {
          this._ac.signal.removeEventListener('abort', onAbort)
          resolve(v)
        },
        (err) => {
          this._ac.signal.removeEventListener('abort', onAbort)
          reject(err)
        }
      )
    })
  }

  /**
   * Abort-aware sleep. Replaces `await new Promise(r => setTimeout(r, ms))`
   * in long-running retry loops. Resolves after `ms` OR rejects with
   * AbortError if the signal fires first.
   */
  sleep (ms) {
    if (this._ac.signal.aborted) return Promise.reject(abortError())
    return new Promise((resolve, reject) => {
      let timer = null
      const onAbort = () => {
        if (timer) clearTimeout(timer)
        reject(abortError())
      }
      timer = setTimeout(() => {
        this._ac.signal.removeEventListener('abort', onAbort)
        resolve()
      }, ms)
      this._ac.signal.addEventListener('abort', onAbort, { once: true })
    })
  }

  /**
   * Synchronous abort check. Useful at the top of an iteration before
   * doing more synchronous work that doesn't naturally observe the signal.
   * Throws AbortError if aborted.
   */
  throwIfAborted () {
    if (this._ac.signal.aborted) throw abortError()
  }

  /**
   * Stop accepting new tracked promises, fire the signal, then wait for
   * every already-tracked promise to settle. Idempotent.
   */
  async drain () {
    if (this._closed) return
    this._closed = true
    this._ac.abort()
    if (this._inflight.size === 0) return
    const snapshot = [...this._inflight]
    await Promise.allSettled(snapshot)
  }
}

function abortError () {
  const err = new Error('Operation aborted')
  err.name = 'AbortError'
  err.code = 'ABORT_ERR'
  return err
}

/**
 * Helper: returns true iff `err` looks like an AbortError thrown by this
 * module's scope.race()/sleep(). Convenience for catch blocks that want
 * to bail without re-throwing.
 */
export function isAbortError (err) {
  return !!err && (err.name === 'AbortError' || err.code === 'ABORT_ERR')
}
