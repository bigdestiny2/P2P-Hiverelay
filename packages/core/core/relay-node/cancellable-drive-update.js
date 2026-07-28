/**
 * Run drive.update() / drive.download() with a hard timeout that *actually*
 * cancels the underlying Hypercore upgrade / block requests when it fires.
 *
 * Background: the previous eagerReplicate retry loop wrapped
 * `drive.update({ wait: true })` in a Promise.race with a setTimeout-reject.
 * When the timeout fired, the surrounding code got control back — but the
 * underlying hypercore upgrade request was still attached to the
 * replicator's activeRequests array, holding a pending promise and an
 * upgrade ref. Over time, repeated calls (or repeated retries within one
 * call) leaked a growing pool of these refs, which is the suspected
 * root cause of the "Cannot make sessions on a closing core" symptom
 * that PR #14 (v0.8.7) papered over with a 503 + Retry-After response.
 *
 * Fix: pass our own `activeRequests = []` array into hypercore's update().
 * On timeout (or any rejection), call
 *
 *   drive.db.core.replicator.clearRequests(activeRequests, err)
 *
 * which walks the array and properly detaches + rejects every ref, then
 * triggers an updateAll() so the replicator knows to stop pursuing the
 * upgrade. This is hypercore's documented(-by-convention) cancellation
 * API; see node_modules/hypercore/lib/replicator.js:1660.
 *
 * For downloads, hyperdrive returns a download tracker on which we call
 * `.destroy()` on timeout — `.done()` returning has no cleanup but
 * `.destroy()` cancels the underlying block requests.
 */

const DEFAULT_UPDATE_TIMEOUT_MS = 30_000
const DEFAULT_DOWNLOAD_TIMEOUT_MS = 120_000

/**
 * Race drive.update(opts) against a timeout. If the timeout fires first,
 * cancel any in-flight upgrade requests so they don't leak.
 *
 * @param {object} drive — Hyperdrive instance
 * @param {object} [opts]
 * @param {number} [opts.timeoutMs] — abort after this many ms (default 30s)
 * @param {boolean} [opts.wait] — passed through to drive.update (default true)
 * @returns {Promise<boolean>} — hypercore.update's return value, or throws
 *   if the timeout fires before update settles
 */
export async function updateWithTimeout (drive, opts = {}) {
  const timeoutMs = Number.isFinite(opts.timeoutMs) ? opts.timeoutMs : DEFAULT_UPDATE_TIMEOUT_MS
  const wait = opts.wait !== false
  const activeRequests = []

  let timer = null
  let timedOut = false

  const updatePromise = drive.update({ wait, activeRequests })

  try {
    return await new Promise((resolve, reject) => {
      timer = setTimeout(() => {
        timedOut = true
        // Cancel any in-flight upgrade refs sitting in our activeRequests
        // array. This is the hypercore-documented way to abort an update.
        const replicator = drive.db && drive.db.core && drive.db.core.replicator
        if (replicator && typeof replicator.clearRequests === 'function') {
          try {
            replicator.clearRequests(activeRequests, new Error('UPDATE_TIMEOUT'))
          } catch {
            // Replicator might be torn down already; ignore.
          }
        }
        reject(new Error('update timeout'))
      }, timeoutMs)
      // We deliberately don't .unref() the timer — brittle's deadlock
      // detector treats unref'd timers as "no pending work" and aborts
      // tests prematurely. Timers are short (30s default) and clearTimeout
      // fires in every resolution path, so production behavior is fine.

      updatePromise.then(
        (value) => {
          if (!timedOut) {
            clearTimeout(timer)
            resolve(value)
          }
        },
        (err) => {
          if (!timedOut) {
            clearTimeout(timer)
            reject(err)
          }
        }
      )
    })
  } finally {
    if (timer) clearTimeout(timer)
    // Defensive: if for any reason a ref remained in our array (e.g. the
    // updatePromise resolved at the same instant the timer fired), make
    // sure nothing leaks. clearRequests on an empty array is a no-op.
    const replicator = drive.db && drive.db.core && drive.db.core.replicator
    if (replicator && typeof replicator.clearRequests === 'function' && activeRequests.length > 0) {
      try { replicator.clearRequests(activeRequests, new Error('UPDATE_CANCELLED')) } catch {}
    }
  }
}

/**
 * Race a drive download against a timeout. On timeout, destroy any
 * in-flight block-download trackers so their pending requests are
 * released and don't accumulate refs in the replicator.
 *
 * 2026-05-23: hyperdrive 11.x changed the `drive.download()` API. It used
 * to return a download-tracker object with `.done()` and `.destroy()`
 * methods. It now returns a `Promise<void>` (the function is `async`).
 * Calling `.done()` on the Promise throws `TypeError: dl.done is not a
 * function`, which previously caused this helper to silently fail every
 * download in production — and the silent failure was masked by the
 * pre-PR #19 anchor-honesty bug, which marked entries anchored=true on
 * metadata-only so the repair loop skipped them anyway. Once PR #19
 * surfaced the honest anchored=false signal on partial pins, the repair
 * loop started trying to fix them — and discovered this latent bug.
 *
 * Fix: detect both API shapes. For the Promise (new) shape, race against
 * a timeout; for the tracker (old) shape, preserve the prior behavior.
 * Tracker-shape cleanup is the only one that can actually cancel
 * in-flight requests; the Promise-shape path lets orphaned in-flight
 * blob.core.download trackers settle on their own background — slight
 * waste but no leak, since the trackers are bounded to the file's
 * blob extent.
 *
 * @param {object} drive — Hyperdrive instance
 * @param {string} [path] — path to download (default '/')
 * @param {object} [opts]
 * @param {number} [opts.timeoutMs] — abort after this many ms (default 120s)
 * @returns {Promise<void>}
 */
export async function downloadWithTimeout (drive, path = '/', opts = {}) {
  const timeoutMs = Number.isFinite(opts.timeoutMs) ? opts.timeoutMs : DEFAULT_DOWNLOAD_TIMEOUT_MS
  // drive.download() throws synchronously if the drive is closing;
  // let that bubble up so the caller can handle it the same way it
  // would have without the timeout wrapper.
  const dl = drive.download(path)
  const isOldTrackerApi = dl && typeof dl.done === 'function' && typeof dl.destroy === 'function'

  let timer = null
  let timedOut = false

  try {
    return await new Promise((resolve, reject) => {
      timer = setTimeout(() => {
        timedOut = true
        if (isOldTrackerApi) {
          try { dl.destroy() } catch { /* best-effort */ }
        }
        reject(new Error('download timeout'))
      }, timeoutMs)
      // No .unref() — see updateWithTimeout for the brittle-deadlock note.

      const settledPromise = isOldTrackerApi ? dl.done() : dl
      settledPromise.then(
        () => {
          if (!timedOut) {
            clearTimeout(timer)
            resolve()
          }
        },
        (err) => {
          if (!timedOut) {
            clearTimeout(timer)
            reject(err)
          }
        }
      )
    })
  } finally {
    if (timer) clearTimeout(timer)
    // Defensive: destroy() is idempotent on hyperdrive download trackers.
    // For Promise-shape (hyperdrive 11.x), there's no tracker to destroy
    // here — the inner blob.core.download trackers settle naturally.
    if (isOldTrackerApi) {
      try { dl.destroy() } catch {}
    }
  }
}

export const UPDATE_TIMEOUT_MS = DEFAULT_UPDATE_TIMEOUT_MS
export const DOWNLOAD_TIMEOUT_MS = DEFAULT_DOWNLOAD_TIMEOUT_MS

/**
 * Return the drive's total on-disk footprint estimate, in bytes,
 * after performing whatever core-updates are needed to know it.
 *
 * Hyperdrive's drive.update() only updates the metadata core
 * (drive.db.core); the blob core (drive.blobs.core) needs its own
 * update to expose its full byteLength. This helper does both so
 * callers can size-check against publisher-declared caps before
 * committing to download the whole thing.
 *
 * Both inner updates run with our own activeRequests array + a
 * timeout so they don't leak hypercore upgrade refs (same pattern
 * as updateWithTimeout).
 *
 * @param {object} drive — Hyperdrive instance
 * @param {object} [opts]
 * @param {number} [opts.timeoutMs] — per-core update timeout (default 10s)
 * @returns {Promise<{ totalBytes: number, metaBytes: number, blobBytes: number }>}
 *   Best-effort sizes. If an update times out, that core's byteLength
 *   is whatever was already known (often 0 on a never-synced drive).
 */
export async function getDriveSize (drive, opts = {}) {
  const timeoutMs = Number.isFinite(opts.timeoutMs) ? opts.timeoutMs : 10_000

  const metaCore = drive && drive.db && drive.db.core
  const blobCore = drive && drive.blobs && drive.blobs.core

  // Helper to update a raw hypercore with a cancellable timeout.
  // Mirrors updateWithTimeout but for a core (not a drive).
  async function updateCore (core) {
    if (!core || typeof core.update !== 'function') return
    const activeRequests = []
    let timer = null
    try {
      await new Promise((resolve, reject) => {
        timer = setTimeout(() => {
          if (core.replicator && typeof core.replicator.clearRequests === 'function') {
            try { core.replicator.clearRequests(activeRequests, new Error('GET_SIZE_TIMEOUT')) } catch {}
          }
          reject(new Error('get-size timeout'))
        }, timeoutMs)
        core.update({ wait: true, activeRequests }).then(
          () => { clearTimeout(timer); resolve() },
          (err) => { clearTimeout(timer); reject(err) }
        )
      }).catch(() => {
        // Best-effort: partial size info is fine for the caller's decision.
      })
    } finally {
      if (timer) clearTimeout(timer)
      if (core.replicator && typeof core.replicator.clearRequests === 'function' && activeRequests.length > 0) {
        try { core.replicator.clearRequests(activeRequests, new Error('GET_SIZE_CANCELLED')) } catch {}
      }
    }
  }

  // Metadata core size — usually already known after the initial drive.update,
  // but we re-update just in case the caller hasn't done one yet.
  await updateCore(metaCore)

  // Blob core size — separate update required; drive.update doesn't touch it.
  await updateCore(blobCore)

  if (!opts.requireAuthoritative) {
    const metaBytes = (metaCore && metaCore.byteLength) || 0
    const blobBytes = (blobCore && blobCore.byteLength) || 0
    return { totalBytes: metaBytes + blobBytes, metaBytes, blobBytes }
  }

  // ── Authoritative mode ────────────────────────────────────────────────
  // A storage proof must describe ONE state of the drive. `length` and
  // `byteLength` are two separate getters, so an append landing between them
  // yields a tuple that never existed: the old byteLength paired with the new
  // length (or vice versa). Sizing a cap or signing a proof off that tuple
  // under-counts the drive. Read length → byteLength → length again and retry
  // until the bracketing reads agree.
  const metaState = readStableCoreState(metaCore)
  const blobState = readStableCoreState(blobCore)

  const result = {
    metaBytes: metaState.byteLength,
    blobBytes: blobState.byteLength,
    totalBytes: metaState.byteLength + blobState.byteLength,
    metaLength: metaState.length,
    blobLength: blobState.length,
    metaFork: metaState.fork,
    blobFork: blobState.fork
  }

  if (!opts.pinSnapshots) return result

  // Pinned proof: capture a snapshot session per core so the caller can read
  // the exact bytes the proof covers. drive.version must not move across the
  // capture — if it does, the two snapshots belong to different drive states
  // and the proof would attest to a version that never existed.
  const versionBefore = drive ? drive.version : undefined
  const snapshots = []
  try {
    for (const core of [metaCore, blobCore]) {
      if (core && typeof core.snapshot === 'function') {
        const snap = core.snapshot()
        snapshots.push(snap)
        if (snap && typeof snap.ready === 'function') await snap.ready()
      } else {
        snapshots.push(null)
      }
    }
    const versionAfter = drive ? drive.version : undefined
    if (versionBefore !== versionAfter) {
      const err = new Error(
        `DRIVE_VERSION_CHANGED_DURING_PROOF: ${versionBefore} -> ${versionAfter}`
      )
      err.code = 'DRIVE_VERSION_CHANGED_DURING_PROOF'
      throw err
    }
    result.driveVersion = versionAfter
    result.metaCoreSnapshot = snapshots[0]
    result.blobCoreSnapshot = snapshots[1]
    return result
  } catch (err) {
    // Stale snapshots are ours to release — the caller never saw them.
    for (const snap of snapshots) {
      if (snap && typeof snap.close === 'function') {
        try { await snap.close() } catch (_) {}
      }
    }
    throw err
  }
}

const STABLE_READ_ATTEMPTS = 8

/**
 * Read a core's (length, byteLength, fork) as one consistent tuple.
 *
 * Bracketing: read length, then byteLength, then length again. Matching
 * bracket reads mean no append landed in between, so the byteLength belongs
 * to that length. Bounded so a core appending in a tight loop fails loudly
 * instead of spinning.
 */
function readStableCoreState (core) {
  if (!core) return { length: 0, byteLength: 0, fork: 0 }
  for (let attempt = 0; attempt < STABLE_READ_ATTEMPTS; attempt++) {
    const lengthBefore = core.length || 0
    const byteLength = core.byteLength || 0
    const lengthAfter = core.length || 0
    if (lengthBefore === lengthAfter) {
      return { length: lengthAfter, byteLength, fork: core.fork || 0 }
    }
  }
  const err = new Error('CORE_STATE_UNSTABLE: core kept appending across size reads')
  err.code = 'CORE_STATE_UNSTABLE'
  throw err
}
