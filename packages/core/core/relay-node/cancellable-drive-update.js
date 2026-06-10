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
  const signal = opts.signal || null

  // 2026-06-07 (#28): for hyperdrive 11.x's Promise-shape download API,
  // we re-implement the download loop here so we can collect every inner
  // blob.core.download tracker and destroy() them on abort/timeout.
  // Without this, the orphaned trackers keep the event loop alive after
  // stop() — fine in production (drives close cleanly via corestore.close
  // on shutdown), but causes reliability-v2 test runner to hang at the
  // file-level timeout. The trackers DO eventually settle on their own
  // (bounded by each file's blob extent) so this is a developer-
  // experience fix, not a production reliability concern.
  //
  // For the old tracker API (hyperdrive 10.x), preserve the prior
  // single-tracker path — destroy() on the top-level tracker cancels
  // its inner block requests via hypercore's documented API.

  // Probe: call drive.download(path) once with no opts to detect API shape.
  // If old API, the result has .done() + .destroy() and we use the
  // tracker-based path. If new (Promise), we throw away the result and
  // run our cancellable re-implementation instead.
  // drive.download() throws synchronously if the drive is closing; let
  // that bubble up — the caller sees the same error path it would have
  // without the timeout wrapper.
  let oldTrackerProbe = null
  let promiseProbe = null
  const probe = drive.download(path)
  if (probe && typeof probe.done === 'function' && typeof probe.destroy === 'function') {
    oldTrackerProbe = probe
  } else if (probe && typeof probe.then === 'function') {
    // New API — we re-do the work below. Detach the orphan Promise so
    // unhandled rejection warnings don't surface.
    promiseProbe = probe
    probe.catch(() => {})
  }

  if (oldTrackerProbe) {
    return _runOldTrackerDownload(oldTrackerProbe, timeoutMs, signal)
  }

  // The #28 re-implementation walks the drive itself (entry/getBlobs/list)
  // so it can destroy per-blob trackers on abort. A drive that lacks that
  // surface (hyperdrive fork, test double) can't be walked — fall back to
  // racing the download() Promise against the timeout/abort, the pre-#28
  // semantics. Same guarded-getBlobs posture as AppLifecycle._isDriveFullyReplicated.
  const hasWalkSurface = typeof drive.getBlobs === 'function' &&
    typeof drive.entry === 'function' && typeof drive.list === 'function'
  if (!hasWalkSurface) {
    if (promiseProbe) return _awaitPromiseDownload(promiseProbe, timeoutMs, signal)
    return // download() returned nothing awaitable; nothing to wait on
  }

  return _runNewPromiseDownload(drive, path, timeoutMs, signal)
}

// ─── Fallback: race the bare download() Promise ─────────────────────
// Used when the drive can't be walked for per-blob trackers. Resolution,
// rejection, and timeout semantics match the walk path; only inner-tracker
// cancellation is unavailable (the orphan settles on its own, bounded by
// the file's blob extent).
async function _awaitPromiseDownload (promise, timeoutMs, signal) {
  let timer = null
  let abortHandler = null
  try {
    return await new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new Error('download timeout')), timeoutMs)
      if (signal) {
        if (signal.aborted) {
          const err = new Error('Aborted')
          err.name = 'AbortError'
          reject(err)
          return
        }
        abortHandler = () => {
          const err = new Error('Aborted')
          err.name = 'AbortError'
          reject(err)
        }
        signal.addEventListener('abort', abortHandler)
      }
      promise.then(resolve, reject)
    })
  } finally {
    if (timer) clearTimeout(timer)
    if (signal && abortHandler) signal.removeEventListener('abort', abortHandler)
  }
}

// ─── Old tracker API (hyperdrive 10.x) ──────────────────────────────
async function _runOldTrackerDownload (dl, timeoutMs, signal) {
  let timer = null
  let abortHandler = null
  let timedOut = false

  try {
    return await new Promise((resolve, reject) => {
      timer = setTimeout(() => {
        timedOut = true
        try { dl.destroy() } catch {}
        reject(new Error('download timeout'))
      }, timeoutMs)

      if (signal) {
        if (signal.aborted) {
          clearTimeout(timer)
          try { dl.destroy() } catch {}
          const err = new Error('Aborted')
          err.name = 'AbortError'
          reject(err)
          return
        }
        abortHandler = () => {
          timedOut = true
          try { dl.destroy() } catch {}
          const err = new Error('Aborted')
          err.name = 'AbortError'
          reject(err)
        }
        signal.addEventListener('abort', abortHandler)
      }

      dl.done().then(
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
    if (signal && abortHandler) signal.removeEventListener('abort', abortHandler)
    try { dl.destroy() } catch {}
  }
}

// ─── New Promise API (hyperdrive 11.x) ──────────────────────────────
async function _runNewPromiseDownload (drive, path, timeoutMs, signal) {
  // We re-implement drive.download(path) here so we control the inner
  // trackers. Mirrors hyperdrive's own implementation (entry vs folder
  // dispatch, blob extent calculation, allSettled on per-blob trackers)
  // but exposes the trackers for explicit destroy() on abort/timeout.

  const activeTrackers = []
  let aborted = false
  let abortReason = null

  const destroyAll = () => {
    for (const t of activeTrackers) {
      try { t.destroy() } catch {}
    }
  }

  let timer = null
  let abortHandler = null

  const arm = () => {
    timer = setTimeout(() => {
      aborted = true
      abortReason = new Error('download timeout')
      destroyAll()
    }, timeoutMs)
    if (signal) {
      if (signal.aborted) {
        aborted = true
        abortReason = new Error('Aborted')
        abortReason.name = 'AbortError'
        destroyAll()
        return
      }
      abortHandler = () => {
        aborted = true
        abortReason = new Error('Aborted')
        abortReason.name = 'AbortError'
        destroyAll()
      }
      signal.addEventListener('abort', abortHandler)
    }
  }

  const disarm = () => {
    if (timer) clearTimeout(timer)
    if (signal && abortHandler) signal.removeEventListener('abort', abortHandler)
  }

  arm()

  try {
    // Single-file path: drive.entry(path) returns metadata for a leaf.
    const isFolder = !path || path.endsWith('/')
    if (!isFolder) {
      const entry = await drive.entry(path)
      if (aborted) throw abortReason
      if (entry) {
        const b = entry.value && entry.value.blob
        if (b) {
          const blobs = await drive.getBlobs()
          if (aborted) throw abortReason
          const tracker = blobs.core.download({ start: b.blockOffset, length: b.blockLength })
          activeTrackers.push(tracker)
          await tracker.downloaded()
        }
      }
      if (aborted) throw abortReason
      return
    }

    // Folder path: walk entries, start a tracker per blob.
    const blobs = await drive.getBlobs()
    if (aborted) throw abortReason

    for await (const entry of drive.list(path)) {
      if (aborted) throw abortReason
      const b = entry.value && entry.value.blob
      if (!b) continue
      const tracker = blobs.core.download({ start: b.blockOffset, length: b.blockLength })
      activeTrackers.push(tracker)
    }

    if (aborted) throw abortReason

    // Wait for all trackers; allSettled so a single block-fetch failure
    // doesn't cascade — matches hyperdrive's own download() behavior.
    await Promise.allSettled(activeTrackers.map(t => t.downloaded()))
    if (aborted) throw abortReason
  } finally {
    disarm()
    // Defense in depth: if anything threw mid-walk and we accumulated
    // trackers but didn't cleanly resolve them, destroy them now so
    // the inner blob refs release the event loop.
    if (aborted) destroyAll()
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
  const metaBytes = (metaCore && metaCore.byteLength) || 0

  // Blob core size — separate update required; drive.update doesn't touch it.
  await updateCore(blobCore)
  const blobBytes = (blobCore && blobCore.byteLength) || 0

  return { totalBytes: metaBytes + blobBytes, metaBytes, blobBytes }
}
