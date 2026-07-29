/**
 * cancellable-drive-update tests.
 *
 * Verifies that updateWithTimeout() and downloadWithTimeout() actually
 * cancel the underlying hypercore upgrade requests / hyperdrive download
 * trackers when the timeout fires. The bug they fix is the leak where
 * Promise.race resolves on timeout but the underlying hypercore update
 * keeps its upgrade ref attached, leaking sessions over time.
 *
 * Tests use a mock Hyperdrive that exposes `activeRequests` and tracks
 * whether `clearRequests` got called. No real swarm needed.
 */

import test from 'brittle'
import { updateWithTimeout, downloadWithTimeout, getDriveSize } from 'p2p-hiverelay/core/relay-node/cancellable-drive-update.js'

// Mock Hyperdrive that:
//   - exposes drive.db.core.replicator.clearRequests(activeRequests, err)
//   - records every clearRequests call so tests can assert
//   - drive.update(opts) returns a pending promise + pushes a fake "ref" into opts.activeRequests
function mockDrive ({ updateLatency = null, updateRejects = null, downloadLatency = null, downloadRejects = null } = {}) {
  const clearCalls = []
  const drive = {
    closed: false,
    closing: false,
    version: 1,
    db: {
      core: {
        replicator: {
          clearRequests (session, err) {
            clearCalls.push({ count: session.length, err })
            // Detach refs from the session (mirror real hypercore behavior)
            while (session.length > 0) {
              const ref = session.pop()
              if (ref && typeof ref.reject === 'function') ref.reject(err || new Error('cancelled'))
            }
          }
        }
      }
    },
    update (opts) {
      // Push a fake ref into activeRequests so the cancellation path has
      // something to detach. Real hypercore pops the ref on resolve/reject
      // via Attachable._detach; the mock mirrors that so a clean update()
      // resolution leaves activeRequests empty.
      return new Promise((resolve, reject) => {
        const arr = (opts && Array.isArray(opts.activeRequests)) ? opts.activeRequests : null
        const ref = {
          resolve: (v) => {
            if (arr) {
              const i = arr.indexOf(ref)
              if (i >= 0) arr.splice(i, 1)
            }
            resolve(v)
          },
          reject: (e) => {
            if (arr) {
              const i = arr.indexOf(ref)
              if (i >= 0) arr.splice(i, 1)
            }
            reject(e)
          }
        }
        if (arr) arr.push(ref)
        if (updateLatency !== null) {
          setTimeout(() => ref.resolve(true), updateLatency).unref?.()
        } else if (updateRejects) {
          setTimeout(() => ref.reject(updateRejects), 5).unref?.()
        }
        // Otherwise hang forever (simulates a real drive.update waiting
        // for an upgrade that never comes).
      })
    },
    download () {
      let destroyed = false
      return {
        destroy () { destroyed = true },
        get destroyed () { return destroyed },
        done () {
          return new Promise((resolve, reject) => {
            if (downloadLatency !== null) {
              setTimeout(() => resolve(undefined), downloadLatency).unref?.()
            } else if (downloadRejects) {
              setTimeout(() => reject(downloadRejects), 5).unref?.()
            }
            // Otherwise hang
          })
        }
      }
    }
  }
  return { drive, clearCalls }
}

// ─── updateWithTimeout ──────────────────────────────────────────────

test('updateWithTimeout: resolves when update completes before timeout', async (t) => {
  const { drive, clearCalls } = mockDrive({ updateLatency: 10 })
  const result = await updateWithTimeout(drive, { timeoutMs: 1000 })
  t.is(result, true)
  t.is(clearCalls.length, 0, 'no cancel called on success')
})

test('updateWithTimeout: rejects + calls clearRequests on timeout', async (t) => {
  const { drive, clearCalls } = mockDrive() // update hangs forever
  try {
    await updateWithTimeout(drive, { timeoutMs: 50 })
    t.fail('should have timed out')
  } catch (err) {
    t.is(err.message, 'update timeout')
  }
  // Allow microtasks to settle so the finally-block clearRequests fires.
  await new Promise(resolve => setImmediate(resolve))
  t.ok(clearCalls.length >= 1, 'clearRequests called on timeout')
  // Critical: the ref was actually drained
  const lastCall = clearCalls[clearCalls.length - 1]
  t.ok(lastCall.err && lastCall.err.message, 'clearRequests passed an error')
})

test('updateWithTimeout: propagates non-timeout rejections cleanly', async (t) => {
  const { drive } = mockDrive({ updateRejects: new Error('network down') })
  try {
    await updateWithTimeout(drive, { timeoutMs: 1000 })
    t.fail('should have rejected')
  } catch (err) {
    t.is(err.message, 'network down')
  }
  // No timeout happened, so clearRequests may or may not have been called
  // depending on whether the ref was detached by the rejection. Either is
  // acceptable; what matters is no LEAK.
})

test('updateWithTimeout: tolerates missing replicator without crashing', async (t) => {
  // Drive without db.core.replicator — older hypercore, mocked corestore, etc.
  const drive = {
    db: {},
    update: () => new Promise(() => {})
  }
  try {
    await updateWithTimeout(drive, { timeoutMs: 50 })
    t.fail('should have timed out')
  } catch (err) {
    t.is(err.message, 'update timeout')
    // Just verify we didn't crash on the missing replicator
  }
})

test('updateWithTimeout: clears the active-requests array on timeout', async (t) => {
  const { drive, clearCalls } = mockDrive() // hangs
  let captured = null
  // Wrap update to capture the activeRequests array
  const origUpdate = drive.update.bind(drive)
  drive.update = (opts) => {
    captured = opts.activeRequests
    return origUpdate(opts)
  }

  try { await updateWithTimeout(drive, { timeoutMs: 30 }) } catch {}
  await new Promise(resolve => setImmediate(resolve))

  t.ok(captured, 'activeRequests was passed to update()')
  t.is(captured.length, 0, 'activeRequests array drained after timeout')
  t.ok(clearCalls.length >= 1, 'clearRequests was called at least once')
})

test('updateWithTimeout: an already-aborted signal never starts an update', async (t) => {
  const controller = new AbortController()
  controller.abort(new Error('client already gone'))
  let updateCalls = 0
  const drive = {
    update () {
      updateCalls++
      return new Promise(() => {})
    }
  }

  let failure = null
  try {
    await updateWithTimeout(drive, { timeoutMs: 1000, signal: controller.signal })
  } catch (err) {
    failure = err
  }
  t.is(failure?.name, 'AbortError')
  t.is(updateCalls, 0, 'abort-before-start creates no replicator request')
})

test('updateWithTimeout: abort detaches only this operation and removes its listener', async (t) => {
  const { drive, clearCalls } = mockDrive()
  let driveCloseCalls = 0
  drive.close = async () => { driveCloseCalls++ }
  const controller = new AbortController()
  let adds = 0
  let removes = 0
  const add = controller.signal.addEventListener.bind(controller.signal)
  const remove = controller.signal.removeEventListener.bind(controller.signal)
  controller.signal.addEventListener = (...args) => { adds++; return add(...args) }
  controller.signal.removeEventListener = (...args) => { removes++; return remove(...args) }

  const pending = updateWithTimeout(drive, {
    timeoutMs: 1000,
    signal: controller.signal
  })
  await new Promise(resolve => setImmediate(resolve))
  controller.abort(new Error('client disconnected'))

  let failure = null
  try { await pending } catch (err) { failure = err }
  t.is(failure?.name, 'AbortError')
  t.is(clearCalls.length, 1, 'operation request set is cleared exactly once')
  t.is(clearCalls[0].count, 1, 'only the update-owned ref was present')
  t.is(driveCloseCalls, 0, 'cancelling an update never closes a shared drive')
  t.is(adds, 1, 'one abort listener installed')
  t.is(removes, 1, 'abort listener removed after settlement')
})

test('updateWithTimeout: timeout and abort race settles and clears idempotently', async (t) => {
  const { drive, clearCalls } = mockDrive()
  const controller = new AbortController()
  const pending = updateWithTimeout(drive, {
    timeoutMs: 15,
    signal: controller.signal
  })
  setTimeout(() => controller.abort(), 15)

  let failure = null
  try { await pending } catch (err) { failure = err }
  t.ok(failure?.name === 'AbortError' || failure?.message === 'update timeout', 'one bounded terminal reason wins')
  await new Promise(resolve => setImmediate(resolve))
  t.is(clearCalls.length, 1, 'race cannot clear/reject the operation twice')
})

// ─── downloadWithTimeout ────────────────────────────────────────────

test('downloadWithTimeout: resolves when download completes before timeout', async (t) => {
  const { drive } = mockDrive({ downloadLatency: 10 })
  await downloadWithTimeout(drive, '/', { timeoutMs: 1000 })
  t.pass('download completed')
})

test('downloadWithTimeout: rejects + destroys tracker on timeout', async (t) => {
  const { drive } = mockDrive() // download hangs
  let trackerRef = null
  const origDownload = drive.download.bind(drive)
  drive.download = (path) => {
    trackerRef = origDownload(path)
    return trackerRef
  }
  try {
    await downloadWithTimeout(drive, '/', { timeoutMs: 50 })
    t.fail('should have timed out')
  } catch (err) {
    t.is(err.message, 'download timeout')
  }
  t.ok(trackerRef.destroyed, 'download tracker was destroyed on timeout')
})

test('downloadWithTimeout: propagates download() construction errors', async (t) => {
  const drive = {
    download () { throw new Error('drive closed') }
  }
  try {
    await downloadWithTimeout(drive, '/', { timeoutMs: 100 })
    t.fail('should have thrown')
  } catch (err) {
    t.is(err.message, 'drive closed')
  }
})

test('downloadWithTimeout: works against hyperdrive 11.x Promise-shape download() API', async (t) => {
  // Real hyperdrive 11.13.4's drive.download() is async — returns a
  // Promise<void>, NOT a tracker object with .done()/.destroy(). The
  // pre-fix code called dl.done() unconditionally and threw
  // "TypeError: dl.done is not a function" in production, silently
  // breaking every repair-loop download.
  let resolveDownload
  const downloadPromise = new Promise(resolve => { resolveDownload = resolve })
  const drive = {
    closed: false,
    closing: false,
    download (path) { return downloadPromise }
  }
  setTimeout(() => resolveDownload(), 20)
  await downloadWithTimeout(drive, '/', { timeoutMs: 500 })
  t.pass('Promise-shape download resolved without TypeError')
})

test('downloadWithTimeout: Promise-shape download timeout rejects cleanly', async (t) => {
  // Same shape as 11.x but the download never resolves; ensure the
  // timeout still rejects with "download timeout".
  const drive = {
    closed: false,
    closing: false,
    download (path) { return new Promise(() => {}) } // hangs forever
  }
  try {
    await downloadWithTimeout(drive, '/', { timeoutMs: 50 })
    t.fail('should have timed out')
  } catch (err) {
    t.is(err.message, 'download timeout', 'timeout fires even without tracker.destroy()')
  }
})

test('downloadWithTimeout: Promise-shape download rejection propagates', async (t) => {
  const drive = {
    closed: false,
    closing: false,
    download (path) { return Promise.reject(new Error('replication failed')) }
  }
  try {
    await downloadWithTimeout(drive, '/', { timeoutMs: 500 })
    t.fail('should have rejected with the underlying error')
  } catch (err) {
    t.is(err.message, 'replication failed', 'underlying download error surfaces verbatim')
  }
})

test('downloadWithTimeout: defensive destroy on rejection path', async (t) => {
  const { drive } = mockDrive({ downloadRejects: new Error('replication failed') })
  let trackerRef = null
  const origDownload = drive.download.bind(drive)
  drive.download = (path) => {
    trackerRef = origDownload(path)
    return trackerRef
  }
  try {
    await downloadWithTimeout(drive, '/', { timeoutMs: 1000 })
    t.fail('should have rejected')
  } catch (err) {
    t.is(err.message, 'replication failed')
  }
  // The finally-block destroys defensively even on reject paths
  t.ok(trackerRef.destroyed, 'tracker destroyed by defensive cleanup')
})

// ─── getDriveSize ───────────────────────────────────────────────────

function mockDriveWithCores ({ metaBytes = 0, blobBytes = 0, blobsCorePresent = true }) {
  const makeCore = (byteLength) => ({
    length: 0,
    byteLength,
    update: () => Promise.resolve(true),
    replicator: {
      clearRequests () {}
    }
  })
  const drive = {
    db: { core: makeCore(metaBytes) }
  }
  if (blobsCorePresent) {
    drive.blobs = { core: makeCore(blobBytes) }
  }
  return drive
}

test('getDriveSize: sums metadata + blob core byteLengths', async (t) => {
  const drive = mockDriveWithCores({ metaBytes: 1_236_505, blobBytes: 381_674_831 })
  const r = await getDriveSize(drive, { timeoutMs: 1000 })
  t.is(r.metaBytes, 1_236_505)
  t.is(r.blobBytes, 381_674_831)
  t.is(r.totalBytes, 382_911_336)
})

test('getDriveSize: tolerates missing blobs core', async (t) => {
  const drive = mockDriveWithCores({ metaBytes: 100, blobsCorePresent: false })
  const r = await getDriveSize(drive, { timeoutMs: 1000 })
  t.is(r.metaBytes, 100)
  t.is(r.blobBytes, 0)
  t.is(r.totalBytes, 100)
})

test('getDriveSize: best-effort under update timeout', async (t) => {
  // Core whose update hangs — getDriveSize should still return whatever
  // byteLength the core had before the update timed out, not throw.
  const hangingCore = {
    length: 0,
    byteLength: 999,
    update: () => new Promise(() => {}), // hang forever
    replicator: {
      clearRequests () {}
    }
  }
  const drive = {
    db: { core: hangingCore },
    blobs: { core: { length: 0, byteLength: 42, update: () => Promise.resolve(true), replicator: { clearRequests () {} } } }
  }
  const r = await getDriveSize(drive, { timeoutMs: 30 })
  // Returned without throwing; sizes reflect whatever was visible at call time.
  t.is(r.metaBytes, 999)
  t.is(r.blobBytes, 42)
  t.is(r.totalBytes, 1041)
})

test('getDriveSize: missing drive.db core returns zeros gracefully', async (t) => {
  const r = await getDriveSize({}, { timeoutMs: 100 })
  t.is(r.metaBytes, 0)
  t.is(r.blobBytes, 0)
  t.is(r.totalBytes, 0)
})

test('getDriveSize retries an append injected between length and byteLength getters', async (t) => {
  function changingCore (firstBytes, finalBytes) {
    const lengths = [1, 2, 2, 2, 2, 2, 2, 2, 2, 2]
    const bytes = [firstBytes, finalBytes, finalBytes, finalBytes, finalBytes]
    return {
      get length () { return lengths.length > 1 ? lengths.shift() : 2 },
      get byteLength () { return bytes.length > 1 ? bytes.shift() : finalBytes },
      async update () { return true },
      replicator: { clearRequests () {} }
    }
  }
  const meta = changingCore(10, 100)
  const blob = changingCore(20, 200)
  const result = await getDriveSize({
    db: { core: meta },
    blobs: { core: blob },
    version: 2
  }, { timeoutMs: 100, requireAuthoritative: true })
  t.is(result.metaLength, 2)
  t.is(result.blobLength, 2)
  t.is(result.totalBytes, 300, 'proof uses one stable signed snapshot per core')
})

test('getDriveSize rejects a drive version advance across pinned proof creation', async (t) => {
  let versionReads = 0
  let snapshotsClosed = 0
  const makeCore = (bytes) => ({
    fork: 0,
    length: 1,
    byteLength: bytes,
    async update () { return true },
    replicator: { clearRequests () {} },
    snapshot () {
      return {
        fork: 0,
        length: 1,
        byteLength: bytes,
        async ready () {},
        async close () { snapshotsClosed++ }
      }
    }
  })
  const drive = {
    db: { core: makeCore(10) },
    blobs: { core: makeCore(20) },
    get version () { return ++versionReads === 1 ? 1 : 2 }
  }
  await t.exception(
    getDriveSize(drive, { timeoutMs: 100, requireAuthoritative: true, pinSnapshots: true }),
    /DRIVE_VERSION_CHANGED_DURING_PROOF/
  )
  t.is(snapshotsClosed, 2, 'both stale proof snapshots are closed')
})
