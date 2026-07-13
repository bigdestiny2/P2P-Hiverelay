import test from 'brittle'
import { _waitForDriveUpdate } from 'p2p-hiverelay-client'

test('client open update clears its losing timeout after prompt success', async (t) => {
  const nativeSetTimeout = globalThis.setTimeout
  const nativeClearTimeout = globalThis.clearTimeout
  const activeTimers = new Set()
  let clearedRequests = 0
  globalThis.setTimeout = (fn, ms, ...args) => {
    const timer = nativeSetTimeout(fn, ms, ...args)
    activeTimers.add(timer)
    return timer
  }
  globalThis.clearTimeout = (timer) => {
    activeTimers.delete(timer)
    return nativeClearTimeout(timer)
  }

  const drive = {
    db: {
      core: {
        replicator: {
          clearRequests (requests) {
            clearedRequests++
            requests.length = 0
          }
        }
      }
    },
    async update ({ activeRequests }) {
      activeRequests.push({ id: 'prompt-update' })
    }
  }

  try {
    await _waitForDriveUpdate(drive, 60_000)
    t.is(activeTimers.size, 0, 'prompt success leaves no referenced timeout')
    t.is(clearedRequests, 1, 'settled update detaches any residual tracked request')
  } finally {
    globalThis.setTimeout = nativeSetTimeout
    globalThis.clearTimeout = nativeClearTimeout
    for (const timer of activeTimers) nativeClearTimeout(timer)
  }
})

test('client open update timeout rejects and clears the active request', async (t) => {
  let clearedRequests = 0
  const drive = {
    db: {
      core: {
        replicator: {
          clearRequests (requests, error) {
            clearedRequests++
            t.ok(error instanceof Error, 'cancellation carries an error')
            requests.length = 0
          }
        }
      }
    },
    update ({ activeRequests }) {
      activeRequests.push({ id: 'stalled-update' })
      return new Promise(() => {})
    }
  }

  await t.exception(
    _waitForDriveUpdate(drive, 10),
    /Drive update timed out/,
    'timeout rejects promptly'
  )
  t.is(clearedRequests, 1, 'timeout detaches the stalled update request exactly once')
})
