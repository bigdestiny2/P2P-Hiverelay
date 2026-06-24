export const LIFECYCLE_ACTION_DELAY_MS = 500

export function runLifecycleAction ({
  action,
  node,
  emit = () => {},
  schedule = setTimeout,
  delayMs = LIFECYCLE_ACTION_DELAY_MS
}) {
  if (action === 'restart') {
    schedule(async () => {
      try {
        await node.stop()
        await node.start()
      } catch (err) {
        emit('error', { context: 'restart', error: err })
      }
    }, delayMs)
    return {
      ok: true,
      status: 200,
      payload: { ok: true, message: 'Restarting node...' }
    }
  }

  if (action === 'shutdown') {
    schedule(async () => {
      try {
        await node.stop()
        node.emit('shutdown-complete', { clean: true })
      } catch (err) {
        node.emit('shutdown-complete', { clean: false, error: err })
      }
    }, delayMs)
    return {
      ok: true,
      status: 200,
      payload: { ok: true, message: 'Shutting down...' }
    }
  }

  return {
    ok: false,
    status: 404,
    payload: { error: 'unknown lifecycle action' }
  }
}
