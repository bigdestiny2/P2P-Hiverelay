import test from 'brittle'
import {
  LIFECYCLE_ACTION_DELAY_MS,
  resolveLifecycleManagementRoute,
  runLifecycleAction
} from '../../packages/core/core/relay-node/api-lifecycle-actions.js'

function scheduler () {
  const calls = []
  return {
    calls,
    schedule (fn, delay) {
      calls.push({ fn, delay })
    }
  }
}

test('api lifecycle actions: route helper maps POST management paths to lifecycle actions', (t) => {
  t.alike(resolveLifecycleManagementRoute('POST', '/api/manage/restart'), {
    action: 'restart'
  })
  t.alike(resolveLifecycleManagementRoute('POST', '/api/manage/shutdown'), {
    action: 'shutdown'
  })
  t.is(resolveLifecycleManagementRoute('GET', '/api/manage/restart'), null)
  t.is(resolveLifecycleManagementRoute('POST', '/api/manage/restart/now'), null)
  t.is(resolveLifecycleManagementRoute('POST', '/api/manage/services/restart'), null)
})

test('api lifecycle actions: restart schedules stop then start after response payload', async (t) => {
  const events = []
  const timers = scheduler()
  const node = {
    async stop () { events.push('stop') },
    async start () { events.push('start') }
  }

  const out = runLifecycleAction({
    action: 'restart',
    node,
    emit: (...args) => events.push(args),
    schedule: timers.schedule
  })

  t.is(out.status, 200)
  t.alike(out.payload, { ok: true, message: 'Restarting node...' })
  t.is(timers.calls.length, 1)
  t.is(timers.calls[0].delay, LIFECYCLE_ACTION_DELAY_MS)
  t.alike(events, [], 'work is deferred until after response')

  await timers.calls[0].fn()
  t.alike(events, ['stop', 'start'])
})

test('api lifecycle actions: restart emits API error when stop or start fails', async (t) => {
  const emitted = []
  const timers = scheduler()
  const err = new Error('start failed')
  const node = {
    async stop () {},
    async start () { throw err }
  }

  runLifecycleAction({
    action: 'restart',
    node,
    emit: (...args) => emitted.push(args),
    schedule: timers.schedule
  })
  await timers.calls[0].fn()

  t.is(emitted.length, 1)
  t.alike(emitted[0], ['error', { context: 'restart', error: err }])
})

test('api lifecycle actions: shutdown schedules stop and emits clean completion', async (t) => {
  const emitted = []
  const timers = scheduler()
  const node = {
    async stop () {},
    emit: (...args) => emitted.push(args)
  }

  const out = runLifecycleAction({
    action: 'shutdown',
    node,
    schedule: timers.schedule
  })

  t.is(out.status, 200)
  t.alike(out.payload, { ok: true, message: 'Shutting down...' })
  t.is(timers.calls.length, 1)
  t.is(timers.calls[0].delay, LIFECYCLE_ACTION_DELAY_MS)
  t.alike(emitted, [], 'shutdown event is deferred')

  await timers.calls[0].fn()
  t.alike(emitted, [['shutdown-complete', { clean: true }]])
})

test('api lifecycle actions: shutdown emits unclean completion when stop fails', async (t) => {
  const emitted = []
  const timers = scheduler()
  const err = new Error('stop failed')
  const node = {
    async stop () { throw err },
    emit: (...args) => emitted.push(args)
  }

  runLifecycleAction({
    action: 'shutdown',
    node,
    schedule: timers.schedule
  })
  await timers.calls[0].fn()

  t.alike(emitted, [['shutdown-complete', { clean: false, error: err }]])
})

test('api lifecycle actions: unknown action is not scheduled', (t) => {
  const timers = scheduler()
  const out = runLifecycleAction({
    action: 'hibernate',
    node: {},
    schedule: timers.schedule
  })

  t.is(out.status, 404)
  t.alike(out.payload, { error: 'unknown lifecycle action' })
  t.is(timers.calls.length, 0)
})
