import test from 'brittle'
import { once } from 'node:events'
import { createServer } from 'node:http'
import { WebSocket } from 'ws'
import { PokerWsAdapter } from '../../packages/services/builtin/poker/ws-adapter.js'

const TABLE = 'a'.repeat(64)

test('poker ws adapter preserves public event reads without an api key', async (t) => {
  const { adapter, server, url } = await startPokerWs()
  t.teardown(async () => {
    adapter.stop()
    await closeServer(server)
  })

  const ws = new WebSocket(url)
  t.teardown(() => {
    try { ws.terminate() } catch {}
  })

  const [raw] = await once(ws, 'message')
  const msg = JSON.parse(raw.toString())
  t.is(msg.type, 'state')
  t.is(msg.state.tableKey, TABLE)
  t.is(adapter.clientCount(TABLE), 1)
})

test('poker ws adapter rejects URL tokens and waits for in-band auth before state', async (t) => {
  const authFailures = []
  const { adapter, server, url } = await startPokerWs({
    apiKey: 'sekrit',
    authTimeoutMs: 100,
    log: (label, info) => {
      if (label === 'ws-auth-failed') authFailures.push(info.reason)
    }
  })
  t.teardown(async () => {
    adapter.stop()
    await closeServer(server)
  })

  const queryToken = new WebSocket(url + '?token=sekrit')
  t.teardown(() => {
    try { queryToken.terminate() } catch {}
  })
  const [queryErr] = await once(queryToken, 'error')
  t.ok(queryErr.message.includes('401'), 'upgrade rejects query-token auth')
  t.alike(authFailures, ['query-token'])

  const ws = new WebSocket(url)
  t.teardown(() => {
    try { ws.terminate() } catch {}
  })
  const messages = []
  ws.on('message', (data) => messages.push(data.toString()))

  await once(ws, 'open')
  await delay(30)
  t.is(adapter.clientCount(TABLE), 0, 'client is not counted before auth')
  t.is(messages.length, 0, 'state frame is not sent before auth')

  ws.send(JSON.stringify({ type: 'auth', token: 'sekrit' }))
  await waitUntil(() => messages.length > 0)

  const state = JSON.parse(messages[0])
  t.is(state.type, 'state')
  t.is(state.state.tableKey, TABLE)
  t.is(adapter.clientCount(TABLE), 1, 'client is counted after valid auth')
})

test('poker ws adapter closes invalid auth frames without attaching clients', async (t) => {
  const authFailures = []
  const { adapter, server, url } = await startPokerWs({
    apiKey: 'sekrit',
    authTimeoutMs: 100,
    log: (label, info) => {
      if (label === 'ws-auth-failed') authFailures.push(info.reason)
    }
  })
  t.teardown(async () => {
    adapter.stop()
    await closeServer(server)
  })

  const ws = new WebSocket(url)
  t.teardown(() => {
    try { ws.terminate() } catch {}
  })

  await once(ws, 'open')
  ws.send(JSON.stringify({ type: 'auth', token: 'wrong' }))
  const [code, reason] = await once(ws, 'close')

  t.is(code, 1008)
  t.is(reason.toString(), 'auth-failed')
  t.alike(authFailures, ['invalid'])
  t.is(adapter.clientCount(TABLE), 0)
})

test('poker ws adapter redacts subscribe failures from clients', async (t) => {
  const logs = []
  const secretPath = '/data/poker/private/subscription-secret'
  const { adapter, server, url } = await startPokerWs({
    log: (label, info) => logs.push({ label, info }),
    pokerApp: {
      getState (tableKey) {
        return tableKey === TABLE ? { tableKey, players: [] } : null
      },
      subscribe () {
        throw new Error('subscribe failed at ' + secretPath)
      }
    }
  })
  t.teardown(async () => {
    adapter.stop()
    await closeServer(server)
  })

  const ws = new WebSocket(url)
  t.teardown(() => {
    try { ws.terminate() } catch {}
  })
  const [raw] = await once(ws, 'message')
  const msg = JSON.parse(raw.toString())
  t.alike(msg, { type: 'error', error: 'subscribe-failed' })
  t.absent(raw.toString().includes(secretPath), 'client frame does not include internal error text')
  t.is(logs[0].label, 'ws-subscribe-error')
  t.ok(logs[0].info.error.includes(secretPath), 'internal log keeps diagnostic detail')
})

test('poker ws adapter redacts public state lookup failures during upgrade', async (t) => {
  const secretPath = '/data/poker/private/state-secret'
  const logs = []
  const { adapter, server, url } = await startPokerWs({
    log: (label, info) => logs.push({ label, info }),
    pokerApp: {
      getState () {
        throw new Error('state failed at ' + secretPath)
      },
      subscribe () {
        return () => {}
      }
    }
  })
  t.teardown(async () => {
    adapter.stop()
    await closeServer(server)
  })

  const ws = new WebSocket(url)
  t.teardown(() => {
    try { ws.terminate() } catch {}
  })
  const [err] = await once(ws, 'error')
  t.ok(err.message.includes('503'), 'upgrade fails with stable service unavailable response')
  t.absent(err.message.includes(secretPath), 'client error does not include internal state failure text')
  t.is(logs[0].label, 'ws-state-error')
  t.is(logs[0].info.context, 'upgrade')
  t.ok(logs[0].info.error.includes(secretPath), 'internal log keeps diagnostic detail')
})

test('poker ws adapter redacts authenticated state lookup failures after auth', async (t) => {
  const secretPath = '/data/poker/private/post-auth-state-secret'
  const logs = []
  const { adapter, server, url } = await startPokerWs({
    apiKey: 'sekrit',
    log: (label, info) => logs.push({ label, info }),
    pokerApp: {
      getState () {
        throw new Error('state failed at ' + secretPath)
      },
      subscribe () {
        return () => {}
      }
    }
  })
  t.teardown(async () => {
    adapter.stop()
    await closeServer(server)
  })

  const ws = new WebSocket(url)
  t.teardown(() => {
    try { ws.terminate() } catch {}
  })
  await once(ws, 'open')
  ws.send(JSON.stringify({ type: 'auth', token: 'sekrit' }))

  const [raw] = await once(ws, 'message')
  const msg = JSON.parse(raw.toString())
  t.alike(msg, { type: 'error', error: 'state-unavailable' })
  t.absent(raw.toString().includes(secretPath), 'client frame does not include internal state failure text')
  const [code, reason] = await once(ws, 'close')
  t.is(code, 1011)
  t.is(reason.toString(), 'state-unavailable')
  t.is(logs[0].label, 'ws-state-error')
  t.is(logs[0].info.context, 'auth')
})

async function startPokerWs (opts = {}) {
  const server = createServer((req, res) => {
    res.statusCode = 404
    res.end()
  })
  const pokerApp = opts.pokerApp || {
    getState (tableKey) {
      return tableKey === TABLE ? { tableKey, players: [] } : null
    },
    subscribe () {
      return () => {}
    }
  }
  const adapter = new PokerWsAdapter({
    pokerApp,
    server,
    apiKey: opts.apiKey,
    authTimeoutMs: opts.authTimeoutMs || 100,
    log: opts.log
  })
  adapter.start()
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = server.address().port
  return { adapter, server, url: `ws://127.0.0.1:${port}/api/poker/${TABLE}/events` }
}

async function closeServer (server) {
  if (!server.listening) return
  await new Promise((resolve) => server.close(resolve))
}

function delay (ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function waitUntil (fn, timeoutMs = 500) {
  const started = Date.now()
  return new Promise((resolve, reject) => {
    const tick = () => {
      if (fn()) return resolve()
      if (Date.now() - started > timeoutMs) return reject(new Error('timed out waiting for condition'))
      setTimeout(tick, 10)
    }
    tick()
  })
}
