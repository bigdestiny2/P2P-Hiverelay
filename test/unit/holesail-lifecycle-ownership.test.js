import test from 'brittle'
import { createRequire } from 'node:module'
import { HolesailTransport } from 'p2p-hiverelay/transports/holesail/index.js'

const require = createRequire(import.meta.url)

function controlledServers (t, opts = {}) {
  const id = require.resolve('holesail-server')
  require(id)
  const original = require.cache[id].exports
  const instances = []
  class ControlledServer {
    constructor () {
      this.key = 'controlled-' + instances.length
      this.destroys = 0
      this.destroyResult = Promise.resolve()
      instances.push(this)
    }

    start (_opts, callback) {
      this.ready = callback
      return opts.start?.call(this)
    }

    destroy () {
      this.destroys++
      if (this.refreshInterval) {
        clearInterval(this.refreshInterval)
        this.refreshInterval = null
      }
      return this.destroyResult
    }
  }
  require.cache[id].exports = ControlledServer
  t.teardown(() => { require.cache[id].exports = original })
  return instances
}

function deferred () {
  let resolve = null
  let reject = null
  const promise = new Promise((_resolve, _reject) => { resolve = _resolve; reject = _reject })
  return { promise, resolve, reject }
}

test('holesail: stop owns pending startup and prevents late readiness', async (t) => {
  const servers = controlledServers(t)
  const transport = new HolesailTransport()
  const events = []
  transport.on('started', () => events.push('started'))
  transport.on('stopped', () => events.push('stopped'))
  const starting = transport.start()
  const startResult = starting.then(() => null, err => err)
  const server = servers[0]
  const destruction = deferred()
  server.destroyResult = destruction.promise
  t.teardown(async () => {
    destruction.resolve()
    server.ready()
    await startResult
    await transport.stop()
  })

  const stopping = transport.stop()
  const repeatedStop = transport.stop()
  let stopSettled = false
  stopping.then(() => { stopSettled = true })
  t.is(stopping, repeatedStop, 'concurrent stops share exact destruction ownership')
  await new Promise(resolve => setImmediate(resolve))
  t.is(server.destroys, 1, 'stop destroys the allocated server even before readiness')
  server.ready()
  const startError = await startResult
  t.is(startError?.name, 'AbortError', 'pending startup settles as cancellation')
  t.is(transport.running, false, 'late ready callback cannot restart the transport')
  t.alike(events, [], 'no started or stopped event before destruction settles')
  t.is(stopSettled, false, 'stop waits for actual server destruction')
  t.is(transport._server, server, 'unsettled owner remains reachable')
  destruction.resolve()
  await stopping
  t.is(server.destroys, 1, 'concurrent stops do not duplicate destruction')
  t.is(transport._server, null, 'settled server is released')
  t.alike(events, ['stopped'], 'stopped is emitted after exact cleanup')
})

test('holesail: concurrent starts and stops preserve normal restart ownership', async (t) => {
  const servers = controlledServers(t)
  const transport = new HolesailTransport()
  t.teardown(() => transport.stop())
  const events = []
  transport.on('started', ({ connectionKey }) => events.push(connectionKey))
  const first = transport.start()
  t.is(transport.start(), first, 'concurrent starts share exact readiness operation')
  t.is(servers.length, 1, 'only one server allocated')
  servers[0].ready()
  await first
  t.is(transport.running, true, 'normal readiness starts the transport')
  t.is(transport.connectionKey, 'controlled-0', 'connection key belongs to the live server')
  await transport.start()
  t.is(servers.length, 1, 'start while running is idempotent')

  const destruction = deferred()
  servers[0].destroyResult = destruction.promise
  const stop = transport.stop()
  const restarted = transport.start()
  t.is(servers.length, 1, 'restart waits for actual predecessor destruction')
  destruction.resolve()
  await stop
  await Promise.resolve()
  t.is(servers.length, 2, 'restart allocates only after previous owner settles')
  servers[1].ready()
  await restarted
  t.is(transport.running, true, 'restart reaches normal readiness')
  t.alike(events, ['controlled-0', 'controlled-1'], 'one started event per successful owner')
  await transport.stop()
  await transport.stop()
  t.is(servers[0].destroys, 1, 'first server destroyed exactly once')
  t.is(servers[1].destroys, 1, 'restarted server destroyed exactly once')
  t.is(transport.connectionKey, null, 'connection key cleared after stop')
})

test('holesail: failed destruction retains owner for exact retry', async (t) => {
  const servers = controlledServers(t)
  const transport = new HolesailTransport()
  const start = transport.start()
  const server = servers[0]
  server.ready()
  await start
  const failure = new Error('controlled destroy failure')
  const destruction = deferred()
  server.destroyResult = destruction.promise
  const events = []
  transport.on('stopped', () => events.push('stopped'))
  t.teardown(async () => {
    server.destroyResult = Promise.resolve()
    await transport.stop()
  })
  const stop = transport.stop()
  const rejected = stop.then(() => null, err => err)
  t.is(transport.stop(), stop, 'pending destruction is shared without duplicate calls')
  await new Promise(resolve => setImmediate(resolve))
  t.is(server.destroys, 1, 'one actual destruction invocation')
  destruction.reject(failure)
  t.is(await rejected, failure, 'failure is propagated rather than swallowed')
  t.is(transport._server, server, 'failed owner remains reachable')
  t.is(transport.running, false, 'failed stop cannot advertise readiness')
  t.alike(events, [], 'no stopped event before cleanup succeeds')
  const restartError = await transport.start().then(() => null, err => err)
  t.ok(restartError, 'restart cannot replace an unresolved cleanup owner')
  t.is(servers.length, 1, 'restart failure preserves the exact server')
  server.destroyResult = Promise.resolve()
  await transport.stop()
  t.is(server.destroys, 2, 'retry invokes destruction on retained owner')
  t.is(transport._server, null, 'successful retry releases owner')
  t.alike(events, ['stopped'], 'stopped emitted only after successful retry')
})

test('holesail: stop wins a readiness callback before its promise continuation', async (t) => {
  const servers = controlledServers(t)
  const transport = new HolesailTransport()
  const starting = transport.start()
  const result = starting.then(() => null, err => err)
  servers[0].ready()
  const stop = transport.stop()
  t.is((await result)?.name, 'AbortError', 'queued readiness observes stop before publishing')
  await stop
  t.is(transport.running, false, 'transport remains stopped')
  t.is(servers[0].destroys, 1, 'server destroyed exactly once')
})

test('holesail: asynchronous startup rejection retains cleanup ownership', async (t) => {
  const id = require.resolve('holesail-server')
  require(id)
  const original = require.cache[id].exports
  const failure = new Error('controlled startup failure')
  let server = null
  require.cache[id].exports = class {
    constructor () { server = this; this.destroys = 0 }
    async start () { throw failure }
    async destroy () { this.destroys++ }
  }
  t.teardown(() => { require.cache[id].exports = original })
  const transport = new HolesailTransport()
  t.is(await transport.start().then(() => null, err => err), failure, 'async start rejection is observed')
  t.is(transport._server, server, 'failed start retains the allocated server')
  t.is(transport.running, false, 'failed start never advertises readiness')
  await transport.stop()
  t.is(server.destroys, 1, 'failed-start owner is cleaned up exactly once')
  t.is(transport._server, null, 'cleanup releases failed-start owner')
})

test('holesail: stop settles the underlying start before destroying late resources', async (t) => {
  const completion = deferred()
  const servers = controlledServers(t, {
    async start () {
      await completion.promise
      this.refreshInterval = setInterval(() => {}, 60_000)
      this.refreshInterval.unref()
    }
  })
  const transport = new HolesailTransport()
  const start = transport.start()
  const startResult = start.then(() => null, err => err)
  const server = servers[0]
  t.teardown(async () => {
    completion.resolve()
    await startResult
    await transport.stop()
    clearInterval(server.refreshInterval)
  })
  server.ready()
  await new Promise(resolve => setImmediate(resolve))
  t.is(transport.running, false, 'listen callback alone is not full startup settlement')
  const stop = transport.stop()
  let stopSettled = false
  stop.then(() => { stopSettled = true })
  await new Promise(resolve => setImmediate(resolve))
  t.is(stopSettled, false, 'stop retains the actual pending upstream operation')
  t.is(server.destroys, 0, 'destruction waits until upstream can no longer allocate resources')
  t.is(transport._server, server, 'pending upstream start retains the exact owner')
  completion.resolve()
  await stop
  t.is((await startResult)?.name, 'AbortError', 'startup cannot become ready after stop')
  t.is(server.destroys, 1, 'one destruction after upstream startup settles')
  t.is(server.refreshInterval, null, 'late upstream timer is destroyed before ownership is released')
  t.is(transport._server, null, 'owner is released only after complete cleanup')
})
