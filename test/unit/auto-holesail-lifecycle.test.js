import test from 'brittle'
import http from 'node:http'
import { EventEmitter } from 'node:events'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import { LifecycleScope } from 'p2p-hiverelay/core/relay-node/lifecycle-scope.js'

for (const phase of ['public IP lookup', 'API health probe']) {
  test(`auto holesail: shutdown cancels an in-flight ${phase}`, async (t) => {
    const scope = new LifecycleScope()
    // Enter the probe immediately; the existing initial sleep has its own
    // LifecycleScope cancellation coverage.
    scope.sleep = async () => {}
    let received = null
    const incoming = new Promise(resolve => { received = resolve })
    const server = http.createServer((_request, _response) => received())
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
    const originalGet = http.get
    let request = null
    let timer = null
    let operation = null
    let drain = null
    t.teardown(async () => {
      http.get = originalGet
      clearTimeout(timer)
      if (request) request.destroy(new Error('test cleanup'))
      if (operation) await operation
      if (drain) await drain
      server.closeAllConnections()
      await new Promise(resolve => server.close(resolve))
    })
    http.get = (_url, options, onResponse) => {
      // Use a real ClientRequest and stalled local server. Preserve the
      // production options so a missing AbortSignal leaves the request live.
      request = originalGet(`http://127.0.0.1:${server.address().port}`, options, onResponse)
      return request
    }
    const events = []
    const node = {
      _scope: scope,
      _stopRequested: false,
      running: true,
      config: { apiPort: 9100 },
      swarm: { connections: [], keyPair: {}, dht: { host: phase === 'API health probe' ? '127.0.0.1' : null } },
      holesailTransport: null,
      emit: (...args) => events.push(args)
    }
    operation = scope.tracked(RelayNode.prototype._autoEnableHolesail.call(node))
    await incoming
    node._stopRequested = true
    drain = scope.drain()
    const drained = await Promise.race([
      drain.then(() => true),
      new Promise(resolve => { timer = setTimeout(() => resolve(false), 1000) })
    ])
    clearTimeout(timer)
    t.is(drained, true, 'scope settles without waiting for the network timeout')
    t.is(request.destroyed, true, 'shutdown destroys the real HTTP request')
    t.alike(events, [], 'shutdown emits no late NAT result or transport start')
    t.is(node.holesailTransport, null, 'no transport is created during shutdown')
  })
}

test('auto holesail: shutdown suppresses a completed health result awaiting continuation', async (t) => {
  const scope = new LifecycleScope()
  scope.sleep = async () => {}
  const originalGet = http.get
  t.teardown(() => { http.get = originalGet })
  let respond = null
  let entered = null
  const enteredProbe = new Promise(resolve => { entered = resolve })
  http.get = (_url, _options, callback) => {
    respond = () => {
      const response = new EventEmitter()
      callback(response)
      response.emit('data', '{"ok":true}')
      response.emit('end')
    }
    entered()
    return new EventEmitter()
  }
  const events = []
  const node = {
    _scope: scope,
    _stopRequested: false,
    running: true,
    config: { apiPort: 9100 },
    swarm: { connections: [], keyPair: {}, dht: { host: '127.0.0.1' } },
    holesailTransport: null,
    emit: (...args) => events.push(args)
  }
  const operation = scope.tracked(RelayNode.prototype._autoEnableHolesail.call(node))
  await enteredProbe
  // Resolve the network promise, then begin shutdown before its await resumes.
  respond()
  node._stopRequested = true
  await scope.drain()
  await operation
  t.is(scope.aborted, true, 'shutdown has aborted the lifecycle')
  t.alike(events, [], 'completed response cannot publish a late NAT result')
  t.is(node.holesailTransport, null, 'completed response cannot start a transport')
})
