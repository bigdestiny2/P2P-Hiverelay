import test from 'brittle'
import { createConnection, createServer } from 'node:net'
import { WebSocket } from 'ws'
import { DHTRelayWS } from 'p2p-hiverelay/transports/dht-relay-ws/index.js'

// Minimal DHT stand-in. The real @hyperswarm/dht-relay only touches the DHT
// inside `relay()` after a successful protocol handshake. For start/stop
// lifecycle tests we never get that far — tests that exercise an actual
// relay handshake belong in integration suites with a real HyperDHT.
function fakeDHT () {
  return { /* stand-in — relay() is invoked but won't be exercised end-to-end */ }
}

async function openRawTcp (port) {
  const socket = createConnection({ host: '127.0.0.1', port })
  await new Promise((resolve, reject) => {
    const onConnect = () => {
      socket.removeListener('error', onError)
      resolve()
    }
    const onError = (err) => {
      socket.removeListener('connect', onConnect)
      reject(err)
    }
    socket.once('connect', onConnect)
    socket.once('error', onError)
  })
  // Shutdown tests intentionally provoke forceful TCP destruction.
  socket.on('error', () => {})
  return socket
}

function rawWebSocketRequest () {
  return [
    'GET / HTTP/1.1',
    'Host: 127.0.0.1',
    'Upgrade: websocket',
    'Connection: Upgrade',
    'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
    'Sec-WebSocket-Version: 13',
    '',
    ''
  ].join('\r\n')
}

function upgradeRawWebSocket (socket) {
  return new Promise((resolve, reject) => {
    let response = ''
    const onData = (chunk) => {
      response += chunk.toString('latin1')
      if (!response.includes('101 Switching Protocols')) return
      cleanup()
      resolve()
    }
    const onClose = () => {
      cleanup()
      reject(new Error('raw socket closed before WebSocket upgrade completed'))
    }
    const cleanup = () => {
      socket.removeListener('data', onData)
      socket.removeListener('close', onClose)
    }
    socket.on('data', onData)
    socket.once('close', onClose)
    socket.write(rawWebSocketRequest())
  })
}

function waitForSocketClose (socket) {
  if (socket.destroyed) return Promise.resolve()
  return new Promise((resolve) => socket.once('close', resolve))
}

test('DHTRelayWS: requires dht', (t) => {
  try {
    // eslint-disable-next-line no-new
    new DHTRelayWS({})
    t.fail('should throw')
  } catch (err) {
    t.ok(err.message.includes('dht is required'), 'clear error when dht missing')
  }
})

test('DHTRelayWS: port 0 atomically allocates a connectable ephemeral port', async (t) => {
  const transport = new DHTRelayWS({ dht: fakeDHT(), port: 0, host: '127.0.0.1' })
  t.is(transport.port, 0, 'preserves the ephemeral-port request before start')

  await transport.start()
  t.ok(transport.running, 'running after start')
  const port = transport.port
  t.ok(Number.isInteger(port) && port > 0, 'exposes the kernel-assigned port after start')
  t.is(transport.server.address().port, port, 'reported port matches the bound listener')
  t.is(transport.getStats().port, port, 'stats expose the effective port')

  // Confirm the port is actually listening by opening a client socket.
  const client = new WebSocket(`ws://127.0.0.1:${port}`)
  await new Promise((resolve, reject) => {
    client.on('open', resolve)
    client.on('error', reject)
  })
  t.ok(true, 'client could connect')
  client.close()

  await transport.stop()
  t.absent(transport.running, 'stopped cleanly')
})

test('DHTRelayWS: port 0 restart does not reuse an occupied old port', async (t) => {
  const transport = new DHTRelayWS({ dht: fakeDHT(), port: 0, host: '127.0.0.1' })
  t.teardown(() => transport.stop())

  await transport.start()
  const firstPort = transport.port
  await transport.stop()

  const blocker = createServer()
  await new Promise((resolve, reject) => {
    blocker.once('error', reject)
    blocker.listen(firstPort, '127.0.0.1', resolve)
  })
  t.teardown(() => new Promise(resolve => blocker.close(resolve)))

  await transport.start()
  t.is(transport._bindPort, 0, 'configured bind request remains ephemeral')
  t.not(transport.port, firstPort, 'restart receives a fresh port while the old one is occupied')
  t.is(transport.server.address().port, transport.port, 'effective port matches the restarted listener')
})

test('DHTRelayWS: concurrent port 0 starts materialize one listener', async (t) => {
  const transport = new DHTRelayWS({ dht: fakeDHT(), port: 0, host: '127.0.0.1' })
  t.teardown(() => transport.stop())
  let started = 0
  transport.on('started', () => { started++ })

  await Promise.all([transport.start(), transport.start()])

  t.is(started, 1, 'concurrent starts emit one successful lifecycle transition')
  t.ok(transport.running, 'transport is running')
  t.is(transport.server.address().port, transport.port, 'one tracked listener owns the effective port')

  const server = transport.server
  await transport.stop()
  t.absent(transport.running, 'transport stopped cleanly')
  t.is(server.address(), null, 'the only materialized listener was closed')
})

test('DHTRelayWS: stop during a pending start cancels the listener', async (t) => {
  const transport = new DHTRelayWS({ dht: fakeDHT(), port: 0, host: '127.0.0.1' })
  t.teardown(() => transport.stop())
  let started = 0
  transport.on('started', () => { started++ })

  const starting = transport.start()
  // Let the queued start construct its WebSocketServer, but stay ahead of the
  // asynchronous `listening` event so stop exercises the pending-start path.
  await Promise.resolve()
  t.ok(transport.server, 'start has materialized a pending server')
  const pendingServer = transport.server
  const stopping = transport.stop()

  await Promise.all([starting, stopping])

  t.is(started, 0, 'cancelled start never advertises a running transport')
  t.absent(transport.running, 'stop resolves with the transport stopped')
  t.is(transport.server, null, 'cancelled listener is no longer tracked')
  t.is(pendingServer.address(), null, 'cancelled listener is closed')

  await transport.start()
  t.ok(transport.running, 'a later sequential start still succeeds')
  t.is(started, 1, 'only the later successful start is advertised')
  t.ok(transport.port > 0, 'later start receives an effective ephemeral port')
})

test('DHTRelayWS: shutdown destroys an incomplete HTTP upgrade within its owner budget', async (t) => {
  t.timeout(7000)
  const transport = new DHTRelayWS({ dht: fakeDHT(), port: 0, host: '127.0.0.1' })
  t.teardown(() => transport.stop())
  await transport.start()

  // Hold verifyClient open forever so this valid HTTP upgrade owns a TCP
  // socket but never becomes a ws client. This is the shutdown gap that an
  // ordinary WebSocketServer.clients sweep cannot see.
  const upgradeStalled = new Promise((resolve) => {
    transport.server.options.verifyClient = (_info, _callback) => { resolve() }
  })
  const raw = await openRawTcp(transport.port)
  t.teardown(() => raw.destroy())
  raw.write(rawWebSocketRequest())
  await upgradeStalled

  const server = transport.server
  const httpServer = transport._httpServer
  const tcpConnectionHandler = transport._httpConnectionHandler
  t.is(server.clients.size, 0, 'incomplete upgrade is not a tracked ws client')
  t.is(transport._tcpSockets.size, 1, 'underlying TCP connection is owned')
  const rawClosed = waitForSocketClose(raw)
  const startedAt = Date.now()
  await transport.stop()
  await rawClosed

  t.ok(Date.now() - startedAt < 5000, 'shutdown finishes far inside the 30s owner budget')
  t.ok(raw.destroyed, 'incomplete upgrade TCP socket was destroyed')
  t.is(server.address(), null, 'WebSocket listener is closed')
  t.absent(httpServer.listening, 'owned HTTP listener is closed')
  t.is(transport.server, null, 'WebSocket server reference is cleared')
  t.is(transport._httpServer, null, 'HTTP server reference is cleared')
  t.is(transport._tcpSockets.size, 0, 'TCP ownership set is cleared')
  t.is(transport.connections.size, 0, 'WebSocket connection map is cleared')
  t.is(transport._ipBuckets.size, 0, 'rate-limit state is cleared')
  t.is(transport._httpConnectionHandler, null, 'TCP ownership listener reference is cleared')
  t.absent(httpServer.listeners('connection').includes(tcpConnectionHandler), 'TCP ownership listener is detached')
  t.alike(server.eventNames(), [], 'WebSocket server listeners are detached')
  t.is(transport._cleanupTimer, null, 'cleanup timer is cleared')
  t.is(transport._supervisorTimer, null, 'supervisor timer is cleared')

  await transport.start()
  t.ok(transport.running, 'transport restarts after forced incomplete-upgrade cleanup')
  await transport.stop()
})

test('DHTRelayWS: shutdown force-terminates an upgraded peer that ignores close', async (t) => {
  t.timeout(7000)
  const transport = new DHTRelayWS({ dht: fakeDHT(), port: 0, host: '127.0.0.1' })
  t.teardown(() => transport.stop())
  await transport.start()

  // A raw TCP peer completes the WebSocket handshake but never parses or
  // acknowledges the server's close frame.
  const raw = await openRawTcp(transport.port)
  t.teardown(() => raw.destroy())
  await upgradeRawWebSocket(raw)
  t.is(transport.connections.size, 1, 'upgraded peer is tracked before shutdown')
  t.is(transport._tcpSockets.size, 1, 'upgraded peer retains TCP ownership')

  const server = transport.server
  const httpServer = transport._httpServer
  const rawClosed = waitForSocketClose(raw)
  const startedAt = Date.now()
  await transport.stop()
  await rawClosed

  t.ok(Date.now() - startedAt < 5000, 'forced shutdown finishes far inside the 30s owner budget')
  t.ok(raw.destroyed, 'non-acknowledging peer TCP socket was destroyed')
  t.is(server.address(), null, 'WebSocket listener is closed')
  t.absent(httpServer.listening, 'owned HTTP listener is closed')
  t.is(transport.server, null, 'WebSocket server reference is cleared')
  t.is(transport._httpServer, null, 'HTTP server reference is cleared')
  t.is(transport._tcpSockets.size, 0, 'TCP ownership set is cleared')
  t.is(transport.connections.size, 0, 'WebSocket connection map is cleared')
})

test('DHTRelayWS: bind failure cleans ownership and permits a later start', async (t) => {
  const blocker = createServer()
  await new Promise((resolve, reject) => {
    blocker.once('error', reject)
    blocker.listen(0, '127.0.0.1', resolve)
  })
  const port = blocker.address().port
  const transport = new DHTRelayWS({ dht: fakeDHT(), port, host: '127.0.0.1' })
  t.teardown(async () => {
    await transport.stop()
    if (blocker.listening) await new Promise(resolve => blocker.close(resolve))
  })

  await t.exception(transport.start(), /EADDRINUSE/)
  t.absent(transport.running, 'failed bind never marks the transport running')
  t.is(transport.server, null, 'failed WebSocket server reference is cleared')
  t.is(transport._httpServer, null, 'failed HTTP server reference is cleared')
  t.is(transport._tcpSockets.size, 0, 'failed bind owns no TCP sockets')

  await new Promise(resolve => blocker.close(resolve))
  await transport.start()
  t.ok(transport.running, 'lifecycle queue recovers for a later start')
  await transport.stop()
  t.is(transport.server, null, 'later stop clears the WebSocket server')
  t.is(transport._httpServer, null, 'later stop clears the HTTP server')
})

test('DHTRelayWS: enforces maxConnections', async (t) => {
  const transport = new DHTRelayWS({ dht: fakeDHT(), port: 0, host: '127.0.0.1', maxConnections: 1 })
  await transport.start()
  t.teardown(() => transport.stop())
  const port = transport.port

  // First client gets in.
  const c1 = new WebSocket(`ws://127.0.0.1:${port}`)
  await new Promise((resolve) => c1.on('open', resolve))

  // Wait a tick so the server registers the connection in `connections`.
  await new Promise((resolve) => setTimeout(resolve, 50))

  // Second client should be closed by the server with our capacity code.
  const c2 = new WebSocket(`ws://127.0.0.1:${port}`)
  const closeCode = await new Promise((resolve) => {
    c2.on('close', (code) => resolve(code))
  })
  t.is(closeCode, 1013, 'capacity refusal returns ws code 1013')

  c1.close()
})

test('DHTRelayWS: getStats reports operating numbers', async (t) => {
  const transport = new DHTRelayWS({ dht: fakeDHT(), port: 0, host: '127.0.0.1' })
  await transport.start()
  t.teardown(() => transport.stop())
  const port = transport.port

  const before = transport.getStats()
  t.is(before.running, true)
  t.is(before.totalConnectionsServed, 0)
  t.is(before.activeConnections, 0)

  // Open and close a couple of clients to bump counters.
  for (let i = 0; i < 3; i++) {
    const c = new WebSocket(`ws://127.0.0.1:${port}`)
    await new Promise((resolve) => c.on('open', resolve))
    c.close()
    await new Promise((resolve) => setTimeout(resolve, 30))
  }

  const after = transport.getStats()
  t.is(after.totalConnectionsServed, 3, 'totalConnectionsServed counts every accept')
})
