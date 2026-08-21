import test from 'brittle'
import { createServer } from 'node:net'
import { WebSocket } from 'ws'
import { DHTRelayWS } from 'p2p-hiverelay/transports/dht-relay-ws/index.js'

// Minimal DHT stand-in. The real @hyperswarm/dht-relay only touches the DHT
// inside `relay()` after a successful protocol handshake. For start/stop
// lifecycle tests we never get that far — tests that exercise an actual
// relay handshake belong in integration suites with a real HyperDHT.
function fakeDHT () {
  return { /* stand-in — relay() is invoked but won't be exercised end-to-end */ }
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
