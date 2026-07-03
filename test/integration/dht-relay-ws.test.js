/**
 * End-to-end test: a "browser-like" client tunnels HyperDHT operations
 * through DHTRelayWS over a real WebSocket against a real HyperDHT node.
 *
 * This is the test that proves the original reviewer feedback ("no
 * DHT-relay WebSocket out of the box") is actually closed — not just that
 * the WS server starts, but that DHT control traffic round-trips correctly.
 */

import test from 'brittle'
import createTestnet from '@hyperswarm/testnet'
import { WebSocket } from 'ws'
import RelayedDHT from '@hyperswarm/dht-relay'
import RelayedStream from '@hyperswarm/dht-relay/ws'
import { DHTRelayWS } from 'p2p-hiverelay/transports/dht-relay-ws/index.js'

function pickPort () {
  return 50000 + Math.floor(Math.random() * 10000)
}

test('e2e: relayed client completes handshake and ready() through the WS', async (t) => {
  // Critical "the protocol actually works" test. Proves that:
  //   1. The WS server accepts a real client socket
  //   2. The dht-relay handshake completes (Node ↔ NodeProxy)
  //   3. The relayed DHT exposes its keypair (proxied from the real DHT)
  // This is the minimum that closes the original "no DHT-relay-WS" feedback —
  // we have an actual end-to-end DHT instance reachable through a browser WS.
  const testnet = await createTestnet(2, t.teardown)
  const relayDHT = testnet.nodes[0]

  const port = pickPort()
  const relayWs = new DHTRelayWS({ dht: relayDHT, port, host: '127.0.0.1' })
  await relayWs.start()
  t.teardown(() => relayWs.stop())

  const socket = new WebSocket(`ws://127.0.0.1:${port}`)
  await new Promise((resolve, reject) => {
    socket.on('open', resolve)
    socket.on('error', reject)
  })

  const browserDHT = new RelayedDHT(new RelayedStream(true, socket))
  await browserDHT.ready()

  t.ok(browserDHT.defaultKeyPair, 'relayed DHT has a keypair after ready')
  t.ok(browserDHT.defaultKeyPair.publicKey, 'keypair has a public key')
  t.is(browserDHT.defaultKeyPair.publicKey.length, 32, 'public key is 32 bytes')
  t.is(relayWs.getStats().activeConnections, 1, 'server tracks the active session')

  await browserDHT.destroy()
  socket.close()
  // Give the server-side close handler a moment.
  await new Promise(resolve => setTimeout(resolve, 100))
})

test('e2e: WS server cleanly handles client disconnect mid-session', async (t) => {
  const testnet = await createTestnet(2, t.teardown)
  const relayDHT = testnet.nodes[0]
  const port = pickPort()
  const relayWs = new DHTRelayWS({ dht: relayDHT, port, host: '127.0.0.1' })
  await relayWs.start()
  t.teardown(() => relayWs.stop())

  // Connect, ready up, then yank the socket without graceful close.
  const socket = new WebSocket(`ws://127.0.0.1:${port}`)
  await new Promise((resolve) => socket.on('open', resolve))

  const browserDHT = new RelayedDHT(new RelayedStream(true, socket))
  await browserDHT.ready()
  t.is(relayWs.getStats().activeConnections, 1, 'relay sees one active session')

  // Hard close — the relay should drop the session, not leak it.
  socket.terminate()
  await new Promise((resolve) => setTimeout(resolve, 100))

  t.is(relayWs.getStats().activeConnections, 0, 'relay cleaned up the dropped connection')
})

test('crash-safety: a proxied DHT op that throws tears down only its connection, never the process', async (t) => {
  const testnet = await createTestnet(2, t.teardown)
  const relayDHT = testnet.nodes[0]

  // Wrap the real DHT so lookup() throws synchronously — simulating a
  // malformed/hostile frame or an op against a closed DHT. Upstream let such a
  // throw propagate out of the protocol EventEmitter → uncaughtException →
  // whole-relay crash-loop under systemd. Our vendored node-proxy `guard` must
  // contain it to the one faulting connection. Everything else proxies to the
  // real DHT (methods bound to it) so the handshake still completes.
  const throwingDht = new Proxy(relayDHT, {
    get (target, prop) {
      if (prop === 'lookup') return () => { throw new Error('boom: simulated DHT fault') }
      const v = target[prop]
      return typeof v === 'function' ? v.bind(target) : v
    }
  })

  const port = pickPort()
  const relayWs = new DHTRelayWS({ dht: throwingDht, port, host: '127.0.0.1' })
  await relayWs.start()
  t.teardown(() => relayWs.stop())

  // A clean run already implies the process survived (brittle aborts on an
  // uncaught fault), but assert it explicitly by trapping any that escape.
  const fatal = []
  const onFatal = (err) => fatal.push(err)
  process.on('uncaughtException', onFatal)
  process.on('unhandledRejection', onFatal)
  t.teardown(() => {
    process.off('uncaughtException', onFatal)
    process.off('unhandledRejection', onFatal)
  })

  const socket = new WebSocket(`ws://127.0.0.1:${port}`)
  await new Promise((resolve, reject) => { socket.on('open', resolve); socket.on('error', reject) })
  const browserDHT = new RelayedDHT(new RelayedStream(true, socket))
  await browserDHT.ready()
  t.is(relayWs.getStats().activeConnections, 1, 'session established (handshake unaffected)')

  // Trigger the throwing op. The relayed lookup stream errors/closes as the
  // relay tears its connection down; we only care that the process survives.
  try {
    const stream = browserDHT.lookup(Buffer.alloc(32))
    stream.on('error', () => {})
    if (typeof stream.resume === 'function') stream.resume()
  } catch (_) {}

  await new Promise((resolve) => setTimeout(resolve, 300))

  t.is(fatal.length, 0, 'no uncaughtException/unhandledRejection escaped the guard')
  t.is(relayWs.getStats().activeConnections, 0, 'only the faulting connection was torn down')

  try { await browserDHT.destroy() } catch (_) {}
  try { socket.close() } catch (_) {}
})
