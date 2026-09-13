import test from 'brittle'
import createTestnet from '@hyperswarm/testnet'
import HyperDHT from 'hyperdht'
import b4a from 'b4a'
import { PearBlindRelayTransport } from 'p2p-hiverelay/transports/pear-blind-relay/index.js'

test('integration: Pear 3.4 blind relay carries a forced fallback session', async (t) => {
  const testnet = await createTestnet(3)
  const relayDht = new HyperDHT({ bootstrap: testnet.bootstrap })
  const serverDht = new HyperDHT({ bootstrap: testnet.bootstrap })
  const clientDht = new HyperDHT({ bootstrap: testnet.bootstrap })
  const transport = new PearBlindRelayTransport({
    dht: relayDht,
    keyPair: HyperDHT.keyPair(),
    maxSessions: 8
  })
  const received = []
  const target = serverDht.createServer((socket) => {
    socket.on('error', () => {})
    socket.on('data', (data) => received.push(b4a.toString(data)))
  })

  t.teardown(async () => {
    await Promise.allSettled([
      target.close(),
      transport.stop(),
      clientDht.destroy(),
      serverDht.destroy(),
      relayDht.destroy()
    ])
    await testnet.destroy()
  })

  await transport.start()
  await target.listen()

  const socket = clientDht.connect(target.publicKey, {
    holepunch: () => false,
    relayThrough: transport.publicKey
  })
  socket.on('error', (error) => t.fail(error))
  await new Promise((resolve, reject) => {
    socket.once('open', resolve)
    socket.once('error', reject)
  })
  socket.write('pear-3.4-fallback')

  const deadline = Date.now() + 5000
  while (received.length === 0 && Date.now() < deadline) {
    await new Promise(resolve => setTimeout(resolve, 20))
  }

  t.alike(received, ['pear-3.4-fallback'])
  t.ok(transport.getStats().sessions.accepted >= 2, 'both endpoints used the relay')
  t.ok(transport.getStats().pairings.matched >= 1, 'native pairing completed')
  socket.end()
})

// These use the actual native transport and unmodified blind-relay client;
// duplex fakes cannot establish control-socket or UDX ownership on teardown.
async function waitFor (predicate) {
  const deadline = Date.now() + 5000
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error('Native relay condition timed out')
    await new Promise(resolve => setTimeout(resolve, 10))
  }
}

async function nativeFixture (t, opts = {}) {
  const { default: blindRelay } = await import('blind-relay')
  const testnet = await createTestnet(3)
  const relayDht = new HyperDHT({ bootstrap: testnet.bootstrap })
  const clientDht = new HyperDHT({ bootstrap: testnet.bootstrap })
  const transport = new PearBlindRelayTransport({ dht: relayDht, keyPair: HyperDHT.keyPair(), ...opts })
  const serverSockets = []
  const peers = []
  t.teardown(async () => {
    for (const peer of peers) { peer.client?.destroy(); peer.socket.destroy() }
    for (const socket of serverSockets) socket.destroy()
    await transport.stop()
    await Promise.allSettled([clientDht.destroy(), relayDht.destroy()])
    await testnet.destroy()
  })
  await transport.start()
  transport.server.on('connection', socket => serverSockets.push(socket))
  async function connect () {
    const socket = clientDht.connect(transport.publicKey)
    socket.on('error', () => {})
    const peer = { socket, client: null }
    peers.push(peer)
    await new Promise((resolve, reject) => { socket.once('open', resolve); socket.once('error', reject) })
    peer.client = new blindRelay.Client(socket, { id: socket.publicKey })
    peer.client.on('error', () => {})
    await new Promise((resolve, reject) => { peer.client.once('open', resolve); peer.client.once('error', reject) })
    return peer
  }
  return { transport, relayDht, serverSockets, connect }
}

function nativePair (peer, n, isInitiator = true) {
  const token = b4a.alloc(32)
  token.writeUInt32LE(n)
  const request = peer.client.pair(isInitiator, token, { id: n + 1 })
  request.on('error', () => {})
  request.resume()
}

test('integration: native protocol channel churn does not escape socket ceiling', async t => {
  const f = await nativeFixture(t, { maxSessions: 1 })
  for (let i = 0; i < 4; i++) {
    const peer = await f.connect()
    t.is(f.serverSockets.filter(socket => !socket.destroyed).length, 1)
    peer.client.destroy()
    await waitFor(() => f.transport.getStats().sockets.active === 0)
    t.is(f.serverSockets.filter(socket => !socket.destroyed).length, 0)
  }
  await f.transport.stop()
  t.is(f.transport.getStats().sessions.accepted, 4)
  t.is(f.transport.getStats().sessions.active, 0)
  t.is(f.relayDht.rawStreams.size, 0)
})

test('integration: native pending work is bounded and stop closes real control sockets', async t => {
  const f = await nativeFixture(t, { maxPendingPerSession: 4 })
  const peer = await f.connect()
  for (let i = 0; i < 1000; i++) nativePair(peer, i)
  await waitFor(() => f.transport.getStats().pairings.refused > 0)
  t.ok(f.transport.getStats().pairings.pending <= 4)
  t.is(f.relayDht.rawStreams.size, 0)
  await f.transport.stop()
  t.ok(f.serverSockets.every(socket => socket.destroyed))
  t.is(f.transport.getStats().pairings.pending, 0)
  t.is(f.transport.getStats().sockets.active, 0)
})

test('integration: native active-link budget is enforced before UDX allocation', async t => {
  const f = await nativeFixture(t, { maxActiveLinks: 2 })
  const a = await f.connect(); const b = await f.connect()
  const controlStreamCount = f.relayDht.rawStreams.size
  nativePair(a, 1); nativePair(b, 1, false)
  await waitFor(() => f.transport.getStats().streams.active === 2)
  t.is(f.relayDht.rawStreams.size, controlStreamCount + 2)
  const owned = [...f.transport._streams]
  nativePair(a, 2); nativePair(b, 2, false)
  await waitFor(() => f.transport.getStats().pairings.refused > 0)
  await waitFor(() => owned.every(stream => stream.destroyed) && f.transport.getStats().streams.active === 0)
  t.ok(f.relayDht.rawStreams.size <= controlStreamCount, 'only remaining Noise control streams survive')
  t.is(f.transport.getStats().streams.opened, 2, 'second pair allocated no UDX streams')
  t.is(f.transport.getStats().pairings.active, 0)
})

test('integration: native same-session matched-pair flood creates no UDX streams', async t => {
  const f = await nativeFixture(t)
  const peer = await f.connect()
  for (let i = 0; i < 100; i++) {
    const token = b4a.alloc(32)
    token.writeUInt32LE(i)
    peer.client._pair.send({ isInitiator: true, token, id: i * 2 + 1, seq: 0 })
    peer.client._pair.send({ isInitiator: false, token, id: i * 2 + 2, seq: 0 })
  }
  await waitFor(() => f.transport.getStats().pairings.refused > 0)
  t.is(f.relayDht.rawStreams.size, 0)
  t.is(f.transport.getStats().streams.opened, 0)
  t.is(f.transport.getStats().pairings.pending, 0)
})
