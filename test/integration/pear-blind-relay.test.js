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
