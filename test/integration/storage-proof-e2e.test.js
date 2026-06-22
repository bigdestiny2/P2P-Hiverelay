/**
 * Storage-proof END-TO-END over a real (testnet) DHT + Protomux.
 *
 * The genuine "live proveSeeded smoke", three real nodes:
 *   - publisher: authors + announces a Hyperdrive,
 *   - relay: storage-proof enabled, seeds (replicates) that drive,
 *   - client: a real HiveRelayClient that discovers the relay via the DHT and
 *     runs client.proveSeeded — which calls the relay's storage-proof service
 *     over the actual JSON-over-Protomux service RPC (anonymous / 'public'
 *     route) and verifies every signed proof against the drive key.
 *
 * Exercises the full path the local unit tests stub: DHT discovery, the service
 * channel, the public access policy, and proof verification end to end.
 */
import test from 'brittle'
import createTestnet from '@hyperswarm/testnet'
import Hyperswarm from 'hyperswarm'
import Corestore from 'corestore'
import Hyperdrive from 'hyperdrive'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import { HiveRelayClient } from 'p2p-hiverelay-client'
import b4a from 'b4a'
import path from 'path'
import { tmpdir } from 'os'
import { randomBytes } from 'crypto'

const tmpStorage = () => path.join(tmpdir(), 'hr-pos-e2e-' + randomBytes(8).toString('hex'))
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

test('e2e: client.proveSeeded verifies a relay holds a seeded drive over the swarm', { timeout: 120000 }, async (t) => {
  const testnet = await createTestnet(3)

  // ── Publisher: authors + announces a multi-block drive ──
  const publisher = new RelayNode({
    storage: tmpStorage(), bootstrapNodes: testnet.bootstrap, enableAPI: false, enableMetrics: false, enableServices: false
  })
  await publisher.start()
  const drive = new Hyperdrive(publisher.store)
  await drive.ready()
  for (let i = 0; i < 6; i++) await drive.put('/f' + i, b4a.from('content-' + i + '-'.padEnd(40, 'x')))
  const driveKey = b4a.toString(drive.key, 'hex')
  publisher.swarm.join(drive.discoveryKey, { server: true, client: true })
  await publisher.swarm.flush()

  // ── Relay: storage-proof enabled, seeds (replicates) the drive ──
  const relay = new RelayNode({
    storage: tmpStorage(),
    bootstrapNodes: testnet.bootstrap,
    enableAPI: false,
    enableMetrics: false,
    enableServices: true,
    plugins: ['storage-proof']
  })
  await relay.start()
  await relay.seedApp(driveKey)
  const relayDrive = relay.seededApps.get(driveKey).drive
  await relayDrive.update({ wait: true })
  // Download the full metadata core so any sampled block index is held locally.
  await relayDrive.core.download({ start: 0, end: relayDrive.core.length }).done()
  t.ok(relayDrive.core.length > 0, 'relay replicated the drive metadata core')

  // ── Client: discover the relay + proveSeeded over the wire ──
  const clientSwarm = new Hyperswarm({ bootstrap: testnet.bootstrap })
  const client = new HiveRelayClient({ swarm: clientSwarm, store: new Corestore(tmpStorage()) })

  t.teardown(async () => {
    try { await client.destroy() } catch {}
    try { await clientSwarm.destroy() } catch {}
    try { await drive.close() } catch {}
    try { await relay.stop() } catch {}
    try { await publisher.stop() } catch {}
    try { await testnet.destroy() } catch {}
  })

  await client.start(); await clientSwarm.flush()

  const relayHex = b4a.toString(relay.swarm.keyPair.publicKey, 'hex')
  let found = false
  for (let i = 0; i < 60 && !found; i++) {
    if (client.relays.has(relayHex)) { found = true; break }
    await sleep(500); await clientSwarm.flush()
  }
  t.ok(found, 'client discovered the storage-proof relay via DHT')

  // The real thing — callService over Protomux, anonymous (public route), signed
  // proofs verified against the drive key. Fail fast if it hangs so the failure
  // is legible rather than eating the global timeout.
  const result = await Promise.race([
    client.proveSeeded(driveKey, { relay: relayHex, samples: 4 }),
    new Promise((_resolve, reject) => setTimeout(() => reject(new Error('PROVE_HANG_60s')), 60000))
  ])
  t.ok(result.ok, 'proveSeeded ok=true — relay produced valid signed proofs over the wire')
  t.is(result.passed, result.total, 'every sampled block verified')
  t.ok(result.total >= 1, 'at least one block sampled')
  t.ok(result.head > 0, 'head reflects the replicated metadata core')
})
