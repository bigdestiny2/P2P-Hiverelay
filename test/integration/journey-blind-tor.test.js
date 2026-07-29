/**
 * GIGA DoD cross-feature journey — blind × tor
 * (docs/GIGA-RELEASE-ARCHITECTURE.md §7 "Cross-feature journeys":
 * custody traffic to a relay reachable over its Tor onion endpoint).
 *
 * What this proves (composition, not internals):
 *   1. A RelayNode with the tor transport enabled binds its OnionPeerListener
 *      and advertises BOTH vports through the (faked) control port — read
 *      plane 80 and peer plane 19737 — and reaches verified-ready health.
 *   2. A client that dials the onion peer vport (SOCKS → fake-daemon
 *      forwarding → OnionPeerListener) completes the Noise XK upgrade and
 *      lands in the relay's normal connection handler, which attaches the
 *      custody/publish protocol channels to that stream.
 *   3. The custody path is reachable through the onion: a properly
 *      publisher-signed custody intent submitted over the channel is
 *      validated and appended to the relay's seeding registry.
 *   4. ONION-INV-006 — reachability ≠ authority: the SAME channel refuses
 *      a forged (bad-signature) intent. The transport granted reachability
 *      (v3 auth/Noise), never service authorization.
 *
 * Realization: real RelayNode + real OnionPeerListener + real Noise XK +
 * real publish-channel request/response on a hyperswarm testnet; the tor
 * daemon is faked at the protocol level (control + SOCKS, see
 * helpers/fake-tor.js) so the whole thing runs headless — the same mocking
 * seam as test/unit/tor-transport.test.js, one layer out.
 */

import test from 'brittle'
import createTestnet from '@hyperswarm/testnet'
import NoiseSecretStream from '@hyperswarm/secret-stream'
import b4a from 'b4a'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import { TorTransport } from 'p2p-hiverelay/transports/tor/index.js'
import { PublishProtocolClient } from 'p2p-hiverelay/core/protocol/publish-channel.js'
import { createCustodyIntent, hashHex } from 'p2p-hiverelay/core/custody-signing.js'
import { startFakeTorDaemon } from './helpers/fake-tor.js'

const PEER_VPORT = 19737
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

function tmpdir (t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hiverelay-journey-blind-tor-'))
  t.teardown(() => { try { fs.rmSync(dir, { recursive: true, force: true }) } catch {} })
  return dir
}

async function waitFor (label, fn, timeoutMs = 15_000) {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    const value = await fn()
    if (value) return value
    await sleep(100)
  }
  throw new Error(`${label} timed out after ${timeoutMs}ms`)
}

test('journey blind × tor: custody ops over the onion peer vport — reachability ≠ authority (ONION-INV-006)', async (t) => {
  const dir = tmpdir(t)
  const relayStorage = path.join(dir, 'relay')
  fs.mkdirSync(relayStorage, { recursive: true })

  const testnet = await createTestnet(3)
  const tor = await startFakeTorDaemon(t)

  const relay = new RelayNode({
    storage: relayStorage,
    bootstrapNodes: testnet.bootstrap,
    enableAPI: false,
    enableRelay: false,
    enableSeeding: true,
    enableServices: false,
    enableNetworkDiscovery: false,
    enableHolesail: false,
    transports: { udp: true, tor: true },
    tor: {
      socksPort: tor.socksPort,
      controlPort: tor.controlPort,
      keyFile: path.join(dir, 'relay-tor', 'hs-key.blob'),
      // No cookie on disk → the transport falls back to bare AUTHENTICATE,
      // which the fake control port accepts.
      cookieAuthFile: path.join(dir, 'relay-tor', 'control_auth_cookie'),
      peer: { port: 0 } // ephemeral loopback bind; the vport mapping materializes after bind
    }
  })
  t.teardown(async () => {
    try { await relay.stop() } catch {}
    try { await testnet.destroy() } catch {}
  })
  await relay.start()

  // ─── 1. Dual vports advertised; health-gated readiness reached ────────
  t.ok(relay.torTransport, 'relay constructed its tor transport from config')
  t.ok(relay.torTransport.running, 'tor transport started headless against the fake daemon')
  await waitFor('tor health ready', () => relay.torTransport.health === 'ready')
  t.is(relay.torTransport.onionAddress, tor.onionAddress, 'persistent v3 identity from the control plane')

  const addOnion = tor.addOnionCommands().pop()
  t.ok(addOnion.includes('Port=80,127.0.0.1:9100'), 'read-plane vport forwarded (apiPort default)')
  t.ok(addOnion.includes('Port=19737,127.0.0.1:' + relay.torTransport.peerListener.port),
    'peer vport 19737 forwarded to the bound OnionPeerListener')

  // The server side must see the inbound peer connection as onion-sourced.
  const serverSide = new Promise((resolve) => {
    relay.torTransport.on('connection', (stream, info) => resolve(info))
  })

  // ─── 2. Client dials the onion peer vport; Noise XK upgrade ───────────
  const clientTor = new TorTransport({ socksPort: tor.socksPort })
  t.teardown(async () => { try { await clientTor.stop() } catch {} })
  await clientTor.start()

  const clientKP = NoiseSecretStream.keyPair()
  const relayPub = relay.swarm.keyPair.publicKey
  const relayPubHex = b4a.toString(relayPub, 'hex')

  const torStream = await clientTor.connect(tor.onionAddress, PEER_VPORT)
  t.teardown(() => { try { torStream.destroy() } catch {} })
  const noise = new NoiseSecretStream(true, torStream, {
    keyPair: clientKP,
    remotePublicKey: relayPub,
    pattern: 'XK'
  })
  t.teardown(() => { try { noise.destroy() } catch {} })
  await new Promise((resolve, reject) => {
    noise.once('handshake', resolve)
    noise.once('error', reject)
  })
  t.alike([...noise.remotePublicKey], [...relayPub], 'client authenticated the relay identity over Noise XK')

  const info = await Promise.race([serverSide, sleep(5000).then(() => null)])
  t.ok(info && info.isOnion === true && info.type === 'tor', 'relay connection handler received it as an onion peer')

  // ─── 3. Custody path reachable through the onion ──────────────────────
  const publisher = NoiseSecretStream.keyPair()
  const publish = new PublishProtocolClient({ submitTimeoutMs: 10_000 })
  t.teardown(() => { try { publish.destroy() } catch {} })
  t.ok(publish.attach(noise, relayPubHex), 'publish channel attaches to the onion stream')
  await Promise.race([
    new Promise((resolve) => publish.once('channel-open', resolve)),
    sleep(5000).then(() => { throw new Error('publish channel never opened over the onion') })
  ])

  const intent = createCustodyIntent({
    addressKey: b4a.toString(NoiseSecretStream.keyPair().publicKey, 'hex'),
    blindContentId: hashHex({ journey: 'blind-tor', n: 1 }),
    ciphertextRoot: b4a.toString(NoiseSecretStream.keyPair().publicKey, 'hex'),
    contentVersion: 1,
    requiredReplicas: 1,
    deadline: Date.now() + 60_000,
    retainUntil: Date.now() + 3_600_000,
    shardPolicy: 'all'
  }, publisher)

  const accepted = await publish.submit(relayPubHex, 'intent', intent)
  t.ok(accepted.ok, 'signed custody intent accepted through the onion: ' + JSON.stringify(accepted))
  const stored = await waitFor('intent in registry', () => {
    try { return relay.seedingRegistry.getCustodyIntent(intent.intentId) } catch { return null }
  })
  t.is(stored.blindContentId, intent.blindContentId, 'registry appended the onion-submitted intent')

  // ─── 4. ONION-INV-006: the transport granted reachability, not authority
  // Same channel, same Noise session — a forged intent (valid shape, bad
  // signature) must still be refused by the custody layer.
  const forged = {
    ...intent,
    intentId: hashHex({ journey: 'blind-tor', forged: true }),
    blindContentId: hashHex({ journey: 'blind-tor', forged: true })
  }
  const refused = await publish.submit(relayPubHex, 'intent', forged)
  t.absent(refused.ok, 'forged intent refused through the same onion channel')
  t.ok(/INVALID_CUSTODY_ENTRY|bad signature/.test(refused.error || ''),
    'refusal is the custody signature check, not a transport error: ' + refused.error)
  let forgedStored = true
  try { forgedStored = relay.seedingRegistry.getCustodyIntent(forged.intentId) } catch { forgedStored = null }
  t.absent(forgedStored, 'forged intent never entered the registry')
})
