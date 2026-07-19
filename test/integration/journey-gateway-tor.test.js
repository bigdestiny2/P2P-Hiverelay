/**
 * GIGA DoD cross-feature journey — gateway × tor
 * (docs/GIGA-RELEASE-ARCHITECTURE.md §7 "Cross-feature journeys":
 * "public app served via gateway while custody entries hard-403; same
 * relay reachable over onion").
 *
 * What this proves (composition, not internals):
 *   1. The onion read-plane vport (80) forwards to the relay's HTTP
 *      API/gateway port — asserted on the actual ADD_ONION the relay's
 *      TorTransport issued from config.
 *   2. A public-tier drive seeded on the relay serves exact bytes through
 *      the onion gateway path (/v1/hyper/<key>/<path>), fetched over the
 *      tor transport's SOCKS connect.
 *   3. A blind (custody-class) drive seeded on the SAME relay is a hard
 *      403 through the SAME onion read plane — identical to clearnet
 *      behavior ("Private app — encrypted content, P2P access only").
 *   4. The relay's signed capability doc, fetched through the same onion
 *      read plane, carries the health-gated privacyTransports onion
 *      advertisement (only present while health === ready).
 *
 * Realization: real RelayNode + real HyperGateway on a hyperswarm testnet,
 * drives authored + seeded through the production seed path (same pattern
 * as test/integration/gateway-streaming.test.js); tor daemon faked at the
 * protocol level (helpers/fake-tor.js) — bytes really traverse the
 * transport's SOCKS stream into the relay's HTTP stack.
 */

import test from 'brittle'
import createTestnet from '@hyperswarm/testnet'
import b4a from 'b4a'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import { TorTransport } from 'p2p-hiverelay/transports/tor/index.js'
import { startFakeTorDaemon } from './helpers/fake-tor.js'

const READ_VPORT = 80
const TEST_MAX_STORAGE_BYTES = 64 * 1024 * 1024
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

function tmpdir (t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hiverelay-journey-gateway-tor-'))
  t.teardown(() => { try { fs.rmSync(dir, { recursive: true, force: true }) } catch {} })
  return dir
}

function pickPort () {
  return 49000 + Math.floor(Math.random() * 10000)
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

/** HTTP/1.0 GET through the onion read plane; parses status/headers/body. */
async function httpGetOverOnion (transport, onionAddress, vport, requestPath) {
  const stream = await transport.connect(onionAddress, vport)
  const raw = await new Promise((resolve, reject) => {
    const chunks = []
    stream.on('data', (d) => chunks.push(d))
    stream.on('end', () => resolve(Buffer.concat(chunks)))
    stream.on('error', reject)
    stream.write(`GET ${requestPath} HTTP/1.0\r\nHost: ${onionAddress}\r\nConnection: close\r\n\r\n`)
  })
  const idx = raw.indexOf('\r\n\r\n')
  const head = raw.subarray(0, idx).toString()
  const lines = head.split('\r\n')
  const headers = {}
  for (const line of lines.slice(1)) {
    const split = line.indexOf(':')
    if (split > 0) headers[line.slice(0, split).trim().toLowerCase()] = line.slice(split + 1).trim()
  }
  return {
    status: Number(lines[0].split(' ')[1]),
    headers,
    body: raw.subarray(idx + 4)
  }
}

test('journey gateway × tor: public bytes through the onion read plane, blind content hard-403 on the same plane', async (t) => {
  const dir = tmpdir(t)
  const relayStorage = path.join(dir, 'relay')
  fs.mkdirSync(relayStorage, { recursive: true })

  const testnet = await createTestnet(3)
  const tor = await startFakeTorDaemon(t)
  const apiPort = pickPort()

  const relay = new RelayNode({
    storage: relayStorage,
    bootstrapNodes: testnet.bootstrap,
    enableAPI: true,
    apiPort,
    apiHost: '127.0.0.1',
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
      cookieAuthFile: path.join(dir, 'relay-tor', 'control_auth_cookie'),
      peer: { port: 0 }
    }
  })
  t.teardown(async () => {
    try { await relay.stop() } catch {}
    try { await testnet.destroy() } catch {}
  })
  await relay.start()

  // ─── Seed a public drive and a blind drive via the production seed path
  // Author through namespace-isolated sessions (two keyless Hyperdrives on
  // one root session deadlock at ready()), then close the writers before
  // the relay adopts the keys through the production seed path.
  const Hyperdrive = (await import('hyperdrive')).default
  const publicHtml = b4a.from('<!doctype html><h1>public over onion</h1>\n')
  const blindCiphertext = b4a.from('sealed-ciphertext-the-gateway-must-never-serve\n')

  const publicWriter = new Hyperdrive(relay.store.namespace('public-app'))
  await publicWriter.ready()
  await publicWriter.put('/index.html', publicHtml)
  const publicKeyHex = b4a.toString(publicWriter.key, 'hex')
  await publicWriter.close()

  const blindWriter = new Hyperdrive(relay.store.namespace('blind-app'))
  await blindWriter.ready()
  await blindWriter.put('/index.html', blindCiphertext)
  const blindKeyHex = b4a.toString(blindWriter.key, 'hex')
  await blindWriter.close()

  await relay.seedApp(publicKeyHex, { privacyTier: 'public', maxStorage: TEST_MAX_STORAGE_BYTES })
  const anchored = await waitFor('public drive anchored', () => relay.appRegistry.get(publicKeyHex)?.anchored === true)
  t.ok(anchored, 'public drive seeded through the production path')

  await relay.seedApp(blindKeyHex, {
    privacyTier: 'p2p-only',
    blind: true,
    maxStorage: TEST_MAX_STORAGE_BYTES
  })
  t.is(relay.seededApps.get(blindKeyHex)?.blind, true, 'blind drive registered as blind/custody-class')

  await waitFor('tor health ready', () => relay.torTransport.health === 'ready')

  // ─── 1. The onion read plane forwards to the gateway/API port ─────────
  const addOnion = tor.addOnionCommands().pop()
  t.ok(addOnion.includes('Port=80,127.0.0.1:' + apiPort),
    'ADD_ONION maps vport 80 to the relay API/gateway port')

  const clientTor = new TorTransport({ socksPort: tor.socksPort })
  t.teardown(async () => { try { await clientTor.stop() } catch {} })
  await clientTor.start()

  // ─── 2. Public drive serves exact bytes through the onion ─────────────
  const pub = await httpGetOverOnion(clientTor, tor.onionAddress, READ_VPORT, '/v1/hyper/' + publicKeyHex + '/index.html')
  t.is(pub.status, 200, 'public drive serves through the onion gateway path')
  t.ok(pub.body.equals(Buffer.from(publicHtml)), 'exact bytes through the onion read plane')

  // ─── 3. Blind content is a hard 403 through the same onion plane ──────
  const blind = await httpGetOverOnion(clientTor, tor.onionAddress, READ_VPORT, '/v1/hyper/' + blindKeyHex + '/index.html')
  t.is(blind.status, 403, 'blind/custody content refused on the onion read plane')
  const blindBody = JSON.parse(blind.body.toString())
  t.is(blindBody.blind, true, '403 names the blind class (clearnet parity)')
  t.ok(/P2P access only/.test(blindBody.error), 'fail-closed message, not content: ' + blindBody.error)
  t.absent(blind.body.includes(blindCiphertext), 'no ciphertext leaks through the gateway')

  // ─── 4. Capability doc over the onion: health-gated advertisement ─────
  const docRes = await httpGetOverOnion(clientTor, tor.onionAddress, READ_VPORT, '/api/capabilities')
  t.is(docRes.status, 200, 'capability doc reachable through the onion read plane')
  const doc = JSON.parse(docRes.body.toString())
  t.ok(Array.isArray(doc.privacyTransports) && doc.privacyTransports.length === 1,
    'privacyTransports advertised while tor health is ready')
  const onionEntry = doc.privacyTransports[0]
  t.is(onionEntry.id, 'tor-v3-onion-v1')
  t.is(onionEntry.addresses[0].address, tor.onionAddress)
  t.alike(onionEntry.vports, [80, 19737], 'read plane + peer plane both advertised')
  t.is(onionEntry.vportRoles.readPlane, 80)
  t.is(onionEntry.vportRoles.peer, 19737)
  t.is(doc.onionGatewayUrl, 'http://' + tor.onionAddress + ':' + apiPort,
    'doc binds the onion read-plane ingress for gateway clients')
})
