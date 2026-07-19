/**
 * GIGA DoD cross-feature journey — namespace × tor
 * (docs/GIGA-RELEASE-ARCHITECTURE.md §7 "Cross-feature journeys":
 * "wake hints over the onion control path into namespaced outboxes";
 * docs/NAMESPACE.md: "encrypted wake/head hints are exactly the bounded
 * control messages the Tor/Nym privacy lanes carry; the log bodies
 * themselves stay on native paths").
 *
 * What this proves (composition, not internals):
 *   1. Advertisement: the relay's signed capability doc — itself fetched
 *      through the onion read plane — carries the health-gated
 *      privacyTransports entry whose supports name the namespaced-outbox
 *      control messages ('outbox.wake', 'outbox.read').
 *   2. Route selection (model level): the privacy-policy resolver picks
 *      the tor onion lane for a wake/head-hint intent (control-only
 *      coverage, source-ip-hidden, hidden-onion), keeps log bodies on the
 *      native direct path (full coverage), and fails CLOSED when the onion
 *      lane is unavailable and the policy is 'deny' — no silent downgrade.
 *   3. Delivery: a head hint for a blind-namespace outbox really traverses
 *      the onion — client TorTransport → SOCKS → peer vport → Noise XK →
 *      the relay's service-RPC channel — and comes back bounded (well
 *      under the notify payload budget) and opaque (a version number, no
 *      record content), while the sealed body never needed the onion.
 *
 * Realization: real RelayNode + real OutboxLogApp (in-memory persistence;
 * the hypercore journal's RelayNode boot path is broken on fresh stores —
 * see the GAP test in journey-namespace-blind.test.js) + real
 * OnionPeerListener Noise upgrade + real service-RPC wire on a hyperswarm
 * testnet; the tor daemon is faked at the protocol level
 * (helpers/fake-tor.js). Body routing is asserted at the resolver level
 * per the DoD model — the hint is the piece that must traverse the onion.
 */

import test from 'brittle'
import createTestnet from '@hyperswarm/testnet'
import NoiseSecretStream from '@hyperswarm/secret-stream'
import Protomux from 'protomux'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import { TorTransport } from 'p2p-hiverelay/transports/tor/index.js'
import { serviceMessageEncoding } from 'p2p-hiverelay/core/services/protocol.js'
import { SERVICES_PROTOCOL_NAME } from 'p2p-hiverelay/core/constants.js'
import {
  PATH_DIRECT,
  PATH_TOR_ONION,
  candidatesFromCapabilityDoc,
  resolvePath
} from 'p2p-hiverelay-client/privacy-policy.js'
import {
  OutboxLogApp,
  canonicalOutboxRecord,
  createOutboxBlindSealAAD,
  createOutboxBlindSealKey,
  sealOutboxBlindPayload
} from 'p2p-hiveservices/builtin/outboxlog/index.js'
import { startFakeTorDaemon } from './helpers/fake-tor.js'

const PEER_VPORT = 19737
const READ_VPORT = 80
const NS = 'wakeapp'
// The bounded control-message budget: notify's max push payload (the wake
// class this lane was built to carry).
const BOUNDED_HINT_BYTES = 3072
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

const HINT_INTENT = Object.freeze({
  transportPrivacy: 'source-ip-hidden',
  relayLocation: 'hidden-onion',
  metadataShaping: 'none',
  pathCoverage: 'control-only',
  downgradePolicy: 'deny'
})

const BODY_INTENT = Object.freeze({
  transportPrivacy: 'direct',
  relayLocation: 'exposed',
  metadataShaping: 'none',
  pathCoverage: 'full',
  downgradePolicy: 'deny'
})

function tmpdir (t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hiverelay-journey-namespace-tor-'))
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

function writerKeyPair (seedByte) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.alloc(32, seedByte))
  return { publicKey, secretKey, publicKeyHex: b4a.toString(publicKey, 'hex') }
}

function signRecord (writer, fields = {}, type = 'head') {
  const namespace = fields._ns || NS
  const data = {
    id: fields.id || writer.publicKeyHex,
    author: writer.publicKeyHex,
    ...fields,
    _k: writer.publicKeyHex,
    _dk: fields._dk || 'd'.repeat(64),
    _ns: namespace,
    _alg: 'ed25519'
  }
  const signed = `pear.app.${data._dk}:${data._ns}:${canonicalOutboxRecord(type, data)}`
  const signature = b4a.alloc(64)
  sodium.crypto_sign_detached(signature, b4a.from(signed, 'utf8'), writer.secretKey)
  return { ...data, _sig: b4a.toString(signature, 'hex') }
}

/** Minimal client half of the relay's service-RPC wire (hiverelay-services). */
function openServiceRpc (stream) {
  const mux = Protomux.from(stream)
  const channel = mux.createChannel({ protocol: SERVICES_PROTOCOL_NAME, id: b4a.from('services-v1') })
  if (!channel) throw new Error('service channel allocation failed')
  const pending = new Map()
  let nextId = 1
  const msg = channel.addMessage({
    encoding: serviceMessageEncoding,
    onmessage: (m) => {
      const waiter = pending.get(m.id)
      if (!waiter) return
      pending.delete(m.id)
      clearTimeout(waiter.timer)
      if (m.type === 2) waiter.resolve(m.result)
      else waiter.reject(new Error(m.error || 'service error'))
    }
  })
  channel.open()
  return {
    call (service, method, params, timeoutMs = 10_000) {
      const id = nextId++
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          pending.delete(id)
          reject(new Error('service call timeout'))
        }, timeoutMs)
        pending.set(id, { resolve, reject, timer })
        msg.send({ type: 1, id, service, method, params })
      })
    }
  }
}

/** HTTP/1.0 GET through the onion read plane. */
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
  const statusLine = raw.subarray(0, idx).toString().split('\r\n')[0]
  return { status: Number(statusLine.split(' ')[1]), body: raw.subarray(idx + 4) }
}

test('journey namespace × tor: wake/head hint rides the onion control lane, bodies stay native', async (t) => {
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
    enableServices: true,
    plugins: [],
    // The shipped operator default (config/default.js) — a relay serving app
    // clients over P2P. Grants connecting peers the 'authenticated-user'
    // role the outboxlog routes require at the application router.
    serviceDefaultPeerRole: 'authenticated-user',
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
  await waitFor('tor health ready', () => relay.torTransport.health === 'ready')

  // Real OutboxLogApp in the relay's real ServiceRegistry (in-memory
  // persistence — the hypercore journal's RelayNode boot path is broken on
  // fresh stores; see the GAP note in journey-namespace-blind.test.js).
  const outboxApp = new OutboxLogApp({
    persistence: false,
    namespaces: {
      [NS]: { blind: true, caps: { maxOutboxes: 4, maxEntriesPerOutbox: 8, maxValueBytes: 16 * 1024 } }
    }
  })
  relay.serviceRegistry.register(outboxApp)
  await relay.serviceRegistry.startAll(relay._buildServiceContext())
  t.is(relay.serviceRegistry.services.get('outboxlog')?.status, 'running', 'outboxlog service running inside the relay')
  // The relay's application router snapshots registry routes at start()
  // (registerFromRegistry); refresh it so the late-registered provider is
  // dispatchable over the service RPC wire.
  relay.router.registerFromRegistry(relay.serviceRegistry)

  // Operator-side state: one blind-namespace outbox with one sealed head row.
  const writer = writerKeyPair(51)
  const outbox = relay.serviceRegistry.services.get('outboxlog').provider
  outbox.sync.create(writer.publicKeyHex, { namespace: NS })
  const sealKey = createOutboxBlindSealKey()
  const aad = createOutboxBlindSealAAD({ namespace: NS, appId: writer.publicKeyHex, type: 'head', id: writer.publicKeyHex, keyId: 'wake-room@1' })
  const headBody = sealOutboxBlindPayload({ head: 'sealed head material' }, { key: sealKey, aad, keyId: 'wake-room@1' })
  const headRecord = signRecord(writer, { id: writer.publicKeyHex, _ns: NS, body: headBody }, 'head')
  t.alike(outbox.sync.append(writer.publicKeyHex, { type: 'head', data: headRecord }), { ok: true, key: 'head!' + writer.publicKeyHex })
  const sealedCiphertext = headBody.sealed.ciphertext

  // Client tor transport against the same fake daemon.
  const clientTor = new TorTransport({ socksPort: tor.socksPort })
  t.teardown(async () => { try { await clientTor.stop() } catch {} })
  await clientTor.start()

  // ─── 1. Advertisement: capability doc over the onion read plane ───────
  const docRes = await httpGetOverOnion(clientTor, tor.onionAddress, READ_VPORT, '/api/capabilities')
  t.is(docRes.status, 200, 'capability doc fetched through the onion read plane')
  const doc = JSON.parse(docRes.body.toString())
  const onionEntry = doc.privacyTransports && doc.privacyTransports.find((e) => e.id === PATH_TOR_ONION)
  t.ok(onionEntry, 'health-gated onion advertisement present while ready')
  t.ok(onionEntry.supports.includes('outbox.wake'), 'advertisement names the wake-hint control message')
  t.ok(onionEntry.supports.includes('outbox.read'), 'advertisement names the outbox read control message')

  // ─── 2. Route selection: hint → onion, body → native, deny fails closed
  const candidates = candidatesFromCapabilityDoc(doc, { direct: true, tor: true })
  t.ok(candidates.some((c) => c.id === PATH_TOR_ONION && c.available), 'resolver sees a usable onion path')

  const hintRoute = resolvePath(HINT_INTENT, candidates)
  t.is(hintRoute.selectedTransport, PATH_TOR_ONION, 'wake/head hint routes over the onion control lane')
  t.ok(hintRoute.satisfied.includes('pathCoverage:control-only'), 'hint is evidence-backed as control-only')
  t.ok(hintRoute.satisfied.includes('relayLocation:hidden-onion'))
  t.absent(hintRoute.downgraded, 'no downgrade needed for the hint')

  const bodyRoute = resolvePath(BODY_INTENT, candidates)
  t.is(bodyRoute.selectedTransport, PATH_DIRECT, 'log bodies stay on the native path')
  t.is(bodyRoute.coverage, 'full', 'body class needs full byte coverage — not the bounded lane')

  const closed = resolvePath(HINT_INTENT, candidatesFromCapabilityDoc(doc, { direct: true, tor: false }))
  t.is(closed.selectedTransport, null, 'onion down + deny policy → fail closed, never a silent downgrade')
  t.ok(closed.unsatisfied.includes('no-satisfying-path'))

  // ─── 3. Delivery: the head hint really traverses the onion ────────────
  const serverSide = new Promise((resolve) => {
    relay.torTransport.on('connection', (stream, info) => resolve(info))
  })
  const relayPub = relay.swarm.keyPair.publicKey
  const torStream = await clientTor.connect(tor.onionAddress, PEER_VPORT)
  t.teardown(() => { try { torStream.destroy() } catch {} })
  const noise = new NoiseSecretStream(true, torStream, {
    keyPair: NoiseSecretStream.keyPair(),
    remotePublicKey: relayPub,
    pattern: 'XK'
  })
  t.teardown(() => { try { noise.destroy() } catch {} })
  await new Promise((resolve, reject) => {
    noise.once('handshake', resolve)
    noise.once('error', reject)
  })
  const info = await Promise.race([serverSide, sleep(5000).then(() => null)])
  t.ok(info && info.isOnion === true, 'peer-plane connection arrived over the onion')

  const rpc = openServiceRpc(noise)
  const hint = await rpc.call('outboxlog', 'heads', { appIds: [writer.publicKeyHex] })
  t.is(hint.heads[writer.publicKeyHex], 1, 'head hint delivered: the namespaced outbox head version')

  const hintBytes = Buffer.byteLength(JSON.stringify(hint))
  t.ok(hintBytes <= BOUNDED_HINT_BYTES, `hint is bounded control traffic (${hintBytes}B <= ${BOUNDED_HINT_BYTES}B)`)
  t.alike(Object.keys(hint), ['heads'], 'hint carries versions only — no record material')
  t.absent(JSON.stringify(hint).includes(sealedCiphertext), 'no ciphertext rides the wake lane')

  // …while the body it points at stays on the native path: the sealed head
  // row is served by the namespace engine without ever traversing the onion.
  const stored = outbox.sync.get(writer.publicKeyHex, 'head!' + writer.publicKeyHex)
  t.ok(stored && stored.body && stored.body.sealed, 'body remains sealed at the relay')
  t.is(stored.body.sealed.ciphertext, sealedCiphertext, 'body content untouched by the hint round-trip')
})
