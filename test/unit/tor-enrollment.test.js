import test from 'brittle'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import fs from 'fs'
import os from 'os'
import path from 'path'
import net from 'net'
import { EventEmitter } from 'events'
import { randomBytes } from 'crypto'
import {
  generateClientAuthKeypair,
  createEnrollment,
  verifyReceipt
} from 'p2p-hiverelay/transports/tor/auth-keys.js'
import { completeOnionEnrollment, restrictedDiscoveryActive } from 'p2p-hiverelay/transports/tor/enrollment.js'
import { TorTransport } from 'p2p-hiverelay/transports/tor/index.js'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'

const SERVICE_ID = 'a'.repeat(56)
const KEY_BLOB = 'ED25519-V3:' + Buffer.alloc(64, 7).toString('base64')

function ed25519Keypair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey, publicKeyHex: b4a.toString(publicKey, 'hex') }
}

/** Daemon-free control-port fake (same shape as tor-auth-keys.test.js). */
class FakeControl extends EventEmitter {
  constructor () {
    super()
    this.commands = []
    this.destroyed = false
  }

  async connect () {}

  cmd (command) {
    this.commands.push(command)
    const head = command.split(' ')[0]
    if (head === 'AUTHENTICATE') return Promise.resolve('250 OK')
    if (head === 'GETINFO') return Promise.resolve('250-version=0.4.9.6\n250 OK')
    if (head === 'ADD_ONION') {
      const lines = ['250-ServiceID=' + SERVICE_ID]
      if (command.startsWith('ADD_ONION NEW:')) lines.push('250-PrivateKey=' + KEY_BLOB)
      lines.push('250 OK')
      return Promise.resolve(lines.join('\n'))
    }
    return Promise.resolve('250 OK')
  }

  destroy () { this.destroyed = true }
}

async function fakeSocks (t) {
  const server = net.createServer((s) => s.destroy())
  await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
  t.teardown(() => { try { server.close() } catch {} })
  return server.address().port
}

function tmpdir (t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tor-enrollment-test-'))
  t.teardown(() => { try { fs.rmSync(dir, { recursive: true, force: true }) } catch {} })
  return dir
}

/** Started transport in restricted-discovery mode (keyFile + rosterFile). */
async function startedTransport (t, dir, opts = {}) {
  const socksPort = await fakeSocks(t)
  const control = new FakeControl()
  const tt = new TorTransport({
    socksPort,
    localPort: 9100,
    keyFile: path.join(dir, 'hs-key.blob'),
    rosterFile: path.join(dir, 'auth-roster.json'),
    endpointKeyId: 'onion-2026-07-a',
    _controlFactory: () => control,
    ...opts
  })
  await tt.start()
  t.teardown(async () => { await tt.stop() })
  return { tt, control }
}

function enrollmentFor ({ client, relayPubkeyHex, kp, now = Date.now(), ttlMs = 30 * 24 * 3600 * 1000 }) {
  return createEnrollment({
    clientIdentity: client.publicKeyHex,
    clientSecretKey: client.secretKey,
    relayPubkey: relayPubkeyHex,
    onionAuthPubX25519: kp.publicKeyB32,
    createdAtMs: now,
    expiresAtMs: now + ttlMs
  })
}

test('pairing-channel enrollment — verify, roster add + persist, rebuild, signed receipt', async (t) => {
  const dir = tmpdir(t)
  const { tt, control } = await startedTransport(t, dir)
  const relay = ed25519Keypair()
  const client = ed25519Keypair()
  const kp = generateClientAuthKeypair()
  const now = Date.now()

  const envelope = enrollmentFor({ client, relayPubkeyHex: relay.publicKeyHex, kp, now })
  const result = await completeOnionEnrollment({
    torTransport: tt,
    relayKeyPair: relay,
    devicePubkeyHex: client.publicKeyHex,
    envelope,
    deviceName: 'phone'
  })

  t.is(result.enrolled, true)
  t.is(tt.onionAddress, SERVICE_ID + '.onion', 'address unchanged across rebuild')

  // roster add + persist via rosterFile (expiry + label from the envelope)
  t.alike(tt.listAuthClients(), [kp.publicKeyB32])
  const saved = JSON.parse(fs.readFileSync(path.join(dir, 'auth-roster.json'), 'utf8'))
  t.is(saved.keys.length, 1)
  t.is(saved.keys[0].pub, kp.publicKeyB32)
  t.is(saved.keys[0].name, 'phone')
  t.is(saved.keys[0].expiresAtMs, envelope.expiresAtMs)

  // service rebuilt in place with the new ClientAuthV3 set
  const rebuild = control.commands.filter((c) => c.startsWith('ADD_ONION')).pop()
  t.ok(rebuild.includes('Flags=V3Auth'))
  t.ok(rebuild.includes('ClientAuthV3=' + kp.publicKeyB32))
  t.ok(control.commands.some((c) => c.startsWith('DEL_ONION')))

  // receipt binds key ↔ onion address ↔ expiry, signed by the relay identity
  const vr = verifyReceipt(result.receipt, {
    expectedRelayPubkey: relay.publicKeyHex,
    expectedClientIdentity: client.publicKeyHex
  })
  t.is(vr.ok, true)
  t.is(vr.receipt.status, 'accepted')
  t.is(vr.receipt.onionAddress, tt.onionAddress)
  t.is(vr.receipt.endpointKeyId, 'onion-2026-07-a')
  t.is(vr.receipt.expiresAtMs, envelope.expiresAtMs)
})

test('enrollment rejections — bad sig, expired, wrong relay, identity mismatch', async (t) => {
  const dir = tmpdir(t)
  const { tt, control } = await startedTransport(t, dir)
  const relay = ed25519Keypair()
  const client = ed25519Keypair()
  const kp = generateClientAuthKeypair()
  const now = Date.now()
  const addCount = () => control.commands.filter((c) => c.startsWith('ADD_ONION')).length

  const run = (envelope, devicePubkeyHex = client.publicKeyHex) =>
    completeOnionEnrollment({ torTransport: tt, relayKeyPair: relay, devicePubkeyHex, envelope })

  // tampered body → signature no longer covers it
  const good = enrollmentFor({ client, relayPubkeyHex: relay.publicKeyHex, kp, now })
  t.is((await run({ ...good, nonce: 'ff'.repeat(32) })).reason, 'bad-signature')

  // expired envelope
  const stale = enrollmentFor({ client, relayPubkeyHex: relay.publicKeyHex, kp, now: now - 200000, ttlMs: 100000 })
  t.is((await run(stale)).reason, 'expired')

  // addressed to a different relay
  const wrongRelay = enrollmentFor({ client, relayPubkeyHex: ed25519Keypair().publicKeyHex, kp, now })
  t.is((await run(wrongRelay)).reason, 'wrong-relay')

  // valid envelope, but the paired device is not the signer
  const stranger = ed25519Keypair()
  t.is((await run(good, stranger.publicKeyHex)).reason, 'identity-mismatch')

  // rejections never touch the roster or the live service
  t.is(addCount(), 1, 'no rebuild beyond initial creation')
  t.alike(tt.listAuthClients(), [])
  t.absent(fs.existsSync(path.join(dir, 'auth-roster.json')), 'nothing persisted')
})

test('enrollment gating — clean no-op without tor / without restricted discovery', async (t) => {
  const dir = tmpdir(t)
  const relay = ed25519Keypair()
  const client = ed25519Keypair()
  const kp = generateClientAuthKeypair()
  const envelope = enrollmentFor({ client, relayPubkeyHex: relay.publicKeyHex, kp })

  t.is(restrictedDiscoveryActive(null), false)
  t.is(restrictedDiscoveryActive({ rosterFile: 'x', clientAuthKeys: [] }), true)
  t.is(restrictedDiscoveryActive({ rosterFile: null, clientAuthKeys: ['a'.repeat(52)] }), true)
  t.is(restrictedDiscoveryActive({ rosterFile: null, clientAuthKeys: [] }), false)

  // no transport at all
  const none = await completeOnionEnrollment({ torTransport: null, relayKeyPair: relay, devicePubkeyHex: client.publicKeyHex, envelope })
  t.alike(none, { enrolled: false, reason: 'tor-disabled' })

  // transport constructed but not running
  const idle = new TorTransport({})
  const notRunning = await completeOnionEnrollment({ torTransport: idle, relayKeyPair: relay, devicePubkeyHex: client.publicKeyHex, envelope })
  t.is(notRunning.reason, 'tor-disabled')

  // running but open discovery — every client already decrypts the descriptor
  const socksPort = await fakeSocks(t)
  const control = new FakeControl()
  const open = new TorTransport({ socksPort, localPort: 9100, keyFile: path.join(dir, 'hs-key.blob'), _controlFactory: () => control })
  await open.start()
  t.teardown(async () => { await open.stop() })
  const openResult = await completeOnionEnrollment({ torTransport: open, relayKeyPair: relay, devicePubkeyHex: client.publicKeyHex, envelope })
  t.alike(openResult, { enrolled: false, reason: 'open-discovery' })
})

test('enrollment rejects finite expiry without enforceable persistent roster authority', async (t) => {
  const root = tmpdir(t)
  const relay = ed25519Keypair()
  const client = ed25519Keypair()
  const staticKey = generateClientAuthKeypair()
  const newKey = generateClientAuthKeypair()

  const staticOnly = await startedTransport(t, path.join(root, 'static-only'), {
    rosterFile: null,
    clientAuthKeys: [staticKey.publicKeyB32]
  })
  const newEnvelope = enrollmentFor({
    client,
    relayPubkeyHex: relay.publicKeyHex,
    kp: newKey
  })
  const noRoster = await completeOnionEnrollment({
    torTransport: staticOnly.tt,
    relayKeyPair: relay,
    devicePubkeyHex: client.publicKeyHex,
    envelope: newEnvelope
  })
  t.alike(noRoster, { enrolled: false, reason: 'persistent-roster-required' })

  const withRoster = await startedTransport(t, path.join(root, 'static-plus-roster'), {
    clientAuthKeys: [staticKey.publicKeyB32]
  })
  const staticEnvelope = enrollmentFor({
    client,
    relayPubkeyHex: relay.publicKeyHex,
    kp: staticKey
  })
  const staticResult = await completeOnionEnrollment({
    torTransport: withRoster.tt,
    relayKeyPair: relay,
    devicePubkeyHex: client.publicKeyHex,
    envelope: staticEnvelope
  })
  t.alike(staticResult, { enrolled: false, reason: 'static-auth-key' })
  t.absent(staticResult.receipt)
})

test('enrollment crossing expiry removes the transient key and signs no receipt', async (t) => {
  const dir = tmpdir(t)
  const wallNow = Date.now()
  let transportNow = wallNow
  const { tt, control } = await startedTransport(t, dir, {
    _now: () => transportNow
  })
  const relay = ed25519Keypair()
  const client = ed25519Keypair()
  const kp = generateClientAuthKeypair()
  const envelope = enrollmentFor({
    client,
    relayPubkeyHex: relay.publicKeyHex,
    kp,
    now: wallNow,
    ttlMs: 24 * 60 * 60 * 1000
  })

  const realCmd = control.cmd.bind(control)
  let crossExpiryOnAdd = true
  control.cmd = (command) => {
    const response = realCmd(command)
    if (crossExpiryOnAdd && command.startsWith('ADD_ONION')) {
      crossExpiryOnAdd = false
      transportNow = envelope.expiresAtMs
    }
    return response
  }

  const result = await completeOnionEnrollment({
    torTransport: tt,
    relayKeyPair: relay,
    devicePubkeyHex: client.publicKeyHex,
    envelope
  })
  t.alike(result, { enrolled: false, reason: 'expired' })
  t.alike(tt.listAuthClients(), [])
  const saved = JSON.parse(fs.readFileSync(path.join(dir, 'auth-roster.json'), 'utf8'))
  t.is(saved.keys[0].pub, kp.publicKeyB32)
  t.is(saved.keys[0].revokedAtMs, envelope.expiresAtMs)
  const live = control.commands.filter((command) => command.startsWith('ADD_ONION')).pop()
  t.absent(live.includes('ClientAuthV3=' + kp.publicKeyB32))
})

test('failed crossed-expiry replacement cannot roll the expired key back', async (t) => {
  const dir = tmpdir(t)
  const wallNow = Date.now()
  let transportNow = wallNow
  const { tt, control } = await startedTransport(t, dir, {
    _now: () => transportNow,
    _rosterExpiryRetryMs: 60_000
  })
  const relay = ed25519Keypair()
  const client = ed25519Keypair()
  const expiredKey = generateClientAuthKeypair()
  const replacementKey = generateClientAuthKeypair()
  const envelope = enrollmentFor({
    client,
    relayPubkeyHex: relay.publicKeyHex,
    kp: expiredKey,
    now: wallNow,
    ttlMs: 24 * 60 * 60 * 1000
  })

  const realCmd = control.cmd.bind(control)
  let crossExpiryOnAdd = true
  let failExpiryReplacement = true
  control.cmd = (command) => {
    const response = realCmd(command)
    if (!command.startsWith('ADD_ONION')) return response
    if (crossExpiryOnAdd) {
      crossExpiryOnAdd = false
      transportNow = envelope.expiresAtMs
      return response
    }
    if (failExpiryReplacement) {
      failExpiryReplacement = false
      return Promise.reject(new Error('injected expiry replacement failure'))
    }
    return response
  }

  await t.exception(
    completeOnionEnrollment({
      torTransport: tt,
      relayKeyPair: relay,
      devicePubkeyHex: client.publicKeyHex,
      envelope
    }),
    /failed to enforce authorization/
  )
  t.alike(tt.listAuthClients(), [])
  t.is(tt._serviceActive, false)
  const saved = JSON.parse(fs.readFileSync(path.join(dir, 'auth-roster.json'), 'utf8'))
  t.is(saved.keys[0].revokedAtMs, envelope.expiresAtMs)

  transportNow = wallNow
  await tt.addAuthClient(replacementKey.publicKeyB32, {
    expiresAtMs: wallNow + 2 * 24 * 60 * 60 * 1000
  })
  const live = control.commands.filter((command) => command.startsWith('ADD_ONION')).pop()
  t.absent(live.includes('ClientAuthV3=' + expiredKey.publicKeyB32), 'clock rewind cannot revive committed expiry')
  t.ok(live.includes('ClientAuthV3=' + replacementKey.publicKeyB32))
  const savedAfterRewind = JSON.parse(fs.readFileSync(path.join(dir, 'auth-roster.json'), 'utf8'))
  t.ok(
    savedAfterRewind.keys.find((entry) => entry.pub === expiredKey.publicKeyB32).revokedAtMs !== null,
    'later mutation cannot overwrite the durable expiry tombstone'
  )
})

test('RelayNode pairDevice — enrollment envelope rides the pairing extras', async (t) => {
  const dir = tmpdir(t)
  const storage = path.join(dir, 'relay')
  fs.mkdirSync(storage, { recursive: true })
  const node = new RelayNode({
    mode: 'private',
    storage,
    enableAPI: false,
    enableServices: false,
    discovery: { mdns: false }
  })
  t.teardown(async () => { if (node.running) await node.stop() })
  await node.start()

  // Stand in the tor transport (no daemon in unit tests), restricted discovery on
  const socksPort = await fakeSocks(t)
  const control = new FakeControl()
  const tt = new TorTransport({
    socksPort,
    localPort: 9100,
    keyFile: path.join(dir, 'hs-key.blob'),
    rosterFile: path.join(dir, 'auth-roster.json'),
    _controlFactory: () => control
  })
  await tt.start()
  node.torTransport = tt

  const relayPubkeyHex = b4a.toString(node.swarm.keyPair.publicKey, 'hex')
  const device = ed25519Keypair()
  const kp = generateClientAuthKeypair()
  const envelope = enrollmentFor({ client: device, relayPubkeyHex, kp })

  const events = []
  node.on('tor-enrollment', (e) => events.push(e))

  const pairing = node.enablePairing({ timeoutMs: 10000 })
  const res = await node.pairDevice(pairing.token, device.publicKeyHex, 'phone', { onionEnrollment: envelope })
  t.is(res.paired, true)
  t.is(res.onionEnrollment.enrolled, true)

  const vr = verifyReceipt(res.onionEnrollment.receipt, {
    expectedRelayPubkey: relayPubkeyHex,
    expectedClientIdentity: device.publicKeyHex
  })
  t.is(vr.ok, true)
  t.is(vr.receipt.onionAddress, tt.onionAddress)
  t.alike(tt.listAuthClients(), [kp.publicKeyB32])
  const saved = JSON.parse(fs.readFileSync(path.join(dir, 'auth-roster.json'), 'utf8'))
  t.is(saved.keys[0].pub, kp.publicKeyB32)
  t.is(events.length, 1)
  t.is(events[0].enrolled, true)
  t.is(events[0].pubkey, device.publicKeyHex)

  // legacy callers (no envelope) keep the plain boolean shape
  const pairing2 = node.enablePairing({ timeoutMs: 10000 })
  const paired = await node.pairDevice(pairing2.token, randomBytes(32).toString('hex'), 'laptop')
  t.is(paired, true)

  // bad token with extras → structured failure, no enrollment attempt
  node.enablePairing({ timeoutMs: 10000 })
  const rejected = await node.pairDevice('deadbeef', device.publicKeyHex, 'phone', { onionEnrollment: envelope })
  t.is(rejected.paired, false)
  t.is(rejected.onionEnrollment, null)
  t.is(events.length, 1, 'no enrollment event for a failed pair')

  // enrollment against a tor-less node no-ops cleanly
  node.torTransport = null
  const skipped = await node.enrollOnionAuthClient(device.publicKeyHex, envelope)
  t.alike(skipped, { enrolled: false, reason: 'tor-disabled' })
})
