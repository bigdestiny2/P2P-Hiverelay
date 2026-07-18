import test from 'brittle'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import fs from 'fs'
import os from 'os'
import path from 'path'
import net from 'net'
import { EventEmitter } from 'events'
import {
  base32Encode,
  base32Decode,
  isValidClientPub,
  generateClientAuthKeypair,
  generateClientAuthGuardKey,
  clientInstallCommand,
  dotAuthLine,
  canonicalize,
  createEnrollment,
  verifyEnrollment,
  createReceipt,
  verifyReceipt,
  OnionRosterStore,
  ENROLLMENT_TYPE,
  RECEIPT_TYPE
} from 'p2p-hiverelay/transports/tor/auth-keys.js'
import { TorTransport } from 'p2p-hiverelay/transports/tor/index.js'

function ed25519Keypair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey, publicKeyHex: b4a.toString(publicKey, 'hex') }
}

function tmpdir (t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tor-authkeys-test-'))
  t.teardown(() => { try { fs.rmSync(dir, { recursive: true, force: true }) } catch {} })
  return dir
}

test('base32 encode/decode round-trip + known vector', async (t) => {
  t.is(base32Encode(b4a.alloc(32, 0)), 'a'.repeat(52))
  const kp = generateClientAuthKeypair()
  t.is(kp.publicKeyB32.length, 52)
  t.ok(isValidClientPub(kp.publicKeyB32))
  t.alike([...base32Decode(kp.publicKeyB32)], [...kp.publicKey])
  t.absent(isValidClientPub('A'.repeat(52))) // uppercase not our canonical form
  t.absent(isValidClientPub('a'.repeat(51)))
})

test('keypair formats for tor wire protocols', async (t) => {
  const kp = generateClientAuthKeypair()
  t.is(kp.publicKey.length, 32)
  t.is(kp.secretKey.length, 32)
  t.ok(/^[A-Za-z0-9+/]{43}$/.test(kp.secretKeyB64)) // base64 no padding, 43 chars
})

test('guard key is a valid public-only Tor client-auth credential', async (t) => {
  const guard = generateClientAuthGuardKey()
  t.is(guard.length, 52)
  t.ok(isValidClientPub(guard))
  t.unlike(guard, generateClientAuthGuardKey(), 'each empty-roster guard is independently generated')
})

test('clientInstallCommand matches ONION_CLIENT_AUTH_ADD wire shape', async (t) => {
  const kp = generateClientAuthKeypair()
  const cmd = clientInstallCommand({ onionAddress: 'x'.repeat(56) + '.onion', secretKeyB64: kp.secretKeyB64, clientName: 'dev1' })
  t.ok(cmd.startsWith('ONION_CLIENT_AUTH_ADD ' + 'x'.repeat(56) + ' x25519:'))
  t.ok(cmd.includes('ClientName=dev1'))
  t.ok(cmd.endsWith('Flags=Permanent'))
})

test('dotAuthLine is the 3-field filesystem form', async (t) => {
  const kp = generateClientAuthKeypair()
  t.is(dotAuthLine(kp.publicKeyB32), 'descriptor:x25519:' + kp.publicKeyB32)
  t.exception(() => dotAuthLine('nope'), /invalid x25519/)
})

test('canonicalize is key-order independent', async (t) => {
  const a = canonicalize({ b: 1, a: { d: [3, 2], c: 'x' } })
  const b = canonicalize({ a: { c: 'x', d: [3, 2] }, b: 1 })
  t.is(a, b)
  t.is(a, '{"a":{"c":"x","d":[3,2]},"b":1}')
})

test('enrollment sign/verify lifecycle', async (t) => {
  const client = ed25519Keypair()
  const relay = ed25519Keypair()
  const kp = generateClientAuthKeypair()
  const now = Date.now()

  const env = createEnrollment({
    clientIdentity: client.publicKeyHex,
    clientSecretKey: client.secretKey,
    relayPubkey: relay.publicKeyHex,
    onionAuthPubX25519: kp.publicKeyB32,
    createdAtMs: now,
    expiresAtMs: now + 100000,
    nonce: 'ab'.repeat(32)
  })
  t.is(env.type, ENROLLMENT_TYPE)
  t.is(env.signature.length, 128)

  const ok = verifyEnrollment(env, { expectedRelayPubkey: relay.publicKeyHex, nowMs: now })
  t.is(ok.ok, true)

  // wrong relay audience
  t.is(verifyEnrollment(env, { expectedRelayPubkey: ed25519Keypair().publicKeyHex, nowMs: now }).reason, 'wrong-relay')
  // tampered field
  const tampered = { ...env, createdAtMs: now + 1 }
  t.is(verifyEnrollment(tampered, { expectedRelayPubkey: relay.publicKeyHex, nowMs: now }).reason, 'bad-signature')
  // wrong signer
  const forged = createEnrollment({
    clientIdentity: client.publicKeyHex,
    clientSecretKey: ed25519Keypair().secretKey,
    relayPubkey: relay.publicKeyHex,
    onionAuthPubX25519: kp.publicKeyB32,
    createdAtMs: now,
    expiresAtMs: now + 100000
  })
  t.is(verifyEnrollment(forged, { expectedRelayPubkey: relay.publicKeyHex, nowMs: now }).reason, 'bad-signature')
  // expired
  t.is(verifyEnrollment(env, { expectedRelayPubkey: relay.publicKeyHex, nowMs: now + 200000 }).reason, 'expired')
  // A future createdAt must not extend an otherwise bounded TTL indefinitely.
  const future = createEnrollment({
    clientIdentity: client.publicKeyHex,
    clientSecretKey: client.secretKey,
    relayPubkey: relay.publicKeyHex,
    onionAuthPubX25519: kp.publicKeyB32,
    createdAtMs: now + 10 * 60 * 1000,
    expiresAtMs: now + 10 * 60 * 1000 + 100000
  })
  t.is(verifyEnrollment(future, { expectedRelayPubkey: relay.publicKeyHex, nowMs: now }).reason, 'created-in-future')
  // Non-integer timestamps are rejected before arithmetic coercion.
  const stringTime = createEnrollment({
    clientIdentity: client.publicKeyHex,
    clientSecretKey: client.secretKey,
    relayPubkey: relay.publicKeyHex,
    onionAuthPubX25519: kp.publicKeyB32,
    createdAtMs: String(now),
    expiresAtMs: String(now + 100000)
  })
  t.is(verifyEnrollment(stringTime, { expectedRelayPubkey: relay.publicKeyHex, nowMs: now }).reason, 'bad-time')
  // bad type
  t.is(verifyEnrollment({ ...env, type: 'x' }, { nowMs: now }).reason, 'wrong-type')
})

test('receipt sign/verify binds address, keyId, expiry', async (t) => {
  const relay = ed25519Keypair()
  const client = ed25519Keypair()
  const kp = generateClientAuthKeypair()
  const now = Date.now()

  const receipt = createReceipt({
    relayPubkey: relay.publicKeyHex,
    relaySecretKey: relay.secretKey,
    status: 'accepted',
    onionAddress: 'b'.repeat(56) + '.onion',
    endpointKeyId: 'onion-2026-07-a',
    clientIdentity: client.publicKeyHex,
    onionAuthPubX25519: kp.publicKeyB32,
    enrolledAtMs: now,
    expiresAtMs: now + 100000
  })
  t.is(receipt.type, RECEIPT_TYPE)

  const ok = verifyReceipt(receipt, { expectedRelayPubkey: relay.publicKeyHex, expectedClientIdentity: client.publicKeyHex })
  t.is(ok.ok, true)
  t.is(ok.receipt.endpointKeyId, 'onion-2026-07-a')

  t.is(verifyReceipt({ ...receipt, onionAddress: 'c'.repeat(56) + '.onion' }, {}).reason, 'bad-signature')
  t.is(verifyReceipt(receipt, { expectedRelayPubkey: ed25519Keypair().publicKeyHex }).reason, 'wrong-relay')
  t.is(verifyReceipt(receipt, { expectedClientIdentity: ed25519Keypair().publicKeyHex }).reason, 'wrong-client')
  t.exception(() => createReceipt({ status: 'maybe' }), /accepted\|rejected/)
})

test('roster store — persist, reload, revoke, purge, 0600', async (t) => {
  const dir = tmpdir(t)
  const file = path.join(dir, 'tor', 'auth-roster.json')
  const alice = generateClientAuthKeypair().publicKeyB32
  const bob = generateClientAuthKeypair().publicKeyB32
  const now = Date.now()

  const store = await new OnionRosterStore(file).load()
  store.add(alice, { name: 'alice', nowMs: now })
  store.add(bob, { nowMs: now, expiresAtMs: now + 1000 })
  await store.save()
  t.is(fs.statSync(file).mode & 0o777, 0o600)

  const reloaded = await new OnionRosterStore(file).load()
  t.alike(new Set(reloaded.activeKeys({ nowMs: now })), new Set([alice, bob]))
  t.alike(reloaded.activeKeys({ nowMs: now + 2000 }), [alice]) // bob expired

  t.is(reloaded.revoke(alice, { nowMs: now }), true)
  t.is(reloaded.revoke(alice, { nowMs: now }), false) // idempotent
  t.alike(reloaded.activeKeys({ nowMs: now }), [bob]) // alice revoked, bob still live

  // purge drops revoked/expired past grace
  t.is(reloaded.purge({ nowMs: now + 8 * 24 * 3600 * 1000 }), 2)
  t.alike(reloaded.activeKeys({ nowMs: now }), [])

  // corrupt file fails closed
  fs.writeFileSync(file, '{broken')
  await t.exception(() => new OnionRosterStore(file).load(), /corrupt onion roster/)

  fs.writeFileSync(file, JSON.stringify({
    version: 1,
    keys: [{
      pub: alice,
      name: null,
      addedAtMs: now,
      expiresAtMs: String(now + 1000),
      revokedAtMs: null
    }]
  }))
  await t.exception(() => new OnionRosterStore(file).load(), /expiresAtMs must be a non-negative safe integer/)
  t.exception(
    () => new OnionRosterStore(file).add(alice, { nowMs: now, expiresAtMs: now }),
    /expiresAtMs must be in the future/
  )

  const epochStore = new OnionRosterStore(file)
  epochStore.add(alice, { nowMs: 0, expiresAtMs: 1000 })
  t.is(epochStore.revoke(alice, { nowMs: 0 }), true)
  t.is(epochStore.revoke(alice, { nowMs: 0 }), false, 'epoch-zero tombstone remains idempotent')
  t.alike(epochStore.activeKeys({ nowMs: 0 }), [])
})

// --- TorTransport roster persistence integration ---

const SERVICE_ID = 'a'.repeat(56)
const KEY_BLOB = 'ED25519-V3:' + Buffer.alloc(64, 7).toString('base64')

class FakeControl extends EventEmitter {
  constructor () { super(); this.commands = []; this.destroyed = false }

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

test('TorTransport rosterFile — add persists, reload restores, service gets union at start', async (t) => {
  const socksPort = await fakeSocks(t)
  const dir = tmpdir(t)
  const rosterFile = path.join(dir, 'auth-roster.json')
  const keyFile = path.join(dir, 'hs-key.blob')
  const alice = generateClientAuthKeypair().publicKeyB32
  const bob = generateClientAuthKeypair().publicKeyB32

  const c1 = new FakeControl()
  const tt1 = new TorTransport({ socksPort, localPort: 9100, keyFile, rosterFile, _controlFactory: () => c1 })
  await tt1.start()
  await tt1.addAuthClient(alice)
  await tt1.addAuthClient(bob)
  const saved = JSON.parse(fs.readFileSync(rosterFile, 'utf8'))
  t.is(saved.keys.length, 2)
  await tt1.stop()

  // fresh instance: roster loads from disk and is bound at service creation
  const c2 = new FakeControl()
  const tt2 = new TorTransport({ socksPort, localPort: 9100, keyFile, rosterFile, _controlFactory: () => c2 })
  await tt2.start()
  const add = c2.commands.filter((c) => c.startsWith('ADD_ONION')).pop()
  t.ok(add.includes('ClientAuthV3=' + alice))
  t.ok(add.includes('ClientAuthV3=' + bob))
  t.alike(new Set(tt2.listAuthClients()), new Set([alice, bob]))

  // revoke persists and rebuilds
  await tt2.removeAuthClient(alice)
  const saved2 = JSON.parse(fs.readFileSync(rosterFile, 'utf8'))
  t.is(saved2.keys.find((k) => k.pub === alice).revokedAtMs > 0, true)
  const rebuild = c2.commands.filter((c) => c.startsWith('ADD_ONION')).pop()
  t.absent(rebuild.includes('ClientAuthV3=' + alice))
  t.ok(rebuild.includes('ClientAuthV3=' + bob))
  await tt2.stop()
})
