/**
 * End-to-end wake loop: a mailbox record lands on an outbox → the head row
 * bumps → the notify watch fires → a real push adapter signs an APNS request.
 *
 * This exists because the loop was broken in a way no single-component test
 * could see. The relay bridge only fires on a row keyed `head!<appId>`, and
 * pear-bots only ever wrote `mailbox!<id>`, so every layer passed its own tests
 * while no bot was ever woken. The appends below are the literal shapes
 * pear-bots' `OutboxlogRelay.enqueue` writes — if either side changes its wire
 * shape, this test is what notices.
 */

import test from 'brittle'
import { generateKeyPairSync, createPublicKey, verify as cryptoVerify } from 'node:crypto'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  NotifyService,
  NOTIFY_DOMAINS,
  notifySignaturePayload
} from '../../packages/services/builtin/notify-service.js'
import { OutboxLogApp } from '../../packages/services/builtin/outboxlog/index.js'
import { sealDeviceToken } from '../../packages/services/builtin/notify-push/index.js'

const NOW = 1782864000000
const HOUR = 60 * 60 * 1000
const PB_NAMESPACE = 'pear-bots'

const tick = () => new Promise(resolve => setImmediate(resolve))

test('wake loop: a pear-bots mailbox enqueue wakes the recipient device', async (t) => {
  const relay = keyPair(51)
  const user = keyPair(52)
  const device = keyPair(53)
  const sender = keyPair(54)
  // pear-bots uses the recipient's own key as the outbox appId, and the same
  // value as the notify watch source key. That equality is what closes the loop.
  const ownerKey = hex(60)

  const provider = { attempts: [], async send (d) { this.attempts.push(d); return { status: 'accepted_by_provider' } } }
  const outbox = new OutboxLogApp({ verifyAppend: () => true, persistence: false })
  // A relay only accepts records tagged `_ns: 'pear-bots'` if that namespace is
  // registered. Without this, every enqueue is rejected 400 "unknown namespace"
  // — so this line is a real operator prerequisite, not test scaffolding.
  await outbox.start({ config: { outboxlog: { namespaces: { [PB_NAMESPACE]: { blind: false } } } } })
  const notify = new NotifyService({ keyPair: relay, provider, clock: () => NOW })

  // Verbatim the closure relay-node/index.js installs at startup.
  notify.attachWatchSource('notify-feed-head', (source, onChange) => {
    return outbox.subscribe(source.key, {}, (event) => {
      if (event && event.key === 'head!' + source.key && !event.replay) onChange(event)
    })
  })

  await installHappyPath(notify, { relay, user, device, sender, modes: ['direct', 'watch'] })
  const installed = await notify.watch(signed(user, NOTIFY_DOMAINS.watch, {
    type: 'hiverelay.notify.watch.v1',
    watchId: hex(59),
    receiveCap: hex(6),
    sendCap: hex(7),
    app: hex(5),
    audience: relay.hex,
    source: { kind: 'notify-feed-head', key: ownerKey, start: 0 },
    channel: 'message',
    policy: { minIntervalSeconds: 30 },
    createdAt: NOW,
    expiresAt: NOW + HOUR
  }))
  t.is(installed.ok, true, 'watch installed against the recipient outbox')

  outbox.create({ appId: ownerKey })

  // 1. The mailbox row alone — this is all pear-bots used to write.
  outbox.append({
    appId: ownerKey,
    op: { type: 'mailbox', data: { id: 'c'.repeat(32), _ns: PB_NAMESPACE, payload: 'sealed-ciphertext', createdAt: NOW } }
  })
  await tick()
  t.is(provider.attempts.length, 0, 'a mailbox row on its own wakes nobody — this was the whole bug')

  // 2. The head row pear-bots now writes immediately after it.
  outbox.append({
    appId: ownerKey,
    op: { type: 'head', data: { id: ownerKey, _ns: PB_NAMESPACE, bumpedAt: NOW } }
  })
  await tick()
  t.is(provider.attempts.length, 1, 'head row wakes the recipient device')

  const wake = provider.attempts[0]
  t.is(wake.payloadCiphertext, '', 'the wake is an opaque poke, not a message')
  t.absent(JSON.stringify(wake).includes('sealed-ciphertext'), 'no record content reaches the push provider')
  t.absent('intent' in wake, 'watch wakes carry no intent — adapters must not require one')

  // 3. Coalescing: a second enqueue inside minIntervalSeconds must not
  //    double-spend the device's push budget.
  outbox.append({ appId: ownerKey, op: { type: 'head', data: { id: ownerKey, _ns: PB_NAMESPACE, bumpedAt: NOW + 1000 } } })
  await tick()
  t.is(provider.attempts.length, 1, 'a second head bump inside the coalescing window is dropped')
})

test('wake loop: the wake reaches a real signing adapter', async (t) => {
  const relay = keyPair(51)
  const user = keyPair(52)
  const device = keyPair(53)
  const sender = keyPair(54)
  const ownerKey = hex(61)

  // A real APNS adapter with an ephemeral key and a recording transport.
  const apnsPem = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    .privateKey.export({ type: 'pkcs8', format: 'pem' })
  const requests = []

  const outbox = new OutboxLogApp({ verifyAppend: () => true, persistence: false })
  // A relay only accepts records tagged `_ns: 'pear-bots'` if that namespace is
  // registered. Without this, every enqueue is rejected 400 "unknown namespace"
  // — so this line is a real operator prerequisite, not test scaffolding.
  await outbox.start({ config: { outboxlog: { namespaces: { [PB_NAMESPACE]: { blind: false } } } } })
  const notify = new NotifyService({ keyPair: relay, clock: () => NOW })

  // Resolve the provider the way an operator does — through config, in start().
  await notify.start({
    config: {
      notify: {
        push: {
          kind: 'apns',
          tokenEncoding: 'sealed',
          credentials: { privateKey: apnsPem, keyId: 'KID', teamId: 'TEAM', bundleId: 'app.pear.bots' },
          transport: async (req) => { requests.push(req); return { status: 200, body: {} } }
        }
      }
    }
  })
  t.is(notify.provider.kind, 'apns', 'config.notify.push resolved a real adapter')
  t.is(notify.limits().egress.live, true, 'and the relay now reports live egress')

  notify.attachWatchSource('notify-feed-head', (source, onChange) => {
    return outbox.subscribe(source.key, {}, (event) => {
      if (event && event.key === 'head!' + source.key && !event.replay) onChange(event)
    })
  })

  // The device sealed its APNS token to this relay; only this relay can open it.
  await installHappyPath(notify, {
    relay,
    user,
    device,
    sender,
    modes: ['direct', 'watch'],
    tokenCiphertext: sealDeviceToken('apns-device-token-xyz', relay.publicKey)
  })
  await notify.watch(signed(user, NOTIFY_DOMAINS.watch, {
    type: 'hiverelay.notify.watch.v1',
    watchId: hex(58),
    receiveCap: hex(6),
    sendCap: hex(7),
    app: hex(5),
    audience: relay.hex,
    source: { kind: 'notify-feed-head', key: ownerKey, start: 0 },
    channel: 'message',
    policy: { minIntervalSeconds: 30 },
    createdAt: NOW,
    expiresAt: NOW + HOUR
  }))

  outbox.create({ appId: ownerKey })
  outbox.append({ appId: ownerKey, op: { type: 'head', data: { id: ownerKey, _ns: PB_NAMESPACE, bumpedAt: NOW } } })
  await tick()

  t.is(requests.length, 1, 'the wake produced exactly one APNS request')
  const req = requests[0]
  t.ok(req.url.endsWith('/3/device/apns-device-token-xyz'), 'sealed device token was opened for egress')
  t.is(req.headers['apns-push-type'], 'background', 'silent wake')
  t.is(req.body.aps['content-available'], 1)

  const [h, p, s] = req.headers.authorization.slice('bearer '.length).split('.')
  t.ok(cryptoVerify(
    'sha256',
    Buffer.from(h + '.' + p, 'utf8'),
    { key: createPublicKey(apnsPem), dsaEncoding: 'ieee-p1363' },
    Buffer.from(s, 'base64url')
  ), 'the request carries a genuinely signed ES256 JWT')

  await notify.stop()
})

async function installHappyPath (notify, { relay, user, device, sender, modes = ['direct'], tokenCiphertext = 'encrypted-provider-token' }) {
  const app = hex(5)
  const bindingId = hex(8)
  const receiveCap = hex(6)
  const sendCap = hex(7)

  await notify['bind-provider'](signed(device, NOTIFY_DOMAINS.providerBinding, {
    type: 'hiverelay.notify.provider-binding.v1',
    bindingId,
    audience: relay.hex,
    app,
    device: device.hex,
    mode: 'runtimePush',
    provider: 'apns',
    platform: 'ios',
    scope: { bundle: 'app.pear.bots' },
    credentialMode: 'runtime-owned',
    tokenHash: hex(10),
    tokenCiphertext,
    generation: 1,
    createdAt: NOW,
    expiresAt: NOW + HOUR,
    nonce: 'a'.repeat(32)
  }))

  await notify['register-device'](signed(device, NOTIFY_DOMAINS.deviceRegistration, {
    type: 'hiverelay.notify.device-registration.v1',
    audience: relay.hex,
    app,
    user: user.hex,
    device: device.hex,
    encryptionKey: hex(12),
    bindingId,
    createdAt: NOW,
    expiresAt: NOW + HOUR,
    nonce: 'b'.repeat(32)
  }))

  await notify['install-receive-cap'](signed(user, NOTIFY_DOMAINS.receiveCap, {
    type: 'hiverelay.notify.receive-cap.v1',
    capId: receiveCap,
    audience: relay.hex,
    user: user.hex,
    app,
    device: device.hex,
    bindingId,
    tokenHash: hex(10),
    channels: ['message'],
    modes,
    quota: { perHour: 30, burst: 5, maxTtlSeconds: 3600, maxUrgency: 'normal' },
    createdAt: NOW,
    expiresAt: NOW + HOUR,
    nonce: 'd'.repeat(32)
  }))

  await notify['install-send-cap'](signed(user, NOTIFY_DOMAINS.sendCap, {
    type: 'hiverelay.notify.send-cap.v1',
    capId: sendCap,
    receiveCap,
    audience: relay.hex,
    app,
    device: device.hex,
    sender: sender.hex,
    channel: 'message',
    quota: { perHour: 10, burst: 3, maxTtlSeconds: 3600, maxUrgency: 'normal' },
    createdAt: NOW,
    expiresAt: NOW + HOUR,
    nonce: 'e'.repeat(32)
  }))

  return { app, bindingId, receiveCap, sendCap }
}

function signed (key, domain, body) {
  const signature = b4a.alloc(64)
  sodium.crypto_sign_detached(signature, notifySignaturePayload(domain, body), key.secretKey)
  return { ...body, signature: b4a.toString(signature, 'hex') }
}

function keyPair (seedByte) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.alloc(32, seedByte))
  return { publicKey, secretKey, hex: b4a.toString(publicKey, 'hex') }
}

function hex (byte) {
  return byte.toString(16).padStart(2, '0').repeat(32)
}
