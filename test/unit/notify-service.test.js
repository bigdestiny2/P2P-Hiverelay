import test from 'brittle'
import { mkdtemp, rm } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  NotifyService,
  NOTIFY_DOMAINS,
  notifySignaturePayload,
  verifyNotifySignature
} from '../../packages/services/builtin/notify-service.js'

const NOW = 1782864000000
const HOUR = 60 * 60 * 1000

test('notify service: signed direct wake path stores redacted delivery event', async (t) => {
  const relay = keyPair(1)
  const user = keyPair(2)
  const device = keyPair(3)
  const sender = keyPair(4)
  const provider = {
    attempts: [],
    async send (delivery) {
      this.attempts.push(delivery)
      return { status: 'accepted_by_provider', providerStatus: 'memory-ok' }
    }
  }
  const notify = new NotifyService({ keyPair: relay, provider, clock: () => NOW })

  await installHappyPath(notify, { relay, user, device, sender })
  const intent = signed(sender, NOTIFY_DOMAINS.intent, {
    type: 'hiverelay.notify.intent.v1',
    intentId: hex(9),
    receiveCap: hex(6),
    sendCap: hex(7),
    app: hex(5),
    receiver: device.hex,
    sender: sender.hex,
    channel: 'message',
    urgency: 'normal',
    ttlSeconds: 3600,
    collapseKey: 'thread-hash',
    dedupeKey: 'event-hash-1',
    createdAt: NOW,
    payloadCiphertext: 'ciphertext',
    payloadEncoding: 'hiverelay.notify.payload.box.v1',
    privacyProfile: 'generic'
  })

  const sent = await notify.send(intent)
  t.is(sent.ok, true)
  t.is(sent.status, 'accepted_by_provider')
  t.is(provider.attempts.length, 1)
  t.is(provider.attempts[0].providerTokenCiphertext, 'encrypted-provider-token')

  const events = await notify['delivery-event'](signed(device, NOTIFY_DOMAINS.deliveryEventRequest, { intentId: intent.intentId, device: device.hex }))
  t.is(events.count, 1)
  t.is(events.events[0].status, 'accepted_by_provider')
  t.is(events.events[0].providerStatus, 'memory-ok')
  t.absent(JSON.stringify(events.events[0]).includes('encrypted-provider-token'))
  t.ok(verifyNotifySignature(events.events[0], NOTIFY_DOMAINS.deliveryEvent, relay.hex))
})

test('notify service: delivery-event requires a device-signed request (no cross-tenant IDOR)', async (t) => {
  const relay = keyPair(1)
  const user = keyPair(2)
  const device = keyPair(3)
  const sender = keyPair(4)
  const attacker = keyPair(88)
  const provider = { attempts: [], async send () { return { status: 'accepted_by_provider' } } }
  const notify = new NotifyService({ keyPair: relay, provider, clock: () => NOW })

  await installHappyPath(notify, { relay, user, device, sender })
  const intent = signed(sender, NOTIFY_DOMAINS.intent, {
    type: 'hiverelay.notify.intent.v1',
    intentId: hex(9),
    receiveCap: hex(6),
    sendCap: hex(7),
    app: hex(5),
    receiver: device.hex,
    sender: sender.hex,
    channel: 'message',
    urgency: 'normal',
    ttlSeconds: 3600,
    createdAt: NOW,
    payloadCiphertext: 'ciphertext',
    privacyProfile: 'generic'
  })
  const sent = await notify.send(intent)
  t.is(sent.ok, true)

  // Unsigned request is rejected outright.
  await t.exception(notify['delivery-event']({ intentId: intent.intentId, device: device.hex }), /BAD_SIGNATURE/)
  // A request with no device field cannot prove caller scope.
  await t.exception(notify['delivery-event'](signed(device, NOTIFY_DOMAINS.deliveryEventRequest, { intentId: intent.intentId })), /BAD_SIGNATURE/)
  // Attacker names the victim's device but signs with their own key: the
  // signature fails to verify against the claimed device key -> rejected.
  await t.exception(notify['delivery-event'](signed(attacker, NOTIFY_DOMAINS.deliveryEventRequest, { intentId: intent.intentId, device: device.hex })), /BAD_SIGNATURE/)
  // Attacker validly proves control of their OWN device, but the victim's
  // event.device != attacker -> reads nothing (no metadata leak).
  const leaked = await notify['delivery-event'](signed(attacker, NOTIFY_DOMAINS.deliveryEventRequest, { intentId: intent.intentId, device: attacker.hex }))
  t.is(leaked.count, 0)
  // The legitimate device still reads its own event.
  const ok = await notify['delivery-event'](signed(device, NOTIFY_DOMAINS.deliveryEventRequest, { intentId: intent.intentId, device: device.hex }))
  t.is(ok.count, 1)
})

test('notify service: sender without matching SendCap is rejected before provider attempt', async (t) => {
  const relay = keyPair(11)
  const user = keyPair(12)
  const device = keyPair(13)
  const sender = keyPair(14)
  const imposter = keyPair(15)
  const provider = { attempts: [], async send (delivery) { this.attempts.push(delivery); return { status: 'accepted_by_provider' } } }
  const notify = new NotifyService({ keyPair: relay, provider, clock: () => NOW })

  await installHappyPath(notify, { relay, user, device, sender })
  const intent = signed(imposter, NOTIFY_DOMAINS.intent, {
    type: 'hiverelay.notify.intent.v1',
    intentId: hex(19),
    receiveCap: hex(6),
    sendCap: hex(7),
    app: hex(5),
    receiver: device.hex,
    sender: imposter.hex,
    channel: 'message',
    urgency: 'normal',
    ttlSeconds: 3600,
    createdAt: NOW,
    payloadCiphertext: 'ciphertext',
    privacyProfile: 'generic'
  })

  const sent = await notify.send(intent)
  t.is(sent.ok, false)
  t.is(sent.reason, 'send_cap_missing')
  t.is(provider.attempts.length, 0)
})

test('notify service: revoked send capability suppresses provider egress', async (t) => {
  const relay = keyPair(21)
  const user = keyPair(22)
  const device = keyPair(23)
  const sender = keyPair(24)
  const provider = { attempts: [], async send (delivery) { this.attempts.push(delivery); return { status: 'accepted_by_provider' } } }
  const notify = new NotifyService({ keyPair: relay, provider, clock: () => NOW })

  await installHappyPath(notify, { relay, user, device, sender })
  const revoke = signed(user, NOTIFY_DOMAINS.revoke, {
    type: 'hiverelay.notify.revocation.v1',
    target: hex(7),
    user: user.hex,
    app: hex(5),
    audience: relay.hex,
    scope: 'send-cap',
    createdAt: NOW,
    nonce: 'c'.repeat(32)
  })
  await notify.revoke(revoke)

  const intent = signed(sender, NOTIFY_DOMAINS.intent, {
    type: 'hiverelay.notify.intent.v1',
    intentId: hex(29),
    receiveCap: hex(6),
    sendCap: hex(7),
    app: hex(5),
    receiver: device.hex,
    sender: sender.hex,
    channel: 'message',
    urgency: 'normal',
    ttlSeconds: 3600,
    createdAt: NOW,
    payloadCiphertext: 'ciphertext',
    privacyProfile: 'generic'
  })

  const sent = await notify.send(intent)
  t.is(sent.ok, false)
  t.is(sent.reason, 'cap_revoked')
  t.is(provider.attempts.length, 0)
})

test('notify service: watch mode is opaque and requires receive/send caps', async (t) => {
  const relay = keyPair(31)
  const user = keyPair(32)
  const device = keyPair(33)
  const sender = keyPair(34)
  const notify = new NotifyService({ keyPair: relay, clock: () => NOW })

  await installHappyPath(notify, { relay, user, device, sender, modes: ['direct', 'watch'] })
  const watch = signed(user, NOTIFY_DOMAINS.watch, {
    type: 'hiverelay.notify.watch.v1',
    watchId: hex(39),
    receiveCap: hex(6),
    sendCap: hex(7),
    app: hex(5),
    audience: relay.hex,
    source: {
      kind: 'hypercore-head',
      key: hex(40),
      start: 42
    },
    channel: 'message',
    policy: { minIntervalSeconds: 60 },
    createdAt: NOW,
    expiresAt: NOW + HOUR
  })

  const installed = await notify.watch(watch)
  t.is(installed.ok, true)
  t.alike(installed.source, { kind: 'hypercore-head', key: hex(40), start: 42 })

  const status = await notify.status({ app: hex(5), device: device.hex })
  t.is(status.counts.watches, 1)
  t.is(status.privacy.plaintextAllowed, false)
})

test('notify service: default file persistence restores signed caps, watches, revocations and events', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'notify-service-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))

  const relay = keyPair(41)
  const user = keyPair(42)
  const device = keyPair(43)
  const sender = keyPair(44)
  const provider = { attempts: [], async send (delivery) { this.attempts.push(delivery); return { status: 'accepted_by_provider' } } }
  const first = new NotifyService({
    keyPair: relay,
    provider,
    clock: () => NOW
  })
  await first.start({ config: { storage: dir } })
  const ids = await installHappyPath(first, { relay, user, device, sender, modes: ['direct', 'watch'] })

  await first.watch(signed(user, NOTIFY_DOMAINS.watch, {
    type: 'hiverelay.notify.watch.v1',
    watchId: hex(45),
    receiveCap: ids.receiveCap,
    sendCap: ids.sendCap,
    app: ids.app,
    audience: relay.hex,
    source: {
      kind: 'notify-feed-head',
      key: hex(46),
      start: 7
    },
    channel: 'message',
    policy: { minIntervalSeconds: 30 },
    createdAt: NOW,
    expiresAt: NOW + HOUR
  }))

  const intent = signed(sender, NOTIFY_DOMAINS.intent, {
    type: 'hiverelay.notify.intent.v1',
    intentId: hex(47),
    receiveCap: ids.receiveCap,
    sendCap: ids.sendCap,
    app: ids.app,
    receiver: device.hex,
    sender: sender.hex,
    channel: 'message',
    urgency: 'normal',
    ttlSeconds: 3600,
    createdAt: NOW,
    payloadCiphertext: 'ciphertext',
    privacyProfile: 'generic'
  })
  const sent = await first.send(intent)
  t.is(sent.ok, true)

  await first.revoke(signed(user, NOTIFY_DOMAINS.revoke, {
    type: 'hiverelay.notify.revocation.v1',
    target: ids.sendCap,
    user: user.hex,
    app: ids.app,
    audience: relay.hex,
    scope: 'send-cap',
    createdAt: NOW,
    nonce: 'f'.repeat(32)
  }))
  await first.stop()

  const restoredProvider = { attempts: [], async send (delivery) { this.attempts.push(delivery); return { status: 'accepted_by_provider' } } }
  const second = new NotifyService({
    keyPair: relay,
    provider: restoredProvider,
    clock: () => NOW
  })
  await second.start({ config: { storage: dir } })

  const status = await second.status({ app: ids.app, device: device.hex })
  t.is(status.counts.providerBindings, 1)
  t.is(status.counts.devices, 1)
  t.is(status.counts.receiveCaps, 1)
  t.is(status.counts.sendCaps, 1)
  t.is(status.counts.watches, 1)
  t.is(status.counts.revocations, 1)
  t.is(status.counts.deliveryEvents, 1)

  const events = await second['delivery-event'](signed(device, NOTIFY_DOMAINS.deliveryEventRequest, { intentId: intent.intentId, device: device.hex }))
  t.is(events.count, 1)
  t.is(events.events[0].status, 'accepted_by_provider')
  t.ok(verifyNotifySignature(events.events[0], NOTIFY_DOMAINS.deliveryEvent, relay.hex))

  const blocked = await second.send(signed(sender, NOTIFY_DOMAINS.intent, {
    type: 'hiverelay.notify.intent.v1',
    intentId: hex(48),
    receiveCap: ids.receiveCap,
    sendCap: ids.sendCap,
    app: ids.app,
    receiver: device.hex,
    sender: sender.hex,
    channel: 'message',
    urgency: 'normal',
    ttlSeconds: 3600,
    createdAt: NOW,
    payloadCiphertext: 'ciphertext',
    privacyProfile: 'generic'
  }))
  t.is(blocked.ok, false)
  t.is(blocked.reason, 'cap_revoked')
  t.is(restoredProvider.attempts.length, 0)
  await second.stop()

  const third = new NotifyService({
    keyPair: relay,
    clock: () => NOW
  })
  await third.start({ config: { storage: dir } })
  const blockedEvents = await third['delivery-event'](signed(device, NOTIFY_DOMAINS.deliveryEventRequest, { intentId: blocked.intentId, device: device.hex }))
  t.is(blockedEvents.count, 1)
  t.is(blockedEvents.events[0].reason, 'cap_revoked')
  await third.stop()
})

test('notify service: manifest exposes v1 service capabilities', (t) => {
  const notify = new NotifyService()
  const manifest = notify.manifest()
  t.is(manifest.name, 'notify')
  t.ok(manifest.capabilities.includes('bind-provider'))
  t.ok(manifest.capabilities.includes('install-receive-cap'))
  t.ok(manifest.capabilities.includes('install-send-cap'))
  t.ok(manifest.capabilities.includes('delivery-event'))
})

async function installHappyPath (notify, { relay, user, device, sender, modes = ['direct'] }) {
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
    scope: { bundle: 'org.hiverelay.runtime' },
    credentialMode: 'runtime-owned',
    tokenHash: hex(10),
    tokenCiphertext: 'encrypted-provider-token',
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
  return {
    publicKey,
    secretKey,
    hex: b4a.toString(publicKey, 'hex')
  }
}

function hex (byte) {
  return byte.toString(16).padStart(2, '0').repeat(32)
}
