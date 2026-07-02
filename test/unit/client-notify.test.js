import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { NotifyService, verifyNotifySignature as verifyServiceNotifySignature } from 'p2p-hiveservices/builtin/notify-service.js'
import {
  NOTIFY_DOMAINS,
  createNotifyDeliveryEventRequest,
  createNotifyDeviceRegistration,
  createNotifyHttpClient,
  createNotifyIntent,
  createNotifyProviderBinding,
  createNotifyReceiveCap,
  createNotifySendCap,
  createNotifyServiceClient,
  createNotifyStatusRequest,
  verifyNotifySignature
} from 'p2p-hiverelay-client/notify.js'

const NOW = 1782864000000
const HOUR = 60 * 60 * 1000

test('client notify: signed builders interoperate with notify service verifier', async (t) => {
  const relay = keyPair(1)
  const user = keyPair(2)
  const device = keyPair(3)
  const sender = keyPair(4)
  const attempts = []
  const notify = new NotifyService({
    keyPair: relay,
    clock: () => NOW,
    provider: {
      async send (delivery) {
        attempts.push(delivery)
        return { status: 'accepted_by_provider', providerStatus: 'client-helper-ok' }
      }
    }
  })

  const providerBinding = createNotifyProviderBinding({
    bindingId: hex(8),
    audience: relay.hex,
    app: hex(5),
    mode: 'runtimePush',
    provider: 'apns',
    platform: 'ios',
    scope: { bundle: 'org.hiverelay.runtime' },
    credentialMode: 'runtime-owned',
    tokenHash: hex(10),
    tokenCiphertext: 'encrypted-provider-token',
    generation: 1,
    expiresAt: NOW + HOUR,
    nonce: 'a'.repeat(32)
  }, device, { now: NOW })
  t.ok(verifyNotifySignature(providerBinding, NOTIFY_DOMAINS.providerBinding, device.hex))
  t.ok(verifyServiceNotifySignature(providerBinding, NOTIFY_DOMAINS.providerBinding, device.hex))
  t.absent(verifyNotifySignature({ ...providerBinding, generation: 2 }, NOTIFY_DOMAINS.providerBinding, device.hex))
  await notify['bind-provider'](providerBinding)

  await notify['register-device'](createNotifyDeviceRegistration({
    audience: relay.hex,
    app: hex(5),
    user: user.hex,
    encryptionKey: hex(12),
    bindingId: hex(8),
    expiresAt: NOW + HOUR,
    nonce: 'b'.repeat(32)
  }, device, { now: NOW }))

  await notify['install-receive-cap'](createNotifyReceiveCap({
    capId: hex(6),
    audience: relay.hex,
    user: user.hex,
    app: hex(5),
    device: device.hex,
    bindingId: hex(8),
    tokenHash: hex(10),
    channels: ['message'],
    modes: ['direct'],
    quota: { perHour: 30, burst: 5, maxTtlSeconds: 3600, maxUrgency: 'normal' },
    expiresAt: NOW + HOUR,
    nonce: 'd'.repeat(32)
  }, user, { now: NOW }))

  await notify['install-send-cap'](createNotifySendCap({
    capId: hex(7),
    receiveCap: hex(6),
    audience: relay.hex,
    app: hex(5),
    device: device.hex,
    sender: sender.hex,
    channel: 'message',
    quota: { perHour: 10, burst: 3, maxTtlSeconds: 3600, maxUrgency: 'normal' },
    expiresAt: NOW + HOUR,
    nonce: 'e'.repeat(32)
  }, user, { now: NOW }))

  const status = await notify.status(createNotifyStatusRequest({
    app: hex(5),
    device: device.hex,
    nonce: 'f'.repeat(32)
  }, device, { now: NOW }))
  t.is(status.counts.receiveCaps, 1)

  const sent = await notify.send(createNotifyIntent({
    intentId: hex(9),
    receiveCap: hex(6),
    sendCap: hex(7),
    app: hex(5),
    receiver: device.hex,
    channel: 'message',
    urgency: 'normal',
    ttlSeconds: 3600,
    payloadCiphertext: 'ciphertext',
    privacyProfile: 'generic'
  }, sender, { now: NOW }))
  t.is(sent.ok, true)
  t.is(attempts.length, 1)

  // The device reads its own delivery events with the signed request builder;
  // a foreign key proving its own device reads nothing.
  const events = await notify['delivery-event'](createNotifyDeliveryEventRequest({ intentId: hex(9) }, device))
  t.is(events.count, 1)
  t.is(events.events[0].status, 'accepted_by_provider')
  const foreign = keyPair(9)
  const denied = await notify['delivery-event'](createNotifyDeliveryEventRequest({ intentId: hex(9) }, foreign))
  t.is(denied.count, 0)
})

test('client notify: service client wraps callService method names', async (t) => {
  const calls = []
  const notify = createNotifyServiceClient({
    async callService (service, method, params, opts) {
      calls.push({ service, method, params, opts })
      return { ok: true, method }
    }
  }, { relay: 'relay-a', timeout: 1000 })

  const sent = await notify.send({ intentId: hex(9) }, { timeout: 2000 })
  await notify.deliveryEvent({ intentId: hex(9) })

  t.alike(sent, { ok: true, method: 'send' })
  t.alike(calls, [
    { service: 'notify', method: 'send', params: { intentId: hex(9) }, opts: { relay: 'relay-a', timeout: 2000 } },
    { service: 'notify', method: 'delivery-event', params: { intentId: hex(9) }, opts: { relay: 'relay-a', timeout: 1000 } }
  ])
})

test('client notify: http client maps stable routes and bearer auth', async (t) => {
  const calls = []
  const client = createNotifyHttpClient('https://relay.example/', {
    apiKey: 'secret',
    fetch: async (url, opts) => {
      calls.push({ url, opts })
      return { ok: true, status: 200, async json () { return { ok: true } } }
    }
  })

  await client.capabilities()
  await client.bindProvider({ bindingId: hex(8) })
  await client.productionGates({ app: hex(5) })

  t.is(calls[0].url, 'https://relay.example/api/v1/notify/capabilities')
  t.is(calls[0].opts.method, 'GET')
  t.is(calls[1].url, 'https://relay.example/api/v1/notify/provider')
  t.is(calls[1].opts.method, 'POST')
  t.is(calls[1].opts.headers.Authorization, 'Bearer secret')
  t.is(calls[1].opts.body, JSON.stringify({ bindingId: hex(8) }))
  t.is(calls[2].url, 'https://relay.example/api/manage/notify/production-gates?app=' + hex(5))
})

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
