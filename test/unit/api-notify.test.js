import test from 'brittle'
import http from 'http'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { RelayAPI } from 'p2p-hiverelay/core/relay-node/api.js'
import {
  NotifyService,
  NOTIFY_DOMAINS,
  notifySignaturePayload
} from 'p2p-hiveservices/builtin/notify-service.js'

const API_KEY = 'notify-test-key'
const NOW = 1782864000000
const HOUR = 60 * 60 * 1000

test('notify http api: capabilities report disabled provider cleanly', async (t) => {
  const { port } = await serverWithApi(t, mockNode({ registry: null }))
  const res = await request(port, 'GET', '/api/v1/notify/capabilities')

  t.is(res.statusCode, 503)
  t.alike(res.body, { error: 'Notify service is not enabled on this relay' })
})

test('notify http api: signed wake flow and redacted diagnostics', async (t) => {
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
        return { status: 'accepted_by_provider', providerStatus: 'http-memory-ok' }
      }
    }
  })
  const { port } = await serverWithApi(t, mockNode({ registry: notifyRegistry(notify) }))

  const caps = await request(port, 'GET', '/api/v1/notify/capabilities')
  t.is(caps.statusCode, 200)
  t.is(caps.body.service, 'notify')
  t.is(caps.body.payload.plaintextAllowed, false)

  const installed = await installNotifyHttp(port, { relay, user, device, sender })
  t.is(installed.sendCap.body.ok, true)

  const unsignedStatus = await request(port, 'GET', '/api/v1/notify/status?app=' + hex(5))
  t.is(unsignedStatus.statusCode, 401)

  const statusQuery = signed(device, NOTIFY_DOMAINS.status, {
    type: 'hiverelay.notify.status.v1',
    app: hex(5),
    device: device.hex,
    createdAt: String(NOW),
    nonce: 'f'.repeat(32)
  })
  const status = await request(port, 'GET', '/api/v1/notify/status?' + new URLSearchParams(statusQuery).toString())
  t.is(status.statusCode, 200)
  t.is(status.body.counts.receiveCaps, 1)

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
  const sent = await request(port, 'POST', '/api/v1/notify/send', intent)
  t.is(sent.statusCode, 200)
  t.is(sent.body.ok, true)
  t.is(attempts.length, 1)
  t.is(attempts[0].providerTokenCiphertext, 'encrypted-provider-token')

  const managementDenied = await request(port, 'GET', '/api/manage/notify')
  t.is(managementDenied.statusCode, 401)

  const management = await request(port, 'GET', '/api/manage/notify', null, { Authorization: 'Bearer ' + API_KEY })
  t.is(management.statusCode, 200)
  t.is(management.body.counts.providerBindings, 1)
  t.absent(JSON.stringify(management.body).includes('encrypted-provider-token'))

  const gates = await request(port, 'GET', '/api/manage/notify/production-gates?app=' + hex(5), null, { Authorization: 'Bearer ' + API_KEY })
  t.is(gates.statusCode, 200)
  t.ok(gates.body.gates.some(gate => gate.id === 'provider-binding' && gate.ok === true))
})

function notifyRegistry (provider) {
  return {
    services: new Map([[
      'notify',
      {
        name: 'notify',
        version: '0.1.0',
        status: 'running',
        capabilities: provider.manifest().capabilities,
        provider
      }
    ]])
  }
}

function mockNode (opts = {}) {
  return {
    running: true,
    config: { storage: null, plugins: opts.plugins || [], trustProxy: true },
    metrics: { getSummary () { return { uptime: 1 } } },
    seededApps: new Map(),
    appRegistry: { apps: new Map(), catalog () { return [] }, catalogForBroadcast () { return [] } },
    getStats () { return { running: true } },
    getHealthStatus () { return { healthy: true } },
    serviceRegistry: opts.registry || null,
    async stop () {},
    async start () {},
    on () {},
    emit () {}
  }
}

async function installNotifyHttp (port, { relay, user, device, sender }) {
  const app = hex(5)
  const bindingId = hex(8)
  const receiveCap = hex(6)
  const sendCap = hex(7)

  const provider = await request(port, 'POST', '/api/v1/notify/provider', signed(device, NOTIFY_DOMAINS.providerBinding, {
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

  const registered = await request(port, 'POST', '/api/v1/notify/device', signed(device, NOTIFY_DOMAINS.deviceRegistration, {
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

  const receive = await request(port, 'POST', '/api/v1/notify/receive-cap', signed(user, NOTIFY_DOMAINS.receiveCap, {
    type: 'hiverelay.notify.receive-cap.v1',
    capId: receiveCap,
    audience: relay.hex,
    user: user.hex,
    app,
    device: device.hex,
    bindingId,
    tokenHash: hex(10),
    channels: ['message'],
    modes: ['direct', 'watch'],
    quota: { perHour: 30, burst: 5, maxTtlSeconds: 3600, maxUrgency: 'normal' },
    createdAt: NOW,
    expiresAt: NOW + HOUR,
    nonce: 'd'.repeat(32)
  }))

  const sendCapRes = await request(port, 'POST', '/api/v1/notify/send-cap', signed(user, NOTIFY_DOMAINS.sendCap, {
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

  return { provider, registered, receive, sendCap: sendCapRes }
}

function request (port, method, path, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      method,
      path,
      headers: { 'Content-Type': 'application/json', ...headers }
    }, (res) => {
      let data = ''
      res.on('data', (chunk) => { data += chunk })
      res.on('end', () => {
        let parsed
        try { parsed = JSON.parse(data) } catch { parsed = data }
        resolve({ statusCode: res.statusCode, body: parsed, headers: res.headers })
      })
    })
    req.on('error', reject)
    if (body != null) req.write(JSON.stringify(body))
    req.end()
  })
}

async function serverWithApi (t, node, opts = {}) {
  const api = new RelayAPI(node, { apiPort: 0, apiHost: '127.0.0.1', apiKey: API_KEY, ...opts })
  await api.start()
  const port = api.server.address().port
  t.teardown(async () => {
    if (api._rateLimitCleanup) clearInterval(api._rateLimitCleanup)
    if (api._dashboardFeed) { try { api._dashboardFeed.stop() } catch {} }
    if (api._pokerFeed) { try { api._pokerFeed.stop() } catch {} }
    await new Promise((resolve) => api.server.close(resolve))
  })
  return { api, port }
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
