/**
 * End-to-end wake loops for both sender-owned virtual lanes and the legacy
 * global-head compatibility watch.
 *
 * This exists because the loop was broken in a way no single-component test
 * could see. The relay bridge only fires on a row keyed `head!<appId>`, and
 * pear-bots only ever wrote `mailbox!<id>`, so every layer passed its own tests
 * while no bot was ever woken. The appends below are the literal shapes
 * pear-bots' `OutboxlogRelay.enqueue` writes — if either side changes its wire
 * shape, this test is what notices.
 */

import test from 'brittle'
import { createHash, generateKeyPairSync, createPublicKey, verify as cryptoVerify } from 'node:crypto'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  NotifyService,
  NOTIFY_DOMAINS,
  notifySignaturePayload
} from '../../packages/services/builtin/notify-service.js'
import {
  OutboxLogApp,
  canonicalOutboxRecord,
  createMemoryOutboxJournal,
  createOutboxBlindSealedBody
} from '../../packages/services/builtin/outboxlog/index.js'
import { sealDeviceToken } from '../../packages/services/builtin/notify-push/index.js'

const NOW = 1782864000000
const HOUR = 60 * 60 * 1000
const PB_NAMESPACE = 'pear-bots'

const tick = () => new Promise(resolve => setImmediate(resolve))

test('wake loop: a signed atomic pear-bots lane commit wakes only that opaque lane', async (t) => {
  const relay = keyPair(51)
  const user = keyPair(52)
  const device = keyPair(53)
  const sender = keyPair(54)
  const laneA = hex(60)
  const laneB = hex(61)

  const provider = { attempts: [], async send (d) { this.attempts.push(d); return { status: 'accepted_by_provider' } } }
  const outbox = new OutboxLogApp({
    journal: createMemoryOutboxJournal([], { durableSync: true }),
    persistence: false
  })
  await outbox.start({ config: { outboxlog: { namespaces: { [PB_NAMESPACE]: { blind: true } } } } })
  const notify = new NotifyService({ keyPair: relay, provider, clock: () => NOW })

  // Verbatim the virtual-lane closure relay-node/index.js installs at startup.
  notify.attachWatchSource('notify-outbox-lane', (source, onChange) => {
    return outbox.subscribe(source.key, {}, (event) => {
      if (event && event.key === 'lane-head!' + source.lane && !event.replay) onChange(event)
    })
  })

  await installHappyPath(notify, { relay, user, device, sender, modes: ['watch'] })
  const watchA = await notify.watch(signed(user, NOTIFY_DOMAINS.watch, {
    type: 'hiverelay.notify.watch.v1',
    watchId: hex(59),
    receiveCap: hex(6),
    sendCap: hex(7),
    app: hex(5),
    audience: relay.hex,
    source: { kind: 'notify-outbox-lane', key: sender.hex, lane: laneA, start: 0 },
    channel: 'message',
    policy: { minIntervalSeconds: 30 },
    createdAt: NOW,
    expiresAt: NOW + HOUR
  }))
  const watchB = await notify.watch(signed(user, NOTIFY_DOMAINS.watch, {
    type: 'hiverelay.notify.watch.v1',
    watchId: hex(58),
    receiveCap: hex(6),
    sendCap: hex(7),
    app: hex(5),
    audience: relay.hex,
    source: { kind: 'notify-outbox-lane', key: sender.hex, lane: laneB, start: 0 },
    channel: 'message',
    policy: { minIntervalSeconds: 30 },
    createdAt: NOW,
    expiresAt: NOW + HOUR
  }))
  t.is(watchA.ok, true)
  t.is(watchB.ok, true)

  const sealed = createOutboxBlindSealedBody({
    nonce: b4a.toString(b4a.alloc(24, 1), 'base64url'),
    ciphertext: b4a.toString(b4a.alloc(48, 2), 'base64url'),
    keyId: 'epoch-1'
  })
  const first = atomicTransition(sender, {
    expected: { version: 0, root: sha256('') },
    mutations: [
      { type: 'mailbox', fields: { id: laneA + '!op-1', body: sealed, expiresAt: NOW + HOUR } },
      { type: 'lane-head', fields: { id: laneA, version: 1, updatedAt: NOW } }
    ]
  })
  outbox.commit(sender.hex, first.commit)
  await tick()
  t.is(provider.attempts.length, 1, 'the exact lane A cursor wakes its watch')

  const wake = provider.attempts[0]
  t.is(wake.payloadCiphertext, '', 'the wake is an opaque poke, not a message')
  t.is(wake.watch.watchId, hex(59), 'lane B did not fan out')
  t.absent(JSON.stringify(wake).includes(sealed.sealed.ciphertext), 'no record content reaches the push provider')
  t.absent('intent' in wake, 'watch wakes carry no intent — adapters must not require one')

  const second = atomicTransition(sender, {
    expected: { version: first.head.version, root: first.head.root },
    base: first.census,
    mutations: [
      { type: 'mailbox', fields: { id: laneB + '!op-2', body: sealed, expiresAt: NOW + HOUR } },
      { type: 'lane-head', fields: { id: laneB, version: 1, updatedAt: NOW } }
    ]
  })
  outbox.commit(sender.hex, second.commit)
  await tick()
  t.is(provider.attempts.length, 2, 'lane B independently wakes its exact watch')
  t.is(provider.attempts[1].watch.watchId, hex(58))

  const third = atomicTransition(sender, {
    expected: { version: second.head.version, root: second.head.root },
    base: second.census,
    mutations: [{ type: 'lane-head', fields: { id: laneA, version: 2, updatedAt: NOW + 1000 } }]
  })
  outbox.commit(sender.hex, third.commit)
  await tick()
  t.is(provider.attempts.length, 2, 'same-lane bumps coalesce inside minIntervalSeconds')
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

function atomicTransition (writer, opts) {
  const census = new Map(opts.base || [])
  const mutations = opts.mutations.map(mutation => {
    const data = signOutboxRecord(writer, mutation.type, mutation.fields)
    const key = mutation.type + '!' + data.id
    census.set(key, key + '\x00' + data._sig)
    return { type: mutation.type, data }
  })
  const values = [...census.values()].sort()
  const createdAt = opts.createdAt == null ? NOW : opts.createdAt
  const head = signOutboxRecord(writer, 'head', {
    id: writer.hex,
    version: opts.expected.version + 1,
    count: values.length,
    root: sha256(values.join('\x01')),
    updatedAt: createdAt
  })
  const fields = {
    appId: writer.hex,
    expectedVersion: opts.expected.version,
    expectedRoot: opts.expected.root,
    mutationSigs: mutations.map(mutation => mutation.data._sig),
    headSig: head._sig,
    createdAt
  }
  const commitId = sha256(canonicalOutboxRecord('commit-id', fields))
  return {
    head,
    census,
    commit: {
      schema: 1,
      commitId,
      expected: { ...opts.expected },
      mutations,
      head: { type: 'head', data: head },
      authorization: signOutboxRecord(writer, 'commit', { id: commitId, ...fields })
    }
  }
}

function signOutboxRecord (writer, type, fields) {
  const data = {
    ...fields,
    _k: writer.hex,
    _dk: writer.hex,
    _ns: PB_NAMESPACE,
    _alg: 'ed25519'
  }
  const message = 'pear.app.' + data._dk + ':' + data._ns + ':' + canonicalOutboxRecord(type, data)
  const signature = b4a.alloc(64)
  sodium.crypto_sign_detached(signature, b4a.from(message, 'utf8'), writer.secretKey)
  return { ...data, _sig: b4a.toString(signature, 'hex') }
}

function sha256 (value) {
  return createHash('sha256').update(String(value), 'utf8').digest('hex')
}

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
