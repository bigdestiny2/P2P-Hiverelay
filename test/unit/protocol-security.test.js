import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  MAX_SERVICE_MESSAGE_BYTES,
  ServiceProtocol,
  serviceMessageEncoding
} from 'p2p-hiverelay/core/services/protocol.js'
import {
  MAX_SERVICE_CATALOG_ENTRIES,
  MAX_SERVICE_DESCRIPTION_BYTES
} from 'p2p-hiverelay/core/services/service-catalog.js'
import { PubSub } from 'p2p-hiverelay/core/router/pubsub.js'

// ─── Test 1 & 2: Service protocol message decoding ────────────────────────
// We test the decode function directly from the ServiceProtocol encoding.
// The encoding spec: 4-byte big-endian length prefix + JSON payload.

/**
 * Encode a buffer with the 4-byte length prefix used by the service protocol.
 */
function encodeWithLengthPrefix (payload) {
  const payloadBuf = typeof payload === 'string' ? b4a.from(payload) : payload
  const buf = b4a.alloc(4 + payloadBuf.length)
  buf.writeUInt32BE(payloadBuf.length, 0)
  payloadBuf.copy(buf, 4)
  return buf
}

test('protocol-security: message > 1MB returns error type', async (t) => {
  // Create a buffer that claims to be > 1MB
  const bigPayload = b4a.alloc(MAX_SERVICE_MESSAGE_BYTES + 1, 0x41) // 1MB + 1 byte of 'A'
  const buf = encodeWithLengthPrefix(bigPayload)

  const result = serviceMessageEncoding.decode({ buffer: buf, start: 0, end: buf.length })
  t.is(result.type, -1, 'type is -1 (error)')
  t.is(result.error, 'message too large', 'error says message too large')
})

test('protocol-security: malformed JSON returns error type', async (t) => {
  const badJson = '{not valid json!!'
  const buf = encodeWithLengthPrefix(badJson)

  const result = serviceMessageEncoding.decode({ buffer: buf, start: 0, end: buf.length })
  t.is(result.type, -1, 'type is -1 (error)')
  t.is(result.error, 'malformed JSON', 'error says malformed JSON')
})

test('protocol-security: truncated service message returns error type', async (t) => {
  const buf = b4a.alloc(4)
  buf.writeUInt32BE(32, 0)

  const result = serviceMessageEncoding.decode({ buffer: buf, start: 0, end: buf.length })
  t.is(result.type, -1, 'type is -1 (error)')
  t.is(result.error, 'malformed JSON', 'error says malformed JSON')
})

test('protocol-security: short service message header returns error type (no throw)', async (t) => {
  for (const buf of [b4a.alloc(0), b4a.alloc(3, 0xff)]) {
    let result = null
    t.execution(() => {
      result = serviceMessageEncoding.decode({ buffer: buf, start: 0, end: buf.length })
    }, `does not throw for ${buf.length}-byte frame`)
    t.is(result.type, -1, 'type is -1 (error)')
    t.is(result.error, 'malformed JSON', 'error says malformed JSON')
  }
})

test('protocol-security: invalid service decode state returns error type (no throw)', async (t) => {
  const valid = encodeWithLengthPrefix('{}')
  const cases = [
    { name: 'missing state', state: null },
    { name: 'missing buffer', state: { start: 0, end: 0 } },
    { name: 'negative start', state: { buffer: valid, start: -1, end: valid.length } },
    { name: 'end before start', state: { buffer: valid, start: 4, end: 2 } },
    { name: 'end past buffer', state: { buffer: valid, start: 0, end: valid.length + 1 } },
    { name: 'unsafe start', state: { buffer: valid, start: Number.MAX_SAFE_INTEGER + 1, end: valid.length } }
  ]

  for (const { name, state } of cases) {
    let result = null
    t.execution(() => {
      result = serviceMessageEncoding.decode(state)
    }, `does not throw for ${name}`)
    t.is(result.type, -1, `${name} type is -1`)
    t.is(result.error, 'malformed JSON', `${name} error says malformed JSON`)
  }
})

// ─── Test 3: Unseed replay detection ──────────────────────────────────────
// The SeedProtocol uses _seenUnseedNonces to deduplicate unseed requests.
// We test this by calling the internal handler method.

/**
 * Helper: generate Ed25519 key pair.
 */
function keygen () {
  const pk = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const sk = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(pk, sk)
  return { pk, sk }
}

/**
 * Build a signed unseed message with binary Buffers (as the P2P protocol uses).
 */
function buildUnseedMsg (appKeyBuf, timestamp, pk, sk) {
  const tsBuf = b4a.alloc(8)
  const view = new DataView(tsBuf.buffer, tsBuf.byteOffset)
  view.setBigUint64(0, BigInt(timestamp))
  const payload = b4a.concat([appKeyBuf, b4a.from('unseed'), tsBuf])

  const sig = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(sig, payload, sk)

  return {
    appKey: appKeyBuf,
    timestamp,
    publisherPubkey: pk,
    publisherSignature: sig
  }
}

test('protocol-security: unseed replay detection drops duplicate signature', async (t) => {
  // We simulate the replay detection mechanism from SeedProtocol._handleUnseed.
  // Instead of instantiating a full SeedProtocol (which needs a Hyperswarm),
  // we replicate the exact dedup logic used in seed-request.js.
  const seenNonces = new Map()
  const received = []

  function handleUnseed (msg, peerKey) {
    // Verify signature (same logic as SeedProtocol._verifyUnseedSignature)
    if (!msg.publisherPubkey || !msg.publisherSignature) return false
    const tsBuf = b4a.alloc(8)
    const view = new DataView(tsBuf.buffer, tsBuf.byteOffset)
    view.setBigUint64(0, BigInt(msg.timestamp))
    const payload = b4a.concat([msg.appKey, b4a.from('unseed'), tsBuf])
    const valid = sodium.crypto_sign_verify_detached(msg.publisherSignature, payload, msg.publisherPubkey)
    if (!valid) return false

    // Timestamp freshness
    const age = Date.now() - msg.timestamp
    if (age > 5 * 60 * 1000 || age < -60000) return false

    // Replay protection: signature hex as dedup key
    const dedupKey = b4a.toString(msg.publisherSignature, 'hex')
    if (seenNonces.has(dedupKey)) {
      return false // replay dropped
    }
    seenNonces.set(dedupKey, Date.now())
    received.push(msg)
    return true
  }

  const { pk, sk } = keygen()
  const appKey = b4a.alloc(32, 0xee)
  const timestamp = Date.now()
  const msg = buildUnseedMsg(appKey, timestamp, pk, sk)

  // First submission succeeds
  const first = handleUnseed(msg, 'peer-a')
  t.ok(first, 'first unseed request accepted')
  t.is(received.length, 1, 'one request recorded')

  // Second submission of the same message is dropped (replay)
  const second = handleUnseed(msg, 'peer-b')
  t.is(second, false, 'duplicate unseed request dropped')
  t.is(received.length, 1, 'still only one request recorded')
})

test('protocol-security: app catalog envelope fields are preserved', async (t) => {
  const registry = {
    catalog () { return [] },
    addRemoteServices () {},
    handleRequest: async () => ({ ok: true })
  }
  const proto = new ServiceProtocol(registry)
  proto._getCatalogEnvelope = () => ({
    apps: [{ appKey: 'a'.repeat(64), version: '1.0.0' }],
    relayPubkey: 'b'.repeat(64),
    catalogTimestamp: 123456,
    signature: 'c'.repeat(128)
  })

  const msg = proto._buildCatalogMessage()
  t.is(msg.type, 7)
  t.is(msg.apps.length, 1)
  t.is(msg.relayPubkey, 'b'.repeat(64))
  t.is(msg.catalogTimestamp, 123456)
  t.is(msg.signature, 'c'.repeat(128))
})

test('protocol-security: peer service catalogs are sanitized before registry and events', async (t) => {
  let stored = null
  const registry = {
    catalog () { return [] },
    addRemoteServices (relay, services) { stored = { relay, services } },
    handleRequest: async () => ({ ok: true })
  }
  const proto = new ServiceProtocol(registry)
  let emitted = null
  proto.on('catalog-received', (event) => { emitted = event })

  await proto._onMessage('peer-a', {
    type: 0,
    services: [
      {
        name: 'storage',
        version: '1.0.0',
        description: 'x'.repeat(MAX_SERVICE_DESCRIPTION_BYTES + 1),
        capabilities: ['get', 'get', 'put'],
        secretToken: 'do-not-leak'
      },
      { name: 'bad\nname', version: '1.0.0' },
      ...Array.from({ length: MAX_SERVICE_CATALOG_ENTRIES + 5 }, (_, i) => ({
        name: 'svc-' + i,
        version: '1.0.0'
      }))
    ]
  })

  t.ok(stored)
  t.is(stored.relay, 'peer-a')
  t.is(stored.services.length, MAX_SERVICE_CATALOG_ENTRIES)
  t.is(stored.services[0].name, 'storage')
  t.alike(stored.services[0].capabilities, ['get', 'put'])
  t.is(Buffer.byteLength(stored.services[0].description, 'utf8'), MAX_SERVICE_DESCRIPTION_BYTES)
  t.alike(emitted, { remotePubkey: 'peer-a', services: stored.services })
  t.absent(JSON.stringify(stored.services).includes('secretToken'))
  t.absent(JSON.stringify(emitted.services).includes('do-not-leak'))
})

test('protocol-security: service RPC redacts unexpected provider errors on the wire', async (t) => {
  const secretPath = '/data/services/storage/private-key-material'
  const registry = {
    catalog () { return [] },
    addRemoteServices () {},
    handleRequest: async () => {
      throw new Error('storage backend failed at ' + secretPath)
    }
  }
  const proto = new ServiceProtocol(registry)
  const sent = []
  const errors = []
  proto.channels.set('peer-a', {
    msgHandler: { send: (msg) => sent.push(msg) },
    channel: { opened: true }
  })
  proto.on('request-error', (event) => errors.push(event))

  await proto._handleRequest('peer-a', {
    type: 1,
    id: 42,
    service: 'storage',
    method: 'drive-read',
    params: {}
  })

  t.alike(sent, [{ type: 3, id: 42, error: 'SERVICE_ERROR' }])
  t.absent(JSON.stringify(sent).includes(secretPath), 'wire error does not expose provider internals')
  t.is(errors.length, 1)
  t.is(errors[0].publicError, 'SERVICE_ERROR')
  t.ok(errors[0].error.includes(secretPath), 'internal event keeps diagnostic detail')
})

test('protocol-security: service RPC preserves fixed public control-plane errors', async (t) => {
  const registry = {
    catalog () { return [] },
    addRemoteServices () {},
    handleRequest: async () => {
      throw new Error('SERVICE_NOT_FOUND: missing')
    }
  }
  const proto = new ServiceProtocol(registry)
  const sent = []
  proto.channels.set('peer-a', {
    msgHandler: { send: (msg) => sent.push(msg) },
    channel: { opened: true }
  })

  await proto._handleRequest('peer-a', {
    type: 1,
    id: 7,
    service: 'missing',
    method: 'foo',
    params: {}
  })

  t.alike(sent, [{ type: 3, id: 7, error: 'SERVICE_NOT_FOUND: missing' }])
})

test('protocol-security: app catalog broadcasts use deltas after initial full sync', async (t) => {
  const registry = {
    catalog () { return [] },
    addRemoteServices () {},
    handleRequest: async () => ({ ok: true })
  }
  const sent = []
  const proto = new ServiceProtocol(registry)
  let apps = [
    { appKey: 'a'.repeat(64), version: '1.0.0' },
    { appKey: 'b'.repeat(64), version: '1.0.0' }
  ]
  proto._getCatalogEnvelope = (opts = {}) => ({
    apps: Array.isArray(opts.apps) ? opts.apps : apps,
    relayPubkey: 'f'.repeat(64),
    catalogTimestamp: 123456,
    signature: null
  })
  proto.channels.set('peer', {
    channel: {
      cork () {},
      uncork () {}
    },
    msgHandler: { send: (msg) => sent.push(msg) }
  })

  proto.sendAppCatalog('peer')
  t.is(sent[0].type, 7, 'initial sync sends full app catalog')
  t.is(sent[0].apps.length, 2)

  apps = [
    { appKey: 'a'.repeat(64), version: '1.0.0' },
    { appKey: 'b'.repeat(64), version: '1.0.0' },
    { appKey: 'c'.repeat(64), version: '1.0.0' }
  ]
  proto.broadcastAppCatalog()
  t.is(sent[1].type, 8, 'live update sends catalog delta')
  t.alike(sent[1].added.map(app => app.appKey), ['c'.repeat(64)])
  t.alike(sent[1].removed, [])
  t.alike(sent[1].apps.map(app => app.appKey), ['c'.repeat(64)], 'signed apps payload is additions only')

  apps = [
    { appKey: 'b'.repeat(64), version: '1.0.0' },
    { appKey: 'c'.repeat(64), version: '1.0.0' }
  ]
  proto.broadcastAppCatalog()
  t.is(sent[2].type, 8)
  t.alike(sent[2].added, [])
  t.alike(sent[2].removed, ['a'.repeat(64)])
})

test('protocol-security: incoming app catalog delta emits signed additions for relay sync', async (t) => {
  const registry = {
    catalog () { return [] },
    addRemoteServices () {},
    handleRequest: async () => ({ ok: true })
  }
  const proto = new ServiceProtocol(registry)
  const fullEvents = []
  const deltaEvents = []
  proto.on('app-catalog', (evt) => fullEvents.push(evt))
  proto.on('app-catalog-delta', (evt) => deltaEvents.push(evt))

  await proto._onMessage('peer', {
    type: 8,
    apps: [{ appKey: 'd'.repeat(64), version: '1.0.0' }],
    removed: ['e'.repeat(64)],
    relayPubkey: 'f'.repeat(64),
    catalogTimestamp: 123456,
    signature: 'a'.repeat(128)
  })

  t.is(deltaEvents.length, 1, 'delta event emitted')
  t.alike(deltaEvents[0].added.map(app => app.appKey), ['d'.repeat(64)])
  t.alike(deltaEvents[0].removed, ['e'.repeat(64)])
  t.is(fullEvents.length, 1, 'relay-sync event emitted for additions')
  t.alike(fullEvents[0].apps.map(app => app.appKey), ['d'.repeat(64)])
  t.alike(fullEvents[0].removed, ['e'.repeat(64)])
  t.is(fullEvents[0].delta, true)
})

test('protocol-security: restricted local methods blocked while ai infer allowed', async (t) => {
  const sent = []
  const registry = {
    catalog () { return [] },
    addRemoteServices () {},
    handleRequest: async () => ({ ok: true })
  }
  const proto = new ServiceProtocol(registry)
  proto.router = {
    dispatch: async () => ({ ok: true })
  }
  proto.channels.set('peer', {
    channel: { opened: true },
    msgHandler: { send: (msg) => sent.push(msg) }
  })

  await proto._handleRequest('peer', {
    id: 1,
    service: 'identity',
    method: 'sign',
    params: { payload: 'x' }
  })
  t.ok(sent[0].error.includes('ACCESS_DENIED'), 'identity.sign is blocked')

  await proto._handleRequest('peer', {
    id: 2,
    service: 'ai',
    method: 'infer',
    params: { prompt: 'hello' }
  })
  t.alike(sent[1].result, { ok: true }, 'ai.infer passes to router')
})

test('protocol-security: detach cleans peer state and pending requests immediately', async (t) => {
  const registry = {
    catalog () { return [] },
    addRemoteServices () {},
    handleRequest: async () => ({ ok: true })
  }
  const proto = new ServiceProtocol(registry)
  const unsubscribed = []
  proto.router = {
    pubsub: {
      unsubscribe (id) {
        unsubscribed.push(id)
      }
    }
  }

  let closed = false
  proto.channels.set('peer', {
    channel: {
      close () {
        closed = true
      }
    },
    msgHandler: { send () {} }
  })
  proto._peerSubscriptions.set('peer', [{ subId: 'sub-a', topic: 'topic/a' }])
  proto._peerRateState.set('peer', { tokens: 0, lastRefill: 1 })
  proto._peerRoles.set('peer', 'operator')
  const timer = setTimeout(() => {}, 60_000)
  let rejection = null
  proto._pendingRequests.set(1, {
    remotePubkey: 'peer',
    timer,
    reject (err) {
      rejection = err
    }
  })

  proto.detach('peer')

  t.ok(closed, 'channel close called')
  t.absent(proto.channels.has('peer'), 'channel entry removed')
  t.absent(proto._peerSubscriptions.has('peer'), 'subscriptions removed')
  t.absent(proto._peerRateState.has('peer'), 'rate limiter bucket removed')
  t.absent(proto._peerRoles.has('peer'), 'peer role removed')
  t.absent(proto._pendingRequests.has(1), 'pending request removed')
  t.alike(unsubscribed, ['sub-a'], 'subscription was unsubscribed')
  t.is(rejection && rejection.message, 'PEER_DISCONNECTED', 'pending request rejected immediately')
})

test('protocol-security: destroy clears orphan peer limiter and subscription state', async (t) => {
  const registry = {
    catalog () { return [] },
    addRemoteServices () {},
    handleRequest: async () => ({ ok: true })
  }
  const proto = new ServiceProtocol(registry)
  const unsubscribed = []
  proto.router = {
    pubsub: {
      unsubscribe (id) {
        unsubscribed.push(id)
      }
    }
  }
  proto._peerSubscriptions.set('orphan', [{ subId: 'sub-orphan', topic: 'topic/orphan' }])
  proto._peerRateState.set('orphan', { tokens: 0, lastRefill: 1 })
  proto._peerRoles.set('orphan', 'operator')

  proto.destroy()

  t.alike(unsubscribed, ['sub-orphan'], 'orphan subscription was unsubscribed')
  t.is(proto._peerSubscriptions.size, 0, 'orphan subscriptions cleared')
  t.is(proto._peerRateState.size, 0, 'orphan rate limiter state cleared')
  t.is(proto._peerRoles.size, 0, 'orphan role state cleared')
})

// ─── Glob subscription firehose guard ─────────────────────────────────────
// A remote peer that sends MSG_SUBSCRIBE with a glob topic (`poker/*` or `*`)
// would otherwise match every per-table publish (`poker/<tableKey>`) and
// re-create the cross-table firehose the per-table topic change removed.
// _handleSubscribe must reject glob topics from remote peers while exact
// topics keep working, and server-local glob subscribes (router.pubsub.subscribe)
// must be unaffected.

/**
 * Build a ServiceProtocol wired to a real PubSub so glob matching is exercised
 * for real, capturing every MSG_EVENT the protocol would send to the peer.
 */
function makeProtoWithPubSub (opts = {}) {
  const registry = {
    catalog () { return [] },
    addRemoteServices () {},
    handleRequest: async () => ({ ok: true })
  }
  const proto = new ServiceProtocol(registry)
  const pubsub = new PubSub(opts)
  proto.router = { pubsub }
  const events = []
  proto.channels.set('peer', {
    channel: { opened: true },
    msgHandler: { send: (msg) => events.push(msg) }
  })
  return { proto, pubsub, events }
}

test('protocol-security: remote glob subscribe matches nothing (no firehose)', async (t) => {
  const { proto, pubsub, events } = makeProtoWithPubSub()
  t.teardown(() => pubsub.destroy())

  // Remote peer attempts a cross-table firehose subscription.
  proto._handleSubscribe('peer', { topics: ['poker/*'] })

  // Nothing was subscribed on behalf of the peer.
  t.is(pubsub.subscriberCount(), 0, 'glob topic created no subscription')
  t.is((proto._peerSubscriptions.get('peer') || []).length, 0, 'no peer subscriptions tracked')

  // Per-table publishes reach the peer for zero topics.
  await pubsub.publish('poker/table-aaaa', { hand: 1 })
  await pubsub.publish('poker/table-bbbb', { hand: 2 })
  t.is(events.length, 0, 'peer received no events for per-table publishes')

  // A bare `*` glob is likewise rejected.
  proto._handleSubscribe('peer', { topics: ['*'] })
  await pubsub.publish('poker/table-cccc', { hand: 3 })
  t.is(events.length, 0, 'bare "*" glob also matches nothing')
  t.is(pubsub.subscriberCount(), 0, 'still no subscriptions')
})

test('protocol-security: remote exact subscribe still receives its own topic only', async (t) => {
  const { proto, pubsub, events } = makeProtoWithPubSub()
  t.teardown(() => pubsub.destroy())

  proto._handleSubscribe('peer', { topics: ['poker/table-aaaa'] })
  t.is(pubsub.subscriberCount(), 1, 'exact topic subscribed')

  await pubsub.publish('poker/table-aaaa', { hand: 1 }) // delivered
  await pubsub.publish('poker/table-bbbb', { hand: 2 }) // not delivered

  t.is(events.length, 1, 'only the subscribed exact topic is delivered')
  t.is(events[0].type, 6, 'event is MSG_EVENT')
  t.is(events[0].topic, 'poker/table-aaaa', 'event carries the subscribed topic')
})

test('protocol-security: remote subscribes are bounded and deduplicated', async (t) => {
  const { proto, pubsub } = makeProtoWithPubSub()
  t.teardown(() => pubsub.destroy())

  const firstBatch = Array.from({ length: 200 }, (_, i) => `topic/${i}`)
  proto._handleSubscribe('peer', { topics: firstBatch })

  t.is(pubsub.subscriberCount(), 64, 'single remote subscribe message is capped')
  t.is(proto._peerSubscriptions.get('peer').length, 64, 'tracked subscriptions match message cap')

  proto._handleSubscribe('peer', { topics: firstBatch })
  t.is(pubsub.subscriberCount(), 64, 'duplicate topics do not create duplicate subscriptions')

  const secondBatch = Array.from({ length: 200 }, (_, i) => `more/${i}`)
  proto._handleSubscribe('peer', { topics: secondBatch })
  t.is(pubsub.subscriberCount(), 128, 'per-peer remote subscriptions are capped')
  t.is(proto._peerSubscriptions.get('peer').length, 128, 'tracked subscriptions match peer cap')
})

test('protocol-security: remote subscribe handles pubsub caps without throwing', async (t) => {
  const { proto, pubsub } = makeProtoWithPubSub({ maxTopics: 1 })
  t.teardown(() => pubsub.destroy())

  const errors = []
  proto.on('subscription-error', (evt) => errors.push(evt))

  proto._handleSubscribe('peer', { topics: ['topic/a', 'topic/b'] })

  t.is(pubsub.subscriberCount(), 1, 'first topic subscribed before pubsub cap')
  t.is(errors.length, 1, 'pubsub cap surfaced as protocol subscription-error')
  t.is(errors[0].error, 'PUBSUB_MAX_TOPICS', 'error reason preserved')
})

test('protocol-security: server-local glob subscribe still works', async (t) => {
  // The guard lives in _handleSubscribe (the remote path); local code calling
  // router.pubsub.subscribe directly must still be able to use globs.
  const { proto, pubsub } = makeProtoWithPubSub()
  t.teardown(() => pubsub.destroy())

  const received = []
  proto.router.pubsub.subscribe('poker/*', (topic, data) => {
    received.push({ topic, data })
  })

  await pubsub.publish('poker/table-aaaa', { hand: 1 })
  await pubsub.publish('poker/table-bbbb', { hand: 2 })

  t.is(received.length, 2, 'local glob subscription matches every per-table publish')
})
