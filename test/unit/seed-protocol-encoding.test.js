import test from 'brittle'
import b4a from 'b4a'
import c from 'compact-encoding'
import { EventEmitter } from 'events'
import {
  MAX_SEED_DENY_DETAIL_BYTES,
  MAX_SEED_DENY_REASON_BYTES,
  MAX_SEED_DISCOVERY_KEYS,
  MAX_SEED_GEO_PREFERENCE_BYTES,
  MAX_SEED_REGION_BYTES,
  seedAcceptEncoding,
  seedDenyEncoding,
  seedRequestEncoding,
  unseedRequestEncoding
} from 'p2p-hiverelay/core/protocol/messages.js'
import { SeedProtocol } from 'p2p-hiverelay/core/protocol/seed-request.js'
import { HiveRelayClient } from 'p2p-hiverelay-client'

function encodeFrame (encoding, msg) {
  const state = { start: 0, end: 0, buffer: null }
  encoding.preencode(state, msg)
  state.buffer = b4a.alloc(state.end)
  state.start = 0
  encoding.encode(state, msg)
  return state.buffer
}

function declaredSeedDiscoveryCountFrame (count) {
  const appKey = b4a.alloc(32, 0x11)
  const state = { start: 0, end: 0, buffer: null }
  c.fixed32.preencode(state, appKey)
  c.uint.preencode(state, count)
  state.buffer = b4a.alloc(state.end)
  c.fixed32.encode(state, appKey)
  c.uint.encode(state, count)
  return state.buffer
}

function declaredSeedGeoFrame (len, payload = null) {
  const appKey = b4a.alloc(32, 0x11)
  const state = { start: 0, end: 0, buffer: null }
  c.fixed32.preencode(state, appKey)
  c.uint.preencode(state, 0)
  c.uint.preencode(state, 1)
  c.uint.preencode(state, len)
  state.end += payload ? payload.byteLength : 0
  state.buffer = b4a.alloc(state.end)
  c.fixed32.encode(state, appKey)
  c.uint.encode(state, 0)
  c.uint.encode(state, 1)
  c.uint.encode(state, len)
  if (payload) payload.copy(state.buffer, state.start)
  return state.buffer
}

function declaredAcceptRegionFrame (len, payload = null) {
  const appKey = b4a.alloc(32, 0x11)
  const relayPubkey = b4a.alloc(32, 0x22)
  const state = { start: 0, end: 0, buffer: null }
  c.fixed32.preencode(state, appKey)
  c.fixed32.preencode(state, relayPubkey)
  c.uint.preencode(state, len)
  state.end += payload ? payload.byteLength : 0
  state.buffer = b4a.alloc(state.end)
  c.fixed32.encode(state, appKey)
  c.fixed32.encode(state, relayPubkey)
  c.uint.encode(state, len)
  if (payload) payload.copy(state.buffer, state.start)
  return state.buffer
}

function declaredDenyFrame ({ reasonLen, reasonPayload = null, detailLen, detailPayload = null }) {
  const appKey = b4a.alloc(32, 0x11)
  const relayPubkey = b4a.alloc(32, 0x22)
  const state = { start: 0, end: 0, buffer: null }
  c.fixed32.preencode(state, appKey)
  c.fixed32.preencode(state, relayPubkey)
  c.uint.preencode(state, reasonLen)
  state.end += reasonPayload ? reasonPayload.byteLength : 0
  c.uint.preencode(state, detailLen)
  state.end += detailPayload ? detailPayload.byteLength : 0
  state.buffer = b4a.alloc(state.end)
  c.fixed32.encode(state, appKey)
  c.fixed32.encode(state, relayPubkey)
  c.uint.encode(state, reasonLen)
  if (reasonPayload) {
    reasonPayload.copy(state.buffer, state.start)
    state.start += reasonPayload.byteLength
  }
  c.uint.encode(state, detailLen)
  if (detailPayload) {
    detailPayload.copy(state.buffer, state.start)
    state.start += detailPayload.byteLength
  }
  return state.buffer
}

function unseedTimestampOnlyFrame () {
  const appKey = b4a.alloc(32, 0x11)
  const state = { start: 0, end: 0, buffer: null }
  c.fixed32.preencode(state, appKey)
  c.uint.preencode(state, Date.now())
  state.buffer = b4a.alloc(state.end)
  c.fixed32.encode(state, appKey)
  c.uint.encode(state, Date.now())
  return state.buffer
}

function baseSeedRequest () {
  return {
    appKey: b4a.alloc(32, 0x01),
    discoveryKeys: [b4a.alloc(32, 0x02)],
    replicationFactor: 2,
    geoPreference: ['NA'],
    maxStorageBytes: 1024,
    bountyRate: 0,
    ttlSeconds: 3600,
    publisherPubkey: b4a.alloc(32, 0x03),
    publisherSignature: b4a.alloc(64, 0x04),
    revocable: false,
    unseedFreezeMs: 1000,
    durability: 1
  }
}

function baseSeedAccept () {
  return {
    appKey: b4a.alloc(32, 0x01),
    relayPubkey: b4a.alloc(32, 0x02),
    region: 'NA',
    availableStorageBytes: 2048,
    relaySignature: b4a.alloc(64, 0x03)
  }
}

function baseSeedDeny () {
  return {
    appKey: b4a.alloc(32, 0x01),
    relayPubkey: b4a.alloc(32, 0x02),
    reasonCode: 'queued-for-review',
    detail: 'pending',
    relaySignature: b4a.alloc(64, 0x03)
  }
}

function baseUnseed () {
  return {
    appKey: b4a.alloc(32, 0x01),
    timestamp: Date.now(),
    publisherPubkey: b4a.alloc(32, 0x02),
    publisherSignature: b4a.alloc(64, 0x03)
  }
}

function fakeChannel () {
  return { stream: { remotePublicKey: b4a.alloc(32, 0x55) } }
}

function fakeOpenChannel (handshake) {
  const sent = []
  return {
    handshake,
    closed: false,
    close () {
      this.closed = true
    },
    _hiverelay: {
      seedRequestMsg: {
        send: (msg) => sent.push(msg)
      }
    },
    sent
  }
}

function clearSeedProtocol (proto) {
  if (proto._pendingCleanup) clearInterval(proto._pendingCleanup)
  if (proto._unseedNonceCleanup) clearInterval(proto._unseedNonceCleanup)
  if (proto.rateLimiter && typeof proto.rateLimiter.destroy === 'function') proto.rateLimiter.destroy()
}

function mockSwarm () {
  const swarm = new EventEmitter()
  swarm.keyPair = { publicKey: Buffer.alloc(32, 0xaa), secretKey: null }
  swarm.connections = new Set()
  swarm.join = () => ({ destroy: () => {} })
  swarm.leave = async () => {}
  swarm.flush = async () => {}
  swarm.destroy = async () => {}
  return swarm
}

function mockStore () {
  return {
    close: async () => {},
    get: () => ({ key: Buffer.alloc(32), ready: async () => {} })
  }
}

test('seed protocol encodings: round-trip valid frames', (t) => {
  const seed = baseSeedRequest()
  const seedFrame = encodeFrame(seedRequestEncoding, seed)
  const seedOut = seedRequestEncoding.decode({ buffer: seedFrame, start: 0, end: seedFrame.length })
  t.alike(seedOut.appKey, seed.appKey)
  t.alike(seedOut.discoveryKeys, seed.discoveryKeys)
  t.alike(seedOut.geoPreference, seed.geoPreference)
  t.is(seedOut.revocable, false)
  t.is(seedOut.unseedFreezeMs, 1000)
  t.is(seedOut.durability, 1)

  const accept = baseSeedAccept()
  const acceptFrame = encodeFrame(seedAcceptEncoding, accept)
  t.alike(seedAcceptEncoding.decode({ buffer: acceptFrame, start: 0, end: acceptFrame.length }), accept)

  const deny = baseSeedDeny()
  const denyFrame = encodeFrame(seedDenyEncoding, deny)
  t.alike(seedDenyEncoding.decode({ buffer: denyFrame, start: 0, end: denyFrame.length }), deny)

  const unseed = baseUnseed()
  const unseedFrame = encodeFrame(unseedRequestEncoding, unseed)
  t.alike(unseedRequestEncoding.decode({ buffer: unseedFrame, start: 0, end: unseedFrame.length }), unseed)
})

test('seed protocol encodings: reject bad outbound frames before allocation growth', (t) => {
  const badAppKey = { start: 0, end: 0, buffer: null }
  t.exception(() => {
    seedRequestEncoding.preencode(badAppKey, { ...baseSeedRequest(), appKey: b4a.alloc(31) })
  }, /appKey/, 'bad appKey rejected')
  t.is(badAppKey.end, 0, 'bad appKey does not grow state.end')

  const tooManyKeys = { start: 0, end: 0, buffer: null }
  t.exception(() => {
    seedRequestEncoding.preencode(tooManyKeys, {
      ...baseSeedRequest(),
      discoveryKeys: Array.from({ length: MAX_SEED_DISCOVERY_KEYS + 1 }, () => b4a.alloc(32))
    })
  }, /too many discovery keys/, 'too many discovery keys rejected')
  t.is(tooManyKeys.end, 0, 'too many discovery keys does not grow state.end')

  const hugeGeo = { start: 0, end: 0, buffer: null }
  t.exception(() => {
    seedRequestEncoding.preencode(hugeGeo, { ...baseSeedRequest(), geoPreference: ['x'.repeat(MAX_SEED_GEO_PREFERENCE_BYTES + 1)] })
  }, /geoPreference too large/, 'huge geoPreference rejected')
  t.is(hugeGeo.end, 0, 'huge geoPreference does not grow state.end')

  const hugeRegion = { start: 0, end: 0, buffer: null }
  t.exception(() => {
    seedAcceptEncoding.preencode(hugeRegion, { ...baseSeedAccept(), region: 'x'.repeat(MAX_SEED_REGION_BYTES + 1) })
  }, /region too large/, 'huge region rejected')
  t.is(hugeRegion.end, 0, 'huge region does not grow state.end')

  const hugeDetail = { start: 0, end: 0, buffer: null }
  t.exception(() => {
    seedDenyEncoding.preencode(hugeDetail, { ...baseSeedDeny(), detail: 'x'.repeat(MAX_SEED_DENY_DETAIL_BYTES + 1) })
  }, /detail too large/, 'huge deny detail rejected')
  t.is(hugeDetail.end, 0, 'huge deny detail does not grow state.end')

  const badTimestamp = { start: 0, end: 0, buffer: null }
  t.exception(() => {
    unseedRequestEncoding.preencode(badTimestamp, { ...baseUnseed(), timestamp: -1 })
  }, /timestamp/, 'bad timestamp rejected')
  t.is(badTimestamp.end, 0, 'bad timestamp does not grow state.end')
})

test('seed protocol encodings: reject oversized declared inbound frames before materializing them', (t) => {
  const tooManyKeys = declaredSeedDiscoveryCountFrame(MAX_SEED_DISCOVERY_KEYS + 1)
  const keyOut = seedRequestEncoding.decode({ buffer: tooManyKeys, start: 0, end: tooManyKeys.length })
  t.is(keyOut.error, 'too many discovery keys')

  const hugeGeo = declaredSeedGeoFrame(MAX_SEED_GEO_PREFERENCE_BYTES + 1)
  const geoOut = seedRequestEncoding.decode({ buffer: hugeGeo, start: 0, end: hugeGeo.length })
  t.is(geoOut.error, 'geoPreference too large')

  const hugeRegion = declaredAcceptRegionFrame(MAX_SEED_REGION_BYTES + 1)
  const regionOut = seedAcceptEncoding.decode({ buffer: hugeRegion, start: 0, end: hugeRegion.length })
  t.is(regionOut.error, 'region too large')

  const hugeReason = declaredDenyFrame({ reasonLen: MAX_SEED_DENY_REASON_BYTES + 1, detailLen: 0 })
  const reasonOut = seedDenyEncoding.decode({ buffer: hugeReason, start: 0, end: hugeReason.length })
  t.is(reasonOut.error, 'reasonCode too large')

  const hugeDetail = declaredDenyFrame({
    reasonLen: 3,
    reasonPayload: b4a.from('bad'),
    detailLen: MAX_SEED_DENY_DETAIL_BYTES + 1
  })
  const detailOut = seedDenyEncoding.decode({ buffer: hugeDetail, start: 0, end: hugeDetail.length })
  t.is(detailOut.error, 'detail too large')
})

test('seed protocol encodings: reject malformed and truncated frames without throwing', (t) => {
  let seedOut = null
  t.execution(() => {
    seedOut = seedRequestEncoding.decode({ buffer: b4a.alloc(31), start: 0, end: 31 })
  }, 'truncated seed request does not throw')
  t.is(seedOut.error, 'malformed seed request')

  let invalidJson = null
  t.execution(() => {
    const payload = b4a.from('not-json')
    const frame = declaredSeedGeoFrame(payload.byteLength, payload)
    invalidJson = seedRequestEncoding.decode({ buffer: frame, start: 0, end: frame.length })
  }, 'invalid geoPreference JSON does not throw')
  t.is(invalidJson.error, 'malformed seed request')

  let acceptOut = null
  t.execution(() => {
    acceptOut = seedAcceptEncoding.decode({ buffer: b4a.alloc(63), start: 0, end: 63 })
  }, 'truncated seed accept does not throw')
  t.is(acceptOut.error, 'malformed seed accept')

  let unseedOut = null
  t.execution(() => {
    const frame = unseedTimestampOnlyFrame()
    unseedOut = unseedRequestEncoding.decode({ buffer: frame, start: 0, end: frame.length })
  }, 'truncated unseed does not throw')
  t.is(unseedOut.error, 'malformed unseed request')
})

test('seed protocol encodings: reject invalid decode state without throwing', (t) => {
  const frame = encodeFrame(seedRequestEncoding, baseSeedRequest())
  const cases = [
    { name: 'missing state', state: null },
    { name: 'missing buffer', state: { start: 0, end: 0 } },
    { name: 'negative start', state: { buffer: frame, start: -1, end: frame.length } },
    { name: 'end before start', state: { buffer: frame, start: 4, end: 2 } },
    { name: 'end past buffer', state: { buffer: frame, start: 0, end: frame.length + 1 } },
    { name: 'unsafe start', state: { buffer: frame, start: Number.MAX_SAFE_INTEGER + 1, end: frame.length } }
  ]

  for (const { name, state } of cases) {
    let result = null
    t.execution(() => {
      result = seedRequestEncoding.decode(state)
    }, `${name} does not throw`)
    t.is(result.appKey, null, `${name} appKey is null`)
    t.is(result.error, 'malformed seed request', `${name} error`)
  }
})

test('SeedProtocol handlers ignore decoded seed protocol errors without throwing', (t) => {
  const proto = new SeedProtocol(null, {})
  t.teardown(() => clearSeedProtocol(proto))
  const events = { request: [], accept: [], unseed: [], deny: [] }
  proto.on('invalid-request', (event) => events.request.push(event))
  proto.on('invalid-accept', (event) => events.accept.push(event))
  proto.on('invalid-unseed', (event) => events.unseed.push(event))
  proto.on('invalid-deny', (event) => events.deny.push(event))

  t.execution(() => proto._onSeedRequest(fakeChannel(), { error: 'too many discovery keys', appKey: null }), 'seed request error handled')
  t.execution(() => proto._onSeedAccept(fakeChannel(), { error: 'region too large', appKey: null }), 'seed accept error handled')
  t.execution(() => proto._onUnseedRequest(fakeChannel(), { error: 'malformed unseed request', appKey: null }), 'unseed error handled')
  t.execution(() => proto._onSeedDeny(fakeChannel(), { error: 'detail too large', appKey: null }), 'seed deny error handled')

  t.is(events.request[0].reason, 'too many discovery keys')
  t.is(events.accept[0].reason, 'region too large')
  t.is(events.unseed[0].reason, 'malformed unseed request')
  t.is(events.deny[0].reason, 'detail too large')
})

test('SeedProtocol handshake accepts current version before pending replay', (t) => {
  const proto = new SeedProtocol(null, {})
  t.teardown(() => clearSeedProtocol(proto))
  const request = baseSeedRequest()
  const channel = fakeOpenChannel(b4a.from(JSON.stringify({ major: 1, minor: 0 })))
  let opened = false

  proto.pendingRequests.set('aa'.repeat(32), request)
  proto.on('channel-open', () => { opened = true })

  proto._onOpen(channel)

  t.is(opened, true)
  t.is(channel.closed, false)
  t.is(channel.sent.length, 1)
  t.alike(channel.sent[0], request)
})

test('SeedProtocol handshake rejects malformed and oversized frames before pending replay', (t) => {
  const proto = new SeedProtocol(null, {})
  t.teardown(() => clearSeedProtocol(proto))
  const malformed = fakeOpenChannel(b4a.from('[]'))
  const oversized = fakeOpenChannel(b4a.alloc(257, 0x20))
  const invalid = []

  proto.pendingRequests.set('aa'.repeat(32), baseSeedRequest())
  proto.on('invalid-handshake', event => invalid.push(event.reason))

  proto._onOpen(malformed)
  proto._onOpen(oversized)

  t.alike(invalid, ['malformed handshake', 'handshake too large'])
  t.is(malformed.closed, true)
  t.is(oversized.closed, true)
  t.is(malformed.sent.length, 0)
  t.is(oversized.sent.length, 0)
})

test('SeedProtocol handshake rejects mismatched major versions before pending replay', (t) => {
  const proto = new SeedProtocol(null, {})
  t.teardown(() => clearSeedProtocol(proto))
  const channel = fakeOpenChannel(b4a.from(JSON.stringify({ major: 2, minor: 0 })))
  let mismatch = null

  proto.pendingRequests.set('aa'.repeat(32), baseSeedRequest())
  proto.on('version-mismatch', event => { mismatch = event })

  proto._onOpen(channel)

  t.is(channel.closed, true)
  t.is(channel.sent.length, 0)
  t.alike(mismatch.remote, { major: 2, minor: 0 })
})

test('HiveRelayClient seed handlers ignore decoded seed protocol errors without throwing', (t) => {
  const client = new HiveRelayClient({ swarm: mockSwarm(), store: mockStore() })
  const events = { accept: [], deny: [] }
  client.on('invalid-accept', (event) => events.accept.push(event))
  client.on('invalid-deny', (event) => events.deny.push(event))

  t.execution(() => client._onSeedAccept('aa'.repeat(32), { error: 'malformed seed accept', appKey: null }), 'client seed accept error handled')
  t.execution(() => client._onSeedDeny('aa'.repeat(32), { error: 'malformed seed deny', appKey: null }), 'client seed deny error handled')

  t.is(events.accept[0].reason, 'malformed seed accept')
  t.is(events.deny[0].reason, 'malformed seed deny')
})
