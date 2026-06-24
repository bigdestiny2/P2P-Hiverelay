/**
 * Seed-revocability tests.
 *
 * Covers the v0.8 protocol additions to seed requests:
 *
 *   - `revocable: false` flag — publisher relinquishes unseed authority
 *   - `unseedFreezeMs` cooldown — publisher commits to a delay before
 *     publisher-side unseed is honored
 *
 * Both fields are committed to the publisher signature and recorded on the
 * registry entry. AppLifecycle.verifyUnseedRequest enforces them. Operator
 * unseed via management API is unaffected — operators always retain
 * takedown authority over their own storage.
 *
 * The tests build a mock RelayNode (just enough surface for AppLifecycle to
 * function) so we can exercise verifyUnseedRequest without booting the full
 * protocol stack.
 */

import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'

import { AppLifecycle } from 'p2p-hiverelay/core/relay-node/app-lifecycle.js'
import { seedRequestEncoding } from 'p2p-hiverelay/core/protocol/messages.js'
import { SeedProtocol } from 'p2p-hiverelay/core/protocol/seed-request.js'

// ─── Helpers ────────────────────────────────────────────────────────

function keygen () {
  const pk = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const sk = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(pk, sk)
  return { pk, sk }
}

function signUnseed (appKeyHex, timestamp, sk) {
  const appKeyBuf = b4a.from(appKeyHex, 'hex')
  const tsBuf = b4a.alloc(8)
  new DataView(tsBuf.buffer, tsBuf.byteOffset).setBigUint64(0, BigInt(timestamp))
  const payload = b4a.concat([appKeyBuf, b4a.from('unseed'), tsBuf])
  const sig = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(sig, payload, sk)
  return b4a.toString(sig, 'hex')
}

function mockNode (entries = []) {
  const map = new Map(entries)
  return {
    appRegistry: {
      get: (k) => map.get(k),
      has: (k) => map.has(k),
      apps: map
    },
    seededApps: map,
    config: {}
  }
}

// ─── Wire-format encoding ───────────────────────────────────────────

test('encoding: seed request preserves revocable=false and unseedFreezeMs', (t) => {
  const msg = {
    appKey: b4a.alloc(32, 0xab),
    discoveryKeys: [b4a.alloc(32, 0xcd)],
    replicationFactor: 3,
    geoPreference: ['NA'],
    maxStorageBytes: 1024 * 1024 * 100,
    bountyRate: 0,
    ttlSeconds: 86400 * 30,
    publisherPubkey: b4a.alloc(32, 0x11),
    publisherSignature: b4a.alloc(64, 0x22),
    revocable: false,
    unseedFreezeMs: 86400_000
  }

  const state = { start: 0, end: 0, buffer: null }
  seedRequestEncoding.preencode(state, msg)
  state.buffer = b4a.alloc(state.end)
  state.start = 0
  seedRequestEncoding.encode(state, msg)
  // Decode reads from the start of the buffer; bounds = full length
  state.start = 0
  state.end = state.buffer.length

  const decoded = seedRequestEncoding.decode(state)
  t.is(decoded.revocable, false, 'revocable=false preserved through encode/decode')
  t.is(decoded.unseedFreezeMs, 86400_000, 'unseedFreezeMs preserved')
  t.is(decoded.replicationFactor, 3, 'existing fields still work')
})

test('encoding: defaults are revocable=true, freeze=0 when fields omitted', (t) => {
  const msg = {
    appKey: b4a.alloc(32, 0xab),
    discoveryKeys: [b4a.alloc(32, 0xcd)],
    replicationFactor: 1,
    geoPreference: [],
    maxStorageBytes: 1000,
    bountyRate: 0,
    ttlSeconds: 3600,
    publisherPubkey: b4a.alloc(32),
    publisherSignature: b4a.alloc(64)
    // revocable + unseedFreezeMs intentionally omitted
  }

  const state = { start: 0, end: 0, buffer: null }
  seedRequestEncoding.preencode(state, msg)
  state.buffer = b4a.alloc(state.end)
  state.start = 0
  seedRequestEncoding.encode(state, msg)
  // Decode reads from the start of the buffer; bounds = full length
  state.start = 0
  state.end = state.buffer.length

  const decoded = seedRequestEncoding.decode(state)
  t.is(decoded.revocable, true, 'default is revocable=true')
  t.is(decoded.unseedFreezeMs, 0, 'default freeze is 0')
})

// ─── Signing payload ────────────────────────────────────────────────

test('signing: revocable flag changes the signed payload', (t) => {
  const proto = new SeedProtocol(null, { keyPair: null })
  t.teardown(() => proto.destroy())
  const base = {
    appKey: b4a.alloc(32, 0x01),
    discoveryKeys: [b4a.alloc(32, 0x02)],
    replicationFactor: 3,
    maxStorageBytes: 1000,
    ttlSeconds: 3600,
    bountyRate: 0,
    revocable: true,
    unseedFreezeMs: 0
  }
  const variant = { ...base, revocable: false }

  const a = proto._serializeForSigning(base)
  const b = proto._serializeForSigning(variant)

  t.unlike(a, b, 'flipping revocable produces a different signed payload')
  t.is(a.length, b.length, 'same length')
})

test('signing: unseedFreezeMs is committed in signed bytes', (t) => {
  const proto = new SeedProtocol(null, { keyPair: null })
  t.teardown(() => proto.destroy())
  const base = {
    appKey: b4a.alloc(32, 0x01),
    discoveryKeys: [b4a.alloc(32, 0x02)],
    replicationFactor: 3,
    maxStorageBytes: 1000,
    ttlSeconds: 3600,
    bountyRate: 0,
    revocable: true,
    unseedFreezeMs: 0
  }
  const variant = { ...base, unseedFreezeMs: 86400_000 }

  const a = proto._serializeForSigning(base)
  const b = proto._serializeForSigning(variant)

  t.unlike(a, b, 'changing freeze produces a different signed payload')
})

test('signing: legacy v1 layout produces 28-byte meta block (unchanged from v0.7)', (t) => {
  const proto = new SeedProtocol(null, { keyPair: null })
  t.teardown(() => proto.destroy())
  const msg = {
    appKey: b4a.alloc(32, 0x01),
    discoveryKeys: [b4a.alloc(32, 0x02)],
    replicationFactor: 3,
    maxStorageBytes: 1000,
    ttlSeconds: 3600,
    bountyRate: 0
  }
  const v1 = proto._serializeForSigningLegacy(msg)
  const v2 = proto._serializeForSigning({ ...msg, revocable: true, unseedFreezeMs: 0 })

  // 32 (appKey) + 32 (dkHash) + 28 (meta) = 92
  t.is(v1.length, 92, 'v1 = 92 bytes total')
  // 32 + 32 + 40 = 104 — meta grew to 40 in v0.8 to commit durability tier
  t.is(v2.length, 104, 'v2 = 104 bytes total (40-byte meta block w/ durability)')
})

// ─── verifyUnseedRequest enforcement ────────────────────────────────

test('verifyUnseedRequest: revocable=true entry allows valid unseed', (t) => {
  const { pk, sk } = keygen()
  const appKey = b4a.toString(b4a.alloc(32, 0xaa), 'hex')
  const pubHex = b4a.toString(pk, 'hex')
  const ts = Date.now()
  const sig = signUnseed(appKey, ts, sk)

  const node = mockNode([[appKey, {
    publisherPubkey: pubHex,
    revocable: true,
    unseedFreezeMs: 0,
    startedAt: ts - 10_000
  }]])
  const lc = new AppLifecycle(node)

  const result = lc.verifyUnseedRequest(appKey, pubHex, sig, ts)
  t.is(result.ok, true, 'unseed accepted')
})

test('verifyUnseedRequest: revocable=false rejects even valid signatures', (t) => {
  const { pk, sk } = keygen()
  const appKey = b4a.toString(b4a.alloc(32, 0xbb), 'hex')
  const pubHex = b4a.toString(pk, 'hex')
  const ts = Date.now()
  const sig = signUnseed(appKey, ts, sk)

  const node = mockNode([[appKey, {
    publisherPubkey: pubHex,
    revocable: false, // ← non-revocable commitment
    unseedFreezeMs: 0,
    startedAt: ts - 10_000
  }]])
  const lc = new AppLifecycle(node)

  const result = lc.verifyUnseedRequest(appKey, pubHex, sig, ts)
  t.is(result.ok, false, 'unseed rejected')
  t.ok(result.error.includes('NON_REVOCABLE'), 'specific error code')
  t.ok(result.error.includes('operator'), 'message points to operator override')
})

test('verifyUnseedRequest: unseedFreezeMs blocks publisher unseed within window', (t) => {
  const { pk, sk } = keygen()
  const appKey = b4a.toString(b4a.alloc(32, 0xcc), 'hex')
  const pubHex = b4a.toString(pk, 'hex')
  const ts = Date.now()
  const sig = signUnseed(appKey, ts, sk)

  const node = mockNode([[appKey, {
    publisherPubkey: pubHex,
    revocable: true,
    unseedFreezeMs: 86400_000, // 24h freeze
    startedAt: ts - 1_000_000 // ~17 minutes ago, well inside the 24h window
  }]])
  const lc = new AppLifecycle(node)

  const result = lc.verifyUnseedRequest(appKey, pubHex, sig, ts)
  t.is(result.ok, false, 'unseed rejected within freeze window')
  t.ok(result.error.includes('UNSEED_FROZEN'), 'specific error code')
  t.ok(result.error.includes('remaining'), 'message reports remaining time')
})

test('verifyUnseedRequest: unseedFreezeMs allows publisher unseed after window', (t) => {
  const { pk, sk } = keygen()
  const appKey = b4a.toString(b4a.alloc(32, 0xdd), 'hex')
  const pubHex = b4a.toString(pk, 'hex')
  const ts = Date.now()
  const sig = signUnseed(appKey, ts, sk)

  const node = mockNode([[appKey, {
    publisherPubkey: pubHex,
    revocable: true,
    unseedFreezeMs: 1000, // 1-second freeze
    startedAt: ts - 5_000 // seeded 5s ago, freeze elapsed
  }]])
  const lc = new AppLifecycle(node)

  const result = lc.verifyUnseedRequest(appKey, pubHex, sig, ts)
  t.is(result.ok, true, 'unseed allowed after freeze')
})

test('verifyUnseedRequest: revocable=false takes precedence over freeze logic', (t) => {
  // Belt-and-suspenders — both fields set, non-revocable wins regardless
  // of whether the freeze window has elapsed.
  const { pk, sk } = keygen()
  const appKey = b4a.toString(b4a.alloc(32, 0xee), 'hex')
  const pubHex = b4a.toString(pk, 'hex')
  const ts = Date.now()
  const sig = signUnseed(appKey, ts, sk)

  const node = mockNode([[appKey, {
    publisherPubkey: pubHex,
    revocable: false,
    unseedFreezeMs: 1000,
    startedAt: ts - 1_000_000_000 // freeze long over
  }]])
  const lc = new AppLifecycle(node)

  const result = lc.verifyUnseedRequest(appKey, pubHex, sig, ts)
  t.is(result.ok, false, 'rejected')
  t.ok(result.error.includes('NON_REVOCABLE'), 'still NON_REVOCABLE — flag wins')
})

test('verifyUnseedRequest: legacy entry without revocability fields defaults to revocable', (t) => {
  // Existing entries seeded before this change have no revocable / freeze
  // fields. Treat them as the permissive default to preserve behavior.
  const { pk, sk } = keygen()
  const appKey = b4a.toString(b4a.alloc(32, 0xff), 'hex')
  const pubHex = b4a.toString(pk, 'hex')
  const ts = Date.now()
  const sig = signUnseed(appKey, ts, sk)

  const node = mockNode([[appKey, {
    publisherPubkey: pubHex,
    startedAt: ts - 10_000
    // no revocable, no unseedFreezeMs
  }]])
  const lc = new AppLifecycle(node)

  const result = lc.verifyUnseedRequest(appKey, pubHex, sig, ts)
  t.is(result.ok, true, 'legacy entry treated as revocable=true')
})
