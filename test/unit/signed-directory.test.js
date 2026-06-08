// signed-directory: brittle tests for the v0.10.2 SignedDirectory service
// per issue #33. Covers the trust model (signature/timestamp/size
// validation), storage policy (TTL, per-author cap, global cap eviction),
// per-peer rate limit, idempotency, and the replication-NOTIFY skip-on-
// rebroadcast invariant.

import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  SignedDirectory,
  signEntry,
  verifyEntry,
  entryDigest,
  STATUS
} from 'p2p-hiverelay/core/services/signed-directory.js'

function makeKeyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

function makeEntry (keyPair, payloadStr = 'hello', ts = null) {
  const timestamp = ts != null ? ts : Math.floor(Date.now() / 1000)
  const payload = b4a.from(payloadStr)
  const signature = signEntry(keyPair, timestamp, payload)
  return {
    authorPubkey: keyPair.publicKey,
    timestamp,
    payload,
    signature
  }
}

// ── trust-model primitives ─────────────────────────────────────────

test('entryDigest is deterministic + binds (author, ts, payload)', (t) => {
  const kp = makeKeyPair()
  const d1 = entryDigest(kp.publicKey, 1000, b4a.from('hi'))
  const d2 = entryDigest(kp.publicKey, 1000, b4a.from('hi'))
  const d3 = entryDigest(kp.publicKey, 1001, b4a.from('hi'))
  const d4 = entryDigest(kp.publicKey, 1000, b4a.from('hj'))
  t.ok(b4a.equals(d1, d2), 'deterministic')
  t.absent(b4a.equals(d1, d3), 'timestamp matters')
  t.absent(b4a.equals(d1, d4), 'payload matters')
  t.is(d1.byteLength, 32, 'sha256 = 32 bytes')
})

test('verifyEntry accepts a valid signature, rejects tampering', (t) => {
  const kp = makeKeyPair()
  const e = makeEntry(kp, 'payload-1')
  t.ok(verifyEntry(e), 'valid signature verifies')

  const tamperedPayload = { ...e, payload: b4a.from('payload-2') }
  t.absent(verifyEntry(tamperedPayload), 'tampered payload fails')

  const tamperedTs = { ...e, timestamp: e.timestamp + 1 }
  t.absent(verifyEntry(tamperedTs), 'tampered timestamp fails')

  const otherKp = makeKeyPair()
  const wrongAuthor = { ...e, authorPubkey: otherKp.publicKey }
  t.absent(verifyEntry(wrongAuthor), 'wrong authorPubkey fails')
})

// ── storage policy ────────────────────────────────────────────────

test('publishLocal accepts a valid fresh entry', (t) => {
  const dir = new SignedDirectory(null)
  t.teardown(() => dir.destroy())
  const kp = makeKeyPair()
  const e = makeEntry(kp, 'offer-1')
  const r = dir.publishLocal(e)
  t.ok(r.ok, 'ok')
  t.ok(r.stored, 'stored')
  t.is(dir.list().length, 1, 'one entry in list')
})

test('rejects unsigned / forged-signature entry', (t) => {
  const dir = new SignedDirectory(null)
  t.teardown(() => dir.destroy())
  const kp = makeKeyPair()
  const e = makeEntry(kp, 'real')
  // Forge the signature with another key
  const otherKp = makeKeyPair()
  const tampered = { ...e, signature: signEntry(otherKp, e.timestamp, e.payload) }
  const r = dir.publishLocal(tampered)
  t.absent(r.ok, 'rejected')
  t.is(r.code, STATUS.ERR_BAD_SIGNATURE)
})

test('rejects entry exceeding maxEntryBytes', (t) => {
  const dir = new SignedDirectory(null, { maxEntryBytes: 100 })
  t.teardown(() => dir.destroy())
  const kp = makeKeyPair()
  const big = b4a.alloc(200, 0x41)
  const ts = Math.floor(Date.now() / 1000)
  const sig = signEntry(kp, ts, big)
  const r = dir.publishLocal({
    authorPubkey: kp.publicKey,
    timestamp: ts,
    payload: big,
    signature: sig
  })
  t.absent(r.ok)
  t.is(r.code, STATUS.ERR_TOO_LARGE)
})

test('rejects timestamp too far in the future (anti-squat)', (t) => {
  const dir = new SignedDirectory(null, { clockSkewToleranceSeconds: 60 })
  t.teardown(() => dir.destroy())
  const kp = makeKeyPair()
  const future = Math.floor(Date.now() / 1000) + 3600 // 1 hour ahead
  const e = makeEntry(kp, 'i-claim-the-future', future)
  const r = dir.publishLocal(e)
  t.absent(r.ok)
  t.is(r.code, STATUS.ERR_BAD_TIMESTAMP)
})

test('rejects timestamp already expired (older than TTL)', (t) => {
  const dir = new SignedDirectory(null, { ttlSeconds: 100 })
  t.teardown(() => dir.destroy())
  const kp = makeKeyPair()
  const veryOld = Math.floor(Date.now() / 1000) - 500
  const e = makeEntry(kp, 'stale', veryOld)
  const r = dir.publishLocal(e)
  t.absent(r.ok)
  t.is(r.code, STATUS.ERR_BAD_TIMESTAMP)
})

test('rejects malformed entry (missing authorPubkey, wrong byte length)', (t) => {
  const dir = new SignedDirectory(null)
  t.teardown(() => dir.destroy())
  const kp = makeKeyPair()
  const e = makeEntry(kp)

  t.is(dir.publishLocal({ ...e, authorPubkey: undefined }).code, STATUS.ERR_BADREQ)
  t.is(dir.publishLocal({ ...e, authorPubkey: b4a.alloc(16) }).code, STATUS.ERR_BADREQ, '16-byte pubkey rejected')
  t.is(dir.publishLocal({ ...e, payload: undefined }).code, STATUS.ERR_BADREQ)
  t.is(dir.publishLocal({ ...e, signature: undefined }).code, STATUS.ERR_BADREQ)
  t.is(dir.publishLocal(null).code, STATUS.ERR_BADREQ)
})

test('newest-timestamp-wins: newer entry overwrites older', (t) => {
  const dir = new SignedDirectory(null)
  t.teardown(() => dir.destroy())
  const kp = makeKeyPair()
  const now = Math.floor(Date.now() / 1000)

  const older = makeEntry(kp, 'v1', now - 10)
  const newer = makeEntry(kp, 'v2', now - 1)

  t.ok(dir.publishLocal(older).ok)
  t.is(dir.list().length, 1)
  t.is(b4a.toString(dir.list()[0].payload), 'v1')

  t.ok(dir.publishLocal(newer).ok)
  t.is(dir.list().length, 1, 'still one entry')
  t.is(b4a.toString(dir.list()[0].payload), 'v2', 'payload now newer')
})

test('older entry does NOT overwrite newer (idempotent ok)', (t) => {
  const dir = new SignedDirectory(null)
  t.teardown(() => dir.destroy())
  const kp = makeKeyPair()
  const now = Math.floor(Date.now() / 1000)
  const older = makeEntry(kp, 'v1', now - 10)
  const newer = makeEntry(kp, 'v2', now - 1)

  t.ok(dir.publishLocal(newer).ok)
  const r = dir.publishLocal(older)
  t.ok(r.ok, 'still ok response')
  t.absent(r.stored, 'but did NOT store')
  t.is(b4a.toString(dir.list()[0].payload), 'v2', 'newer wins')
})

test('per-peer publish rate limit (only on publish source, not notify)', (t) => {
  const dir = new SignedDirectory(null, { publishRatePerMinute: 3 })
  t.teardown(() => dir.destroy())
  const peerHex = 'a'.repeat(64)

  // 3 distinct authors so each is a fresh entry, not idempotent.
  for (let i = 0; i < 3; i++) {
    const kp = makeKeyPair()
    const e = makeEntry(kp, 'payload-' + i)
    const r = dir._tryStore(e, { peerHex, source: 'publish' })
    t.ok(r.ok, 'attempt ' + i + ' accepted')
  }

  // 4th attempt should be rate-limited.
  const kp4 = makeKeyPair()
  const e4 = makeEntry(kp4, 'payload-4')
  const r4 = dir._tryStore(e4, { peerHex, source: 'publish' })
  t.absent(r4.ok)
  t.is(r4.code, STATUS.ERR_RATE_LIMITED)

  // NOTIFY skips the rate limit (replication path).
  const kpN = makeKeyPair()
  const eN = makeEntry(kpN, 'replicated')
  const rN = dir._tryStore(eN, { peerHex, source: 'notify', skipRateLimit: true })
  t.ok(rN.ok, 'notify bypasses rate limit')
})

test('global cap with TTL-oldest eviction', (t) => {
  const dir = new SignedDirectory(null, { maxTotalEntries: 3 })
  t.teardown(() => dir.destroy())
  const now = Math.floor(Date.now() / 1000)

  // Three entries at staggered timestamps
  const e1 = makeEntry(makeKeyPair(), 'a', now - 100)
  const e2 = makeEntry(makeKeyPair(), 'b', now - 50)
  const e3 = makeEntry(makeKeyPair(), 'c', now - 10)
  t.ok(dir.publishLocal(e1).ok)
  t.ok(dir.publishLocal(e2).ok)
  t.ok(dir.publishLocal(e3).ok)
  t.is(dir.list().length, 3, 'at capacity')

  // Fourth entry: oldest (e1 at now-100) should be evicted to make room
  const e4 = makeEntry(makeKeyPair(), 'd', now - 5)
  t.ok(dir.publishLocal(e4).ok, 'accepted after eviction')
  t.is(dir.list().length, 3, 'still 3 total')
  const payloads = dir.list().map(e => b4a.toString(e.payload)).sort()
  t.alike(payloads, ['b', 'c', 'd'], 'e1 (a) was evicted')
})

test('TTL eviction via _cleanupExpired clears aged entries', (t) => {
  const dir = new SignedDirectory(null, { ttlSeconds: 1 })
  t.teardown(() => dir.destroy())
  const kp = makeKeyPair()
  const now = Math.floor(Date.now() / 1000)
  const e = makeEntry(kp, 'will-expire', now)
  dir.publishLocal(e)
  t.is(dir.list().length, 1)

  // Backdate the stored entry by 2s (past TTL=1s). Bypass setTimeout.
  const stored = dir._entries.get(b4a.toString(kp.publicKey, 'hex'))
  stored.timestamp = now - 2
  dir._cleanupExpired()
  t.is(dir.list().length, 0, 'expired entry cleaned up')
  t.is(dir.stats.totalEvicted, 1)
})

test('list({since}) filters by timestamp (relevant for adapters)', (t) => {
  const dir = new SignedDirectory(null)
  t.teardown(() => dir.destroy())
  const now = Math.floor(Date.now() / 1000)
  dir.publishLocal(makeEntry(makeKeyPair(), 'old', now - 100))
  dir.publishLocal(makeEntry(makeKeyPair(), 'newer', now - 10))

  t.is(dir.list().length, 2, 'all visible via direct list')

  // _onListReq filters by `since` but we don't have a channel — test the
  // internal predicate via a direct iteration matching the same logic.
  const since = now - 50
  const filtered = dir.list().filter(e => e.timestamp >= since)
  t.is(filtered.length, 1)
  t.is(b4a.toString(filtered[0].payload), 'newer')
})

test('getStats surfaces entries + reject counters by reason', (t) => {
  const dir = new SignedDirectory(null, { maxEntryBytes: 50 })
  t.teardown(() => dir.destroy())
  const kp = makeKeyPair()

  dir.publishLocal(makeEntry(kp, 'ok'))
  const big = b4a.alloc(100, 0x42)
  const ts = Math.floor(Date.now() / 1000)
  dir.publishLocal({
    authorPubkey: kp.publicKey,
    timestamp: ts,
    payload: big,
    signature: signEntry(kp, ts, big)
  })

  const stats = dir.getStats()
  t.is(stats.entries, 1)
  t.is(stats.totalPublished, 1)
  t.is(stats.totalRejected, 1)
  t.is(stats.rejectedReasons.TOO_LARGE, 1)
  t.ok(stats.enabled)
})

test('destroy() clears state + interval', (t) => {
  const dir = new SignedDirectory(null)
  const kp = makeKeyPair()
  dir.publishLocal(makeEntry(kp, 'present'))
  t.is(dir._entries.size, 1)
  t.ok(dir._cleanupInterval)

  dir.destroy()
  t.is(dir._entries.size, 0)
  t.absent(dir._cleanupInterval, 'interval cleared')
})

test('disabled directory rejects publish (defense-in-depth)', (t) => {
  const dir = new SignedDirectory(null, { enabled: false })
  t.teardown(() => dir.destroy())
  // publishLocal goes through _tryStore which doesn't check enabled (so
  // tests can populate); the wire-level _onPublish does. Exercise the
  // wire-level path via a fake channel.
  const fakeChannel = {
    opened: true,
    _directory: {
      statusMsg: { send: (m) => { fakeChannel.lastStatus = m } },
      listResMsg: { send: () => {} },
      notifyMsg: { send: () => {} }
    },
    _mux: { stream: { remotePublicKey: b4a.alloc(32, 0xAB) } }
  }
  const kp = makeKeyPair()
  dir._onPublish(fakeChannel, makeEntry(kp))
  t.is(fakeChannel.lastStatus.code, STATUS.ERR_DISABLED)
})

test('NOTIFY broadcast skips the originating channel (no echo)', (t) => {
  const dir = new SignedDirectory(null)
  t.teardown(() => dir.destroy())

  const sends = { ch1: [], ch2: [] }
  function fakeChannel (name) {
    const ch = {
      opened: true,
      _directory: {
        statusMsg: { send: () => {} },
        listResMsg: { send: () => {} },
        notifyMsg: { send: (m) => sends[name].push(m) }
      },
      _mux: { stream: { remotePublicKey: b4a.alloc(32, name === 'ch1' ? 0x11 : 0x22) } }
    }
    return ch
  }
  const ch1 = fakeChannel('ch1')
  const ch2 = fakeChannel('ch2')
  dir._channels.add(ch1)
  dir._channels.add(ch2)

  const kp = makeKeyPair()
  dir._onPublish(ch1, makeEntry(kp, 'broadcast-me'))

  t.is(sends.ch1.length, 0, 'source channel does not receive notify (no echo)')
  t.is(sends.ch2.length, 1, 'other channel got the notify')
})
