import assert from 'node:assert'
import { mkdtemp, rm, readFile, readdir, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'brittle'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import { StorageAdmissionAuthority } from '../../packages/core/config/storage-admission-authority.js'
import {
  DEFAULT_OUTBOXLOG_NAMESPACE,
  OUTBOXLOG_OUTBOX_CORE_PREFIX,
  OUTBOXLOG_PARTITIONED_JOURNAL_INDEX_NAME,
  OutboxLogApp,
  canonicalOutboxRecord,
  createHypercoreOutboxJournal,
  createJsonlOutboxJournal,
  createOutboxBlindSealedBody,
  createPartitionedHypercoreOutboxJournal,
  createMemoryOutboxPersistence,
  createMemoryOutboxJournal,
  createOutboxNamespaceRegistry,
  createOutboxSwarmHub,
  createOutboxLog,
  isOutboxBlindRecord,
  isOutboxBlindSealedBody,
  verifyOutboxRecordSignature
} from '../../packages/services/builtin/outboxlog/index.js'
import { OUTBOXLOG_JOURNAL_VERSION } from '../../packages/services/builtin/outboxlog/outbox-log.js'

const HEX64 = /^[0-9a-f]{64}$/i
const A = 'a'.repeat(64)
const B = 'b'.repeat(64)
const C = 'c'.repeat(64)
const JOURNAL_BOUND = 32 * 1024 * 1024

const post = (id, extra = {}) => ({ id, ...extra })

function createJournalAdmission (getUsedBytes = () => 0, maxStorageBytes = 256 * 1024 * 1024) {
  return new StorageAdmissionAuthority({ storage: '/mock', maxStorageBytes }, {
    recoveryKinds: [],
    getUsedBytes,
    getActualBytes: () => 0,
    sampleFilesystem: () => ({
      ok: true,
      checkedAt: Date.now(),
      storagePath: '/mock',
      realpath: '/mock',
      device: '1',
      inode: '1',
      totalBytes: 100 * 1024 * 1024 * 1024,
      freeBytes: 80 * 1024 * 1024 * 1024
    })
  })
}

function journalStorage (storageAdmission = createJournalAdmission()) {
  return { storageAdmission, maxJournalStorageBytes: JOURNAL_BOUND }
}

// Ported from peerit-relay/test/wire-conformance.mjs. The old relay accepts
// unsigned records, so this gate runs with a permissive verifier and the strict
// HiveRelay signature delta is tested separately below.
function runWireConformance (sync, { label = 'engine' } = {}) {
  let passed = 0
  const ok = (condition, message) => { assert.ok(condition, `[${label}] ${message}`); passed++ }
  const eq = (actual, expected, message) => { assert.deepStrictEqual(actual, expected, `[${label}] ${message}`); passed++ }

  const created = sync.create(A)
  ok(created.appId === A, 'create returns the appId')
  ok(created.writerPublicKey === A, 'writer public key == appId (single-writer outbox)')
  ok(HEX64.test(created.inviteKey), 'create returns a 64-hex inviteKey')

  ok(sync.join(A, created.inviteKey).appId === A, 'join with the correct invite succeeds')
  assert.throws(() => sync.join(B, 'x'), `[${label}] join on an unknown outbox throws`); passed++

  eq(sync.append(A, { type: 'post', data: post('p1', { t: 'hello' }) }), { ok: true, key: 'post!p1' }, 'append post p1 -> post!p1')
  eq(sync.append(A, { type: 'post', data: post('p2', { t: 'world' }) }), { ok: true, key: 'post!p2' }, 'append post p2 -> post!p2')
  eq(sync.append(A, { type: 'vote', data: post('p1:voterX', { dir: 1 }) }), { ok: true, key: 'vote!p1:voterX' }, 'append vote -> vote!p1:voterX')
  eq(sync.append(A, { type: 'head', data: post(A, { version: 1, count: 3, root: 'r' }) }), { ok: true, key: 'head!' + A }, 'append head -> head!<appId>')

  eq(sync.get(A, 'post!p1'), post('p1', { t: 'hello' }), 'get returns the stored record body')
  ok(sync.get(A, 'post!nope') === null, 'get of a missing key is null')

  eq(sync.list(A, 'post!').map((row) => row.key), ['post!p1', 'post!p2'], 'list by prefix returns sorted matching keys')
  eq(sync.list(A, 'post!')[0].value, post('p1', { t: 'hello' }), 'list rows carry {key,value}')

  eq(sync.range(A, { gt: 'post!p1', limit: 10 }).map((row) => row.key), ['post!p2', 'vote!p1:voterX'], 'range gt is exclusive and ordered')
  eq(sync.range(A, { prefix: 'post!', reverse: true }).map((row) => row.key), ['post!p2', 'post!p1'], 'range reverse flips order')
  ok(sync.range(A, { limit: 0 }).length <= 1000, 'range clamps a bad limit into 1..1000')

  eq(sync.count(A, 'post!'), { count: 2 }, 'count by prefix')
  eq(sync.count(A), { count: 4 }, 'count with no prefix = all rows')

  const h = sync.heads([A, B])
  ok(h.heads[A] === 4, 'heads reports the appId version after 4 appends')
  ok(h.heads[B] === 0, 'heads reports 0 for an outbox that does not exist')

  sync.append(A, { type: 'post', data: post('p3') })
  ok(sync.heads([A]).heads[A] === 5, 'a further append bumps the version to 5')

  sync.create(B)
  sync.append(B, { type: 'head', data: post(B, { version: 1, count: 0, root: 'r' }) })
  const dir = sync.directory()
  ok(dir.heads[A] && dir.heads[A].version === 1, 'directory carries A\'s head record')
  ok(dir.heads[B] && dir.heads[B].id === B, 'directory carries B\'s head record')
  ok(dir.count === 2, 'directory count == number of heads returned')

  assert.throws(() => sync.append(A, { type: 'post', data: { t: 'no id' } }), `[${label}] append without data.id is 400`); passed++
  assert.throws(() => sync.append(A, { type: 'post', data: post('big', { blob: 'x'.repeat(70 * 1024) }) }), `[${label}] oversized record is 413`); passed++

  return passed
}

test('outboxlog: preserves Peerit relay sync wire conformance', (t) => {
  const log = createOutboxLog({ verifyAppend: () => true })
  t.is(runWireConformance(log.sync, { label: 'outboxlog' }), 26)
})

test('outboxlog: default verifier accepts same-writer opaque records', (t) => {
  const writer = keyPair(1)
  const log = createOutboxLog()
  const record = signRecord(writer, {
    id: 'p1',
    body: {
      ciphertext: 'opaque-bytes-for-private-namespace-later',
      nested: { relayMustNotCare: true }
    }
  })

  log.sync.create(writer.publicKeyHex)

  t.ok(verifyOutboxRecordSignature({ appId: writer.publicKeyHex, type: 'post', data: record }))
  t.alike(log.sync.append(writer.publicKeyHex, { type: 'post', data: record }), { ok: true, key: 'post!p1' })
  t.alike(log.sync.get(writer.publicKeyHex, 'post!p1').body, record.body)
})

test('outboxlog: default verifier rejects foreign writers and tampered bodies', (t) => {
  const writer = keyPair(1)
  const foreign = keyPair(2)
  const log = createOutboxLog()

  log.sync.create(writer.publicKeyHex)

  const foreignRecord = signRecord(foreign, { id: 'foreign' })
  const foreignErr = throws(() => log.sync.append(writer.publicKeyHex, { type: 'post', data: foreignRecord }))
  t.is(foreignErr.status, 400)
  t.is(log.sync.get(writer.publicKeyHex, 'post!foreign'), null)

  const record = signRecord(writer, { id: 'tamper', body: { ciphertext: 'before' } })
  const tampered = { ...record, body: { ciphertext: 'after' } }
  const tamperErr = throws(() => log.sync.append(writer.publicKeyHex, { type: 'post', data: tampered }))
  t.is(tamperErr.status, 400)
  t.is(log.sync.get(writer.publicKeyHex, 'post!tamper'), null)
})

test('outboxlog: namespace registry accepts non-Peerit app records and enforces caps', (t) => {
  const writer = keyPair(3)
  const secondWriter = keyPair(4)
  const foreign = keyPair(5)
  const namespaces = {
    peerit: { blind: false },
    poked: { blind: false, caps: { maxOutboxes: 1, maxEntriesPerOutbox: 1, maxValueBytes: 2048 } }
  }
  const registry = createOutboxNamespaceRegistry({ namespaces })
  const log = createOutboxLog({ namespaces })
  const record = signRecord(writer, { id: 'poke-1', body: { move: 'tap' }, _ns: 'poked' }, 'poke')

  t.alike(registry.snapshot().map(entry => entry.name), ['peerit', 'poked'])
  t.ok(verifyOutboxRecordSignature({ appId: writer.publicKeyHex, type: 'poke', data: record }, { namespaces }))
  t.absent(verifyOutboxRecordSignature({ appId: writer.publicKeyHex, type: 'poke', data: record }))

  log.sync.create(writer.publicKeyHex, { namespace: 'poked' })
  t.alike(log.sync.append(writer.publicKeyHex, { type: 'poke', data: record }), { ok: true, key: 'poke!poke-1' })
  t.alike(log.sync.get(writer.publicKeyHex, 'poke!poke-1').body, { move: 'tap' })

  const rowCap = throws(() => log.sync.append(writer.publicKeyHex, {
    type: 'poke',
    data: signRecord(writer, { id: 'poke-2', _ns: 'poked' }, 'poke')
  }))
  t.is(rowCap.status, 503)

  const outboxCap = throws(() => log.sync.create(secondWriter.publicKeyHex, { namespace: 'poked' }))
  t.is(outboxCap.status, 503)

  const unknownNamespace = throws(() => log.sync.append(foreign.publicKeyHex, {
    type: 'poke',
    data: signRecord(foreign, { id: 'unknown', _ns: 'unknown-app' }, 'poke')
  }))
  t.is(unknownNamespace.status, 400)
})

test('outboxlog: namespace caps.bytesPerDay rejects appends over the rolling byte budget', (t) => {
  const writer = keyPair(31)
  const openWriter = keyPair(32)
  const first = signRecord(writer, { id: 'b1', body: { move: 'tap' }, _ns: 'metered' }, 'poke')
  const second = signRecord(writer, { id: 'b2', body: { move: 'tap' }, _ns: 'metered' }, 'poke')
  // Budget exactly one record: "bytes" is the same measure as maxValueBytes
  // (Buffer.byteLength(JSON.stringify(record))).
  const namespaces = {
    metered: { blind: false, caps: { bytesPerDay: Buffer.byteLength(JSON.stringify(first)) } },
    open: { blind: false }
  }
  const log = createOutboxLog({ namespaces })
  log.sync.create(writer.publicKeyHex, { namespace: 'metered' })

  t.alike(log.sync.append(writer.publicKeyHex, { type: 'poke', data: first }), { ok: true, key: 'poke!b1' }, 'under-cap append accepted')

  const capErr = throws(() => log.sync.append(writer.publicKeyHex, { type: 'poke', data: second }))
  t.is(capErr.status, 503)
  t.is(capErr.message, 'namespace at daily byte capacity')
  t.is(log.sync.get(writer.publicKeyHex, 'poke!b2'), null, 'rejected append stores nothing')

  // An uncapped namespace in the same registry is unaffected.
  log.sync.create(openWriter.publicKeyHex, { namespace: 'open' })
  const open = signRecord(openWriter, { id: 'b3', body: { move: 'tap' }, _ns: 'open' }, 'poke')
  t.alike(log.sync.append(openWriter.publicKeyHex, { type: 'poke', data: open }), { ok: true, key: 'poke!b3' })
})

test('outboxlog: caps.bytesPerDay resolves as min(namespace cap, global fallback)', (t) => {
  const writer = keyPair(33)
  const record = signRecord(writer, { id: 'g1', body: { move: 'tap' }, _ns: 'roomy' }, 'poke')
  const bytes = Buffer.byteLength(JSON.stringify(record))
  // Namespace cap is generous; the engine-level maxBytesPerDay is tighter, so
  // the global fallback wins. (The namespace-tighter-than-global direction is
  // covered above: the default uncapped fallback lets the namespace cap bite.)
  const log = createOutboxLog({
    maxBytesPerDay: bytes,
    namespaces: { roomy: { blind: false, caps: { bytesPerDay: bytes * 1024 } } }
  })
  log.sync.create(writer.publicKeyHex, { namespace: 'roomy' })
  t.alike(log.sync.append(writer.publicKeyHex, { type: 'poke', data: record }), { ok: true, key: 'poke!g1' })
  const err = throws(() => log.sync.append(writer.publicKeyHex, {
    type: 'poke',
    data: signRecord(writer, { id: 'g2', body: { move: 'tap' }, _ns: 'roomy' }, 'poke')
  }))
  t.is(err.status, 503)
})

test('outboxlog: global maxBytesPerDay also meters the namespace-less legacy mode', (t) => {
  // Same always-applies behavior as the maxValueBytes fallback: with no
  // namespace registry configured the global option is the effective cap.
  const log = createOutboxLog({
    verifyAppend: () => true,
    maxBytesPerDay: Buffer.byteLength(JSON.stringify(post('p1')))
  })
  log.sync.create(A)
  t.alike(log.sync.append(A, { type: 'post', data: post('p1') }), { ok: true, key: 'post!p1' })
  const err = throws(() => log.sync.append(A, { type: 'post', data: post('p2') }))
  t.is(err.status, 503)
  t.is(err.message, 'namespace at daily byte capacity')
})

test('outboxlog: caps.bytesPerDay rolling 24h window frees capacity as charges expire', (t) => {
  const writer = keyPair(34)
  let now = 1762000000000
  const first = signRecord(writer, { id: 'w1', body: { move: 'tap' }, _ns: 'metered' }, 'poke')
  const second = signRecord(writer, { id: 'w2', body: { move: 'tap' }, _ns: 'metered' }, 'poke')
  const namespaces = { metered: { blind: false, caps: { bytesPerDay: Buffer.byteLength(JSON.stringify(first)) } } }
  const log = createOutboxLog({ namespaces, now: () => now })
  log.sync.create(writer.publicKeyHex, { namespace: 'metered' })
  t.alike(log.sync.append(writer.publicKeyHex, { type: 'poke', data: first }), { ok: true, key: 'poke!w1' })

  t.is(throws(() => log.sync.append(writer.publicKeyHex, { type: 'poke', data: second })).status, 503, 'at budget: rejected')

  now += 60 * 1000 // one minute later: still inside the rolling 24h window
  t.is(throws(() => log.sync.append(writer.publicKeyHex, { type: 'poke', data: second })).status, 503, 'inside the window: still rejected')

  now += 25 * 60 * 60 * 1000 // past the window: the first charge expired
  t.alike(log.sync.append(writer.publicKeyHex, { type: 'poke', data: second }), { ok: true, key: 'poke!w2' }, 'expired charges free the budget')
})

test('outboxlog: caps.bytesPerDay applies to blind namespaces (sealed bytes count)', (t) => {
  const writer = keyPair(35)
  const sealed = (id, nonce) => signRecord(writer, {
    id,
    _ns: 'vault',
    body: createOutboxBlindSealedBody({ nonce, ciphertext: 'opaque-box', keyId: 'room-key-1' })
  }, 'message')
  const first = sealed('s1', 'n1')
  const namespaces = { vault: { blind: true, caps: { bytesPerDay: Buffer.byteLength(JSON.stringify(first)) } } }
  const log = createOutboxLog({ namespaces })
  log.sync.create(writer.publicKeyHex, { namespace: 'vault' })
  t.alike(log.sync.append(writer.publicKeyHex, { type: 'message', data: first }), { ok: true, key: 'message!s1' }, 'blind append under cap accepted')
  const err = throws(() => log.sync.append(writer.publicKeyHex, { type: 'message', data: sealed('s2', 'n2') }))
  t.is(err.status, 503)
  t.is(log.sync.get(writer.publicKeyHex, 'message!s2'), null)
})

test('outboxlog: caps.bytesPerDay window survives journal replay and snapshot restore', (t) => {
  const writer = keyPair(36)
  let now = 1762000000000
  const rec = (id) => signRecord(writer, { id, body: { move: 'tap' }, _ns: 'metered' }, 'poke')
  const namespaces = { metered: { blind: false, caps: { bytesPerDay: Buffer.byteLength(JSON.stringify(rec('r1'))) } } }

  // Journal path: replayed appends re-charge the window from their journaled ts.
  const journal = createMemoryOutboxJournal()
  const first = createOutboxLog({ namespaces, journal, now: () => now })
  first.sync.create(writer.publicKeyHex, { namespace: 'metered' })
  t.alike(first.sync.append(writer.publicKeyHex, { type: 'poke', data: rec('r1') }), { ok: true, key: 'poke!r1' })

  const replayed = createOutboxLog({ namespaces, journal, now: () => now })
  t.is(throws(() => replayed.sync.append(writer.publicKeyHex, { type: 'poke', data: rec('r2') })).status, 503, 'journal replay rebuilds the window')
  now += 25 * 60 * 60 * 1000
  t.alike(replayed.sync.append(writer.publicKeyHex, { type: 'poke', data: rec('r2') }), { ok: true, key: 'poke!r2' }, 'replayed charges expire on the same wall clock')

  // Snapshot path: checkpoints persist the pruned charge list (byteWindows).
  now = 1762000000000
  const persistence = createMemoryOutboxPersistence()
  const snapFirst = createOutboxLog({ namespaces, persistence, now: () => now })
  snapFirst.sync.create(writer.publicKeyHex, { namespace: 'metered' })
  snapFirst.sync.append(writer.publicKeyHex, { type: 'poke', data: rec('r1') })
  snapFirst.flush()
  const restored = createOutboxLog({ namespaces, persistence, now: () => now })
  t.is(throws(() => restored.sync.append(writer.publicKeyHex, { type: 'poke', data: rec('r2') })).status, 503, 'snapshot byteWindows survive restart')
})

test('outboxlog: caps.bytesPerDay — pre-feature journal entries without ts do not re-charge (documented boundary)', (t) => {
  const writer = keyPair(37)
  const now = 1762000000000
  const rec = (id) => signRecord(writer, { id, body: { move: 'tap' }, _ns: 'metered' }, 'poke')
  const namespaces = { metered: { blind: false, caps: { bytesPerDay: Buffer.byteLength(JSON.stringify(rec('r1'))) } } }

  const journal = createMemoryOutboxJournal()
  const first = createOutboxLog({ namespaces, journal, now: () => now })
  first.sync.create(writer.publicKeyHex, { namespace: 'metered' })
  first.sync.append(writer.publicKeyHex, { type: 'poke', data: rec('r1') })
  t.ok(journal.entries().every(entry => entry.kind !== 'append' || Number.isFinite(entry.ts)), 'new journal appends carry ts')

  // Simulate a pre-upgrade journal (entries carry no ts): the window
  // under-counts by that legacy volume for up to 24h after upgrade.
  const legacy = journal.entries().map((entry) => {
    const { ts, ...rest } = entry
    return rest
  })
  const restored = createOutboxLog({ namespaces, journal: createMemoryOutboxJournal(legacy), now: () => now })
  t.alike(restored.sync.append(writer.publicKeyHex, { type: 'poke', data: rec('r2') }), { ok: true, key: 'poke!r2' }, 'legacy no-ts entries do not re-charge (explicit, never silent)')
})

test('outboxlog: blind namespace requires sealed ciphertext body and rejects unsafe plaintext fields', (t) => {
  const writer = keyPair(6)
  const log = createOutboxLog({
    namespaces: {
      privchat: { blind: true, caps: { maxOutboxes: 2, maxEntriesPerOutbox: 2 } }
    }
  })
  log.sync.create(writer.publicKeyHex, { namespace: 'privchat' })

  const sealed = signRecord(writer, {
    id: 'm1',
    _ns: 'privchat',
    body: createOutboxBlindSealedBody({ nonce: 'n1', ciphertext: 'opaque-box', keyId: 'room-key-1' })
  }, 'message')
  t.ok(isOutboxBlindSealedBody(sealed.body))
  t.ok(isOutboxBlindRecord(sealed))
  t.alike(log.sync.append(writer.publicKeyHex, { type: 'message', data: sealed }), { ok: true, key: 'message!m1' })
  t.alike(log.sync.get(writer.publicKeyHex, 'message!m1').body, {
    sealed: {
      version: 1,
      alg: 'xchacha20poly1305',
      nonce: 'n1',
      ciphertext: 'opaque-box',
      keyId: 'room-key-1'
    }
  })

  const nakedCiphertext = signRecord(writer, {
    id: 'm2',
    _ns: 'privchat',
    body: { nonce: 'n2', ciphertext: 'opaque-but-unsealed' }
  }, 'message')
  const nakedErr = throws(() => log.sync.append(writer.publicKeyHex, { type: 'message', data: nakedCiphertext }))
  t.is(nakedErr.status, 400)
  t.is(log.sync.get(writer.publicKeyHex, 'message!m2'), null)

  const badSeal = signRecord(writer, {
    id: 'm3',
    _ns: 'privchat',
    body: { sealed: { version: 0, alg: 'xchacha20poly1305', nonce: 'n3', ciphertext: 'box' } }
  }, 'message')
  t.absent(isOutboxBlindRecord(badSeal))
  const badSealErr = throws(() => log.sync.append(writer.publicKeyHex, { type: 'message', data: badSeal }))
  t.is(badSealErr.status, 400)
  t.is(log.sync.get(writer.publicKeyHex, 'message!m3'), null)

  const leaky = signRecord(writer, {
    id: 'm4',
    _ns: 'privchat',
    body: { plaintext: 'do-not-store-this' }
  }, 'message')
  const err = throws(() => log.sync.append(writer.publicKeyHex, { type: 'message', data: leaky }))
  t.is(err.status, 400)
  t.is(log.sync.get(writer.publicKeyHex, 'message!m4'), null)
})

test('outboxlog: emits append events without read-side group creation', (t) => {
  const log = createOutboxLog({ verifyAppend: () => true })
  let seen = null
  const off = log.subscribe(A, (event) => {
    seen = event
  })

  t.alike(log.sync.status(A), { appId: A, inviteKey: null, writerCount: 0, viewLength: 0 })
  log.sync.create(A)
  log.sync.append(A, { type: 'post', data: post('live') })

  t.is(seen.appId, A)
  t.is(seen.key, 'post!live')
  t.alike(seen.value, post('live'))
  off()
})

test('outboxlog: directory pages heads and exposes delta watermark', (t) => {
  const log = createOutboxLog({ verifyAppend: () => true })
  for (const [appId, version] of [[B, 2], [A, 1], [C, 3]]) {
    log.sync.create(appId)
    log.sync.append(appId, { type: 'head', data: post(appId, { version, root: 'r' + version }) })
  }

  const first = log.sync.directory({ limit: 2 })
  t.alike(Object.keys(first.heads), [A, B])
  t.is(first.count, 2)
  t.is(first.total, 3)
  t.is(first.hasMore, true)
  t.is(first.nextCursor, B)
  t.is(first.watermark, 3)

  const second = log.sync.directory({ cursor: first.nextCursor, limit: 2 })
  t.alike(Object.keys(second.heads), [C])
  t.is(second.count, 1)
  t.is(second.total, 1)
  t.is(second.hasMore, false)
  t.is(second.nextCursor, null)

  log.sync.append(B, { type: 'post', data: post('not-a-head') })
  t.is(log.sync.directory({ since: first.watermark }).count, 0)

  log.sync.append(B, { type: 'head', data: post(B, { version: 20, root: 'r20' }) })
  const delta = log.sync.directory({ since: first.watermark })
  t.alike(Object.keys(delta.heads), [B])
  t.is(delta.heads[B].version, 20)
  t.is(delta.count, 1)
  t.is(delta.total, 1)
  t.is(delta.watermark, 4)
})

test('outboxlog: directory watermark survives persistence reloads', (t) => {
  const persistence = createMemoryOutboxPersistence()
  const first = createOutboxLog({ verifyAppend: () => true, persistence })
  first.sync.create(A)
  first.sync.append(A, { type: 'head', data: post(A, { version: 1 }) })
  first.sync.create(B)
  first.sync.append(B, { type: 'head', data: post(B, { version: 2 }) })

  const before = first.sync.directory()
  t.is(before.watermark, 2)
  t.is(before.count, 2)

  const second = createOutboxLog({ verifyAppend: () => true, persistence })
  const after = second.sync.directory({ since: 1 })
  t.alike(Object.keys(after.heads), [B])
  t.is(after.heads[B].version, 2)
  t.is(after.watermark, before.watermark)
})

test('outboxlog: takedown suppresses a record from every serve path but keeps it in storage', (t) => {
  const log = createOutboxLog({ verifyAppend: () => true })
  log.sync.create(A)
  log.sync.append(A, { type: 'post', data: post('p1', { t: 'keep' }) })
  log.sync.append(A, { type: 'post', data: post('p2', { t: 'drop-me' }) })
  log.sync.append(A, { type: 'head', data: post(A, { version: 1 }) })

  // Baseline: both posts and the directory head are served.
  t.alike(log.sync.list(A, 'post!').map(r => r.key), ['post!p1', 'post!p2'])
  t.is(log.sync.count(A, 'post!').count, 2)
  t.ok(Object.keys(log.sync.directory().heads).includes(A))

  // Operator drops post!p2 by its opaque (appId, key) id. No content is read.
  const result = log.takedown(A, 'post!p2')
  t.alike(result, { appId: A, key: 'post!p2', suppressed: true })

  // Serve-time suppression across get / list / range / count / events.
  t.is(log.sync.get(A, 'post!p2'), null, 'get suppressed')
  t.alike(log.sync.list(A, 'post!').map(r => r.key), ['post!p1'], 'list suppressed')
  t.alike(log.sync.range(A, { gte: 'post!', lt: 'post!\xff' }).map(r => r.key), ['post!p1'], 'range suppressed')
  t.is(log.sync.count(A, 'post!').count, 1, 'count suppressed')
  t.absent(log.sync.events(A).events.map(e => e.key).includes('post!p2'), 'append marker suppressed')

  // p1 is untouched.
  t.alike(log.sync.get(A, 'post!p1'), post('p1', { t: 'keep' }))

  // The record STILL EXISTS in storage — takedown is serve-time only.
  t.ok(log.isSuppressed(A, 'post!p2'))
  t.is(log.snapshot().groups.find(([id]) => id === A)[1].rows.filter(([k]) => k === 'post!p2').length, 1,
    'suppressed record remains in the persisted rows')

  // takedowns() lists the opaque id + audit metadata without any content.
  const listed = log.takedowns()
  t.is(listed.count, 1)
  t.is(listed.takedowns[0].appId, A)
  t.is(listed.takedowns[0].key, 'post!p2')
  t.ok(Number.isFinite(listed.takedowns[0].ts), 'takedown carries an audit timestamp')
  t.is(listed.takedowns[0].reason, null, 'no reason supplied')
  t.absent(JSON.stringify(listed).includes('drop-me'), 'no record content in the audit surface')

  // operatorStats() is dashboard-safe: counts + namespaces, no record bodies.
  if (typeof log.operatorStats === 'function') {
    const ops = log.operatorStats()
    t.is(ops.suppressedCount, 1)
    t.ok(ops.groups >= 1)
    t.ok(Array.isArray(ops.namespaces))
    t.absent(JSON.stringify(ops).includes('drop-me'))
  }

  // restore() reverses it; the record serves again.
  t.alike(log.restore(A, 'post!p2'), { appId: A, key: 'post!p2', suppressed: false })
  t.alike(log.sync.get(A, 'post!p2'), post('p2', { t: 'drop-me' }))
  t.is(log.sync.count(A, 'post!').count, 2)
})

test('outboxlog: taking down head!<appId> hides the outbox from the directory', (t) => {
  const log = createOutboxLog({ verifyAppend: () => true })
  log.sync.create(A)
  log.sync.append(A, { type: 'head', data: post(A, { version: 1 }) })
  log.sync.create(B)
  log.sync.append(B, { type: 'head', data: post(B, { version: 1 }) })

  t.alike(Object.keys(log.sync.directory().heads).sort(), [A, B].sort())
  log.takedown(A, 'head!' + A)
  t.alike(Object.keys(log.sync.directory().heads), [B], 'A dropped from directory by opaque head id')
  // The head row itself still exists in storage.
  t.ok(log.isSuppressed(A, 'head!' + A))
})

test('outboxlog: takedown works on a blind record by opaque id without reading content', (t) => {
  // Blind namespace: the relay may not read/decode the record. Takedown must
  // still be able to drop it purely by its opaque (appId, key) id.
  const log = createOutboxLog({ verifyAppend: () => true, namespaces: { blindns: { blind: true } } })
  log.sync.create(A, { namespace: 'blindns' })
  const sealed = createOutboxBlindSealedBody({ nonce: 'n'.repeat(48), ciphertext: 'ciphertext-bytes' })
  log.sync.append(A, { type: 'post', data: { id: 'secret', _ns: 'blindns', body: sealed } })

  t.ok(isOutboxBlindRecord(log.sync.get(A, 'post!secret')), 'record is blind-sealed')
  log.takedown(A, 'post!secret')
  t.is(log.sync.get(A, 'post!secret'), null, 'blind record suppressed by opaque id')
  t.ok(log.isSuppressed(A, 'post!secret'))
})

test('outboxlog: takedown survives persistence reloads', (t) => {
  const persistence = createMemoryOutboxPersistence()
  const first = createOutboxLog({ verifyAppend: () => true, persistence })
  first.sync.create(A)
  first.sync.append(A, { type: 'post', data: post('p1') })
  first.sync.append(A, { type: 'post', data: post('p2') })
  first.takedown(A, 'post!p2')
  t.is(first.sync.get(A, 'post!p2'), null)

  const second = createOutboxLog({ verifyAppend: () => true, persistence })
  t.is(second.sync.get(A, 'post!p2'), null, 'takedown reloaded from snapshot')
  t.alike(second.sync.list(A, 'post!').map(r => r.key), ['post!p1'])
  t.ok(second.isSuppressed(A, 'post!p2'))
  // The record is still in storage post-reload.
  t.alike(second.snapshot().groups.find(([id]) => id === A)[1].rows.map(([k]) => k).sort(), ['post!p1', 'post!p2'])
})

test('outboxlog: takedown survives journal replay', (t) => {
  const journal = createMemoryOutboxJournal()
  const first = createOutboxLog({ verifyAppend: () => true, journal })
  first.sync.create(A)
  first.sync.append(A, { type: 'post', data: post('p1') })
  first.takedown(A, 'post!p1')
  first.restore(A, 'post!p1')
  first.takedown(A, 'post!p1')

  const second = createOutboxLog({ verifyAppend: () => true, journal })
  t.is(second.sync.get(A, 'post!p1'), null, 'net takedown replayed from journal')
  t.ok(second.isSuppressed(A, 'post!p1'))
})

test('outboxlog: takedown of a bad opaque id is rejected', (t) => {
  const log = createOutboxLog({ verifyAppend: () => true })
  const err = throws(() => log.takedown(A, ''))
  t.is(err.status, 400)
})

test('outboxlog: takedown audit fields (ts/reason) survive journal replay and snapshot reloads', (t) => {
  const journal = createMemoryOutboxJournal()
  const first = createOutboxLog({ verifyAppend: () => true, journal })
  first.sync.create(A)
  first.sync.append(A, { type: 'post', data: post('p1') })
  first.takedown(A, 'post!p1', 'notice-2026-071')

  const replayed = createOutboxLog({ verifyAppend: () => true, journal })
  const entry = replayed.takedowns().takedowns[0]
  t.is(entry.reason, 'notice-2026-071', 'reason replayed from journal')
  t.ok(Number.isFinite(entry.ts), 'ts replayed from journal')

  const persistence = createMemoryOutboxPersistence()
  const snap1 = createOutboxLog({ verifyAppend: () => true, persistence })
  snap1.sync.create(A)
  snap1.takedown(A, 'post!p9', 'court-order-42')
  const snap2 = createOutboxLog({ verifyAppend: () => true, persistence })
  const fromSnapshot = snap2.takedowns().takedowns[0]
  t.is(fromSnapshot.reason, 'court-order-42', 'reason reloaded from snapshot')
  t.ok(Number.isFinite(fromSnapshot.ts), 'ts reloaded from snapshot')

  // Legacy pre-audit snapshots carry 2-element [appId, key] pairs — they must
  // still load, with null audit metadata.
  const legacy = persistence.snapshot()
  legacy.suppressed = legacy.suppressed.map(([appId, key]) => [appId, key])
  persistence.saveSync(legacy)
  const legacyReader = createOutboxLog({ verifyAppend: () => true, persistence })
  t.alike(legacyReader.takedowns().takedowns[0], { appId: A, key: 'post!p9', ts: null, reason: null },
    'legacy 2-element snapshot loads with null audit fields')
})

test('outboxlog: takedown reason must be a short string; whitespace-only means none', (t) => {
  const log = createOutboxLog({ verifyAppend: () => true })
  t.is(throws(() => log.takedown(A, 'post!p1', 'x'.repeat(513))).status, 400, 'over-long reason rejected')
  t.is(throws(() => log.takedown(A, 'post!p1', 42)).status, 400, 'non-string reason rejected')
  t.is(throws(() => log.takedown(A, 'post!p1', { note: 'x' })).status, 400, 'object reason rejected')
  t.ok(log.isSuppressed(A, 'post!p1') === false, 'failed takedowns leave no suppression behind')

  t.alike(log.takedown(A, 'post!p1', '  padded  '), { appId: A, key: 'post!p1', suppressed: true })
  t.is(log.takedowns().takedowns[0].reason, 'padded', 'reason trimmed')
  log.takedown(A, 'post!p2', '   ')
  t.is(log.takedowns().takedowns.find((e) => e.key === 'post!p2').reason, null, 'whitespace-only reason stored as null')
})

test('outboxlog: jsonl journal boots past a torn final line; mid-file corruption still refuses', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'outboxlog-journal-'))
  try {
    const journalPath = join(dir, 'ops.jsonl')
    const good = [
      JSON.stringify({ version: OUTBOXLOG_JOURNAL_VERSION, seq: 1, kind: 'takedown', appId: A, key: 'post!p1', drop: true, ts: 1, reason: null }),
      JSON.stringify({ version: OUTBOXLOG_JOURNAL_VERSION, seq: 2, kind: 'takedown', appId: A, key: 'post!p2', drop: true, ts: 2, reason: null })
    ]
    // Crash mid-append: the final line is a partial write.
    await writeFile(journalPath, good.join('\n') + '\n' + '{"version":1,"seq":3,"kind":"tak', 'utf8')
    const journal = createJsonlOutboxJournal(journalPath)
    t.is(journal.loadSync().length, 2, 'good prefix returned despite torn tail')
    t.is(await readFile(journalPath, 'utf8'), good.join('\n') + '\n', 'file truncated to the good prefix')
    const names = await readdir(dir)
    t.ok(names.some((n) => n.startsWith('ops.jsonl.torn-')), 'damaged original quarantined for forensics')
    // Exclusive writer ownership: release before the engine re-opens the same
    // path (the gen-based journal holds a process-local lock).
    journal.close()

    // The engine end-to-end: a torn tail no longer bricks service startup.
    const engine = createOutboxLog({ verifyAppend: () => true, journalPath: join(dir, 'ops.jsonl') })
    t.ok(engine.isSuppressed(A, 'post!p2'), 'engine replayed the good prefix')
    engine.close()

    // Mid-file corruption (valid lines AFTER the bad one) is real damage, not a
    // crash artifact — boot must still refuse.
    await writeFile(journalPath, good[0] + '\n' + '{"version":1,"seq":2,"kind":"tak\n' + good[1] + '\n', 'utf8')
    const corrupt = createJsonlOutboxJournal(journalPath)
    try {
      assert.throws(() => corrupt.loadSync(), /corrupt journal line 2/, 'mid-file corruption still blocks boot')
    } finally {
      corrupt.close()
    }
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('outboxlog: append event replay is per-outbox bounded and watermark based', (t) => {
  const log = createOutboxLog({
    verifyAppend: () => true,
    maxAppendEventsPerOutbox: 2,
    maxAppendEventLimit: 2
  })
  log.sync.create(A)
  log.sync.create(B)
  log.sync.append(A, { type: 'post', data: post('p1') })
  log.sync.append(A, { type: 'post', data: post('p2') })
  log.sync.append(B, { type: 'post', data: post('b1') })
  log.sync.append(A, { type: 'post', data: post('p3') })

  const replay = log.sync.events(A, { since: 0, limit: 10 })
  t.alike(replay.events.map(event => event.key), ['post!p2', 'post!p3'])
  t.alike(replay.events.map(event => event.topic), ['outbox/' + A, 'outbox/' + A])
  t.alike(replay.events.map(event => event.seq), [2, 4])
  t.is(replay.count, 2)
  t.is(replay.watermark, 4)
  t.is(replay.nextSince, 4)
  t.is(replay.hasMore, false)
  t.absent('value' in replay.events[0])

  const delta = log.sync.events(A, { since: replay.events[0].seq })
  t.alike(delta.events.map(event => event.key), ['post!p3'])

  const seen = []
  const off = log.subscribe(A, { since: replay.events[0].seq }, event => seen.push(event))
  log.sync.append(A, { type: 'post', data: post('p4') })
  t.alike(seen.map(event => event.key), ['post!p3', 'post!p4'])
  t.is(seen[0].replay, true)
  t.absent('value' in seen[0])
  t.alike(seen[1].value, post('p4'))
  off()
})

test('outboxlog: append event replay survives persistence reloads', (t) => {
  const persistence = createMemoryOutboxPersistence()
  const first = createOutboxLog({ verifyAppend: () => true, persistence })
  first.sync.create(A)
  first.sync.append(A, { type: 'post', data: post('p1') })
  first.sync.append(A, { type: 'post', data: post('p2') })

  const before = first.sync.events(A)
  t.is(before.watermark, 2)
  t.alike(before.events.map(event => event.key), ['post!p1', 'post!p2'])

  const second = createOutboxLog({ verifyAppend: () => true, persistence })
  const after = second.sync.events(A, { since: 1 })
  t.alike(after.events.map(event => event.key), ['post!p2'])
  t.is(after.watermark, before.watermark)
})

test('outboxlog: operation journal replays accepted mutations into directory and event markers', (t) => {
  const journal = createMemoryOutboxJournal()
  const first = createOutboxLog({ verifyAppend: () => true, journal })
  const created = first.sync.create(A)
  first.sync.append(A, { type: 'head', data: post(A, { version: 1, root: 'ra' }) })
  first.sync.append(A, { type: 'post', data: post('p1', { body: 'opaque-a' }) })
  first.sync.append(B, { type: 'post', data: post('b1', { body: 'opaque-b' }) })

  t.alike(journal.entries().map(entry => entry.kind), ['create', 'append', 'append', 'append'])
  t.absent('value' in journal.entries()[1])

  const second = createOutboxLog({ verifyAppend: () => true, journal })
  t.alike(second.sync.status(A), {
    appId: A,
    inviteKey: created.inviteKey,
    writerCount: 1,
    viewLength: 2
  })
  t.alike(second.sync.get(A, 'post!p1'), post('p1', { body: 'opaque-a' }))
  t.alike(second.sync.get(B, 'post!b1'), post('b1', { body: 'opaque-b' }))

  const directory = second.sync.directory()
  t.alike(Object.keys(directory.heads), [A])
  t.is(directory.watermark, 1)
  t.alike(second.sync.events(A).events.map(event => event.key), ['head!' + A, 'post!p1'])
  t.alike(second.sync.events(B).events.map(event => event.key), ['post!b1'])
  t.is(second._stats().appendSeq, 3)
})

test('outboxlog: operation journal rejects non-contiguous persisted entries', (t) => {
  const journal = createMemoryOutboxJournal([
    {
      version: 1,
      seq: 2,
      kind: 'create',
      appId: A,
      inviteKey: '1'.repeat(64)
    }
  ])
  const err = throws(() => createOutboxLog({ verifyAppend: () => true, journal }))
  t.is(err.status, 500)
  t.ok(err.message.includes('corrupt outboxlog journal entry 1'))
})

test('outboxlog: JSONL operation journal restores accepted rows', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'outboxlog-journal-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const journalPath = join(dir, 'outboxlog-ops.jsonl')

  const first = createOutboxLog({ verifyAppend: () => true, journalPath })
  first.sync.create(A)
  first.sync.append(A, { type: 'post', data: post('p1', { body: 'opaque-jsonl' }) })
  first.close()

  const second = createOutboxLog({ verifyAppend: () => true, journalPath })
  t.alike(second.sync.get(A, 'post!p1'), post('p1', { body: 'opaque-jsonl' }))
  t.alike(second.sync.events(A).events.map(event => event.key), ['post!p1'])
})

test('outboxlog: Corestore operation journal mirrors and replays accepted rows', async (t) => {
  const store = createMockCorestore()
  const admission = createJournalAdmission()
  const journal = await createHypercoreOutboxJournal({ store, ...journalStorage(admission) })
  const first = createOutboxLog({ verifyAppend: () => true, journal })
  first.sync.create(A)
  first.sync.append(A, { type: 'post', data: post('p1', { body: 'opaque-core' }) })
  await journal.flush()

  t.alike(store.names, ['outboxlog/operations'])
  t.is(store.core('outboxlog/operations').length, 2)
  t.alike(store.blocks('outboxlog/operations').map(block => JSON.parse(block.toString('utf8')).kind), ['create', 'append'])

  await journal.close()
  const secondJournal = await createHypercoreOutboxJournal({ store, ...journalStorage(admission) })
  const second = createOutboxLog({ verifyAppend: () => true, journal: secondJournal })
  t.alike(second.sync.get(A, 'post!p1'), post('p1', { body: 'opaque-core' }))
  t.alike(second.sync.events(A).events.map(event => event.key), ['post!p1'])
})

test('outboxlog: Corestore operation journal rejects corrupt blocks before replay', async (t) => {
  const store = createMockCorestore()
  const core = store.get({ name: 'outboxlog/operations' })
  await core.append(Buffer.from('{not-json', 'utf8'))
  const admission = createJournalAdmission()

  await t.exception(createHypercoreOutboxJournal({ store, ...journalStorage(admission) }), /corrupt block 0/)
  core._blocks[0] = Buffer.from(JSON.stringify({ seq: 1, kind: 'create', appId: A, inviteKey: '1'.repeat(64) }))
  const retry = await createHypercoreOutboxJournal({ store, ...journalStorage(admission) })
  t.is(retry.loadSync().length, 1, 'factory failure releases only its lease, so corrected state can retry in-process')
  await retry.close()
})

test('outboxlog: partitioned Corestore journal mirrors accepted rows into per-outbox cores', async (t) => {
  const store = createMockCorestore()
  const admission = createJournalAdmission()
  const journal = await createPartitionedHypercoreOutboxJournal({ store, ...journalStorage(admission) })
  const first = createOutboxLog({ verifyAppend: () => true, journal })
  first.sync.create(A)
  first.sync.append(A, { type: 'post', data: post('p1', { body: 'opaque-core-a' }) })
  first.sync.create(B)
  first.sync.append(B, { type: 'post', data: post('b1', { body: 'opaque-core-b' }) })
  await journal.flush()

  const names = new Set(store.names)
  t.ok(names.has(OUTBOXLOG_PARTITIONED_JOURNAL_INDEX_NAME))
  t.ok(names.has(OUTBOXLOG_OUTBOX_CORE_PREFIX + A))
  t.ok(names.has(OUTBOXLOG_OUTBOX_CORE_PREFIX + B))
  t.is(store.core(OUTBOXLOG_PARTITIONED_JOURNAL_INDEX_NAME).length, 2)
  t.alike(store.blocks(OUTBOXLOG_PARTITIONED_JOURNAL_INDEX_NAME).map(parseBlockJson).map(block => block.appId), [A, B])
  t.alike(store.blocks(OUTBOXLOG_OUTBOX_CORE_PREFIX + A).map(parseBlockJson).map(block => block.kind), ['create', 'append'])
  t.alike(store.blocks(OUTBOXLOG_OUTBOX_CORE_PREFIX + B).map(parseBlockJson).map(block => block.kind), ['create', 'append'])

  const info = journal.info()
  t.is(info.mode, 'hypercore-outboxes')
  t.is(info.index.name, OUTBOXLOG_PARTITIONED_JOURNAL_INDEX_NAME)
  t.alike(info.outboxes.map(outbox => outbox.appId), [A, B])

  await journal.close()
  const secondJournal = await createPartitionedHypercoreOutboxJournal({ store, ...journalStorage(admission) })
  const second = createOutboxLog({ verifyAppend: () => true, journal: secondJournal })
  t.alike(second.sync.get(A, 'post!p1'), post('p1', { body: 'opaque-core-a' }))
  t.alike(second.sync.get(B, 'post!b1'), post('b1', { body: 'opaque-core-b' }))
  t.alike(second.sync.events(A).events.map(event => event.key), ['post!p1'])
  t.alike(second.sync.events(B).events.map(event => event.key), ['post!b1'])
})

test('outboxlog: partitioned Corestore journal exposes seed-core pickup keys', async (t) => {
  const store = createMockCorestore()
  const journal = await createPartitionedHypercoreOutboxJournal({ store, ...journalStorage() })
  const log = createOutboxLog({ verifyAppend: () => true, journal })
  log.sync.create(A)
  log.sync.append(A, { type: 'post', data: post('p1') })
  log.sync.create(B)
  log.sync.append(B, { type: 'post', data: post('b1') })

  const calls = []
  const seeded = await journal.seedCores({
    announceAuthorityOwnedCore: async (core) => {
      calls.push(core.key.toString('hex'))
      return { ok: true }
    },
    withdrawAuthorityOwnedCore: async () => true
  })
  const info = journal.info()

  t.alike(seeded.map(entry => entry.role), ['index', 'outbox', 'outbox'])
  t.alike(seeded.map(entry => entry.coreKey), [
    info.index.coreKey,
    info.outboxes[0].coreKey,
    info.outboxes[1].coreKey
  ])
  t.alike(calls, seeded.map(entry => entry.coreKey))
})

test('outboxlog: partitioned Corestore journal rejects corrupt outbox blocks before replay', async (t) => {
  const store = createMockCorestore()
  const index = store.get({ name: OUTBOXLOG_PARTITIONED_JOURNAL_INDEX_NAME })
  await index.append(Buffer.from(JSON.stringify({
    version: 1,
    kind: 'outbox',
    appId: A,
    inviteKey: '1'.repeat(64),
    firstSeq: 1,
    coreName: OUTBOXLOG_OUTBOX_CORE_PREFIX + A
  }), 'utf8'))
  await store.get({ name: OUTBOXLOG_OUTBOX_CORE_PREFIX + A }).append(Buffer.from('{not-json', 'utf8'))

  await t.exception(createPartitionedHypercoreOutboxJournal({ store, ...journalStorage() }), /corrupt outbox block 0/)
})

test('outboxlog aggregate commitment composes burst appends without per-partition multiplication', async (t) => {
  const admission = createJournalAdmission()
  const store = createMockCorestore()
  const journal = await createPartitionedHypercoreOutboxJournal({ store, ...journalStorage(admission) })
  for (let i = 0; i < 5; i++) {
    journal.appendSync({ seq: i + 1, kind: 'append', appId: String.fromCharCode(97 + i).repeat(64), inviteKey: '1'.repeat(64) })
  }
  await journal.flush()
  const records = admission.snapshot().records
  t.is(records.length, 1, 'one aggregate journal commitment covers index plus every partition')
  t.is(records[0].kind, 'outboxlog')
  t.is(records[0].boundBytes, JOURNAL_BOUND)
  t.is(journal.info().outboxes.length, 5)
  await journal.close()
})

test('outboxlog exact reconciliation ignores concurrent unrelated tree growth', async (t) => {
  let unrelatedBytes = 0
  const admission = createJournalAdmission(() => unrelatedBytes)
  const store = createMockCorestore()
  const journal = await createHypercoreOutboxJournal({ store, ...journalStorage(admission) })
  unrelatedBytes = 100 * 1024 * 1024
  journal.appendSync({ seq: 1, kind: 'append', appId: A })
  await journal.flush()
  const record = admission.get('outboxlog:outboxlog/operations')
  t.ok(record.actualBytesOverride < 1024 * 1024, 'actual is derived from the unique journal core, not whole-tree delta')
  t.is(record.boundBytes, JOURNAL_BOUND)
  await journal.close()
})

test('outboxlog blocks new appends after authority close/fatal and keeps the core unchanged', async (t) => {
  for (const mode of ['closed', 'fatal']) {
    const admission = createJournalAdmission()
    const store = createMockCorestore()
    const journal = await createHypercoreOutboxJournal({ store, ...journalStorage(admission) })
    const before = journal.core.length
    if (mode === 'closed') admission.closeMutations('test-stop')
    else admission.failClosed('test-fatal')
    t.exception(() => journal.appendSync({ seq: 1, kind: 'append', appId: A }), /storage mutation blocked/)
    t.is(journal.core.length, before, mode + ': no bytes dispatched')
    await journal.close()
  }
})

test('outboxlog timeout tracks a late successful append and retains conservative debt', async (t) => {
  const admission = createJournalAdmission()
  const core = createMockCore('late-success')
  let settle = null
  core.append = block => new Promise(resolve => {
    settle = () => {
      core._blocks.push(Buffer.from(block))
      resolve()
    }
  })
  const journal = await createHypercoreOutboxJournal({
    core,
    appendTimeoutMs: 10,
    ...journalStorage(admission)
  })
  const beforeDebt = journal.storageController.consumedBytes
  journal.appendSync({ seq: 1, kind: 'append', appId: A })
  await t.exception(journal.flush(), /append-timeout/)
  t.ok(journal.storageController.consumedBytes > beforeDebt, 'timeout never returns admitted debt')
  t.is(admission.fatalReason, 'outboxlog-append-outcome-ambiguous')
  settle()
  await admission.drainMutations({ timeoutMs: 100 })
  t.is(core.length, 1, 'late append is observed through its real settlement promise')
  t.ok(admission.get('outboxlog:outboxlog/operations').actualBytesOverride > 0)
  await journal.close()
})

test('OutboxLogApp stop drains a late-success timeout before releasing journal ownership', async (t) => {
  const admission = createJournalAdmission()
  const core = createMockCore('late-stop-success')
  core.append = block => new Promise(resolve => {
    setTimeout(() => {
      core._blocks.push(Buffer.from(block))
      resolve()
    }, 15)
  })
  const journal = await createHypercoreOutboxJournal({
    core,
    appendTimeoutMs: 10,
    ...journalStorage(admission)
  })
  const app = new OutboxLogApp({
    journal,
    persistence: false,
    verifyAppend: () => true
  })
  app.create({ appId: A })
  await t.exception(app.stop(), /append failed/)
  t.is(core.length, 1, 'real append settled before stop returned')
  t.absent(journal.storageController.ownershipHandoff, 'safe settlement permits lease release')
  t.ok(admission.get('outboxlog:outboxlog/operations').actualBytesOverride > 0)
})

test('outboxlog never-settling append causes bounded terminal drain without releasing ownership', async (t) => {
  const admission = createJournalAdmission()
  const core = createMockCore('never-settles')
  core.append = () => new Promise(() => {})
  const journal = await createHypercoreOutboxJournal({
    core,
    appendTimeoutMs: 10,
    ...journalStorage(admission)
  })
  journal.appendSync({ seq: 1, kind: 'append', appId: A })
  await t.exception(journal.flush(), /append-timeout/)
  await t.exception(journal.close(), /settlement timeout/)
  await t.exception(admission.drainMutations({ timeoutMs: 10 }), /drain timeout/)
  t.ok(journal.storageController.ownershipHandoff, 'terminal failure does not release the aggregate owner')
  t.ok(admission.get('outboxlog:outboxlog/operations'), 'aggregate debt remains installed')
})

test('outboxlog aggregate controller is exclusive and restores its monotonic ledger', async (t) => {
  const admission = createJournalAdmission()
  const core = createMockCore('exclusive-restart')
  const first = await createHypercoreOutboxJournal({ core, ...journalStorage(admission) })
  await t.exception(createHypercoreOutboxJournal({ core, ...journalStorage(admission) }), /handoff unavailable/)
  first.appendSync({ seq: 1, kind: 'append', appId: A })
  await first.flush()
  const consumed = first.storageController.consumedBytes
  await first.close()

  const second = await createHypercoreOutboxJournal({ core, ...journalStorage(admission) })
  t.ok(second.storageController.consumedBytes >= consumed, 'restart cannot reuse previously consumed budget')
  await second.close()
})

test('outboxlog process restart retains full aggregate debt after exact bytes materialize', async (t) => {
  const core = createMockCore('process-restart')
  const firstAdmission = createJournalAdmission()
  const first = await createHypercoreOutboxJournal({ core, ...journalStorage(firstAdmission) })
  first.appendSync({ seq: 1, kind: 'append', appId: A })
  await first.flush()
  await first.close()
  const storage = await core.info({ storage: true })
  const actual = Object.values(storage.storage).reduce((sum, bytes) => sum + bytes, 0)

  const tooSmall = createJournalAdmission(() => actual, JOURNAL_BOUND)
  await t.exception(createHypercoreOutboxJournal({ core, ...journalStorage(tooSmall) }), /storage admission blocked/)

  // Exact tree bytes and the full future-growth promise are separate safety
  // terms. A restart needs capacity for both; stale-high attribution is never
  // subtracted from the commitment.
  const restartedAdmission = createJournalAdmission(() => actual, JOURNAL_BOUND + actual)
  const restarted = await createHypercoreOutboxJournal({ core, ...journalStorage(restartedAdmission) })
  t.is(restartedAdmission.get('outboxlog:outboxlog/operations').actualBytesOverride, actual)
  t.is(restartedAdmission.snapshot().committedRemainderBytes, JOURNAL_BOUND)
  t.ok(restarted.storageController.consumedBytes >= actual)
  await restarted.close()
})

test('outboxlog app: wraps the engine as a ServiceProvider', async (t) => {
  const app = new OutboxLogApp({ verifyAppend: () => true })
  const manifest = app.manifest()

  t.is(manifest.name, 'outboxlog')
  t.ok(manifest.capabilities.includes('outboxlog.sync'))
  t.ok(manifest.capabilities.includes('outboxlog.namespaces'))
  t.alike(app.create({ appId: A }).appId, A)
  t.alike(app.append({ appId: A, op: { type: 'post', data: post('p1') } }), { ok: true, key: 'post!p1' })
  t.alike(app.count({ appId: A }), { count: 1 })
  t.alike(app.events({ appId: A }).events.map(event => event.key), ['post!p1'])

  await app.start({ node: { id: 'relay' } })
  t.alike(app.node, { id: 'relay' })
  await app.stop()
  t.is(app.node, null)
})

test('outboxlog app: storage-authority relay refuses legacy file/JSONL persistence', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'outboxlog-bounded-required-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const app = new OutboxLogApp({
    storagePath: dir,
    persistencePath: join(dir, 'outboxlog-state.json')
  })
  let failure = null
  try {
    await app.start({
      node: { storageAdmission: {} },
      config: {
        storage: dir,
        outboxlog: { journal: 'jsonl', journalPath: join(dir, 'outboxlog-ops.jsonl') }
      }
    })
  } catch (err) {
    failure = err
  }
  t.is(failure?.code, 'OUTBOXLOG_BOUNDED_PERSISTENCE_REQUIRED')
  t.ok(/journal="hypercore"/.test(failure?.message || ''), 'migration action is explicit')
})

test('outboxlog app: namespace config admits Poked-style apps without a relay fork', async (t) => {
  const writer = keyPair(8)
  const app = new OutboxLogApp()
  await app.start({
    config: {
      outboxlog: {
        namespace: 'peerit',
        namespaces: {
          peerit: { blind: false },
          poked: { blind: false, caps: { maxOutboxes: 4, maxEntriesPerOutbox: 4 } }
        }
      }
    },
    node: { id: 'relay-poked' }
  })

  const record = signRecord(writer, { id: 'poke-app-1', _ns: 'poked', body: { move: 'nudge' } }, 'poke')
  t.alike(app.namespaces().map(entry => entry.name), ['peerit', 'poked'])
  t.alike(app.create({ appId: writer.publicKeyHex, namespace: 'poked' }).writerPublicKey, writer.publicKeyHex)
  t.alike(app.append({ appId: writer.publicKeyHex, op: { type: 'poke', data: record } }), { ok: true, key: 'poke!poke-app-1' })
  t.alike(app.get({ appId: writer.publicKeyHex, key: 'poke!poke-app-1' }).body, { move: 'nudge' })
  await app.stop()
})

test('outboxlog app: HIVERELAY_OUTBOXLOG_NAMESPACE-style config admits a peerit append', async (t) => {
  // Mirrors what the CLI produces when HIVERELAY_OUTBOXLOG_NAMESPACE=peerit is
  // set: applyOutboxlogNamespaceEnv → config.outboxlog.namespace === 'peerit'.
  // Proves that config registers the namespace so a peerit-signed append is
  // accepted (not rejected `unknown namespace`), closing the ENV-driven
  // operator gap.
  const writer = keyPair(9)
  const app = new OutboxLogApp()
  await app.start({
    config: { outboxlog: { namespace: 'peerit' } },
    node: { id: 'relay-bern' }
  })

  t.alike(app.namespaces().map(entry => entry.name), ['peerit'], 'peerit namespace is registered')

  const record = signRecord(writer, { id: 'peerit-rec-1', _ns: 'peerit', body: { hello: 'bern' } }, 'post')
  t.alike(
    app.append({ appId: writer.publicKeyHex, op: { type: 'post', data: record } }),
    { ok: true, key: 'post!peerit-rec-1' },
    'peerit-signed append is accepted, not rejected unknown namespace'
  )
  await app.stop()
})

test('outboxlog app: an unregistered namespace is still rejected (unknown namespace)', async (t) => {
  // Guard the negative: with only the default namespace registered (no env,
  // no config), a peerit-signed record must be refused — this is the failure
  // the env wiring exists to fix.
  const writer = keyPair(10)
  const app = new OutboxLogApp()
  await app.start({ node: { id: 'relay-default' } })

  const record = signRecord(writer, { id: 'peerit-rec-2', _ns: 'peerit', body: { hello: 'x' } }, 'post')
  const err = throws(() => app.append({ appId: writer.publicKeyHex, op: { type: 'post', data: record } }))
  t.ok(/unknown namespace/i.test(err.message), 'peerit append rejected when the namespace is unregistered')
  await app.stop()
})

test('outboxlog app: hypercore journal config restores rows from context store', async (t) => {
  const store = createMockCorestore()
  const storageAdmission = createJournalAdmission()
  const first = new OutboxLogApp({ verifyAppend: () => true })
  await first.start({
    config: { outboxlog: { journal: 'hypercore', maxJournalStorageBytes: JOURNAL_BOUND } },
    store,
    node: { id: 'relay-a', storageAdmission }
  })
  first.create({ appId: A })
  first.append({ appId: A, op: { type: 'post', data: post('p1', { body: 'app-core' }) } })
  await first.stop()

  const second = new OutboxLogApp({ verifyAppend: () => true })
  await second.start({
    config: { outboxlog: { journal: 'hypercore', maxJournalStorageBytes: JOURNAL_BOUND } },
    store,
    node: { id: 'relay-b', storageAdmission }
  })
  t.alike(second.get({ appId: A, key: 'post!p1' }), post('p1', { body: 'app-core' }))
  t.alike(second.events({ appId: A }).events.map(event => event.key), ['post!p1'])
  await second.stop()
})

test('outboxlog app: partitioned hypercore journal config restores rows and exposes seed cores', async (t) => {
  const store = createMockCorestore()
  const storageAdmission = createJournalAdmission()
  const first = new OutboxLogApp({ verifyAppend: () => true })
  await first.start({
    config: { outboxlog: { journal: 'hypercore-outboxes', maxJournalStorageBytes: JOURNAL_BOUND } },
    store,
    node: { id: 'relay-a', storageAdmission }
  })
  first.create({ appId: A })
  first.append({ appId: A, op: { type: 'post', data: post('p1', { body: 'app-outbox-core' }) } })
  await first.stop()

  // Idempotent fake seeder (mirrors the real Seeder: re-seeding a pinned core
  // is a cheap no-op). `calls` records only the first pin of each distinct key.
  const calls = []
  const pinned = new Set()
  const second = new OutboxLogApp({ verifyAppend: () => true })
  await second.start({
    config: { outboxlog: { persistence: 'hypercore-outboxes', maxJournalStorageBytes: JOURNAL_BOUND, seedMaxStorageBytes: 4 * 1024 * 1024 } },
    store,
    node: {
      id: 'relay-b',
      storageAdmission,
      seeder: {
        announceAuthorityOwnedCore: async (core) => {
          const coreKey = core.key.toString('hex')
          if (pinned.has(coreKey)) return { ok: true }
          pinned.add(coreKey)
          calls.push(coreKey)
          return { ok: true }
        },
        withdrawAuthorityOwnedCore: async (coreKey) => pinned.delete(coreKey)
      }
    }
  })

  t.alike(second.get({ appId: A, key: 'post!p1' }), post('p1', { body: 'app-outbox-core' }))
  t.alike(second.events({ appId: A }).events.map(event => event.key), ['post!p1'])
  const info = second.journalInfo()
  t.is(info.index.name, OUTBOXLOG_PARTITIONED_JOURNAL_INDEX_NAME)
  t.alike(info.outboxes.map(outbox => outbox.name), [OUTBOXLOG_OUTBOX_CORE_PREFIX + A])
  // On restore both cores already exist, so start() auto-seeds them both to the
  // fleet seeder; this explicit re-seed is idempotent (no new pins).
  const seeded = await second.seedPersistenceCores()
  t.alike(seeded.map(entry => entry.coreKey), [info.index.coreKey, info.outboxes[0].coreKey])
  t.alike(calls, seeded.map(entry => entry.coreKey))
  await second.stop()
})

test('outboxlog app: default file persistence restores signed opaque rows', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'outboxlog-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))

  const writer = keyPair(7)
  const first = new OutboxLogApp()
  await first.start({ config: { storage: dir }, node: { id: 'relay-a' } })
  const created = first.create({ appId: writer.publicKeyHex })
  const record = signRecord(writer, {
    id: 'persisted',
    body: { ciphertext: 'opaque-signed-box' }
  })
  t.alike(first.append({ appId: writer.publicKeyHex, op: { type: 'post', data: record } }), { ok: true, key: 'post!persisted' })
  t.is(first.status({ appId: writer.publicKeyHex }).inviteKey, created.inviteKey)
  await first.stop()

  const second = new OutboxLogApp()
  await second.start({ config: { storage: dir }, node: { id: 'relay-b' } })
  t.alike(second.status({ appId: writer.publicKeyHex }), {
    appId: writer.publicKeyHex,
    inviteKey: created.inviteKey,
    writerCount: 1,
    viewLength: 1
  })
  t.alike(second.get({ appId: writer.publicKeyHex, key: 'post!persisted' }).body, record.body)
  t.is(second.heads({ appIds: [writer.publicKeyHex] }).heads[writer.publicKeyHex], 1)
  await second.stop()
})

function parseBlockJson (block) {
  return JSON.parse(block.toString('utf8'))
}

test('outboxlog swarm hub: destroy() stops delivery and clears channel state', (t) => {
  const hub = createOutboxSwarmHub()
  const events = []
  const a = hub.join('topic-x')
  const b = hub.join('topic-x')
  hub.subscribe(a.channelId, (event) => events.push(event))

  hub.destroy()
  t.is(hub._channelCount(), 0, 'channels cleared')
  t.is(hub.join('topic-y'), null, 'join is inert after destroy')
  t.alike(hub.send(b.channelId, a.channelId, 'hello'), { ok: false }, 'send delivers nothing after destroy')
  t.is(events.length, 0, 'no delivery after destroy')

  hub.destroy() // idempotent
  t.is(hub._channelCount(), 0)
})

test('outboxlog: snapshot checkpoints lag the journal, restore replays the tail (#144)', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'outboxlog-ckpt-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))

  const writer = keyPair(23)
  const journalFile = join(dir, 'ops.jsonl')
  let snapshotSaves = 0
  let stored = null
  const countingPersistence = {
    loadSync () { return stored },
    saveSync (state) { snapshotSaves++; stored = state }
  }

  const log = createOutboxLog({
    persistence: countingPersistence,
    journalPath: journalFile,
    checkpointInterval: 10
  })
  log.sync.create(writer.publicKeyHex)
  for (let i = 0; i < 25; i++) {
    log.sync.append(writer.publicKeyHex, { type: 'post', data: signRecord(writer, { id: 'r' + i, body: { ciphertext: 'c' + i } }) })
  }
  // 26 journaled mutations (create + 25 appends) at interval 10 -> two
  // journal-managed checkpoints. The redundant compatibility snapshot is not
  // rewritten: each full-state checkpoint is fsynced only once.
  t.is(snapshotSaves, 0, 'compacting journal avoids duplicate full-state snapshot writes')
  const manifestBeforeFlush = JSON.parse(await readFile(journalFile + '.manifest.json', 'utf8'))
  t.is(manifestBeforeFlush.active, 2, 'two generational checkpoints landed')

  // Crash without flush(): release only the writer lease (no checkpoint), then
  // a fresh instance restores checkpoint + journal tail.
  log.close()
  const restored = createOutboxLog({ persistence: countingPersistence, journalPath: journalFile })
  for (const i of [0, 9, 19, 24]) {
    t.alike(restored.sync.get(writer.publicKeyHex, 'post!r' + i).body, { ciphertext: 'c' + i }, 'row r' + i + ' survives (tail replay)')
  }

  // A new tail mutation plus flush() forces the pending journal checkpoint
  // without duplicating it through compatibility persistence.
  restored.sync.append(writer.publicKeyHex, { type: 'post', data: signRecord(writer, { id: 'r25', body: { ciphertext: 'c25' } }) })
  const before = snapshotSaves
  restored.flush()
  const manifestAfterFlush = JSON.parse(await readFile(journalFile + '.manifest.json', 'utf8'))
  t.is(manifestAfterFlush.active, 3, 'flush() writes the dirty journal checkpoint')
  t.is(snapshotSaves, before, 'flush does not duplicate the checkpoint through compatibility persistence')
})

test('outboxlog: append lands in the journal even when snapshot persistence is configured (#146)', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'outboxlog-both-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))

  const writer = keyPair(20)
  const stateFile = join(dir, 'outboxlog-state.json')
  const journalFile = join(dir, 'outboxlog-ops.jsonl')
  const log = createOutboxLog({ persistencePath: stateFile, journalPath: journalFile })
  log.sync.create(writer.publicKeyHex)
  const rec = signRecord(writer, { id: 'j1', body: { ciphertext: 'x' } })
  t.alike(log.sync.append(writer.publicKeyHex, { type: 'post', data: rec }), { ok: true, key: 'post!j1' })

  // The journal-first fix: the append-log is written even though snapshot
  // persistence is also configured (it used to be silently empty).
  const journalText = await readFile(journalFile, 'utf8')
  t.ok(journalText.includes('"kind":"append"'), 'append op landed in the journal')

  // ...and the journal alone replays into a fresh instance.
  log.close()
  const replay = createOutboxLog({ journalPath: journalFile })
  t.alike(replay.sync.get(writer.publicKeyHex, 'post!j1').body, rec.body)
})

test('outboxlog: hand-edited state rows are dropped on load (#146)', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'outboxlog-tamper-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))

  const writer = keyPair(21)
  const attacker = keyPair(22)
  const stateFile = join(dir, 'outboxlog-state.json')

  const first = createOutboxLog({ persistencePath: stateFile })
  first.sync.create(writer.publicKeyHex)
  const good = signRecord(writer, { id: 'real', body: { ciphertext: 'legit' } })
  first.sync.append(writer.publicKeyHex, { type: 'post', data: good })

  // The persisted file is not a trust root: hand-edit it to inject a tampered
  // row (body mutated -> signature no longer matches) and a foreign-writer row
  // (valid signature but _k != appId).
  const state = JSON.parse(await readFile(stateFile, 'utf8'))
  const group = state.groups.find(([appId]) => appId === writer.publicKeyHex)[1]
  group.rows.push(['post!forged', { ...good, id: 'forged', body: { ciphertext: 'tampered' } }])
  group.rows.push(['post!foreign', signRecord(attacker, { id: 'foreign', body: { ciphertext: 'evil' } })])
  await writeFile(stateFile, JSON.stringify(state))

  const second = createOutboxLog({ persistencePath: stateFile })
  t.alike(second.sync.get(writer.publicKeyHex, 'post!real').body, good.body, 'legit row survives')
  t.is(second.sync.get(writer.publicKeyHex, 'post!forged'), null, 'tampered row dropped on load')
  t.is(second.sync.get(writer.publicKeyHex, 'post!foreign'), null, 'foreign-writer row dropped on load')
})

function keyPair (seedByte) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.alloc(32, seedByte))
  return {
    publicKey,
    secretKey,
    publicKeyHex: b4a.toString(publicKey, 'hex')
  }
}

function signRecord (writer, fields = {}, type = 'post') {
  const namespace = fields._ns || DEFAULT_OUTBOXLOG_NAMESPACE
  const data = {
    id: fields.id || 'p1',
    author: writer.publicKeyHex,
    ...fields,
    _k: writer.publicKeyHex,
    _dk: fields._dk || 'd'.repeat(64),
    _ns: namespace,
    _alg: 'ed25519'
  }
  const signed = `pear.app.${data._dk}:${data._ns}:${canonicalOutboxRecord(type, data)}`
  const signature = b4a.alloc(64)
  sodium.crypto_sign_detached(signature, b4a.from(signed, 'utf8'), writer.secretKey)
  return { ...data, _sig: b4a.toString(signature, 'hex') }
}

function throws (fn) {
  try {
    fn()
  } catch (err) {
    return err
  }
  throw new Error('expected function to throw')
}

function createMockCorestore () {
  const cores = new Map()
  const names = []
  return {
    names,
    get ({ name, createIfMissing = true }) {
      if (createIfMissing === false && !cores.has(name)) return createMissingMockCore()
      names.push(name)
      if (!cores.has(name)) cores.set(name, createMockCore(name))
      return cores.get(name)
    },
    core (name) {
      return cores.get(name)
    },
    blocks (name) {
      const core = cores.get(name)
      return core ? core._blocks.slice() : []
    }
  }
}

function createMissingMockCore () {
  return {
    async ready () {
      const err = new Error('no stored core')
      err.code = 'STORAGE_EMPTY'
      throw err
    },
    async close () {}
  }
}

function createMockCore (name) {
  const blocks = []
  const userData = new Map()
  return {
    key: Buffer.from(name.padEnd(32, '0').slice(0, 32)),
    writable: true,
    _blocks: blocks,
    get length () {
      return blocks.length
    },
    get byteLength () {
      return blocks.reduce((total, block) => total + block.byteLength, 0)
    },
    async ready () {},
    async get (index) {
      return blocks[index]
    },
    async append (block) {
      blocks.push(Buffer.from(block))
    },
    async getUserData (key) {
      return userData.get(key) || null
    },
    async setUserData (key, value) {
      userData.set(key, Buffer.from(value))
    },
    async info () {
      return {
        storage: {
          oplog: 4096,
          tree: 4096,
          blocks: blocks.reduce((total, block) => total + block.byteLength, 0),
          bitfield: 4096
        }
      }
    }
  }
}
