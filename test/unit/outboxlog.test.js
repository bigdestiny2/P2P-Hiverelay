import assert from 'node:assert'
import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'brittle'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import {
  DEFAULT_OUTBOXLOG_NAMESPACE,
  OUTBOXLOG_OUTBOX_CORE_PREFIX,
  OUTBOXLOG_PARTITIONED_JOURNAL_INDEX_NAME,
  OutboxLogApp,
  canonicalOutboxRecord,
  createHypercoreOutboxJournal,
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

const HEX64 = /^[0-9a-f]{64}$/i
const A = 'a'.repeat(64)
const B = 'b'.repeat(64)
const C = 'c'.repeat(64)

const post = (id, extra = {}) => ({ id, ...extra })

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

  // takedowns() lists the opaque id without any content.
  t.alike(log.takedowns(), { takedowns: [{ appId: A, key: 'post!p2' }], count: 1 })

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

  const second = createOutboxLog({ verifyAppend: () => true, journalPath })
  t.alike(second.sync.get(A, 'post!p1'), post('p1', { body: 'opaque-jsonl' }))
  t.alike(second.sync.events(A).events.map(event => event.key), ['post!p1'])
})

test('outboxlog: Corestore operation journal mirrors and replays accepted rows', async (t) => {
  const store = createMockCorestore()
  const journal = await createHypercoreOutboxJournal({ store })
  const first = createOutboxLog({ verifyAppend: () => true, journal })
  first.sync.create(A)
  first.sync.append(A, { type: 'post', data: post('p1', { body: 'opaque-core' }) })
  await journal.flush()

  t.alike(store.names, ['outboxlog/operations'])
  t.is(store.core('outboxlog/operations').length, 2)
  t.alike(store.blocks('outboxlog/operations').map(block => JSON.parse(block.toString('utf8')).kind), ['create', 'append'])

  const secondJournal = await createHypercoreOutboxJournal({ store })
  const second = createOutboxLog({ verifyAppend: () => true, journal: secondJournal })
  t.alike(second.sync.get(A, 'post!p1'), post('p1', { body: 'opaque-core' }))
  t.alike(second.sync.events(A).events.map(event => event.key), ['post!p1'])
})

test('outboxlog: Corestore operation journal rejects corrupt blocks before replay', async (t) => {
  const store = createMockCorestore()
  const core = store.get({ name: 'outboxlog/operations' })
  await core.append(Buffer.from('{not-json', 'utf8'))

  await t.exception(createHypercoreOutboxJournal({ store }), /corrupt block 0/)
})

test('outboxlog: partitioned Corestore journal mirrors accepted rows into per-outbox cores', async (t) => {
  const store = createMockCorestore()
  const journal = await createPartitionedHypercoreOutboxJournal({ store })
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

  const secondJournal = await createPartitionedHypercoreOutboxJournal({ store })
  const second = createOutboxLog({ verifyAppend: () => true, journal: secondJournal })
  t.alike(second.sync.get(A, 'post!p1'), post('p1', { body: 'opaque-core-a' }))
  t.alike(second.sync.get(B, 'post!b1'), post('b1', { body: 'opaque-core-b' }))
  t.alike(second.sync.events(A).events.map(event => event.key), ['post!p1'])
  t.alike(second.sync.events(B).events.map(event => event.key), ['post!b1'])
})

test('outboxlog: partitioned Corestore journal exposes seed-core pickup keys', async (t) => {
  const store = createMockCorestore()
  const journal = await createPartitionedHypercoreOutboxJournal({ store })
  const log = createOutboxLog({ verifyAppend: () => true, journal })
  log.sync.create(A)
  log.sync.append(A, { type: 'post', data: post('p1') })
  log.sync.create(B)
  log.sync.append(B, { type: 'post', data: post('b1') })

  const calls = []
  const seeded = await journal.seedCores({
    seedCore: async (coreKey) => {
      calls.push(coreKey)
      return { ok: true }
    }
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

  await t.exception(createPartitionedHypercoreOutboxJournal({ store }), /corrupt outbox block 0/)
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

test('outboxlog app: hypercore journal config restores rows from context store', async (t) => {
  const store = createMockCorestore()
  const first = new OutboxLogApp({ verifyAppend: () => true })
  await first.start({ config: { outboxlog: { journal: 'hypercore' } }, store, node: { id: 'relay-a' } })
  first.create({ appId: A })
  first.append({ appId: A, op: { type: 'post', data: post('p1', { body: 'app-core' }) } })
  await first.stop()

  const second = new OutboxLogApp({ verifyAppend: () => true })
  await second.start({ config: { outboxlog: { journal: 'hypercore' } }, store, node: { id: 'relay-b' } })
  t.alike(second.get({ appId: A, key: 'post!p1' }), post('p1', { body: 'app-core' }))
  t.alike(second.events({ appId: A }).events.map(event => event.key), ['post!p1'])
  await second.stop()
})

test('outboxlog app: partitioned hypercore journal config restores rows and exposes seed cores', async (t) => {
  const store = createMockCorestore()
  const first = new OutboxLogApp({ verifyAppend: () => true })
  await first.start({ config: { outboxlog: { journal: 'hypercore-outboxes' } }, store, node: { id: 'relay-a' } })
  first.create({ appId: A })
  first.append({ appId: A, op: { type: 'post', data: post('p1', { body: 'app-outbox-core' }) } })
  await first.stop()

  const calls = []
  const second = new OutboxLogApp({ verifyAppend: () => true })
  await second.start({
    config: { outboxlog: { persistence: 'hypercore-outboxes' } },
    store,
    node: {
      id: 'relay-b',
      seeder: {
        seedCore: async (coreKey) => {
          calls.push(coreKey)
          return { ok: true }
        }
      }
    }
  })

  t.alike(second.get({ appId: A, key: 'post!p1' }), post('p1', { body: 'app-outbox-core' }))
  t.alike(second.events({ appId: A }).events.map(event => event.key), ['post!p1'])
  const info = second.journalInfo()
  t.is(info.index.name, OUTBOXLOG_PARTITIONED_JOURNAL_INDEX_NAME)
  t.alike(info.outboxes.map(outbox => outbox.name), [OUTBOXLOG_OUTBOX_CORE_PREFIX + A])
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
  // 26 journaled mutations (create + 25 appends) at interval 10 -> 2 snapshot
  // writes, not 26. The journal carries per-append durability.
  t.is(snapshotSaves, 2, 'snapshot writes are checkpointed, not per-append')

  // Crash without flush(): a fresh instance restores checkpoint + journal tail.
  const restored = createOutboxLog({ persistence: countingPersistence, journalPath: journalFile })
  for (const i of [0, 9, 19, 24]) {
    t.alike(restored.sync.get(writer.publicKeyHex, 'post!r' + i).body, { ciphertext: 'c' + i }, 'row r' + i + ' survives (tail replay)')
  }

  // flush() forces the pending checkpoint.
  const before = snapshotSaves
  log.flush()
  t.is(snapshotSaves, before + 1, 'flush() writes the dirty checkpoint')
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
    get ({ name }) {
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

function createMockCore (name) {
  const blocks = []
  return {
    key: Buffer.from(name.padEnd(32, '0').slice(0, 32)),
    _blocks: blocks,
    get length () {
      return blocks.length
    },
    async ready () {},
    async get (index) {
      return blocks[index]
    },
    async append (block) {
      blocks.push(Buffer.from(block))
    }
  }
}
