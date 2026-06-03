#!/usr/bin/env node

/**
 * test-poker-app.js
 *
 * Validates the PokerApp signed-log substrate end-to-end:
 *
 *   1. SignedLog accepts a well-formed signed entry and refuses everything
 *      malformed (bad sig, wrong table, gap in seq, future ts, oversized,
 *      unknown writer).
 *   2. Per-writer monotonic seq is enforced independently across writers.
 *   3. SignedLog.canonicalBytes() round-trips with the relay-side canonical.
 *   4. Subscribers receive entries after a successful append, errors in one
 *      subscriber don't break others.
 *   5. PokerApp.createTable + duplicate detection + maxTables cap.
 *   6. PokerApp.getState / getLog return the expected shapes.
 *   7. PokerApp.closeTable + reaper TTL eviction.
 *   8. HTTP adapter handles each route correctly with a stubbed req/res.
 */

import sodium from 'sodium-universal'
import b4a from 'b4a'
import { EventEmitter } from 'events'
import { SignedLog, REJECT } from '../packages/services/builtin/poker/signed-log.js'
import { PokerApp } from '../packages/services/builtin/poker/index.js'
import { handlePokerRoute } from '../packages/services/builtin/poker/http-adapter.js'

let passed = 0
let failed = 0

function assert (condition, label) {
  if (condition) {
    console.log(`  PASS  ${label}`)
    passed++
  } else {
    console.log(`  FAIL  ${label}`)
    failed++
  }
}

// ─── Test helpers ───────────────────────────────────────────────────────────

function makeKeyPair () {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return {
    publicKey,
    secretKey,
    pubHex: b4a.toString(publicKey, 'hex')
  }
}

function signEntry (kp, entry) {
  // Build the canonical bytes the relay will check, sign them, return
  // the entry with a hex signature attached.
  const canonical = SignedLog.canonicalBytes(entry)
  const sig = b4a.alloc(64)
  sodium.crypto_sign_detached(sig, canonical, kp.secretKey)
  return { ...entry, signature: b4a.toString(sig, 'hex') }
}

const TABLE_KEY_KP = makeKeyPair()
const TABLE_KEY = TABLE_KEY_KP.pubHex

// ── 1. SignedLog accept + reject matrix ─────────────────────────────────────
async function testSignedLogMatrix () {
  console.log('\n── 1. SignedLog accept + reject matrix ──')
  const alice = makeKeyPair()
  const log = new SignedLog({ tableKey: TABLE_KEY, writers: [alice.pubHex] })

  const now = 1700000000000
  const goodBody = {
    tableKey: TABLE_KEY,
    writer: alice.pubHex,
    seq: 0,
    ts: now,
    payload: { kind: 'sit', seat: 0 }
  }
  const good = signEntry(alice, goodBody)
  let r = log.append(good, { now })
  assert(r.ok && r.index === 0, 'happy path append')

  // Bad signature — tamper after signing.
  const tampered = { ...signEntry(alice, { ...goodBody, seq: 1 }), payload: { kind: 'other' } }
  r = log.append(tampered, { now })
  assert(!r.ok && r.reason === REJECT.BAD_SIG, 'tampered payload → BAD_SIG')

  // Wrong table.
  const wrongTable = signEntry(alice, { ...goodBody, tableKey: 'd'.repeat(64), seq: 1 })
  r = log.append(wrongTable, { now })
  assert(!r.ok && r.reason === REJECT.WRONG_TABLE, 'wrong tableKey → WRONG_TABLE')

  // Unknown writer.
  const bob = makeKeyPair()
  const bobEntry = signEntry(bob, { ...goodBody, writer: bob.pubHex, seq: 0 })
  r = log.append(bobEntry, { now })
  assert(!r.ok && r.reason === REJECT.UNKNOWN_WRITER, 'unknown writer → UNKNOWN_WRITER')

  // Seq gap.
  const gap = signEntry(alice, { ...goodBody, seq: 5 })
  r = log.append(gap, { now })
  assert(!r.ok && r.reason === REJECT.BAD_SEQ, 'seq gap → BAD_SEQ')

  // Future ts.
  const future = signEntry(alice, { ...goodBody, seq: 1, ts: now + 5 * 60 * 1000 })
  r = log.append(future, { now })
  assert(!r.ok && r.reason === REJECT.BAD_TS && r.detail === 'future', 'future ts → BAD_TS future')

  // Past ts.
  const past = signEntry(alice, { ...goodBody, seq: 1, ts: now - 5 * 60 * 1000 })
  r = log.append(past, { now })
  assert(!r.ok && r.reason === REJECT.BAD_TS && r.detail === 'past', 'past ts → BAD_TS past')

  // Oversized payload.
  const huge = signEntry(alice, { ...goodBody, seq: 1, payload: { junk: 'x'.repeat(80 * 1024) } })
  r = log.append(huge, { now })
  assert(!r.ok && r.reason === REJECT.OVERSIZED, 'huge payload → OVERSIZED')

  // Recover: seq 1 still works after all the rejections.
  const next = signEntry(alice, { ...goodBody, seq: 1, payload: { kind: 'bet', amount: 10 } })
  r = log.append(next, { now })
  assert(r.ok && r.index === 1, 'seq 1 still accepted after multiple rejects')
}

// ── 2. Per-writer monotonic seq is independent across writers ───────────────
async function testPerWriterSeq () {
  console.log('\n── 2. Per-writer seq independence ──')
  const a = makeKeyPair()
  const b = makeKeyPair()
  const log = new SignedLog({ tableKey: TABLE_KEY, writers: [a.pubHex, b.pubHex] })
  const now = 1700000000000

  let r = log.append(signEntry(a, { tableKey: TABLE_KEY, writer: a.pubHex, seq: 0, ts: now, payload: 'a0' }), { now })
  assert(r.ok, 'a:0 accepted')
  r = log.append(signEntry(b, { tableKey: TABLE_KEY, writer: b.pubHex, seq: 0, ts: now, payload: 'b0' }), { now })
  assert(r.ok, 'b:0 accepted (independent of a)')
  r = log.append(signEntry(a, { tableKey: TABLE_KEY, writer: a.pubHex, seq: 1, ts: now, payload: 'a1' }), { now })
  assert(r.ok, 'a:1 accepted')
  r = log.append(signEntry(b, { tableKey: TABLE_KEY, writer: b.pubHex, seq: 2, ts: now, payload: 'b2' }), { now })
  assert(!r.ok && r.reason === REJECT.BAD_SEQ, 'b:2 rejected (expected 1)')
}

// ── 3. Subscribers fire on append; bad subscriber doesn't kill others ──────
async function testSubscribers () {
  console.log('\n── 3. Subscribers ──')
  const alice = makeKeyPair()
  const log = new SignedLog({ tableKey: TABLE_KEY, writers: [alice.pubHex] })
  const now = 1700000000000
  let calls = 0
  let goodCalls = 0
  log.subscribe(() => { throw new Error('boom') })
  log.subscribe(() => { calls++ })
  log.subscribe(() => { goodCalls++ })
  const r = log.append(signEntry(alice, {
    tableKey: TABLE_KEY, writer: alice.pubHex, seq: 0, ts: now, payload: null
  }), { now })
  assert(r.ok, 'append succeeded despite throwing subscriber')
  assert(calls === 1 && goodCalls === 1, 'both well-behaved subscribers fired')
}

// ── 4. PokerApp createTable / dup / cap ─────────────────────────────────────
async function testCreateTable () {
  console.log('\n── 4. PokerApp createTable ──')
  const a = makeKeyPair()
  const app = new PokerApp({ maxTables: 2 })
  await app.start({})

  const t = app.createTable({ tableKey: TABLE_KEY, writers: [a.pubHex] })
  assert(t.tableKey === TABLE_KEY.toLowerCase(), 'created descriptor has tableKey')
  assert(Array.isArray(t.writers) && t.writers.length === 1, 'writers array carried')

  let threw = false
  try { app.createTable({ tableKey: TABLE_KEY, writers: [a.pubHex] }) } catch { threw = true }
  assert(threw, 'duplicate tableKey throws')

  app.createTable({ tableKey: 'd'.repeat(64), writers: [a.pubHex] })
  threw = false
  try { app.createTable({ tableKey: 'e'.repeat(64), writers: [a.pubHex] }) } catch { threw = true }
  assert(threw, 'max tables cap throws')

  await app.stop()
}

// ── 5. PokerApp submitEntry / getState / getLog ─────────────────────────────
async function testSubmitAndState () {
  console.log('\n── 5. PokerApp submitEntry / getState / getLog ──')
  const a = makeKeyPair()
  const app = new PokerApp()
  await app.start({})
  app.createTable({ tableKey: TABLE_KEY, writers: [a.pubHex] })
  const now = Date.now()
  const r = app.submitEntry(TABLE_KEY, signEntry(a, {
    tableKey: TABLE_KEY, writer: a.pubHex, seq: 0, ts: now, payload: { kind: 'sit' }
  }))
  assert(r.ok && r.index === 0, 'submitEntry happy path')

  const st = app.getState(TABLE_KEY)
  assert(st.length === 1, 'state.length = 1')
  assert(st.writers[a.pubHex] === 0, 'state.writers shows last seq for writer')

  const log = app.getLog(TABLE_KEY, 0)
  assert(log.entries.length === 1, 'log has the entry')
  assert(log.entries[0].payload.kind === 'sit', 'log payload preserved')

  await app.stop()
}

// ── 6. closeTable + reaper ──────────────────────────────────────────────────
async function testCloseAndReaper () {
  console.log('\n── 6. closeTable + reaper ──')
  const a = makeKeyPair()
  const app = new PokerApp({ defaultLifetimeMs: 10, reaperIntervalMs: 5 })
  await app.start({})
  app.createTable({ tableKey: TABLE_KEY, writers: [a.pubHex] })
  assert(app.listTables().length === 1, 'table listed')
  app.closeTable(TABLE_KEY)
  assert(app.listTables().length === 0, 'table closed manually')

  // Re-create and let the reaper drop it.
  app.createTable({ tableKey: TABLE_KEY, writers: [a.pubHex] })
  await new Promise(r => setTimeout(r, 60))
  assert(app.listTables().length === 0, 'reaper evicted idle table')

  await app.stop()
}

// ── 7. canonicalBytes determinism ───────────────────────────────────────────
async function testCanonical () {
  console.log('\n── 7. canonicalBytes deterministic ──')
  const a = { tableKey: TABLE_KEY, writer: 'aa'.repeat(32), seq: 1, ts: 1, payload: { x: 1, y: 2 } }
  const b = { tableKey: TABLE_KEY, writer: 'aa'.repeat(32), seq: 1, ts: 1, payload: { y: 2, x: 1 } }
  const ba = SignedLog.canonicalBytes(a)
  const bb = SignedLog.canonicalBytes(b)
  assert(b4a.equals(ba, bb), 'key order in payload does not affect canonical')
}

// ── 8. HTTP adapter — stubbed req/res ──────────────────────────────────────
function stubReq (method, url, body) {
  const req = new EventEmitter()
  req.method = method
  req.url = url
  // Asynchronously emit body data + end so listeners attached after creation
  // (the adapter attaches them inside the handler) still receive it.
  setTimeout(() => {
    if (body != null) req.emit('data', Buffer.from(typeof body === 'string' ? body : JSON.stringify(body)))
    req.emit('end')
  }, 0)
  return req
}
function stubRes () {
  return {
    _headers: {},
    statusCode: 0,
    body: null,
    setHeader (k, v) { this._headers[k] = v },
    writeHead (s) { this.statusCode = s },
    end (b) { this.body = b }
  }
}

async function testHttpAdapter () {
  console.log('\n── 8. HTTP adapter ──')
  const a = makeKeyPair()
  const app = new PokerApp()
  await app.start({})
  const ctx = { pokerApp: app }

  // POST /api/poker/tables → 201
  let res = stubRes()
  let handled = await handlePokerRoute(
    stubReq('POST', '/api/poker/tables', { tableKey: TABLE_KEY, writers: [a.pubHex] }),
    res, ctx
  )
  assert(handled, 'POST /tables handled')
  assert(res.statusCode === 201, 'POST /tables → 201')

  // GET /api/poker/tables → list of one
  res = stubRes()
  await handlePokerRoute(stubReq('GET', '/api/poker/tables'), res, ctx)
  assert(res.statusCode === 200 && JSON.parse(res.body).tables.length === 1, 'GET /tables lists table')

  // GET /api/poker/<table>/state → 200
  res = stubRes()
  await handlePokerRoute(stubReq('GET', '/api/poker/' + TABLE_KEY + '/state'), res, ctx)
  assert(res.statusCode === 200, 'GET /state → 200')

  // POST /api/poker/<table>/move with a good signed entry → 200
  const now = Date.now()
  const signed = signEntry(a, {
    tableKey: TABLE_KEY, writer: a.pubHex, seq: 0, ts: now, payload: { kind: 'sit' }
  })
  res = stubRes()
  await handlePokerRoute(stubReq('POST', '/api/poker/' + TABLE_KEY + '/move', signed), res, ctx)
  assert(res.statusCode === 200, 'POST /move (good sig) → 200')

  // POST /api/poker/<table>/move with bad seq → 422 + reason 'bad-seq'
  const badSig = signEntry(a, {
    tableKey: TABLE_KEY, writer: a.pubHex, seq: 99, ts: now, payload: { kind: 'bet' }
  })
  res = stubRes()
  await handlePokerRoute(stubReq('POST', '/api/poker/' + TABLE_KEY + '/move', badSig), res, ctx)
  assert(res.statusCode === 422, 'POST /move (bad seq) → 422')
  assert(JSON.parse(res.body).reason === 'bad-seq', 'reason: bad-seq')

  // GET /api/poker/<table>/log?from=0 → entries returned
  res = stubRes()
  await handlePokerRoute(stubReq('GET', '/api/poker/' + TABLE_KEY + '/log?from=0'), res, ctx)
  const body = JSON.parse(res.body)
  assert(res.statusCode === 200 && body.entries.length === 1, 'GET /log → 1 entry')

  // GET unknown table → 404
  res = stubRes()
  await handlePokerRoute(stubReq('GET', '/api/poker/' + 'd'.repeat(64) + '/state'), res, ctx)
  assert(res.statusCode === 404, 'GET unknown table → 404')

  // Unknown verb under a known table → 404 (not 5xx)
  res = stubRes()
  await handlePokerRoute(stubReq('GET', '/api/poker/' + TABLE_KEY + '/bogus'), res, ctx)
  assert(res.statusCode === 404, 'unknown verb → 404')

  // Wrong-prefix path passes through (returns false)
  res = stubRes()
  handled = await handlePokerRoute(stubReq('GET', '/api/something-else'), res, ctx)
  assert(handled === false, 'non-matching prefix returns false')

  await app.stop()
}

async function main () {
  await testSignedLogMatrix()
  await testPerWriterSeq()
  await testSubscribers()
  await testCreateTable()
  await testSubmitAndState()
  await testCloseAndReaper()
  await testCanonical()
  await testHttpAdapter()
  console.log(`\n── done: ${passed} passed, ${failed} failed ──`)
  process.exit(failed === 0 ? 0 : 1)
}

main().catch((err) => {
  console.error('fatal:', err)
  process.exit(2)
})
