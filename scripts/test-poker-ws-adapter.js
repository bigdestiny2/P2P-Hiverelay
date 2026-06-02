#!/usr/bin/env node

/**
 * test-poker-ws-adapter.js
 *
 * Validates PokerWsAdapter against a real http.Server + ws client:
 *
 *   1. Path matcher accepts /api/poker/<hex64>/events and nothing else.
 *   2. Connect to a known table → receives an initial { type:'state' } frame.
 *   3. A submitted entry on that table is pushed to the connected client
 *      as { type:'entry', entry, index } in order.
 *   4. Two clients on the same table both receive the same entry.
 *   5. A client on a different table does NOT receive the entry.
 *   6. Connecting to a non-existent table is rejected at handshake with 404.
 *   7. stop() detaches subscriptions and closes connections cleanly.
 *   8. API-key gate rejects bad tokens with 401.
 */

import http from 'http'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import WebSocket from 'ws'
import { SignedLog } from '../packages/core/core/poker/signed-log.js'
import { PokerApp } from '../packages/core/core/poker/index.js'
import { PokerWsAdapter, _matchTableKeyForTest as matchTableKey } from '../packages/core/core/poker/ws-adapter.js'

let passed = 0
let failed = 0

function assert (condition, label) {
  if (condition) { console.log(`  PASS  ${label}`); passed++ }
  else { console.log(`  FAIL  ${label}`); failed++ }
}

function makeKeyPair () {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey, pubHex: b4a.toString(publicKey, 'hex') }
}

function signEntry (kp, entry) {
  const canonical = SignedLog.canonicalBytes(entry)
  const sig = b4a.alloc(64)
  sodium.crypto_sign_detached(sig, canonical, kp.secretKey)
  return { ...entry, signature: b4a.toString(sig, 'hex') }
}

/**
 * Buffer every frame the client receives, starting NOW. Avoids the race
 * where a frame is delivered before a per-call `ws.on('message')` listener
 * is attached (the initial /state frame is sent during the upgrade
 * response and can land before the client even sees 'open').
 *
 * Returns an awaitable: `await capture.next(predicate)` resolves to the
 * next frame matching `predicate`, or null on timeout.
 */
function startCapture (ws) {
  const frames = []
  const waiters = []
  ws.on('message', (raw) => {
    let msg
    try { msg = JSON.parse(raw.toString('utf8')) } catch { return }
    frames.push(msg)
    for (const w of waiters.slice()) {
      if (w.predicate(msg)) {
        waiters.splice(waiters.indexOf(w), 1)
        clearTimeout(w.timer)
        w.resolve(msg)
      }
    }
  })
  return {
    frames,
    next (predicate, timeoutMs = 500) {
      // Already-buffered match?
      for (const m of frames) if (predicate(m)) return Promise.resolve(m)
      return new Promise((resolve) => {
        const w = { predicate, resolve, timer: null }
        w.timer = setTimeout(() => {
          const idx = waiters.indexOf(w)
          if (idx >= 0) waiters.splice(idx, 1)
          resolve(null)
        }, timeoutMs)
        waiters.push(w)
      })
    }
  }
}

// ── 1. matchTableKey ────────────────────────────────────────────────────────
function testMatchKey () {
  console.log('\n── 1. matchTableKey ──')
  const valid = 'a'.repeat(64)
  assert(matchTableKey('/api/poker/' + valid + '/events') === valid, 'happy path')
  assert(matchTableKey('/api/poker/' + valid + '/events/extra') === null, 'trailing junk rejected')
  assert(matchTableKey('/api/poker//events') === null, 'empty key rejected')
  assert(matchTableKey('/api/poker/not-hex/events') === null, 'non-hex rejected')
  assert(matchTableKey('/api/poker/' + valid.slice(1) + '/events') === null, 'wrong length rejected')
  assert(matchTableKey('/api/something/' + valid + '/events') === null, 'wrong prefix rejected')
}

// ── 2..7. Full integration over a real http.Server ─────────────────────────
async function integration () {
  console.log('\n── 2..7. Integration over http.Server + ws ──')
  const a = makeKeyPair()
  const TABLE = 'a'.repeat(64)
  const OTHER_TABLE = 'b'.repeat(64)

  const app = new PokerApp()
  await app.start({})
  app.createTable({ tableKey: TABLE, writers: [a.pubHex] })
  app.createTable({ tableKey: OTHER_TABLE, writers: [a.pubHex] })

  const server = http.createServer()
  await new Promise((resolve) => server.listen(0, resolve))
  const port = server.address().port
  const adapter = new PokerWsAdapter({ pokerApp: app, server })
  adapter.start()

  // 2. Connect; receive initial state. Attach capture BEFORE open await so
  // the state frame (sent during the upgrade response) isn't missed.
  const c1 = new WebSocket('ws://127.0.0.1:' + port + '/api/poker/' + TABLE + '/events')
  const cap1 = startCapture(c1)
  await new Promise((r) => c1.once('open', r))
  const state = await cap1.next((m) => m.type === 'state')
  assert(state && state.state.tableKey === TABLE, 'initial state frame on connect')

  // 3. Push an entry; client gets it.
  const now = Date.now()
  const entry = signEntry(a, {
    tableKey: TABLE, writer: a.pubHex, seq: 0, ts: now, payload: { kind: 'sit', seat: 0 }
  })
  const submitResult = app.submitEntry(TABLE, entry)
  assert(submitResult.ok, 'submitEntry ok')
  const frame = await cap1.next((m) => m.type === 'entry')
  assert(frame && frame.entry.payload.kind === 'sit', 'client received entry frame with payload')
  assert(frame && frame.index === 0, 'frame index = 0')

  // 4. Second client on same table also gets next entry.
  const c2 = new WebSocket('ws://127.0.0.1:' + port + '/api/poker/' + TABLE + '/events')
  const cap2 = startCapture(c2)
  await new Promise((r) => c2.once('open', r))
  await cap2.next((m) => m.type === 'state')
  assert(adapter.clientCount(TABLE) === 2, 'two clients on same table')

  const entry2 = signEntry(a, {
    tableKey: TABLE, writer: a.pubHex, seq: 1, ts: now, payload: { kind: 'bet', amount: 5 }
  })
  app.submitEntry(TABLE, entry2)
  const [f1, f2] = await Promise.all([
    cap1.next((m) => m.type === 'entry' && m.index === 1),
    cap2.next((m) => m.type === 'entry' && m.index === 1)
  ])
  assert(f1 && f2 && f1.entry.payload.amount === 5 && f2.entry.payload.amount === 5,
    'both clients received entry 1')

  // 5. Client on OTHER_TABLE does NOT see this entry.
  const cOther = new WebSocket('ws://127.0.0.1:' + port + '/api/poker/' + OTHER_TABLE + '/events')
  const capOther = startCapture(cOther)
  await new Promise((r) => cOther.once('open', r))
  await capOther.next((m) => m.type === 'state')
  const noLeak = await capOther.next((m) => m.type === 'entry', 200)
  assert(noLeak === null, 'other-table client received no leaked entry')

  // 6. Non-existent table → handshake 404.
  const missing = 'c'.repeat(64)
  const ws404 = new WebSocket('ws://127.0.0.1:' + port + '/api/poker/' + missing + '/events')
  const err404 = await new Promise((r) => {
    ws404.on('unexpected-response', (_req, res) => r(res.statusCode))
    ws404.on('error', () => r('error-event'))
    setTimeout(() => r('timeout'), 1000)
  })
  assert(err404 === 404, 'missing table → 404 at handshake (' + err404 + ')')

  // 7. Close clients, then stop adapter.
  c1.close(); c2.close(); cOther.close()
  await new Promise(r => setTimeout(r, 50))
  adapter.stop()
  assert(adapter.clientCount() === 0, 'all clients detached after stop')
  await new Promise(r => server.close(r))
  await app.stop()
}

// ── 8. API key gate ────────────────────────────────────────────────────────
async function testApiKeyGate () {
  console.log('\n── 8. API key gate ──')
  const a = makeKeyPair()
  const TABLE = 'a'.repeat(64)
  const app = new PokerApp()
  await app.start({})
  app.createTable({ tableKey: TABLE, writers: [a.pubHex] })

  const server = http.createServer()
  await new Promise((r) => server.listen(0, r))
  const port = server.address().port
  const adapter = new PokerWsAdapter({ pokerApp: app, server, apiKey: 'sekrit' })
  adapter.start()

  // No token → 401
  let ws = new WebSocket('ws://127.0.0.1:' + port + '/api/poker/' + TABLE + '/events')
  let status = await new Promise((r) => {
    ws.on('unexpected-response', (_req, res) => r(res.statusCode))
    ws.on('error', () => r('error-event'))
    setTimeout(() => r('timeout'), 1000)
  })
  assert(status === 401, 'no token → 401 (' + status + ')')

  // Right token → opens
  ws = new WebSocket('ws://127.0.0.1:' + port + '/api/poker/' + TABLE + '/events?token=sekrit')
  const opened = await new Promise((r) => {
    ws.once('open', () => r(true))
    ws.once('error', () => r(false))
    setTimeout(() => r('timeout'), 1000)
  })
  assert(opened === true, 'good token → connection opens')

  ws.close()
  await new Promise(r => setTimeout(r, 50))
  adapter.stop()
  await new Promise(r => server.close(r))
  await app.stop()
}

async function main () {
  testMatchKey()
  await integration()
  await testApiKeyGate()
  console.log(`\n── done: ${passed} passed, ${failed} failed ──`)
  process.exit(failed === 0 ? 0 : 1)
}

main().catch((err) => {
  console.error('fatal:', err)
  process.exit(2)
})
