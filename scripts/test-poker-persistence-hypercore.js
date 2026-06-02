#!/usr/bin/env node

/**
 * test-poker-persistence-hypercore.js
 *
 * Validates HypercorePersistence end-to-end against a real Corestore:
 *
 *   1. createPersistentTable on a fresh tableKey: opens a core, creates the
 *      in-memory table, no entries to replay.
 *   2. Submitting an entry mirrors to disk: core.length grows.
 *   3. Restart cycle: stop adapter, close PokerApp, re-create both pointing
 *      at the same store + tableKey → replay restores the in-memory log
 *      and the writer's lastSeq cursor.
 *   4. After restart, the writer can append seq N+1 (cursor was correctly
 *      restored from the replayed entries).
 *   5. Corrupt block in the core → createPersistentTable throws and the
 *      half-created PokerApp table is cleaned up.
 *   6. mirror-error event fires if the core's append fails (forced via a
 *      bad backing store), without rolling back the in-memory append.
 *   7. listMirrors() returns the expected shape.
 */

import { mkdtemp, rm } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import Corestore from 'corestore'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import { SignedLog } from '../packages/core/core/poker/signed-log.js'
import { PokerApp } from '../packages/core/core/poker/index.js'
import { HypercorePersistence } from '../packages/core/core/poker/persistence-hypercore.js'

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

const TABLE = 'a'.repeat(64)

async function setup () {
  const dir = await mkdtemp(join(tmpdir(), 'poker-persist-'))
  const store = new Corestore(dir)
  await store.ready()
  const app = new PokerApp()
  await app.start({})
  const persistence = new HypercorePersistence({ pokerApp: app, store })
  return { dir, store, app, persistence }
}

async function teardown (env) {
  try { await env.persistence.stop() } catch {}
  try { await env.app.stop() } catch {}
  try { await env.store.close() } catch {}
  try { await rm(env.dir, { recursive: true, force: true }) } catch {}
}

// ── 1, 2. Create + mirror ──────────────────────────────────────────────────
async function testCreateAndMirror () {
  console.log('\n── 1+2. Create + mirror to disk ──')
  const env = await setup()
  const a = makeKeyPair()
  try {
    const desc = await env.persistence.createPersistentTable({
      tableKey: TABLE, writers: [a.pubHex]
    })
    assert(desc.tableKey === TABLE, 'descriptor returned')
    assert(env.persistence.listMirrors().length === 1, 'one mirror active')

    const now = Date.now()
    const e0 = signEntry(a, { tableKey: TABLE, writer: a.pubHex, seq: 0, ts: now, payload: { kind: 'sit' } })
    const r = env.app.submitEntry(TABLE, e0)
    assert(r.ok, 'in-memory append ok')

    // Mirror is async — give it a tick.
    await new Promise(r => setTimeout(r, 50))
    const mirrors = env.persistence.listMirrors()
    assert(mirrors[0].length === 1, 'core.length = 1 after mirror')
  } finally {
    await teardown(env)
  }
}

// ── 3, 4. Restart cycle ────────────────────────────────────────────────────
async function testRestart () {
  console.log('\n── 3+4. Restart cycle replays from disk ──')
  // First pass: write some entries.
  const dir = await mkdtemp(join(tmpdir(), 'poker-restart-'))
  const a = makeKeyPair()
  const now = Date.now()
  {
    const store = new Corestore(dir)
    await store.ready()
    const app = new PokerApp()
    await app.start({})
    const p = new HypercorePersistence({ pokerApp: app, store })
    await p.createPersistentTable({ tableKey: TABLE, writers: [a.pubHex] })
    for (let i = 0; i < 3; i++) {
      const e = signEntry(a, {
        tableKey: TABLE, writer: a.pubHex, seq: i, ts: now, payload: { kind: 'act', i }
      })
      assert(env.appAppend(app, e), 'first-pass append ' + i)
    }
    await new Promise(r => setTimeout(r, 100))
    await p.stop()
    await app.stop()
    await store.close()
  }
  // Second pass: open same store, expect rehydration.
  {
    const store = new Corestore(dir)
    await store.ready()
    const app = new PokerApp()
    await app.start({})
    const p = new HypercorePersistence({ pokerApp: app, store })

    let hydratedCount = -1
    p.on('hydrated', (h) => { hydratedCount = h.count })

    await p.createPersistentTable({ tableKey: TABLE, writers: [a.pubHex] })
    assert(hydratedCount === 3, 'hydrated 3 entries (' + hydratedCount + ')')

    const log = app.getLog(TABLE, 0)
    assert(log.entries.length === 3, 'in-memory log has 3 entries after replay')
    assert(log.entries[2].payload.i === 2, 'last entry payload correct')

    // Cursor restored: writer should be able to append seq 3.
    const nextSeq = signEntry(a, {
      tableKey: TABLE, writer: a.pubHex, seq: 3, ts: now, payload: { kind: 'after-restart' }
    })
    const r = app.submitEntry(TABLE, nextSeq)
    assert(r.ok, 'post-restart append at seq 3 succeeded (' + (r.reason || 'ok') + ')')

    await p.stop()
    await app.stop()
    await store.close()
  }
  await rm(dir, { recursive: true, force: true })
}

// Small helper used inside testRestart's first pass — wraps submitEntry +
// asserts ok in one line.
const env = {
  appAppend (app, entry) {
    const r = app.submitEntry(TABLE, entry)
    return r.ok
  }
}

// ── 5. Corrupt block → throws, cleans up ───────────────────────────────────
async function testCorruptBlock () {
  console.log('\n── 5. Corrupt block on replay ──')
  const dir = await mkdtemp(join(tmpdir(), 'poker-corrupt-'))
  const a = makeKeyPair()
  // Write a single garbage block directly to the core.
  {
    const store = new Corestore(dir)
    await store.ready()
    const core = store.get({ name: 'poker/' + TABLE })
    await core.ready()
    await core.append(Buffer.from('not-json', 'utf8'))
    await store.close()
  }
  // Open and try to provision — should throw and not leave a half-table.
  {
    const store = new Corestore(dir)
    await store.ready()
    const app = new PokerApp()
    await app.start({})
    const p = new HypercorePersistence({ pokerApp: app, store })

    let threw = false
    try { await p.createPersistentTable({ tableKey: TABLE, writers: [a.pubHex] }) }
    catch { threw = true }
    assert(threw, 'createPersistentTable throws on corrupt block')
    assert(app.listTables().length === 0, 'no half-table left behind')

    await p.stop()
    await app.stop()
    await store.close()
  }
  await rm(dir, { recursive: true, force: true })
}

// ── 6. mirror-error event ─────────────────────────────────────────────────
async function testMirrorErrorEvent () {
  console.log('\n── 6. mirror-error event on append failure ──')
  const env = await setup()
  const a = makeKeyPair()
  try {
    await env.persistence.createPersistentTable({ tableKey: TABLE, writers: [a.pubHex] })

    // Sabotage the core's append by replacing it with a thrower.
    const internal = env.persistence._mirrors.get(TABLE)
    internal.core.append = () => { return Promise.reject(new Error('forced-failure')) }

    let errored = null
    env.persistence.on('mirror-error', (e) => { errored = e })

    const now = Date.now()
    const e0 = signEntry(a, { tableKey: TABLE, writer: a.pubHex, seq: 0, ts: now, payload: 'x' })
    const r = env.app.submitEntry(TABLE, e0)
    assert(r.ok, 'in-memory append still succeeds even if mirror will fail')

    // Wait briefly for the async mirror to fail.
    await new Promise(r => setTimeout(r, 50))
    assert(errored && errored.error === 'forced-failure',
      'mirror-error fired with the underlying error (' + (errored ? errored.error : 'null') + ')')
  } finally {
    await teardown(env)
  }
}

// ── 7. listMirrors shape ───────────────────────────────────────────────────
async function testListMirrorsShape () {
  console.log('\n── 7. listMirrors shape ──')
  const env = await setup()
  const a = makeKeyPair()
  try {
    await env.persistence.createPersistentTable({ tableKey: TABLE, writers: [a.pubHex] })
    const list = env.persistence.listMirrors()
    assert(list.length === 1, 'one mirror')
    assert(typeof list[0].tableKey === 'string' && list[0].tableKey === TABLE, 'tableKey present')
    assert(typeof list[0].coreKey === 'string' && /^[0-9a-f]{64}$/.test(list[0].coreKey),
      'coreKey is hex64')
    assert(typeof list[0].length === 'number', 'length is a number')
  } finally {
    await teardown(env)
  }
}

async function main () {
  await testCreateAndMirror()
  await testRestart()
  await testCorruptBlock()
  await testMirrorErrorEvent()
  await testListMirrorsShape()
  console.log(`\n── done: ${passed} passed, ${failed} failed ──`)
  process.exit(failed === 0 ? 0 : 1)
}

main().catch((err) => {
  console.error('fatal:', err)
  process.exit(2)
})
