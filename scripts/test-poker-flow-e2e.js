#!/usr/bin/env node

/**
 * test-poker-flow-e2e.js
 *
 * Substrate completeness check. Walks a minimal but realistic poker-shaped
 * sequence through every layer of the substrate together, then verifies a
 * disconnection-and-restart cycle recovers correctly. The point isn't to
 * exercise game logic (the relay doesn't know any) — it's to prove the
 * substrate composes into the shape an actual poker app would need.
 *
 * Flow simulated (payload kinds are illustrative; relay treats them as opaque):
 *
 *   Phase 1 — Sit
 *     Alice writes (Alice, seq=0, payload={kind:'sit', seat:0})
 *     Bob   writes (Bob,   seq=0, payload={kind:'sit', seat:1})
 *
 *   Phase 2 — DKG / shuffle commit (parallel writers, per-writer seq)
 *     Alice writes (Alice, seq=1, payload={kind:'dkg-commit', round:0, ...})
 *     Bob   writes (Bob,   seq=1, payload={kind:'dkg-commit', round:0, ...})
 *
 *   Phase 3 — Pre-committed reveal shares for board cards 0..2
 *     Alice writes (Alice, seq=2..4, payload={kind:'precommit-share', card:i, ciphertext:...})
 *     Bob   writes (Bob,   seq=2..4, payload={kind:'precommit-share', card:i, ciphertext:...})
 *
 *   Phase 4 — Betting (turn-based: Alice then Bob)
 *     Alice writes (Alice, seq=5, payload={kind:'bet', amount:10})
 *     Bob   writes (Bob,   seq=5, payload={kind:'call'})
 *
 *   Phase 5 — Disconnect Bob; relay restart; Alice continues
 *     close + reopen the PokerApp + persistence over the same store
 *     verify Alice can append seq=6 against the restored cursor
 *     verify Bob's seq=2..5 are still readable from the log
 *
 *   Phase 6 — WS push is live across both clients on the live table
 *     two WS subscribers connect, an append fans out to both
 *
 *   Phase 7 — Slashing-grade dispute is end-to-end resolvable
 *     submit poker/invalid-share with a real Chaum-Pedersen proof
 *     verifier confirms validity → claim refuted
 *
 * If all phases pass we have evidence the substrate is exactly what a
 * poker app needs: ordering + persistence + push + arbitration.
 */

import http from 'http'
import { mkdtemp, rm } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import Corestore from 'corestore'
import WebSocket from 'ws'
import sodium from 'sodium-universal'
import b4a from 'b4a'

import { SignedLog } from '../packages/core/core/poker/signed-log.js'
import { PokerApp } from '../packages/core/core/poker/index.js'
import { HypercorePersistence } from '../packages/core/core/poker/persistence-hypercore.js'
import { PokerWsAdapter } from '../packages/core/core/poker/ws-adapter.js'
import {
  proveShareEquality, publicFromSecret, shareFor, SCALAR_BYTES, POINT_BYTES
} from '../packages/core/core/poker/crypto/chaum-pedersen.js'
import { makeInvalidShareVerifier } from '../packages/core/core/poker/crypto/share-verifier.js'
import { ArbitrationService } from '../packages/services/builtin/arbitration-service.js'

let passed = 0
let failed = 0
function assert (cond, label) {
  if (cond) { console.log(`  PASS  ${label}`); passed++ }
  else { console.log(`  FAIL  ${label}`); failed++ }
}

function makeKeyPair () {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey, pubHex: b4a.toString(publicKey, 'hex') }
}
function signEntry (kp, body) {
  const canonical = SignedLog.canonicalBytes(body)
  const sig = b4a.alloc(64)
  sodium.crypto_sign_detached(sig, canonical, kp.secretKey)
  return { ...body, signature: b4a.toString(sig, 'hex') }
}
function randomScalar () {
  const s = b4a.alloc(SCALAR_BYTES); sodium.crypto_core_ed25519_scalar_random(s); return s
}
function randomPoint () {
  const r = randomScalar(); const p = b4a.alloc(POINT_BYTES)
  sodium.crypto_scalarmult_ed25519_base_noclamp(p, r); return p
}

const TABLE_KEY = 'a'.repeat(64)

async function main () {
  const Alice = makeKeyPair()
  const Bob = makeKeyPair()
  const now = Date.now()
  const dir = await mkdtemp(join(tmpdir(), 'poker-flow-'))

  // ── Phase 1: Sit ────────────────────────────────────────────────────────
  console.log('\n── Phase 1: Sit ──')
  let store = new Corestore(dir); await store.ready()
  let app = new PokerApp(); await app.start({})
  let p = new HypercorePersistence({ pokerApp: app, store })
  await p.createPersistentTable({
    tableKey: TABLE_KEY, writers: [Alice.pubHex, Bob.pubHex]
  })
  for (const kp of [Alice, Bob]) {
    const r = app.submitEntry(TABLE_KEY, signEntry(kp, {
      tableKey: TABLE_KEY, writer: kp.pubHex, seq: 0, ts: now,
      payload: { kind: 'sit', seat: kp === Alice ? 0 : 1 }
    }))
    assert(r.ok, (kp === Alice ? 'Alice' : 'Bob') + ' sit')
  }

  // ── Phase 2: DKG commit (parallel writers, independent seqs) ───────────
  console.log('\n── Phase 2: DKG commit ──')
  for (const kp of [Alice, Bob]) {
    const r = app.submitEntry(TABLE_KEY, signEntry(kp, {
      tableKey: TABLE_KEY, writer: kp.pubHex, seq: 1, ts: now,
      payload: { kind: 'dkg-commit', round: 0, commitment: 'aa'.repeat(16) }
    }))
    assert(r.ok, (kp === Alice ? 'Alice' : 'Bob') + ' dkg-commit')
  }

  // ── Phase 3: Pre-committed reveal shares for board cards 0..2 ──────────
  console.log('\n── Phase 3: Pre-committed reveal shares ──')
  let seqA = 2, seqB = 2
  for (let card = 0; card < 3; card++) {
    const rA = app.submitEntry(TABLE_KEY, signEntry(Alice, {
      tableKey: TABLE_KEY, writer: Alice.pubHex, seq: seqA++, ts: now,
      payload: { kind: 'precommit-share', card, ciphertext: 'cc'.repeat(16) }
    }))
    const rB = app.submitEntry(TABLE_KEY, signEntry(Bob, {
      tableKey: TABLE_KEY, writer: Bob.pubHex, seq: seqB++, ts: now,
      payload: { kind: 'precommit-share', card, ciphertext: 'dd'.repeat(16) }
    }))
    assert(rA.ok && rB.ok, 'card ' + card + ' precommits accepted')
  }

  // ── Phase 4: Betting ────────────────────────────────────────────────────
  console.log('\n── Phase 4: Betting ──')
  let r = app.submitEntry(TABLE_KEY, signEntry(Alice, {
    tableKey: TABLE_KEY, writer: Alice.pubHex, seq: seqA++, ts: now,
    payload: { kind: 'bet', amount: 10 }
  }))
  assert(r.ok, 'Alice bet')
  r = app.submitEntry(TABLE_KEY, signEntry(Bob, {
    tableKey: TABLE_KEY, writer: Bob.pubHex, seq: seqB++, ts: now,
    payload: { kind: 'call' }
  }))
  assert(r.ok, 'Bob call')

  // Snapshot log length before restart.
  const preState = app.getState(TABLE_KEY)
  assert(preState.length === 12, 'log has 12 entries pre-restart (' + preState.length + ')')
  assert(preState.writers[Alice.pubHex] === 5 && preState.writers[Bob.pubHex] === 5,
    'per-writer cursors at 5 each pre-restart')

  // Let the mirror drain to disk before tearing down.
  await new Promise(r => setTimeout(r, 100))

  // ── Phase 5: Disconnect, restart, continue ─────────────────────────────
  console.log('\n── Phase 5: Restart → replay → continue ──')
  await p.stop(); await app.stop(); await store.close()

  store = new Corestore(dir); await store.ready()
  app = new PokerApp(); await app.start({})
  p = new HypercorePersistence({ pokerApp: app, store })
  let hydratedCount = -1
  p.on('hydrated', (h) => { hydratedCount = h.count })
  await p.createPersistentTable({
    tableKey: TABLE_KEY, writers: [Alice.pubHex, Bob.pubHex]
  })
  assert(hydratedCount === 12, 'hydrated 12 entries (' + hydratedCount + ')')

  const restored = app.getState(TABLE_KEY)
  assert(restored.length === 12 &&
    restored.writers[Alice.pubHex] === 5 && restored.writers[Bob.pubHex] === 5,
    'cursors restored from disk')

  // Alice continues at seq 6; Bob's offline.
  const after = app.submitEntry(TABLE_KEY, signEntry(Alice, {
    tableKey: TABLE_KEY, writer: Alice.pubHex, seq: 6, ts: now,
    payload: { kind: 'flop-reveal-request' }
  }))
  assert(after.ok, 'post-restart append at next seq succeeds')

  // ── Phase 6: WS push across two live subscribers ───────────────────────
  console.log('\n── Phase 6: WS push fans out across subscribers ──')
  const server = http.createServer()
  await new Promise(r => server.listen(0, r))
  const port = server.address().port
  const ws = new PokerWsAdapter({ pokerApp: app, server })
  ws.start()

  // Capture frames at construction (avoids the open-race).
  const startCap = (ws) => {
    const frames = []
    ws.on('message', (raw) => { try { frames.push(JSON.parse(raw.toString('utf8'))) } catch {} })
    return frames
  }
  const c1 = new WebSocket('ws://127.0.0.1:' + port + '/api/poker/' + TABLE_KEY + '/events')
  const f1 = startCap(c1)
  const c2 = new WebSocket('ws://127.0.0.1:' + port + '/api/poker/' + TABLE_KEY + '/events')
  const f2 = startCap(c2)
  await Promise.all([
    new Promise(r => c1.once('open', r)),
    new Promise(r => c2.once('open', r))
  ])
  // Wait for initial state frames.
  await new Promise(r => setTimeout(r, 80))
  const stateOk1 = f1.some(m => m.type === 'state')
  const stateOk2 = f2.some(m => m.type === 'state')
  assert(stateOk1 && stateOk2, 'both clients got initial state frame')

  // Push another append; expect both clients to receive the entry frame.
  const pushed = app.submitEntry(TABLE_KEY, signEntry(Bob, {
    tableKey: TABLE_KEY, writer: Bob.pubHex, seq: 6, ts: now,
    payload: { kind: 'reconnect' }
  }))
  assert(pushed.ok, 'append for Bob (reconnect)')
  await new Promise(r => setTimeout(r, 80))
  const gotEntry1 = f1.find(m => m.type === 'entry' && m.entry.payload.kind === 'reconnect')
  const gotEntry2 = f2.find(m => m.type === 'entry' && m.entry.payload.kind === 'reconnect')
  assert(gotEntry1 && gotEntry2, 'both clients received the reconnect entry')

  c1.close(); c2.close()
  await new Promise(r => setTimeout(r, 50))
  ws.stop()
  await new Promise(r => server.close(r))

  // ── Phase 7: Arbitration end-to-end with real Chaum-Pedersen proof ─────
  console.log('\n── Phase 7: Arbitration with real CP proof ──')
  const arb = new ArbitrationService()
  arb.node = { router: { pubsub: { publish () {} } } }
  arb.setAppEvidenceVerifier('poker/invalid-share', makeInvalidShareVerifier())

  const x = randomScalar()
  const Y = publicFromSecret(x)
  const C1 = randomPoint()
  const D = shareFor(x, C1)
  const proof = proveShareEquality({ x, Y, C1, D })

  const dispute = await arb.submit({
    type: 'poker/invalid-share',
    respondent: 'b'.repeat(64),
    claimant: 'c'.repeat(64),
    appEvidence: {
      tableKey: TABLE_KEY, handId: 'h1', cardIndex: 0,
      ciphertext: b4a.toString(C1, 'hex'),
      share: b4a.toString(D, 'hex'),
      witness: {
        Y: b4a.toString(Y, 'hex'),
        proof: {
          A: b4a.toString(proof.A, 'hex'),
          B: b4a.toString(proof.B, 'hex'),
          z: b4a.toString(proof.z, 'hex')
        }
      }
    },
    penalty: 0
  }, { caller: 'local' })

  const ev = await arb.evidence({ id: dispute.id })
  assert(ev.appEvidence && ev.appEvidence.verdict === 'claim-refuted',
    'real CP proof verifies → claim-refuted (' + (ev.appEvidence ? ev.appEvidence.reason : 'null') + ')')

  // Teardown
  await p.stop(); await app.stop(); await store.close()
  await rm(dir, { recursive: true, force: true })

  console.log(`\n── done: ${passed} passed, ${failed} failed ──`)
  process.exit(failed === 0 ? 0 : 1)
}

main().catch((err) => {
  console.error('fatal:', err)
  process.exit(2)
})
