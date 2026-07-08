/**
 * Open-join (dynamic writer set) — Phase A substrate.
 *
 * Covers the log-derived mutable writer set: self-signed claim-seat admission,
 * seat races resolved by append order, maxSeats cap, the scoped UNKNOWN_WRITER
 * relaxation (claim-seat ONLY), per-author rate limiting, host revoke (kick),
 * signature-binding of the envelope control fields, and rehydrate.
 */
import test from 'brittle'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import { SignedLog, REJECT, KIND } from '../../packages/services/builtin/poker/signed-log.js'
import { PokerApp } from '../../packages/services/builtin/poker/index.js'

const NOW = 1700000000000

function makeKeyPair () {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey, pubHex: b4a.toString(publicKey, 'hex') }
}

function sign (kp, entry) {
  const canonical = SignedLog.canonicalBytes(entry)
  const sig = b4a.alloc(64)
  sodium.crypto_sign_detached(sig, canonical, kp.secretKey)
  return { ...entry, signature: b4a.toString(sig, 'hex') }
}

const TABLE = makeKeyPair().pubHex

function claimSeat (kp, { seq = 0, seat, ts = NOW, table = TABLE }) {
  return sign(kp, { tableKey: table, writer: kp.pubHex, seq, ts, kind: KIND.CLAIM_SEAT, seat, payload: null })
}
function revokeSeat (kp, { seq, target, ts = NOW, table = TABLE }) {
  return sign(kp, { tableKey: table, writer: kp.pubHex, seq, ts, kind: KIND.REVOKE_SEAT, target, payload: null })
}
function action (kp, { seq, ts = NOW, table = TABLE, payload = { type: 'bet', amount: 1 } }) {
  return sign(kp, { tableKey: table, writer: kp.pubHex, seq, ts, payload })
}

// ── admission ────────────────────────────────────────────────────────────────

test('non-writer claim-seat for a free seat is admitted and can then act', (t) => {
  const host = makeKeyPair()
  const bob = makeKeyPair()
  const log = new SignedLog({ tableKey: TABLE, writers: [host.pubHex], maxSeats: 4 })

  t.absent(log.writers.has(bob.pubHex), 'bob starts as a non-writer')
  const r = log.append(claimSeat(bob, { seat: 1 }), { now: NOW })
  t.ok(r.ok, 'claim-seat accepted')
  t.ok(log.writers.has(bob.pubHex), 'bob is now a writer')
  t.is(log.state().seats[1], bob.pubHex, 'bob occupies seat 1')

  // Admission grants write access: a plain action from bob (seq 1) is accepted.
  const a = log.append(action(bob, { seq: 1 }), { now: NOW })
  t.ok(a.ok, 'admitted writer can append a game action')
})

test('claim-seat for a taken seat is rejected and the loser stays a non-writer', (t) => {
  const host = makeKeyPair()
  const bob = makeKeyPair()
  const carol = makeKeyPair()
  const log = new SignedLog({ tableKey: TABLE, writers: [host.pubHex], maxSeats: 4 })

  t.ok(log.append(claimSeat(bob, { seat: 1 }), { now: NOW }).ok, 'bob wins seat 1')
  const r = log.append(claimSeat(carol, { seat: 1 }), { now: NOW })
  t.is(r.reason, REJECT.SEAT_TAKEN, 'carol loses the seat-1 race')
  t.absent(log.writers.has(carol.pubHex), 'losing claimant is not a writer')
  t.is(log.entries.length, 1, 'the losing claim is NOT stored (no storage flood)')
})

test('simultaneous seat claims resolve deterministically by append order', (t) => {
  const host = makeKeyPair()
  const bob = makeKeyPair()
  const carol = makeKeyPair()
  const log = new SignedLog({ tableKey: TABLE, writers: [host.pubHex], maxSeats: 4 })

  t.ok(log.append(claimSeat(bob, { seat: 2 }), { now: NOW }).ok, 'first-appended claim wins seat 2')
  t.is(log.append(claimSeat(carol, { seat: 2 }), { now: NOW }).reason, REJECT.SEAT_TAKEN)
  t.ok(log.append(claimSeat(carol, { seat: 3 }), { now: NOW }).ok, 'carol takes a different free seat')
  t.is(log.state().seats[2], bob.pubHex)
  t.is(log.state().seats[3], carol.pubHex)
})

test('writer set is capped at maxSeats', (t) => {
  const host = makeKeyPair()
  const log = new SignedLog({ tableKey: TABLE, writers: [host.pubHex], maxSeats: 2 })
  const bob = makeKeyPair()
  const carol = makeKeyPair()

  t.ok(log.append(claimSeat(bob, { seat: 1 }), { now: NOW }).ok, 'seat 1 fills the table (2/2)')
  const r = log.append(claimSeat(carol, { seat: 1 }), { now: NOW })
  // seat 1 taken → SEAT_TAKEN; but even a fresh in-range seat would be full.
  t.is(r.reason, REJECT.SEAT_TAKEN)
  t.is(log.writers.size, 2, 'no admission past the cap')
})

test('seat index outside [0,maxSeats) is SEAT_INVALID', (t) => {
  const host = makeKeyPair()
  const bob = makeKeyPair()
  const log = new SignedLog({ tableKey: TABLE, writers: [host.pubHex], maxSeats: 3 })
  t.is(log.append(claimSeat(bob, { seat: 5 }), { now: NOW }).reason, REJECT.SEAT_INVALID)
})

test('a private (fixed-roster) table has open-join disabled', (t) => {
  const alice = makeKeyPair()
  const bob = makeKeyPair()
  const carol = makeKeyPair()
  // maxSeats defaults to writers.length → already full.
  const log = new SignedLog({ tableKey: TABLE, writers: [alice.pubHex, bob.pubHex] })
  t.is(log.maxSeats, 2, 'default maxSeats == genesis writer count')
  t.is(log.append(claimSeat(carol, { seat: 0 }), { now: NOW }).reason, REJECT.SEAT_TAKEN)
  t.is(log.append(claimSeat(carol, { seat: 2 }), { now: NOW }).reason, REJECT.SEAT_INVALID)
  t.is(log.writers.size, 2, 'no stranger can join a private table')
})

// ── the scoped UNKNOWN_WRITER relaxation ─────────────────────────────────────

test('a non-writer CANNOT append a non-claim entry (forged action rejected)', (t) => {
  const host = makeKeyPair()
  const mallory = makeKeyPair()
  const log = new SignedLog({ tableKey: TABLE, writers: [host.pubHex], maxSeats: 4 })
  const r = log.append(action(mallory, { seq: 0 }), { now: NOW })
  t.is(r.reason, REJECT.UNKNOWN_WRITER, 'the relaxation is scoped to claim-seat only')
})

test('envelope control fields are signature-bound (tampered seat → BAD_SIG)', (t) => {
  const host = makeKeyPair()
  const bob = makeKeyPair()
  const log = new SignedLog({ tableKey: TABLE, writers: [host.pubHex], maxSeats: 4 })
  const good = claimSeat(bob, { seat: 1 })
  const tampered = { ...good, seat: 2 } // keep bob's signature, change the seat
  t.is(log.append(tampered, { now: NOW }).reason, REJECT.BAD_SIG, 'seat is bound into the signature')
})

test('ordinary entries are byte-identical to the legacy 5-part canonical', (t) => {
  const kp = makeKeyPair()
  const base = { tableKey: TABLE, writer: kp.pubHex, seq: 0, ts: NOW, payload: { type: 'x' } }
  // Same object with an explicit null kind must canonicalize identically to
  // no-kind — proving zero migration for every pre-existing signature.
  const a = SignedLog.canonicalBytes(base)
  const b = SignedLog.canonicalBytes({ ...base, kind: null })
  t.ok(b4a.equals(a, b), 'null kind adds nothing to the signed bytes')
})

// ── rate limiting ────────────────────────────────────────────────────────────

test('per-author claim-seat rate limit sheds a flood, then refills', (t) => {
  const host = makeKeyPair()
  const flooder = makeKeyPair()
  const log = new SignedLog({
    tableKey: TABLE, writers: [host.pubHex], maxSeats: 6, claimBurst: 2, claimRefillMs: 10000
  })
  // Seat 0 is the host's — every claim for it loses (stays a non-writer) but
  // still consumes a token, so we can watch the bucket drain.
  t.is(log.append(claimSeat(flooder, { seat: 0 }), { now: NOW }).reason, REJECT.SEAT_TAKEN, 'token 1')
  t.is(log.append(claimSeat(flooder, { seat: 0 }), { now: NOW }).reason, REJECT.SEAT_TAKEN, 'token 2')
  t.is(log.append(claimSeat(flooder, { seat: 0 }), { now: NOW }).reason, REJECT.RATE_LIMITED, 'bucket empty')
  // After a refill window one token returns.
  t.is(log.append(claimSeat(flooder, { seat: 0 }), { now: NOW + 10000 }).reason, REJECT.SEAT_TAKEN, 'refilled')
})

// ── revoke / kick ────────────────────────────────────────────────────────────

test('genesis revoke frees the seat and de-authorizes the target', (t) => {
  const host = makeKeyPair()
  const bob = makeKeyPair()
  const log = new SignedLog({ tableKey: TABLE, writers: [host.pubHex], maxSeats: 4 })
  t.ok(log.append(claimSeat(bob, { seat: 1 }), { now: NOW }).ok, 'bob joins')

  const r = log.append(revokeSeat(host, { seq: 0, target: bob.pubHex }), { now: NOW })
  t.ok(r.ok, 'host kicks bob')
  t.absent(log.writers.has(bob.pubHex), 'bob de-authorized')
  t.absent(log.state().seats[1], 'seat 1 freed')
  // A kicked player can no longer act.
  t.is(log.append(action(bob, { seq: 1 }), { now: NOW }).reason, REJECT.UNKNOWN_WRITER)
})

test('only the genesis may revoke, and genesis cannot be revoked', (t) => {
  const host = makeKeyPair()
  const bob = makeKeyPair()
  const log = new SignedLog({ tableKey: TABLE, writers: [host.pubHex], maxSeats: 4 })
  t.ok(log.append(claimSeat(bob, { seat: 1 }), { now: NOW }).ok)

  // bob is a writer but not genesis → cannot kick.
  t.is(log.append(revokeSeat(bob, { seq: 1, target: host.pubHex }), { now: NOW }).reason, REJECT.NOT_GENESIS)
  // host cannot revoke itself.
  t.is(log.append(revokeSeat(host, { seq: 0, target: host.pubHex }), { now: NOW }).reason, REJECT.NOT_GENESIS)
})

// ── rehydrate ────────────────────────────────────────────────────────────────

test('_replay reconstructs the writer set and seat map after restart', (t) => {
  const host = makeKeyPair()
  const bob = makeKeyPair()
  const carol = makeKeyPair()
  const live = new SignedLog({ tableKey: TABLE, writers: [host.pubHex], maxSeats: 4 })
  live.append(claimSeat(bob, { seat: 1 }), { now: NOW })
  live.append(claimSeat(carol, { seat: 2 }), { now: NOW })
  live.append(action(bob, { seq: 1 }), { now: NOW })
  live.append(revokeSeat(host, { seq: 0, target: carol.pubHex }), { now: NOW })

  const restored = new SignedLog({ tableKey: TABLE, writers: [host.pubHex], maxSeats: 4 })
  restored._replay(live.entries)

  t.ok(restored.writers.has(bob.pubHex), 'bob restored as writer')
  t.absent(restored.writers.has(carol.pubHex), 'kicked carol not restored')
  t.is(restored.state().seats[1], bob.pubHex, 'bob seat restored')
  t.absent(restored.state().seats[2], 'carol seat stays freed')
  t.alike(restored.state().writers, live.state().writers, 'writer cursors match live')
})

// ── PokerApp wiring ──────────────────────────────────────────────────────────

test('PokerApp.createTable forwards maxSeats + genesis; listTables/getState expose seats', (t) => {
  const host = makeKeyPair()
  const app = new PokerApp()
  app.createTable({ tableKey: TABLE, writers: [host.pubHex], maxSeats: 6 })

  const bob = makeKeyPair()
  // submitEntry uses the real wall clock (no injected now), so sign with a
  // current timestamp rather than the fixed test epoch.
  const r = app.submitEntry(TABLE, claimSeat(bob, { seat: 1, ts: Date.now() }))
  t.ok(r.ok, 'claim-seat routes through submitEntry')

  const st = app.getState(TABLE)
  t.is(st.maxSeats, 6)
  t.is(st.seats[0], host.pubHex, 'genesis seated at 0')
  t.is(st.seats[1], bob.pubHex, 'claimer seated at 1')

  const listed = app.listTables().find((x) => x.tableKey === TABLE)
  t.is(listed.writers, 2, 'writer count reflects the admitted claimer')
  t.is(listed.maxSeats, 6)
  t.ok(listed.open, 'table still has free seats')
})
