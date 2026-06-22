/**
 * Poker pubsub producer: an accepted append fans out on the PER-TABLE topic
 * `poker/<tableKey>` (consumed by client.subscribeService('poker', tableKey)).
 * Per-table (not a global firehose) so a subscriber only sees its own table;
 * rejected entries don't publish; hydration (replay) is silent; and a node
 * without pubsub still appends fine.
 */
import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { PokerApp } from 'p2p-hiveservices/builtin/poker/index.js'
import { SignedLog } from 'p2p-hiveservices/builtin/poker/signed-log.js'

const TABLE = 'a'.repeat(64)

function keypair () {
  const pk = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const sk = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(pk, sk)
  return { sk, hex: b4a.toString(pk, 'hex') }
}
function signedEntry (writer, seq, payload) {
  const e = { tableKey: TABLE, writer: writer.hex, seq, ts: Date.now(), payload }
  const sig = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(sig, SignedLog.canonicalBytes(e), writer.sk)
  e.signature = b4a.toString(sig, 'hex')
  return e
}
function pubsubNode () {
  const published = []
  return { node: { router: { pubsub: { publish: (topic, data) => published.push({ topic, data }) } } }, published }
}

test('accepted append publishes to the per-table topic poker/<tableKey>', async (t) => {
  const w = keypair()
  const { node, published } = pubsubNode()
  const app = new PokerApp(); await app.start({ node })
  app.createTable({ tableKey: TABLE, writers: [w.hex] })

  const res = app.submitEntry(TABLE, signedEntry(w, 0, { move: 'check' }))
  t.ok(res.ok, 'entry accepted')
  t.is(published.length, 1, 'exactly one publish')
  t.is(published[0].topic, 'poker/' + TABLE, 'per-table topic, not a global firehose')
  t.is(published[0].data.tableKey, TABLE)
  t.is(published[0].data.index, 0)
  t.alike(published[0].data.entry.payload, { move: 'check' }, 'payload verbatim — relay adds nothing (card-blind)')
  await app.stop()
})

test('rejected append (unknown writer) is NOT published', async (t) => {
  const w = keypair(); const stranger = keypair()
  const { node, published } = pubsubNode()
  const app = new PokerApp(); await app.start({ node })
  app.createTable({ tableKey: TABLE, writers: [w.hex] })
  const res = app.submitEntry(TABLE, signedEntry(stranger, 0, {}))
  t.absent(res.ok, 'rejected')
  t.is(published.length, 0, 'nothing published for a rejected entry')
  await app.stop()
})

test('hydration via replayEntries does NOT re-publish history', async (t) => {
  const w = keypair()
  const { node, published } = pubsubNode()
  const app = new PokerApp(); await app.start({ node })
  app.createTable({ tableKey: TABLE, writers: [w.hex] })
  app.replayEntries(TABLE, [signedEntry(w, 0, {})])
  t.is(published.length, 0, 'replay is silent — restarts do not re-emit the backlog')
  await app.stop()
})

test('node without pubsub: append still succeeds, no crash', async (t) => {
  const w = keypair()
  const app = new PokerApp(); await app.start({ node: {} })
  app.createTable({ tableKey: TABLE, writers: [w.hex] })
  t.ok(app.submitEntry(TABLE, signedEntry(w, 0, {})).ok, 'append works without a pubsub')
  await app.stop()
})

test('topic is canonical-lowercase even when the table key is upper/mixed-case', async (t) => {
  // The relay lowercases tableKeys; the topic must too, so a subscriber that
  // passes the lowercase key (per subscribeService docs) always matches.
  const w = keypair()
  const { node, published } = pubsubNode()
  const app = new PokerApp(); await app.start({ node })
  const UPPER = TABLE.toUpperCase()
  app.createTable({ tableKey: UPPER, writers: [w.hex] })
  const e = { tableKey: UPPER, writer: w.hex, seq: 0, ts: Date.now(), payload: {} }
  const sig = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(sig, SignedLog.canonicalBytes(e), w.sk)
  e.signature = b4a.toString(sig, 'hex')
  t.ok(app.submitEntry(UPPER, e).ok, 'accepted')
  t.is(published[0].topic, 'poker/' + TABLE, 'published to the lowercase topic regardless of input case')
  await app.stop()
})
