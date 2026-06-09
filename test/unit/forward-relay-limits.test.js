/**
 * forward-relay dial-policy regression tests.
 *
 * When an operator enables forwardRelay, the relay dials DHT peers on a
 * client's behalf. Two gaps the audit flagged:
 *   - allowTarget was never wired, so an enabled relay would dial ANY
 *     32-byte pubkey on demand (DHT scanning / connection laundering).
 *   - only a per-peer CONCURRENCY cap existed; a peer could churn
 *     OPEN/CLOSE to dial in a tight loop without exceeding it.
 *
 * These tests exercise the policy directly with a stubbed swarm — no DHT.
 */

import test from 'brittle'
import { EventEmitter } from 'events'
import b4a from 'b4a'
import { ForwardRelay } from 'p2p-hiverelay/core/protocol/forward-relay.js'

// STATUS codes (mirror forward-relay.js)
const OK = 0
const ERR_CAPACITY = 2
const ERR_TARGET = 3

function fakeStream () {
  const s = new EventEmitter()
  s.write = () => {}
  s.destroy = () => {}
  return s
}

function makeRelay (opts = {}) {
  const swarm = { dht: { connect: () => fakeStream() } }
  return new ForwardRelay(swarm, opts)
}

// Build a fresh forward channel for `peer`, returning the channel plus a
// captured list of STATUS messages the relay sent back on it.
function makeChannel (peerHex) {
  const sent = []
  const peer = b4a.from(peerHex, 'hex')
  const channel = { _mux: { stream: { remotePublicKey: peer } }, _forward: { state: null } }
  const msgs = {
    statusMsg: { send: (m) => sent.push(m) },
    dataMsg: { send: () => {} },
    closeMsg: { send: () => {} }
  }
  return { channel, msgs, sent }
}

const PEER = 'a'.repeat(64)
const target = (hexChar) => b4a.from(hexChar.repeat(64), 'hex')

test('_allowDial: allows up to the cap then blocks within the window', (t) => {
  const fr = makeRelay({ maxDialsPerMinPerPeer: 3 })
  t.ok(fr._allowDial(PEER), 'dial 1 allowed')
  t.ok(fr._allowDial(PEER), 'dial 2 allowed')
  t.ok(fr._allowDial(PEER), 'dial 3 allowed')
  t.absent(fr._allowDial(PEER), 'dial 4 blocked (cap reached)')
  // A different peer has its own budget.
  t.ok(fr._allowDial('b'.repeat(64)), 'other peer unaffected')
})

test('_onOpen: rejects a target not in the allowlist', (t) => {
  const fr = makeRelay({ allowTarget: () => false })
  const { channel, msgs, sent } = makeChannel(PEER)
  fr._onOpen(channel, { target: target('c') }, msgs)
  t.is(sent.length, 1)
  t.is(sent[0].code, ERR_TARGET, 'disallowed target rejected with ERR_TARGET')
  t.is(channel._forward.state, null, 'no forward opened')
})

test('_onOpen: allowed target opens (status OK)', (t) => {
  const fr = makeRelay({ allowTarget: (tHex) => tHex === 'c'.repeat(64) })
  const { channel, msgs, sent } = makeChannel(PEER)
  fr._onOpen(channel, { target: target('c') }, msgs)
  t.is(sent[0].code, OK, 'allowed target gets OK')
  t.ok(channel._forward.state, 'forward state established')
})

test('_onOpen: dial-rate cap rejects once exceeded (separate forwards, same peer)', (t) => {
  const fr = makeRelay({ maxDialsPerMinPerPeer: 2 })
  const codes = []
  for (let i = 0; i < 3; i++) {
    const { channel, msgs, sent } = makeChannel(PEER)
    fr._onOpen(channel, { target: target(['c', 'd', 'e'][i]) }, msgs)
    codes.push(sent[0].code)
  }
  t.is(codes[0], OK, 'dial 1 ok')
  t.is(codes[1], OK, 'dial 2 ok')
  t.is(codes[2], ERR_CAPACITY, 'dial 3 hits the rate cap')
})
