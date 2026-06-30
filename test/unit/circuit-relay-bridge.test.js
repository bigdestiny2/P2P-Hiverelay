// circuit-relay-bridge: v0.8.19 regression tests for the proper bridge
// data plane.
//
// Background: prior to v0.8.19, _bridgeCircuit called Relay.createCircuit
// with `channel.stream` arguments — but `channel.stream` is undefined in
// modern protomux (the Channel class only exposes `_mux.stream`). The
// reservation handshake completed successfully on the wire, but no
// actual bridged data ever flowed. PearPaste was the first customer to
// drive a flow that reached the bridge code and discovered the gap.
//
// Same release fixes a silent auth bypass — the reserve/connect identity
// checks were reading channel.stream?.remotePublicKey (always undefined),
// causing the check to short-circuit to "pass" and allowing any peer to
// reserve under any pubkey. Now reads channel._mux.stream.remotePublicKey.
//
// These tests do not stand up a real swarm. They mock protomux channels
// (with _hiverelay message senders that record calls) and a mock Relay
// (which tracks registerCircuit/recordCircuitBytes/closeCircuit calls).
// That's enough to exercise the routing/auth/accounting logic.

import test from 'brittle'
import b4a from 'b4a'
import { CircuitRelay, REASON_CODES } from 'p2p-hiverelay/core/protocol/relay-circuit.js'
import { ERR } from 'p2p-hiverelay/core/protocol/messages.js'

// ─── Test helpers ─────────────────────────────────────────────────

function pub (byteVal) {
  // 32-byte fake pubkey filled with a known byte
  return b4a.alloc(32, byteVal)
}

function makeMockChannel ({ remotePubkey = null } = {}) {
  const sends = {
    statusMsg: [],
    dataMsg: [],
    readyMsg: [],
    closeMsg: []
  }
  const channel = {
    opened: true,
    closed: false,
    _hiverelay: null,
    // The underlying _mux.stream is what the v0.8.19 auth check reads.
    // Set remotePublicKey here to simulate the noise-authenticated peer.
    _mux: {
      stream: remotePubkey ? { remotePublicKey: remotePubkey } : { remotePublicKey: null }
    }
  }
  // _hiverelay senders capture the outgoing payload so tests can assert
  // on what got sent to whom.
  channel._hiverelay = {
    reserveMsg: { send: (msg) => sends.reserveMsg && sends.reserveMsg.push(msg) },
    connectMsg: { send: (msg) => sends.connectMsg && sends.connectMsg.push(msg) },
    statusMsg: { send: (msg) => sends.statusMsg.push(msg) },
    dataMsg: { send: (msg) => sends.dataMsg.push(msg) },
    readyMsg: { send: (msg) => sends.readyMsg.push(msg) },
    closeMsg: { send: (msg) => sends.closeMsg.push(msg) }
  }
  channel.sends = sends
  return channel
}

function makeMockRelay ({ atCapacity = false, perPeerCap = 5 } = {}) {
  const calls = { register: [], record: [], close: [] }
  return {
    circuits: new Map(),
    maxConnections: atCapacity ? 0 : 256,
    maxCircuitsPerPeer: perPeerCap,
    registerCircuit (circuitId, sourcePeerKey, maxBytes) {
      calls.register.push({ circuitId, sourcePeerKey, maxBytes })
      if (atCapacity) return false
      return true
    },
    recordCircuitBytes (circuitId, bytes) {
      calls.record.push({ circuitId, bytes })
      return true
    },
    closeCircuit (circuitId, reason) {
      calls.close.push({ circuitId, reason })
    },
    _calls: calls
  }
}

// ─── Tests ────────────────────────────────────────────────────────

test('reserve+connect bridges a circuit and sends ready to BOTH peers', (t) => {
  const cr = new CircuitRelay(null, makeMockRelay())
  t.teardown(() => cr.destroy())
  const alice = pub(0xAA)
  const bob = pub(0xBB)

  const aliceChannel = makeMockChannel({ remotePubkey: alice })
  const bobChannel = makeMockChannel({ remotePubkey: bob })

  // Alice reserves.
  cr._onReserve(aliceChannel, { peerPubkey: alice })
  t.is(aliceChannel.sends.statusMsg.length, 1, 'reserve responded with status')
  t.is(aliceChannel.sends.statusMsg[0].code, ERR.NONE, 'reserve status code is NONE (accepted)')

  // Bob connects targeting Alice.
  cr._onConnect(bobChannel, { targetPubkey: alice, sourcePubkey: bob })

  // Both sides should now have received a ready message with the
  // OTHER peer's pubkey + the same circuitId.
  t.is(aliceChannel.sends.readyMsg.length, 1, 'alice got ready')
  t.is(bobChannel.sends.readyMsg.length, 1, 'bob got ready')
  t.ok(b4a.equals(aliceChannel.sends.readyMsg[0].remotePubkey, bob), 'alice ready carries bob pubkey')
  t.ok(b4a.equals(bobChannel.sends.readyMsg[0].remotePubkey, alice), 'bob ready carries alice pubkey')
  t.ok(b4a.equals(aliceChannel.sends.readyMsg[0].circuitId, bobChannel.sends.readyMsg[0].circuitId),
    'both peers see the same circuitId')
  t.is(aliceChannel.sends.readyMsg[0].circuitId.byteLength, 16, 'circuitId is 16 bytes')

  t.is(cr.activeCircuits.size, 1, 'one active circuit tracked')
})

test('data sent on one channel is forwarded to the other', (t) => {
  const cr = new CircuitRelay(null, makeMockRelay())
  t.teardown(() => cr.destroy())
  const alice = pub(0xAA)
  const bob = pub(0xBB)

  const aliceChannel = makeMockChannel({ remotePubkey: alice })
  const bobChannel = makeMockChannel({ remotePubkey: bob })

  cr._onReserve(aliceChannel, { peerPubkey: alice })
  cr._onConnect(bobChannel, { targetPubkey: alice, sourcePubkey: bob })
  const circuitId = aliceChannel.sends.readyMsg[0].circuitId

  // Alice sends data through the circuit.
  const payload = b4a.from('hello bob, this is alice')
  cr._onCircuitData(aliceChannel, { circuitId, data: payload })

  t.is(bobChannel.sends.dataMsg.length, 1, 'bob received forwarded data')
  t.ok(b4a.equals(bobChannel.sends.dataMsg[0].data, payload), 'payload arrives intact')
  t.is(aliceChannel.sends.dataMsg.length, 0, 'alice does not receive her own data back')

  // Reverse direction.
  const reply = b4a.from('hi alice')
  cr._onCircuitData(bobChannel, { circuitId, data: reply })
  t.is(aliceChannel.sends.dataMsg.length, 1, 'alice received reply')
  t.ok(b4a.equals(aliceChannel.sends.dataMsg[0].data, reply), 'reply arrives intact')
})

test('data from a non-endpoint channel is dropped (no impersonation)', (t) => {
  const cr = new CircuitRelay(null, makeMockRelay())
  t.teardown(() => cr.destroy())
  const alice = pub(0xAA)
  const bob = pub(0xBB)
  const eve = pub(0xEE)

  const aliceChannel = makeMockChannel({ remotePubkey: alice })
  const bobChannel = makeMockChannel({ remotePubkey: bob })
  const eveChannel = makeMockChannel({ remotePubkey: eve })

  cr._onReserve(aliceChannel, { peerPubkey: alice })
  cr._onConnect(bobChannel, { targetPubkey: alice, sourcePubkey: bob })
  const circuitId = aliceChannel.sends.readyMsg[0].circuitId

  // Eve learned the circuitId somehow and tries to inject data.
  cr._onCircuitData(eveChannel, { circuitId, data: b4a.from('mwahaha') })

  t.is(aliceChannel.sends.dataMsg.length, 0, 'alice did not receive eve traffic')
  t.is(bobChannel.sends.dataMsg.length, 0, 'bob did not receive eve traffic')
})

test('data for unknown circuitId is dropped silently (no feedback to attacker)', (t) => {
  const cr = new CircuitRelay(null, makeMockRelay())
  t.teardown(() => cr.destroy())
  const alice = pub(0xAA)
  const aliceChannel = makeMockChannel({ remotePubkey: alice })

  // Random 16-byte circuitId, no matching bridge.
  const fakeId = b4a.alloc(16, 0xFF)
  cr._onCircuitData(aliceChannel, { circuitId: fakeId, data: b4a.from('ping') })

  t.is(aliceChannel.sends.dataMsg.length, 0, 'no echo')
  t.is(aliceChannel.sends.closeMsg.length, 0, 'no close to dox the lookup')
})

test('per-frame size cap closes the circuit (DoS guard)', (t) => {
  const relayMock = makeMockRelay()
  const cr = new CircuitRelay(null, relayMock, { maxDataMsgBytes: 100 })
  t.teardown(() => cr.destroy())
  const alice = pub(0xAA)
  const bob = pub(0xBB)

  const aliceChannel = makeMockChannel({ remotePubkey: alice })
  const bobChannel = makeMockChannel({ remotePubkey: bob })

  cr._onReserve(aliceChannel, { peerPubkey: alice })
  cr._onConnect(bobChannel, { targetPubkey: alice, sourcePubkey: bob })
  const circuitId = aliceChannel.sends.readyMsg[0].circuitId

  // Send a frame larger than the cap.
  const big = b4a.alloc(200, 0x42)
  cr._onCircuitData(aliceChannel, { circuitId, data: big })

  t.is(bobChannel.sends.dataMsg.length, 0, 'oversized frame not forwarded')
  t.is(cr.activeCircuits.size, 0, 'circuit was torn down')
  t.is(relayMock._calls.close.length, 1, 'relay was notified of close')
  t.is(relayMock._calls.close[0].reason, 'FRAME_TOO_LARGE')
})

test('per-circuit byte cap closes the circuit when reached', (t) => {
  const relayMock = makeMockRelay()
  const cr = new CircuitRelay(null, relayMock, { maxCircuitBytes: 50 })
  t.teardown(() => cr.destroy())
  const alice = pub(0xAA)
  const bob = pub(0xBB)

  const aliceChannel = makeMockChannel({ remotePubkey: alice })
  const bobChannel = makeMockChannel({ remotePubkey: bob })

  cr._onReserve(aliceChannel, { peerPubkey: alice })
  cr._onConnect(bobChannel, { targetPubkey: alice, sourcePubkey: bob })
  const circuitId = aliceChannel.sends.readyMsg[0].circuitId

  // First frame: 30 bytes, under cap.
  cr._onCircuitData(aliceChannel, { circuitId, data: b4a.alloc(30, 0x01) })
  t.is(bobChannel.sends.dataMsg.length, 1, 'first frame forwarded')

  // Second frame: 30 bytes, would push total to 60 > 50.
  cr._onCircuitData(aliceChannel, { circuitId, data: b4a.alloc(30, 0x02) })
  t.is(bobChannel.sends.dataMsg.length, 1, 'second frame NOT forwarded')
  t.is(cr.activeCircuits.size, 0, 'circuit torn down')
  t.is(relayMock._calls.close[0].reason, 'BYTES_EXCEEDED')
})

test('per-circuit rate cap closes the circuit when exceeded', (t) => {
  const relayMock = makeMockRelay()
  const cr = new CircuitRelay(null, relayMock, { maxCircuitRateBytesPerSecond: 50 })
  t.teardown(() => cr.destroy())
  const alice = pub(0xAA)
  const bob = pub(0xBB)

  const aliceChannel = makeMockChannel({ remotePubkey: alice })
  const bobChannel = makeMockChannel({ remotePubkey: bob })

  cr._onReserve(aliceChannel, { peerPubkey: alice })
  cr._onConnect(bobChannel, { targetPubkey: alice, sourcePubkey: bob })
  const circuitId = aliceChannel.sends.readyMsg[0].circuitId

  cr._onCircuitData(aliceChannel, { circuitId, data: b4a.alloc(30, 0x01) })
  t.is(bobChannel.sends.dataMsg.length, 1, 'first frame forwarded')

  cr._onCircuitData(aliceChannel, { circuitId, data: b4a.alloc(30, 0x02) })
  t.is(bobChannel.sends.dataMsg.length, 1, 'second frame not forwarded')
  t.is(cr.activeCircuits.size, 0, 'circuit torn down')
  t.is(relayMock._calls.close[0].reason, 'RATE_EXCEEDED')
})

test('circuit duration cap closes stale active circuits in the bridge layer', (t) => {
  const relayMock = makeMockRelay()
  const cr = new CircuitRelay(null, relayMock, { maxCircuitDuration: 50 })
  t.teardown(() => cr.destroy())
  const alice = pub(0xAA)
  const bob = pub(0xBB)

  const aliceChannel = makeMockChannel({ remotePubkey: alice })
  const bobChannel = makeMockChannel({ remotePubkey: bob })

  cr._onReserve(aliceChannel, { peerPubkey: alice })
  cr._onConnect(bobChannel, { targetPubkey: alice, sourcePubkey: bob })
  const circuitId = aliceChannel.sends.readyMsg[0].circuitId
  const circuit = cr.activeCircuits.get(b4a.toString(circuitId, 'hex'))
  circuit.startedAt = Date.now() - 51

  cr._onCircuitData(aliceChannel, { circuitId, data: b4a.alloc(1, 0x01) })

  t.is(bobChannel.sends.dataMsg.length, 0, 'stale circuit data not forwarded')
  t.is(cr.activeCircuits.size, 0, 'circuit torn down')
  t.is(relayMock._calls.close[0].reason, 'DURATION_EXCEEDED')
})

test('single-argument CircuitRelay constructor keeps Bare relay compatibility', (t) => {
  const relayMock = makeMockRelay()
  const cr = new CircuitRelay(relayMock)
  t.teardown(() => cr.destroy())

  t.is(cr.relay, relayMock)
  t.is(cr.swarm, null)
})

test('reserve with mismatched pubkey is REJECTED (auth bypass closed)', (t) => {
  const cr = new CircuitRelay(null, makeMockRelay())
  t.teardown(() => cr.destroy())
  const alice = pub(0xAA)
  const mallory = pub(0xCC)

  // Mallory's channel is authenticated as mallory, but the reserve
  // payload claims to be alice. Pre-v0.8.19 this silently passed
  // because channel.stream was undefined. v0.8.19 reads _mux.stream
  // correctly and catches it.
  const malloryChannel = makeMockChannel({ remotePubkey: mallory })
  cr._onReserve(malloryChannel, { peerPubkey: alice })

  t.is(malloryChannel.sends.statusMsg.length, 1, 'got a status response')
  t.is(malloryChannel.sends.statusMsg[0].code, ERR.NOT_FOUND, 'reserve rejected')
  t.is(malloryChannel.sends.statusMsg[0].message, 'Peer identity mismatch')
  t.is(cr.reservations.size, 0, 'no reservation granted')
})

test('connect with mismatched sourcePubkey is REJECTED (auth bypass closed)', (t) => {
  const cr = new CircuitRelay(null, makeMockRelay())
  t.teardown(() => cr.destroy())
  const alice = pub(0xAA)
  const bob = pub(0xBB)
  const mallory = pub(0xCC)

  // Alice has a real reservation.
  const aliceChannel = makeMockChannel({ remotePubkey: alice })
  cr._onReserve(aliceChannel, { peerPubkey: alice })

  // Mallory tries to connect to Alice but claims to be Bob.
  const malloryChannel = makeMockChannel({ remotePubkey: mallory })
  cr._onConnect(malloryChannel, { targetPubkey: alice, sourcePubkey: bob })

  t.is(malloryChannel.sends.statusMsg.length, 1, 'got a status response')
  t.is(malloryChannel.sends.statusMsg[0].code, ERR.NOT_FOUND, 'connect rejected')
  t.is(malloryChannel.sends.statusMsg[0].message, 'Source identity mismatch')
  t.is(cr.activeCircuits.size, 0, 'no bridge established')
})

test('connect before reserve queues the pending connect (existing semantics preserved)', (t) => {
  const cr = new CircuitRelay(null, makeMockRelay())
  t.teardown(() => cr.destroy())
  const alice = pub(0xAA)
  const bob = pub(0xBB)

  const bobChannel = makeMockChannel({ remotePubkey: bob })

  // Bob connects before Alice reserves.
  cr._onConnect(bobChannel, { targetPubkey: alice, sourcePubkey: bob })
  t.is(bobChannel.sends.statusMsg.length, 1, 'got a status response')
  t.is(bobChannel.sends.statusMsg[0].code, ERR.NOT_FOUND, 'queued, not bridged yet')
  t.is(cr.pendingConnects.size, 1, 'pending connect queued')

  // Now Alice reserves.
  const aliceChannel = makeMockChannel({ remotePubkey: alice })
  cr._onReserve(aliceChannel, { peerPubkey: alice })

  // The pending connect should have fired.
  t.is(cr.activeCircuits.size, 1, 'pending connect bridged on reserve')
  t.is(aliceChannel.sends.readyMsg.length, 1, 'alice got ready')
  t.is(bobChannel.sends.readyMsg.length, 1, 'bob got ready')
})

test('channel close tears down circuits the channel was part of', (t) => {
  const relayMock = makeMockRelay()
  const cr = new CircuitRelay(null, relayMock)
  t.teardown(() => cr.destroy())
  const alice = pub(0xAA)
  const bob = pub(0xBB)

  const aliceChannel = makeMockChannel({ remotePubkey: alice })
  const bobChannel = makeMockChannel({ remotePubkey: bob })

  cr._onReserve(aliceChannel, { peerPubkey: alice })
  cr._onConnect(bobChannel, { targetPubkey: alice, sourcePubkey: bob })
  t.is(cr.activeCircuits.size, 1, 'circuit established')

  // Bob's channel drops.
  cr._onChannelClose(bobChannel)

  t.is(cr.activeCircuits.size, 0, 'circuit torn down')
  // Alice should have been notified of close.
  t.is(aliceChannel.sends.closeMsg.length, 1, 'alice notified of close')
  t.is(aliceChannel.sends.closeMsg[0].reason, REASON_CODES.PEER_CLOSED, 'reason is PEER_CLOSED')
})

test('relay at-capacity refuses to register new circuit', (t) => {
  const relayMock = makeMockRelay({ atCapacity: true })
  const cr = new CircuitRelay(null, relayMock)
  t.teardown(() => cr.destroy())
  const alice = pub(0xAA)
  const bob = pub(0xBB)

  // With atCapacity, `relay.circuits.size >= relay.maxConnections` is
  // true (0 >= 0), so the reserve itself gets rejected before we even
  // attempt to bridge. Tweak the mock to allow reservation but reject
  // registration — that's the real "tons of reservations queued, one
  // tries to bridge" scenario.
  relayMock.maxConnections = 256 // allow reservation

  const aliceChannel = makeMockChannel({ remotePubkey: alice })
  const bobChannel = makeMockChannel({ remotePubkey: bob })

  cr._onReserve(aliceChannel, { peerPubkey: alice })
  cr._onConnect(bobChannel, { targetPubkey: alice, sourcePubkey: bob })

  // Bridge attempt would have called registerCircuit, which returns
  // false in atCapacity mode.
  t.is(relayMock._calls.register.length, 1, 'attempted to register')
  t.is(cr.activeCircuits.size, 0, 'no active circuit')
  t.is(bobChannel.sends.statusMsg.length, 1, 'bob got status (capacity full)')
  t.is(bobChannel.sends.statusMsg[0].code, ERR.CAPACITY_FULL, 'rejected as capacity full')
})

test('getStats reports activeCircuits in addition to reservations', (t) => {
  const cr = new CircuitRelay(null, makeMockRelay())
  t.teardown(() => cr.destroy())
  const alice = pub(0xAA)
  const bob = pub(0xBB)

  const aliceChannel = makeMockChannel({ remotePubkey: alice })
  const bobChannel = makeMockChannel({ remotePubkey: bob })

  cr._onReserve(aliceChannel, { peerPubkey: alice })
  cr._onConnect(bobChannel, { targetPubkey: alice, sourcePubkey: bob })

  const stats = cr.getStats()
  t.is(stats.activeReservations, 1)
  t.is(stats.pendingConnects, 0)
  t.is(stats.activeCircuits, 1, 'new field exposed in v0.8.19')
})
