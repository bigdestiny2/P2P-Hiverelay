// Runnable walkthrough of the async two-player turn loop on the blind
// substrate.
//
// Two players (Alice = side 0, Bob = side 1) play three WeGo turns against
// one relay. All substrate operations are real (sealed cells, read
// capabilities, inbox frames, watch requests); the HTTP transport is
// simulated by an in-memory relay so the example runs with no daemon:
// replace InMemoryRelay's put/fetch with blind-client transport calls
// against a QualifiedEndpoint for production use.

import b4a from 'b4a'
import { createNodeCryptoRuntime } from '@hiverelay/blind-client/runtime/node'
import {
  ACTIVE_GAME_LEASE_CLASS,
  canonicalString,
  createPlayerInbox,
  makeCommitment,
  makePoke,
  makeReveal,
  makeWatch,
  openSealedEntry,
  verifyReveal
} from './adapter.js'
import { initialState, resolveTurn, stateHash } from './game-sim.js'

const runtime = createNodeCryptoRuntime()
const relayPublicKey = b4a.alloc(32, 0xA1)
const admission = { profileId: 1, schemeId: 1, parameterHash: b4a.alloc(32, 0xB2), token: b4a.from([1]) }
const gameId = 'example-game-001'
const epoch = 1000

// Stand-in for a blind relay's cell store + inboxes: opaque ciphertext and
// fixed-size frames only. Replace put/fetch/append with blind-client
// transport calls against a QualifiedEndpoint for production use.
class InMemoryRelay {
  constructor () { this.cells = new Map(); this.frames = 0 }
  async put (request) { this.cells.set(b4a.toString(request.storageSlot, 'hex'), request.cellBlob) }
  async fetch (readCap) { return this.cells.get(readCap.storageSlot) }
  async append () { this.frames += 1 }
}

const relay = new InMemoryRelay()
const state = initialState({ gameId, seed: 42, turns: 8 })
console.log(`game ${gameId} — initial state hash ${stateHash(state).slice(0, 16)}…`)

// Each player owns an inbox the opponent can poke (capability rendezvous).
const aliceInbox = await createPlayerInbox({ runtime, relayPublicKey, allocationEpoch: epoch, admission })
const bobInbox = await createPlayerInbox({ runtime, relayPublicKey, allocationEpoch: epoch, admission })

// Both players' move scripts for the demo (three sealed turns).
const aliceOrders = [
  { A1: { type: 'MOVE', dx: 3 }, A2: { type: 'FIRE', targetId: 'B1' } },
  { A1: { type: 'MOVE', dx: 3 }, A2: { type: 'FIRE', targetId: 'B1' } },
  { A1: { type: 'MOVE', dx: 3 }, A2: { type: 'MOVE', dx: 2 } }
]
const bobOrders = [
  { B1: { type: 'FIRE', targetId: 'A2' }, B2: { type: 'MOVE', dx: -1 } },
  { B1: { type: 'FIRE', targetId: 'A2' }, B2: { type: 'MOVE', dx: -1 } },
  { B1: { type: 'FIRE', targetId: 'A1' }, B2: { type: 'FIRE', targetId: 'A2' } }
]

let current = state
for (let turn = 1; turn <= 3; turn++) {
  // --- commit phase: only hashes are published ---
  const nonceA = b4a.toString(runtime.randomBytes(16), 'hex')
  const nonceB = b4a.toString(runtime.randomBytes(16), 'hex')
  const commitA = await makeCommitment({ runtime, relayPublicKey, allocationEpoch: epoch, admission, gameId, turn, player: 0, orders: aliceOrders[turn - 1], nonce: nonceA })
  const commitB = await makeCommitment({ runtime, relayPublicKey, allocationEpoch: epoch, admission, gameId, turn, player: 1, orders: bobOrders[turn - 1], nonce: nonceB })
  await relay.put(commitA.request)
  await relay.put(commitB.request)
  console.log(`turn ${turn}: commitments sealed (lease L${ACTIVE_GAME_LEASE_CLASS}) — relay sees ${commitA.request.cellBlob.byteLength} opaque bytes per commit`)

  // --- reveal phase: sealed entries + read-capability pokes to the
  // opponent's inbox ---
  const revealA = await makeReveal({ runtime, relayPublicKey, allocationEpoch: epoch, admission, gameId, turn, player: 0, orders: aliceOrders[turn - 1], nonce: nonceA })
  const revealB = await makeReveal({ runtime, relayPublicKey, allocationEpoch: epoch, admission, gameId, turn, player: 1, orders: bobOrders[turn - 1], nonce: nonceB })
  await relay.put(revealA.request)
  await relay.put(revealB.request)
  const pokeA = await makePoke({ runtime, inboxReadCap: bobInbox.readCap, cellReadCap: revealA.readCap, admission })
  const pokeB = await makePoke({ runtime, inboxReadCap: aliceInbox.readCap, cellReadCap: revealB.readCap, admission })
  await relay.append(pokeA)
  await relay.append(pokeB)

  // --- opponent side: watch fires, open, verify commitment, resolve ---
  const watchA = await makeWatch({ runtime, readCap: aliceInbox.readCap, afterRevision: BigInt(relay.frames), admission })
  const watchB = await makeWatch({ runtime, readCap: bobInbox.readCap, afterRevision: BigInt(relay.frames), admission })
  const openedA = await openSealedEntry({ runtime, readCap: serializeCap(revealA.readCap), cellBlob: await relay.fetch(serializeCap(revealA.readCap)) })
  const openedB = await openSealedEntry({ runtime, readCap: serializeCap(revealB.readCap), cellBlob: await relay.fetch(serializeCap(revealB.readCap)) })
  const commitAEntry = await openSealedEntry({ runtime, readCap: serializeCap(commitA.readCap), cellBlob: await relay.fetch(serializeCap(commitA.readCap)) })
  const commitBEntry = await openSealedEntry({ runtime, readCap: serializeCap(commitB.readCap), cellBlob: await relay.fetch(serializeCap(commitB.readCap)) })

  const violationA = verifyReveal({ commitEntry: commitAEntry, revealEntry: openedA })
  const violationB = verifyReveal({ commitEntry: commitBEntry, revealEntry: openedB })
  if (violationA || violationB) throw new Error(`protocol violation: ${violationA || violationB}`)

  console.log(`turn ${turn}: pokes delivered, reveals verified against commitments (watch armed at ${watchA.request.maxWaitMillis}ms max wait)`)

  current = resolveTurn(current, openedA.orders, openedB.orders)
  console.log(`turn ${turn}: resolved — state hash ${stateHash(current).slice(0, 16)}… units ${canonicalString(current.units)}`)
}

console.log(`game over — winner side ${current.winner}; relay stored ${relay.frames} opaque pokes and never saw an order`)

function serializeCap (readCap) {
  return {
    storageSlot: b4a.toString(readCap.storageSlot, 'hex'),
    sizeClass: readCap.sizeClass,
    cellKey: b4a.toString(readCap.cellKey, 'hex')
  }
}
