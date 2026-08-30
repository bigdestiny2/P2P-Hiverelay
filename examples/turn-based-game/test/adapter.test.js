// Adapter property tests. Run: npm test (node:test)
import test from 'node:test'
import assert from 'node:assert/strict'
import b4a from 'b4a'
import { createNodeCryptoRuntime } from '@hiverelay/blind-client/runtime/node'
import {
  canonicalString,
  commitmentHash,
  verifyReveal
} from '../adapter.js'
import { initialState, resolveTurn, stateHash } from '../game-sim.js'

const runtime = createNodeCryptoRuntime()
const gameId = 'test-game'

test('canonical encoding is key-order independent', () => {
  const a = { z: 1, a: { y: [2, { b: 1, a: 2 }], x: 's' }, m: null }
  const b = { m: null, a: { x: 's', y: [2, { a: 2, b: 1 }] }, z: 1 }
  assert.equal(canonicalString(a), canonicalString(b))
})

test('commitment binds orders, nonce, turn and game', () => {
  const orders = [{ unitId: 'A1', type: 'MOVE', dx: 3 }]
  const base = { orders, nonce: 'n0', turn: 1, gameId }
  const h = commitmentHash(base)
  const changed = (over) => commitmentHash({ ...base, ...over })
  assert.notEqual(changed({ orders: [{ unitId: 'A1', type: 'MOVE', dx: 2 }] }).toString('hex'), h.toString('hex'))
  assert.notEqual(changed({ nonce: 'n1' }).toString('hex'), h.toString('hex'))
  assert.notEqual(changed({ turn: 2 }).toString('hex'), h.toString('hex'))
  assert.notEqual(changed({ gameId: 'other-game' }).toString('hex'), h.toString('hex'))
  assert.equal(changed({}).toString('hex'), h.toString('hex'))
})

test('verifyReveal accepts authentic reveal, rejects tampering', () => {
  const orders = { A1: { type: 'MOVE', dx: 3 } }
  const nonce = 'n0'
  const turn = 1
  const commitEntry = {
    kind: 'COMMIT', gameId, turn, player: 0,
    commitment: b4a.toString(commitmentHash({ orders, nonce, turn, gameId }), 'hex')
  }
  const revealEntry = { kind: 'REVEAL', gameId, turn, player: 0, orders, nonce }
  assert.equal(verifyReveal({ commitEntry, revealEntry }), null)

  const swapped = { ...revealEntry, orders: { A1: { type: 'MOVE', dx: 1 } } }
  assert.equal(verifyReveal({ commitEntry, revealEntry: swapped }), 'commitment_mismatch')

  const otherTurn = { ...revealEntry, turn: 2, nonce }
  assert.equal(verifyReveal({ commitEntry, revealEntry: otherTurn }), 'turn_mismatch')

  const otherGame = { ...revealEntry, gameId: 'other' }
  assert.equal(verifyReveal({ commitEntry, revealEntry: otherGame }), 'game_id_mismatch')

  const otherPlayer = { ...revealEntry, player: 1 }
  assert.equal(verifyReveal({ commitEntry, revealEntry: otherPlayer }), 'player_mismatch')
})

test('resolver is deterministic and merge-order independent', () => {
  const ordersA = { A1: { type: 'MOVE', dx: 3 }, A2: { type: 'FIRE', targetId: 'B1' } }
  const ordersB = { B1: { type: 'FIRE', targetId: 'A2' }, B2: { type: 'MOVE', dx: -2 } }
  const run = () => resolveTurn(initialState({ gameId, seed: 42 }), ordersA, ordersB)
  assert.equal(stateHash(run()), stateHash(run()))
  // stateHash includes rng state -> different seeds diverge (sanity)
  const s2 = resolveTurn(initialState({ gameId, seed: 7 }), ordersA, ordersB)
  assert.notEqual(stateHash(s2), stateHash(run()))
})

test('invalid orders are deterministic no-ops, recorded in events', () => {
  const state = initialState({ gameId, seed: 42 })
  const badA = {
    B9: { type: 'MOVE', dx: 1 },                    // enemy unit
    A1: { type: 'MOVE', dx: 99 },                   // out of move range
    A2: { type: 'FIRE', targetId: 'A1' }            // friendly fire
  }
  const badB = {
    B1: { type: 'STAND' }                           // unknown type
  }
  const next = resolveTurn(state, badA, badB)
  const evt = next.events[next.events.length - 1]
  assert.equal(evt.dropped.length, 4)
  assert.ok(evt.dropped.some(d => d.reason === 'not_your_unit'))
  assert.ok(evt.dropped.some(d => d.reason === 'bad_move'))
  assert.ok(evt.dropped.some(d => d.reason === 'bad_target'))
  assert.ok(evt.dropped.some(d => d.reason === 'unknown_type'))
  // determinism of the no-op path itself
  assert.equal(stateHash(resolveTurn(state, badA, badB)), stateHash(next))
})
