// Minimal deterministic turn resolver for the example game. Kept deliberately
// small: the point of this example is the substrate composition, not the
// game. It still honors the rules that matter for P2P determinism — seeded
// RNG carried in state, integer math, fixed resolution order, validated
// orders, and a hashable state.

import { canonicalBytes } from './adapter.js'
import { blake2b256 } from '@hiverelay/blind-protocol/hashes'
import b4a from 'b4a'

// splitmix64 — 64-bit state, BigInt, JSON-serializable as a string.
export function createRng (seedString) {
  let state = BigInt.asUintN(64, BigInt(seedString))
  return {
    next () {
      state = BigInt.asUintN(64, state + 0x9e3779b97f4a7c15n)
      let z = state
      z = BigInt.asUintN(64, ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n))
      z = BigInt.asUintN(64, ((z ^ (z >> 27n)) * 0x94d049bb133111ebn))
      return BigInt.asUintN(64, z ^ (z >> 31n))
    },
    toJSON () {
      return state.toString()
    }
  }
}

export function initialState ({ gameId, seed, turns = 8 }) {
  return {
    v: 1,
    gameId,
    turn: 0,
    maxTurns: turns,
    rng: String(seed),
    units: {
      A1: { side: 0, x: 0, hp: 10 },
      A2: { side: 0, x: 0, hp: 10 },
      B1: { side: 1, x: 7, hp: 10 },
      B2: { side: 1, x: 7, hp: 10 }
    },
    events: [],
    winner: null
  }
}

const MOVE_MAX = 3
const FIRE_RANGE = 2
const BOARD = 8

export function validateOrder (state, side, unitId, order) {
  if (order === null || typeof order !== 'object') return 'malformed'
  const unit = state.units[unitId]
  if (!unit || unit.side !== side) return 'not_your_unit'
  if (order.type === 'MOVE') {
    if (!Number.isInteger(order.dx) || order.dx === 0 || Math.abs(order.dx) > MOVE_MAX) return 'bad_move'
    return null
  }
  if (order.type === 'FIRE') {
    const target = state.units[order.targetId]
    if (!target || target.side === side) return 'bad_target'
    return null
  }
  return 'unknown_type'
}

// state + ordersA + ordersB -> state' — pure, deterministic.
export function resolveTurn (state, ordersA, ordersB) {
  const next = JSON.parse(JSON.stringify(state))
  next.turn += 1
  const rng = createRng(next.rng)
  const dropped = []

  // fixed order: movement for side 0 then side 1, units sorted by id
  const apply = (side, orders) => {
    for (const unitId of Object.keys(orders).sort()) {
      const order = orders[unitId]
      const reason = validateOrder(state, side, unitId, order)
      if (reason) {
        dropped.push({ unitId, reason })
        continue
      }
      if (order.type === 'MOVE') {
        const x = state.units[unitId].x + order.dx
        next.units[unitId].x = Math.max(0, Math.min(BOARD - 1, x))
      }
    }
  }
  apply(0, ordersA)
  apply(1, ordersB)

  // fire phase: simultaneous — damage computed from pre-fire positions
  const damage = {}
  const fire = (side, orders) => {
    for (const unitId of Object.keys(orders).sort()) {
      const order = orders[unitId]
      if (order.type !== 'FIRE') continue
      if (validateOrder(state, side, unitId, order)) continue
      const shooter = next.units[unitId]
      const target = next.units[order.targetId]
      if (Math.abs(shooter.x - target.x) > FIRE_RANGE) {
        dropped.push({ unitId, reason: 'out_of_range' })
        continue
      }
      damage[order.targetId] = (damage[order.targetId] || 0) + Number(rng.next() % 4n) + 2
    }
  }
  fire(0, ordersA)
  fire(1, ordersB)
  for (const unitId of Object.keys(damage).sort()) {
    next.units[unitId].hp = Math.max(0, next.units[unitId].hp - damage[unitId])
  }

  // objectives: side 0 wins by reaching sector 7; side 1 wins by eliminating
  // both side-0 units; nobody wins by turn cap -> side 1 holds the field
  const survivors = Object.keys(next.units).filter(id => next.units[id].side === 0 && next.units[id].hp > 0)
  if (survivors.some(id => next.units[id].x === BOARD - 1)) next.winner = 0
  else if (survivors.length === 0) next.winner = 1
  else if (next.turn >= next.maxTurns) next.winner = 1

  next.rng = rng.toJSON()
  next.events.push({ turn: state.turn, dropped, damage })
  return next
}

export function stateHash (state) {
  return b4a.toString(blake2b256(canonicalBytes(state)), 'hex')
}
