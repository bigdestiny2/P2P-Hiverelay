// Game-side adapter for the hiverelay-blind/1 substrate.
//
// Implements the application adoption contract for an async two-player
// turn-based game: the application owns canonical encoding, signatures,
// commitment/reveal rules, and capability distribution; the substrate sees
// only opaque sealed bytes. Every cryptographic operation below is the real
// substrate client — only the HTTP transport is left to the embedder.
//
// Composition (all generic, no protocol additions):
//   - COMMIT/REVEAL entries  -> fixed-class encrypted cells (G3)
//   - capability handoff     -> opaque inbox frames (rendezvous composition)
//   - your-move notification -> INBOX.WATCH long-poll + polling fallback
//   - abandonment            -> lease expiry (active games renew, dead
//                               games let mirrors age out)

import b4a from 'b4a'
import { INBOX_APPEND_AUTH_MODE, INBOX_FRAME_CLASS } from '@hiverelay/blind-protocol/registry'
import { blake2b256 } from '@hiverelay/blind-protocol/hashes'
import {
  createAppendInboxRequest,
  createCellReplica,
  createInboxReplica,
  createWatchInboxRequest,
  openCell
} from '@hiverelay/blind-client'

export const COMMIT_SIZE_CLASS = 1
export const REVEAL_SIZE_CLASS = 1
export const POKE_FRAME_CLASS = 1
export const ACTIVE_GAME_LEASE_CLASS = 2 // L7: renewed while the game lives

// -- canonical encoding ----------------------------------------------------

export function canonicalString (value) {
  if (Array.isArray(value)) return '[' + value.map(canonicalString).join(',') + ']'
  if (value === null || typeof value === 'number' || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'string') return JSON.stringify(value)
  const keys = Object.keys(value).sort()
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalString(value[k])).join(',') + '}'
}

export function canonicalBytes (value) {
  return b4a.from(canonicalString(value), 'utf8')
}

// -- commitment / reveal (the game's own authority) ------------------------
//
// commitment = H(canonical(orders) || nonce || u64be(turn) || gameId)
//
// The binding covers every degree of freedom a replaying opponent could
// exploit: different orders, a reused nonce, a different turn, or a replay
// of the whole commitment in another game.

function u64be (n) {
  const bytes = b4a.alloc(8)
  let v = BigInt(n)
  for (let i = 7; i >= 0; i--) {
    bytes[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return bytes
}

export function commitmentHash ({ orders, nonce, turn, gameId }) {
  return blake2b256(b4a.concat([
    canonicalBytes(orders),
    b4a.from(nonce),
    u64be(turn),
    b4a.from(gameId)
  ]))
}

export function makeCommitment ({ runtime, relayPublicKey, allocationEpoch, admission, gameId, turn, player, orders, nonce }) {
  const commitment = commitmentHash({ orders, nonce, turn, gameId })
  const entry = { v: 1, kind: 'COMMIT', gameId, turn, player, commitment: b4a.toString(commitment, 'hex') }
  return createCellReplica({
    runtime,
    relayPublicKey,
    allocationEpoch,
    sizeClass: COMMIT_SIZE_CLASS,
    leaseClass: ACTIVE_GAME_LEASE_CLASS,
    structuredContent: canonicalBytes(entry),
    admission
  })
}

export function makeReveal ({ runtime, relayPublicKey, allocationEpoch, admission, gameId, turn, player, orders, nonce }) {
  const entry = { v: 1, kind: 'REVEAL', gameId, turn, player, orders, nonce }
  return createCellReplica({
    runtime,
    relayPublicKey,
    allocationEpoch,
    sizeClass: REVEAL_SIZE_CLASS,
    leaseClass: ACTIVE_GAME_LEASE_CLASS,
    structuredContent: canonicalBytes(entry),
    admission
  })
}

// Verify a reveal against the earlier commitment. Returns null when the
// reveal is authentic, or a string naming the violation for the caller's
// policy (the substrate has no opinion — this is application authority).
export function verifyReveal ({ commitEntry, revealEntry }) {
  if (commitEntry.gameId !== revealEntry.gameId) return 'game_id_mismatch'
  if (commitEntry.turn !== revealEntry.turn) return 'turn_mismatch'
  if (commitEntry.player !== revealEntry.player) return 'player_mismatch'
  const expected = commitmentHash({
    orders: revealEntry.orders,
    nonce: revealEntry.nonce,
    turn: revealEntry.turn,
    gameId: revealEntry.gameId
  })
  if (b4a.toString(expected, 'hex') !== commitEntry.commitment) return 'commitment_mismatch'
  return null
}

export function decodeEntry (bytes) {
  return JSON.parse(b4a.toString(bytes, 'utf8'))
}

// Opponent opens a sealed cell using the read capability handed over via an
// inbox frame. The relay served only ciphertext; it never saw the entry.
export async function openSealedEntry ({ runtime, readCap, cellBlob }) {
  return decodeEntry(await openCell({
    runtime,
    storageSlot: b4a.from(readCap.storageSlot, 'hex'),
    sizeClass: readCap.sizeClass,
    cellKey: b4a.from(readCap.cellKey, 'hex'),
    cellBlob
  }))
}

// -- capability handoff + liveness -----------------------------------------

export async function createPlayerInbox ({ runtime, relayPublicKey, allocationEpoch, admission }) {
  return createInboxReplica({
    runtime,
    relayPublicKey,
    allocationEpoch,
    frameClassBits: 1 << (POKE_FRAME_CLASS - 1),
    appendAuthMode: INBOX_APPEND_AUTH_MODE.OPEN_CAPABILITY,
    retentionClass: 2,
    leaseClass: ACTIVE_GAME_LEASE_CLASS,
    admission
  })
}

// A poke frame is the serialized read capability for a sealed entry, padded
// to the exact frame class size (fixed-size frames are the substrate's
// padding property — the relay cannot size-classify pokes by content).
// Appending targets the OPPONENT's inbox; in OPEN_CAPABILITY mode the inbox
// read capability is sufficient to append, which is exactly the
// capability-created rendezvous composition from the adoption contract.
export async function makePoke ({ runtime, inboxReadCap, cellReadCap, admission }) {
  const payload = b4a.from(canonicalString({
    storageSlot: b4a.toString(cellReadCap.storageSlot, 'hex'),
    sizeClass: cellReadCap.sizeClass,
    cellKey: b4a.toString(cellReadCap.cellKey, 'hex')
  }), 'utf8')
  const frameSize = pokeFrameSize()
  if (payload.byteLength > frameSize) throw new Error('read capability exceeds frame class')
  const frame = b4a.alloc(frameSize)
  b4a.copy(payload, frame)
  return createAppendInboxRequest({ runtime, readCap: inboxReadCap, frameClass: POKE_FRAME_CLASS, frame, admission })
}

export function pokeFrameSize () {
  return INBOX_FRAME_CLASS[POKE_FRAME_CLASS]
}

// Long-poll the inbox: the substrate wakes us when a frame lands
// (maxWaitMillis is bounded 1..30000 by the client; the edge enforces its
// own monotonic budget on top). Advisory only — the game stays correct
// with plain READ polling, this just makes "knowing it's your move"
// near-instant.
export async function makeWatch ({ runtime, readCap, afterRevision, admission }) {
  return createWatchInboxRequest({ runtime, readCap, afterRevision, maxWaitMillis: 30000, admission })
}
