// FORWARD HTTPS target durability store v3.
//
// Role-bound TARGET_STORE WAL store over one accepted BlindTransactionStore
// with maximumWalPayloadBytes exactly 16777216. Recovery streams every frame
// through the single hash-bound derive function; live cost planning uses the
// same function family. Slot lifecycle, charge-entry cap, terminal headroom
// and the FAILED_PRUNE_DURABLE_PENDING absorbing teardown are enforced here.

import b4a from 'b4a'
import { BlindTransactionStore } from './transaction-store.js'
import {
  FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3,
  createForwardHttpsStoreQuotaCostPlanV3,
  reserveForwardHttpsAggregateQuotaV3,
  commitForwardHttpsAggregateQuotaV3,
  releaseForwardHttpsAggregateQuotaV3,
  adjustForwardHttpsAggregateQuotaV3,
  bindForwardHttpsStoreQuotaActualBuffersV3,
  applyForwardHttpsAggregateQuotaWalFrameV3,
  beginForwardHttpsAggregateQuotaRecoveryV3,
  absorbForwardHttpsAggregateQuotaRecoveryFrameV3,
  finishForwardHttpsAggregateQuotaRecoveryV3,
  encodeForwardHttpsRetentionPrunedV3,
  decodeForwardHttpsRetentionPrunedV3
} from './forward-https-replay-journal-v4.js'
import {
  FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE,
  FORWARD_HTTPS_STORAGE_SLOT_STATE_V3,
  FORWARD_HTTPS_STORAGE_HISTORIC_IDENTITY_V3,
  createForwardHttpsChargeRegistryV3,
  encodeForwardHttpsSessionTerminalV3,
  verifyForwardHttpsTerminalHeadroomV3
} from './forward-https-storage-authority-v3.js'

const ROLE = FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3.TARGET_STORE
const ZERO32 = b4a.alloc(32)
const SESSION_MAGIC = b4a.from('FTS3', 'ascii')
const WAL_TYPE = Object.freeze({
  TURN_FINAL: 112,
  TRANSPORT_RESERVED: 113,
  PROCESSOR_PREPARED: 114,
  PROCESSOR_REQUEST_READY: 115,
  PROCESSOR_COMPLETED: 116,
  SESSION_TERMINAL: 117,
  RETENTION_PRUNED: 118,
  QUARANTINED: 119
})
const CHARGE_ENTRY_CAP = 65536
const PRODUCTION_SLOTS = 65536

export const FORWARD_HTTPS_TARGET_STORE_V3_LIMITS = Object.freeze({
  maximumWalPayloadBytes: 16777216,
  chargeEntryCapPerSession: CHARGE_ENTRY_CAP,
  productionSlotsPerRole: PRODUCTION_SLOTS,
  walTypes: WAL_TYPE,
  descriptorOperationBits: 0,
  advertisedOperationBits: 0,
  readinessOperationBits: 0,
  runtimeReady: false,
  releaseReady: false,
  authorizesRelease: false
})

export class ForwardHttpsTargetStoreV3Error extends Error {
  constructor (message, code = FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INVALID) {
    super(message)
    this.name = 'ForwardHttpsTargetStoreV3Error'
    this.code = code
  }
}

function fail (message, code) {
  throw new ForwardHttpsTargetStoreV3Error(message, code)
}

function transactionIdFor (stableSessionId, salt) {
  const id = b4a.from(stableSessionId)
  id[31] = (id[31] ^ salt) | 1
  return id
}

function keyOf (stableSessionId) {
  return b4a.toString(stableSessionId, 'hex')
}

function sessionPayload (walTypeMagic, stableSessionId, body) {
  return b4a.concat([walTypeMagic, stableSessionId, body || b4a.alloc(0)])
}

export async function openForwardHttpsTargetStoreV3 (options) {
  if (!options || typeof options !== 'object') throw new TypeError('options must be a closed object')
  if (typeof options.root !== 'string') throw new TypeError('root is required')
  if (!options.storeQuotaCapability) throw new TypeError('storeQuotaCapability is required')
  const capacity = options.limits && typeof options.limits.maximumRetainedTurnsPerRole === 'number'
    ? options.limits.maximumRetainedTurnsPerRole
    : PRODUCTION_SLOTS
  if (!Number.isSafeInteger(capacity) || capacity < 1 || capacity > PRODUCTION_SLOTS) throw new TypeError('slot capacity is invalid')
  if (options.limits) {
    verifyForwardHttpsTerminalHeadroomV3({
      capacity,
      maximumDurableBytesPerStore: options.limits.maximumDurableBytesPerStore,
      maximumForwardStorageBytesAggregate: options.limits.maximumForwardStorageBytesAggregate
    })
  }
  const state = {
    role: ROLE,
    storeQuotaCapability: options.storeQuotaCapability,
    capacity,
    storeId: b4a.from(options.storeId),
    mapGeneration: options.mapGeneration == null ? 1n : BigInt(options.mapGeneration),
    ownerFenceTokenHash: b4a.from(options.ownerFenceTokenHash),
    durabilityContinuityHash: b4a.from(options.durabilityContinuityHash),
    slots: new Map(),
    unconsumed: capacity,
    consumedUnpruned: 0,
    consumedPruned: 0,
    roleGlobalLogicalBytes: 0,
    walHeadSequence: 0n,
    walHeadHash: b4a.from(ZERO32),
    failedPruneDurablePending: false,
    blocker: null,
    closed: false,
    localOperational: false,
    store: new BlindTransactionStore({
      root: options.root,
      mapGeneration: options.mapGeneration == null ? 1n : options.mapGeneration,
      ownerFenceTokenHash: options.ownerFenceTokenHash,
      durabilityContinuityHash: options.durabilityContinuityHash,
      maximumWalPayloadBytes: 16777216,
      faultInjector: options.faultInjector || null
    })
  }
  // Recovery runs through the quota recovery sink: sink-private one-use
  // claims are minted, derived and burned inside absorb; finish merges the
  // canonical predecessor state and is mandatory before localOperational.
  state.recoverySink = beginForwardHttpsAggregateQuotaRecoveryV3(state.storeQuotaCapability)
  await state.store.open(frame => recoverFrame(state, frame))
  state.recoveryFinalState = await finishForwardHttpsAggregateQuotaRecoveryV3(state.recoverySink)
  state.recoverySink = null
  state.walHeadSequence = state.store.walSequence
  state.walHeadHash = b4a.from(state.store.walHash)
  state.localOperational = true
  return state
}

async function recoverFrame (state, frame) {
  const { entry: derived } = await absorbForwardHttpsAggregateQuotaRecoveryFrameV3(state.recoverySink, { frame })
  if (derived.scope === 'ROLE_GLOBAL') {
    state.roleGlobalLogicalBytes += derived.ordinaryLogicalCharge
    return
  }
  const key = keyOf(derived.stableSessionId)
  let slot = state.slots.get(key)
  if (slot && (slot.state === FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.CONSUMED_PRUNED || slot.prunedReleased)) {
    fail('post-prune SESSION entry is INTEGRITY', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  }
  if (derived.scope === 'SESSION' && derived.walType === WAL_TYPE.TRANSPORT_RESERVED) {
    recoverPrefixFrame(state, slot, key, derived, frame)
  } else if (derived.scope === 'SESSION' && derived.walType !== WAL_TYPE.SESSION_TERMINAL) {
    if (!slot) {
      if (derived.walType !== WAL_TYPE.TURN_FINAL) fail('first session frame must create the allocation', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
      if (state.unconsumed < 1) fail('recovered slots exceed capacity', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
      slot = freshSlot(state, derived.stableSessionId)
      slot.state = FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED
      state.unconsumed--
    }
    if (slot.orphan && b4a.equals(payloadCommitment(frame.payload) || b4a.alloc(0), slot.orphan.requestCommitment)) {
      // Matching final for the exact same operation, requestCommitment and
      // revision chain: the open prefix is applied exactly once. Orphan
      // entries become ordinary session entries and the record closes;
      // FRESH PREFIX_ALLOCATED and EXISTING ALLOCATED_WITH_PREFIX both
      // return to ALLOCATED. A final of any other operation does not close
      // the record and its entry is preserved by a later flags2 abort.
      slot.state = FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED
      slot.orphan = null
    }
    slot.registry.admit(derived)
    slot.priorRevision++
  } else if (derived.walType === WAL_TYPE.SESSION_TERMINAL) {
    applyTerminalRecovery(state, slot, key, frame, derived)
  } else if (derived.walType === WAL_TYPE.RETENTION_PRUNED) {
    applyPruneRecovery(state, slot, key, derived, frame)
  }
  state.walHeadSequence = derived.walSequence
}

function newOrphanRecord (requestCommitment) {
  return { requestCommitment: b4a.from(requestCommitment), entries: [], removedSum: 0n, lastRevision: 0n, headSequence: 0n }
}

// The type113 payload body opens with the 32-byte operation requestCommitment
// at this layer (payload offset 36..68). Only frames of the exact same
// operation extend a run; a mixed requestCommitment is INTEGRITY, and only a
// same-sid non-113 SESSION final carrying the same commitment is the
// matching final that closes the run exactly once.
function payloadCommitment (payload) {
  return payload.byteLength >= 68 ? b4a.from(payload.subarray(36, 68)) : null
}

// Crashed-prefix recovery: the predecessor identity of every complete
// same-operation target113 run is classified solely from complete canonical
// WAL. FRESH (no prior complete session frame) claims exactly one recovered
// FREE slot as PREFIX_ALLOCATED. EXISTING overlays ALLOCATED_WITH_PREFIX on
// the one ALLOCATED slot with the complete pre-operation state preserved and
// the prefix recorded as bounded orphan removable entries. No second slot is
// ever claimed.
function recoverPrefixFrame (state, slot, key, derived, frame) {
  const commitment = payloadCommitment(frame.payload)
  if (commitment === null) fail('type113 payload is truncated', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  if (!slot) {
    if (state.unconsumed < 1) fail('recovered prefix slots exceed capacity', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
    slot = freshSlot(state, derived.stableSessionId)
    slot.state = FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.PREFIX_ALLOCATED
    state.unconsumed--
    slot.orphan = newOrphanRecord(commitment)
  } else if (slot.state === FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED) {
    slot.state = FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED_WITH_PREFIX
    slot.orphan = newOrphanRecord(commitment)
  } else if (slot.state !== FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.PREFIX_ALLOCATED && slot.state !== FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED_WITH_PREFIX) {
    fail('prefix frame after a closed disposition is INTEGRITY', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  }
  if (!b4a.equals(commitment, slot.orphan.requestCommitment)) {
    fail('mixed prefix requestCommitment is INTEGRITY', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  }
  const entry = slot.registry.admit(derived)
  slot.priorRevision++
  slot.orphan.entries.push(entry)
  slot.orphan.removedSum += BigInt(derived.ordinaryLogicalCharge)
  slot.orphan.lastRevision = slot.priorRevision
  slot.orphan.headSequence = derived.walSequence
  state.slots.set(key, slot)
}

function freshSlot (state, stableSessionId) {
  const slot = {
    stableSessionId: b4a.from(stableSessionId),
    state: FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.FREE,
    registry: createForwardHttpsChargeRegistryV3(ROLE, stableSessionId),
    priorRevision: 0n,
    minimal: false,
    expiresAtEpoch: 0,
    recoveryGraceUntilEpoch: 0,
    trustedEpochHighWatermark: 0,
    authorityBitmap: 0,
    authorityCommitments: null,
    prunedReleased: false,
    orphan: null
  }
  state.slots.set(keyOf(stableSessionId), slot)
  return slot
}

function applyTerminalRecovery (state, slot, key, frame, derived) {
  if (!slot) {
    // flags1 minimal terminal: FREE -> CONSUMED_UNPRUNED, revision exactly1
    if (state.unconsumed < 1) fail('recovered terminal slots exceed capacity', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
    slot = freshSlot(state, derived.stableSessionId)
    state.unconsumed--
    slot.priorRevision = 1n
    slot.minimal = true
    slot.authorityBitmap = derived.authorityBitmap
    slot.authorityCommitments = derived.authorityCommitments
  } else {
    if (slot.state !== FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED && slot.state !== FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED_WITH_PREFIX) fail('duplicate terminal is INTEGRITY', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
    slot.priorRevision++
  }
  // Overlay terminalization: orphan prefix entries persist as ordinary
  // removable entries inside the consumed registry and are removed only by
  // the later terminal-existing or terminal-only FPR9. No flags2 abort is
  // possible after terminalization.
  slot.orphan = null
  slot.state = FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.CONSUMED_UNPRUNED
  state.consumedUnpruned++
}

function applyPruneRecovery (state, slot, key, derived, frame) {
  if (!slot) fail('unmatched prune tombstone is INTEGRITY', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  const pruned = decodeForwardHttpsRetentionPrunedV3(frame.payload)
  if (pruned.flags === 1) {
    // flags1 fresh-orphan abort: exact recorded orphan removal, slot returns
    // FREE and the historic identity is PRUNED_RELEASED.
    if (slot.state !== FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.PREFIX_ALLOCATED || !slot.orphan) {
      fail('flags1 abort without a fresh recovered prefix is INTEGRITY', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
    }
    assertOrphanMatch(slot, pruned)
    slot.registry.removeExact(slot.orphan.entries)
    slot.orphan = null
    slot.state = FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.FREE
    slot.prunedReleased = true
    state.unconsumed++
  } else if (pruned.flags === 2) {
    // flags2 existing-session prefix-abort: removes exactly the recorded
    // orphan entries; slot, authority vector, PREPARED state and session
    // clock are byte-identically preserved; never an identity transition.
    if (slot.state !== FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED_WITH_PREFIX || !slot.orphan) {
      fail('flags2 abort without an existing-session prefix is INTEGRITY', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
    }
    assertOrphanMatch(slot, pruned)
    slot.registry.removeExact(slot.orphan.entries)
    slot.orphan = null
    slot.state = FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED
  } else if (slot.state === FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED) {
    // nonterminal PRUNE: RELEASE_ALLOCATED, slot returns FREE
    slot.state = FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.FREE
    slot.prunedReleased = true
    state.unconsumed++
    slot.authorityBitmap = 0
  } else if (slot.state === FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.CONSUMED_UNPRUNED) {
    // terminal PRUNE: slot stays permanently consumed
    slot.state = FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.CONSUMED_PRUNED
    state.consumedUnpruned--
    state.consumedPruned++
    slot.authorityBitmap = 0
  } else {
    fail('duplicate or misordered prune tombstone is INTEGRITY', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  }
  state.roleGlobalLogicalBytes += derived.ordinaryLogicalCharge
}

function assertOrphanMatch (slot, pruned) {
  if (pruned.chargeEntryCount !== slot.orphan.entries.length ||
      pruned.removedOrdinaryLogicalBytes !== slot.orphan.removedSum ||
      pruned.priorSessionRevision !== slot.orphan.lastRevision) {
    fail('prefix abort does not match the recorded orphan entries', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  }
}

function requireOperational (state) {
  if (state.closed) fail('target store is closed', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.CLOSED)
  if (state.failedPruneDurablePending) fail('target store is FAILED_PRUNE_DURABLE_PENDING', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  if (!state.localOperational) fail('target store is not operational', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INVALID)
}

function sessionSlot (state, stableSessionId) {
  const slot = state.slots.get(keyOf(stableSessionId))
  if (!slot) return null
  return slot
}

// Append one operation through the atomic composite: bind mints the ordinal0
// claim, each frame runs validate->begin->appendSync->derive inside one call,
// and commit follows the final derive with no remaining claim. The slot
// mutation happens only after the frame is durable and derived.
async function appendOperation (state, slot, operation, frames) {
  const plan = createForwardHttpsStoreQuotaCostPlanV3(state.storeQuotaCapability, {
    operation,
    knownInputBuffers: frames.map(frame => frame.payload),
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  })
  const union = await reserveForwardHttpsAggregateQuotaV3(state.storeQuotaCapability, plan)
  const reservation = union.reservation || union.terminalReservation
  let attempted = false
  try {
    const { transitionAuthority } = bindForwardHttpsStoreQuotaActualBuffersV3(state.storeQuotaCapability, reservation, {
      logicalRecordBuffers: [],
      encryptedPlaintextBuffers: frames.slice(0, -1).map(frame => frame.payload),
      finalWalMetadataBuffers: [frames[frames.length - 1].payload],
      temporaryWriteBuffers: []
    })
    attempted = true
    let claimOrHandoff = transitionAuthority
    let entry = null
    for (const frame of frames) {
      const applied = await applyForwardHttpsAggregateQuotaWalFrameV3(state.storeQuotaCapability, reservation, claimOrHandoff, frame,
        async candidate => state.store.appendAndApply(candidate, () => {}))
      entry = applied.entry
      claimOrHandoff = applied.transitionAuthorityHandoff
      if (slot) {
        slot.registry.admit(entry)
        slot.priorRevision++
      }
      state.walHeadSequence = entry.walSequence
    }
    await commitForwardHttpsAggregateQuotaV3(state.storeQuotaCapability, reservation, {
      durableWalHeadSequence: state.store.walSequence,
      durableWalHeadHash: state.store.walHash
    })
    return entry
  } catch (error) {
    if (!attempted) await releaseForwardHttpsAggregateQuotaV3(state.storeQuotaCapability, reservation).catch(() => {})
    throw error
  }
}

// Append one ordinary SESSION operation. type112/114/115/116 are single-frame
// operations; a type113 crypto reservation is the prefix frame of a two-frame
// TURN_FINAL operation (113 then the 112 final).
async function appendSession (state, input) {
  requireOperational(state)
  const walType = input.walType
  if (![WAL_TYPE.TURN_FINAL, WAL_TYPE.TRANSPORT_RESERVED, WAL_TYPE.PROCESSOR_PREPARED, WAL_TYPE.PROCESSOR_REQUEST_READY, WAL_TYPE.PROCESSOR_COMPLETED].includes(walType)) {
    throw new TypeError('walType is not an ordinary target SESSION type')
  }
  const stableSessionId = b4a.from(input.stableSessionId)
  const slot = sessionSlot(state, stableSessionId)
  // ALLOCATED_WITH_PREFIX follows the exact allocated-session rules: later
  // operations are admitted with fresh contiguous crypto revisions strictly
  // beyond the recorded orphan last revision.
  if (!slot || (slot.state !== FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED && slot.state !== FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED_WITH_PREFIX)) fail('session is not ALLOCATED', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.SEQUENCE_INVALID)
  const planned = input.plannedRemovableChargeEntryCount == null ? 1 : input.plannedRemovableChargeEntryCount
  if (slot.registry.count + planned > CHARGE_ENTRY_CAP) {
    await terminalizeBudgetExhausted(state, slot, input)
    fail('removable charge entry cap exceeded; session terminalized BUDGET_EXHAUSTED', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.BUDGET_EXHAUSTED)
  }
  const payload = sessionPayload(SESSION_MAGIC, stableSessionId, input.body || b4a.alloc(0))
  const operation = walType === WAL_TYPE.TURN_FINAL || walType === WAL_TYPE.TRANSPORT_RESERVED
    ? 'TURN_FINAL'
    : walType === WAL_TYPE.PROCESSOR_PREPARED
      ? 'PROCESSOR_PREPARED'
      : walType === WAL_TYPE.PROCESSOR_REQUEST_READY
        ? 'PROCESSOR_REQUEST_READY'
        : 'PROCESSOR_COMPLETED'
  const frames = walType === WAL_TYPE.TRANSPORT_RESERVED
    ? [
        { type: WAL_TYPE.TRANSPORT_RESERVED, transactionId: input.transactionId || transactionIdFor(stableSessionId, 0xa5), virtualBucket: 0, payload },
        // The operation final carries the exact same requestCommitment so
        // recovery applies the prefix exactly once and never mixes operations.
        { type: WAL_TYPE.TURN_FINAL, transactionId: input.transactionId || transactionIdFor(stableSessionId, 0xa5), virtualBucket: 0, payload: sessionPayload(SESSION_MAGIC, stableSessionId, b4a.concat([b4a.from(payload.subarray(36, 68)), input.finalBody || b4a.alloc(0)])) }
      ]
    : [{ type: walType, transactionId: input.transactionId || transactionIdFor(stableSessionId, 0xa5), virtualBucket: 0, payload }]
  const entry = await appendOperation(state, slot, operation, frames)
  return Object.freeze({ walSequence: entry.walSequence, walHash: b4a.from(state.store.walHash), payload })
}

export function appendForwardHttpsTargetSessionV3 (state, input) {
  return appendSession(state, input)
}

// Fresh target OPEN TURN_FINAL=112: one FREE slot becomes ALLOCATED.
export async function openForwardHttpsTargetSessionV3 (state, input) {
  requireOperational(state)
  const stableSessionId = b4a.from(input.stableSessionId)
  const existing = state.slots.get(keyOf(stableSessionId))
  // PRUNED_RELEASED returns mutation-free CONFLICT; a present session is
  // SEQUENCE_INVALID; no historic state is reclassified as NEVER_SEEN.
  if (existing && existing.prunedReleased) fail('session identity is PRUNED_RELEASED', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.CONFLICT)
  if (existing) fail('session identity is not NEVER_SEEN', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.SEQUENCE_INVALID)
  if (state.unconsumed < 1) fail('no FREE slot for a fresh target session', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.CAPACITY)
  const slot = freshSlot(state, stableSessionId)
  state.unconsumed--
  const payload = sessionPayload(SESSION_MAGIC, stableSessionId, input.body || b4a.alloc(0))
  try {
    const entry = await appendOperation(state, slot, 'TURN_FINAL', [{
      type: WAL_TYPE.TURN_FINAL,
      transactionId: input.transactionId || transactionIdFor(stableSessionId, 0xa5),
      virtualBucket: 0,
      payload
    }])
    slot.state = FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED
    return Object.freeze({ walSequence: entry.walSequence, walHash: b4a.from(state.store.walHash), payload })
  } catch (error) {
    if (slot.state === FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.FREE) {
      state.slots.delete(keyOf(stableSessionId))
      state.unconsumed++
    }
    throw error
  }
}

async function terminalizeBudgetExhausted (state, slot, input) {
  const payload = encodeForwardHttpsSessionTerminalV3({
    role: ROLE,
    flags: 0,
    stableSessionId: slot.stableSessionId,
    sequence: input.sequence == null ? 1n : input.sequence,
    priorSessionRevision: slot.priorRevision,
    newTrustedEpochHighWatermark: input.newTrustedEpochHighWatermark || 0,
    reason: 'BUDGET_EXHAUSTED',
    buckets: [0, 0, 0, 0, 0],
    transportTurnsSpent: 0,
    transportBytesSpent: 0
  })
  await appendTerminalPayload(state, slot, payload)
}

async function appendTerminalPayload (state, slot, payload) {
  const entry = await appendOperation(state, null, 'SESSION_TERMINAL', [{
    type: WAL_TYPE.SESSION_TERMINAL,
    transactionId: transactionIdFor(slot.stableSessionId, 0x5a),
    virtualBucket: 0,
    payload
  }])
  slot.priorRevision++
  slot.state = FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.CONSUMED_UNPRUNED
  state.consumedUnpruned++
  return { entry, sequence: entry.walSequence, walHash: state.store.walHash }
}

// FTM9 flags0: existing ALLOCATED or ALLOCATED_WITH_PREFIX session
// terminalization. Never CAPACITY. On an open prefix the exact orphan-last
// revision floor applies and the orphan entries persist as ordinary removable
// entries inside the consumed registry; no flags2 abort is possible after.
export async function terminalizeForwardHttpsTargetSessionV3 (state, input) {
  requireOperational(state)
  const slot = sessionSlot(state, b4a.from(input.stableSessionId))
  if (!slot || (slot.state !== FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED && slot.state !== FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED_WITH_PREFIX)) fail('session is not ALLOCATED', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.TERMINAL)
  const payload = encodeForwardHttpsSessionTerminalV3({
    role: ROLE,
    flags: 0,
    stableSessionId: slot.stableSessionId,
    sequence: input.sequence,
    priorSessionRevision: slot.priorRevision,
    newTrustedEpochHighWatermark: input.newTrustedEpochHighWatermark || 0,
    reason: input.reason,
    buckets: input.buckets || [0, 0, 0, 0, 0],
    transportTurnsSpent: input.transportTurnsSpent || 0,
    transportBytesSpent: input.transportBytesSpent || 0
  })
  const frame = await appendTerminalPayload(state, slot, payload)
  // The orphan record closes with terminalization; its entries persist into
  // the consumed registry and are removed only by the later terminal-existing
  // or terminal-only FPR9.
  slot.orphan = null
  return Object.freeze({ walSequence: frame.sequence, walHash: b4a.from(frame.walHash), payload })
}

// FTM9 flags1: NEVER_SEEN canonical non-OPEN SEQUENCE_INVALID minimal terminal.
export async function terminalizeForwardHttpsTargetAbsentSequenceV3 (state, input) {
  requireOperational(state)
  const stableSessionId = b4a.from(input.stableSessionId)
  if (state.slots.has(keyOf(stableSessionId))) fail('session identity is not NEVER_SEEN', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.SEQUENCE_INVALID)
  if (state.unconsumed < 1) fail('no FREE slot for the minimal terminal', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.CAPACITY)
  const slot = freshSlot(state, stableSessionId)
  state.unconsumed--
  const payload = encodeForwardHttpsSessionTerminalV3({
    role: ROLE,
    flags: 1,
    stableSessionId,
    sequence: input.sequence,
    priorSessionRevision: 0n,
    newTrustedEpochHighWatermark: input.newTrustedEpochHighWatermark,
    reason: 'FORWARD_HTTPS_TARGET_STORE_V3_SEQUENCE_INVALID',
    exactRequestCommitment: input.exactRequestCommitment,
    expiresAtEpoch: input.expiresAtEpoch,
    retainedUntilEpoch: input.expiresAtEpoch + 900
  })
  const applied = await appendTerminalPayload(state, slot, payload)
  slot.priorRevision = 1n
  slot.minimal = true
  slot.expiresAtEpoch = input.expiresAtEpoch
  slot.recoveryGraceUntilEpoch = input.expiresAtEpoch + 900
  slot.trustedEpochHighWatermark = input.newTrustedEpochHighWatermark
  slot.authorityBitmap = (1 << 7) | (1 << 9)
  slot.authorityCommitments = applied.entry.authorityCommitments
  return Object.freeze({ walSequence: applied.sequence, walHash: b4a.from(applied.walHash), payload })
}

// FPR9 retention prune. flags0 nonterminal releases the slot to FREE;
// terminal keeps it permanently consumed. Terminal/terminal-only never
// return CAPACITY. flags1 fresh-orphan abort and flags2 existing-session
// prefix-abort are ordinary net-admission transitions evaluated against the
// exact protected inequalities: equality admits, ceiling+1 returns CAPACITY
// before WAL with zero mutation, and no clock wait applies.
export async function pruneForwardHttpsTargetSessionV3 (state, input) {
  requireOperational(state)
  const slot = sessionSlot(state, b4a.from(input.stableSessionId))
  if (!slot) fail('session is absent', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  const flags = input.flags === undefined ? 0 : input.flags
  if (flags !== 0 && flags !== 1 && flags !== 2) throw new TypeError('flags must be 0, 1 or 2')
  if (flags === 1) return pruneForwardHttpsPrefixOrphanAbortV3(state, slot, input)
  if (flags === 2) return pruneForwardHttpsExistingPrefixAbortV3(state, slot, input)
  const consumed = slot.state === FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.CONSUMED_UNPRUNED
  if (slot.state !== FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED && !consumed) fail('session slot state cannot be pruned', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  const entries = slot.registry.entriesAscending()
  const count = slot.minimal && entries.length === 0 ? 0 : entries.length
  if (count === 0 && !slot.minimal) fail('nonterminal prune requires ordinary entries', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  const pruneEpochSeconds = input.pruneEpochSeconds
  if (slot.minimal && pruneEpochSeconds <= slot.recoveryGraceUntilEpoch) fail('terminal-only prune must wait the full grace', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  const payload = encodeForwardHttpsRetentionPrunedV3({
    role: ROLE,
    stableSessionId: slot.stableSessionId,
    priorSessionRevision: slot.priorRevision,
    pruneEpochSeconds,
    trustedEpochHighWatermark: Math.max(slot.trustedEpochHighWatermark, pruneEpochSeconds),
    expiresAtEpoch: slot.expiresAtEpoch,
    recoveryGraceUntilEpoch: slot.recoveryGraceUntilEpoch,
    removedOrdinaryLogicalBytes: slot.registry.removedLogicalBytes(),
    chargeEntryCount: count,
    beforeAuthorityBitmap: slot.authorityBitmap,
    allocationDisposition: consumed ? 0 : 1,
    terminalSlotState: consumed ? 2 : 1,
    chargeEntryBuffers: entries,
    authorityCommitments: slot.authorityCommitments || Array.from({ length: 10 }, () => b4a.from(ZERO32))
  })
  const frame = await appendPruneTombstone(state, slot, payload)
  if (consumed) {
    slot.state = FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.CONSUMED_PRUNED
    state.consumedUnpruned--
    state.consumedPruned++
  } else {
    slot.state = FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.FREE
    slot.prunedReleased = true
    state.unconsumed++
  }
  slot.authorityBitmap = 0
  state.roleGlobalLogicalBytes += 736
  state.walHeadSequence = frame.sequence
  return Object.freeze({ walSequence: frame.sequence, walHash: b4a.from(frame.walHash), payload })
}

// flags1 RECOVERED_PREFIX_ORPHAN abort: only for a TARGET PREFIX_ALLOCATED
// fresh orphan. Removes all positive prefix ordinary charge, adds the
// 736/480 tombstone under ordinary net admission, clears prefix authority,
// moves PREFIX_ALLOCATED to FREE and leaves PRUNED_RELEASED. Eligibility is
// immediate after successful fresh recovery.
async function pruneForwardHttpsPrefixOrphanAbortV3 (state, slot, input) {
  if (slot.state !== FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.PREFIX_ALLOCATED || !slot.orphan) {
    fail('flags1 abort requires a fresh recovered prefix', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  }
  const pruneEpochSeconds = input.pruneEpochSeconds
  if (!Number.isSafeInteger(pruneEpochSeconds) || pruneEpochSeconds < 1) fail('flags1 abort requires a nonzero trusted prune epoch', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  const payload = encodeForwardHttpsRetentionPrunedV3({
    role: ROLE,
    flags: 1,
    stableSessionId: slot.stableSessionId,
    priorSessionRevision: slot.orphan.lastRevision,
    pruneEpochSeconds,
    trustedEpochHighWatermark: Math.max(slot.trustedEpochHighWatermark, pruneEpochSeconds),
    expiresAtEpoch: 0,
    recoveryGraceUntilEpoch: 0,
    removedOrdinaryLogicalBytes: slot.orphan.removedSum,
    chargeEntryCount: slot.orphan.entries.length,
    beforeAuthorityBitmap: slot.authorityBitmap,
    allocationDisposition: 1,
    terminalSlotState: 3,
    chargeEntryBuffers: slot.orphan.entries,
    authorityCommitments: slot.authorityCommitments || Array.from({ length: 10 }, () => b4a.from(ZERO32))
  })
  const frame = await appendPruneTombstone(state, slot, payload)
  slot.registry.removeExact(slot.orphan.entries)
  slot.orphan = null
  slot.state = FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.FREE
  slot.prunedReleased = true
  slot.authorityBitmap = 0
  state.unconsumed++
  state.roleGlobalLogicalBytes += 736
  state.walHeadSequence = frame.sequence
  return Object.freeze({ walSequence: frame.sequence, walHash: b4a.from(frame.walHash), payload })
}

// flags2 EXISTING_SESSION_PREFIX_ABORT: only for an ALLOCATED_WITH_PREFIX
// session. Removes exactly the recorded orphan entries (count, sum and
// chain), leaves the authority vector byte-identically unchanged, preserves
// PREPARED state and the session clock and keeps the slot ALLOCATED. It is
// never an identity transition: no PRUNED_RELEASED is recorded and there is
// no restore clause. Later committed entries are preserved.
async function pruneForwardHttpsExistingPrefixAbortV3 (state, slot, input) {
  if (slot.state !== FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED_WITH_PREFIX || !slot.orphan) {
    fail('flags2 abort requires an existing-session prefix', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  }
  const pruneEpochSeconds = input.pruneEpochSeconds
  if (!Number.isSafeInteger(pruneEpochSeconds) || pruneEpochSeconds < 1) fail('flags2 abort requires a nonzero trusted prune epoch', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  const payload = encodeForwardHttpsRetentionPrunedV3({
    role: ROLE,
    flags: 2,
    stableSessionId: slot.stableSessionId,
    priorSessionRevision: slot.orphan.lastRevision,
    pruneEpochSeconds,
    trustedEpochHighWatermark: Math.max(slot.trustedEpochHighWatermark, pruneEpochSeconds),
    expiresAtEpoch: 0,
    recoveryGraceUntilEpoch: 0,
    removedOrdinaryLogicalBytes: slot.orphan.removedSum,
    chargeEntryCount: slot.orphan.entries.length,
    beforeAuthorityBitmap: slot.authorityBitmap,
    allocationDisposition: 2,
    terminalSlotState: 1,
    chargeEntryBuffers: slot.orphan.entries,
    authorityCommitments: slot.authorityCommitments || Array.from({ length: 10 }, () => b4a.from(ZERO32))
  })
  const frame = await appendPruneTombstone(state, slot, payload)
  slot.registry.removeExact(slot.orphan.entries)
  slot.orphan = null
  slot.state = FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED
  state.roleGlobalLogicalBytes += 736
  state.walHeadSequence = frame.sequence
  return Object.freeze({ walSequence: frame.sequence, walHash: b4a.from(frame.walHash), payload })
}

async function appendPruneTombstone (state, slot, payload) {
  const plan = createForwardHttpsStoreQuotaCostPlanV3(state.storeQuotaCapability, {
    operation: 'PRUNE',
    knownInputBuffers: [payload],
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  })
  const union = await reserveForwardHttpsAggregateQuotaV3(state.storeQuotaCapability, plan)
  const reservation = union.reservation || union.terminalReservation
  let frame
  try {
    const { transitionAuthority } = bindForwardHttpsStoreQuotaActualBuffersV3(state.storeQuotaCapability, reservation, {
      logicalRecordBuffers: [],
      encryptedPlaintextBuffers: [],
      finalWalMetadataBuffers: [payload],
      temporaryWriteBuffers: []
    })
    await applyForwardHttpsAggregateQuotaWalFrameV3(state.storeQuotaCapability, reservation, transitionAuthority, {
      type: WAL_TYPE.RETENTION_PRUNED,
      transactionId: transactionIdFor(slot.stableSessionId, 0x5a),
      virtualBucket: 0,
      payload
    }, async candidate => {
      frame = await state.store.appendAndApply(candidate, () => {})
      return frame
    })
  } catch (error) {
    await releaseForwardHttpsAggregateQuotaV3(state.storeQuotaCapability, reservation).catch(() => {})
    throw error
  }
  // The tombstone is durable. The adjust path is the only permitted commit;
  // any failure here enters the absorbing FAILED_PRUNE_DURABLE_PENDING state.
  try {
    await adjustForwardHttpsAggregateQuotaV3(state.storeQuotaCapability, {
      durableTombstonePayloadBuffer: payload,
      durableWalHeadSequence: frame.sequence,
      durableWalHeadHash: frame.walHash
    })
  } catch (error) {
    state.failedPruneDurablePending = true
    state.localOperational = false
    state.blocker = FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY
    fail('post-fsync prune adjustment failed; FAILED_PRUNE_DURABLE_PENDING', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  }
  return frame
}

export function forwardHttpsTargetStoreV3Status (state) {
  return Object.freeze({
    role: ROLE,
    localOperational: state.localOperational && !state.failedPruneDurablePending,
    state: state.failedPruneDurablePending ? 'FAILED_PRUNE_DURABLE_PENDING' : state.closed ? 'CLOSED' : 'OPEN',
    blocker: state.blocker,
    walHeadSequence: state.walHeadSequence,
    walHeadHash: b4a.from(state.walHeadHash),
    slotCapacity: state.capacity,
    unconsumedSlots: state.unconsumed,
    consumedUnprunedSlots: state.consumedUnpruned,
    consumedPrunedSlots: state.consumedPruned,
    roleGlobalLogicalBytes: state.roleGlobalLogicalBytes,
    descriptorOperationBits: 0,
    advertisedOperationBits: 0,
    readinessOperationBits: 0,
    runtimeReady: false,
    releaseReady: false,
    authorizesRelease: false
  })
}

// FAILED_PRUNE_DURABLE_PENDING teardown is absorbing and close-only: it
// invalidates process capabilities without apply/refund/retry, closes the
// child store and remains idempotent for exact-authority repeat closes.
export async function closeForwardHttpsTargetStoreV3 (state) {
  if (!state || typeof state !== 'object') fail('target store authority is forged', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INVALID)
  if (state.closed) return
  state.closed = true
  state.localOperational = false
  await state.store.close()
}

export const FORWARD_HTTPS_TARGET_STORE_V3_WAL_TYPE = WAL_TYPE
export const FORWARD_HTTPS_TARGET_STORE_V3_HISTORIC_IDENTITY = FORWARD_HTTPS_STORAGE_HISTORIC_IDENTITY_V3
