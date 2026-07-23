// FORWARD HTTPS source durability store v3.
//
// Role-bound SOURCE_STORE WAL store over one accepted BlindTransactionStore
// with maximumWalPayloadBytes exactly 16777216. Same storage-authority rules
// as the target store; role-local WAL types are 96..101.

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
  deriveForwardHttpsStoreWalQuotaEntryV3,
  encodeForwardHttpsRetentionPrunedV3
} from './forward-https-replay-journal-v4.js'
import {
  FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE,
  FORWARD_HTTPS_STORAGE_SLOT_STATE_V3,
  createForwardHttpsChargeRegistryV3,
  encodeForwardHttpsSessionTerminalV3,
  verifyForwardHttpsTerminalHeadroomV3
} from './forward-https-storage-authority-v3.js'

const ROLE = FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3.SOURCE_STORE
const ZERO32 = b4a.alloc(32)
const SESSION_MAGIC = b4a.from('FSS3', 'ascii')
const WAL_TYPE = Object.freeze({
  PREPARED_NEW: 96,
  TRANSPORT_RESERVED: 97,
  RESULT_PERSISTED: 98,
  SESSION_TERMINAL: 99,
  RETENTION_PRUNED: 100,
  QUARANTINED: 101
})
const CHARGE_ENTRY_CAP = 65536
const PRODUCTION_SLOTS = 65536

export const FORWARD_HTTPS_SOURCE_STORE_V3_LIMITS = Object.freeze({
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

export class ForwardHttpsSourceStoreV3Error extends Error {
  constructor (message, code = FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INVALID) {
    super(message)
    this.name = 'ForwardHttpsSourceStoreV3Error'
    this.code = code
  }
}

function fail (message, code) {
  throw new ForwardHttpsSourceStoreV3Error(message, code)
}

function transactionIdFor (stableSessionId, salt) {
  const id = b4a.from(stableSessionId)
  id[31] = (id[31] ^ salt) | 1
  return id
}

function keyOf (stableSessionId) {
  return b4a.toString(stableSessionId, 'hex')
}

function sessionPayload (stableSessionId, body) {
  return b4a.concat([SESSION_MAGIC, stableSessionId, body || b4a.alloc(0)])
}

export async function openForwardHttpsSourceStoreV3 (options) {
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
  await state.store.open(frame => recoverFrame(state, frame))
  state.walHeadSequence = state.store.walSequence
  state.walHeadHash = b4a.from(state.store.walHash)
  state.localOperational = true
  return state
}

function recoverFrame (state, frame) {
  const derived = deriveForwardHttpsStoreWalQuotaEntryV3({ role: ROLE, frame })
  if (derived.scope === 'ROLE_GLOBAL') {
    state.roleGlobalLogicalBytes += derived.ordinaryLogicalCharge
    return
  }
  const key = keyOf(derived.stableSessionId)
  let slot = state.slots.get(key)
  if (slot && (slot.state === FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.CONSUMED_PRUNED || slot.prunedReleased)) {
    fail('post-prune SESSION entry is INTEGRITY', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  }
  if (derived.scope === 'SESSION' && derived.walType !== WAL_TYPE.SESSION_TERMINAL) {
    if (!slot) {
      if (derived.walType !== WAL_TYPE.PREPARED_NEW) fail('first source session frame must be PREPARED_NEW', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
      if (state.unconsumed < 1) fail('recovered slots exceed capacity', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
      slot = freshSlot(state, derived.stableSessionId)
      slot.state = FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED
      state.unconsumed--
    }
    slot.registry.admit(derived)
    slot.priorRevision++
  } else if (derived.walType === WAL_TYPE.SESSION_TERMINAL) {
    if (!slot) {
      if (state.unconsumed < 1) fail('recovered terminal slots exceed capacity', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
      slot = freshSlot(state, derived.stableSessionId)
      state.unconsumed--
      slot.priorRevision = 1n
      slot.minimal = true
      slot.authorityBitmap = derived.authorityBitmap
      slot.authorityCommitments = derived.authorityCommitments
    } else {
      if (slot.state !== FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED) fail('duplicate terminal is INTEGRITY', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
      slot.priorRevision++
    }
    slot.state = FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.CONSUMED_UNPRUNED
    state.consumedUnpruned++
  } else if (derived.walType === WAL_TYPE.RETENTION_PRUNED) {
    if (!slot) fail('unmatched prune tombstone is INTEGRITY', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
    if (slot.state === FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED) {
      slot.state = FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.FREE
      slot.prunedReleased = true
      state.unconsumed++
    } else if (slot.state === FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.CONSUMED_UNPRUNED) {
      slot.state = FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.CONSUMED_PRUNED
      state.consumedUnpruned--
      state.consumedPruned++
    } else {
      fail('duplicate or misordered prune tombstone is INTEGRITY', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
    }
    slot.authorityBitmap = 0
    state.roleGlobalLogicalBytes += derived.ordinaryLogicalCharge
  }
  state.walHeadSequence = derived.walSequence
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
    prunedReleased: false
  }
  state.slots.set(keyOf(stableSessionId), slot)
  return slot
}

function requireOperational (state) {
  if (state.closed) fail('source store is closed', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.CLOSED)
  if (state.failedPruneDurablePending) fail('source store is FAILED_PRUNE_DURABLE_PENDING', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  if (!state.localOperational) fail('source store is not operational', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INVALID)
}

// Fresh source PREPARED_NEW=96: FREE -> ALLOCATED with the PREPARE quota row.
export async function prepareForwardHttpsSourceSessionV3 (state, input) {
  requireOperational(state)
  const stableSessionId = b4a.from(input.stableSessionId)
  if (state.slots.has(keyOf(stableSessionId))) fail('session identity is not NEVER_SEEN', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.SEQUENCE_INVALID)
  if (state.unconsumed < 1) fail('no FREE slot for a fresh source session', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.CAPACITY)
  const slot = freshSlot(state, stableSessionId)
  state.unconsumed--
  const payload = sessionPayload(stableSessionId, input.body || b4a.alloc(0))
  const plan = createForwardHttpsStoreQuotaCostPlanV3(state.storeQuotaCapability, {
    operation: 'PREPARE',
    knownInputBuffers: [payload],
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  })
  const reservation = await reserveForwardHttpsAggregateQuotaV3(state.storeQuotaCapability, plan)
  try {
    bindForwardHttpsStoreQuotaActualBuffersV3(state.storeQuotaCapability, reservation, {
      logicalRecordBuffers: [],
      encryptedPlaintextBuffers: [],
      finalWalMetadataBuffers: [payload],
      temporaryWriteBuffers: []
    })
    const frame = await state.store.appendAndApply({
      type: WAL_TYPE.PREPARED_NEW,
      transactionId: input.transactionId || transactionIdFor(stableSessionId, 0xa5),
      virtualBucket: 0,
      payload
    }, recovered => {
      const derived = deriveForwardHttpsStoreWalQuotaEntryV3({ role: ROLE, frame: recovered })
      slot.registry.admit(derived)
      slot.priorRevision++
      slot.state = FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED
      state.walHeadSequence = derived.walSequence
    })
    await commitForwardHttpsAggregateQuotaV3(state.storeQuotaCapability, reservation, {
      durableWalHeadSequence: frame.sequence,
      durableWalHeadHash: frame.walHash
    })
    return Object.freeze({ walSequence: frame.sequence, walHash: b4a.from(frame.walHash), payload })
  } catch (error) {
    slot.state = FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.FREE
    state.slots.delete(keyOf(stableSessionId))
    state.unconsumed++
    await releaseForwardHttpsAggregateQuotaV3(state.storeQuotaCapability, reservation).catch(() => {})
    throw error
  }
}

// Ordinary source SESSION frame: TRANSPORT_RESERVED=97 or RESULT_PERSISTED=98.
export async function appendForwardHttpsSourceSessionV3 (state, input) {
  requireOperational(state)
  const walType = input.walType
  if (![WAL_TYPE.TRANSPORT_RESERVED, WAL_TYPE.RESULT_PERSISTED].includes(walType)) throw new TypeError('walType must be 97 or 98')
  const stableSessionId = b4a.from(input.stableSessionId)
  const slot = state.slots.get(keyOf(stableSessionId))
  if (!slot || slot.state !== FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED) fail('session is not ALLOCATED', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.SEQUENCE_INVALID)
  const planned = input.plannedRemovableChargeEntryCount == null ? 1 : input.plannedRemovableChargeEntryCount
  if (slot.registry.count + planned > CHARGE_ENTRY_CAP) {
    await terminalizeBudgetExhausted(state, slot, input)
    fail('removable charge entry cap exceeded; session terminalized BUDGET_EXHAUSTED', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.BUDGET_EXHAUSTED)
  }
  const payload = sessionPayload(stableSessionId, input.body || b4a.alloc(0))
  const plan = createForwardHttpsStoreQuotaCostPlanV3(state.storeQuotaCapability, {
    operation: walType === WAL_TYPE.RESULT_PERSISTED ? 'RESULT' : 'PREPARE',
    knownInputBuffers: [payload],
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  })
  const reservation = await reserveForwardHttpsAggregateQuotaV3(state.storeQuotaCapability, plan)
  try {
    bindForwardHttpsStoreQuotaActualBuffersV3(state.storeQuotaCapability, reservation, {
      logicalRecordBuffers: [],
      encryptedPlaintextBuffers: [],
      finalWalMetadataBuffers: [payload],
      temporaryWriteBuffers: []
    })
    const frame = await state.store.appendAndApply({
      type: walType,
      transactionId: input.transactionId || transactionIdFor(stableSessionId, 0xa5),
      virtualBucket: 0,
      payload
    }, recovered => {
      const derived = deriveForwardHttpsStoreWalQuotaEntryV3({ role: ROLE, frame: recovered })
      slot.registry.admit(derived)
      slot.priorRevision++
      state.walHeadSequence = derived.walSequence
    })
    await commitForwardHttpsAggregateQuotaV3(state.storeQuotaCapability, reservation, {
      durableWalHeadSequence: frame.sequence,
      durableWalHeadHash: frame.walHash
    })
    return Object.freeze({ walSequence: frame.sequence, walHash: b4a.from(frame.walHash), payload })
  } catch (error) {
    await releaseForwardHttpsAggregateQuotaV3(state.storeQuotaCapability, reservation).catch(() => {})
    throw error
  }
}

async function appendTerminalPayload (state, slot, payload) {
  const plan = createForwardHttpsStoreQuotaCostPlanV3(state.storeQuotaCapability, {
    operation: 'SESSION_TERMINAL',
    knownInputBuffers: [payload],
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  })
  const reservation = await reserveForwardHttpsAggregateQuotaV3(state.storeQuotaCapability, plan)
  try {
    const frame = await state.store.appendAndApply({
      type: WAL_TYPE.SESSION_TERMINAL,
      transactionId: transactionIdFor(slot.stableSessionId, 0x5a),
      virtualBucket: 0,
      payload
    }, recovered => {
      const derived = deriveForwardHttpsStoreWalQuotaEntryV3({ role: ROLE, frame: recovered })
      slot.priorRevision++
      slot.state = FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.CONSUMED_UNPRUNED
      state.consumedUnpruned++
      state.walHeadSequence = derived.walSequence
    })
    await commitForwardHttpsAggregateQuotaV3(state.storeQuotaCapability, reservation, {
      durableWalHeadSequence: frame.sequence,
      durableWalHeadHash: frame.walHash
    })
    return frame
  } catch (error) {
    await releaseForwardHttpsAggregateQuotaV3(state.storeQuotaCapability, reservation).catch(() => {})
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

export async function terminalizeForwardHttpsSourceSessionV3 (state, input) {
  requireOperational(state)
  const slot = state.slots.get(keyOf(b4a.from(input.stableSessionId)))
  if (!slot || slot.state !== FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED) fail('session is not ALLOCATED', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.TERMINAL)
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
  return Object.freeze({ walSequence: frame.sequence, walHash: b4a.from(frame.walHash), payload })
}

export async function terminalizeForwardHttpsSourceAbsentSequenceV3 (state, input) {
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
    reason: 'SEQUENCE_INVALID',
    exactRequestCommitment: input.exactRequestCommitment,
    expiresAtEpoch: input.expiresAtEpoch,
    retainedUntilEpoch: input.expiresAtEpoch + 900
  })
  const frame = await appendTerminalPayload(state, slot, payload)
  slot.priorRevision = 1n
  slot.minimal = true
  slot.expiresAtEpoch = input.expiresAtEpoch
  slot.recoveryGraceUntilEpoch = input.expiresAtEpoch + 900
  slot.trustedEpochHighWatermark = input.newTrustedEpochHighWatermark
  slot.authorityBitmap = (1 << 7) | (1 << 9)
  const derived = deriveForwardHttpsStoreWalQuotaEntryV3({
    role: ROLE,
    frame: { type: WAL_TYPE.SESSION_TERMINAL, payload, payloadHash: frame.payloadHash, sequence: frame.sequence, frameBytes: 416 }
  })
  slot.authorityCommitments = derived.authorityCommitments
  return Object.freeze({ walSequence: frame.sequence, walHash: b4a.from(frame.walHash), payload })
}

export async function pruneForwardHttpsSourceSessionV3 (state, input) {
  requireOperational(state)
  const slot = state.slots.get(keyOf(b4a.from(input.stableSessionId)))
  if (!slot) fail('session is absent', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
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
  const plan = createForwardHttpsStoreQuotaCostPlanV3(state.storeQuotaCapability, {
    operation: 'PRUNE',
    knownInputBuffers: [payload],
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  })
  const reservation = await reserveForwardHttpsAggregateQuotaV3(state.storeQuotaCapability, plan)
  let frame
  try {
    frame = await state.store.appendAndApply({
      type: WAL_TYPE.RETENTION_PRUNED,
      transactionId: transactionIdFor(slot.stableSessionId, 0x5a),
      virtualBucket: 0,
      payload
    }, () => {})
  } catch (error) {
    await releaseForwardHttpsAggregateQuotaV3(state.storeQuotaCapability, reservation).catch(() => {})
    throw error
  }
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

export function forwardHttpsSourceStoreV3Status (state) {
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

export async function closeForwardHttpsSourceStoreV3 (state) {
  if (!state || typeof state !== 'object') fail('source store authority is forged', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INVALID)
  if (state.closed) return
  state.closed = true
  state.localOperational = false
  await state.store.close()
}

export const FORWARD_HTTPS_SOURCE_STORE_V3_WAL_TYPE = WAL_TYPE
