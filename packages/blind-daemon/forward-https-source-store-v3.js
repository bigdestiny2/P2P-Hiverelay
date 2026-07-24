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
  bindForwardHttpsStoreQuotaActualBuffersV3,
  applyForwardHttpsAggregateQuotaWalFrameV3,
  assertForwardHttpsAggregateQuotaOperationalV3,
  absorbForwardHttpsAggregateQuotaRecoveryFrameV3,
  encodeForwardHttpsRetentionPrunedV3,
  decodeForwardHttpsRetentionPrunedV3
} from './forward-https-replay-journal-v4.js'

const ROLE = FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3.SOURCE_STORE
const ZERO32 = b4a.alloc(32)

// Module-private store-side vocabulary and arithmetic. No decoder, registry
// commitment, charge or bitmap logic is duplicated here: commitment
// computation lives solely in the hash-bound replay module's codecs.
const STORE_ERROR_CODE = Object.freeze({
  INVALID: 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_INVALID',
  CAPACITY: 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_CAPACITY',
  TERMINAL: 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_TERMINAL',
  CONFLICT: 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_CONFLICT',
  SESSION_CLOSED: 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_SESSION_CLOSED',
  BUDGET_EXHAUSTED: 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_BUDGET_EXHAUSTED',
  SEQUENCE_INVALID: 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_SEQUENCE_INVALID',
  CHAIN_INVALID: 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_CHAIN_INVALID',
  CLOSED: 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_CLOSED',
  INTEGRITY: 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_INTEGRITY'
})

const SLOT_STATE = Object.freeze({
  FREE: 'FREE',
  PROVISIONAL: 'PROVISIONAL',
  PREFIX_ALLOCATED: 'PREFIX_ALLOCATED',
  ALLOCATED: 'ALLOCATED',
  ALLOCATED_WITH_PREFIX: 'ALLOCATED_WITH_PREFIX',
  CONSUMED_UNPRUNED: 'CONSUMED_UNPRUNED',
  CONSUMED_PRUNED: 'CONSUMED_PRUNED'
})

const HISTORIC_IDENTITY = Object.freeze({
  NEVER_SEEN: 'NEVER_SEEN',
  PRESENT_PREFIX_ALLOCATED: 'PRESENT_PREFIX_ALLOCATED',
  ALLOCATED_WITH_PREFIX: 'ALLOCATED_WITH_PREFIX',
  PRESENT_ALLOCATED: 'PRESENT_ALLOCATED',
  PRESENT_CONSUMED_UNPRUNED: 'PRESENT_CONSUMED_UNPRUNED',
  PRUNED_RELEASED: 'PRUNED_RELEASED',
  PRUNED_CONSUMED: 'PRUNED_CONSUMED'
})

function classifyHistoricIdentity (slotState, hadPruneTombstone) {
  if (slotState === SLOT_STATE.ALLOCATED || slotState === SLOT_STATE.PROVISIONAL) return HISTORIC_IDENTITY.PRESENT_ALLOCATED
  if (slotState === SLOT_STATE.PREFIX_ALLOCATED) return HISTORIC_IDENTITY.PRESENT_PREFIX_ALLOCATED
  if (slotState === SLOT_STATE.ALLOCATED_WITH_PREFIX) return HISTORIC_IDENTITY.ALLOCATED_WITH_PREFIX
  if (slotState === SLOT_STATE.CONSUMED_UNPRUNED) return HISTORIC_IDENTITY.PRESENT_CONSUMED_UNPRUNED
  if (slotState === SLOT_STATE.CONSUMED_PRUNED) return HISTORIC_IDENTITY.PRUNED_CONSUMED
  if (slotState === SLOT_STATE.FREE && hadPruneTombstone) return HISTORIC_IDENTITY.PRUNED_RELEASED
  return HISTORIC_IDENTITY.NEVER_SEEN
}

const CHARGE_ENTRY_BYTES = 49

function writeU64be (output, offset, value) {
  if (typeof value === 'number') value = BigInt(value)
  for (let index = 7; index >= 0; index--) { output[offset + index] = Number(value & 0xffn); value >>= 8n }
  return offset + 8
}

// Formula-free removable charge-entry accumulator. The streaming commitment
// over these exact49-byte entries is computed only inside the replay module's
// FPR9 codec; this registry packs entries, counts, sums and removes.
function createChargeRegistry (role, stableSessionId) {
  const session = b4a.from(stableSessionId)
  const entries = []
  return Object.freeze({
    role,
    stableSessionId: session,
    get count () { return entries.length },
    admit (derived) {
      if (!derived || derived.scope !== 'SESSION' || derived.ordinaryLogicalCharge <= 0) {
        fail('charge entry must be an ordinary SESSION derivation', STORE_ERROR_CODE.INTEGRITY)
      }
      if (!b4a.equals(derived.stableSessionId, session)) fail('charge entry session mismatch', STORE_ERROR_CODE.INTEGRITY)
      if (entries.length >= CHARGE_ENTRY_CAP) fail('removable charge entry cap exceeded', STORE_ERROR_CODE.INTEGRITY)
      const entry = b4a.alloc(CHARGE_ENTRY_BYTES)
      entry[0] = derived.walType
      writeU64be(entry, 1, derived.walSequence)
      b4a.copy(derived.payloadHash, entry, 9)
      writeU64be(entry, 41, BigInt(derived.ordinaryLogicalCharge))
      entries.push(entry)
      return entry
    },
    removedLogicalBytes () {
      return entries.reduce((sum, entry) => {
        let value = 0n
        for (let index = 41; index < 49; index++) value = (value << 8n) | BigInt(entry[index])
        return sum + value
      }, 0n)
    },
    removeExact (entryBuffers) {
      let removedSum = 0n
      let removedCount = 0
      for (const target of entryBuffers) {
        const index = entries.findIndex(entry => b4a.equals(entry, target))
        if (index === -1) fail('orphan entry is not in the charge registry', STORE_ERROR_CODE.INTEGRITY)
        const removed = entries.splice(index, 1)[0]
        let value = 0n
        for (let byte = 41; byte < 49; byte++) value = (value << 8n) | BigInt(removed[byte])
        removedSum += value
        removedCount++
      }
      return Object.freeze({ count: removedCount, removedSum })
    },
    entriesAscending () {
      return Object.freeze([...entries].sort((left, right) => {
        for (let index = 1; index < 9; index++) if (left[index] !== right[index]) return left[index] - right[index]
        return 0
      }).map(entry => b4a.from(entry)))
    }
  })
}

// Protected terminal headroom arithmetic (test-open minimums).
function verifyTerminalHeadroom (input) {
  const capacity = input.capacity
  if (!Number.isSafeInteger(capacity) || capacity < 1 || capacity > 65536) throw new TypeError('capacity is outside 1..65536')
  const perStore = input.maximumDurableBytesPerStore
  const aggregate = input.maximumForwardStorageBytesAggregate
  if (!Number.isSafeInteger(perStore) || perStore < 1 || perStore > 8589934592) throw new TypeError('per-store ceiling is invalid')
  if (!Number.isSafeInteger(aggregate) || aggregate < 1 || aggregate > 17179869184) throw new TypeError('aggregate ceiling is invalid')
  if (BigInt(perStore) < BigInt(capacity) * 1344n || BigInt(perStore) < BigInt(capacity) * 896n ||
      BigInt(aggregate) < 2n * BigInt(capacity) * 1344n || BigInt(aggregate) < 2n * BigInt(capacity) * 896n) {
    fail('terminal headroom minimums are violated', STORE_ERROR_CODE.INVALID)
  }
}

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
  constructor (message, code = STORE_ERROR_CODE.INVALID) {
    super(message)
    this.name = 'ForwardHttpsSourceStoreV3Error'
    this.code = code
  }
}

function fail (message, code) {
  throw new ForwardHttpsSourceStoreV3Error(message, code)
}

// Module-level fault points (FORWARD_HTTPS_SOURCE_STORE_V3_FAULT_POINT): the
// injector observes exactly the point string (no context); any injector
// failure or non-undefined return is a coded INTEGRITY error, never an
// uncoded callback escape.
async function storeFault (state, point) {
  if (state.faultInjector === null) return
  let result
  try {
    result = await state.faultInjector(point)
  } catch (error) {
    fail(`fault injector failed at ${point}`, STORE_ERROR_CODE.INTEGRITY)
  }
  if (result !== undefined) fail(`fault injector returned a value at ${point}`, STORE_ERROR_CODE.INTEGRITY)
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

function requireBytes32 (value, field, nonzero = true) {
  if (!value || typeof value.byteLength !== 'number') throw new TypeError(`${field} must be bytes`)
  const output = b4a.isBuffer(value) ? value : b4a.from(value)
  if (output.byteLength !== 32) throw new TypeError(`${field} must be exactly 32 bytes`)
  if (nonzero && b4a.equals(output, ZERO32)) throw new TypeError(`${field} must be nonzero`)
  return output
}

// Exact retained v4 open ABI for the source store: 13 required keys, 2
// optional. The recovery sink is begun by the caller through the quota ABI
// and passed in; the store absorbs through it but never begins or finishes it.
export async function openForwardHttpsSourceStoreV3 (options) {
  const required = ['root', 'replayJournalAuthority', 'sourceStoreQuotaCapability', 'sourceQuotaRecoverySink', 'wireV3AbiHash', 'privateIpcV4Hash', 'signedLaunchTopologyHash', 'storeId', 'mapGeneration', 'ownerFenceTokenHash', 'durabilityContinuityHash', 'epochSeconds', 'monotonicMillis']
  const optional = ['limits', 'faultInjector']
  if (!options || typeof options !== 'object' || Array.isArray(options)) throw new TypeError('options must be a closed object')
  for (const key of required) if (!Object.hasOwn(options, key)) throw new TypeError(`options.${key} is required`)
  for (const key of Object.keys(options)) if (!required.includes(key) && !optional.includes(key)) throw new TypeError(`options contains unknown field ${key}`)
  if (typeof options.root !== 'string') throw new TypeError('root is required')
  if (!options.replayJournalAuthority || typeof options.replayJournalAuthority !== 'object') throw new TypeError('replayJournalAuthority is required')
  if (!options.sourceStoreQuotaCapability || typeof options.sourceStoreQuotaCapability !== 'object') throw new TypeError('sourceStoreQuotaCapability is required')
  if (!options.sourceQuotaRecoverySink || typeof options.sourceQuotaRecoverySink !== 'object') throw new TypeError('sourceQuotaRecoverySink is required')
  const wireV3AbiHash = requireBytes32(options.wireV3AbiHash, 'wireV3AbiHash')
  const privateIpcV4Hash = requireBytes32(options.privateIpcV4Hash, 'privateIpcV4Hash')
  const signedLaunchTopologyHash = requireBytes32(options.signedLaunchTopologyHash, 'signedLaunchTopologyHash')
  const storeId = requireBytes32(options.storeId, 'storeId')
  if (typeof options.mapGeneration !== 'bigint' || options.mapGeneration <= 0n) throw new TypeError('mapGeneration must be a nonzero u64')
  const ownerFenceTokenHash = requireBytes32(options.ownerFenceTokenHash, 'ownerFenceTokenHash')
  const durabilityContinuityHash = requireBytes32(options.durabilityContinuityHash, 'durabilityContinuityHash')
  if (typeof options.epochSeconds !== 'function') throw new TypeError('epochSeconds must be a function')
  if (typeof options.monotonicMillis !== 'function') throw new TypeError('monotonicMillis must be a function')
  const capacity = options.limits && typeof options.limits.maximumRetainedTurnsPerRole === 'number'
    ? options.limits.maximumRetainedTurnsPerRole
    : PRODUCTION_SLOTS
  if (!Number.isSafeInteger(capacity) || capacity < 1 || capacity > PRODUCTION_SLOTS) throw new TypeError('slot capacity is invalid')
  if (options.limits) {
    verifyTerminalHeadroom({
      capacity,
      maximumDurableBytesPerStore: options.limits.maximumDurableBytesPerStore,
      maximumForwardStorageBytesAggregate: options.limits.maximumForwardStorageBytesAggregate
    })
  }
  const state = {
    role: ROLE,
    storeQuotaCapability: options.sourceStoreQuotaCapability,
    replayJournalAuthority: options.replayJournalAuthority,
    epochSeconds: options.epochSeconds,
    wireV3AbiHash,
    privateIpcV4Hash,
    signedLaunchTopologyHash,
    storeId,
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
    faultInjector: options.faultInjector || null,
    store: new BlindTransactionStore({
      root: options.root,
      mapGeneration: options.mapGeneration,
      ownerFenceTokenHash,
      durabilityContinuityHash,
      maximumWalPayloadBytes: 16777216,
      // The caller's injector observes only this module's frozen fault points;
      // raw engine points (with contexts) never escape to callers.
      faultInjector: null
    })
  }
  // Recovery absorbs through the caller-begun quota recovery sink. The caller
  // (composite) finishes the sink and initializes the quota authority; only
  // recovery work is permitted before initialization.
  state.recoverySink = options.sourceQuotaRecoverySink
  await state.store.open(frame => recoverFrame(state, frame))
  state.recoverySink = null
  state.walHeadSequence = state.store.walSequence
  state.walHeadHash = b4a.from(state.store.walHash)
  state.localOperational = true
  try {
    await storeFault(state, FORWARD_HTTPS_SOURCE_STORE_V3_FAULT_POINT.OPEN_AFTER_RECOVERY)
  } catch (error) {
    // A rejected open never leaks a live engine: the store is failure-atomic
    // toward CLOSED before the coded error escapes.
    state.closed = true
    state.localOperational = false
    await state.store.close().catch(() => {})
    throw error
  }
  return state
}

async function recoverFrame (state, frame) {
  const { entry: derived } = await absorbForwardHttpsAggregateQuotaRecoveryFrameV3(state.recoverySink, { frame, storeQuotaCapability: state.storeQuotaCapability })
  if (derived.scope === 'ROLE_GLOBAL') {
    state.roleGlobalLogicalBytes += derived.ordinaryLogicalCharge
    return
  }
  const key = keyOf(derived.stableSessionId)
  let slot = state.slots.get(key)
  if (slot && (slot.state === SLOT_STATE.CONSUMED_PRUNED || slot.prunedReleased)) {
    fail('post-prune SESSION entry is INTEGRITY', STORE_ERROR_CODE.INTEGRITY)
  }
  if (derived.scope === 'SESSION' && derived.walType !== WAL_TYPE.SESSION_TERMINAL) {
    if (!slot) {
      if (derived.walType !== WAL_TYPE.PREPARED_NEW) fail('first source session frame must be PREPARED_NEW', STORE_ERROR_CODE.INTEGRITY)
      if (state.unconsumed < 1) fail('recovered slots exceed capacity', STORE_ERROR_CODE.INTEGRITY)
      slot = freshSlot(state, derived.stableSessionId)
      slot.state = SLOT_STATE.ALLOCATED
      state.unconsumed--
    }
    slot.registry.admit(derived)
    slot.priorRevision++
  } else if (derived.walType === WAL_TYPE.SESSION_TERMINAL) {
    if (!slot) {
      if (state.unconsumed < 1) fail('recovered terminal slots exceed capacity', STORE_ERROR_CODE.INTEGRITY)
      slot = freshSlot(state, derived.stableSessionId)
      state.unconsumed--
      slot.priorRevision = 1n
      slot.minimal = true
      slot.authorityBitmap = derived.authorityBitmap
      slot.authorityCommitments = derived.authorityCommitments
      // The FTM9-carried exact expiry clock is recovered with the session.
      slot.expiresAtEpoch = frame.payload.readUInt32BE(141)
      slot.recoveryGraceUntilEpoch = frame.payload.readUInt32BE(145)
      slot.trustedEpochHighWatermark = frame.payload.readUInt32BE(72)
    } else {
      if (slot.state !== SLOT_STATE.ALLOCATED) fail('duplicate terminal is INTEGRITY', STORE_ERROR_CODE.INTEGRITY)
      slot.priorRevision++
      slot.authorityBitmap = derived.authorityBitmap
      slot.authorityCommitments = derived.authorityCommitments
    }
    slot.state = SLOT_STATE.CONSUMED_UNPRUNED
    state.consumedUnpruned++
  } else if (derived.walType === WAL_TYPE.RETENTION_PRUNED) {
    if (!slot) fail('unmatched prune tombstone is INTEGRITY', STORE_ERROR_CODE.INTEGRITY)
    const pruned = decodeForwardHttpsRetentionPrunedV3(frame.payload)
    if (slot.state === SLOT_STATE.ALLOCATED) {
      assertPruneMatch(slot, pruned, frame.payload)
      slot.state = SLOT_STATE.FREE
      slot.prunedReleased = true
      state.unconsumed++
    } else if (slot.state === SLOT_STATE.CONSUMED_UNPRUNED) {
      assertPruneMatch(slot, pruned, frame.payload)
      slot.state = SLOT_STATE.CONSUMED_PRUNED
      state.consumedUnpruned--
      state.consumedPruned++
    } else {
      fail('duplicate or misordered prune tombstone is INTEGRITY', STORE_ERROR_CODE.INTEGRITY)
    }
    slot.authorityBitmap = 0
    state.roleGlobalLogicalBytes += derived.ordinaryLogicalCharge
  }
  state.walHeadSequence = derived.walSequence
}

// Independent match of a recovered flags0 tombstone: count, exact sum,
// revision, vector and clocks are matched against the recovered registry and
// the whole tombstone is re-encoded from the recovered entries and compared
// byte-for-byte (chain and both registry commitments are recomputed by the
// hash-bound replay codec). Any tamper is INTEGRITY.
function assertPruneMatch (slot, pruned, payload) {
  if (pruned.priorSessionRevision !== slot.priorRevision ||
      pruned.beforeAuthorityBitmap !== slot.authorityBitmap ||
      pruned.chargeEntryCount !== slot.registry.count ||
      pruned.removedOrdinaryLogicalBytes !== slot.registry.removedLogicalBytes() ||
      pruned.expiresAtEpoch !== slot.expiresAtEpoch ||
      pruned.recoveryGraceUntilEpoch !== slot.recoveryGraceUntilEpoch) {
    fail('recovered tombstone does not independently match the session registry', STORE_ERROR_CODE.INTEGRITY)
  }
  const reencoded = encodeForwardHttpsRetentionPrunedV3({
    role: ROLE,
    flags: pruned.flags,
    stableSessionId: slot.stableSessionId,
    priorSessionRevision: pruned.priorSessionRevision,
    pruneEpochSeconds: pruned.pruneEpochSeconds,
    trustedEpochHighWatermark: pruned.trustedEpochHighWatermark,
    expiresAtEpoch: pruned.expiresAtEpoch,
    recoveryGraceUntilEpoch: pruned.recoveryGraceUntilEpoch,
    removedOrdinaryLogicalBytes: pruned.removedOrdinaryLogicalBytes,
    chargeEntryCount: pruned.chargeEntryCount,
    beforeAuthorityBitmap: pruned.beforeAuthorityBitmap,
    allocationDisposition: pruned.allocationDisposition,
    terminalSlotState: pruned.terminalSlotState,
    chargeEntryBuffers: slot.registry.entriesAscending(),
    authorityCommitments: slot.authorityCommitments || Array.from({ length: 10 }, () => b4a.from(ZERO32))
  })
  if (!b4a.equals(reencoded, payload)) fail('recovered tombstone does not byte-match the re-encoded candidate', STORE_ERROR_CODE.INTEGRITY)
}

function freshSlot (state, stableSessionId) {
  const slot = {
    stableSessionId: b4a.from(stableSessionId),
    state: SLOT_STATE.FREE,
    registry: createChargeRegistry(ROLE, stableSessionId),
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
  if (state.closed) fail('source store is closed', STORE_ERROR_CODE.CLOSED)
  if (state.failedPruneDurablePending) fail('source store is FAILED_PRUNE_DURABLE_PENDING', STORE_ERROR_CODE.INTEGRITY)
  if (!state.localOperational) fail('source store is not operational', STORE_ERROR_CODE.INVALID)
  // The universal operational gate: every role operation passes it before
  // any identity, cache, callback or mutation work (v13).
  assertForwardHttpsAggregateQuotaOperationalV3(state.storeQuotaCapability)
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
  if (union.disposition === 'ENTRY_CAP_TERMINAL') {
    // The canonical mirror proves cap+1 even where the store-side pre-check
    // passed (the mirror runs ahead of the store registry): drive the exact
    // terminal conversion instead of binding the ordinary frames — a lawful
    // in-cap turn never releases a terminal reservation into FAILED_PREWRITE
    // (REREVIEW3-P1-002).
    await driveEntryCapTerminal(state, slot, union, slot.stableSessionId)
    fail('removable charge entry cap exceeded; ENTRY_CAP_TERMINAL', STORE_ERROR_CODE.BUDGET_EXHAUSTED)
  }
  const reservation = union.reservation
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

// Fresh source PREPARED_NEW=96: FREE -> ALLOCATED with the PREPARE quota row.
export async function prepareForwardHttpsSourceTurnV3 (state, input) {
  requireOperational(state)
  const stableSessionId = b4a.from(input.stableSessionId)
  const existing = state.slots.get(keyOf(stableSessionId))
  // PRUNED_RELEASED returns mutation-free CONFLICT; a present session is
  // SEQUENCE_INVALID; no historic state is reclassified as NEVER_SEEN.
  if (existing && existing.prunedReleased) fail('session identity is PRUNED_RELEASED', STORE_ERROR_CODE.CONFLICT)
  if (existing) fail('session identity is not NEVER_SEEN', STORE_ERROR_CODE.SEQUENCE_INVALID)
  if (state.unconsumed < 1) fail('no FREE slot for a fresh source session', STORE_ERROR_CODE.CAPACITY)
  const slot = freshSlot(state, stableSessionId)
  state.unconsumed--
  const payload = sessionPayload(stableSessionId, input.body || b4a.alloc(0))
  try {
    const entry = await appendOperation(state, slot, 'PREPARE', [{
      type: WAL_TYPE.PREPARED_NEW,
      transactionId: input.transactionId || transactionIdFor(stableSessionId, 0xa5),
      virtualBucket: 0,
      payload
    }])
    slot.state = SLOT_STATE.ALLOCATED
    return Object.freeze({ walSequence: entry.walSequence, walHash: b4a.from(state.store.walHash), payload })
  } catch (error) {
    if (slot.state === SLOT_STATE.FREE) {
      state.slots.delete(keyOf(stableSessionId))
      state.unconsumed++
    }
    throw error
  }
}

// The exact 192-byte flags0 BUDGET_EXHAUSTED FTM9 the store constructs for
// the wired cap+1 terminal conversion (frozen layout; module-private, never
// exported): the prior revision comes from the exact minted expectation, the
// flags0 tail is zeroed.
function terminalFtm9Payload (state, slot, stableSessionId, priorSessionRevision) {
  const output = b4a.alloc(192)
  let offset = 0
  b4a.copy(b4a.from('FTM9', 'ascii'), output, offset); offset += 4
  output[offset++] = 1
  output[offset++] = 1
  output.writeUInt16BE(0, offset); offset += 2
  b4a.copy(stableSessionId, output, offset); offset += 32
  offset = writeU64be(output, offset, state.walHeadSequence + 1n)
  for (let index = 0; index < 5; index++) { output.writeUInt16BE(0, offset); offset += 2 }
  output.writeUInt16BE(0, offset); offset += 2
  output.writeUInt32BE(0, offset); offset += 4
  offset = writeU64be(output, offset, priorSessionRevision)
  output.writeUInt32BE(slot.trustedEpochHighWatermark || 0, offset); offset += 4
  const reason = b4a.from('BUDGET_EXHAUSTED', 'ascii')
  output[offset++] = reason.byteLength
  b4a.copy(reason, output, offset)
  return output
}

// Drive the exact ENTRY_CAP terminal conversion against the minted terminal
// reservation: bind the exact flags0 BUDGET_EXHAUSTED FTM9, append and
// commit, and transition the slot ALLOCATED -> CONSUMED_UNPRUNED exactly as
// the recoverFrame terminal arm does on reopen.
async function driveEntryCapTerminal (state, slot, union, stableSessionId) {
  const payload = terminalFtm9Payload(state, slot, stableSessionId, union.terminalExpectation.priorSessionRevision)
  const { transitionAuthority } = bindForwardHttpsStoreQuotaActualBuffersV3(state.storeQuotaCapability, union.terminalReservation, {
    logicalRecordBuffers: [],
    encryptedPlaintextBuffers: [],
    finalWalMetadataBuffers: [payload],
    temporaryWriteBuffers: []
  })
  const applied = await applyForwardHttpsAggregateQuotaWalFrameV3(state.storeQuotaCapability, union.terminalReservation, transitionAuthority, {
    type: WAL_TYPE.SESSION_TERMINAL,
    transactionId: transactionIdFor(stableSessionId, 0x5a),
    virtualBucket: 0,
    payload
  }, async candidate => state.store.appendAndApply(candidate, () => {}))
  await commitForwardHttpsAggregateQuotaV3(state.storeQuotaCapability, union.terminalReservation, {
    durableWalHeadSequence: state.store.walSequence,
    durableWalHeadHash: state.store.walHash
  })
  slot.priorRevision++
  slot.authorityBitmap = applied.entry.authorityBitmap
  slot.authorityCommitments = applied.entry.authorityCommitments
  slot.state = SLOT_STATE.CONSUMED_UNPRUNED
  state.consumedUnpruned++
  state.walHeadSequence = applied.entry.walSequence
}

// Store-side cap+1 decision: reserve the rejected ordinary operation and
// either drive the exact terminal conversion (the canonical mirror proves
// cap+1 too) or release the ordinary reservation cleanly (the mirror admits
// what the store registry cannot hold) — the minted reservation and the FIFO
// op ticket are never abandoned (REREVIEW3-P1-001).
async function terminalizeEntryCap (state, slot, operation, frames, stableSessionId) {
  const plan = createForwardHttpsStoreQuotaCostPlanV3(state.storeQuotaCapability, {
    operation,
    knownInputBuffers: frames.map(frame => frame.payload),
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  })
  const union = await reserveForwardHttpsAggregateQuotaV3(state.storeQuotaCapability, plan)
  if (union.disposition !== 'ENTRY_CAP_TERMINAL') {
    await releaseForwardHttpsAggregateQuotaV3(state.storeQuotaCapability, union.reservation)
    fail('removable charge entry cap exceeded; ENTRY_CAP_TERMINAL', STORE_ERROR_CODE.BUDGET_EXHAUSTED)
  }
  await driveEntryCapTerminal(state, slot, union, stableSessionId)
  fail('removable charge entry cap exceeded; ENTRY_CAP_TERMINAL', STORE_ERROR_CODE.BUDGET_EXHAUSTED)
}

// Ordinary source SESSION frame: TRANSPORT_RESERVED=97 or RESULT_PERSISTED=98.
export async function persistForwardHttpsSourceResultV3 (state, input) {
  requireOperational(state)
  const walType = input.walType
  if (![WAL_TYPE.TRANSPORT_RESERVED, WAL_TYPE.RESULT_PERSISTED].includes(walType)) throw new TypeError('walType must be 97 or 98')
  const stableSessionId = b4a.from(input.stableSessionId)
  const slot = state.slots.get(keyOf(stableSessionId))
  // Identity first-match at the store boundary (v16 stage_2): PRUNED_RELEASED
  // returns mutation-free CONFLICT; consumed identities are sticky TERMINAL.
  if (slot && slot.prunedReleased) fail('session identity is PRUNED_RELEASED', STORE_ERROR_CODE.CONFLICT)
  if (slot && (slot.state === SLOT_STATE.CONSUMED_UNPRUNED || slot.state === SLOT_STATE.CONSUMED_PRUNED)) fail('session identity is TERMINAL', STORE_ERROR_CODE.TERMINAL)
  if (!slot || slot.state !== SLOT_STATE.ALLOCATED) fail('session is not ALLOCATED', STORE_ERROR_CODE.SEQUENCE_INVALID)
  const planned = input.plannedRemovableChargeEntryCount == null ? 1 : input.plannedRemovableChargeEntryCount
  // The exact operation row plans exactly one removable entry; a caller hint
  // above it rejects at the boundary, pre-mutation.
  if (!Number.isSafeInteger(planned) || planned !== 1) {
    throw new TypeError('plannedRemovableChargeEntryCount exceeds the exact operation row')
  }
  const payload = sessionPayload(stableSessionId, input.body || b4a.alloc(0))
  const operation = walType === WAL_TYPE.RESULT_PERSISTED ? 'RESULT' : 'PREPARE'
  const frames = [{
    type: walType,
    transactionId: input.transactionId || transactionIdFor(stableSessionId, 0xa5),
    virtualBucket: 0,
    payload
  }]
  if (slot.registry.count + planned > CHARGE_ENTRY_CAP) {
    // Cap+1 terminalizes through the quota ENTRY_CAP_TERMINAL arm before the
    // caller sees BUDGET_EXHAUSTED: the exact flags0 BUDGET_EXHAUSTED FTM9
    // binds the minted terminal reservation, appends and commits, and the
    // session ends CONSUMED_UNPRUNED.
    await terminalizeEntryCap(state, slot, operation, frames, stableSessionId)
    fail('removable charge entry cap exceeded; ENTRY_CAP_TERMINAL', STORE_ERROR_CODE.BUDGET_EXHAUSTED)
  }
  const entry = await appendOperation(state, slot, operation, frames)
  return Object.freeze({ walSequence: entry.walSequence, walHash: b4a.from(state.store.walHash), payload })
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
  if (!state || typeof state !== 'object') fail('source store authority is forged', STORE_ERROR_CODE.INVALID)
  if (state.closed) return
  state.closed = true
  state.localOperational = false
  // Failure-atomic toward CLOSED: a close-fault failure is reported after the
  // engine closes, never leaving the store stuck or the engine open.
  let closeFault = null
  try {
    await storeFault(state, FORWARD_HTTPS_SOURCE_STORE_V3_FAULT_POINT.CLOSE_BEFORE_STORE_CLOSE)
  } catch (error) {
    closeFault = error
  }
  // A faulted close carries blocker INTEGRITY on the store status.
  if (closeFault !== null) state.blocker = STORE_ERROR_CODE.INTEGRITY
  await state.store.close()
  if (closeFault !== null) throw closeFault
}

export const FORWARD_HTTPS_SOURCE_WAL_TYPE = WAL_TYPE

export const FORWARD_HTTPS_SOURCE_STORE_V3_STATUS = Object.freeze({
  schemaVersion: 3,
  implementationReady: false,
  descriptorOperationBits: 0,
  advertisedOperationBits: 0,
  readinessOperationBits: 0,
  runtimeReady: false,
  releaseReady: false,
  authorizesRelease: false
})

export const FORWARD_HTTPS_SOURCE_STORE_V3_ERROR_CODE = STORE_ERROR_CODE

export const FORWARD_HTTPS_SOURCE_STORE_V3_FAULT_POINT = Object.freeze({
  OPEN_AFTER_RECOVERY: 'OPEN_AFTER_RECOVERY',
  PREPARE_AFTER_REPLAY_BURN: 'PREPARE_AFTER_REPLAY_BURN',
  PREPARE_AFTER_FINALIZE: 'PREPARE_AFTER_FINALIZE',
  PREPARE_BEFORE_WAL_APPEND: 'PREPARE_BEFORE_WAL_APPEND',
  PREPARE_AFTER_WAL_FSYNC: 'PREPARE_AFTER_WAL_FSYNC',
  RESULT_BEFORE_WAL_APPEND: 'RESULT_BEFORE_WAL_APPEND',
  RESULT_AFTER_WAL_FSYNC: 'RESULT_AFTER_WAL_FSYNC',
  TERMINAL_AFTER_WAL_FSYNC: 'TERMINAL_AFTER_WAL_FSYNC',
  QUARANTINE_AFTER_WAL_FSYNC: 'QUARANTINE_AFTER_WAL_FSYNC',
  PRUNE_AFTER_WAL_FSYNC: 'PRUNE_AFTER_WAL_FSYNC',
  CLOSE_BEFORE_STORE_CLOSE: 'CLOSE_BEFORE_STORE_CLOSE'
})

// V18 source_module_exact names for the turn-level surface.

export function forwardHttpsSourceTurnStateV3 (state, stableSessionId) {
  const slot = state.slots.get(keyOf(b4a.from(stableSessionId))) || null
  return Object.freeze({
    present: slot !== null,
    slotState: slot ? slot.state : SLOT_STATE.FREE,
    identity: classifyHistoricIdentity(slot ? slot.state : SLOT_STATE.FREE, slot ? slot.prunedReleased : false),
    chargeEntryCount: slot ? slot.registry.count : 0,
    priorSessionRevision: slot ? slot.priorRevision : 0n
  })
}
