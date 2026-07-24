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
  bindForwardHttpsStoreQuotaActualBuffersV3,
  applyForwardHttpsAggregateQuotaWalFrameV3,
  assertForwardHttpsAggregateQuotaOperationalV3,
  absorbForwardHttpsAggregateQuotaRecoveryFrameV3,
  encodeForwardHttpsRetentionPrunedV3,
  decodeForwardHttpsRetentionPrunedV3
} from './forward-https-replay-journal-v4.js'

const ROLE = FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3.TARGET_STORE
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

const CHARGE_ENTRY_CAP = 65536
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
  constructor (message, code = STORE_ERROR_CODE.INVALID) {
    super(message)
    this.name = 'ForwardHttpsTargetStoreV3Error'
    this.code = code
  }
}

function fail (message, code) {
  throw new ForwardHttpsTargetStoreV3Error(message, code)
}

// Module-level fault points (FORWARD_HTTPS_TARGET_STORE_V3_FAULT_POINT): the
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

function sessionPayload (walTypeMagic, stableSessionId, body) {
  return b4a.concat([walTypeMagic, stableSessionId, body || b4a.alloc(0)])
}

function requireBytes32 (value, field, nonzero = true) {
  if (!value || typeof value.byteLength !== 'number') throw new TypeError(`${field} must be bytes`)
  const output = b4a.isBuffer(value) ? value : b4a.from(value)
  if (output.byteLength !== 32) throw new TypeError(`${field} must be exactly 32 bytes`)
  if (nonzero && b4a.equals(output, ZERO32)) throw new TypeError(`${field} must be nonzero`)
  return output
}

// Exact retained v4 open ABI for the target store: 21 required keys, 2
// optional. The recovery sink is begun by the caller through the quota ABI
// and passed in; the store absorbs through it but never begins or finishes
// it. Signer callbacks and the at-rest key are validated and held by the
// composite; they are never retained by this store.
export async function openForwardHttpsTargetStoreV3 (options) {
  const required = ['root', 'replayJournalAuthority', 'targetStoreQuotaCapability', 'targetQuotaRecoverySink', 'wireV3AbiHash', 'privateIpcV4Hash', 'signedLaunchTopologyHash', 'storeId', 'mapGeneration', 'ownerFenceTokenHash', 'durabilityContinuityHash', 'targetSignerPublicKey', 'targetSignerDescriptorSequence', 'targetSignerDescriptorHash', 'signResult', 'createResponderState', 'advanceResponderIngress', 'advanceResponderOutcome', 'atRestKey', 'epochSeconds', 'monotonicMillis']
  const optional = ['limits', 'faultInjector']
  if (!options || typeof options !== 'object' || Array.isArray(options)) throw new TypeError('options must be a closed object')
  for (const key of required) if (!Object.hasOwn(options, key)) throw new TypeError(`options.${key} is required`)
  for (const key of Object.keys(options)) if (!required.includes(key) && !optional.includes(key)) throw new TypeError(`options contains unknown field ${key}`)
  if (typeof options.root !== 'string') throw new TypeError('root is required')
  if (!options.replayJournalAuthority || typeof options.replayJournalAuthority !== 'object') throw new TypeError('replayJournalAuthority is required')
  if (!options.targetStoreQuotaCapability || typeof options.targetStoreQuotaCapability !== 'object') throw new TypeError('targetStoreQuotaCapability is required')
  if (!options.targetQuotaRecoverySink || typeof options.targetQuotaRecoverySink !== 'object') throw new TypeError('targetQuotaRecoverySink is required')
  const wireV3AbiHash = requireBytes32(options.wireV3AbiHash, 'wireV3AbiHash')
  const privateIpcV4Hash = requireBytes32(options.privateIpcV4Hash, 'privateIpcV4Hash')
  const signedLaunchTopologyHash = requireBytes32(options.signedLaunchTopologyHash, 'signedLaunchTopologyHash')
  const storeId = requireBytes32(options.storeId, 'storeId')
  if (typeof options.mapGeneration !== 'bigint' || options.mapGeneration <= 0n) throw new TypeError('mapGeneration must be a nonzero u64')
  const ownerFenceTokenHash = requireBytes32(options.ownerFenceTokenHash, 'ownerFenceTokenHash')
  const durabilityContinuityHash = requireBytes32(options.durabilityContinuityHash, 'durabilityContinuityHash')
  requireBytes32(options.targetSignerPublicKey, 'targetSignerPublicKey')
  if (typeof options.targetSignerDescriptorSequence !== 'bigint' || options.targetSignerDescriptorSequence <= 0n) throw new TypeError('targetSignerDescriptorSequence must be a nonzero u64')
  requireBytes32(options.targetSignerDescriptorHash, 'targetSignerDescriptorHash')
  for (const callback of ['signResult', 'createResponderState', 'advanceResponderIngress', 'advanceResponderOutcome']) {
    if (typeof options[callback] !== 'function') throw new TypeError(`${callback} must be a function`)
  }
  requireBytes32(options.atRestKey, 'atRestKey')
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
    storeQuotaCapability: options.targetStoreQuotaCapability,
    replayJournalAuthority: options.replayJournalAuthority,
    epochSeconds: options.epochSeconds,
    wireV3AbiHash,
    privateIpcV4Hash,
    signedLaunchTopologyHash,
    capacity,
    storeId,
    mapGeneration: options.mapGeneration,
    ownerFenceTokenHash,
    durabilityContinuityHash,
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
      mapGeneration: options.mapGeneration == null ? 1n : options.mapGeneration,
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
  state.recoverySink = options.targetQuotaRecoverySink
  await state.store.open(frame => recoverFrame(state, frame))
  state.recoverySink = null
  state.walHeadSequence = state.store.walSequence
  state.walHeadHash = b4a.from(state.store.walHash)
  state.localOperational = true
  try {
    await storeFault(state, FORWARD_HTTPS_TARGET_STORE_V3_FAULT_POINT.OPEN_AFTER_RECOVERY)
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
  if (derived.scope === 'SESSION' && derived.walType === WAL_TYPE.TRANSPORT_RESERVED) {
    recoverPrefixFrame(state, slot, key, derived, frame)
  } else if (derived.scope === 'SESSION' && derived.walType !== WAL_TYPE.SESSION_TERMINAL) {
    if (!slot) {
      if (derived.walType !== WAL_TYPE.TURN_FINAL) fail('first session frame must create the allocation', STORE_ERROR_CODE.INTEGRITY)
      if (state.unconsumed < 1) fail('recovered slots exceed capacity', STORE_ERROR_CODE.INTEGRITY)
      slot = freshSlot(state, derived.stableSessionId)
      slot.state = SLOT_STATE.ALLOCATED
      state.unconsumed--
    }
    if (slot.orphan) {
      const finalCommitment = payloadCommitment(frame.payload)
      if (slot.state === SLOT_STATE.PREFIX_ALLOCATED && !b4a.equals(finalCommitment || b4a.alloc(0), slot.orphan.requestCommitment)) {
        // A fresh prefix admits no later operation: a non-matching final is
        // never admitted onto the PREFIX_ALLOCATED slot.
        fail('non-matching final on a fresh prefix is INTEGRITY', STORE_ERROR_CODE.INTEGRITY)
      }
      if (b4a.equals(finalCommitment || b4a.alloc(0), slot.orphan.requestCommitment)) {
        // Matching final for the exact same operation, requestCommitment and
        // revision chain: the open prefix is applied exactly once. Orphan
        // entries become ordinary session entries and the record closes;
        // FRESH PREFIX_ALLOCATED and EXISTING ALLOCATED_WITH_PREFIX both
        // return to ALLOCATED. A final of any other operation does not close
        // the record and its entry is preserved by a later flags2 abort.
        slot.state = SLOT_STATE.ALLOCATED
        slot.orphan = null
      }
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
  if (commitment === null) fail('type113 payload is truncated', STORE_ERROR_CODE.INTEGRITY)
  if (!slot) {
    if (state.unconsumed < 1) fail('recovered prefix slots exceed capacity', STORE_ERROR_CODE.INTEGRITY)
    slot = freshSlot(state, derived.stableSessionId)
    slot.state = SLOT_STATE.PREFIX_ALLOCATED
    state.unconsumed--
    slot.orphan = newOrphanRecord(commitment)
  } else if (slot.state === SLOT_STATE.ALLOCATED) {
    slot.state = SLOT_STATE.ALLOCATED_WITH_PREFIX
    slot.orphan = newOrphanRecord(commitment)
  } else if (slot.state !== SLOT_STATE.PREFIX_ALLOCATED && slot.state !== SLOT_STATE.ALLOCATED_WITH_PREFIX) {
    fail('prefix frame after a closed disposition is INTEGRITY', STORE_ERROR_CODE.INTEGRITY)
  }
  if (!b4a.equals(commitment, slot.orphan.requestCommitment)) {
    fail('mixed prefix requestCommitment is INTEGRITY', STORE_ERROR_CODE.INTEGRITY)
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
    state: SLOT_STATE.FREE,
    registry: createChargeRegistry(ROLE, stableSessionId),
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
    if (slot.state !== SLOT_STATE.ALLOCATED && slot.state !== SLOT_STATE.ALLOCATED_WITH_PREFIX) fail('duplicate terminal is INTEGRITY', STORE_ERROR_CODE.INTEGRITY)
    slot.priorRevision++
    slot.authorityBitmap = derived.authorityBitmap
    slot.authorityCommitments = derived.authorityCommitments
  }
  // Overlay terminalization: orphan prefix entries persist as ordinary
  // removable entries inside the consumed registry and are removed only by
  // the later terminal-existing or terminal-only FPR9. No flags2 abort is
  // possible after terminalization.
  slot.orphan = null
  slot.state = SLOT_STATE.CONSUMED_UNPRUNED
  state.consumedUnpruned++
}

function applyPruneRecovery (state, slot, key, derived, frame) {
  if (!slot) fail('unmatched prune tombstone is INTEGRITY', STORE_ERROR_CODE.INTEGRITY)
  const pruned = decodeForwardHttpsRetentionPrunedV3(frame.payload)
  if (pruned.flags === 1) {
    // flags1 fresh-orphan abort: exact recorded orphan removal, slot returns
    // FREE and the historic identity is PRUNED_RELEASED.
    if (slot.state !== SLOT_STATE.PREFIX_ALLOCATED || !slot.orphan) {
      fail('flags1 abort without a fresh recovered prefix is INTEGRITY', STORE_ERROR_CODE.INTEGRITY)
    }
    assertOrphanMatch(slot, pruned)
    slot.registry.removeExact(slot.orphan.entries)
    slot.orphan = null
    slot.state = SLOT_STATE.FREE
    slot.prunedReleased = true
    state.unconsumed++
  } else if (pruned.flags === 2) {
    // flags2 existing-session prefix-abort: removes exactly the recorded
    // orphan entries; slot, authority vector, PREPARED state and session
    // clock are byte-identically preserved; never an identity transition.
    if (slot.state !== SLOT_STATE.ALLOCATED_WITH_PREFIX || !slot.orphan) {
      fail('flags2 abort without an existing-session prefix is INTEGRITY', STORE_ERROR_CODE.INTEGRITY)
    }
    assertOrphanMatch(slot, pruned)
    slot.registry.removeExact(slot.orphan.entries)
    slot.orphan = null
    slot.state = SLOT_STATE.ALLOCATED
  } else if (slot.state === SLOT_STATE.ALLOCATED) {
    // nonterminal PRUNE: RELEASE_ALLOCATED, slot returns FREE
    assertPruneMatch(slot, pruned, frame.payload)
    slot.state = SLOT_STATE.FREE
    slot.prunedReleased = true
    state.unconsumed++
    slot.authorityBitmap = 0
  } else if (slot.state === SLOT_STATE.CONSUMED_UNPRUNED) {
    // terminal PRUNE: slot stays permanently consumed
    assertPruneMatch(slot, pruned, frame.payload)
    slot.state = SLOT_STATE.CONSUMED_PRUNED
    state.consumedUnpruned--
    state.consumedPruned++
    slot.authorityBitmap = 0
  } else {
    fail('duplicate or misordered prune tombstone is INTEGRITY', STORE_ERROR_CODE.INTEGRITY)
  }
  state.roleGlobalLogicalBytes += derived.ordinaryLogicalCharge
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

function assertOrphanMatch (slot, pruned) {
  if (pruned.chargeEntryCount !== slot.orphan.entries.length ||
      pruned.removedOrdinaryLogicalBytes !== slot.orphan.removedSum ||
      pruned.priorSessionRevision !== slot.orphan.lastRevision) {
    fail('prefix abort does not match the recorded orphan entries', STORE_ERROR_CODE.INTEGRITY)
  }
}

function requireOperational (state) {
  if (state.closed) fail('target store is closed', STORE_ERROR_CODE.CLOSED)
  if (state.failedPruneDurablePending) fail('target store is FAILED_PRUNE_DURABLE_PENDING', STORE_ERROR_CODE.INTEGRITY)
  if (!state.localOperational) fail('target store is not operational', STORE_ERROR_CODE.INVALID)
  // The universal operational gate: every role operation passes it before
  // any identity, cache, callback or mutation work (v13).
  assertForwardHttpsAggregateQuotaOperationalV3(state.storeQuotaCapability)
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

// The exact 192-byte flags0 BUDGET_EXHAUSTED FTM9 the store constructs for
// the wired cap+1 terminal conversion (frozen layout; module-private, never
// exported): the prior revision and watermark come from the exact slot, the
// flags0 tail is zeroed.
function terminalFtm9Payload (state, slot, stableSessionId) {
  const output = b4a.alloc(192)
  let offset = 0
  b4a.copy(b4a.from('FTM9', 'ascii'), output, offset); offset += 4
  output[offset++] = 1
  output[offset++] = 2
  output.writeUInt16BE(0, offset); offset += 2
  b4a.copy(stableSessionId, output, offset); offset += 32
  offset = writeU64be(output, offset, state.walHeadSequence + 1n)
  for (let index = 0; index < 5; index++) { output.writeUInt16BE(0, offset); offset += 2 }
  output.writeUInt16BE(0, offset); offset += 2
  output.writeUInt32BE(0, offset); offset += 4
  offset = writeU64be(output, offset, slot.priorRevision)
  output.writeUInt32BE(slot.trustedEpochHighWatermark || 0, offset); offset += 4
  const reason = b4a.from('BUDGET_EXHAUSTED', 'ascii')
  output[offset++] = reason.byteLength
  b4a.copy(reason, output, offset)
  return output
}

// Wired cap+1 terminal conversion (required_tests[15], REREVIEW2-P1-006):
// reserve the rejected ordinary operation so the quota ENTRY_CAP_TERMINAL arm
// mints the exact expectation, bind the exact flags0 BUDGET_EXHAUSTED FTM9,
// append and commit, and transition the slot ALLOCATED -> CONSUMED_UNPRUNED
// exactly as the recoverFrame terminal arm does on reopen.
async function terminalizeEntryCap (state, slot, operation, frames, stableSessionId) {
  const payload = terminalFtm9Payload(state, slot, stableSessionId)
  const plan = createForwardHttpsStoreQuotaCostPlanV3(state.storeQuotaCapability, {
    operation,
    knownInputBuffers: frames.map(frame => frame.payload),
    temporaryWriteBuffers: [],
    existingDestinationBytes: 0
  })
  const union = await reserveForwardHttpsAggregateQuotaV3(state.storeQuotaCapability, plan)
  if (union.disposition !== 'ENTRY_CAP_TERMINAL') {
    fail('ENTRY_CAP_TERMINAL arm did not fire for the proven cap+1', STORE_ERROR_CODE.INTEGRITY)
  }
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
  // Identity first-match at the store boundary (v16 stage_2): PRUNED_RELEASED
  // returns mutation-free CONFLICT; PRESENT_PREFIX_ALLOCATED returns
  // mutation-free SESSION_CLOSED (only the exact prefix PRUNE is eligible);
  // consumed identities are sticky TERMINAL; ALLOCATED_WITH_PREFIX follows
  // the exact allocated-session rules subject to the orphan-prefix surcharge.
  if (slot && slot.prunedReleased) fail('session identity is PRUNED_RELEASED', STORE_ERROR_CODE.CONFLICT)
  if (slot && slot.state === SLOT_STATE.PREFIX_ALLOCATED) fail('session prefix is closed', STORE_ERROR_CODE.SESSION_CLOSED)
  if (slot && (slot.state === SLOT_STATE.CONSUMED_UNPRUNED || slot.state === SLOT_STATE.CONSUMED_PRUNED)) fail('session identity is TERMINAL', STORE_ERROR_CODE.TERMINAL)
  if (!slot || (slot.state !== SLOT_STATE.ALLOCATED && slot.state !== SLOT_STATE.ALLOCATED_WITH_PREFIX)) fail('session is not ALLOCATED', STORE_ERROR_CODE.SEQUENCE_INVALID)
  // Planned removable charge-entry count from the exact bound operation row:
  // type113 count plus the ordinary final SESSION indicator (TURN_FINAL=2,
  // PROCESSOR_REQUEST_READY=4, PROCESSOR_COMPLETED=22, others=1).
  const planned = input.plannedRemovableChargeEntryCount == null
    ? (walType === WAL_TYPE.TURN_FINAL || walType === WAL_TYPE.TRANSPORT_RESERVED
        ? 2
        : walType === WAL_TYPE.PROCESSOR_REQUEST_READY
          ? 4
          : walType === WAL_TYPE.PROCESSOR_COMPLETED ? 22 : 1)
    : input.plannedRemovableChargeEntryCount
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
  if (!state || typeof state !== 'object') fail('target store authority is forged', STORE_ERROR_CODE.INVALID)
  if (state.closed) return
  state.closed = true
  state.localOperational = false
  // Failure-atomic toward CLOSED: a close-fault failure is reported after the
  // engine closes, never leaving the store stuck or the engine open.
  let closeFault = null
  try {
    await storeFault(state, FORWARD_HTTPS_TARGET_STORE_V3_FAULT_POINT.CLOSE_BEFORE_STORE_CLOSE)
  } catch (error) {
    closeFault = error
  }
  // A faulted close carries blocker INTEGRITY on the store status.
  if (closeFault !== null) state.blocker = STORE_ERROR_CODE.INTEGRITY
  await state.store.close()
  if (closeFault !== null) throw closeFault
}

export const FORWARD_HTTPS_TARGET_WAL_TYPE = WAL_TYPE

export const FORWARD_HTTPS_TARGET_STORE_V3_STATUS = Object.freeze({
  schemaVersion: 3,
  implementationReady: false,
  descriptorOperationBits: 0,
  advertisedOperationBits: 0,
  readinessOperationBits: 0,
  runtimeReady: false,
  releaseReady: false,
  authorizesRelease: false
})

export const FORWARD_HTTPS_TARGET_STORE_V3_ERROR_CODE = STORE_ERROR_CODE

export const FORWARD_HTTPS_TARGET_STORE_V3_FAULT_POINT = Object.freeze({
  OPEN_AFTER_RECOVERY: 'OPEN_AFTER_RECOVERY',
  TURN_AFTER_REPLAY_BURN: 'TURN_AFTER_REPLAY_BURN',
  CRYPTO_RESERVATION_BEFORE_WAL_APPEND: 'CRYPTO_RESERVATION_BEFORE_WAL_APPEND',
  CRYPTO_RESERVATION_AFTER_WAL_WRITE_BEFORE_FSYNC: 'CRYPTO_RESERVATION_AFTER_WAL_WRITE_BEFORE_FSYNC',
  CRYPTO_RESERVATION_AFTER_WAL_FSYNC: 'CRYPTO_RESERVATION_AFTER_WAL_FSYNC',
  TURN_AFTER_SIGN: 'TURN_AFTER_SIGN',
  TURN_BEFORE_WAL_APPEND: 'TURN_BEFORE_WAL_APPEND',
  TURN_AFTER_WAL_FSYNC: 'TURN_AFTER_WAL_FSYNC',
  PROCESSOR_INGRESS_AFTER_CALLBACK: 'PROCESSOR_INGRESS_AFTER_CALLBACK',
  PROCESSOR_REQUEST_READY_BEFORE_WAL_APPEND: 'PROCESSOR_REQUEST_READY_BEFORE_WAL_APPEND',
  PROCESSOR_REQUEST_READY_AFTER_WAL_FSYNC: 'PROCESSOR_REQUEST_READY_AFTER_WAL_FSYNC',
  PROCESSOR_PREPARED_AFTER_WAL_FSYNC: 'PROCESSOR_PREPARED_AFTER_WAL_FSYNC',
  PROCESSOR_BEFORE_RECOVER: 'PROCESSOR_BEFORE_RECOVER',
  PROCESSOR_AFTER_RECOVER: 'PROCESSOR_AFTER_RECOVER',
  PROCESSOR_BEFORE_APPLY: 'PROCESSOR_BEFORE_APPLY',
  PROCESSOR_AFTER_APPLY: 'PROCESSOR_AFTER_APPLY',
  PROCESSOR_OUTCOME_AFTER_CALLBACK: 'PROCESSOR_OUTCOME_AFTER_CALLBACK',
  PROCESSOR_COMPLETED_BEFORE_WAL_APPEND: 'PROCESSOR_COMPLETED_BEFORE_WAL_APPEND',
  PROCESSOR_COMPLETED_AFTER_WAL_FSYNC: 'PROCESSOR_COMPLETED_AFTER_WAL_FSYNC',
  QUARANTINE_AFTER_WAL_FSYNC: 'QUARANTINE_AFTER_WAL_FSYNC',
  PRUNE_AFTER_WAL_FSYNC: 'PRUNE_AFTER_WAL_FSYNC',
  CLOSE_BEFORE_STORE_CLOSE: 'CLOSE_BEFORE_STORE_CLOSE'
})

// V18 target_module_exact names for the turn-level surface. Accepting a
// forwarded turn opens the session when absent and appends otherwise;
// processor work covers the 114/115/116 operation rows.
export async function acceptForwardedHttpsTargetTurnV3 (state, input) {
  requireOperational(state)
  const stableSessionId = b4a.from(input.stableSessionId)
  const existing = state.slots.get(keyOf(stableSessionId))
  if (existing) {
    // Identity first-match at the store boundary (v16 stage_2): PRUNED_RELEASED
    // returns mutation-free CONFLICT; PRESENT_PREFIX_ALLOCATED returns
    // mutation-free SESSION_CLOSED (only the exact prefix PRUNE is eligible);
    // consumed identities are sticky TERMINAL; ALLOCATED_WITH_PREFIX follows
    // the exact allocated-session rules subject to the orphan-prefix surcharge.
    if (existing.prunedReleased) fail('session identity is PRUNED_RELEASED', STORE_ERROR_CODE.CONFLICT)
    if (existing.state === SLOT_STATE.PREFIX_ALLOCATED) fail('session prefix is closed', STORE_ERROR_CODE.SESSION_CLOSED)
    if (existing.state === SLOT_STATE.CONSUMED_UNPRUNED || existing.state === SLOT_STATE.CONSUMED_PRUNED) fail('session identity is TERMINAL', STORE_ERROR_CODE.TERMINAL)
    if (existing.state === SLOT_STATE.ALLOCATED || existing.state === SLOT_STATE.ALLOCATED_WITH_PREFIX) return appendSession(state, input)
    fail('session identity is not NEVER_SEEN', STORE_ERROR_CODE.SEQUENCE_INVALID)
  }
  // Fresh target OPEN TURN_FINAL=112: one FREE slot becomes ALLOCATED.
  if (input.walType !== undefined && input.walType !== WAL_TYPE.TURN_FINAL) throw new TypeError('walType is not an ordinary target SESSION type')
  if (state.unconsumed < 1) fail('no FREE slot for a fresh target session', STORE_ERROR_CODE.CAPACITY)
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

export async function runNextForwardHttpsTargetProcessorWorkV3 (state, input) {
  if (![WAL_TYPE.PROCESSOR_PREPARED, WAL_TYPE.PROCESSOR_REQUEST_READY, WAL_TYPE.PROCESSOR_COMPLETED].includes(input.walType)) {
    throw new TypeError('walType must be 114, 115 or 116')
  }
  return appendSession(state, input)
}

export function forwardHttpsTargetTurnStateV3 (state, stableSessionId) {
  const slot = state.slots.get(keyOf(b4a.from(stableSessionId))) || null
  return Object.freeze({
    present: slot !== null,
    slotState: slot ? slot.state : SLOT_STATE.FREE,
    identity: classifyHistoricIdentity(slot ? slot.state : SLOT_STATE.FREE, slot ? slot.prunedReleased : false),
    chargeEntryCount: slot ? slot.registry.count : 0,
    priorSessionRevision: slot ? slot.priorRevision : 0n,
    openPrefix: slot ? slot.orphan !== null : false
  })
}
