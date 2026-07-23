// FORWARD HTTPS durability storage authority v3.
//
// Owns the FTM9 terminal-delta codec, the per-role terminal slot lifecycle
// (FREE|PROVISIONAL|ALLOCATED|CONSUMED_UNPRUNED|CONSUMED_PRUNED), the bounded
// removable charge-entry registry with its streaming BLAKE2b-256 commitment,
// the protected aggregate terminal headroom arithmetic and the historic
// identity classification used by recovery. All durable charge/codec facts
// flow through the one hash-bound replay module; this module adds no decoder,
// offset, charge, count, bitmap or registry copy beyond the FTM9 encoder the
// contract assigns to the store-side authority.

import b4a from 'b4a'
import { blake2b256 } from '@hiverelay/blind-protocol'
import {
  FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3
} from './forward-https-replay-journal-v4.js'

const ZERO32 = b4a.alloc(32)
const U32_MAX = 4294967295
const EXPIRY_HORIZON = 4294966394 // UINT32_MAX-901
const RECOVERY_GRACE_SECONDS = 900
const FTM9_PAYLOAD_BYTES = 192
const FTM9_FRAME_BYTES = 416
const FTM9_LOGICAL_BYTES = 608
const FPR9_LOGICAL_BYTES = 736
const FPR9_FRAME_BYTES = 480
const SLOT_LIABILITY_UNCONSUMED_LOGICAL = 1344
const SLOT_LIABILITY_UNCONSUMED_PHYSICAL = 896
const SLOT_LIABILITY_CONSUMED_UNPRUNED_LOGICAL = 736
const SLOT_LIABILITY_CONSUMED_UNPRUNED_PHYSICAL = 480
const PRODUCTION_SLOTS_PER_ROLE = 65536
const CHARGE_ENTRY_CAP = 65536
const CHARGE_ENTRY_BYTES = 49
const AUTHORITY_CLASS_COUNT = 10

const DOMAIN_MINIMAL_TERMINAL = b4a.from('hiverelay.blind.forward-https-minimal-terminal-authority.v3', 'ascii')
const DOMAIN_RETENTION_LOOKUP = b4a.from('hiverelay.blind.forward-https-retention-lookup.v3', 'ascii')
const DOMAIN_TERMINAL_STATE = b4a.from('hiverelay.blind.forward-https-terminal-state.v3', 'ascii')
const DOMAIN_CHARGE_REGISTRY_INIT = b4a.from('hiverelay.blind.forward-https-quota-charge-registry-init.v4', 'ascii')
const DOMAIN_CHARGE_REGISTRY_STEP = b4a.from('hiverelay.blind.forward-https-quota-charge-registry-step.v4', 'ascii')
const DOMAIN_CHARGE_REGISTRY_FINAL = b4a.from('hiverelay.blind.forward-https-quota-charge-registry-final.v4', 'ascii')

export const FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE = deepFreeze({
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

export const FORWARD_HTTPS_STORAGE_AUTHORITY_V3_LIMITS = deepFreeze({
  productionSlotsPerRole: PRODUCTION_SLOTS_PER_ROLE,
  removableChargeEntryCapPerSession: CHARGE_ENTRY_CAP,
  chargeEntryBytes: CHARGE_ENTRY_BYTES,
  terminalPayloadBytes: FTM9_PAYLOAD_BYTES,
  terminalFrameBytes: FTM9_FRAME_BYTES,
  terminalLogicalBytes: FTM9_LOGICAL_BYTES,
  pruneLogicalBytes: FPR9_LOGICAL_BYTES,
  pruneFrameBytes: FPR9_FRAME_BYTES,
  slotLiabilityUnconsumedLogicalBytes: SLOT_LIABILITY_UNCONSUMED_LOGICAL,
  slotLiabilityUnconsumedPhysicalBytes: SLOT_LIABILITY_UNCONSUMED_PHYSICAL,
  slotLiabilityConsumedUnprunedLogicalBytes: SLOT_LIABILITY_CONSUMED_UNPRUNED_LOGICAL,
  slotLiabilityConsumedUnprunedPhysicalBytes: SLOT_LIABILITY_CONSUMED_UNPRUNED_PHYSICAL,
  productionHeadroomLogicalPerRole: 88080384,
  productionHeadroomPhysicalPerRole: 58720256,
  productionHeadroomLogicalAggregate: 176160768,
  productionHeadroomPhysicalAggregate: 117440512,
  productionOrdinaryLogicalCeilingPerStoreAtFreshRoot: 8501854208,
  productionOrdinaryPhysicalCeilingPerStoreAtFreshRoot: 8531214336,
  productionOrdinaryLogicalCeilingAggregateAtFreshRoot: 17003708416,
  productionOrdinaryPhysicalCeilingAggregateAtFreshRoot: 17062428672,
  descriptorOperationBits: 0,
  advertisedOperationBits: 0,
  readinessOperationBits: 0,
  runtimeReady: false,
  releaseReady: false,
  authorizesRelease: false
})

export const FORWARD_HTTPS_STORAGE_SLOT_STATE_V3 = deepFreeze({
  FREE: 'FREE',
  PROVISIONAL: 'PROVISIONAL',
  PREFIX_ALLOCATED: 'PREFIX_ALLOCATED',
  ALLOCATED: 'ALLOCATED',
  ALLOCATED_WITH_PREFIX: 'ALLOCATED_WITH_PREFIX',
  CONSUMED_UNPRUNED: 'CONSUMED_UNPRUNED',
  CONSUMED_PRUNED: 'CONSUMED_PRUNED'
})

// Exact seven-state identity model. PRESENT_PREFIX_ALLOCATED is the FRESH
// type113 prefix predecessor; ALLOCATED_WITH_PREFIX is the EXISTING-session
// type113 prefix overlay, which reuses the one ALLOCATED slot and adds none.
export const FORWARD_HTTPS_STORAGE_HISTORIC_IDENTITY_V3 = deepFreeze({
  NEVER_SEEN: 'NEVER_SEEN',
  PRESENT_PREFIX_ALLOCATED: 'PRESENT_PREFIX_ALLOCATED',
  ALLOCATED_WITH_PREFIX: 'ALLOCATED_WITH_PREFIX',
  PRESENT_ALLOCATED: 'PRESENT_ALLOCATED',
  PRESENT_CONSUMED_UNPRUNED: 'PRESENT_CONSUMED_UNPRUNED',
  PRUNED_RELEASED: 'PRUNED_RELEASED',
  PRUNED_CONSUMED: 'PRUNED_CONSUMED'
})

export class ForwardHttpsStorageAuthorityV3Error extends Error {
  constructor (message, code = FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INVALID) {
    super(message)
    this.name = 'ForwardHttpsStorageAuthorityV3Error'
    this.code = code
  }
}

function deepFreeze (value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item)
    Object.freeze(value)
  }
  return value
}

function fail (message, code) {
  throw new ForwardHttpsStorageAuthorityV3Error(message, code)
}

function roleByte (role) {
  if (role === FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3.SOURCE_STORE) return 1
  if (role === FORWARD_HTTPS_AGGREGATE_QUOTA_ROLE_V3.TARGET_STORE) return 2
  throw new TypeError('role must be SOURCE_STORE or TARGET_STORE')
}

function asBytes32 (value, field, nonzero = false) {
  if (!value || typeof value.byteLength !== 'number') throw new TypeError(`${field} must be bytes`)
  const output = b4a.isBuffer(value) ? value : b4a.from(value)
  if (output.byteLength !== 32) throw new TypeError(`${field} must be exactly 32 bytes`)
  if (nonzero && b4a.equals(output, ZERO32)) throw new TypeError(`${field} must be nonzero`)
  return output
}

function writeU64 (output, offset, value) {
  if (typeof value === 'number') value = BigInt(value)
  if (typeof value !== 'bigint' || value < 0n || value > (1n << 64n) - 1n) throw new TypeError('u64 is out of range')
  for (let index = 7; index >= 0; index--) { output[offset + index] = Number(value & 0xffn); value >>= 8n }
  return offset + 8
}

export function deriveForwardHttpsMinimalTerminalAuthorityCommitmentV3 (input) {
  if (!input || typeof input !== 'object') throw new TypeError('input must be a closed object')
  const role = roleByte(input.role)
  const stableSessionId = asBytes32(input.stableSessionId, 'stableSessionId', true)
  const sequence = typeof input.sequence === 'bigint' ? input.sequence : BigInt(input.sequence)
  if (sequence <= 0n) throw new TypeError('sequence must be a nonzero u64')
  const requestCommitment = asBytes32(input.exactRequestCommitment, 'exactRequestCommitment', true)
  const expiresAtEpoch = checkEpoch(input.expiresAtEpoch, 'expiresAtEpoch')
  if (expiresAtEpoch > EXPIRY_HORIZON) throw new TypeError('expiresAtEpoch exceeds the representable horizon')
  const retainedUntilEpoch = expiresAtEpoch + RECOVERY_GRACE_SECONDS
  if (input.retainedUntilEpoch !== retainedUntilEpoch) throw new TypeError('retainedUntilEpoch must equal expiresAtEpoch+900')
  const highWatermark = checkEpoch(input.newTrustedEpochHighWatermark, 'newTrustedEpochHighWatermark')
  const reason = typeof input.reason === 'string' ? b4a.from(input.reason, 'ascii') : b4a.from(input.reason)
  if (reason.byteLength < 1 || reason.byteLength > 64) throw new TypeError('reason must be 1..64 bytes')
  const sequenceBytes = b4a.alloc(8)
  writeU64(sequenceBytes, 0, sequence)
  const scalars = b4a.alloc(13)
  scalars.writeUInt32BE(expiresAtEpoch, 0)
  scalars.writeUInt32BE(retainedUntilEpoch, 4)
  scalars.writeUInt32BE(highWatermark, 8)
  scalars[12] = reason.byteLength
  return blake2b256(b4a.concat([DOMAIN_MINIMAL_TERMINAL, b4a.from([role]), stableSessionId, sequenceBytes, requestCommitment, scalars, reason]))
}

function checkEpoch (value, field) {
  if (!Number.isSafeInteger(value) || value < 0 || value > U32_MAX) throw new TypeError(`${field} must be a u32 epoch`)
  return value
}

export function deriveForwardHttpsMinimalTerminalAuthorityClassesV3 (minimalTerminalAuthorityCommitment) {
  const M = asBytes32(minimalTerminalAuthorityCommitment, 'minimalTerminalAuthorityCommitment', true)
  const commitments = Array.from({ length: AUTHORITY_CLASS_COUNT }, () => b4a.from(ZERO32))
  commitments[7] = blake2b256(b4a.concat([DOMAIN_RETENTION_LOOKUP, M]))
  commitments[9] = blake2b256(b4a.concat([DOMAIN_TERMINAL_STATE, M]))
  return Object.freeze(commitments)
}

// FTM9 ForwardHttpsSessionTerminalV3 encoder. flags0 (EXISTING_DELTA, nonzero
// prior revision, zero 51-byte tail) and flags1 (MINIMAL_ABSENT_SEQUENCE,
// prior revision 0, exact expiry/+900/authority-commitment tail).
export function encodeForwardHttpsSessionTerminalV3 (input) {
  if (!input || typeof input !== 'object') throw new TypeError('input must be a closed object')
  const role = roleByte(input.role)
  const flags = input.flags
  if (flags !== 0 && flags !== 1) throw new TypeError('flags must be EXISTING_DELTA=0 or MINIMAL_ABSENT_SEQUENCE=1')
  const stableSessionId = asBytes32(input.stableSessionId, 'stableSessionId', true)
  const sequence = typeof input.sequence === 'bigint' ? input.sequence : BigInt(input.sequence)
  const priorSessionRevision = typeof input.priorSessionRevision === 'bigint' ? input.priorSessionRevision : BigInt(input.priorSessionRevision)
  if (flags === 0 && priorSessionRevision === 0n) fail('FTM9 existing delta requires nonzero prior revision', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  if (flags === 1 && (priorSessionRevision !== 0n || sequence === 0n)) fail('FTM9 minimal terminal requires zero revision and nonzero sequence', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  const reason = typeof input.reason === 'string' ? b4a.from(input.reason, 'ascii') : b4a.from(input.reason)
  if (reason.byteLength < 1 || reason.byteLength > 64) throw new TypeError('reason must be 1..64 bytes')
  // flags1 carries the exact 46-byte role SEQUENCE_INVALID code; a synthetic
  // short SEQUENCE_INVALID reason is forbidden.
  const exactReason = role === 1
    ? 'FORWARD_HTTPS_SOURCE_STORE_V3_SEQUENCE_INVALID'
    : 'FORWARD_HTTPS_TARGET_STORE_V3_SEQUENCE_INVALID'
  if (flags === 1 && b4a.toString(reason, 'ascii') !== exactReason) fail('FTM9 minimal terminal reason must be the exact role SEQUENCE_INVALID code', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  const buckets = input.buckets || [0, 0, 0, 0, 0]
  if (!Array.isArray(buckets) || buckets.length !== 5) throw new TypeError('buckets must contain five u16 counters')
  for (const value of buckets) if (!Number.isSafeInteger(value) || value < 0 || value > 65535) throw new TypeError('bucket counter must be u16')
  const turns = input.transportTurnsSpent || 0
  const spent = input.transportBytesSpent || 0
  if (!Number.isSafeInteger(turns) || turns < 0 || turns > 65535) throw new TypeError('transportTurnsSpent must be u16')
  if (!Number.isSafeInteger(spent) || spent < 0 || spent > U32_MAX) throw new TypeError('transportBytesSpent must be u32')
  if (flags === 1 && (buckets.some(value => value !== 0) || turns !== 0 || spent !== 0)) fail('FTM9 minimal terminal counters must be zero', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  const highWatermark = checkEpoch(input.newTrustedEpochHighWatermark, 'newTrustedEpochHighWatermark')
  const output = b4a.alloc(FTM9_PAYLOAD_BYTES)
  let offset = 0
  b4a.copy(b4a.from('FTM9', 'ascii'), output, offset); offset += 4
  output[offset++] = 1
  output[offset++] = role
  output.writeUInt16BE(flags, offset); offset += 2
  b4a.copy(stableSessionId, output, offset); offset += 32
  offset = writeU64(output, offset, sequence)
  for (const value of buckets) { output.writeUInt16BE(value, offset); offset += 2 }
  output.writeUInt16BE(turns, offset); offset += 2
  output.writeUInt32BE(spent, offset); offset += 4
  offset = writeU64(output, offset, priorSessionRevision)
  output.writeUInt32BE(highWatermark, offset); offset += 4
  output[offset++] = reason.byteLength
  b4a.copy(reason, output, offset); offset += 64
  if (flags === 1) {
    const expiresAtEpoch = checkEpoch(input.expiresAtEpoch, 'expiresAtEpoch')
    if (expiresAtEpoch > EXPIRY_HORIZON) throw new TypeError('expiresAtEpoch exceeds the representable horizon')
    const retainedUntilEpoch = expiresAtEpoch + RECOVERY_GRACE_SECONDS
    if (input.retainedUntilEpoch !== retainedUntilEpoch) throw new TypeError('retainedUntilEpoch must equal expiresAtEpoch+900')
    // The frozen minimal tail carries the exact request commitment; the
    // minimal authority commitment M is always recomputed from the payload
    // fields, never stored.
    const requestCommitment = asBytes32(input.exactRequestCommitment, 'exactRequestCommitment', true)
    output.writeUInt32BE(expiresAtEpoch, offset); offset += 4
    output.writeUInt32BE(retainedUntilEpoch, offset); offset += 4
    b4a.copy(requestCommitment, output, offset); offset += 32
    offset += 11 // zero padding
  } else {
    offset += 51 // zero tail
  }
  if (offset !== FTM9_PAYLOAD_BYTES) throw new Error('FTM9 payload accounting mismatch')
  return output
}

// Adopted V13 streaming final commitment over count, exact removed sum and
// the init/step chain, computed over the exact49-byte entries in WAL order.
function streamingCommitment (roleByteValue, session, walOrderedEntries) {
  let chain = blake2b256(b4a.concat([DOMAIN_CHARGE_REGISTRY_INIT, b4a.from([roleByteValue]), session]))
  let removed = 0n
  for (const entry of walOrderedEntries) {
    chain = blake2b256(b4a.concat([DOMAIN_CHARGE_REGISTRY_STEP, chain, entry]))
    let value = 0n
    for (let index = 41; index < 49; index++) value = (value << 8n) | BigInt(entry[index])
    removed += value
  }
  const count = b4a.alloc(4)
  count.writeUInt32BE(walOrderedEntries.length, 0)
  const removedBytes = b4a.alloc(8)
  writeU64(removedBytes, 0, removed)
  return blake2b256(b4a.concat([DOMAIN_CHARGE_REGISTRY_FINAL, b4a.from([roleByteValue]), session, count, removedBytes, chain]))
}

// Per-session removable charge-entry registry. Counts are streamed in WAL
// order with bounded constant working memory; the exact49-byte entries are
// walType:u8 || walSequence:u64be || payloadHash:bytes32 || charge:u64be.
export function createForwardHttpsChargeRegistryV3 (role, stableSessionId) {
  const roleByteValue = roleByte(role)
  const session = asBytes32(stableSessionId, 'stableSessionId', true)
  const entries = []
  return Object.freeze({
    role,
    stableSessionId: session,
    get count () { return entries.length },
    admit (derived) {
      if (!derived || derived.scope !== 'SESSION' || derived.ordinaryLogicalCharge <= 0) {
        fail('charge entry must be an ordinary SESSION derivation', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
      }
      if (!b4a.equals(derived.stableSessionId, session)) fail('charge entry session mismatch', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
      if (entries.length >= CHARGE_ENTRY_CAP) fail('removable charge entry cap exceeded', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
      const entry = b4a.alloc(CHARGE_ENTRY_BYTES)
      entry[0] = derived.walType
      writeU64(entry, 1, derived.walSequence)
      b4a.copy(derived.payloadHash, entry, 9)
      writeU64(entry, 41, BigInt(derived.ordinaryLogicalCharge))
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
    // flags2 existing-session prefix abort: remove exactly the recorded orphan
    // prefix entries (count, sum and chain). Every later committed entry is
    // preserved; there is no snapshot restore.
    removeExact (entryBuffers) {
      let removedSum = 0n
      let removedCount = 0
      for (const target of entryBuffers) {
        const index = entries.findIndex(entry => b4a.equals(entry, target))
        if (index === -1) fail('orphan entry is not in the charge registry', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
        const removed = entries.splice(index, 1)[0]
        let value = 0n
        for (let byte = 41; byte < 49; byte++) value = (value << 8n) | BigInt(removed[byte])
        removedSum += value
        removedCount++
      }
      return Object.freeze({ count: removedCount, removedSum })
    },
    commitment () {
      return streamingCommitment(roleByteValue, session, entries)
    },
    entriesAscending () {
      return Object.freeze([...entries].sort((left, right) => {
        for (let index = 1; index < 9; index++) if (left[index] !== right[index]) return left[index] - right[index]
        return 0
      }).map(entry => b4a.from(entry)))
    }
  })
}

// Streaming charge commitment: identical digest to the registry commitment,
// computed in one pass over the entries in WAL order with O(1) working memory
// beyond the bounded per-session runs. Used by recovery so a 65536-entry
// session never requires an attacker-sized duplicate buffer.
export function streamForwardHttpsChargeCommitmentV3 (role, stableSessionId, orderedEntries) {
  const roleByteValue = roleByte(role)
  const session = asBytes32(stableSessionId, 'stableSessionId', true)
  const buffered = []
  let count = 0
  for (const entry of orderedEntries) {
    if (entry.byteLength !== CHARGE_ENTRY_BYTES) fail('charge entry must be exactly 49 bytes', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
    buffered.push(b4a.from(entry))
    count++
    if (count > CHARGE_ENTRY_CAP) fail('recovered removable charge entries exceed the cap', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INTEGRITY)
  }
  return {
    count,
    commitment: streamingCommitment(roleByteValue, session, buffered)
  }
}

// Protected aggregate terminal headroom. capacity is the effective per-role
// terminal slot capacity (65536 production; maximumRetainedTurnsPerRole under
// test limits). All four inequalities must hold before child mutation.
export function verifyForwardHttpsTerminalHeadroomV3 (input) {
  if (!input || typeof input !== 'object') throw new TypeError('input must be a closed object')
  const capacity = input.capacity
  if (!Number.isSafeInteger(capacity) || capacity < 1 || capacity > PRODUCTION_SLOTS_PER_ROLE) throw new TypeError('capacity is outside 1..65536')
  const perStoreLogical = input.maximumDurableBytesPerStore
  const aggregate = input.maximumForwardStorageBytesAggregate
  if (!Number.isSafeInteger(perStoreLogical) || perStoreLogical < 1 || perStoreLogical > 8589934592) throw new TypeError('per-store ceiling is invalid')
  if (!Number.isSafeInteger(aggregate) || aggregate < 1 || aggregate > 17179869184) throw new TypeError('aggregate ceiling is invalid')
  const ok =
    BigInt(perStoreLogical) >= BigInt(capacity) * 1344n &&
    BigInt(perStoreLogical) >= BigInt(capacity) * 896n &&
    BigInt(aggregate) >= 2n * BigInt(capacity) * 1344n &&
    BigInt(aggregate) >= 2n * BigInt(capacity) * 896n
  if (!ok) fail('terminal headroom minimums are violated', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.INVALID)
  return deepFreeze({
    capacity,
    headroomLogicalPerRole: capacity * SLOT_LIABILITY_UNCONSUMED_LOGICAL,
    headroomPhysicalPerRole: capacity * SLOT_LIABILITY_UNCONSUMED_PHYSICAL,
    headroomLogicalAggregate: 2 * capacity * SLOT_LIABILITY_UNCONSUMED_LOGICAL,
    headroomPhysicalAggregate: 2 * capacity * SLOT_LIABILITY_UNCONSUMED_PHYSICAL,
    ordinaryLogicalCeilingPerStore: perStoreLogical - capacity * SLOT_LIABILITY_UNCONSUMED_LOGICAL,
    ordinaryPhysicalCeilingPerStore: perStoreLogical - capacity * SLOT_LIABILITY_UNCONSUMED_PHYSICAL,
    ordinaryLogicalCeilingAggregate: aggregate - 2 * capacity * SLOT_LIABILITY_UNCONSUMED_LOGICAL,
    ordinaryPhysicalCeilingAggregate: aggregate - 2 * capacity * SLOT_LIABILITY_UNCONSUMED_PHYSICAL
  })
}

// Protected admission inequalities. plannedOrdinary* is the exact frozen row
// addition for the operation; unconsumed/consumedUnpruned slot counts are
// recovered. Terminal and terminal-PRUNE admissions are guaranteed by the
// protected liability and never return CAPACITY here.
export function checkForwardHttpsProtectedAdmissionV3 (input) {
  const required = ['currentSourceLogical', 'currentTargetLogical', 'currentSourcePhysical', 'currentTargetPhysical', 'currentReplayPhysical', 'plannedOrdinaryLogical', 'plannedOrdinaryPhysical', 'sourceUnconsumedSlots', 'targetUnconsumedSlots', 'sourceConsumedUnprunedSlots', 'targetConsumedUnprunedSlots', 'maximumDurableBytesPerStore', 'maximumForwardStorageBytesAggregate']
  for (const key of required) if (!Object.hasOwn(input || {}, key)) throw new TypeError(`input.${key} is required`)
  const role = input.role || null
  const plannedLogical = BigInt(input.plannedOrdinaryLogical)
  const plannedPhysical = BigInt(input.plannedOrdinaryPhysical)
  const sourceLogical = BigInt(input.currentSourceLogical) + (role === 'SOURCE_STORE' ? plannedLogical : 0n)
  const targetLogical = BigInt(input.currentTargetLogical) + (role === 'TARGET_STORE' ? plannedLogical : 0n)
  const perStore = BigInt(input.maximumDurableBytesPerStore)
  const aggregate = BigInt(input.maximumForwardStorageBytesAggregate)
  const sourceProtectedLogical = (BigInt(input.sourceUnconsumedSlots) * 1344n) + (BigInt(input.sourceConsumedUnprunedSlots) * 736n)
  const targetProtectedLogical = (BigInt(input.targetUnconsumedSlots) * 1344n) + (BigInt(input.targetConsumedUnprunedSlots) * 736n)
  const sourceProtectedPhysical = (BigInt(input.sourceUnconsumedSlots) * 896n) + (BigInt(input.sourceConsumedUnprunedSlots) * 480n)
  const targetProtectedPhysical = (BigInt(input.targetUnconsumedSlots) * 896n) + (BigInt(input.targetConsumedUnprunedSlots) * 480n)
  if (sourceLogical + sourceProtectedLogical > perStore || targetLogical + targetProtectedLogical > perStore) return false
  const sourcePhysical = BigInt(input.currentSourcePhysical) + (role === 'SOURCE_STORE' ? plannedPhysical : 0n) + sourceProtectedPhysical
  const targetPhysical = BigInt(input.currentTargetPhysical) + (role === 'TARGET_STORE' ? plannedPhysical : 0n) + targetProtectedPhysical
  if (sourcePhysical > perStore || targetPhysical > perStore) return false
  const aggregateLogical = BigInt(input.currentSourceLogical) + BigInt(input.currentTargetLogical) + plannedLogical +
    (BigInt(input.sourceUnconsumedSlots) + BigInt(input.targetUnconsumedSlots)) * 1344n +
    (BigInt(input.sourceConsumedUnprunedSlots) + BigInt(input.targetConsumedUnprunedSlots)) * 736n
  if (aggregateLogical > aggregate) return false
  const aggregatePhysical = BigInt(input.currentSourcePhysical) + BigInt(input.currentTargetPhysical) + BigInt(input.currentReplayPhysical) + plannedPhysical +
    (BigInt(input.sourceUnconsumedSlots) + BigInt(input.targetUnconsumedSlots)) * 896n +
    (BigInt(input.sourceConsumedUnprunedSlots) + BigInt(input.targetConsumedUnprunedSlots)) * 480n
  return aggregatePhysical <= aggregate
}

// Terminal invariance: appending FTM9 adds exactly608 logical/416 physical
// while converting one unconsumed slot (liability1344/896) to consumed-unpruned
// (liability736/480); the protected sum is invariant and cannot return CAPACITY.
export function verifyForwardHttpsTerminalInvarianceV3 (unconsumedSlotsBefore, consumedUnprunedBefore) {
  if (!Number.isSafeInteger(unconsumedSlotsBefore) || unconsumedSlotsBefore < 1) {
    fail('terminalization requires one unconsumed slot', FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE.CAPACITY)
  }
  const before = BigInt(unconsumedSlotsBefore) * 1344n + BigInt(consumedUnprunedBefore) * 736n
  const after = BigInt(unconsumedSlotsBefore - 1) * 1344n + BigInt(consumedUnprunedBefore + 1) * 736n
  const delta = 608n
  return deepFreeze({ protectedSumInvariant: before === after + delta, logicalReduction: 608, physicalReduction: 416 })
}

// V18 storage_module_exact constant names.
export const FORWARD_HTTPS_STORAGE_V3_LIMITS = FORWARD_HTTPS_STORAGE_AUTHORITY_V3_LIMITS
export const FORWARD_HTTPS_STORAGE_V3_ERROR_CODE = FORWARD_HTTPS_STORAGE_AUTHORITY_V3_ERROR_CODE
export const FORWARD_HTTPS_STORAGE_V3_STATUS = deepFreeze({
  schemaVersion: 3,
  implementationReady: true,
  descriptorOperationBits: 0,
  advertisedOperationBits: 0,
  readinessOperationBits: 0,
  runtimeReady: false,
  releaseReady: false,
  authorizesRelease: false
})
export const FORWARD_HTTPS_STORAGE_V3_FAULT_POINT = deepFreeze({})

// Historic identity classification from complete canonical WAL state. The
// latest slot-disposing transition governs: identical WAL evidence has
// exactly one identity. A flags2 prefix-abort is never an identity
// transition; the slot stays ALLOCATED and the identity PRESENT_ALLOCATED.
export function classifyForwardHttpsHistoricIdentityV3 (slotState, hadPruneTombstone) {
  if (slotState === FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED || slotState === FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.PROVISIONAL) {
    return FORWARD_HTTPS_STORAGE_HISTORIC_IDENTITY_V3.PRESENT_ALLOCATED
  }
  if (slotState === FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.PREFIX_ALLOCATED) return FORWARD_HTTPS_STORAGE_HISTORIC_IDENTITY_V3.PRESENT_PREFIX_ALLOCATED
  if (slotState === FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.ALLOCATED_WITH_PREFIX) return FORWARD_HTTPS_STORAGE_HISTORIC_IDENTITY_V3.ALLOCATED_WITH_PREFIX
  if (slotState === FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.CONSUMED_UNPRUNED) return FORWARD_HTTPS_STORAGE_HISTORIC_IDENTITY_V3.PRESENT_CONSUMED_UNPRUNED
  if (slotState === FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.CONSUMED_PRUNED) return FORWARD_HTTPS_STORAGE_HISTORIC_IDENTITY_V3.PRUNED_CONSUMED
  if (slotState === FORWARD_HTTPS_STORAGE_SLOT_STATE_V3.FREE && hadPruneTombstone) return FORWARD_HTTPS_STORAGE_HISTORIC_IDENTITY_V3.PRUNED_RELEASED
  return FORWARD_HTTPS_STORAGE_HISTORIC_IDENTITY_V3.NEVER_SEEN
}
