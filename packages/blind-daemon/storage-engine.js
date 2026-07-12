import { createPublicKey, verify as verifySignature } from 'node:crypto'
import b4a from 'b4a'
import {
  CELL_SIZE_CLASS,
  OPERATION,
  allocationCommitment,
  arrayOf,
  blake2b256,
  blindPreparedAdmissionStoreV1,
  boundedBytes,
  cellManageRequestCommitment,
  cellPutRequestCommitment,
  cellStorageSlot,
  constant,
  decodeCanonical,
  encodeCanonical,
  fixedBytes,
  optional,
  ranged,
  relayResultBindingV1,
  struct,
  u8,
  u16be,
  u32be,
  u64be
} from '@hiverelay/blind-protocol'
import {
  BLIND_STORE_SERVICE_TAG,
  BlindOpaqueBodyError,
  BlindTransactionStore,
  BlindWalIntegrityError
} from './transaction-store.js'
import { inspectBlindStoreFormatAuthorityBinding } from './store-format-binding.js'

const ZERO32 = b4a.alloc(32)
const ED25519_SPKI_PREFIX = b4a.from('302a300506032b6570032100', 'hex')
const SIX_HOURS_SECONDS = 21600
const SIX_HOURS_MILLIS = 21600000n
const CLOCK_MAX_JUMP_EPOCHS = 4
const EXPIRY_GRACE_EPOCHS = 4
const RETENTION_HORIZON_EPOCHS = 1460
const MAX_RESERVATION_MILLIS = 15n * 60n * 1000n
const MAX_CHARGED_READ_PIN_CONTROL_BYTES = 32 * 1024
const CONTROL_RECORD_BYTES = 512
const TOMBSTONE_RECORD_BYTES = 512
const MAX_U64 = (1n << 64n) - 1n
const MAX_U32 = 0xffffffff

const OBJECT_STATE = Object.freeze({ PRESENT: 1, TOMBSTONE: 2 })
const POLICY_STATE = Object.freeze({ VISIBLE: 1, SUPPRESSED: 2 })
const TERMINAL_REASON = Object.freeze({ INVALID_BODY: 1, ATTEMPTS_EXHAUSTED: 2, RESERVATION_EXPIRED: 3 })
const TOMBSTONE_REASON = Object.freeze({ OWNER_DROP: 1, EXPIRED_GC: 2 })
const COMPACT_KIND = Object.freeze({ CELL: 1, SPEND: 2, REQUEST_RESULT: 3 })
const INTEGRITY_REASON = Object.freeze({ MISSING: 1, LENGTH: 2, HASH: 3 })

export const BLIND_CELL_STORAGE_PRODUCTION_BLOCKERS = Object.freeze([
  'FINAL_STORE_FORMAT_AUTHORITY_UNPUBLISHED',
  'ALL_FAMILY_SHADOW_SEMANTIC_AUTHORITY_UNIMPLEMENTED',
  'PROFILE2_EXTERNAL_JOURNAL_WITNESS_UNIMPLEMENTED',
  'ONLINE_REBALANCE_UNIMPLEMENTED',
  'SIGNED_REPAIR_AND_BACKUP_EVIDENCE_UNIMPLEMENTED',
  'CHECKPOINT_ACCELERATED_SCRUB_UNIMPLEMENTED'
])

export const BLIND_CELL_STORE_FORMAT_BINDING_BLOCKER = 'EXACT_STORE_FORMAT_AUTHORITY_BINDING_MISSING'

export const BLIND_CELL_WAL_TYPE = Object.freeze({
  INGRESS_RESERVED: 1,
  ATTEMPT_CONSUMED: 2,
  PUT_COMMITTED: 3,
  PUT_TERMINAL: 4,
  RENEW_COMMITTED: 5,
  DROP_COMMITTED: 6,
  POLICY_COMMITTED: 7,
  GC_COMMITTED: 8,
  FLOOR_ADVANCE: 9,
  CLOCK_UNSAFE: 10,
  CLOCK_CONFIRM: 11,
  COMPACT: 12,
  INTEGRITY_FAILED: 13,
  READ_PIN_COMMITTED: 14,
  READ_PIN_FINALIZED: 15,
  READ_PIN_EXPIRED: 16
})

const version1 = constant(u8, 1, 'version')
const bytes32 = fixedBytes(32)
const nonzeroStateRevision = u64be

const ingressReservedV1 = struct([
  ['version', version1],
  ['spendTag', bytes32],
  ['requestCommitment', bytes32],
  ['requestFingerprint', bytes32],
  ['storageSlot', bytes32],
  ['allocationEpoch', u32be],
  ['sizeClass', ranged(u8, 1, 5, 'sizeClass')],
  ['leaseClass', ranged(u8, 1, 4, 'leaseClass')],
  ['declaredBlobHash', bytes32],
  ['createPublicKey', bytes32],
  ['renewPublicKey', bytes32],
  ['dropPublicKey', bytes32],
  ['allocationCommitment', bytes32],
  ['profileId', ranged(u16be, 1, 0xffff, 'profileId')],
  ['preparedAdmissionBytes', boundedBytes(1, 17408, 'preparedAdmissionBytes')],
  ['resultBindingBytes', optional(boundedBytes(1, 1024, 'resultBindingBytes'), 'resultBindingBytes')],
  ['declaredBytes', u32be],
  ['deadlineUnixMillis', u64be],
  ['remainingAttempts', constant(u8, 2, 'remainingAttempts')],
  ['reservedEpoch', u32be]
], { name: 'BlindIngressReservedStoreV1' })

const attemptConsumedV1 = struct([
  ['version', version1],
  ['spendTag', bytes32],
  ['requestCommitment', bytes32],
  ['remainingAttempts', ranged(u8, 0, 1, 'remainingAttempts')]
], { name: 'BlindAttemptConsumedStoreV1' })

const putCommittedV1 = struct([
  ['version', version1],
  ['spendTag', bytes32],
  ['requestCommitment', bytes32],
  ['requestFingerprint', bytes32],
  ['storageSlot', bytes32],
  ['blobObjectId', bytes32],
  ['leaseEpoch', u32be],
  ['stateRevision', constant(u64be, 0n, 'stateRevision')],
  ['policyRevision', constant(u64be, 0n, 'policyRevision')],
  ['resultBindingBytes', optional(boundedBytes(1, 1024, 'resultBindingBytes'), 'resultBindingBytes')],
  ['resultIdentity', bytes32],
  ['committedEpoch', u32be]
], { name: 'BlindPutCommittedStoreV1' })

const putTerminalV1 = struct([
  ['version', version1],
  ['spendTag', bytes32],
  ['requestCommitment', bytes32],
  ['requestFingerprint', bytes32],
  ['terminalReason', ranged(u8, 1, 3, 'terminalReason')],
  ['terminalEpoch', u32be]
], { name: 'BlindPutTerminalStoreV1' })

const renewCommittedV1 = struct([
  ['version', version1],
  ['spendTag', bytes32],
  ['requestCommitment', bytes32],
  ['requestFingerprint', bytes32],
  ['storageSlot', bytes32],
  ['profileId', ranged(u16be, 1, 0xffff, 'profileId')],
  ['oldStateRevision', nonzeroStateRevision],
  ['newStateRevision', nonzeroStateRevision],
  ['oldLeaseEpoch', u32be],
  ['newLeaseEpoch', u32be],
  ['leaseClass', ranged(u8, 1, 4, 'leaseClass')],
  ['preparedAdmissionBytes', boundedBytes(1, 17408, 'preparedAdmissionBytes')],
  ['resultBindingBytes', optional(boundedBytes(1, 1024, 'resultBindingBytes'), 'resultBindingBytes')],
  ['resultIdentity', bytes32],
  ['committedEpoch', u32be]
], { name: 'BlindRenewCommittedStoreV1' })

const dropCommittedV1 = struct([
  ['version', version1],
  ['requestCommitment', bytes32],
  ['requestFingerprint', bytes32],
  ['storageSlot', bytes32],
  ['oldStateRevision', u64be],
  ['newStateRevision', nonzeroStateRevision],
  ['oldLeaseEpoch', u32be],
  ['resultBindingBytes', optional(boundedBytes(1, 1024, 'resultBindingBytes'), 'resultBindingBytes')],
  ['resultIdentity', bytes32],
  ['committedEpoch', u32be]
], { name: 'BlindDropCommittedStoreV1' })

const policyCommittedV1 = struct([
  ['version', version1],
  ['storageSlot', bytes32],
  ['oldPolicyRevision', u64be],
  ['newPolicyRevision', nonzeroStateRevision],
  ['policyState', ranged(u8, 1, 2, 'policyState')],
  ['committedEpoch', u32be]
], { name: 'BlindPolicyCommittedStoreV1' })

const gcCommittedV1 = struct([
  ['version', version1],
  ['storageSlot', bytes32],
  ['oldStateRevision', u64be],
  ['newStateRevision', nonzeroStateRevision],
  ['expectedLeaseEpoch', u32be],
  ['tombstoneEpoch', u32be]
], { name: 'BlindGcCommittedStoreV1' })

const floorTransitionV1 = struct([
  ['version', version1],
  ['oldEpochFloor', u32be],
  ['newEpochFloor', u32be]
], { name: 'BlindFloorTransitionStoreV1' })

const clockUnsafeV1 = struct([
  ['version', version1],
  ['epochFloor', u32be],
  ['observedEpoch', u32be],
  ['direction', ranged(u8, 1, 2, 'direction')]
], { name: 'BlindClockUnsafeStoreV1' })

const compactV1 = struct([
  ['version', version1],
  ['entryKind', ranged(u8, 1, 3, 'entryKind')],
  ['key', bytes32],
  ['compactedEpoch', u32be]
], { name: 'BlindCompactStoreV1' })

const integrityFailedV1 = struct([
  ['version', version1],
  ['reason', ranged(u8, 1, 3, 'reason')],
  ['detectedEpoch', u32be],
  ['evidenceHash', bytes32]
], { name: 'BlindIntegrityFailedStoreV1' })

const chargedReadPinEntryV1 = struct([
  ['storageSlot', bytes32],
  ['present', ranged(u8, 0, 1, 'present')],
  ['sizeClass', ranged(u8, 0, 5, 'sizeClass')],
  ['allocationEpoch', u32be],
  ['leaseClass', ranged(u8, 0, 4, 'leaseClass')],
  ['leaseEpoch', u32be],
  ['stateRevision', u64be],
  ['policyRevision', u64be],
  ['cellBlobHash', bytes32],
  ['allocationCommitment', bytes32]
], {
  name: 'BlindChargedReadPinEntryStoreV1',
  validate (value) {
    if (value.present === 0 && (value.sizeClass !== 0 || value.allocationEpoch !== 0 ||
        value.leaseClass !== 0 || value.leaseEpoch !== 0 || value.stateRevision !== 0n ||
        value.policyRevision !== 0n || !isZero(value.cellBlobHash) || !isZero(value.allocationCommitment))) {
      throw new Error('absent charged-read pin entry must use its exact zero state')
    }
    if (value.present === 1 && (value.sizeClass === 0 || value.leaseClass === 0 ||
        isZero(value.storageSlot) || isZero(value.cellBlobHash) || isZero(value.allocationCommitment))) {
      throw new Error('present charged-read pin entry is incomplete')
    }
  }
})

const chargedReadPinEntriesV1 = arrayOf(chargedReadPinEntryV1, 1, 64, 'charged read pin entries')

const chargedReadPinCommittedV1 = struct([
  ['version', version1],
  ['operationId', ranged(u8, OPERATION.CELL.GET, OPERATION.CELL.BATCH_GET, 'operationId')],
  ['spendTag', bytes32],
  ['requestCommitment', bytes32],
  ['requestFingerprint', bytes32],
  ['preparedAdmissionBytes', boundedBytes(1, 17408, 'preparedAdmissionBytes')],
  ['resultBindingBytes', boundedBytes(1, 1024, 'resultBindingBytes')],
  ['receiptEpoch', u32be],
  ['retryExpiresUnixMillis', u64be],
  ['entries', chargedReadPinEntriesV1],
  ['committedEpoch', u32be]
], {
  name: 'BlindChargedReadPinCommittedStoreV1',
  validate (value) {
    if (value.operationId !== OPERATION.CELL.GET && value.operationId !== OPERATION.CELL.PROVE &&
        value.operationId !== OPERATION.CELL.BATCH_GET) throw new Error('unknown charged CELL read operation')
    if (value.operationId !== OPERATION.CELL.BATCH_GET && value.entries.length !== 1) {
      throw new Error('charged unary CELL read must pin exactly one entry')
    }
  }
})

const chargedReadPinFinalizedV1 = struct([
  ['version', version1],
  ['spendTag', bytes32],
  ['requestCommitment', bytes32],
  ['resultCommitment', bytes32],
  ['finalizedEpoch', u32be]
], { name: 'BlindChargedReadPinFinalizedStoreV1' })

const CHARGED_READ_FINALIZATION_CONTROL_BYTES = encodeCanonical(chargedReadPinFinalizedV1, {
  version: 1,
  spendTag: ZERO32,
  requestCommitment: ZERO32,
  resultCommitment: ZERO32,
  finalizedEpoch: 0
}).byteLength

const chargedReadPinExpiredV1 = struct([
  ['version', version1],
  ['spendTag', bytes32],
  ['requestCommitment', bytes32],
  ['retryExpiresUnixMillis', u64be],
  ['observedUnixMillis', u64be],
  ['terminalEpoch', u32be]
], { name: 'BlindChargedReadPinExpiredStoreV1' })

const WAL_PAYLOAD_CODEC = new Map([
  [BLIND_CELL_WAL_TYPE.INGRESS_RESERVED, ingressReservedV1],
  [BLIND_CELL_WAL_TYPE.ATTEMPT_CONSUMED, attemptConsumedV1],
  [BLIND_CELL_WAL_TYPE.PUT_COMMITTED, putCommittedV1],
  [BLIND_CELL_WAL_TYPE.PUT_TERMINAL, putTerminalV1],
  [BLIND_CELL_WAL_TYPE.RENEW_COMMITTED, renewCommittedV1],
  [BLIND_CELL_WAL_TYPE.DROP_COMMITTED, dropCommittedV1],
  [BLIND_CELL_WAL_TYPE.POLICY_COMMITTED, policyCommittedV1],
  [BLIND_CELL_WAL_TYPE.GC_COMMITTED, gcCommittedV1],
  [BLIND_CELL_WAL_TYPE.FLOOR_ADVANCE, floorTransitionV1],
  [BLIND_CELL_WAL_TYPE.CLOCK_UNSAFE, clockUnsafeV1],
  [BLIND_CELL_WAL_TYPE.CLOCK_CONFIRM, floorTransitionV1],
  [BLIND_CELL_WAL_TYPE.COMPACT, compactV1],
  [BLIND_CELL_WAL_TYPE.INTEGRITY_FAILED, integrityFailedV1],
  [BLIND_CELL_WAL_TYPE.READ_PIN_COMMITTED, chargedReadPinCommittedV1],
  [BLIND_CELL_WAL_TYPE.READ_PIN_FINALIZED, chargedReadPinFinalizedV1],
  [BLIND_CELL_WAL_TYPE.READ_PIN_EXPIRED, chargedReadPinExpiredV1]
])

const LEASE_EPOCHS = Object.freeze({ 1: 4, 2: 28, 3: 120, 4: 360 })

const FINGERPRINT_DOMAIN = b4a.from('hiverelay.blind.store-request-fingerprint.v1', 'ascii')
const RESULT_IDENTITY_DOMAIN = b4a.from('hiverelay.blind.store-result-identity.v1', 'ascii')
const REPAIR_LOCATOR_DOMAIN = b4a.from('hiverelay.blind.repair-locator-commitment.v1', 'ascii')
const REPAIR_EVIDENCE_DOMAIN = b4a.from('hiverelay.blind.repair-evidence.v1', 'ascii')
const CONTROL_SNAPSHOT_STATES = new WeakMap()

export class BlindCellStorageError extends Error {
  constructor (code, message, retryable = false) {
    super(message)
    this.name = 'BlindCellStorageError'
    this.code = code
    this.retryable = retryable
  }
}

function fail (code, message, retryable = false) {
  throw new BlindCellStorageError(code, message, retryable)
}

function renewNotDue (retryAfterEpoch) {
  const error = new BlindCellStorageError('RENEW_NOT_DUE', 'renewal would not extend the lease', true)
  error.retryAfterEpoch = retryAfterEpoch
  throw error
}

function isZero (value) {
  for (const byte of value) if (byte !== 0) return false
  return true
}

function fixed (value, length, field, nonzero = false) {
  if (!value || typeof value.byteLength !== 'number') fail('BAD_ENCODING', `${field} must be bytes`)
  value = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (value.byteLength !== length) fail('BAD_ENCODING', `${field} must be exactly ${length} bytes`)
  if (nonzero && isZero(value)) fail('BAD_ENCODING', `${field} must be nonzero`)
  return value
}

function integer (value, minimum, maximum, field) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail('BAD_ENCODING', `${field} is outside ${minimum}..${maximum}`)
  }
  return value
}

function u64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail('BAD_ENCODING', `${field} must be an unsigned safe integer or bigint`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) fail('BAD_ENCODING', `${field} is outside u64`)
  return value
}

function u32bytes (value) {
  const output = b4a.alloc(4)
  output[0] = value >>> 24
  output[1] = value >>> 16
  output[2] = value >>> 8
  output[3] = value
  return output
}

function u64bytes (value) {
  value = u64(value, 'u64')
  const output = b4a.alloc(8)
  for (let index = 7; index >= 0; index--) {
    output[index] = Number(value & 0xffn)
    value >>= 8n
  }
  return output
}

function hex (value) {
  return b4a.toString(value, 'hex')
}

function hashParts (domain, ...parts) {
  return blake2b256(b4a.concat([domain, ...parts]))
}

function equal (left, right) {
  return b4a.equals(left, right)
}

function cloneBytes (value) {
  return value == null ? null : b4a.from(value)
}

function cloneControlSnapshotValue (value) {
  if (value == null || typeof value !== 'object') return value
  if (typeof value.byteLength === 'number') return b4a.from(value)
  if (value instanceof Map) {
    return new Map([...value].map(([key, child]) => [key, cloneControlSnapshotValue(child)]))
  }
  if (Array.isArray(value)) return value.map(cloneControlSnapshotValue)
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, cloneControlSnapshotValue(child)]))
}

export function verifyBlindCellStorageControlSnapshotState (snapshot) {
  const state = CONTROL_SNAPSHOT_STATES.get(snapshot)
  if (!state) throw new TypeError('a branded Cell storage control snapshot state is required')
  return cloneControlSnapshotValue(state)
}

function validateDistinctKeys (keys) {
  const values = keys.map(([field, value]) => [field, fixed(value, 32, field, true)])
  if (new Set(values.map(([, value]) => hex(value))).size !== values.length) {
    fail('BAD_ENCODING', 'create, renew, and drop public keys must be distinct')
  }
  return Object.fromEntries(values)
}

function verifyEd25519 (publicKey, message, signature) {
  publicKey = fixed(publicKey, 32, 'Ed25519 public key', true)
  signature = fixed(signature, 64, 'Ed25519 signature')
  try {
    const key = createPublicKey({ key: b4a.concat([ED25519_SPKI_PREFIX, publicKey]), format: 'der', type: 'spki' })
    return verifySignature(null, message, key, signature)
  } catch {
    return false
  }
}

function nowEpochFromMillis (millis) {
  millis = u64(millis, 'nowUnixMillis')
  const epoch = millis / SIX_HOURS_MILLIS
  if (epoch > 0xffffffffn) fail('INTERNAL', 'clock is outside the version-1 epoch range')
  return Number(epoch)
}

function requestFingerprint (parts) {
  return hashParts(FINGERPRINT_DOMAIN, ...parts)
}

function resultIdentity (operation, slot, requestCommitment, blobHash, leaseClass, leaseEpoch, stateRevision) {
  return hashParts(
    RESULT_IDENTITY_DOMAIN,
    b4a.from(operation, 'ascii'),
    slot,
    requestCommitment,
    blobHash,
    b4a.from([leaseClass]),
    u32bytes(leaseEpoch),
    u64bytes(stateRevision)
  )
}

function quotaInteger (value, fallback, minimum, maximum, field) {
  if (value == null) value = fallback
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${field} is outside ${minimum}..${maximum}`)
  }
  return value
}

function publicCell (record) {
  return {
    storageSlot: b4a.from(record.storageSlot),
    allocationEpoch: record.allocationEpoch,
    sizeClass: record.sizeClass,
    leaseClass: record.leaseClass,
    leaseEpoch: record.leaseEpoch,
    stateRevision: record.stateRevision,
    policyRevision: record.policyRevision,
    cellBlobHash: b4a.from(record.cellBlobHash),
    allocationCommitment: b4a.from(record.allocationCommitment),
    objectState: record.objectState === OBJECT_STATE.PRESENT ? 'PRESENT' : 'TOMBSTONE',
    policyState: record.policyState === POLICY_STATE.VISIBLE ? 'VISIBLE' : 'SUPPRESSED'
  }
}

function clonePublicCell (cell) {
  return {
    storageSlot: b4a.from(cell.storageSlot),
    allocationEpoch: cell.allocationEpoch,
    sizeClass: cell.sizeClass,
    leaseClass: cell.leaseClass,
    leaseEpoch: cell.leaseEpoch,
    stateRevision: cell.stateRevision,
    policyRevision: cell.policyRevision,
    cellBlobHash: b4a.from(cell.cellBlobHash),
    allocationCommitment: b4a.from(cell.allocationCommitment),
    objectState: cell.objectState,
    policyState: cell.policyState
  }
}

function publiclyVisible (record, epochFloor) {
  return Boolean(record && record.objectState === OBJECT_STATE.PRESENT &&
    record.policyState === POLICY_STATE.VISIBLE && epochFloor <= record.leaseEpoch + EXPIRY_GRACE_EPOCHS)
}

function chargedReadPinEntry (storageSlot, record, epochFloor) {
  if (!publiclyVisible(record, epochFloor)) {
    return {
      storageSlot: b4a.from(storageSlot),
      present: 0,
      sizeClass: 0,
      allocationEpoch: 0,
      leaseClass: 0,
      leaseEpoch: 0,
      stateRevision: 0n,
      policyRevision: 0n,
      cellBlobHash: b4a.from(ZERO32),
      allocationCommitment: b4a.from(ZERO32)
    }
  }
  return {
    storageSlot: b4a.from(storageSlot),
    present: 1,
    sizeClass: record.sizeClass,
    allocationEpoch: record.allocationEpoch,
    leaseClass: record.leaseClass,
    leaseEpoch: record.leaseEpoch,
    stateRevision: record.stateRevision,
    policyRevision: record.policyRevision,
    cellBlobHash: b4a.from(record.cellBlobHash),
    allocationCommitment: b4a.from(record.allocationCommitment)
  }
}

function cloneChargedReadPinEntry (entry) {
  return {
    ...entry,
    storageSlot: b4a.from(entry.storageSlot),
    cellBlobHash: b4a.from(entry.cellBlobHash),
    allocationCommitment: b4a.from(entry.allocationCommitment)
  }
}

function chargedBatchResultBytes (resultBindingBytes, entries) {
  let bytes = 162 + resultBindingBytes.byteLength
  for (const entry of entries) {
    bytes += entry.present === 0 ? 1 : 2 + CELL_SIZE_CLASS[entry.sizeClass]
  }
  return bytes
}

function chargedResultBand (bytes) {
  if (bytes <= 4 * 1024) return 1
  if (bytes <= 16 * 1024) return 2
  if (bytes <= 64 * 1024) return 3
  if (bytes <= 256 * 1024) return 4
  if (bytes <= 1024 * 1024) return 5
  if (bytes <= 4 * 1024 * 1024) return 6
  fail('TOO_LARGE', 'charged batch result exceeds the operation result cap')
}

function expiryBefore (left, right) {
  return left.retryExpiresUnixMillis < right.retryExpiresUnixMillis ||
    (left.retryExpiresUnixMillis === right.retryExpiresUnixMillis && left.spendKey < right.spendKey)
}

function pushExpiry (heap, value) {
  heap.push(value)
  let index = heap.length - 1
  while (index > 0) {
    const parent = (index - 1) >>> 1
    if (!expiryBefore(heap[index], heap[parent])) break
    const swap = heap[parent]
    heap[parent] = heap[index]
    heap[index] = swap
    index = parent
  }
}

function popExpiry (heap) {
  if (heap.length === 0) return null
  const first = heap[0]
  const last = heap.pop()
  if (heap.length === 0) return first
  heap[0] = last
  let index = 0
  while (true) {
    const left = index * 2 + 1
    const right = left + 1
    if (left >= heap.length) break
    let next = left
    if (right < heap.length && expiryBefore(heap[right], heap[left])) next = right
    if (!expiryBefore(heap[next], heap[index])) break
    const swap = heap[index]
    heap[index] = heap[next]
    heap[next] = swap
    index = next
  }
  return first
}

function resultView (entry, status, replay) {
  return {
    status,
    replay,
    receiptEpoch: entry.committedEpoch,
    resultBindingBytes: cloneBytes(entry.resultBindingBytes),
    resultIdentity: cloneBytes(entry.resultIdentity),
    cell: clonePublicCell(entry.resultCell)
  }
}

export class BlindCellStorageEngine {
  constructor (options = {}) {
    if (options.durabilityProfileId != null && options.durabilityProfileId !== 1) {
      throw new BlindCellStorageError(
        'FINAL_EXTERNAL_WITNESS_UNIMPLEMENTED',
        'durability profile 2 must fail closed until its external journal and per-result witness coordinator is integrated'
      )
    }
    this.relayPublicKey = b4a.from(fixed(options.relayPublicKey, 32, 'relayPublicKey', true))
    this.storeId = options.storeId == null ? null : b4a.from(fixed(options.storeId, 32, 'storeId', true))
    this.durabilityContinuityHash = b4a.from(fixed(options.durabilityContinuityHash, 32,
      'durabilityContinuityHash', true))
    this.durabilityProfileHash = options.durabilityProfileHash == null
      ? null
      : b4a.from(fixed(options.durabilityProfileHash, 32, 'durabilityProfileHash', true))
    this.storeFormatAuthority = options.storeFormatAuthority == null
      ? null
      : inspectBlindStoreFormatAuthorityBinding(options.storeFormatAuthority)
    this.nowUnixMillis = typeof options.nowUnixMillis === 'function' ? options.nowUnixMillis : () => BigInt(Date.now())
    this.initialEpochFloor = options.initialEpochFloor == null
      ? nowEpochFromMillis(this.nowUnixMillis())
      : integer(options.initialEpochFloor, 0, 0xffffffff, 'initialEpochFloor')
    this.autoClock = options.autoClock !== false
    this.reservationMillis = BigInt(quotaInteger(
      options.reservationMillis,
      Number(MAX_RESERVATION_MILLIS),
      1,
      Number(MAX_RESERVATION_MILLIS),
      'reservationMillis'
    ))
    this.quota = Object.freeze({
      maxStoredBytes: quotaInteger(options.maxStoredBytes, 1024 * 1024 * 1024, 4096, Number.MAX_SAFE_INTEGER - CELL_SIZE_CLASS[5], 'maxStoredBytes'),
      maxStagingBytes: quotaInteger(options.maxStagingBytes, 64 * 1024 * 1024, 4096, Number.MAX_SAFE_INTEGER - CELL_SIZE_CLASS[5], 'maxStagingBytes'),
      maxStagingBytesPerProfile: quotaInteger(options.maxStagingBytesPerProfile, 32 * 1024 * 1024, 4096, Number.MAX_SAFE_INTEGER - CELL_SIZE_CLASS[5], 'maxStagingBytesPerProfile'),
      maxControlBytes: quotaInteger(options.maxControlBytes, 256 * 1024 * 1024, CONTROL_RECORD_BYTES, Number.MAX_SAFE_INTEGER - CONTROL_RECORD_BYTES, 'maxControlBytes'),
      maxTombstoneBytes: quotaInteger(options.maxTombstoneBytes, 256 * 1024 * 1024, TOMBSTONE_RECORD_BYTES, Number.MAX_SAFE_INTEGER - TOMBSTONE_RECORD_BYTES, 'maxTombstoneBytes'),
      maxCells: quotaInteger(options.maxCells, 1000000, 1, 0xffffffff, 'maxCells'),
      maxStartupReferences: quotaInteger(options.maxStartupReferences, 1000000, 1, 0xffffffff, 'maxStartupReferences')
    })
    this.transactionStore = new BlindTransactionStore({
      root: options.root,
      partitionKey: options.partitionKey,
      mapGeneration: options.mapGeneration,
      ownerFenceTokenHash: options.ownerFenceTokenHash,
      durabilityContinuityHash: this.durabilityContinuityHash,
      maximumOpaqueBodyBytes: CELL_SIZE_CLASS[5],
      maximumChunkBytes: options.maximumChunkBytes,
      storeSessionContext: options.storeSessionContext,
      beforeRecovery: options.beforeRecovery,
      faultInjector: options.faultInjector
    })
    this.spends = new Map()
    this.commitments = new Map()
    this.requestResults = new Map()
    this.cells = new Map()
    this.accounting = {
      storedBytes: 0,
      stagingBytes: 0,
      controlBytes: 0,
      tombstoneBytes: 0,
      reservedCells: 0,
      stagingByProfile: new Map()
    }
    this.epochFloor = 0
    this.clockUnsafe = false
    this.readOnlyReason = null
    this.integrityEvidence = []
    this.opened = false
    this.clockTimer = null
    this.closing = false
    this.activeOperations = 0
    this.drainWaiters = []
    this.snapshotting = false
    this.reservationSweepIterator = null
    this.chargedReadExpiryHeap = []
    this.chargedReadSweepTimer = null
    this.closePromise = null
    this.identityDestroyed = false
  }

  async open () {
    if (this.identityDestroyed) throw new Error('cell storage engine identity was destroyed on close')
    if (this.opened) throw new Error('cell storage engine is already open')
    this.closing = false
    try {
      await this.transactionStore.open(frame => this.#applyFrame(frame, true))
      this.opened = true
      if (this.transactionStore.walSequence === 0n) {
        await this.#appendAndApply(BLIND_CELL_WAL_TYPE.FLOOR_ADVANCE, this.transactionStore.newTransactionId(), 0, {
          version: 1,
          oldEpochFloor: 0,
          newEpochFloor: this.initialEpochFloor
        })
      }
      await this.#sweepAllRecoveredReservations()
      if (!this.readOnlyReason) {
        const recoveredReadSweep = await this.#sweepExpiredChargedReadPins(4096)
        if (recoveredReadSweep.moreDue) this.#scheduleChargedReadSweep()
      }
      this.#enforceRecoveredQuota()
      await this.#verifyLiveReferences()
      await this.transactionStore.cleanupOrphans(this.#liveReferenceKeys(), this.quota.maxStartupReferences)
      await this.#refreshClock()
      if (this.autoClock) {
        this.clockTimer = setInterval(() => {
          this.#runOperation(async () => {
            await this.#refreshClock()
            await this.#sweepReservationBatch(4096)
            const readSweep = await this.#sweepExpiredChargedReadPins(4096)
            if (readSweep.moreDue) this.#scheduleChargedReadSweep()
          }).catch(() => { this.readOnlyReason = this.readOnlyReason || 'CLOCK_TIMER_FAILED' })
        }, 60000)
        if (typeof this.clockTimer.unref === 'function') this.clockTimer.unref()
      }
      return this
    } catch (error) {
      if (this.clockTimer) clearInterval(this.clockTimer)
      this.clockTimer = null
      if (this.chargedReadSweepTimer) clearTimeout(this.chargedReadSweepTimer)
      this.chargedReadSweepTimer = null
      this.opened = false
      await this.transactionStore.close().catch(() => {})
      this.#destroyIdentityAuthorities()
      throw error
    }
  }

  #enforceRecoveredQuota () {
    const profileExceeded = [...this.accounting.stagingByProfile.values()]
      .some(value => value > this.quota.maxStagingBytesPerProfile)
    if (this.accounting.storedBytes + this.accounting.stagingBytes > this.quota.maxStoredBytes ||
        this.accounting.stagingBytes > this.quota.maxStagingBytes ||
        this.accounting.controlBytes > this.quota.maxControlBytes ||
        this.accounting.tombstoneBytes > this.quota.maxTombstoneBytes ||
        this.cells.size + this.accounting.reservedCells > this.quota.maxCells || profileExceeded) {
      this.readOnlyReason = 'RECOVERED_QUOTA_EXCEEDED'
    }
  }

  #assertOpen () {
    if (!this.opened) throw new Error('cell storage engine is not open')
  }

  #destroyIdentityAuthorities () {
    if (this.identityDestroyed) return
    this.relayPublicKey.fill(0)
    if (this.storeId) this.storeId.fill(0)
    this.durabilityContinuityHash.fill(0)
    if (this.durabilityProfileHash) this.durabilityProfileHash.fill(0)
    if (this.storeFormatAuthority) this.storeFormatAuthority.storeFormatHash.fill(0)
    this.identityDestroyed = true
  }

  #assertWritable (leaseMutation = false) {
    this.#assertOpen()
    if (this.readOnlyReason) fail('INTERNAL', `store is read-only: ${this.readOnlyReason}`)
    if (leaseMutation && this.clockUnsafe) fail('BUSY', 'store clock is unsafe', true)
  }

  #resultBindingBytes (value, field = 'resultBinding') {
    if (value == null) return null
    let canonicalBytes
    let binding
    try {
      canonicalBytes = value && typeof value.byteLength === 'number'
        ? b4a.from(value)
        : encodeCanonical(relayResultBindingV1, value)
      binding = decodeCanonical(relayResultBindingV1, canonicalBytes, { copyBytes: true })
      if (!equal(canonicalBytes, encodeCanonical(relayResultBindingV1, binding))) throw new Error('non-canonical')
    } catch {
      fail('BAD_ENCODING', `${field} is not a canonical relay result binding`)
    }
    if (binding.durabilityProfileId !== 1 || binding.externalCommitWitness != null ||
        !equal(binding.relayPublicKey, this.relayPublicKey) ||
        !equal(binding.durabilityContinuityHash, this.durabilityContinuityHash) ||
        (this.storeId && !equal(binding.storeId, this.storeId)) ||
        (this.durabilityProfileHash && !equal(binding.durabilityProfileHash, this.durabilityProfileHash))) {
      fail('BAD_ENCODING', `${field} does not bind this profile-1 relay/store authority`)
    }
    return canonicalBytes
  }

  #preparedAdmission (value, field = 'preparedAdmission') {
    if (!value || typeof value !== 'object' || (!value.costClass && value.resourceClass == null)) {
      fail('BAD_ENCODING', `${field} is incomplete`)
    }
    const costClass = value.costClass || value
    const walCommitRecord = value.walCommitRecord && typeof value.walCommitRecord.byteLength === 'number'
      ? b4a.from(value.walCommitRecord)
      : null
    if (!walCommitRecord || walCommitRecord.byteLength < 1 || walCommitRecord.byteLength > 16384) {
      fail('BAD_ENCODING', `${field}.walCommitRecord is outside 1..16384 bytes`)
    }
    const prepared = {
      version: 1,
      spendTag: fixed(value.spendTag, 32, `${field}.spendTag`, true),
      requestCommitment: fixed(value.requestCommitment, 32, `${field}.requestCommitment`, true),
      profileId: integer(value.profileId, 1, 0xffff, `${field}.profileId`),
      schemeId: integer(value.schemeId, 1, 0xffff, `${field}.schemeId`),
      parameterHash: fixed(value.parameterHash, 32, `${field}.parameterHash`, true),
      resourceClass: integer(costClass.resourceClass, 0, 0xffff, `${field}.resourceClass`),
      leaseClass: integer(costClass.leaseClass, 0, 0xff, `${field}.leaseClass`),
      costUnits: u64(costClass.costUnits, `${field}.costUnits`),
      walCommitRecord
    }
    return {
      value: prepared,
      canonicalBytes: encodeCanonical(blindPreparedAdmissionStoreV1, prepared)
    }
  }

  async #runOperation (operation) {
    if (this.closing || this.snapshotting) fail('BUSY', 'store lifecycle is quiescing', true)
    this.activeOperations++
    try {
      return await operation()
    } finally {
      this.activeOperations--
      for (let index = this.drainWaiters.length - 1; index >= 0; index--) {
        if (this.activeOperations <= this.drainWaiters[index].target) {
          const [{ resolve }] = this.drainWaiters.splice(index, 1)
          resolve()
        }
      }
    }
  }

  async #waitForActiveOperations (target) {
    if (this.activeOperations <= target) return
    await new Promise(resolve => this.drainWaiters.push({ target, resolve }))
  }

  async #waitForDrain () {
    await this.#waitForActiveOperations(0)
  }

  #assertAccounting () {
    for (const [field, value] of Object.entries({
      storedBytes: this.accounting.storedBytes,
      stagingBytes: this.accounting.stagingBytes,
      controlBytes: this.accounting.controlBytes,
      tombstoneBytes: this.accounting.tombstoneBytes,
      reservedCells: this.accounting.reservedCells
    })) {
      if (!Number.isSafeInteger(value) || value < 0) throw new BlindWalIntegrityError(`${field} accounting underflow or overflow`)
    }
    for (const value of this.accounting.stagingByProfile.values()) {
      if (!Number.isSafeInteger(value) || value <= 0) throw new BlindWalIntegrityError('per-profile staging accounting is invalid')
    }
  }

  async #appendAndApply (type, transactionId, virtualBucket, value) {
    const codec = WAL_PAYLOAD_CODEC.get(type)
    if (!codec) throw new BlindWalIntegrityError(`unknown cell WAL type ${type}`)
    return this.transactionStore.appendAndApply({
      type,
      transactionId,
      virtualBucket,
      payload: encodeCanonical(codec, value)
    }, frame => this.#applyFrame(frame, false))
  }

  #applyFrame (frame, recovering) {
    const codec = WAL_PAYLOAD_CODEC.get(frame.type)
    if (!codec) throw new BlindWalIntegrityError(`unknown cell WAL type ${frame.type}`)
    let value
    try {
      value = decodeCanonical(codec, frame.payload, { copyBytes: true })
    } catch (error) {
      throw new BlindWalIntegrityError(`non-canonical cell WAL payload: ${error.message}`)
    }
    switch (frame.type) {
      case BLIND_CELL_WAL_TYPE.INGRESS_RESERVED: this.#applyReservation(frame, value); break
      case BLIND_CELL_WAL_TYPE.ATTEMPT_CONSUMED: this.#applyAttempt(frame, value); break
      case BLIND_CELL_WAL_TYPE.PUT_COMMITTED: this.#applyPut(frame, value); break
      case BLIND_CELL_WAL_TYPE.PUT_TERMINAL: this.#applyTerminal(frame, value); break
      case BLIND_CELL_WAL_TYPE.RENEW_COMMITTED: this.#applyRenew(frame, value); break
      case BLIND_CELL_WAL_TYPE.DROP_COMMITTED: this.#applyDrop(frame, value); break
      case BLIND_CELL_WAL_TYPE.POLICY_COMMITTED: this.#applyPolicy(frame, value); break
      case BLIND_CELL_WAL_TYPE.GC_COMMITTED: this.#applyGc(frame, value); break
      case BLIND_CELL_WAL_TYPE.FLOOR_ADVANCE: this.#applyFloor(value, false); break
      case BLIND_CELL_WAL_TYPE.CLOCK_UNSAFE: this.#applyClockUnsafe(value); break
      case BLIND_CELL_WAL_TYPE.CLOCK_CONFIRM: this.#applyFloor(value, true); break
      case BLIND_CELL_WAL_TYPE.COMPACT: this.#applyCompact(value); break
      case BLIND_CELL_WAL_TYPE.INTEGRITY_FAILED: this.#applyIntegrity(value, recovering); break
      case BLIND_CELL_WAL_TYPE.READ_PIN_COMMITTED: this.#applyReadPin(frame, value); break
      case BLIND_CELL_WAL_TYPE.READ_PIN_FINALIZED: this.#applyReadPinFinalized(frame, value); break
      case BLIND_CELL_WAL_TYPE.READ_PIN_EXPIRED: this.#applyReadPinExpired(frame, value); break
      default: throw new BlindWalIntegrityError(`unhandled cell WAL type ${frame.type}`)
    }
    this.#assertAccounting()
  }

  #verifyBucket (frame, storageSlot) {
    const expected = this.transactionStore.virtualBucket(BLIND_STORE_SERVICE_TAG.CELL, storageSlot)
    if (frame.virtualBucket !== expected) throw new BlindWalIntegrityError('cell WAL frame is assigned to the wrong keyed virtual bucket')
  }

  #applyReservation (frame, value) {
    this.#verifyBucket(frame, value.storageSlot)
    const spendKey = hex(value.spendTag)
    const commitmentKey = hex(value.requestCommitment)
    const slotKey = hex(value.storageSlot)
    if (this.spends.has(spendKey) || this.commitments.has(commitmentKey) || this.cells.has(slotKey)) {
      throw new BlindWalIntegrityError('reservation redefines an existing spend, commitment, or cell')
    }
    const declaredLength = CELL_SIZE_CLASS[value.sizeClass]
    if (declaredLength !== value.declaredBytes) throw new BlindWalIntegrityError('reservation size class and declared bytes disagree')
    if (!equal(cellStorageSlot(value), value.storageSlot)) throw new BlindWalIntegrityError('reservation storage slot is not self-certifying')
    const expectedAllocation = allocationCommitment({
      relayPublicKey: this.relayPublicKey,
      storageSlot: value.storageSlot,
      allocationEpoch: value.allocationEpoch,
      sizeClass: value.sizeClass,
      leaseClass: value.leaseClass,
      declaredCellBlobHash: value.declaredBlobHash,
      createPublicKey: value.createPublicKey,
      renewPublicKey: value.renewPublicKey,
      dropPublicKey: value.dropPublicKey
    })
    if (!equal(expectedAllocation, value.allocationCommitment)) throw new BlindWalIntegrityError('reservation allocation commitment mismatch')
    for (const field of ['spendTag', 'requestCommitment', 'requestFingerprint', 'declaredBlobHash', 'createPublicKey', 'renewPublicKey', 'dropPublicKey']) {
      if (isZero(value[field])) throw new BlindWalIntegrityError(`reservation ${field} must be nonzero`)
    }
    if (new Set([value.createPublicKey, value.renewPublicKey, value.dropPublicKey].map(hex)).size !== 3) {
      throw new BlindWalIntegrityError('reservation management keys must be distinct')
    }
    if (value.reservedEpoch !== this.epochFloor || value.deadlineUnixMillis === 0n) {
      throw new BlindWalIntegrityError('reservation clock binding is inconsistent')
    }
    let resultBindingBytes
    let preparedAdmissionBytes
    try {
      resultBindingBytes = this.#resultBindingBytes(value.resultBindingBytes, 'reserved resultBindingBytes')
      const decodedPrepared = decodeCanonical(blindPreparedAdmissionStoreV1, value.preparedAdmissionBytes, { copyBytes: true })
      const canonicalPrepared = this.#preparedAdmission(decodedPrepared, 'reserved preparedAdmissionBytes')
      if (!equal(canonicalPrepared.canonicalBytes, value.preparedAdmissionBytes) ||
          !equal(canonicalPrepared.value.spendTag, value.spendTag) ||
          !equal(canonicalPrepared.value.requestCommitment, value.requestCommitment) ||
          canonicalPrepared.value.profileId !== value.profileId) throw new Error('binding mismatch')
      preparedAdmissionBytes = canonicalPrepared.canonicalBytes
    } catch (error) {
      throw new BlindWalIntegrityError(error.message)
    }
    const entry = {
      status: 'reserved',
      transactionId: b4a.from(frame.transactionId),
      spendTag: b4a.from(value.spendTag),
      requestCommitment: b4a.from(value.requestCommitment),
      requestFingerprint: b4a.from(value.requestFingerprint),
      storageSlot: b4a.from(value.storageSlot),
      allocationEpoch: value.allocationEpoch,
      sizeClass: value.sizeClass,
      leaseClass: value.leaseClass,
      declaredBlobHash: b4a.from(value.declaredBlobHash),
      createPublicKey: b4a.from(value.createPublicKey),
      renewPublicKey: b4a.from(value.renewPublicKey),
      dropPublicKey: b4a.from(value.dropPublicKey),
      allocationCommitment: b4a.from(value.allocationCommitment),
      profileId: value.profileId,
      preparedAdmissionBytes,
      resultBindingBytes,
      declaredBytes: value.declaredBytes,
      deadlineUnixMillis: value.deadlineUnixMillis,
      remainingAttempts: value.remainingAttempts,
      reservedEpoch: value.reservedEpoch,
      terminalEpoch: null,
      resultIdentity: null,
      committedEpoch: null,
      inFlight: false
    }
    this.spends.set(spendKey, entry)
    this.commitments.set(commitmentKey, { spendKey, fingerprint: hex(value.requestFingerprint) })
    this.accounting.stagingBytes += value.declaredBytes
    this.accounting.controlBytes += CONTROL_RECORD_BYTES
    this.accounting.tombstoneBytes += TOMBSTONE_RECORD_BYTES
    this.accounting.reservedCells++
    this.accounting.stagingByProfile.set(value.profileId,
      (this.accounting.stagingByProfile.get(value.profileId) || 0) + value.declaredBytes)
  }

  #reservationFor (frame, spendTag, requestCommitment) {
    const entry = this.spends.get(hex(spendTag))
    if (!entry || entry.status !== 'reserved' || !equal(entry.requestCommitment, requestCommitment) ||
        !equal(entry.transactionId, frame.transactionId)) {
      throw new BlindWalIntegrityError('WAL transition has no matching live reservation')
    }
    return entry
  }

  #applyAttempt (frame, value) {
    const entry = this.#reservationFor(frame, value.spendTag, value.requestCommitment)
    this.#verifyBucket(frame, entry.storageSlot)
    if (value.remainingAttempts !== entry.remainingAttempts - 1) {
      throw new BlindWalIntegrityError('attempt credit did not decrement exactly once')
    }
    entry.remainingAttempts = value.remainingAttempts
  }

  #applyPut (frame, value) {
    const entry = this.#reservationFor(frame, value.spendTag, value.requestCommitment)
    this.#verifyBucket(frame, value.storageSlot)
    if (!equal(entry.storageSlot, value.storageSlot) || !equal(entry.requestFingerprint, value.requestFingerprint)) {
      throw new BlindWalIntegrityError('put commit does not match its reservation')
    }
    const expectedLeaseEpoch = value.committedEpoch + LEASE_EPOCHS[entry.leaseClass]
    const expectedResult = resultIdentity('stored', entry.storageSlot, entry.requestCommitment,
      entry.declaredBlobHash, entry.leaseClass, value.leaseEpoch, 0n)
    let resultBindingBytes
    try {
      resultBindingBytes = this.#resultBindingBytes(value.resultBindingBytes, 'committed resultBindingBytes')
    } catch (error) {
      throw new BlindWalIntegrityError(error.message)
    }
    if (entry.remainingAttempts > 1 || value.committedEpoch !== this.epochFloor || value.leaseEpoch !== expectedLeaseEpoch ||
        !equal(value.resultIdentity, expectedResult) || isZero(value.blobObjectId) ||
        (entry.resultBindingBytes == null) !== (resultBindingBytes == null) ||
        (entry.resultBindingBytes != null && !equal(entry.resultBindingBytes, resultBindingBytes))) {
      throw new BlindWalIntegrityError('put commit result, lease, attempt, or epoch binding is invalid')
    }
    const slotKey = hex(value.storageSlot)
    if (this.cells.has(slotKey)) throw new BlindWalIntegrityError('put commit overwrites an existing cell')
    entry.status = 'committed'
    entry.inFlight = false
    entry.resultIdentity = b4a.from(value.resultIdentity)
    entry.resultBindingBytes = resultBindingBytes
    entry.committedEpoch = value.committedEpoch
    const record = {
      storageSlot: b4a.from(entry.storageSlot),
      allocationEpoch: entry.allocationEpoch,
      sizeClass: entry.sizeClass,
      leaseClass: entry.leaseClass,
      leaseEpoch: value.leaseEpoch,
      stateRevision: value.stateRevision,
      policyRevision: value.policyRevision,
      cellBlobHash: b4a.from(entry.declaredBlobHash),
      blobReference: { virtualBucket: frame.virtualBucket, objectId: b4a.from(value.blobObjectId) },
      createPublicKey: b4a.from(entry.createPublicKey),
      renewPublicKey: b4a.from(entry.renewPublicKey),
      dropPublicKey: b4a.from(entry.dropPublicKey),
      allocationCommitment: b4a.from(entry.allocationCommitment),
      objectState: OBJECT_STATE.PRESENT,
      policyState: POLICY_STATE.VISIBLE,
      tombstoneReason: null,
      terminalEpoch: null,
      createSpendTag: b4a.from(entry.spendTag),
      resultIdentity: b4a.from(value.resultIdentity),
      createdEpoch: value.committedEpoch
    }
    this.cells.set(slotKey, record)
    entry.resultCell = publicCell(record)
    this.#releaseStaging(entry)
    this.accounting.reservedCells--
    this.accounting.storedBytes += entry.declaredBytes
  }

  #applyTerminal (frame, value) {
    const entry = this.#reservationFor(frame, value.spendTag, value.requestCommitment)
    this.#verifyBucket(frame, entry.storageSlot)
    if (!equal(entry.requestFingerprint, value.requestFingerprint) || value.terminalEpoch !== this.epochFloor) {
      throw new BlindWalIntegrityError('terminal transition fingerprint or epoch mismatch')
    }
    entry.status = 'terminal'
    entry.inFlight = false
    entry.terminalReason = value.terminalReason
    entry.terminalEpoch = value.terminalEpoch
    this.#releaseStaging(entry)
    this.accounting.tombstoneBytes -= TOMBSTONE_RECORD_BYTES
    this.accounting.reservedCells--
  }

  #releaseStaging (entry) {
    this.accounting.stagingBytes -= entry.declaredBytes
    const profileBytes = (this.accounting.stagingByProfile.get(entry.profileId) || 0) - entry.declaredBytes
    if (profileBytes === 0) this.accounting.stagingByProfile.delete(entry.profileId)
    else this.accounting.stagingByProfile.set(entry.profileId, profileBytes)
  }

  #applyRenew (frame, value) {
    this.#verifyBucket(frame, value.storageSlot)
    const spendKey = hex(value.spendTag)
    const commitmentKey = hex(value.requestCommitment)
    if (this.spends.has(spendKey) || this.commitments.has(commitmentKey)) {
      throw new BlindWalIntegrityError('renew commit redefines a spend or request commitment')
    }
    const record = this.cells.get(hex(value.storageSlot))
    if (!record || record.objectState !== OBJECT_STATE.PRESENT || record.stateRevision !== value.oldStateRevision ||
        record.leaseEpoch !== value.oldLeaseEpoch || value.newStateRevision !== value.oldStateRevision + 1n ||
        value.newLeaseEpoch <= value.oldLeaseEpoch) {
      throw new BlindWalIntegrityError('renew commit violates the cell state machine')
    }
    const expectedLeaseEpoch = Math.max(value.oldLeaseEpoch, value.committedEpoch + LEASE_EPOCHS[value.leaseClass])
    const expectedResult = resultIdentity('renewed', value.storageSlot, value.requestCommitment,
      record.cellBlobHash, value.leaseClass, value.newLeaseEpoch, value.newStateRevision)
    let resultBindingBytes
    let preparedAdmissionBytes
    try {
      resultBindingBytes = this.#resultBindingBytes(value.resultBindingBytes, 'renew resultBindingBytes')
      const decodedPrepared = decodeCanonical(blindPreparedAdmissionStoreV1, value.preparedAdmissionBytes, { copyBytes: true })
      const canonicalPrepared = this.#preparedAdmission(decodedPrepared, 'renew preparedAdmissionBytes')
      if (!equal(canonicalPrepared.canonicalBytes, value.preparedAdmissionBytes) ||
          !equal(canonicalPrepared.value.spendTag, value.spendTag) ||
          !equal(canonicalPrepared.value.requestCommitment, value.requestCommitment) ||
          canonicalPrepared.value.profileId !== value.profileId) throw new Error('binding mismatch')
      preparedAdmissionBytes = canonicalPrepared.canonicalBytes
    } catch (error) {
      throw new BlindWalIntegrityError(error.message)
    }
    if (value.committedEpoch !== this.epochFloor || value.newLeaseEpoch !== expectedLeaseEpoch ||
        !equal(value.resultIdentity, expectedResult)) {
      throw new BlindWalIntegrityError('renew commit result, lease, or epoch binding is invalid')
    }
    record.stateRevision = value.newStateRevision
    record.leaseEpoch = value.newLeaseEpoch
    record.leaseClass = value.leaseClass
    const entry = {
      status: 'committed',
      operation: 'renew',
      transactionId: b4a.from(frame.transactionId),
      spendTag: b4a.from(value.spendTag),
      requestCommitment: b4a.from(value.requestCommitment),
      requestFingerprint: b4a.from(value.requestFingerprint),
      storageSlot: b4a.from(value.storageSlot),
      expectedStateRevision: value.oldStateRevision,
      expectedLeaseEpoch: value.oldLeaseEpoch,
      requestedLeaseClass: value.leaseClass,
      profileId: value.profileId,
      resultIdentity: b4a.from(value.resultIdentity),
      preparedAdmissionBytes,
      resultBindingBytes,
      committedEpoch: value.committedEpoch,
      terminalEpoch: null,
      resultCell: publicCell(record)
    }
    this.spends.set(spendKey, entry)
    this.commitments.set(commitmentKey, { spendKey, fingerprint: hex(value.requestFingerprint) })
    this.accounting.controlBytes += CONTROL_RECORD_BYTES
  }

  #applyDrop (frame, value) {
    this.#verifyBucket(frame, value.storageSlot)
    const commitmentKey = hex(value.requestCommitment)
    if (this.requestResults.has(commitmentKey)) throw new BlindWalIntegrityError('drop commit redefines a request result')
    const record = this.cells.get(hex(value.storageSlot))
    if (!record || record.objectState !== OBJECT_STATE.PRESENT || record.stateRevision !== value.oldStateRevision ||
        record.leaseEpoch !== value.oldLeaseEpoch || value.newStateRevision !== value.oldStateRevision + 1n) {
      throw new BlindWalIntegrityError('drop commit violates the cell state machine')
    }
    const expectedResult = resultIdentity('dropped', value.storageSlot, value.requestCommitment,
      record.cellBlobHash, 0, value.oldLeaseEpoch, value.newStateRevision)
    let resultBindingBytes
    try {
      resultBindingBytes = this.#resultBindingBytes(value.resultBindingBytes, 'drop resultBindingBytes')
    } catch (error) {
      throw new BlindWalIntegrityError(error.message)
    }
    if (value.committedEpoch !== this.epochFloor || !equal(value.resultIdentity, expectedResult)) {
      throw new BlindWalIntegrityError('drop commit result or epoch binding is invalid')
    }
    record.objectState = OBJECT_STATE.TOMBSTONE
    record.tombstoneReason = TOMBSTONE_REASON.OWNER_DROP
    record.stateRevision = value.newStateRevision
    record.terminalEpoch = value.committedEpoch
    const result = {
      operation: 'drop',
      requestCommitment: b4a.from(value.requestCommitment),
      requestFingerprint: b4a.from(value.requestFingerprint),
      storageSlot: b4a.from(value.storageSlot),
      resultIdentity: b4a.from(value.resultIdentity),
      resultBindingBytes,
      committedEpoch: value.committedEpoch,
      transactionId: b4a.from(frame.transactionId),
      resultCell: publicCell(record)
    }
    this.requestResults.set(commitmentKey, result)
    this.accounting.storedBytes -= record.sizeClass == null ? 0 : CELL_SIZE_CLASS[record.sizeClass]
  }

  #applyReadPin (frame, value) {
    if (frame.virtualBucket !== 0) throw new BlindWalIntegrityError('charged read pin must use the coordinator bucket')
    const spendKey = hex(value.spendTag)
    const commitmentKey = hex(value.requestCommitment)
    if (this.spends.has(spendKey) || this.commitments.has(commitmentKey) ||
        value.committedEpoch !== this.epochFloor || value.receiptEpoch !== this.epochFloor ||
        value.retryExpiresUnixMillis === 0n || isZero(value.requestFingerprint)) {
      throw new BlindWalIntegrityError('charged read pin redefines state or has an invalid epoch/deadline')
    }
    let preparedAdmissionBytes
    let preparedAdmission
    let resultBindingBytes
    try {
      const decodedPrepared = decodeCanonical(blindPreparedAdmissionStoreV1, value.preparedAdmissionBytes, { copyBytes: true })
      const prepared = this.#preparedAdmission(decodedPrepared, 'charged read preparedAdmissionBytes')
      if (!equal(prepared.canonicalBytes, value.preparedAdmissionBytes) ||
          !equal(prepared.value.spendTag, value.spendTag) ||
          !equal(prepared.value.requestCommitment, value.requestCommitment)) throw new Error('binding mismatch')
      preparedAdmissionBytes = prepared.canonicalBytes
      preparedAdmission = prepared.value
      resultBindingBytes = this.#resultBindingBytes(value.resultBindingBytes, 'charged read resultBindingBytes')
      if (!resultBindingBytes) throw new Error('missing result binding')
    } catch (error) {
      throw new BlindWalIntegrityError(error.message)
    }
    const slots = new Set()
    for (const pinned of value.entries) {
      const slotKey = hex(pinned.storageSlot)
      if (slots.has(slotKey)) throw new BlindWalIntegrityError('charged read pin has duplicate slots')
      slots.add(slotKey)
      const current = chargedReadPinEntry(pinned.storageSlot, this.cells.get(slotKey), this.epochFloor)
      if (!equal(encodeCanonical(chargedReadPinEntryV1, current),
        encodeCanonical(chargedReadPinEntryV1, pinned))) {
        throw new BlindWalIntegrityError('charged read pin does not match its commit-time cell state')
      }
    }
    if (value.operationId !== OPERATION.CELL.BATCH_GET && value.entries[0].present !== 1) {
      throw new BlindWalIntegrityError('charged unary read pinned an absent cell')
    }
    const expectedFingerprint = requestFingerprint([
      b4a.from([value.operationId]),
      value.spendTag,
      value.requestCommitment,
      blake2b256(preparedAdmissionBytes)
    ])
    try {
      if (!equal(value.requestFingerprint, expectedFingerprint)) throw new Error('fingerprint mismatch')
      this.#verifyChargedReadCost(value.operationId, preparedAdmission, value.entries, resultBindingBytes)
    } catch (error) {
      throw new BlindWalIntegrityError(error.message)
    }
    const entry = {
      status: 'read-pinned',
      operation: `read-${value.operationId}`,
      transactionId: b4a.from(frame.transactionId),
      spendTag: b4a.from(value.spendTag),
      requestCommitment: b4a.from(value.requestCommitment),
      requestFingerprint: b4a.from(value.requestFingerprint),
      preparedAdmissionBytes,
      resultBindingBytes,
      receiptEpoch: value.receiptEpoch,
      retryExpiresUnixMillis: value.retryExpiresUnixMillis,
      entries: value.entries.map(cloneChargedReadPinEntry),
      resultCommitment: null,
      committedEpoch: value.committedEpoch,
      terminalEpoch: null,
      controlBytes: frame.payload.byteLength + CHARGED_READ_FINALIZATION_CONTROL_BYTES
    }
    this.spends.set(spendKey, entry)
    this.commitments.set(commitmentKey, { spendKey, fingerprint: hex(value.requestFingerprint) })
    this.accounting.controlBytes += entry.controlBytes
    pushExpiry(this.chargedReadExpiryHeap, {
      retryExpiresUnixMillis: entry.retryExpiresUnixMillis,
      spendKey,
      transactionId: hex(entry.transactionId)
    })
  }

  #applyReadPinFinalized (frame, value) {
    if (frame.virtualBucket !== 0 || value.finalizedEpoch !== this.epochFloor) {
      throw new BlindWalIntegrityError('charged read finalization has an invalid bucket or epoch')
    }
    const entry = this.spends.get(hex(value.spendTag))
    if (!entry || entry.status !== 'read-pinned' ||
        !equal(entry.transactionId, frame.transactionId) ||
        !equal(entry.requestCommitment, value.requestCommitment) || isZero(value.resultCommitment) ||
        frame.payload.byteLength !== CHARGED_READ_FINALIZATION_CONTROL_BYTES) {
      throw new BlindWalIntegrityError('charged read finalization has no matching pin')
    }
    if (!this.#chargedReadSourcesMatch(entry, true)) {
      throw new BlindWalIntegrityError('charged read finalization crossed a pinned source transition')
    }
    entry.status = 'read-finalized'
    entry.resultCommitment = b4a.from(value.resultCommitment)
  }

  #applyReadPinExpired (frame, value) {
    if (frame.virtualBucket !== 0 || value.terminalEpoch !== this.epochFloor) {
      throw new BlindWalIntegrityError('charged read expiry has an invalid bucket or epoch')
    }
    const entry = this.spends.get(hex(value.spendTag))
    if (!entry || (entry.status !== 'read-pinned' && entry.status !== 'read-finalized') ||
        !equal(entry.transactionId, frame.transactionId) ||
        !equal(entry.requestCommitment, value.requestCommitment) ||
        entry.retryExpiresUnixMillis !== value.retryExpiresUnixMillis ||
        value.observedUnixMillis < value.retryExpiresUnixMillis) {
      throw new BlindWalIntegrityError('charged read expiry has no matching retry pin')
    }
    this.accounting.controlBytes -= entry.controlBytes
    entry.status = 'read-expired'
    entry.terminalEpoch = value.terminalEpoch
    entry.entries = null
    entry.preparedAdmissionBytes = null
    entry.resultBindingBytes = null
    entry.resultCommitment = null
    entry.receiptEpoch = null
    entry.controlBytes = CONTROL_RECORD_BYTES
    this.accounting.controlBytes += CONTROL_RECORD_BYTES
  }

  #applyPolicy (frame, value) {
    this.#verifyBucket(frame, value.storageSlot)
    const record = this.cells.get(hex(value.storageSlot))
    if (!record || record.objectState !== OBJECT_STATE.PRESENT || record.policyRevision !== value.oldPolicyRevision ||
        value.newPolicyRevision !== value.oldPolicyRevision + 1n || record.policyState === value.policyState ||
        value.committedEpoch !== this.epochFloor) {
      throw new BlindWalIntegrityError('policy commit violates the independent policy revision state machine')
    }
    record.policyRevision = value.newPolicyRevision
    record.policyState = value.policyState
  }

  #applyGc (frame, value) {
    this.#verifyBucket(frame, value.storageSlot)
    const record = this.cells.get(hex(value.storageSlot))
    if (!record || record.objectState !== OBJECT_STATE.PRESENT || record.stateRevision !== value.oldStateRevision ||
        record.leaseEpoch !== value.expectedLeaseEpoch || value.newStateRevision !== value.oldStateRevision + 1n ||
        value.tombstoneEpoch <= value.expectedLeaseEpoch + EXPIRY_GRACE_EPOCHS || value.tombstoneEpoch !== this.epochFloor) {
      throw new BlindWalIntegrityError('GC commit violates the lease and revision state machine')
    }
    record.objectState = OBJECT_STATE.TOMBSTONE
    record.tombstoneReason = TOMBSTONE_REASON.EXPIRED_GC
    record.stateRevision = value.newStateRevision
    record.terminalEpoch = value.tombstoneEpoch
    this.accounting.storedBytes -= CELL_SIZE_CLASS[record.sizeClass]
  }

  #applyFloor (value, confirmed) {
    if (value.oldEpochFloor !== this.epochFloor || value.newEpochFloor < value.oldEpochFloor) {
      throw new BlindWalIntegrityError('epoch floor rollback or discontinuity')
    }
    if (!confirmed && value.newEpochFloor > value.oldEpochFloor + CLOCK_MAX_JUMP_EPOCHS && value.oldEpochFloor !== 0) {
      throw new BlindWalIntegrityError('unconfirmed epoch floor jump exceeds four epochs')
    }
    this.epochFloor = value.newEpochFloor
    if (confirmed) this.clockUnsafe = false
  }

  #applyClockUnsafe (value) {
    if (value.epochFloor !== this.epochFloor ||
        (value.direction === 1 && value.observedEpoch >= value.epochFloor) ||
        (value.direction === 2 && value.observedEpoch <= value.epochFloor + CLOCK_MAX_JUMP_EPOCHS)) {
      throw new BlindWalIntegrityError('CLOCK_UNSAFE transition is inconsistent with the persisted floor')
    }
    this.clockUnsafe = true
  }

  #applyCompact (value) {
    if (value.compactedEpoch !== this.epochFloor) throw new BlindWalIntegrityError('compaction does not bind the effective epoch floor')
    const key = hex(value.key)
    if (value.entryKind === COMPACT_KIND.CELL) {
      const record = this.cells.get(key)
      if (!record || record.objectState !== OBJECT_STATE.TOMBSTONE || record.terminalEpoch == null ||
          value.compactedEpoch - record.terminalEpoch <= RETENTION_HORIZON_EPOCHS) {
        throw new BlindWalIntegrityError('cell tombstone compacted before its retention horizon')
      }
      this.cells.delete(key)
      this.accounting.tombstoneBytes -= TOMBSTONE_RECORD_BYTES
      return
    }
    if (value.entryKind === COMPACT_KIND.SPEND) {
      const entry = this.spends.get(key)
      const ageEpoch = entry && (entry.terminalEpoch == null ? entry.committedEpoch : entry.terminalEpoch)
      if (!entry || ageEpoch == null || value.compactedEpoch - ageEpoch <= RETENTION_HORIZON_EPOCHS) {
        throw new BlindWalIntegrityError('spend compacted before its retention horizon')
      }
      this.spends.delete(key)
      this.commitments.delete(hex(entry.requestCommitment))
      this.accounting.controlBytes -= entry.controlBytes || CONTROL_RECORD_BYTES
      return
    }
    const entry = this.requestResults.get(key)
    if (!entry || value.compactedEpoch - entry.committedEpoch <= RETENTION_HORIZON_EPOCHS) {
      throw new BlindWalIntegrityError('request result compacted before its retention horizon')
    }
    this.requestResults.delete(key)
  }

  #applyIntegrity (value, recovering) {
    this.readOnlyReason = 'RECOVERY_GAP_READ_ONLY'
    if (recovering || this.integrityEvidence.every(item => !equal(item.evidenceHash, value.evidenceHash))) {
      this.integrityEvidence.push({
        reason: value.reason,
        detectedEpoch: value.detectedEpoch,
        evidenceHash: b4a.from(value.evidenceHash)
      })
    }
  }

  #putInput (input) {
    if (!input || typeof input !== 'object' || !input.request || !input.preparedAdmission) {
      fail('BAD_ENCODING', 'putCell requires a request and preparedAdmission')
    }
    const request = input.request
    const resultBindingBytes = this.#resultBindingBytes(input.resultBinding)
    const keys = validateDistinctKeys([
      ['createPublicKey', request.createPublicKey],
      ['renewPublicKey', request.renewPublicKey],
      ['dropPublicKey', request.dropPublicKey]
    ])
    const storageSlot = fixed(request.storageSlot, 32, 'storageSlot', true)
    const allocationEpoch = integer(request.allocationEpoch, 0, 0xffffffff, 'allocationEpoch')
    const sizeClass = integer(request.sizeClass, 1, 5, 'sizeClass')
    const leaseClass = integer(request.leaseClass, 1, 4, 'leaseClass')
    const clientNonce = fixed(request.clientNonce, 32, 'clientNonce')
    const declaredBlobHash = fixed(request.declaredBlobHash, 32, 'declaredBlobHash', true)
    if (!equal(cellStorageSlot({ allocationEpoch, createPublicKey: keys.createPublicKey }), storageSlot)) {
      fail('BAD_SLOT', 'storageSlot is not self-certifying')
    }
    const allocation = allocationCommitment({
      relayPublicKey: this.relayPublicKey,
      storageSlot,
      allocationEpoch,
      sizeClass,
      leaseClass,
      declaredCellBlobHash: declaredBlobHash,
      createPublicKey: keys.createPublicKey,
      renewPublicKey: keys.renewPublicKey,
      dropPublicKey: keys.dropPublicKey
    })
    if (!verifyEd25519(keys.createPublicKey, allocation, request.createSignature)) {
      fail('BAD_CREATE_SIG', 'cell create signature is invalid')
    }
    const expectedRequestCommitment = cellPutRequestCommitment({ allocationCommitment: allocation, clientNonce })
    const preparedAdmission = this.#preparedAdmission(input.preparedAdmission)
    const spendTag = preparedAdmission.value.spendTag
    const suppliedRequestCommitment = preparedAdmission.value.requestCommitment
    if (!equal(expectedRequestCommitment, suppliedRequestCommitment)) fail('SPEND_INVALID', 'prepared admission binds another request')
    const profileId = preparedAdmission.value.profileId
    const fingerprint = requestFingerprint([
      spendTag,
      expectedRequestCommitment,
      storageSlot,
      allocation,
      declaredBlobHash,
      u32bytes(CELL_SIZE_CLASS[sizeClass]),
      b4a.from([leaseClass]),
      u32bytes(profileId),
      blake2b256(preparedAdmission.canonicalBytes)
    ])
    const source = input.source == null ? request.cellBlob : input.source
    if (source == null) fail('BAD_ENCODING', 'putCell requires an opaque body source')
    return {
      request,
      source,
      storageSlot,
      allocationEpoch,
      sizeClass,
      leaseClass,
      clientNonce,
      declaredBlobHash,
      createPublicKey: keys.createPublicKey,
      renewPublicKey: keys.renewPublicKey,
      dropPublicKey: keys.dropPublicKey,
      allocationCommitment: allocation,
      requestCommitment: expectedRequestCommitment,
      spendTag,
      profileId,
      preparedAdmissionBytes: preparedAdmission.canonicalBytes,
      fingerprint,
      resultBindingBytes
    }
  }

  #spendReplay (entry, input) {
    if (!entry) fail('INTERNAL', 'spend state disappeared during a locked transaction')
    if (!equal(entry.requestCommitment, input.requestCommitment)) fail('SPEND_REPLAY', 'spend tag is committed to another request')
    if (!equal(entry.requestFingerprint, input.fingerprint)) fail('CONFLICT', 'request commitment was reused with inconsistent fields')
    if (entry.status === 'committed') {
      const record = this.cells.get(hex(entry.storageSlot))
      if (!record || record.objectState !== OBJECT_STATE.PRESENT || record.policyState !== POLICY_STATE.VISIBLE ||
          this.epochFloor > record.leaseEpoch + EXPIRY_GRACE_EPOCHS) {
        fail('RETRY_TERMINAL', 'the committed result is no longer replayable')
      }
      return resultView(entry, 'stored', true)
    }
    if (entry.status === 'terminal') fail('RETRY_TERMINAL', 'the ingress reservation reached a terminal state')
    return null
  }

  #checkCreateQuota (declaredBytes, profileId) {
    if (this.cells.size + this.accounting.reservedCells >= this.quota.maxCells) fail('BUSY', 'cell record quota is full', true)
    if (this.accounting.storedBytes + this.accounting.stagingBytes + declaredBytes > this.quota.maxStoredBytes) {
      fail('BUSY', 'opaque storage quota is full', true)
    }
    if (this.accounting.stagingBytes + declaredBytes > this.quota.maxStagingBytes) fail('BUSY', 'global staging quota is full', true)
    if ((this.accounting.stagingByProfile.get(profileId) || 0) + declaredBytes > this.quota.maxStagingBytesPerProfile) {
      fail('BUSY', 'generic admission-profile staging quota is full', true)
    }
    if (this.accounting.controlBytes + CONTROL_RECORD_BYTES > this.quota.maxControlBytes) fail('BUSY', 'control-record quota is full', true)
    if (this.accounting.tombstoneBytes + TOMBSTONE_RECORD_BYTES > this.quota.maxTombstoneBytes) {
      fail('BUSY', 'reserved tombstone quota is full', true)
    }
  }

  async #reservePut (input) {
    const spendKey = `spend:${hex(input.spendTag)}`
    const cellKey = `cell:${hex(input.storageSlot)}`
    return this.transactionStore.withLocks([spendKey, cellKey], async () => {
      const existingSpend = this.spends.get(hex(input.spendTag))
      if (existingSpend) {
        const replay = this.#spendReplay(existingSpend, input)
        if (replay) return replay
        const now = u64(this.nowUnixMillis(), 'nowUnixMillis')
        if (now > existingSpend.deadlineUnixMillis || existingSpend.remainingAttempts === 0) {
          const reason = now > existingSpend.deadlineUnixMillis
            ? TERMINAL_REASON.RESERVATION_EXPIRED
            : TERMINAL_REASON.ATTEMPTS_EXHAUSTED
          await this.#terminalReservation(existingSpend, reason)
          fail('RETRY_TERMINAL', 'the ingress reservation expired or exhausted its attempts')
        }
        return { status: 'reserved', entry: existingSpend }
      }
      const commitment = this.commitments.get(hex(input.requestCommitment))
      if (commitment) {
        if (commitment.fingerprint !== hex(input.fingerprint)) fail('CONFLICT', 'request commitment was reused with inconsistent fields')
        fail('SPEND_REPLAY', 'request commitment is already bound to another spend tag')
      }
      if (this.cells.has(hex(input.storageSlot))) fail('CONFLICT', 'cell slots are first-write-wins')
      this.#checkCreateQuota(CELL_SIZE_CLASS[input.sizeClass], input.profileId)
      const nowMillis = u64(this.nowUnixMillis(), 'nowUnixMillis')
      if (nowMillis > MAX_U64 - this.reservationMillis) fail('BUSY', 'reservation deadline space is exhausted')
      const deadlineUnixMillis = nowMillis + this.reservationMillis
      const transactionId = this.transactionStore.newTransactionId()
      const virtualBucket = this.transactionStore.virtualBucket(BLIND_STORE_SERVICE_TAG.CELL, input.storageSlot)
      await this.#appendAndApply(BLIND_CELL_WAL_TYPE.INGRESS_RESERVED, transactionId, virtualBucket, {
        version: 1,
        spendTag: input.spendTag,
        requestCommitment: input.requestCommitment,
        requestFingerprint: input.fingerprint,
        storageSlot: input.storageSlot,
        allocationEpoch: input.allocationEpoch,
        sizeClass: input.sizeClass,
        leaseClass: input.leaseClass,
        declaredBlobHash: input.declaredBlobHash,
        createPublicKey: input.createPublicKey,
        renewPublicKey: input.renewPublicKey,
        dropPublicKey: input.dropPublicKey,
        allocationCommitment: input.allocationCommitment,
        profileId: input.profileId,
        preparedAdmissionBytes: input.preparedAdmissionBytes,
        resultBindingBytes: input.resultBindingBytes,
        declaredBytes: CELL_SIZE_CLASS[input.sizeClass],
        deadlineUnixMillis,
        remainingAttempts: 2,
        reservedEpoch: this.epochFloor
      })
      return { status: 'reserved', entry: this.spends.get(hex(input.spendTag)) }
    })
  }

  async #consumeAttempt (input) {
    return this.transactionStore.withLocks([
      `spend:${hex(input.spendTag)}`,
      `cell:${hex(input.storageSlot)}`
    ], async () => {
      const entry = this.spends.get(hex(input.spendTag))
      const replay = this.#spendReplay(entry, input)
      if (replay) return replay
      if (entry.inFlight) fail('BUSY', 'an exact body attempt is already in flight', true)
      const now = u64(this.nowUnixMillis(), 'nowUnixMillis')
      if (now > entry.deadlineUnixMillis || entry.remainingAttempts === 0) {
        await this.#terminalReservation(entry, now > entry.deadlineUnixMillis
          ? TERMINAL_REASON.RESERVATION_EXPIRED
          : TERMINAL_REASON.ATTEMPTS_EXHAUSTED)
        fail('RETRY_TERMINAL', 'the ingress reservation expired or exhausted its attempts')
      }
      await this.#appendAndApply(BLIND_CELL_WAL_TYPE.ATTEMPT_CONSUMED, entry.transactionId,
        this.transactionStore.virtualBucket(BLIND_STORE_SERVICE_TAG.CELL, entry.storageSlot), {
          version: 1,
          spendTag: entry.spendTag,
          requestCommitment: entry.requestCommitment,
          remainingAttempts: entry.remainingAttempts - 1
        })
      entry.inFlight = true
      return { status: 'attempt', entry }
    })
  }

  async #terminalReservation (entry, reason) {
    await this.#appendAndApply(BLIND_CELL_WAL_TYPE.PUT_TERMINAL, entry.transactionId,
      this.transactionStore.virtualBucket(BLIND_STORE_SERVICE_TAG.CELL, entry.storageSlot), {
        version: 1,
        spendTag: entry.spendTag,
        requestCommitment: entry.requestCommitment,
        requestFingerprint: entry.requestFingerprint,
        terminalReason: reason,
        terminalEpoch: this.epochFloor
      })
  }

  async #sweepReservationBatch (limit) {
    limit = integer(limit, 1, 65536, 'reservation sweep limit')
    if (!this.reservationSweepIterator) this.reservationSweepIterator = this.spends.values()
    let scanned = 0
    let terminal = 0
    const now = u64(this.nowUnixMillis(), 'nowUnixMillis')
    while (scanned < limit) {
      const next = this.reservationSweepIterator.next()
      if (next.done) {
        this.reservationSweepIterator = null
        return { complete: true, scanned, terminal }
      }
      scanned++
      const entry = next.value
      if (entry.status !== 'reserved' || entry.inFlight || (now <= entry.deadlineUnixMillis && entry.remainingAttempts > 0)) continue
      await this.transactionStore.withLocks([
        `spend:${hex(entry.spendTag)}`,
        `cell:${hex(entry.storageSlot)}`
      ], async () => {
        if (entry.status !== 'reserved' || entry.inFlight) return
        const currentNow = u64(this.nowUnixMillis(), 'nowUnixMillis')
        if (currentNow <= entry.deadlineUnixMillis && entry.remainingAttempts > 0) return
        await this.#terminalReservation(entry, currentNow > entry.deadlineUnixMillis
          ? TERMINAL_REASON.RESERVATION_EXPIRED
          : TERMINAL_REASON.ATTEMPTS_EXHAUSTED)
        terminal++
      })
    }
    return { complete: false, scanned, terminal }
  }

  async #sweepAllRecoveredReservations () {
    while (true) {
      const result = await this.#sweepReservationBatch(4096)
      if (result.complete) return
      await new Promise(resolve => setImmediate(resolve))
    }
  }

  putCell (input) {
    return this.#runOperation(() => this.#putCell(input))
  }

  #leaseEpochFor (leaseClass) {
    const duration = LEASE_EPOCHS[leaseClass]
    if (this.epochFloor > MAX_U32 - duration) fail('BUSY', 'lease epoch space is exhausted', false)
    return this.epochFloor + duration
  }

  async #putCell (input) {
    this.#assertWritable(true)
    await this.#refreshClock()
    this.#assertWritable(true)
    input = this.#putInput(input)
    if (input.allocationEpoch > this.epochFloor + 1 || this.epochFloor >= input.allocationEpoch + RETENTION_HORIZON_EPOCHS) {
      fail('BAD_SLOT', 'allocation epoch is outside its accepted transport-capability window')
    }
    this.#leaseEpochFor(input.leaseClass)
    const reservation = await this.#reservePut(input)
    if (reservation.status === 'stored') return reservation
    const attempt = await this.#consumeAttempt(input)
    if (attempt.status === 'stored') return attempt
    const entry = attempt.entry
    let staged
    try {
      staged = await this.transactionStore.stageOpaque({
        source: input.source,
        expectedLength: entry.declaredBytes,
        expectedHash: entry.declaredBlobHash,
        deadlineUnixMillis: entry.deadlineUnixMillis,
        nowUnixMillis: this.nowUnixMillis,
        signal: input.request.signal
      })
    } catch (error) {
      if (error instanceof BlindOpaqueBodyError) {
        await this.transactionStore.withLocks([
          `spend:${hex(entry.spendTag)}`,
          `cell:${hex(entry.storageSlot)}`
        ], async () => {
          entry.inFlight = false
          if (error.terminal || entry.remainingAttempts === 0) {
            if (entry.status === 'reserved') {
              await this.#terminalReservation(entry,
                error.code === 'BODY_DEADLINE_EXPIRED'
                  ? TERMINAL_REASON.RESERVATION_EXPIRED
                  : error.terminal
                    ? TERMINAL_REASON.INVALID_BODY
                    : TERMINAL_REASON.ATTEMPTS_EXHAUSTED)
            }
          }
        })
        throw new BlindCellStorageError(
          error.terminal || entry.remainingAttempts === 0 ? 'RETRY_TERMINAL' : 'BUSY',
          error.message,
          !error.terminal && entry.remainingAttempts > 0
        )
      }
      await this.transactionStore.withLocks([
        `spend:${hex(entry.spendTag)}`,
        `cell:${hex(entry.storageSlot)}`
      ], async () => { entry.inFlight = false })
      this.readOnlyReason = 'AMBIGUOUS_STAGING_REQUIRES_RECOVERY'
      throw error
    }
    return this.transactionStore.withLocks([
      `spend:${hex(entry.spendTag)}`,
      `cell:${hex(entry.storageSlot)}`
    ], async () => {
      const current = this.spends.get(hex(entry.spendTag))
      const replay = this.#spendReplay(current, input)
      if (replay) {
        await this.transactionStore.discardStaged(staged)
        return replay
      }
      if (current !== entry || this.cells.has(hex(entry.storageSlot))) {
        entry.inFlight = false
        await this.transactionStore.discardStaged(staged)
        fail('BUSY', 'reservation changed before body publication', true)
      }
      const virtualBucket = this.transactionStore.virtualBucket(BLIND_STORE_SERVICE_TAG.CELL, entry.storageSlot)
      const leaseEpoch = this.#leaseEpochFor(entry.leaseClass)
      try {
        const reference = await this.transactionStore.publishOpaque(staged, virtualBucket)
        const identity = resultIdentity('stored', entry.storageSlot, entry.requestCommitment,
          entry.declaredBlobHash, entry.leaseClass, leaseEpoch, 0n)
        await this.#appendAndApply(BLIND_CELL_WAL_TYPE.PUT_COMMITTED, entry.transactionId, virtualBucket, {
          version: 1,
          spendTag: entry.spendTag,
          requestCommitment: entry.requestCommitment,
          requestFingerprint: entry.requestFingerprint,
          storageSlot: entry.storageSlot,
          blobObjectId: reference.objectId,
          leaseEpoch,
          stateRevision: 0n,
          policyRevision: 0n,
          resultBindingBytes: entry.resultBindingBytes,
          resultIdentity: identity,
          committedEpoch: this.epochFloor
        })
        return resultView(entry, 'stored', false)
      } catch (error) {
        entry.inFlight = false
        this.readOnlyReason = 'AMBIGUOUS_PUBLISH_REQUIRES_RECOVERY'
        throw error
      }
    })
  }

  readCell (storageSlot) {
    return this.#runOperation(() => this.#readCell(storageSlot))
  }

  async #readCell (storageSlot) {
    this.#assertOpen()
    storageSlot = fixed(storageSlot, 32, 'storageSlot', true)
    return this.transactionStore.withLocks([`cell:${hex(storageSlot)}`], async () => {
      const record = this.cells.get(hex(storageSlot))
      if (!publiclyVisible(record, this.epochFloor)) {
        fail('NOT_FOUND', 'cell is absent')
      }
      try {
        const cellBlob = await this.transactionStore.readOpaque(
          record.blobReference,
          CELL_SIZE_CLASS[record.sizeClass],
          record.cellBlobHash
        )
        return { sizeClass: record.sizeClass, cellBlob, cell: publicCell(record), receiptEpoch: this.epochFloor }
      } catch (error) {
        if (error instanceof BlindWalIntegrityError) {
          await this.#recordIntegrityFailures([this.#repairFailure(record, error.reason || 'HASH')])
          fail('NOT_FOUND', 'cell is absent')
        }
        throw error
      }
    })
  }

  readCells (storageSlots) {
    return this.#runOperation(() => this.#readCells(storageSlots))
  }

  async #readCells (storageSlots) {
    this.#assertOpen()
    if (!Array.isArray(storageSlots) || storageSlots.length < 1 || storageSlots.length > 64) {
      fail('BAD_ENCODING', 'readCells requires 1..64 storage slots')
    }
    const slots = storageSlots.map((slot, index) => fixed(slot, 32, `storageSlots[${index}]`, true))
    if (new Set(slots.map(hex)).size !== slots.length) fail('BAD_ENCODING', 'readCells storage slots must be distinct')
    const locked = await this.transactionStore.withLocks(slots.map(slot => `cell:${hex(slot)}`), async () => {
      const entries = []
      const failures = []
      for (const storageSlot of slots) {
        const record = this.cells.get(hex(storageSlot))
        if (!publiclyVisible(record, this.epochFloor)) {
          entries.push(null)
          continue
        }
        try {
          const cellBlob = await this.transactionStore.readOpaque(
            record.blobReference,
            CELL_SIZE_CLASS[record.sizeClass],
            record.cellBlobHash
          )
          entries.push({
            sizeClass: record.sizeClass,
            cellBlob,
            cell: publicCell(record),
            receiptEpoch: this.epochFloor
          })
        } catch (error) {
          if (!(error instanceof BlindWalIntegrityError)) throw error
          failures.push(this.#repairFailure(record, error.reason || 'HASH'))
          entries.push(null)
        }
      }
      return { entries, failures }
    })
    if (locked.failures.length > 0) await this.#recordIntegrityFailures(locked.failures)
    return locked.entries
  }

  inspectCellState (storageSlot) {
    return this.#runOperation(async () => {
      this.#assertOpen()
      storageSlot = fixed(storageSlot, 32, 'storageSlot', true)
      return this.transactionStore.withLocks([`cell:${hex(storageSlot)}`], async () => {
        const record = this.cells.get(hex(storageSlot))
        if (!record) return null
        return {
          publiclyVisible: publiclyVisible(record, this.epochFloor),
          cell: publicCell(record)
        }
      })
    })
  }

  inspectCellsState (storageSlots) {
    return this.#runOperation(async () => {
      this.#assertOpen()
      if (!Array.isArray(storageSlots) || storageSlots.length < 1 || storageSlots.length > 64) {
        fail('BAD_ENCODING', 'inspectCellsState requires 1..64 storage slots')
      }
      const slots = storageSlots.map((slot, index) => fixed(slot, 32, `storageSlots[${index}]`, true))
      if (new Set(slots.map(hex)).size !== slots.length) fail('BAD_ENCODING', 'storage slots must be distinct')
      return this.transactionStore.withLocks(slots.map(slot => `cell:${hex(slot)}`), async () => slots.map(storageSlot => {
        const record = this.cells.get(hex(storageSlot))
        return record == null
          ? null
          : { publiclyVisible: publiclyVisible(record, this.epochFloor), cell: publicCell(record) }
      }))
    })
  }

  #chargedReadInput (input) {
    if (!input || (input.operationId !== OPERATION.CELL.GET && input.operationId !== OPERATION.CELL.PROVE &&
        input.operationId !== OPERATION.CELL.BATCH_GET) || !input.request || !input.preparedAdmission) {
      fail('BAD_ENCODING', 'chargedCellRead requires GET, PROVE, or BATCH_GET authority')
    }
    const storageSlots = input.operationId === OPERATION.CELL.BATCH_GET
      ? input.request.slots
      : [input.request.storageSlot]
    if (!Array.isArray(storageSlots) || storageSlots.length < 1 || storageSlots.length > 64) {
      fail('BAD_ENCODING', 'charged CELL read has an invalid slot set')
    }
    const slots = storageSlots.map((slot, index) => fixed(slot, 32, `storageSlots[${index}]`, true))
    if (new Set(slots.map(hex)).size !== slots.length) fail('BAD_ENCODING', 'charged CELL read slots must be distinct')
    const requestCommitment = fixed(input.requestCommitment, 32, 'requestCommitment', true)
    const preparedAdmission = this.#preparedAdmission(input.preparedAdmission)
    if (!equal(preparedAdmission.value.requestCommitment, requestCommitment)) {
      fail('SPEND_INVALID', 'prepared admission binds another charged read')
    }
    const resultBindingBytes = this.#resultBindingBytes(input.resultBinding)
    if (!resultBindingBytes) fail('BAD_ENCODING', 'charged CELL read requires a result binding pin')
    const fingerprint = requestFingerprint([
      b4a.from([input.operationId]),
      preparedAdmission.value.spendTag,
      requestCommitment,
      blake2b256(preparedAdmission.canonicalBytes)
    ])
    return {
      operationId: input.operationId,
      request: input.request,
      slots,
      requestCommitment,
      spendTag: preparedAdmission.value.spendTag,
      preparedAdmissionBytes: preparedAdmission.canonicalBytes,
      resultBindingBytes,
      fingerprint
    }
  }

  #verifyChargedReadCost (operationId, preparedAdmission, entries, resultBindingBytes) {
    const expectedResourceClass = operationId === OPERATION.CELL.BATCH_GET
      ? chargedResultBand(chargedBatchResultBytes(resultBindingBytes, entries))
      : entries[0].present === 0 ? 1 : entries[0].sizeClass
    if (preparedAdmission.resourceClass !== expectedResourceClass || preparedAdmission.leaseClass !== 0) {
      fail('SPEND_INVALID', 'prepared admission cost does not match the pinned charged read')
    }
  }

  #chargedReadSourcesMatch (entry, exact) {
    for (const pinned of entry.entries) {
      const record = this.cells.get(hex(pinned.storageSlot))
      if (exact) {
        const current = chargedReadPinEntry(pinned.storageSlot, record, this.epochFloor)
        if (!equal(encodeCanonical(chargedReadPinEntryV1, current),
          encodeCanonical(chargedReadPinEntryV1, pinned))) return false
        continue
      }
      if (pinned.present === 0) continue
      if (!publiclyVisible(record, this.epochFloor) || record.sizeClass !== pinned.sizeClass ||
          record.policyRevision !== pinned.policyRevision ||
          !equal(record.cellBlobHash, pinned.cellBlobHash) ||
          !equal(record.allocationCommitment, pinned.allocationCommitment)) return false
    }
    return true
  }

  #newChargedReadPin (authority) {
    const entries = authority.slots.map(storageSlot => chargedReadPinEntry(
      storageSlot,
      this.cells.get(hex(storageSlot)),
      this.epochFloor
    ))
    if (authority.operationId !== OPERATION.CELL.BATCH_GET && entries[0].present !== 1) {
      fail('NOT_FOUND', 'cell is absent')
    }
    const preparedAdmission = decodeCanonical(blindPreparedAdmissionStoreV1,
      authority.preparedAdmissionBytes, { copyBytes: true })
    this.#verifyChargedReadCost(authority.operationId, preparedAdmission, entries,
      authority.resultBindingBytes)
    const now = u64(this.nowUnixMillis(), 'nowUnixMillis')
    if (now > MAX_U64 - MAX_RESERVATION_MILLIS) {
      fail('BUSY', 'charged read retry deadline space is exhausted')
    }
    return {
      version: 1,
      operationId: authority.operationId,
      spendTag: authority.spendTag,
      requestCommitment: authority.requestCommitment,
      requestFingerprint: authority.fingerprint,
      preparedAdmissionBytes: authority.preparedAdmissionBytes,
      resultBindingBytes: authority.resultBindingBytes,
      receiptEpoch: this.epochFloor,
      retryExpiresUnixMillis: now + MAX_RESERVATION_MILLIS,
      entries,
      committedEpoch: this.epochFloor
    }
  }

  #checkChargedReadControlCapacity (value) {
    const payloadBytes = encodeCanonical(chargedReadPinCommittedV1, value).byteLength
    const controlBytes = payloadBytes + CHARGED_READ_FINALIZATION_CONTROL_BYTES
    if (payloadBytes > MAX_CHARGED_READ_PIN_CONTROL_BYTES ||
        this.accounting.controlBytes + controlBytes > this.quota.maxControlBytes) {
      fail('BUSY', 'charged read retry-pin control quota is full', true)
    }
    return payloadBytes
  }

  chargedCellReadState (input) {
    return this.#runOperation(async () => {
      this.#assertOpen()
      const authority = this.#chargedReadInput(input)
      return this.transactionStore.withLocks([`spend:${hex(authority.spendTag)}`], async () => {
        const entry = this.spends.get(hex(authority.spendTag))
        if (!entry) return { kind: 'fresh' }
        if (!equal(entry.requestCommitment, authority.requestCommitment)) {
          fail('SPEND_REPLAY', 'charged read spend is committed to another request')
        }
        if (!equal(entry.requestFingerprint, authority.fingerprint) ||
            entry.operation !== `read-${authority.operationId}`) {
          fail('CONFLICT', 'charged read retry fields conflict with the committed spend')
        }
        if (entry.status === 'read-finalized') {
          if (u64(this.nowUnixMillis(), 'nowUnixMillis') >= entry.retryExpiresUnixMillis) {
            fail('RETRY_TERMINAL', 'charged read retry pin expired')
          }
          return { kind: 'replay' }
        }
        if (entry.status === 'read-pinned') {
          if (u64(this.nowUnixMillis(), 'nowUnixMillis') >= entry.retryExpiresUnixMillis) {
            fail('RETRY_TERMINAL', 'charged read retry pin expired')
          }
          return { kind: 'resumable' }
        }
        fail('RETRY_TERMINAL', 'charged read spend is terminal')
      })
    })
  }

  chargedCellRead (input) {
    return this.#runOperation(() => this.#chargedCellRead(input))
  }

  async #chargedCellRead (input) {
    this.#assertWritable(false)
    const authority = this.#chargedReadInput(input)
    const lockKeys = [`spend:${hex(authority.spendTag)}`,
      ...authority.slots.map(slot => `cell:${hex(slot)}`)]
    return this.transactionStore.withLocks(lockKeys, async () => {
      let entry = this.spends.get(hex(authority.spendTag))
      if (entry) {
        if (!equal(entry.requestCommitment, authority.requestCommitment)) {
          fail('SPEND_REPLAY', 'charged read spend is committed to another request')
        }
        if (!equal(entry.requestFingerprint, authority.fingerprint) ||
            entry.operation !== `read-${authority.operationId}`) {
          fail('CONFLICT', 'charged read retry fields conflict with the committed spend')
        }
        return this.#materializeChargedRead(entry)
      }
      const priorCommitment = this.commitments.get(hex(authority.requestCommitment))
      if (priorCommitment) {
        fail(priorCommitment.fingerprint === hex(authority.fingerprint) ? 'SPEND_REPLAY' : 'CONFLICT',
          'charged read request commitment is already used')
      }
      const value = this.#newChargedReadPin(authority)
      this.#checkChargedReadControlCapacity(value)
      await this.#appendAndApply(BLIND_CELL_WAL_TYPE.READ_PIN_COMMITTED,
        this.transactionStore.newTransactionId(), 0, value)
      entry = this.spends.get(hex(authority.spendTag))
      return this.#materializeChargedRead(entry)
    })
  }

  async #materializeChargedRead (entry) {
    if (!entry || (entry.status !== 'read-pinned' && entry.status !== 'read-finalized')) {
      fail('RETRY_TERMINAL', 'charged read retry pin is not live')
    }
    const now = u64(this.nowUnixMillis(), 'nowUnixMillis')
    if (now >= entry.retryExpiresUnixMillis) fail('RETRY_TERMINAL', 'charged read retry pin expired')
    const entries = []
    for (const pinned of entry.entries) {
      if (pinned.present === 0) {
        entries.push({ status: 0, pin: cloneChargedReadPinEntry(pinned) })
        continue
      }
      const record = this.cells.get(hex(pinned.storageSlot))
      if (!this.#chargedReadSourcesMatch({ entries: [pinned] }, false)) {
        fail('RETRY_TERMINAL', 'charged read source visibility was revoked')
      }
      let cellBlob
      try {
        cellBlob = await this.transactionStore.readOpaque(
          record.blobReference,
          CELL_SIZE_CLASS[pinned.sizeClass],
          pinned.cellBlobHash
        )
      } catch (error) {
        if (error instanceof BlindWalIntegrityError) {
          await this.#recordIntegrityFailures([this.#repairFailure(record, error.reason || 'HASH')])
          fail('RETRY_TERMINAL', 'charged read source integrity failed')
        }
        throw error
      }
      entries.push({
        status: 1,
        sizeClass: pinned.sizeClass,
        cellBlob,
        pin: cloneChargedReadPinEntry(pinned)
      })
    }
    return {
      replay: entry.status === 'read-finalized',
      needsFinalize: entry.status === 'read-pinned',
      spendTag: b4a.from(entry.spendTag),
      requestCommitment: b4a.from(entry.requestCommitment),
      resultBindingBytes: b4a.from(entry.resultBindingBytes),
      receiptEpoch: entry.receiptEpoch,
      entries,
      resultCommitment: cloneBytes(entry.resultCommitment)
    }
  }

  finalizeChargedCellRead (input) {
    return this.#runOperation(async () => {
      this.#assertWritable(false)
      if (!input || typeof input !== 'object') fail('BAD_ENCODING', 'charged read finalization is required')
      const spendTag = fixed(input.spendTag, 32, 'spendTag', true)
      const requestCommitment = fixed(input.requestCommitment, 32, 'requestCommitment', true)
      const resultCommitment = fixed(input.resultCommitment, 32, 'resultCommitment', true)
      const initial = this.spends.get(hex(spendTag))
      if (!initial || !Array.isArray(initial.entries)) {
        fail('RETRY_TERMINAL', 'charged read finalization has no matching live pin')
      }
      const lockKeys = [
        `spend:${hex(spendTag)}`,
        ...initial.entries.map(entry => `cell:${hex(entry.storageSlot)}`)
      ]
      return this.transactionStore.withLocks(lockKeys, async () => {
        const entry = this.spends.get(hex(spendTag))
        if (!entry || (entry.status !== 'read-pinned' && entry.status !== 'read-finalized') ||
            !equal(entry.requestCommitment, requestCommitment)) {
          fail('RETRY_TERMINAL', 'charged read finalization has no matching live pin')
        }
        if (!Array.isArray(entry.entries) || entry.entries.length !== initial.entries.length ||
            entry.entries.some((value, index) => !equal(value.storageSlot, initial.entries[index].storageSlot))) {
          fail('RETRY_TERMINAL', 'charged read finalization pin changed before lock acquisition')
        }
        if (entry.status === 'read-finalized') {
          if (!equal(entry.resultCommitment, resultCommitment)) {
            fail('INTERNAL', 'charged read reconstruction changed after finalization')
          }
          if (!this.#chargedReadSourcesMatch(entry, false)) {
            fail('NOT_FOUND', 'charged read source visibility was revoked before replay authorization')
          }
          return { replay: true, resultCommitment: b4a.from(entry.resultCommitment) }
        }
        if (u64(this.nowUnixMillis(), 'nowUnixMillis') >= entry.retryExpiresUnixMillis) {
          fail('RETRY_TERMINAL', 'charged read retry pin expired before finalization')
        }
        if (!this.#chargedReadSourcesMatch(entry, true)) {
          fail('NOT_FOUND', 'charged read source changed before result finalization')
        }
        const value = {
          version: 1,
          spendTag,
          requestCommitment,
          resultCommitment,
          finalizedEpoch: this.epochFloor
        }
        await this.#appendAndApply(BLIND_CELL_WAL_TYPE.READ_PIN_FINALIZED,
          entry.transactionId, 0, value)
        return { replay: false, resultCommitment: b4a.from(resultCommitment) }
      })
    })
  }

  sweepExpiredChargedReadPins (limit = 4096) {
    return this.#runOperation(async () => {
      const result = await this.#sweepExpiredChargedReadPins(limit)
      if (result.moreDue) this.#scheduleChargedReadSweep()
      return result.expired
    })
  }

  async #sweepExpiredChargedReadPins (limit) {
    this.#assertWritable(false)
    limit = integer(limit, 1, 65536, 'charged read sweep limit')
    const now = u64(this.nowUnixMillis(), 'nowUnixMillis')
    let expired = 0
    let scanned = 0
    while (scanned < limit && this.chargedReadExpiryHeap.length > 0 &&
        this.chargedReadExpiryHeap[0].retryExpiresUnixMillis <= now) {
      const candidate = popExpiry(this.chargedReadExpiryHeap)
      scanned++
      await this.transactionStore.withLocks([`spend:${candidate.spendKey}`], async () => {
        const entry = this.spends.get(candidate.spendKey)
        if (!entry || (entry.status !== 'read-pinned' && entry.status !== 'read-finalized') ||
            hex(entry.transactionId) !== candidate.transactionId ||
            entry.retryExpiresUnixMillis !== candidate.retryExpiresUnixMillis ||
            entry.retryExpiresUnixMillis > now) return
        await this.#appendAndApply(BLIND_CELL_WAL_TYPE.READ_PIN_EXPIRED,
          entry.transactionId, 0, {
            version: 1,
            spendTag: entry.spendTag,
            requestCommitment: entry.requestCommitment,
            retryExpiresUnixMillis: entry.retryExpiresUnixMillis,
            observedUnixMillis: now,
            terminalEpoch: this.epochFloor
          })
        expired++
      })
    }
    return {
      expired,
      moreDue: this.chargedReadExpiryHeap.length > 0 &&
        this.chargedReadExpiryHeap[0].retryExpiresUnixMillis <= now
    }
  }

  #scheduleChargedReadSweep () {
    if (this.chargedReadSweepTimer || this.closing) return
    this.chargedReadSweepTimer = setTimeout(() => {
      this.chargedReadSweepTimer = null
      this.#runOperation(() => this.#sweepExpiredChargedReadPins(4096))
        .then(result => { if (result.moreDue) this.#scheduleChargedReadSweep() })
        .catch(() => { this.readOnlyReason = this.readOnlyReason || 'CHARGED_READ_SWEEP_FAILED' })
    }, 0)
    if (typeof this.chargedReadSweepTimer.unref === 'function') this.chargedReadSweepTimer.unref()
  }

  verifyCellManagementCapability (input) {
    return this.#runOperation(async () => {
      this.#assertOpen()
      if (!input || (input.operationId !== OPERATION.CELL.RENEW && input.operationId !== OPERATION.CELL.DROP)) {
        fail('BAD_ENCODING', 'management capability requires CELL.RENEW or CELL.DROP')
      }
      const storageSlot = fixed(input.storageSlot, 32, 'storageSlot', true)
      const requestCommitment = fixed(input.requestCommitment, 32, 'requestCommitment', true)
      const signature = fixed(input.signature, 64, 'signature')
      return this.transactionStore.withLocks([`cell:${hex(storageSlot)}`], async () => {
        const record = this.cells.get(hex(storageSlot))
        if (!record) fail('NOT_FOUND', 'cell management record is absent')
        const publicKey = input.operationId === OPERATION.CELL.RENEW
          ? record.renewPublicKey
          : record.dropPublicKey
        return verifyEd25519(publicKey, requestCommitment, signature)
      })
    })
  }

  preparedCellOperationState (input) {
    return this.#runOperation(async () => {
      this.#assertOpen()
      if (!input || !input.preparedAdmission ||
          (input.operationId !== OPERATION.CELL.PUT && input.operationId !== OPERATION.CELL.RENEW)) {
        fail('BAD_ENCODING', 'prepared operation state requires admitted CELL.PUT or CELL.RENEW')
      }
      const spendTag = fixed(input.preparedAdmission.spendTag, 32, 'spendTag', true)
      const requestCommitment = fixed(input.requestCommitment, 32, 'requestCommitment', true)
      return this.transactionStore.withLocks([`spend:${hex(spendTag)}`], async () => {
        const entry = this.spends.get(hex(spendTag))
        if (!entry) return { kind: 'fresh' }
        if (!equal(entry.requestCommitment, requestCommitment)) return { kind: 'conflict' }
        if (entry.status === 'terminal') return { kind: 'terminal' }
        const expectedOperation = input.operationId === OPERATION.CELL.PUT ? null : 'renew'
        const actualOperation = entry.operation == null ? null : entry.operation
        if (actualOperation !== expectedOperation) return { kind: 'conflict' }
        if (entry.status === 'committed') return { kind: 'replay' }
        return { kind: 'resumable' }
      })
    })
  }

  cellRequestResultState (requestCommitment) {
    return this.#runOperation(async () => {
      this.#assertOpen()
      requestCommitment = fixed(requestCommitment, 32, 'requestCommitment', true)
      return this.transactionStore.withLocks([`result:${hex(requestCommitment)}`], async () => ({
        kind: this.requestResults.has(hex(requestCommitment)) ? 'replay' : 'fresh'
      }))
    })
  }

  checkCellCapacity (input) {
    return this.#runOperation(async () => {
      this.#assertOpen()
      if (!input || !Number.isInteger(input.operationId)) fail('BAD_ENCODING', 'cell capacity input is invalid')
      if (this.readOnlyReason) fail('INTERNAL', `store is read-only: ${this.readOnlyReason}`)
      if ((input.operationId === OPERATION.CELL.PUT || input.operationId === OPERATION.CELL.RENEW) && this.clockUnsafe) {
        fail('BUSY', 'store clock is unsafe', true)
      }
      if (input.operationId === OPERATION.CELL.PUT || input.operationId === OPERATION.CELL.RENEW) {
        const disposition = await this.preparedCellOperationState(input)
        if (disposition.kind !== 'fresh') return true
      }
      if (input.operationId === OPERATION.CELL.PUT) {
        const sizeClass = integer(input.request.sizeClass, 1, 5, 'sizeClass')
        const profileId = integer(input.preparedAdmission.profileId, 1, 0xffff, 'profileId')
        this.#checkCreateQuota(CELL_SIZE_CLASS[sizeClass], profileId)
      } else if (input.operationId === OPERATION.CELL.RENEW &&
          this.accounting.controlBytes + CONTROL_RECORD_BYTES > this.quota.maxControlBytes) {
        fail('BUSY', 'control-record quota is full', true)
      } else if ((input.operationId === OPERATION.CELL.GET || input.operationId === OPERATION.CELL.PROVE ||
          input.operationId === OPERATION.CELL.BATCH_GET) && input.preparedAdmission) {
        const authority = this.#chargedReadInput(input)
        await this.transactionStore.withLocks([
          `spend:${hex(authority.spendTag)}`,
          ...authority.slots.map(slot => `cell:${hex(slot)}`)
        ], async () => {
          const existing = this.spends.get(hex(authority.spendTag))
          if (existing) return
          const value = this.#newChargedReadPin(authority)
          this.#checkChargedReadControlCapacity(value)
        })
      }
      return true
    })
  }

  #managementRecord (storageSlot) {
    const record = this.cells.get(hex(storageSlot))
    if (!record) fail('NOT_FOUND', 'cell management record is absent')
    return record
  }

  renewCell (input) {
    return this.#runOperation(() => this.#renewCell(input))
  }

  async #renewCell (input) {
    this.#assertWritable(true)
    await this.#refreshClock()
    this.#assertWritable(true)
    if (!input || !input.request || !input.preparedAdmission) fail('BAD_ENCODING', 'renewCell requires request and preparedAdmission')
    const request = input.request
    const resultBindingBytes = this.#resultBindingBytes(input.resultBinding)
    const storageSlot = fixed(request.storageSlot, 32, 'storageSlot', true)
    const expectedRevision = u64(request.expectedRevision, 'expectedRevision')
    const expectedLeaseEpoch = integer(request.expectedLeaseEpoch, 0, 0xffffffff, 'expectedLeaseEpoch')
    const leaseClass = integer(request.leaseClass, 1, 4, 'leaseClass')
    const clientNonce = fixed(request.clientNonce, 32, 'clientNonce')
    const commitment = cellManageRequestCommitment({
      operation: 'cell-renew',
      relayPublicKey: this.relayPublicKey,
      storageSlot,
      expectedRevision,
      expectedLeaseEpoch,
      requestedLeaseClass: leaseClass,
      clientNonce
    })
    const preparedAdmission = this.#preparedAdmission(input.preparedAdmission)
    const spendTag = preparedAdmission.value.spendTag
    if (!equal(commitment, preparedAdmission.value.requestCommitment)) {
      fail('SPEND_INVALID', 'prepared admission binds another request')
    }
    const profileId = preparedAdmission.value.profileId
    const fingerprint = requestFingerprint([
      spendTag, commitment, storageSlot, u64bytes(expectedRevision), u32bytes(expectedLeaseEpoch),
      b4a.from([leaseClass]), u32bytes(profileId), blake2b256(preparedAdmission.canonicalBytes)
    ])
    return this.transactionStore.withLocks([
      `spend:${hex(spendTag)}`,
      `cell:${hex(storageSlot)}`
    ], async () => {
      const record = this.#managementRecord(storageSlot)
      if (!verifyEd25519(record.renewPublicKey, commitment, request.signature)) {
        fail('BAD_MANAGEMENT_SIG', 'cell renew signature is invalid')
      }
      const existing = this.spends.get(hex(spendTag))
      if (existing) {
        if (!equal(existing.requestCommitment, commitment)) fail('SPEND_REPLAY', 'spend tag is committed to another request')
        if (!equal(existing.requestFingerprint, fingerprint)) fail('CONFLICT', 'renew request fields conflict')
        if (existing.status !== 'committed' || existing.operation !== 'renew') fail('RETRY_TERMINAL', 'renew retry is terminal')
        const current = this.cells.get(hex(storageSlot))
        if (!current || current.objectState !== OBJECT_STATE.PRESENT || current.policyState !== POLICY_STATE.VISIBLE ||
            this.epochFloor > current.leaseEpoch + EXPIRY_GRACE_EPOCHS) {
          fail('RETRY_TERMINAL', 'renew result visibility was revoked by a terminal cell transition')
        }
        return resultView(existing, 'renewed', true)
      }
      const priorCommitment = this.commitments.get(hex(commitment))
      if (priorCommitment) fail(priorCommitment.fingerprint === hex(fingerprint) ? 'SPEND_REPLAY' : 'CONFLICT', 'renew commitment is already used')
      if (record.objectState !== OBJECT_STATE.PRESENT ||
          this.epochFloor > record.leaseEpoch + EXPIRY_GRACE_EPOCHS) {
        fail('NOT_FOUND', 'cell is not renewable')
      }
      if (record.stateRevision !== expectedRevision || record.leaseEpoch !== expectedLeaseEpoch) {
        fail('STALE_REVISION', 'cell renew CAS is stale')
      }
      const targetLeaseEpoch = Math.max(record.leaseEpoch, this.epochFloor + LEASE_EPOCHS[leaseClass])
      this.#leaseEpochFor(leaseClass)
      if (targetLeaseEpoch === record.leaseEpoch) {
        renewNotDue(Math.max(this.epochFloor + 1, record.leaseEpoch - LEASE_EPOCHS[leaseClass] + 1))
      }
      if (this.accounting.controlBytes + CONTROL_RECORD_BYTES > this.quota.maxControlBytes) fail('BUSY', 'control-record quota is full', true)
      if (record.stateRevision === MAX_U64) fail('BUSY', 'cell state revision space is exhausted')
      const newRevision = record.stateRevision + 1n
      const identity = resultIdentity('renewed', storageSlot, commitment, record.cellBlobHash,
        leaseClass, targetLeaseEpoch, newRevision)
      await this.#appendAndApply(BLIND_CELL_WAL_TYPE.RENEW_COMMITTED, this.transactionStore.newTransactionId(),
        this.transactionStore.virtualBucket(BLIND_STORE_SERVICE_TAG.CELL, storageSlot), {
          version: 1,
          spendTag,
          requestCommitment: commitment,
          requestFingerprint: fingerprint,
          storageSlot,
          profileId,
          oldStateRevision: record.stateRevision,
          newStateRevision: newRevision,
          oldLeaseEpoch: record.leaseEpoch,
          newLeaseEpoch: targetLeaseEpoch,
          leaseClass,
          preparedAdmissionBytes: preparedAdmission.canonicalBytes,
          resultBindingBytes,
          resultIdentity: identity,
          committedEpoch: this.epochFloor
        })
      return resultView(this.spends.get(hex(spendTag)), 'renewed', false)
    })
  }

  dropCell (request) {
    return this.#runOperation(() => this.#dropCell(request))
  }

  async #dropCell (request) {
    this.#assertWritable(false)
    if (!request || typeof request !== 'object') fail('BAD_ENCODING', 'dropCell requires a request')
    const operationInput = request.request == null ? { request, resultBinding: null } : request
    request = operationInput.request
    const resultBindingBytes = this.#resultBindingBytes(operationInput.resultBinding)
    const storageSlot = fixed(request.storageSlot, 32, 'storageSlot', true)
    const expectedRevision = u64(request.expectedRevision, 'expectedRevision')
    const expectedLeaseEpoch = integer(request.expectedLeaseEpoch, 0, 0xffffffff, 'expectedLeaseEpoch')
    const clientNonce = fixed(request.clientNonce, 32, 'clientNonce')
    const commitment = cellManageRequestCommitment({
      operation: 'cell-drop',
      relayPublicKey: this.relayPublicKey,
      storageSlot,
      expectedRevision,
      expectedLeaseEpoch,
      requestedLeaseClass: 0,
      clientNonce
    })
    const fingerprint = requestFingerprint([commitment, storageSlot, u64bytes(expectedRevision), u32bytes(expectedLeaseEpoch)])
    return this.transactionStore.withLocks([`cell:${hex(storageSlot)}`], async () => {
      const record = this.#managementRecord(storageSlot)
      if (!verifyEd25519(record.dropPublicKey, commitment, request.signature)) {
        fail('BAD_MANAGEMENT_SIG', 'cell drop signature is invalid')
      }
      const existing = this.requestResults.get(hex(commitment))
      if (existing) {
        if (!equal(existing.requestFingerprint, fingerprint)) fail('CONFLICT', 'drop request fields conflict')
        return resultView(existing, 'dropped', true)
      }
      if (record.objectState !== OBJECT_STATE.PRESENT) fail('NOT_FOUND', 'cell is not droppable')
      if (record.stateRevision !== expectedRevision || record.leaseEpoch !== expectedLeaseEpoch) {
        fail('STALE_REVISION', 'cell drop CAS is stale')
      }
      if (record.stateRevision === MAX_U64) fail('BUSY', 'cell state revision space is exhausted')
      const newRevision = record.stateRevision + 1n
      const identity = resultIdentity('dropped', storageSlot, commitment, record.cellBlobHash, 0,
        record.leaseEpoch, newRevision)
      const oldReference = record.blobReference
      await this.#appendAndApply(BLIND_CELL_WAL_TYPE.DROP_COMMITTED, this.transactionStore.newTransactionId(),
        this.transactionStore.virtualBucket(BLIND_STORE_SERVICE_TAG.CELL, storageSlot), {
          version: 1,
          requestCommitment: commitment,
          requestFingerprint: fingerprint,
          storageSlot,
          oldStateRevision: record.stateRevision,
          newStateRevision: newRevision,
          oldLeaseEpoch: record.leaseEpoch,
          resultBindingBytes,
          resultIdentity: identity,
          committedEpoch: this.epochFloor
        })
      await this.transactionStore.removeOpaque(oldReference).catch(() => {})
      return resultView(this.requestResults.get(hex(commitment)), 'dropped', false)
    })
  }

  setPolicy (storageSlot, expectedPolicyRevision, suppress) {
    return this.#runOperation(() => this.#setPolicy(storageSlot, expectedPolicyRevision, suppress))
  }

  async #setPolicy (storageSlot, expectedPolicyRevision, suppress) {
    this.#assertWritable(false)
    storageSlot = fixed(storageSlot, 32, 'storageSlot', true)
    expectedPolicyRevision = u64(expectedPolicyRevision, 'expectedPolicyRevision')
    if (typeof suppress !== 'boolean') fail('BAD_ENCODING', 'suppress must be boolean')
    return this.transactionStore.withLocks([`cell:${hex(storageSlot)}`], async () => {
      const record = this.#managementRecord(storageSlot)
      if (record.objectState !== OBJECT_STATE.PRESENT) fail('NOT_FOUND', 'cell is not policy mutable')
      if (record.policyRevision !== expectedPolicyRevision) fail('STALE_REVISION', 'policy CAS is stale')
      const policyState = suppress ? POLICY_STATE.SUPPRESSED : POLICY_STATE.VISIBLE
      if (record.policyState === policyState) fail('CONFLICT', 'cell already has the requested policy state')
      if (record.policyRevision === MAX_U64) fail('BUSY', 'cell policy revision space is exhausted')
      await this.#appendAndApply(BLIND_CELL_WAL_TYPE.POLICY_COMMITTED, this.transactionStore.newTransactionId(),
        this.transactionStore.virtualBucket(BLIND_STORE_SERVICE_TAG.CELL, storageSlot), {
          version: 1,
          storageSlot,
          oldPolicyRevision: record.policyRevision,
          newPolicyRevision: record.policyRevision + 1n,
          policyState,
          committedEpoch: this.epochFloor
        })
      return publicCell(record)
    })
  }

  refreshClock () {
    return this.#runOperation(() => this.#refreshClock())
  }

  async #refreshClock () {
    this.#assertOpen()
    if (this.readOnlyReason) return { state: 'READ_ONLY', epochFloor: this.epochFloor }
    const observedEpoch = nowEpochFromMillis(this.nowUnixMillis())
    return this.transactionStore.withLocks(['clock'], async () => {
      if (this.clockUnsafe) return { state: 'CLOCK_UNSAFE', epochFloor: this.epochFloor }
      if (observedEpoch === this.epochFloor) return { state: 'READY', epochFloor: this.epochFloor }
      if (observedEpoch < this.epochFloor || observedEpoch > this.epochFloor + CLOCK_MAX_JUMP_EPOCHS) {
        await this.#appendAndApply(BLIND_CELL_WAL_TYPE.CLOCK_UNSAFE, this.transactionStore.newTransactionId(), 0, {
          version: 1,
          epochFloor: this.epochFloor,
          observedEpoch,
          direction: observedEpoch < this.epochFloor ? 1 : 2
        })
        return { state: 'CLOCK_UNSAFE', epochFloor: this.epochFloor }
      }
      await this.#appendAndApply(BLIND_CELL_WAL_TYPE.FLOOR_ADVANCE, this.transactionStore.newTransactionId(), 0, {
        version: 1,
        oldEpochFloor: this.epochFloor,
        newEpochFloor: observedEpoch
      })
      return { state: 'READY', epochFloor: this.epochFloor }
    })
  }

  confirmClock (confirmedEpoch) {
    return this.#runOperation(() => this.#confirmClock(confirmedEpoch))
  }

  async #confirmClock (confirmedEpoch) {
    this.#assertWritable(false)
    confirmedEpoch = integer(confirmedEpoch, 0, 0xffffffff, 'confirmedEpoch')
    if (confirmedEpoch < this.epochFloor) fail('BAD_ENCODING', 'confirmed clock cannot roll the epoch floor backward')
    return this.transactionStore.withLocks(['clock'], async () => {
      await this.#appendAndApply(BLIND_CELL_WAL_TYPE.CLOCK_CONFIRM, this.transactionStore.newTransactionId(), 0, {
        version: 1,
        oldEpochFloor: this.epochFloor,
        newEpochFloor: confirmedEpoch
      })
      return { state: 'READY', epochFloor: this.epochFloor }
    })
  }

  gc (limit = 256) {
    return this.#runOperation(() => this.#gc(limit))
  }

  async #gc (limit = 256) {
    this.#assertWritable(true)
    await this.#refreshClock()
    this.#assertWritable(true)
    limit = integer(limit, 1, 4096, 'GC limit')
    let collected = 0
    for (const candidate of this.cells.values()) {
      if (collected >= limit) break
      if (candidate.objectState !== OBJECT_STATE.PRESENT || this.epochFloor <= candidate.leaseEpoch + EXPIRY_GRACE_EPOCHS) continue
      await this.transactionStore.withLocks([`cell:${hex(candidate.storageSlot)}`], async () => {
        const record = this.cells.get(hex(candidate.storageSlot))
        if (!record || record !== candidate || record.objectState !== OBJECT_STATE.PRESENT ||
            this.epochFloor <= record.leaseEpoch + EXPIRY_GRACE_EPOCHS) return
        if (record.stateRevision === MAX_U64) {
          this.readOnlyReason = 'STATE_REVISION_EXHAUSTED'
          return
        }
        const reference = record.blobReference
        await this.#appendAndApply(BLIND_CELL_WAL_TYPE.GC_COMMITTED, this.transactionStore.newTransactionId(),
          this.transactionStore.virtualBucket(BLIND_STORE_SERVICE_TAG.CELL, record.storageSlot), {
            version: 1,
            storageSlot: record.storageSlot,
            oldStateRevision: record.stateRevision,
            newStateRevision: record.stateRevision + 1n,
            expectedLeaseEpoch: record.leaseEpoch,
            tombstoneEpoch: this.epochFloor
          })
        await this.transactionStore.removeOpaque(reference).catch(() => {})
        collected++
      })
    }
    return collected
  }

  compact (limit = 1024) {
    return this.#runOperation(() => this.#compact(limit))
  }

  async #compact (limit = 1024) {
    this.#assertWritable(false)
    limit = integer(limit, 1, 4096, 'compaction limit')
    const candidates = []
    for (const [key, record] of this.cells) {
      if (candidates.length >= limit) break
      if (record.objectState === OBJECT_STATE.TOMBSTONE && record.terminalEpoch != null &&
          this.epochFloor - record.terminalEpoch > RETENTION_HORIZON_EPOCHS) {
        candidates.push({ kind: COMPACT_KIND.CELL, key })
      }
    }
    for (const [key, entry] of this.spends) {
      if (candidates.length >= limit) break
      const ageEpoch = entry.terminalEpoch == null ? entry.committedEpoch : entry.terminalEpoch
      if (ageEpoch != null && this.epochFloor - ageEpoch > RETENTION_HORIZON_EPOCHS) {
        candidates.push({ kind: COMPACT_KIND.SPEND, key })
      }
    }
    for (const [key, entry] of this.requestResults) {
      if (candidates.length >= limit) break
      if (this.epochFloor - entry.committedEpoch > RETENTION_HORIZON_EPOCHS) {
        candidates.push({ kind: COMPACT_KIND.REQUEST_RESULT, key })
      }
    }
    let compacted = 0
    for (const candidate of candidates) {
      await this.#appendAndApply(BLIND_CELL_WAL_TYPE.COMPACT, this.transactionStore.newTransactionId(), 0, {
        version: 1,
        entryKind: candidate.kind,
        key: b4a.from(candidate.key, 'hex'),
        compactedEpoch: this.epochFloor
      })
      compacted++
    }
    return compacted
  }

  #liveReferenceKeys () {
    const references = new Set()
    for (const record of this.cells.values()) {
      if (record.objectState === OBJECT_STATE.PRESENT) references.add(this.transactionStore.referenceKey(record.blobReference))
    }
    return references
  }

  async #verifyLiveReferences () {
    if (this.cells.size > this.quota.maxStartupReferences) {
      this.readOnlyReason = 'STARTUP_REFERENCE_BOUND_EXCEEDED'
      return
    }
    for (const record of this.cells.values()) {
      if (record.objectState !== OBJECT_STATE.PRESENT) continue
      const inspection = await this.transactionStore.inspectOpaque(
        record.blobReference,
        CELL_SIZE_CLASS[record.sizeClass],
        record.cellBlobHash,
        { hash: true }
      )
      if (!inspection.ok) {
        await this.#recordIntegrityFailures([this.#repairFailure(record, inspection.reason)])
        return
      }
    }
  }

  #repairFailure (record, reason) {
    const reasonCode = INTEGRITY_REASON[reason] || INTEGRITY_REASON.HASH
    return {
      locatorCommitment: hashParts(REPAIR_LOCATOR_DOMAIN, record.storageSlot),
      virtualBucket: record.blobReference.virtualBucket,
      expectedLength: CELL_SIZE_CLASS[record.sizeClass],
      expectedHash: b4a.from(record.cellBlobHash),
      reason: reasonCode
    }
  }

  #evidenceHash (failures) {
    const encoded = []
    for (const failure of failures) {
      encoded.push(
        failure.locatorCommitment,
        u32bytes(failure.virtualBucket),
        u32bytes(failure.expectedLength),
        failure.expectedHash,
        b4a.from([failure.reason])
      )
    }
    return hashParts(REPAIR_EVIDENCE_DOMAIN, ...encoded)
  }

  async #recordIntegrityFailures (failures) {
    const evidenceHash = this.#evidenceHash(failures)
    if (this.readOnlyReason === 'RECOVERY_GAP_READ_ONLY' &&
        this.integrityEvidence.some(item => equal(item.evidenceHash, evidenceHash))) return
    this.readOnlyReason = 'RECOVERY_GAP_READ_ONLY'
    try {
      await this.#appendAndApply(BLIND_CELL_WAL_TYPE.INTEGRITY_FAILED, this.transactionStore.newTransactionId(), 0, {
        version: 1,
        reason: failures[0].reason,
        detectedEpoch: this.epochFloor,
        evidenceHash
      })
    } finally {
      this.readOnlyReason = 'RECOVERY_GAP_READ_ONLY'
    }
  }

  scrub (options = {}) {
    return this.#runOperation(() => this.#scrub(options))
  }

  async #scrub (options = {}) {
    this.#assertOpen()
    const limit = integer(options.limit == null ? 1024 : options.limit, 1, 100000, 'scrub limit')
    const maxFailures = integer(options.maxFailures == null ? 256 : options.maxFailures, 1, 4096, 'max scrub failures')
    const failures = []
    let scannedBytes = 0
    let scannedObjects = 0
    let failureCount = 0
    for (const record of this.cells.values()) {
      if (scannedObjects >= limit) break
      if (record.objectState !== OBJECT_STATE.PRESENT) continue
      const inspection = await this.transactionStore.inspectOpaque(
        record.blobReference,
        CELL_SIZE_CLASS[record.sizeClass],
        record.cellBlobHash
      )
      scannedObjects++
      scannedBytes += CELL_SIZE_CLASS[record.sizeClass]
      if (!inspection.ok) {
        failureCount++
        if (failures.length < maxFailures) failures.push(this.#repairFailure(record, inspection.reason))
      }
    }
    if (failures.length > 0 && !this.readOnlyReason) await this.#recordIntegrityFailures(failures)
    return {
      version: 1,
      state: failures.length === 0 ? 'VERIFIED' : 'RECOVERY_GAP_READ_ONLY',
      walSequence: this.transactionStore.walSequence,
      walHash: b4a.from(this.transactionStore.walHash),
      effectiveEpochFloor: this.epochFloor,
      scannedObjects,
      scannedBytes,
      failureCount,
      evidenceHash: failures.length === 0 ? b4a.from(ZERO32) : this.#evidenceHash(failures),
      failures
    }
  }

  repairUnderSameIdentity () {
    fail(
      'FRESH_IDENTITY_REQUIRED',
      'profile-1 body repair must be client-authorized onto a fresh relay/store identity; this store cannot fabricate continuity'
    )
  }

  async captureControlSnapshotState () {
    this.#assertOpen()
    if (this.closing || this.snapshotting) fail('BUSY', 'store lifecycle is already quiescing', true)
    if (!this.storeId) fail('INTERNAL', 'Cell control snapshot capture requires a bound storeId')
    this.snapshotting = true
    this.activeOperations++
    try {
      await this.#waitForActiveOperations(1)
      const state = cloneControlSnapshotValue({
        relayPublicKey: this.relayPublicKey,
        storeId: this.storeId,
        durabilityContinuityHash: this.durabilityContinuityHash,
        durabilityProfileHash: this.durabilityProfileHash,
        walSequence: this.transactionStore.walSequence,
        walHash: this.transactionStore.walHash,
        spends: this.spends,
        commitments: this.commitments,
        requestResults: this.requestResults,
        cells: this.cells,
        accounting: this.accounting,
        epochFloor: this.epochFloor,
        clockUnsafe: this.clockUnsafe,
        readOnlyReason: this.readOnlyReason,
        integrityEvidence: this.integrityEvidence,
        chargedReadExpiryHeap: this.chargedReadExpiryHeap
      })
      const snapshot = Object.freeze({
        kind: 'BLIND_CELL_STORAGE_CONTROL_SNAPSHOT_STATE_V1',
        walSequence: state.walSequence,
        epochFloor: state.epochFloor
      })
      CONTROL_SNAPSHOT_STATES.set(snapshot, state)
      return snapshot
    } finally {
      this.activeOperations--
      this.snapshotting = false
      for (let index = this.drainWaiters.length - 1; index >= 0; index--) {
        if (this.activeOperations <= this.drainWaiters[index].target) {
          const [{ resolve }] = this.drainWaiters.splice(index, 1)
          resolve()
        }
      }
    }
  }

  status () {
    this.#assertOpen()
    const blockers = this.storeFormatAuthority == null
      ? Object.freeze([...BLIND_CELL_STORAGE_PRODUCTION_BLOCKERS, BLIND_CELL_STORE_FORMAT_BINDING_BLOCKER])
      : BLIND_CELL_STORAGE_PRODUCTION_BLOCKERS
    let chargedReadPins = 0
    let chargedReadFinalized = 0
    let chargedReadExpired = 0
    for (const entry of this.spends.values()) {
      if (entry.status === 'read-pinned') chargedReadPins++
      if (entry.status === 'read-finalized') chargedReadFinalized++
      if (entry.status === 'read-expired') chargedReadExpired++
    }
    return {
      state: this.readOnlyReason ? 'READ_ONLY' : this.clockUnsafe ? 'CLOCK_UNSAFE' : 'READY',
      readOnlyReason: this.readOnlyReason,
      epochFloor: this.epochFloor,
      walSequence: this.transactionStore.walSequence,
      walHash: b4a.from(this.transactionStore.walHash),
      mapGeneration: this.transactionStore.mapGeneration,
      storeFormat: this.storeFormatAuthority == null
        ? Object.freeze({ bound: false, publicationFinal: false })
        : Object.freeze({
          bound: true,
          authorityVersion: this.storeFormatAuthority.authorityVersion,
          formatMajor: this.storeFormatAuthority.formatMajor,
          formatMinor: this.storeFormatAuthority.formatMinor,
          storeFormatHash: b4a.from(this.storeFormatAuthority.storeFormatHash),
          publicationFinal: false
        }),
      accounting: {
        storedBytes: this.accounting.storedBytes,
        stagingBytes: this.accounting.stagingBytes,
        controlBytes: this.accounting.controlBytes,
        tombstoneBytes: this.accounting.tombstoneBytes,
        reservedCells: this.accounting.reservedCells,
        cellRecords: this.cells.size,
        spends: this.spends.size,
        requestResults: this.requestResults.size,
        chargedReadPins,
        chargedReadFinalized,
        chargedReadExpired
      },
      blockers
    }
  }

  async close () {
    if (this.closePromise) return this.closePromise
    this.closePromise = (async () => {
      this.closing = true
      if (this.clockTimer) clearInterval(this.clockTimer)
      this.clockTimer = null
      if (this.chargedReadSweepTimer) clearTimeout(this.chargedReadSweepTimer)
      this.chargedReadSweepTimer = null
      await this.#waitForDrain()
      try {
        await this.transactionStore.close()
      } finally {
        this.opened = false
        this.#destroyIdentityAuthorities()
      }
    })()
    return this.closePromise
  }
}

export const BLIND_CELL_STORAGE_LIMITS = Object.freeze({
  cellSizeClasses: Object.freeze({ ...CELL_SIZE_CLASS }),
  leaseEpochs: LEASE_EPOCHS,
  epochSeconds: SIX_HOURS_SECONDS,
  expiryGraceEpochs: EXPIRY_GRACE_EPOCHS,
  retentionHorizonEpochs: RETENTION_HORIZON_EPOCHS,
  reservationMillis: Number(MAX_RESERVATION_MILLIS),
  chargedReadRetryMillis: Number(MAX_RESERVATION_MILLIS),
  chargedReadPinControlBytes: MAX_CHARGED_READ_PIN_CONTROL_BYTES,
  chargedReadFinalizationControlBytes: CHARGED_READ_FINALIZATION_CONTROL_BYTES,
  ingressAttempts: 2,
  controlRecordAccountingBytes: CONTROL_RECORD_BYTES,
  tombstoneAccountingBytes: TOMBSTONE_RECORD_BYTES
})

export const BLIND_CELL_STORE_FORMAT_STATUS = Object.freeze({
  authority: 'VERIFIED_DRAFT_AUTHORITY_BOUND_EXACTLY',
  authorityArtifact: 'hiverelay-blind-store-format-authority-v1.draft.cenc',
  executableArtifactVerifier: true,
  descriptorRuntimeEngineBindingReady: true,
  finalAuthorityPublished: false,
  publicationBlocker: 'FINAL_STORE_FORMAT_AUTHORITY_UNPUBLISHED',
  finalStoreFormatHashRequired: true,
  profile1BehavioralSlice: true,
  profile2Ready: false
})
