import { createHmac } from 'node:crypto'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  INBOX_APPEND_RESULT,
  INBOX_FRAME_CLASS,
  OPERATION,
  RESULT_SIGNATURE_DOMAIN_ID,
  arrayOf,
  blake2b256,
  boundedBytes,
  constant,
  decodeCanonical,
  encodeCanonical,
  fixedBytes,
  inboxAppendAckV1,
  inboxCreateCommitment,
  inboxPhysicalTopic,
  inboxReadEntriesCommitment,
  optional,
  ranged,
  relayResultBindingV1,
  resultSignaturePayload,
  struct,
  u8,
  u16be,
  u32be,
  u64be
} from '@hiverelay/blind-protocol'
import {
  BLIND_STORE_SERVICE_TAG,
  BlindTransactionStore,
  BlindWalIntegrityError
} from './transaction-store.js'
import { inspectBlindStoreFormatAuthorityBinding } from './store-format-binding.js'

const ZERO32 = b4a.alloc(32)
const MAX_U64 = (1n << 64n) - 1n
const MAX_U32 = 0xffffffff
const CONTROL_RECORD_BYTES = 512
const TOMBSTONE_RECORD_BYTES = 512
const FRAME_INDEX_RECORD_BYTES = 256
const RETRY_RECORD_BYTES = 256
const CURSOR_MINUTES = 15n
const MAX_RESERVATION_MILLIS = 15n * 60n * 1000n
const CURSOR_MAGIC = b4a.from('HRI1', 'ascii')
const CURSOR_BYTES = 92
const CURSOR_DOMAIN = b4a.from('hiverelay.blind.inbox-cursor-auth.v1', 'ascii')
const FINGERPRINT_DOMAIN = b4a.from('hiverelay.blind.inbox-store-request-fingerprint.v1', 'ascii')
const RESULT_IDENTITY_DOMAIN = b4a.from('hiverelay.blind.inbox-store-result-identity.v1', 'ascii')
const RETRY_SOURCE_DOMAIN = b4a.from('hiverelay.blind.inbox-retry-source.v1', 'ascii')
const INTEGRITY_EVIDENCE_DOMAIN = b4a.from('hiverelay.blind.inbox-integrity-evidence.v1', 'ascii')

const LEASE_EPOCHS = Object.freeze({ 1: 4, 2: 28, 3: 120, 4: 360 })
const OBJECT_STATE = Object.freeze({ PRESENT: 1, TOMBSTONE: 2 })
const POLICY_STATE = Object.freeze({ VISIBLE: 1, SUPPRESSED: 2 })
const TOMBSTONE_REASON = Object.freeze({ OWNER_CLOSE: 1, EXPIRED_GC: 2 })
const INTEGRITY_REASON = Object.freeze({ MISSING: 1, LENGTH: 2, HASH: 3, INODE: 3 })

export const BLIND_INBOX_WAL_TYPE = Object.freeze({
  CREATE_COMMITTED: 32,
  RENEW_COMMITTED: 33,
  CLOSE_COMMITTED: 34,
  APPEND_COMMITTED: 35,
  READ_PIN_COMMITTED: 36,
  READ_PIN_FINALIZED: 37,
  READ_PIN_EXPIRED: 38,
  FLOOR_ADVANCE: 39,
  APPEND_EXPIRED: 40,
  INBOX_GC: 41,
  POLICY_COMMITTED: 42,
  INTEGRITY_FAILED: 43,
  APPEND_ACK_FINALIZED: 44
})

export const BLIND_INBOX_STORAGE_BLOCKERS = Object.freeze([
  'FINAL_STORE_FORMAT_AUTHORITY_UNPUBLISHED',
  'SHARED_ALL_FAMILY_WAL_DISPATCH_UNASSEMBLED',
  'ENGINE_INSTANCE_WAL_BARRIER_PUBLICATION_AUTHORITY_UNIMPLEMENTED',
  'INBOX_CHECKPOINT_ENGINE_RESTORE_UNASSEMBLED',
  'INBOX_CONTROL_RETENTION_HORIZON_COMPACTION_UNASSEMBLED',
  'INBOX_PROVISIONAL_APPEND_RECONCILIATION_UNASSEMBLED',
  'INBOX_SHARED_CLOCK_FLOOR_AUTHORITY_UNASSEMBLED',
  'PROFILE2_EXTERNAL_JOURNAL_WITNESS_UNIMPLEMENTED',
  'WATCH_PER_CONNECTION_SCOPE_UNASSEMBLED'
])

export const BLIND_INBOX_STORAGE_STATUS = Object.freeze({
  family: 'INBOX',
  operations: Object.freeze(['CREATE', 'RENEW', 'CLOSE', 'APPEND', 'READ', 'WATCH']),
  selfCertifyingTopics: true,
  durableMutationAndSpendAtomicity: true,
  admissionWalCommitRecordPersisted: true,
  deterministicMutationReplay: true,
  authenticatedSnapshotCursor: true,
  immutableChargedReadPins: true,
  boundedWatchLifecycle: true,
  exactFrameRetention: true,
  postRetentionAntiReplaySnapshotCompositionReady: true,
  frameBodyRecoveryVerification: true,
  boundedAccountingAndCapacity: true,
  productionReady: false,
  blockers: BLIND_INBOX_STORAGE_BLOCKERS
})

export class BlindInboxStorageError extends Error {
  constructor (code, message, retryable = false) {
    super(message)
    this.name = 'BlindInboxStorageError'
    this.code = code
    this.retryable = retryable
  }
}

function fail (code, message, retryable = false) {
  throw new BlindInboxStorageError(code, message, retryable)
}

function renewNotDue (retryAfterEpoch) {
  const error = new BlindInboxStorageError('RENEW_NOT_DUE', 'renewal would not extend the inbox lease', true)
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
  return b4a.from(value)
}

function integer (value, minimum, maximum, field) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail('BAD_ENCODING', `${field} is outside ${minimum}..${maximum}`)
  }
  return value
}

function quotaInteger (value, fallback, minimum, maximum, field) {
  if (value == null) value = fallback
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${field} is outside ${minimum}..${maximum}`)
  }
  return value
}

function u64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail('BAD_ENCODING', `${field} is invalid`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
    fail('BAD_ENCODING', `${field} is outside u64`)
  }
  return value
}

function equal (left, right) {
  return Boolean(left && right && left.byteLength === right.byteLength && b4a.equals(left, right))
}

function hex (value) {
  return b4a.toString(value, 'hex')
}

function cloneBytes (value) {
  return value == null ? null : b4a.from(value)
}

function cloneValue (value) {
  if (value == null || typeof value !== 'object') return value
  if (typeof value.byteLength === 'number') return b4a.from(value)
  if (value instanceof Map) return new Map([...value].map(([key, child]) => [key, cloneValue(child)]))
  if (Array.isArray(value)) return value.map(cloneValue)
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, cloneValue(child)]))
}

function u16bytes (value) {
  return b4a.from([value >>> 8, value])
}

function u32bytes (value) {
  return b4a.from([value >>> 24, value >>> 16, value >>> 8, value])
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

function readU64be (buffer, offset) {
  let value = 0n
  for (let index = 0; index < 8; index++) value = (value << 8n) | BigInt(buffer[offset + index])
  return value
}

function hashParts (domain, ...parts) {
  return blake2b256(b4a.concat([domain, ...parts]))
}

function nowEpochFromMillis (millis) {
  millis = u64(millis, 'nowUnixMillis')
  return Number(millis / 21_600_000n)
}

function minuteFromMillis (millis) {
  return u64(millis, 'nowUnixMillis') / 60_000n
}

function requestFingerprint (value) {
  return hashParts(
    FINGERPRINT_DOMAIN,
    b4a.from([value.operation]),
    value.spendTag,
    value.requestCommitment,
    value.physicalTopic,
    b4a.from([value.frameClass]),
    value.frameHash == null ? ZERO32 : value.frameHash,
    b4a.from([value.requestedLeaseClass]),
    u16bytes(value.profileId),
    u32bytes(value.declaredBytes)
  )
}

function resultIdentity (operation, physicalTopic, requestCommitment, resultRevision, resultHash, committedEpoch) {
  return hashParts(
    RESULT_IDENTITY_DOMAIN,
    b4a.from([operation]),
    physicalTopic,
    requestCommitment,
    u64bytes(resultRevision),
    resultHash,
    u32bytes(committedEpoch)
  )
}

function retrySourceCommitment (physicalTopic, sourceRevision, reconstruction, pins) {
  const pinBytes = []
  for (const pin of pins) pinBytes.push(u64bytes(pin.appendRevision), pin.frameHash)
  return hashParts(
    RETRY_SOURCE_DOMAIN,
    physicalTopic,
    u64bytes(sourceRevision),
    u64bytes(reconstruction.firstAppendRevision),
    u64bytes(reconstruction.lastAppendRevision),
    b4a.from([reconstruction.entryCount]),
    reconstruction.nextCursorHash,
    ...pinBytes
  )
}

const version1 = constant(u8, 1, 'version')
const bytes32 = fixedBytes(32)
const preparedAdmissionStoreV1 = struct([
  ['version', version1],
  ['spendTag', bytes32],
  ['requestCommitment', bytes32],
  ['profileId', ranged(u16be, 1, 0xffff, 'profileId')],
  ['schemeId', ranged(u16be, 1, 0xffff, 'schemeId')],
  ['parameterHash', bytes32],
  ['resourceClass', u16be],
  ['leaseClass', u8],
  ['costUnits', u64be],
  ['walCommitRecord', boundedBytes(1, 16384, 'walCommitRecord')]
], { name: 'BlindInboxPreparedAdmissionStoreV1' })

const spendFields = [
  ['spendTag', bytes32],
  ['requestCommitment', bytes32],
  ['requestFingerprint', bytes32],
  ['preparedAdmissionBytes', boundedBytes(1, 17408, 'preparedAdmissionBytes')],
  ['deadlineUnixMillis', u64be],
  ['committedEpoch', u32be],
  ['resultBindingBytes', boundedBytes(1, 1024, 'resultBindingBytes')]
]

const createCommittedV1 = struct([
  ['version', version1],
  ...spendFields,
  ['allocationEpoch', u32be],
  ['physicalTopic', bytes32],
  ['frameClassBits', ranged(u8, 1, 7, 'frameClassBits')],
  ['appendAuthMode', ranged(u8, 0, 1, 'appendAuthMode')],
  ['appendPublicKey', optional(bytes32, 'appendPublicKey')],
  ['createPublicKey', bytes32],
  ['renewPublicKey', bytes32],
  ['closePublicKey', bytes32],
  ['retentionClass', ranged(u8, 1, 4, 'retentionClass')],
  ['leaseClass', ranged(u8, 1, 4, 'leaseClass')],
  ['clientNonce', bytes32],
  ['createCommitment', bytes32],
  ['leaseEpoch', u32be],
  ['resultIdentity', bytes32]
], { name: 'BlindInboxCreateCommittedStoreV1' })

const renewCommittedV1 = struct([
  ['version', version1],
  ...spendFields,
  ['physicalTopic', bytes32],
  ['oldStateRevision', u64be],
  ['newStateRevision', u64be],
  ['oldLeaseEpoch', u32be],
  ['newLeaseEpoch', u32be],
  ['leaseClass', ranged(u8, 1, 4, 'leaseClass')],
  ['clientNonce', bytes32],
  ['resultIdentity', bytes32]
], { name: 'BlindInboxRenewCommittedStoreV1' })

const closeCommittedV1 = struct([
  ['version', version1],
  ['transactionId', bytes32],
  ['requestCommitment', bytes32],
  ['requestFingerprint', bytes32],
  ['physicalTopic', bytes32],
  ['oldStateRevision', u64be],
  ['newStateRevision', u64be],
  ['oldLeaseEpoch', u32be],
  ['clientNonce', bytes32],
  ['committedEpoch', u32be],
  ['resultBindingBytes', boundedBytes(1, 1024, 'resultBindingBytes')],
  ['resultIdentity', bytes32]
], { name: 'BlindInboxCloseCommittedStoreV1' })

const appendCommittedV1 = struct([
  ['version', version1],
  ...spendFields,
  ['physicalTopic', bytes32],
  ['frameClass', ranged(u8, 1, 3, 'frameClass')],
  ['frameHash', bytes32],
  ['frameObjectId', bytes32],
  ['clientNonce', bytes32],
  ['appendRevision', u64be],
  ['appendLeaseEpoch', u32be],
  ['expiresAtEpoch', u32be],
  ['resultIdentity', bytes32]
], { name: 'BlindInboxAppendCommittedStoreV1' })

const retryPinEntryV1 = struct([
  ['appendRevision', u64be],
  ['frameHash', bytes32],
  ['frameClass', ranged(u8, 1, 3, 'frameClass')],
  ['frameObjectId', bytes32]
], { name: 'BlindInboxRetryPinEntryStoreV1' })

const retryPinEntriesV1 = arrayOf(retryPinEntryV1, 0, 64, 'retry pin entries')

const readPinCommittedV1 = struct([
  ['version', version1],
  ['operationId', ranged(u8, OPERATION.INBOX.READ, OPERATION.INBOX.WATCH, 'operationId')],
  ...spendFields,
  ['physicalTopic', bytes32],
  ['clientNonce', bytes32],
  ['snapshotRevision', u64be],
  ['entries', retryPinEntriesV1],
  ['entriesCommitment', bytes32],
  ['nextCursor', optional(boundedBytes(1, 128, 'nextCursor'), 'nextCursor')],
  ['sourceCommitment', bytes32],
  ['retryExpiresMinute', u64be]
], {
  name: 'BlindInboxReadPinCommittedStoreV1',
  validate (value) {
    if (value.operationId !== OPERATION.INBOX.READ && value.operationId !== OPERATION.INBOX.WATCH) {
      throw new Error('unknown Inbox retry operation')
    }
  }
})

const readPinFinalizedV1 = struct([
  ['version', version1],
  ['spendTag', bytes32],
  ['requestCommitment', bytes32],
  ['resultCommitment', bytes32],
  ['resultIdentity', bytes32],
  ['finalizedEpoch', u32be]
], { name: 'BlindInboxReadPinFinalizedStoreV1' })

const appendAckFinalizedV1 = struct([
  ['version', version1],
  ['spendTag', bytes32],
  ['requestCommitment', bytes32],
  ['ackSignature', fixedBytes(64)],
  ['resultCommitment', bytes32],
  ['finalizedEpoch', u32be]
], { name: 'BlindInboxAppendAckFinalizedStoreV1' })

const readPinExpiredV1 = struct([
  ['version', version1],
  ['spendTag', bytes32],
  ['requestCommitment', bytes32],
  ['retryExpiresMinute', u64be],
  ['terminalEpoch', u32be]
], { name: 'BlindInboxReadPinExpiredStoreV1' })

const floorAdvanceV1 = struct([
  ['version', version1],
  ['oldEpochFloor', u32be],
  ['newEpochFloor', u32be]
], { name: 'BlindInboxFloorAdvanceStoreV1' })

const appendExpiredV1 = struct([
  ['version', version1],
  ['transactionId', bytes32],
  ['spendTag', bytes32],
  ['requestCommitment', bytes32],
  ['requestFingerprint', bytes32],
  ['physicalTopic', bytes32],
  ['profileId', ranged(u16be, 1, 0xffff, 'profileId')],
  ['appendRevision', u64be],
  ['frameHash', bytes32],
  ['frameClass', ranged(u8, 1, 3, 'frameClass')],
  ['declaredBytes', u32be],
  ['deadlineUnixMillis', u64be],
  ['remainingAttempts', ranged(u8, 0, 1, 'remainingAttempts')],
  ['reservedEpoch', u32be],
  ['resultIdentity', bytes32],
  ['frameObjectId', bytes32],
  ['storedAtEpoch', u32be],
  ['retentionClassAtAppend', ranged(u8, 1, 4, 'retentionClassAtAppend')],
  ['appendLeaseEpoch', u32be],
  ['expiresAtEpoch', u32be],
  ['expiredEpoch', u32be],
  ['clientNonce', bytes32],
  ['resultBindingBytes', boundedBytes(1, 1024, 'resultBindingBytes')],
  ['ackSignature', fixedBytes(64)],
  ['resultCommitment', bytes32]
], { name: 'BlindInboxAppendExpiredStoreV1' })

const inboxGcV1 = struct([
  ['version', version1],
  ['physicalTopic', bytes32],
  ['oldStateRevision', u64be],
  ['newStateRevision', u64be],
  ['expectedLeaseEpoch', u32be],
  ['terminalEpoch', u32be]
], { name: 'BlindInboxGcStoreV1' })

const policyCommittedV1 = struct([
  ['version', version1],
  ['physicalTopic', bytes32],
  ['oldPolicyRevision', u64be],
  ['newPolicyRevision', u64be],
  ['policyState', ranged(u8, 1, 2, 'policyState')],
  ['committedEpoch', u32be]
], { name: 'BlindInboxPolicyCommittedStoreV1' })

const integrityFailedV1 = struct([
  ['version', version1],
  ['reason', ranged(u8, 1, 3, 'reason')],
  ['detectedEpoch', u32be],
  ['evidenceHash', bytes32]
], { name: 'BlindInboxIntegrityFailedStoreV1' })

const WAL_CODECS = new Map([
  [BLIND_INBOX_WAL_TYPE.CREATE_COMMITTED, createCommittedV1],
  [BLIND_INBOX_WAL_TYPE.RENEW_COMMITTED, renewCommittedV1],
  [BLIND_INBOX_WAL_TYPE.CLOSE_COMMITTED, closeCommittedV1],
  [BLIND_INBOX_WAL_TYPE.APPEND_COMMITTED, appendCommittedV1],
  [BLIND_INBOX_WAL_TYPE.READ_PIN_COMMITTED, readPinCommittedV1],
  [BLIND_INBOX_WAL_TYPE.READ_PIN_FINALIZED, readPinFinalizedV1],
  [BLIND_INBOX_WAL_TYPE.APPEND_ACK_FINALIZED, appendAckFinalizedV1],
  [BLIND_INBOX_WAL_TYPE.READ_PIN_EXPIRED, readPinExpiredV1],
  [BLIND_INBOX_WAL_TYPE.FLOOR_ADVANCE, floorAdvanceV1],
  [BLIND_INBOX_WAL_TYPE.APPEND_EXPIRED, appendExpiredV1],
  [BLIND_INBOX_WAL_TYPE.INBOX_GC, inboxGcV1],
  [BLIND_INBOX_WAL_TYPE.POLICY_COMMITTED, policyCommittedV1],
  [BLIND_INBOX_WAL_TYPE.INTEGRITY_FAILED, integrityFailedV1]
])

function frameKey (physicalTopic, appendRevision) {
  return `${hex(physicalTopic)}:${u64(appendRevision, 'appendRevision').toString()}`
}

function preparedView (value, field = 'preparedAdmission') {
  if (!value || typeof value !== 'object' || !value.costClass) fail('BAD_ENCODING', `${field} is incomplete`)
  const walCommitRecord = value.walCommitRecord && typeof value.walCommitRecord.byteLength === 'number'
    ? b4a.from(value.walCommitRecord)
    : null
  if (!walCommitRecord || walCommitRecord.byteLength < 1 || walCommitRecord.byteLength > 16384) {
    fail('BAD_ENCODING', `${field}.walCommitRecord is outside 1..16384 bytes`)
  }
  const canonicalValue = {
    version: 1,
    spendTag: fixed(value.spendTag, 32, `${field}.spendTag`, true),
    requestCommitment: fixed(value.requestCommitment, 32, `${field}.requestCommitment`, true),
    profileId: integer(value.profileId, 1, 0xffff, `${field}.profileId`),
    schemeId: integer(value.schemeId, 1, 0xffff, `${field}.schemeId`),
    parameterHash: fixed(value.parameterHash, 32, `${field}.parameterHash`, true),
    resourceClass: integer(value.costClass.resourceClass, 0, 0xffff, `${field}.resourceClass`),
    leaseClass: integer(value.costClass.leaseClass, 0, 0xff, `${field}.leaseClass`),
    costUnits: u64(value.costClass.costUnits, `${field}.costUnits`),
    walCommitRecord
  }
  return { value: canonicalValue, canonicalBytes: encodeCanonical(preparedAdmissionStoreV1, canonicalValue) }
}

function decodePrepared (canonicalBytes) {
  const value = decodeCanonical(preparedAdmissionStoreV1, canonicalBytes, { copyBytes: true })
  if (!equal(canonicalBytes, encodeCanonical(preparedAdmissionStoreV1, value))) {
    throw new BlindWalIntegrityError('Inbox prepared admission changed on canonical re-encoding')
  }
  return value
}

function publicInbox (record) {
  return Object.freeze({
    physicalTopic: b4a.from(record.physicalTopic),
    allocationEpoch: record.allocationEpoch,
    frameClassBits: record.frameClassBits,
    appendAuthMode: record.appendAuthMode,
    appendPublicKey: cloneBytes(record.appendPublicKey),
    createPublicKey: b4a.from(record.createPublicKey),
    renewPublicKey: b4a.from(record.renewPublicKey),
    closePublicKey: b4a.from(record.closePublicKey),
    retentionClass: record.retentionClass,
    leaseClass: record.leaseClass,
    leaseEpoch: record.leaseEpoch,
    stateRevision: record.stateRevision,
    policyRevision: record.policyRevision,
    appendRevision: record.appendRevision,
    objectState: record.objectState,
    policyState: record.policyState,
    createCommitment: b4a.from(record.createCommitment)
  })
}

function operationSpendBase (operation, prepared, request, nowMillis, committedEpoch) {
  const frameClass = operation === OPERATION.INBOX.APPEND ? request.frameClass : 0
  const frameHash = operation === OPERATION.INBOX.APPEND ? fixed(request.frameHash, 32, 'frameHash', true) : null
  const requestedLeaseClass = operation === OPERATION.INBOX.CREATE || operation === OPERATION.INBOX.RENEW
    ? request.leaseClass
    : 0
  const declaredBytes = operation === OPERATION.INBOX.APPEND ? INBOX_FRAME_CLASS[frameClass] : 0
  const common = {
    operation,
    spendTag: prepared.value.spendTag,
    requestCommitment: prepared.value.requestCommitment,
    physicalTopic: fixed(request.physicalTopic, 32, 'physicalTopic', true),
    frameClass,
    frameHash,
    requestedLeaseClass,
    profileId: prepared.value.profileId,
    declaredBytes
  }
  return {
    ...common,
    requestFingerprint: requestFingerprint(common),
    preparedAdmissionBytes: prepared.canonicalBytes,
    deadlineUnixMillis: u64(nowMillis, 'nowUnixMillis') + MAX_RESERVATION_MILLIS,
    committedEpoch
  }
}

export class BlindInboxStorageEngine {
  constructor (options = {}) {
    if (options.durabilityProfileId != null && options.durabilityProfileId !== 1) {
      throw new BlindInboxStorageError(
        'FINAL_EXTERNAL_WITNESS_UNIMPLEMENTED',
        'durability profile 2 is unavailable until external journal witnesses are assembled'
      )
    }
    this.relayPublicKey = fixed(options.relayPublicKey, 32, 'relayPublicKey', true)
    this.storeId = options.storeId == null ? null : fixed(options.storeId, 32, 'storeId', true)
    this.durabilityContinuityHash = fixed(options.durabilityContinuityHash, 32,
      'durabilityContinuityHash', true)
    this.durabilityProfileHash = options.durabilityProfileHash == null
      ? null
      : fixed(options.durabilityProfileHash, 32, 'durabilityProfileHash', true)
    this.cursorKey = fixed(options.cursorKey, 32, 'cursorKey', true)
    this.storeFormatAuthority = options.storeFormatAuthority == null
      ? null
      : inspectBlindStoreFormatAuthorityBinding(options.storeFormatAuthority)
    this.nowUnixMillis = typeof options.nowUnixMillis === 'function' ? options.nowUnixMillis : () => BigInt(Date.now())
    this.initialEpochFloor = options.initialEpochFloor == null
      ? nowEpochFromMillis(this.nowUnixMillis())
      : integer(options.initialEpochFloor, 0, MAX_U32, 'initialEpochFloor')
    this.autoClock = options.autoClock !== false
    this.quota = Object.freeze({
      maxStoredFrameBytes: quotaInteger(options.maxStoredFrameBytes, 4 * 1024 * 1024 * 1024,
        INBOX_FRAME_CLASS[1], Number.MAX_SAFE_INTEGER - INBOX_FRAME_CLASS[3], 'maxStoredFrameBytes'),
      maxStagingFrameBytes: quotaInteger(options.maxStagingFrameBytes, 64 * 1024 * 1024,
        INBOX_FRAME_CLASS[1], Number.MAX_SAFE_INTEGER - INBOX_FRAME_CLASS[3], 'maxStagingFrameBytes'),
      maxStagingFrameBytesPerProfile: quotaInteger(options.maxStagingFrameBytesPerProfile, 32 * 1024 * 1024,
        INBOX_FRAME_CLASS[1], Number.MAX_SAFE_INTEGER - INBOX_FRAME_CLASS[3], 'maxStagingFrameBytesPerProfile'),
      maxControlBytes: quotaInteger(options.maxControlBytes, 256 * 1024 * 1024,
        CONTROL_RECORD_BYTES, Number.MAX_SAFE_INTEGER - CONTROL_RECORD_BYTES, 'maxControlBytes'),
      maxTombstoneBytes: quotaInteger(options.maxTombstoneBytes, 256 * 1024 * 1024,
        TOMBSTONE_RECORD_BYTES, Number.MAX_SAFE_INTEGER - TOMBSTONE_RECORD_BYTES, 'maxTombstoneBytes'),
      maxFrameIndexBytes: quotaInteger(options.maxFrameIndexBytes, 256 * 1024 * 1024,
        FRAME_INDEX_RECORD_BYTES, Number.MAX_SAFE_INTEGER - FRAME_INDEX_RECORD_BYTES, 'maxFrameIndexBytes'),
      maxInboxes: quotaInteger(options.maxInboxes, 1000000, 1, MAX_U32, 'maxInboxes'),
      maxFrames: quotaInteger(options.maxFrames, 4000000, 1, MAX_U32, 'maxFrames'),
      maxFramesPerTopic: quotaInteger(options.maxFramesPerTopic, 100000, 1, MAX_U32, 'maxFramesPerTopic'),
      maxStartupReferences: quotaInteger(options.maxStartupReferences, 1000000, 1, MAX_U32, 'maxStartupReferences'),
      maxGlobalWaiters: quotaInteger(options.maxGlobalWaiters, 4096, 1, 65535, 'maxGlobalWaiters'),
      maxWaitersPerTopic: quotaInteger(options.maxWaitersPerTopic, 256, 1, 65535, 'maxWaitersPerTopic')
    })
    this.transactionStore = new BlindTransactionStore({
      root: options.root,
      mapGeneration: options.mapGeneration,
      ownerFenceTokenHash: options.ownerFenceTokenHash,
      durabilityContinuityHash: options.durabilityContinuityHash,
      maximumWalPayloadBytes: options.maximumWalPayloadBytes == null ? 1024 * 1024 : options.maximumWalPayloadBytes,
      maximumOpaqueBodyBytes: INBOX_FRAME_CLASS[3],
      maximumChunkBytes: options.maximumChunkBytes == null ? INBOX_FRAME_CLASS[3] : options.maximumChunkBytes,
      storeSessionContext: options.storeSessionContext,
      beforeRecovery: options.beforeRecovery,
      faultInjector: options.faultInjector
    })
    this.spends = new Map()
    this.commitments = new Map()
    this.requestResults = new Map()
    this.inboxes = new Map()
    this.frames = new Map()
    this.framesByTopic = new Map()
    this.retryPins = new Map()
    this.accounting = {
      storedFrameBytes: 0,
      stagingFrameBytes: 0,
      controlBytes: 0,
      tombstoneBytes: 0,
      frameIndexBytes: 0,
      reservedFrames: 0,
      stagingByProfile: new Map()
    }
    this.integrityEvidence = []
    this.epochFloor = 0
    this.clockUnsafe = false
    this.readOnlyReason = null
    this.opened = false
    this.closing = false
    this.activeOperations = 0
    this.drainWaiters = []
    this.clockTimer = null
    this.waitersByTopic = new Map()
    this.waiterCount = 0
    this.closePromise = null
  }

  async open () {
    if (this.opened) throw new Error('inbox storage engine is already open')
    this.closing = false
    try {
      await this.transactionStore.open(frame => this.#applyFrame(frame))
      this.opened = true
      if (this.transactionStore.walSequence === 0n) {
        await this.#appendAndApply(BLIND_INBOX_WAL_TYPE.FLOOR_ADVANCE,
          this.transactionStore.newTransactionId(), 0, {
            version: 1,
            oldEpochFloor: 0,
            newEpochFloor: this.initialEpochFloor
          })
      }
      await this.#verifyFrameBodies()
      await this.transactionStore.cleanupOrphans(this.#liveReferenceKeys(), this.quota.maxStartupReferences)
      await this.#sweepExpiredRetryPins(4096)
      await this.#sweepExpired(4096)
      this.#assertRecoveredQuota()
      if (this.autoClock) {
        this.clockTimer = setInterval(() => {
          this.#runOperation(async () => {
            await this.advanceEpochFloor(nowEpochFromMillis(this.nowUnixMillis()))
            await this.#sweepExpiredRetryPins(4096)
            await this.#sweepExpired(4096)
          }).catch(() => { this.readOnlyReason = this.readOnlyReason || 'CLOCK_TIMER_FAILED' })
        }, 60_000)
        if (typeof this.clockTimer.unref === 'function') this.clockTimer.unref()
      }
      return this
    } catch (error) {
      this.opened = false
      if (this.clockTimer) clearInterval(this.clockTimer)
      this.clockTimer = null
      await this.transactionStore.close().catch(() => {})
      throw error
    }
  }

  #assertOpen () {
    if (!this.opened) throw new Error('inbox storage engine is not open')
  }

  #assertWritable (leaseMutation = false) {
    this.#assertOpen()
    if (this.readOnlyReason) fail('INTERNAL', `store is read-only: ${this.readOnlyReason}`)
    if (leaseMutation && this.clockUnsafe) fail('BUSY', 'store clock is unsafe', true)
  }

  #assertRecoveredQuota () {
    const profileExceeded = [...this.accounting.stagingByProfile.values()]
      .some(value => value > this.quota.maxStagingFrameBytesPerProfile)
    if (this.accounting.storedFrameBytes > this.quota.maxStoredFrameBytes ||
        this.accounting.stagingFrameBytes > this.quota.maxStagingFrameBytes ||
        this.accounting.controlBytes > this.quota.maxControlBytes ||
        this.accounting.tombstoneBytes > this.quota.maxTombstoneBytes ||
        this.accounting.frameIndexBytes > this.quota.maxFrameIndexBytes ||
        this.inboxes.size > this.quota.maxInboxes || this.frames.size > this.quota.maxFrames || profileExceeded) {
      this.readOnlyReason = 'RECOVERED_QUOTA_EXCEEDED'
    }
  }

  async #runOperation (operation) {
    if (this.closing) fail('BUSY', 'inbox store is closing', true)
    this.activeOperations++
    try {
      return await operation()
    } finally {
      this.activeOperations--
      if (this.activeOperations === 0) for (const resolve of this.drainWaiters.splice(0)) resolve()
    }
  }

  async #waitForDrain () {
    if (this.activeOperations === 0) return
    await new Promise(resolve => this.drainWaiters.push(resolve))
  }

  #resultBindingBytes (value) {
    let canonicalBytes
    let binding
    try {
      canonicalBytes = value && typeof value.byteLength === 'number' ? b4a.from(value) : encodeCanonical(relayResultBindingV1, value)
      binding = decodeCanonical(relayResultBindingV1, canonicalBytes, { copyBytes: true })
      if (!equal(canonicalBytes, encodeCanonical(relayResultBindingV1, binding))) throw new Error('non-canonical')
    } catch {
      fail('BAD_ENCODING', 'resultBinding is not canonical')
    }
    if (binding.durabilityProfileId !== 1 || binding.externalCommitWitness != null ||
        !equal(binding.relayPublicKey, this.relayPublicKey) ||
        !equal(binding.durabilityContinuityHash, this.durabilityContinuityHash) ||
        (this.storeId && !equal(binding.storeId, this.storeId)) ||
        (this.durabilityProfileHash && !equal(binding.durabilityProfileHash, this.durabilityProfileHash))) {
      fail('BAD_ENCODING', 'resultBinding does not bind this profile-1 Inbox store')
    }
    return canonicalBytes
  }

  async #appendAndApply (type, transactionId, virtualBucket, value) {
    const codec = WAL_CODECS.get(type)
    if (!codec) throw new BlindWalIntegrityError(`unknown Inbox WAL type ${type}`)
    return this.transactionStore.appendAndApply({
      type,
      transactionId,
      virtualBucket,
      payload: encodeCanonical(codec, value)
    }, frame => this.#applyFrame(frame))
  }

  #applyFrame (frame) {
    const codec = WAL_CODECS.get(frame.type)
    if (!codec) throw new BlindWalIntegrityError(`unknown Inbox WAL type ${frame.type}`)
    let value
    try {
      value = decodeCanonical(codec, frame.payload, { copyBytes: true })
      if (!equal(frame.payload, encodeCanonical(codec, value))) throw new Error('non-canonical')
    } catch (error) {
      throw new BlindWalIntegrityError(`non-canonical Inbox WAL payload: ${error.message}`)
    }
    switch (frame.type) {
      case BLIND_INBOX_WAL_TYPE.CREATE_COMMITTED: this.#applyCreate(frame, value); break
      case BLIND_INBOX_WAL_TYPE.RENEW_COMMITTED: this.#applyRenew(frame, value); break
      case BLIND_INBOX_WAL_TYPE.CLOSE_COMMITTED: this.#applyClose(frame, value); break
      case BLIND_INBOX_WAL_TYPE.APPEND_COMMITTED: this.#applyAppend(frame, value); break
      case BLIND_INBOX_WAL_TYPE.APPEND_ACK_FINALIZED: this.#applyAppendAckFinalized(frame, value); break
      case BLIND_INBOX_WAL_TYPE.READ_PIN_COMMITTED: this.#applyReadPin(frame, value); break
      case BLIND_INBOX_WAL_TYPE.READ_PIN_FINALIZED: this.#applyReadFinal(frame, value); break
      case BLIND_INBOX_WAL_TYPE.READ_PIN_EXPIRED: this.#applyReadExpired(frame, value); break
      case BLIND_INBOX_WAL_TYPE.FLOOR_ADVANCE: this.#applyFloor(value); break
      case BLIND_INBOX_WAL_TYPE.APPEND_EXPIRED: this.#applyAppendExpired(frame, value); break
      case BLIND_INBOX_WAL_TYPE.INBOX_GC: this.#applyInboxGc(frame, value); break
      case BLIND_INBOX_WAL_TYPE.POLICY_COMMITTED: this.#applyPolicy(frame, value); break
      case BLIND_INBOX_WAL_TYPE.INTEGRITY_FAILED: this.#applyIntegrity(value); break
      default: throw new BlindWalIntegrityError(`unhandled Inbox WAL type ${frame.type}`)
    }
    this.#assertAccounting()
  }

  #verifyBucket (frame, physicalTopic) {
    const expected = this.transactionStore.virtualBucket(BLIND_STORE_SERVICE_TAG.INBOX, physicalTopic)
    if (frame.virtualBucket !== expected) throw new BlindWalIntegrityError('Inbox WAL frame uses the wrong private virtual bucket')
  }

  #assertSpendFresh (value, operation) {
    const prepared = decodePrepared(value.preparedAdmissionBytes)
    if (!equal(prepared.spendTag, value.spendTag) || !equal(prepared.requestCommitment, value.requestCommitment)) {
      throw new BlindWalIntegrityError('Inbox WAL prepared admission does not bind its spend/request')
    }
    if (this.spends.has(hex(value.spendTag)) || this.commitments.has(hex(value.requestCommitment))) {
      throw new BlindWalIntegrityError('Inbox WAL redefines a spend or request commitment')
    }
    const fingerprint = requestFingerprint({
      operation,
      spendTag: value.spendTag,
      requestCommitment: value.requestCommitment,
      physicalTopic: value.physicalTopic,
      frameClass: operation === OPERATION.INBOX.APPEND ? value.frameClass : 0,
      frameHash: operation === OPERATION.INBOX.APPEND ? value.frameHash : null,
      requestedLeaseClass: operation === OPERATION.INBOX.CREATE || operation === OPERATION.INBOX.RENEW ? value.leaseClass : 0,
      profileId: prepared.profileId,
      declaredBytes: operation === OPERATION.INBOX.APPEND ? INBOX_FRAME_CLASS[value.frameClass] : 0
    })
    if (!equal(fingerprint, value.requestFingerprint)) throw new BlindWalIntegrityError('Inbox WAL request fingerprint mismatch')
    return prepared
  }

  #addSpend (entry) {
    const spendKey = hex(entry.spendTag)
    const commitmentKey = hex(entry.requestCommitment)
    this.spends.set(spendKey, entry)
    this.commitments.set(commitmentKey, { spendKey, fingerprint: hex(entry.requestFingerprint) })
    this.accounting.controlBytes += CONTROL_RECORD_BYTES
  }

  #applyCreate (frame, value) {
    this.#verifyBucket(frame, value.physicalTopic)
    const prepared = this.#assertSpendFresh(value, OPERATION.INBOX.CREATE)
    const topicKey = hex(value.physicalTopic)
    if (this.inboxes.has(topicKey)) throw new BlindWalIntegrityError('Inbox CREATE redefines a physical topic')
    if (!equal(inboxPhysicalTopic(value), value.physicalTopic)) throw new BlindWalIntegrityError('Inbox CREATE topic is not self-certifying')
    const expectedCreate = inboxCreateCommitment({ ...value, relayPublicKey: this.relayPublicKey })
    if (!equal(expectedCreate, value.createCommitment)) throw new BlindWalIntegrityError('Inbox CREATE commitment mismatch')
    const keys = [value.createPublicKey, value.renewPublicKey, value.closePublicKey]
    if (value.appendPublicKey) keys.push(value.appendPublicKey)
    if (new Set(keys.map(hex)).size !== keys.length || keys.some(isZero) ||
        (value.appendAuthMode === 1) !== (value.appendPublicKey != null)) {
      throw new BlindWalIntegrityError('Inbox CREATE capability key policy is invalid')
    }
    const expectedLeaseEpoch = Math.min(MAX_U32, value.committedEpoch + LEASE_EPOCHS[value.leaseClass])
    if (value.leaseEpoch !== expectedLeaseEpoch) throw new BlindWalIntegrityError('Inbox CREATE lease epoch mismatch')
    const expectedIdentity = resultIdentity(OPERATION.INBOX.CREATE, value.physicalTopic,
      value.requestCommitment, 0n, value.createCommitment, value.committedEpoch)
    if (!equal(expectedIdentity, value.resultIdentity)) throw new BlindWalIntegrityError('Inbox CREATE result identity mismatch')
    const spend = {
      status: 'committed',
      transactionId: b4a.from(frame.transactionId),
      spendTag: b4a.from(value.spendTag),
      requestCommitment: b4a.from(value.requestCommitment),
      requestFingerprint: b4a.from(value.requestFingerprint),
      physicalTopic: b4a.from(value.physicalTopic),
      operation: OPERATION.INBOX.CREATE,
      profileId: prepared.profileId,
      frameClass: 0,
      frameHash: null,
      requestedLeaseClass: value.leaseClass,
      declaredBytes: 0,
      deadlineUnixMillis: value.deadlineUnixMillis,
      remainingAttempts: 1,
      reservedEpoch: value.committedEpoch,
      resultIdentity: b4a.from(value.resultIdentity),
      resultRevision: 0n,
      resultLeaseClass: value.leaseClass,
      resultLeaseEpoch: value.leaseEpoch,
      committedEpoch: value.committedEpoch,
      resultCommitment: null,
      retryState: 0,
      resultBindingBytes: b4a.from(value.resultBindingBytes),
      clientNonce: b4a.from(value.clientNonce),
      inFlight: false
    }
    this.#addSpend(spend)
    this.inboxes.set(topicKey, {
      physicalTopic: b4a.from(value.physicalTopic),
      metadataVirtualBucket: frame.virtualBucket,
      allocationEpoch: value.allocationEpoch,
      allocationLeaseClass: value.leaseClass,
      frameClassBits: value.frameClassBits,
      appendAuthMode: value.appendAuthMode,
      appendPublicKey: cloneBytes(value.appendPublicKey),
      createPublicKey: b4a.from(value.createPublicKey),
      renewPublicKey: b4a.from(value.renewPublicKey),
      closePublicKey: b4a.from(value.closePublicKey),
      retentionClass: value.retentionClass,
      leaseClass: value.leaseClass,
      leaseEpoch: value.leaseEpoch,
      stateRevision: 0n,
      policyRevision: 0n,
      appendRevision: 0n,
      allocatedAppendRevision: 0n,
      createCommitment: b4a.from(value.createCommitment),
      objectState: OBJECT_STATE.PRESENT,
      policyState: POLICY_STATE.VISIBLE,
      tombstoneReason: null,
      terminalEpoch: null,
      createSpendTag: b4a.from(value.spendTag),
      createRequestCommitment: b4a.from(value.requestCommitment),
      resultIdentity: b4a.from(value.resultIdentity),
      createdEpoch: value.committedEpoch,
      frameCount: 0
    })
    this.framesByTopic.set(topicKey, new Map())
    this.accounting.tombstoneBytes += TOMBSTONE_RECORD_BYTES
  }

  #applyRenew (frame, value) {
    this.#verifyBucket(frame, value.physicalTopic)
    const prepared = this.#assertSpendFresh(value, OPERATION.INBOX.RENEW)
    const record = this.inboxes.get(hex(value.physicalTopic))
    if (!record || record.objectState !== OBJECT_STATE.PRESENT) throw new BlindWalIntegrityError('Inbox RENEW has no live record')
    if (record.stateRevision !== value.oldStateRevision || record.leaseEpoch !== value.oldLeaseEpoch ||
        value.newStateRevision !== value.oldStateRevision + 1n || value.newLeaseEpoch <= value.oldLeaseEpoch) {
      throw new BlindWalIntegrityError('Inbox RENEW revision/lease transition is invalid')
    }
    const expected = resultIdentity(OPERATION.INBOX.RENEW, value.physicalTopic,
      value.requestCommitment, value.newStateRevision, record.createCommitment, value.committedEpoch)
    if (!equal(expected, value.resultIdentity)) throw new BlindWalIntegrityError('Inbox RENEW result identity mismatch')
    record.stateRevision = value.newStateRevision
    record.leaseEpoch = value.newLeaseEpoch
    record.leaseClass = value.leaseClass
    this.#addSpend({
      status: 'committed',
      transactionId: b4a.from(frame.transactionId),
      spendTag: b4a.from(value.spendTag),
      requestCommitment: b4a.from(value.requestCommitment),
      requestFingerprint: b4a.from(value.requestFingerprint),
      physicalTopic: b4a.from(value.physicalTopic),
      operation: OPERATION.INBOX.RENEW,
      profileId: prepared.profileId,
      frameClass: 0,
      frameHash: null,
      requestedLeaseClass: value.leaseClass,
      declaredBytes: 0,
      deadlineUnixMillis: value.deadlineUnixMillis,
      remainingAttempts: 1,
      reservedEpoch: value.committedEpoch,
      resultIdentity: b4a.from(value.resultIdentity),
      resultRevision: value.newStateRevision,
      resultLeaseClass: value.leaseClass,
      resultLeaseEpoch: value.newLeaseEpoch,
      committedEpoch: value.committedEpoch,
      resultCommitment: null,
      retryState: 0,
      resultBindingBytes: b4a.from(value.resultBindingBytes),
      clientNonce: b4a.from(value.clientNonce),
      inFlight: false
    })
  }

  #applyClose (frame, value) {
    this.#verifyBucket(frame, value.physicalTopic)
    if (!equal(frame.transactionId, value.transactionId)) {
      throw new BlindWalIntegrityError('Inbox CLOSE transaction identity mismatch')
    }
    const record = this.inboxes.get(hex(value.physicalTopic))
    if (!record || record.objectState !== OBJECT_STATE.PRESENT) throw new BlindWalIntegrityError('Inbox CLOSE has no live record')
    if (record.stateRevision !== value.oldStateRevision || record.leaseEpoch !== value.oldLeaseEpoch ||
        value.newStateRevision !== value.oldStateRevision + 1n) {
      throw new BlindWalIntegrityError('Inbox CLOSE revision transition is invalid')
    }
    const expected = resultIdentity(OPERATION.INBOX.CLOSE, value.physicalTopic,
      value.requestCommitment, value.newStateRevision, record.createCommitment, value.committedEpoch)
    if (!equal(expected, value.resultIdentity)) throw new BlindWalIntegrityError('Inbox CLOSE result identity mismatch')
    const key = hex(value.requestCommitment)
    if (this.requestResults.has(key) || this.commitments.has(key)) throw new BlindWalIntegrityError('Inbox CLOSE request commitment is duplicated')
    record.objectState = OBJECT_STATE.TOMBSTONE
    record.tombstoneReason = TOMBSTONE_REASON.OWNER_CLOSE
    record.terminalEpoch = value.committedEpoch
    record.stateRevision = value.newStateRevision
    record.closeResultBindingBytes = b4a.from(value.resultBindingBytes)
    record.closeClientNonce = b4a.from(value.clientNonce)
    record.closeRequestCommitment = b4a.from(value.requestCommitment)
    this.requestResults.set(key, {
      operation: 'close',
      transactionId: b4a.from(value.transactionId),
      requestCommitment: b4a.from(value.requestCommitment),
      physicalTopic: b4a.from(value.physicalTopic),
      resultIdentity: b4a.from(value.resultIdentity),
      resultRevision: value.newStateRevision,
      committedEpoch: value.committedEpoch,
      resultBindingBytes: b4a.from(value.resultBindingBytes),
      clientNonce: b4a.from(value.clientNonce),
      resultLeaseClass: 0,
      resultLeaseEpoch: value.oldLeaseEpoch
    })
    this.accounting.controlBytes += CONTROL_RECORD_BYTES
    this.#notifyTopic(hex(value.physicalTopic), true)
  }

  #applyAppend (frame, value) {
    this.#verifyBucket(frame, value.physicalTopic)
    const prepared = this.#assertSpendFresh(value, OPERATION.INBOX.APPEND)
    const topicKey = hex(value.physicalTopic)
    const record = this.inboxes.get(topicKey)
    if (!record || record.objectState !== OBJECT_STATE.PRESENT) throw new BlindWalIntegrityError('Inbox APPEND has no live record')
    if ((record.frameClassBits & (1 << (value.frameClass - 1))) === 0 ||
        value.appendRevision !== record.allocatedAppendRevision + 1n || value.appendLeaseEpoch !== record.leaseEpoch ||
        value.expiresAtEpoch !== Math.min(value.appendLeaseEpoch,
          value.committedEpoch + LEASE_EPOCHS[record.retentionClass])) {
      throw new BlindWalIntegrityError('Inbox APPEND class/revision/expiry transition is invalid')
    }
    const expected = resultIdentity(OPERATION.INBOX.APPEND, value.physicalTopic,
      value.requestCommitment, value.appendRevision, value.frameHash, value.committedEpoch)
    if (!equal(expected, value.resultIdentity)) throw new BlindWalIntegrityError('Inbox APPEND result identity mismatch')
    const key = frameKey(value.physicalTopic, value.appendRevision)
    if (this.frames.has(key)) throw new BlindWalIntegrityError('Inbox APPEND redefines a frame revision')
    const frameRecord = {
      physicalTopic: b4a.from(value.physicalTopic),
      appendRevision: value.appendRevision,
      frameHash: b4a.from(value.frameHash),
      frameClass: value.frameClass,
      frameVirtualBucket: frame.virtualBucket,
      frameObjectId: b4a.from(value.frameObjectId),
      appendLeaseEpoch: value.appendLeaseEpoch,
      storedAtEpoch: value.committedEpoch,
      expiresAtEpoch: value.expiresAtEpoch,
      spendTag: b4a.from(value.spendTag),
      requestCommitment: b4a.from(value.requestCommitment),
      resultIdentity: b4a.from(value.resultIdentity)
    }
    this.frames.set(key, frameRecord)
    this.framesByTopic.get(topicKey).set(value.appendRevision, frameRecord)
    record.allocatedAppendRevision = value.appendRevision
    record.frameCount++
    this.accounting.storedFrameBytes += INBOX_FRAME_CLASS[value.frameClass]
    this.accounting.frameIndexBytes += FRAME_INDEX_RECORD_BYTES
    this.#addSpend({
      status: 'append-provisional',
      transactionId: b4a.from(frame.transactionId),
      spendTag: b4a.from(value.spendTag),
      requestCommitment: b4a.from(value.requestCommitment),
      requestFingerprint: b4a.from(value.requestFingerprint),
      physicalTopic: b4a.from(value.physicalTopic),
      operation: OPERATION.INBOX.APPEND,
      profileId: prepared.profileId,
      frameClass: value.frameClass,
      frameHash: b4a.from(value.frameHash),
      requestedLeaseClass: 0,
      declaredBytes: INBOX_FRAME_CLASS[value.frameClass],
      deadlineUnixMillis: value.deadlineUnixMillis,
      remainingAttempts: 1,
      reservedEpoch: value.committedEpoch,
      resultIdentity: b4a.from(value.resultIdentity),
      resultRevision: value.appendRevision,
      committedEpoch: value.committedEpoch,
      resultCommitment: null,
      retryState: 0,
      resultBindingBytes: b4a.from(value.resultBindingBytes),
      clientNonce: b4a.from(value.clientNonce),
      retentionClassAtAppend: record.retentionClass,
      appendLeaseEpoch: value.appendLeaseEpoch,
      expiresAtEpoch: value.expiresAtEpoch,
      ackSignature: null,
      inFlight: false
    })
  }

  #appendAckBytes (spend, signature) {
    let relayBinding
    try {
      relayBinding = decodeCanonical(relayResultBindingV1, spend.resultBindingBytes, { copyBytes: true })
      if (!equal(encodeCanonical(relayResultBindingV1, relayBinding), spend.resultBindingBytes) ||
          relayBinding.durabilityProfileId !== 1 || relayBinding.externalCommitWitness != null ||
          !equal(relayBinding.relayPublicKey, this.relayPublicKey) ||
          !equal(relayBinding.durabilityContinuityHash, this.durabilityContinuityHash) ||
          (this.storeId && !equal(relayBinding.storeId, this.storeId)) ||
          (this.durabilityProfileHash && !equal(relayBinding.durabilityProfileHash, this.durabilityProfileHash))) {
        throw new Error('binding authority mismatch')
      }
    } catch (error) {
      throw new BlindWalIntegrityError(`Inbox APPEND ACK binding is invalid: ${error.message}`)
    }
    const value = {
      version: 1,
      relayBinding,
      topicCommitment: blake2b256(spend.physicalTopic),
      frameHash: b4a.from(spend.frameHash),
      appendRevision: spend.resultRevision,
      storedAtEpoch: spend.committedEpoch,
      expiresAtEpoch: spend.expiresAtEpoch,
      requestNonce: b4a.from(spend.clientNonce),
      requestCommitment: b4a.from(spend.requestCommitment),
      result: INBOX_APPEND_RESULT.STORED,
      signature: b4a.from(signature)
    }
    const body = encodeCanonical(inboxAppendAckV1, value)
    const unsigned = body.subarray(0, body.byteLength - sodium.crypto_sign_BYTES)
    if (!sodium.crypto_sign_verify_detached(value.signature,
      resultSignaturePayload(RESULT_SIGNATURE_DOMAIN_ID.INBOX_APPEND_ACK, unsigned),
      relayBinding.relayPublicKey)) {
      throw new BlindWalIntegrityError('Inbox APPEND ACK signature verification failed')
    }
    return body
  }

  #applyAppendAckFinalized (frame, value) {
    const spend = this.spends.get(hex(value.spendTag))
    if (!spend || spend.status !== 'append-provisional' || spend.operation !== OPERATION.INBOX.APPEND ||
        !equal(spend.requestCommitment, value.requestCommitment) || value.finalizedEpoch < spend.committedEpoch) {
      throw new BlindWalIntegrityError('Inbox APPEND ACK finalization has no exact provisional spend')
    }
    this.#verifyBucket(frame, spend.physicalTopic)
    const body = this.#appendAckBytes(spend, value.ackSignature)
    if (!equal(blake2b256(body), value.resultCommitment)) {
      throw new BlindWalIntegrityError('Inbox APPEND ACK result commitment mismatch')
    }
    spend.status = 'committed'
    spend.ackSignature = b4a.from(value.ackSignature)
    spend.resultCommitment = b4a.from(value.resultCommitment)
    const record = this.inboxes.get(hex(spend.physicalTopic))
    if (!record) throw new BlindWalIntegrityError('Inbox APPEND finalization lost its inbox record')
    const before = record.appendRevision
    while (record.appendRevision < record.allocatedAppendRevision) {
      const next = this.frames.get(frameKey(record.physicalTopic, record.appendRevision + 1n))
      if (!next) break
      const nextSpend = this.spends.get(hex(next.spendTag))
      if (!nextSpend || (nextSpend.status !== 'committed' && nextSpend.status !== 'expired-append')) break
      record.appendRevision++
    }
    if (record.appendRevision > before) this.#notifyTopic(hex(record.physicalTopic), false)
  }

  #applyReadPin (frame, value) {
    this.#verifyBucket(frame, value.physicalTopic)
    const prepared = this.#assertSpendFresh(value, value.operationId)
    const topicKey = hex(value.physicalTopic)
    const record = this.inboxes.get(topicKey)
    if (!record || record.objectState !== OBJECT_STATE.PRESENT) throw new BlindWalIntegrityError('Inbox read pin has no live inbox')
    let previous = 0n
    const pins = []
    for (const entry of value.entries) {
      if (entry.appendRevision <= previous || entry.appendRevision > value.snapshotRevision) {
        throw new BlindWalIntegrityError('Inbox read pin revisions are invalid')
      }
      const stored = this.frames.get(frameKey(value.physicalTopic, entry.appendRevision))
      if (!stored || !equal(stored.frameHash, entry.frameHash) || stored.frameClass !== entry.frameClass ||
          !equal(stored.frameObjectId, entry.frameObjectId)) {
        throw new BlindWalIntegrityError('Inbox read pin substitutes an immutable frame')
      }
      previous = entry.appendRevision
      pins.push({ appendRevision: entry.appendRevision, frameHash: b4a.from(entry.frameHash) })
    }
    const reconstruction = {
      version: 1,
      firstAppendRevision: value.entries.length === 0 ? 0n : value.entries[0].appendRevision,
      lastAppendRevision: value.entries.length === 0 ? 0n : value.entries[value.entries.length - 1].appendRevision,
      entryCount: value.entries.length,
      nextCursorHash: value.nextCursor == null ? b4a.from(ZERO32) : blake2b256(value.nextCursor)
    }
    const expectedSource = retrySourceCommitment(value.physicalTopic, value.snapshotRevision, reconstruction, pins)
    if (!equal(expectedSource, value.sourceCommitment)) throw new BlindWalIntegrityError('Inbox read pin source commitment mismatch')
    const spend = {
      status: 'reserved',
      transactionId: b4a.from(frame.transactionId),
      spendTag: b4a.from(value.spendTag),
      requestCommitment: b4a.from(value.requestCommitment),
      requestFingerprint: b4a.from(value.requestFingerprint),
      physicalTopic: b4a.from(value.physicalTopic),
      operation: value.operationId,
      profileId: prepared.profileId,
      frameClass: 0,
      frameHash: null,
      requestedLeaseClass: 0,
      declaredBytes: 0,
      deadlineUnixMillis: value.deadlineUnixMillis,
      remainingAttempts: 1,
      reservedEpoch: value.committedEpoch,
      resultIdentity: null,
      resultRevision: null,
      committedEpoch: null,
      resultCommitment: null,
      retryState: 0,
      resultBindingBytes: b4a.from(value.resultBindingBytes),
      clientNonce: b4a.from(value.clientNonce),
      inFlight: false
    }
    this.#addSpend(spend)
    this.retryPins.set(hex(value.spendTag), {
      spendTag: b4a.from(value.spendTag),
      requestCommitment: b4a.from(value.requestCommitment),
      physicalTopic: b4a.from(value.physicalTopic),
      operation: value.operationId,
      locatorCommitment: blake2b256(value.physicalTopic),
      sourceRevision: value.snapshotRevision,
      sourceCommitment: b4a.from(value.sourceCommitment),
      resultCommitment: null,
      reconstruction,
      retryExpiresMinute: value.retryExpiresMinute,
      retryState: 0,
      entries: pins,
      pinnedEntries: value.entries.map(cloneValue),
      entriesCommitment: b4a.from(value.entriesCommitment),
      nextCursor: cloneBytes(value.nextCursor),
      resultBindingBytes: b4a.from(value.resultBindingBytes),
      clientNonce: b4a.from(value.clientNonce),
      committedEpoch: value.committedEpoch
    })
    this.accounting.controlBytes += (1 + pins.length) * RETRY_RECORD_BYTES
  }

  #applyReadFinal (frame, value) {
    const spend = this.spends.get(hex(value.spendTag))
    const pin = this.retryPins.get(hex(value.spendTag))
    if (!spend || spend.status !== 'reserved' || !pin ||
        !equal(spend.requestCommitment, value.requestCommitment) ||
        !equal(pin.requestCommitment, value.requestCommitment) || value.finalizedEpoch < pin.committedEpoch) {
      throw new BlindWalIntegrityError('Inbox read finalization has no exact provisional pin')
    }
    this.#verifyBucket(frame, spend.physicalTopic)
    const expected = resultIdentity(spend.operation, spend.physicalTopic, spend.requestCommitment,
      pin.sourceRevision, value.resultCommitment, pin.committedEpoch)
    if (!equal(expected, value.resultIdentity)) throw new BlindWalIntegrityError('Inbox read final result identity mismatch')
    spend.status = 'committed'
    spend.resultIdentity = b4a.from(value.resultIdentity)
    spend.resultRevision = pin.sourceRevision
    spend.committedEpoch = pin.committedEpoch
    spend.resultCommitment = b4a.from(value.resultCommitment)
    spend.retryState = 1
    pin.resultCommitment = b4a.from(value.resultCommitment)
    pin.retryState = 1
  }

  #applyReadExpired (frame, value) {
    const spendKey = hex(value.spendTag)
    const spend = this.spends.get(spendKey)
    const pin = this.retryPins.get(spendKey)
    if (!spend || (spend.status !== 'committed' && spend.status !== 'reserved') || !pin ||
        !equal(spend.requestCommitment, value.requestCommitment) || pin.retryExpiresMinute !== value.retryExpiresMinute) {
      throw new BlindWalIntegrityError('Inbox retry expiry has no exact committed pin')
    }
    this.#verifyBucket(frame, spend.physicalTopic)
    if (spend.status === 'reserved') {
      spend.status = 'terminal'
      spend.terminalReason = 3
      spend.terminalEpoch = value.terminalEpoch
      spend.remainingAttempts = 0
    } else {
      spend.retryState = 3
    }
    this.retryPins.delete(spendKey)
    this.accounting.controlBytes -= (1 + pin.entries.length) * RETRY_RECORD_BYTES
  }

  #applyFloor (value) {
    if (value.oldEpochFloor !== this.epochFloor || value.newEpochFloor < value.oldEpochFloor ||
        (value.oldEpochFloor !== 0 && value.newEpochFloor - value.oldEpochFloor > 4)) {
      throw new BlindWalIntegrityError('Inbox epoch floor transition is invalid')
    }
    this.epochFloor = value.newEpochFloor
  }

  #applyAppendExpired (frame, value) {
    this.#verifyBucket(frame, value.physicalTopic)
    const key = frameKey(value.physicalTopic, value.appendRevision)
    const stored = this.frames.get(key)
    const spend = this.spends.get(hex(value.spendTag))
    if (!stored || !spend || spend.status !== 'committed' || spend.operation !== OPERATION.INBOX.APPEND ||
        !equal(spend.transactionId, value.transactionId) || !equal(stored.frameHash, value.frameHash) ||
        !equal(stored.frameObjectId, value.frameObjectId) || !equal(stored.spendTag, value.spendTag) ||
        !equal(stored.requestCommitment, value.requestCommitment) ||
        !equal(spend.requestFingerprint, value.requestFingerprint) || !equal(spend.physicalTopic, value.physicalTopic) ||
        spend.profileId !== value.profileId || spend.frameClass !== value.frameClass ||
        spend.declaredBytes !== value.declaredBytes || spend.deadlineUnixMillis !== value.deadlineUnixMillis ||
        spend.remainingAttempts !== value.remainingAttempts || spend.reservedEpoch !== value.reservedEpoch ||
        !equal(spend.resultIdentity, value.resultIdentity) || spend.resultRevision !== value.appendRevision ||
        spend.committedEpoch !== value.storedAtEpoch || spend.retentionClassAtAppend !== value.retentionClassAtAppend ||
        spend.appendLeaseEpoch !== value.appendLeaseEpoch || spend.expiresAtEpoch !== value.expiresAtEpoch ||
        !equal(spend.clientNonce, value.clientNonce) || !equal(spend.resultBindingBytes, value.resultBindingBytes) ||
        !equal(spend.ackSignature, value.ackSignature) || !equal(spend.resultCommitment, value.resultCommitment) ||
        value.declaredBytes !== INBOX_FRAME_CLASS[value.frameClass] ||
        value.expiresAtEpoch !== Math.min(value.appendLeaseEpoch,
          value.storedAtEpoch + LEASE_EPOCHS[value.retentionClassAtAppend]) ||
        value.expiresAtEpoch > value.expiredEpoch || this.#framePinned(stored)) {
      throw new BlindWalIntegrityError('Inbox APPEND expiry transition is invalid')
    }
    const ack = this.#appendAckBytes(spend, value.ackSignature)
    if (!equal(blake2b256(ack), value.resultCommitment)) {
      throw new BlindWalIntegrityError('Inbox expired APPEND ACK commitment mismatch')
    }
    spend.status = 'expired-append'
    spend.expiredEpoch = value.expiredEpoch
    this.frames.delete(key)
    const topicKey = hex(value.physicalTopic)
    this.framesByTopic.get(topicKey)?.delete(value.appendRevision)
    const inbox = this.inboxes.get(topicKey)
    if (inbox) inbox.frameCount--
    this.accounting.storedFrameBytes -= INBOX_FRAME_CLASS[stored.frameClass]
    this.accounting.frameIndexBytes -= FRAME_INDEX_RECORD_BYTES
  }

  #applyInboxGc (frame, value) {
    this.#verifyBucket(frame, value.physicalTopic)
    const record = this.inboxes.get(hex(value.physicalTopic))
    if (!record || record.objectState !== OBJECT_STATE.PRESENT || record.stateRevision !== value.oldStateRevision ||
        record.leaseEpoch !== value.expectedLeaseEpoch || value.newStateRevision !== value.oldStateRevision + 1n ||
        value.terminalEpoch <= record.leaseEpoch) {
      throw new BlindWalIntegrityError('Inbox lease GC transition is invalid')
    }
    record.objectState = OBJECT_STATE.TOMBSTONE
    record.tombstoneReason = TOMBSTONE_REASON.EXPIRED_GC
    record.terminalEpoch = value.terminalEpoch
    record.stateRevision = value.newStateRevision
    this.#notifyTopic(hex(value.physicalTopic), true)
  }

  #applyPolicy (frame, value) {
    this.#verifyBucket(frame, value.physicalTopic)
    const record = this.inboxes.get(hex(value.physicalTopic))
    if (!record || record.policyRevision !== value.oldPolicyRevision ||
        value.newPolicyRevision !== value.oldPolicyRevision + 1n) {
      throw new BlindWalIntegrityError('Inbox policy transition is invalid')
    }
    record.policyRevision = value.newPolicyRevision
    record.policyState = value.policyState
    if (value.policyState === POLICY_STATE.SUPPRESSED) this.#notifyTopic(hex(value.physicalTopic), true)
  }

  #applyIntegrity (value) {
    if (value.detectedEpoch > this.epochFloor || isZero(value.evidenceHash)) {
      throw new BlindWalIntegrityError('Inbox integrity evidence is invalid')
    }
    if (!this.integrityEvidence.some(entry => equal(entry.evidenceHash, value.evidenceHash))) {
      this.integrityEvidence.push({ reason: value.reason, detectedEpoch: value.detectedEpoch, evidenceHash: b4a.from(value.evidenceHash) })
    }
    this.readOnlyReason = 'RECOVERY_GAP_READ_ONLY'
  }

  #assertAccounting () {
    for (const [field, value] of Object.entries(this.accounting)) {
      if (field === 'stagingByProfile') continue
      if (!Number.isSafeInteger(value) || value < 0) throw new BlindWalIntegrityError(`Inbox ${field} accounting is invalid`)
    }
    for (const value of this.accounting.stagingByProfile.values()) {
      if (!Number.isSafeInteger(value) || value <= 0) throw new BlindWalIntegrityError('Inbox profile staging accounting is invalid')
    }
  }

  #publiclyVisible (record) {
    return Boolean(record && record.objectState === OBJECT_STATE.PRESENT &&
      record.policyState === POLICY_STATE.VISIBLE && record.leaseEpoch >= this.epochFloor)
  }

  #topicLocks (physicalTopic, prepared = null, requestCommitment = null) {
    const keys = [`inbox:${hex(physicalTopic)}`]
    if (prepared) keys.push(`spend:${hex(prepared.value.spendTag)}`, `commitment:${hex(prepared.value.requestCommitment)}`)
    if (requestCommitment) keys.push(`commitment:${hex(requestCommitment)}`)
    return keys
  }

  #spendDisposition (prepared, operationId) {
    const spend = this.spends.get(hex(prepared.value.spendTag))
    const commitment = this.commitments.get(hex(prepared.value.requestCommitment))
    if (!spend && !commitment) return { kind: 'fresh' }
    if (!spend || !commitment || commitment.spendKey !== hex(prepared.value.spendTag) ||
        spend.operation !== operationId || !equal(spend.requestCommitment, prepared.value.requestCommitment)) {
      return { kind: 'conflict' }
    }
    if (spend.status === 'terminal') return { kind: 'terminal' }
    if (spend.status === 'committed' || spend.status === 'append-provisional' ||
        spend.status === 'expired-append') return { kind: 'replay', spend }
    return { kind: 'reserved', spend }
  }

  status () {
    return Object.freeze({
      ...BLIND_INBOX_STORAGE_STATUS,
      opened: this.opened,
      epochFloor: this.epochFloor,
      clockUnsafe: this.clockUnsafe,
      readOnlyReason: this.readOnlyReason,
      walSequence: this.transactionStore.walSequence,
      walHash: b4a.from(this.transactionStore.walHash),
      inboxCount: this.inboxes.size,
      frameCount: this.frames.size,
      waiterCount: this.waiterCount,
      accounting: Object.freeze({ ...this.accounting, stagingByProfile: new Map(this.accounting.stagingByProfile) })
    })
  }

  inspectInboxState (physicalTopic) {
    this.#assertOpen()
    physicalTopic = fixed(physicalTopic, 32, 'physicalTopic', true)
    const record = this.inboxes.get(hex(physicalTopic))
    if (!this.#publiclyVisible(record)) return null
    return Object.freeze({ publiclyVisible: true, inbox: publicInbox(record) })
  }

  preparedInboxOperationState (input) {
    this.#assertOpen()
    const prepared = preparedView(input.preparedAdmission)
    if (!equal(prepared.value.requestCommitment, fixed(input.requestCommitment, 32, 'requestCommitment', true))) {
      fail('SPEND_INVALID', 'prepared admission does not match requestCommitment')
    }
    return spendViewOrFresh(this.#spendDisposition(prepared, input.operationId))
  }

  closeRequestState (requestCommitment) {
    this.#assertOpen()
    requestCommitment = fixed(requestCommitment, 32, 'requestCommitment', true)
    return this.requestResults.has(hex(requestCommitment))
      ? Object.freeze({ kind: 'replay' })
      : Object.freeze({ kind: 'fresh' })
  }

  verifyManagementCapability (input) {
    this.#assertOpen()
    const record = this.inboxes.get(hex(fixed(input.physicalTopic, 32, 'physicalTopic', true)))
    if (!record) return false
    const operationId = input.operationId
    const publicKey = operationId === OPERATION.INBOX.RENEW ? record.renewPublicKey : record.closePublicKey
    return verifyEd25519(publicKey, fixed(input.requestCommitment, 32, 'requestCommitment', true), input.signature)
  }

  verifyAppendCapability (input) {
    this.#assertOpen()
    const record = this.inboxes.get(hex(fixed(input.physicalTopic, 32, 'physicalTopic', true)))
    if (!record) return false
    if (record.appendAuthMode === 0) return input.signature == null
    return input.signature != null && verifyEd25519(record.appendPublicKey,
      fixed(input.requestCommitment, 32, 'requestCommitment', true), input.signature)
  }

  checkCapacity (input) {
    this.#assertOpen()
    const operationId = input.operationId
    if (operationId === OPERATION.INBOX.CREATE) {
      if (this.inboxes.size >= this.quota.maxInboxes ||
          this.accounting.tombstoneBytes + TOMBSTONE_RECORD_BYTES > this.quota.maxTombstoneBytes ||
          this.accounting.controlBytes + CONTROL_RECORD_BYTES > this.quota.maxControlBytes) {
        fail('BUSY', 'Inbox CREATE capacity is full', true)
      }
      return true
    }
    if (operationId === OPERATION.INBOX.APPEND) {
      const frameBytes = INBOX_FRAME_CLASS[input.request.frameClass]
      const record = this.inboxes.get(hex(input.request.physicalTopic))
      if (!record || record.frameCount >= this.quota.maxFramesPerTopic || this.frames.size >= this.quota.maxFrames ||
          this.accounting.storedFrameBytes + this.accounting.stagingFrameBytes + frameBytes > this.quota.maxStoredFrameBytes ||
          this.accounting.stagingFrameBytes + frameBytes > this.quota.maxStagingFrameBytes ||
          this.accounting.frameIndexBytes + FRAME_INDEX_RECORD_BYTES > this.quota.maxFrameIndexBytes ||
          this.accounting.controlBytes + CONTROL_RECORD_BYTES > this.quota.maxControlBytes) {
        fail('BUSY', 'Inbox APPEND capacity is full', true)
      }
      const profileId = input.preparedAdmission?.profileId
      if (Number.isInteger(profileId) && (this.accounting.stagingByProfile.get(profileId) || 0) + frameBytes >
          this.quota.maxStagingFrameBytesPerProfile) fail('BUSY', 'Inbox profile staging capacity is full', true)
      return true
    }
    if ((operationId === OPERATION.INBOX.READ || operationId === OPERATION.INBOX.WATCH) && input.preparedAdmission) {
      const maximumPins = 1 + Math.min(64, input.request.limit)
      if (this.accounting.controlBytes + maximumPins * RETRY_RECORD_BYTES + CONTROL_RECORD_BYTES >
          this.quota.maxControlBytes) fail('BUSY', 'Inbox retry-pin capacity is full', true)
    }
    return true
  }

  createInbox (input) {
    return this.#runOperation(() => this.#createInbox(input))
  }

  async #createInbox (input) {
    this.#assertWritable(true)
    const request = input.request
    const prepared = preparedView(input.preparedAdmission)
    if (!equal(prepared.value.requestCommitment, fixed(input.requestCommitment, 32, 'requestCommitment', true))) {
      fail('SPEND_INVALID', 'CREATE prepared admission does not match request')
    }
    const topic = fixed(request.physicalTopic, 32, 'physicalTopic', true)
    return this.transactionStore.withLocks(this.#topicLocks(topic, prepared), async () => {
      const disposition = this.#spendDisposition(prepared, OPERATION.INBOX.CREATE)
      const existing = this.inboxes.get(hex(topic))
      if (disposition.kind === 'conflict') fail('SPEND_REPLAY', 'CREATE spend conflicts with another request')
      if (disposition.kind === 'terminal') fail('RETRY_TERMINAL', 'CREATE spend is terminal')
      if (disposition.kind === 'replay') {
        if (!this.#publiclyVisible(existing)) fail('NOT_FOUND', 'inbox is absent')
        return this.#mutationResult(disposition.spend, existing)
      }
      if (existing) fail('CONFLICT', 'physical topic already exists')
      this.checkCapacity({ operationId: OPERATION.INBOX.CREATE, request, preparedAdmission: input.preparedAdmission })
      const nowMillis = this.nowUnixMillis()
      const committedEpoch = this.epochFloor
      const base = operationSpendBase(OPERATION.INBOX.CREATE, prepared, request, nowMillis, committedEpoch)
      const createCommitment = inboxCreateCommitment({ ...request, relayPublicKey: this.relayPublicKey })
      const leaseEpoch = Math.min(MAX_U32, committedEpoch + LEASE_EPOCHS[request.leaseClass])
      const bindingBytes = this.#resultBindingBytes(input.resultBinding)
      const identity = resultIdentity(OPERATION.INBOX.CREATE, topic, prepared.value.requestCommitment,
        0n, createCommitment, committedEpoch)
      await this.#appendAndApply(BLIND_INBOX_WAL_TYPE.CREATE_COMMITTED,
        this.transactionStore.newTransactionId(), this.transactionStore.virtualBucket(BLIND_STORE_SERVICE_TAG.INBOX, topic), {
          version: 1,
          ...base,
          resultBindingBytes: bindingBytes,
          allocationEpoch: request.allocationEpoch,
          physicalTopic: topic,
          frameClassBits: request.frameClassBits,
          appendAuthMode: request.appendAuthMode,
          appendPublicKey: request.appendPublicKey,
          createPublicKey: request.createPublicKey,
          renewPublicKey: request.renewPublicKey,
          closePublicKey: request.closePublicKey,
          retentionClass: request.retentionClass,
          leaseClass: request.leaseClass,
          clientNonce: request.clientNonce,
          createCommitment,
          leaseEpoch,
          resultIdentity: identity
        })
      return this.#mutationResult(this.spends.get(hex(prepared.value.spendTag)), this.inboxes.get(hex(topic)))
    })
  }

  renewInbox (input) {
    return this.#runOperation(() => this.#renewInbox(input))
  }

  async #renewInbox (input) {
    this.#assertWritable(true)
    const request = input.request
    const topic = fixed(request.physicalTopic, 32, 'physicalTopic', true)
    const prepared = preparedView(input.preparedAdmission)
    return this.transactionStore.withLocks(this.#topicLocks(topic, prepared), async () => {
      const disposition = this.#spendDisposition(prepared, OPERATION.INBOX.RENEW)
      const record = this.inboxes.get(hex(topic))
      if (disposition.kind === 'conflict') fail('SPEND_REPLAY', 'RENEW spend conflicts with another request')
      if (disposition.kind === 'terminal') fail('RETRY_TERMINAL', 'RENEW spend is terminal')
      if (disposition.kind === 'replay') {
        if (!this.#publiclyVisible(record)) fail('NOT_FOUND', 'inbox is absent')
        return this.#mutationResult(disposition.spend, record)
      }
      this.#assertManagementCas(record, request)
      const target = Math.min(MAX_U32, Math.max(record.leaseEpoch,
        this.epochFloor + LEASE_EPOCHS[request.leaseClass]))
      if (target === record.leaseEpoch) renewNotDue(Math.max(this.epochFloor + 1, record.leaseEpoch - LEASE_EPOCHS[request.leaseClass] + 1))
      const base = operationSpendBase(OPERATION.INBOX.RENEW, prepared, request, this.nowUnixMillis(), this.epochFloor)
      const newRevision = record.stateRevision + 1n
      const bindingBytes = this.#resultBindingBytes(input.resultBinding)
      const identity = resultIdentity(OPERATION.INBOX.RENEW, topic, prepared.value.requestCommitment,
        newRevision, record.createCommitment, this.epochFloor)
      await this.#appendAndApply(BLIND_INBOX_WAL_TYPE.RENEW_COMMITTED,
        this.transactionStore.newTransactionId(), record.metadataVirtualBucket, {
          version: 1,
          ...base,
          resultBindingBytes: bindingBytes,
          physicalTopic: topic,
          oldStateRevision: record.stateRevision,
          newStateRevision: newRevision,
          oldLeaseEpoch: record.leaseEpoch,
          newLeaseEpoch: target,
          leaseClass: request.leaseClass,
          clientNonce: request.clientNonce,
          resultIdentity: identity
        })
      return this.#mutationResult(this.spends.get(hex(prepared.value.spendTag)), record)
    })
  }

  closeInbox (input) {
    return this.#runOperation(() => this.#closeInbox(input))
  }

  async #closeInbox (input) {
    this.#assertWritable(false)
    const request = input.request
    const topic = fixed(request.physicalTopic, 32, 'physicalTopic', true)
    const requestCommitment = fixed(input.requestCommitment, 32, 'requestCommitment', true)
    return this.transactionStore.withLocks(this.#topicLocks(topic, null, requestCommitment), async () => {
      const prior = this.requestResults.get(hex(requestCommitment))
      const record = this.inboxes.get(hex(topic))
      if (prior) return this.#closeResult(prior, record)
      this.#assertManagementCas(record, request)
      const newRevision = record.stateRevision + 1n
      const identity = resultIdentity(OPERATION.INBOX.CLOSE, topic, requestCommitment,
        newRevision, record.createCommitment, this.epochFloor)
      const transactionId = this.transactionStore.newTransactionId()
      await this.#appendAndApply(BLIND_INBOX_WAL_TYPE.CLOSE_COMMITTED,
        transactionId, record.metadataVirtualBucket, {
          version: 1,
          transactionId,
          requestCommitment,
          requestFingerprint: blake2b256(b4a.concat([requestCommitment, request.clientNonce])),
          physicalTopic: topic,
          oldStateRevision: record.stateRevision,
          newStateRevision: newRevision,
          oldLeaseEpoch: record.leaseEpoch,
          clientNonce: request.clientNonce,
          committedEpoch: this.epochFloor,
          resultBindingBytes: this.#resultBindingBytes(input.resultBinding),
          resultIdentity: identity
        })
      return this.#closeResult(this.requestResults.get(hex(requestCommitment)), record)
    })
  }

  #assertManagementCas (record, request) {
    if (!this.#publiclyVisible(record)) fail('NOT_FOUND', 'inbox is absent')
    if (record.stateRevision !== u64(request.expectedRevision, 'expectedRevision') ||
        record.leaseEpoch !== integer(request.expectedLeaseEpoch, 0, MAX_U32, 'expectedLeaseEpoch')) {
      fail('STALE_REVISION', 'Inbox management CAS is stale')
    }
  }

  appendFrame (input) {
    return this.#runOperation(() => this.#appendFrame(input))
  }

  async #appendFrame (input) {
    this.#assertWritable(true)
    const request = input.request
    const topic = fixed(request.physicalTopic, 32, 'physicalTopic', true)
    const prepared = preparedView(input.preparedAdmission)
    const frameBytes = fixed(request.frame, INBOX_FRAME_CLASS[request.frameClass], 'frame')
    if (!equal(blake2b256(frameBytes), request.frameHash)) fail('CONFLICT', 'frame bytes do not match frameHash')
    return this.transactionStore.withLocks(this.#topicLocks(topic, prepared), async () => {
      const disposition = this.#spendDisposition(prepared, OPERATION.INBOX.APPEND)
      const record = this.inboxes.get(hex(topic))
      if (disposition.kind === 'conflict') fail('SPEND_REPLAY', 'APPEND spend conflicts with another request')
      if (disposition.kind === 'terminal') fail('RETRY_TERMINAL', 'APPEND spend is terminal')
      if (disposition.kind === 'replay') {
        if (disposition.spend.status === 'expired-append') {
          if (!equal(disposition.spend.frameHash, request.frameHash)) {
            fail('CONFLICT', 'expired APPEND retry changed frame identity')
          }
          return this.#appendResult(disposition.spend, {
            physicalTopic: disposition.spend.physicalTopic,
            frameHash: disposition.spend.frameHash,
            appendRevision: disposition.spend.resultRevision,
            storedAtEpoch: disposition.spend.committedEpoch,
            expiresAtEpoch: disposition.spend.expiresAtEpoch
          })
        }
        const storedFrame = this.frames.get(frameKey(topic, disposition.spend.resultRevision))
        if (!storedFrame || !equal(storedFrame.frameHash, request.frameHash)) fail('CONFLICT', 'APPEND retry changed frame identity')
        const observed = await this.transactionStore.readOpaque({
          virtualBucket: storedFrame.frameVirtualBucket,
          objectId: storedFrame.frameObjectId
        }, INBOX_FRAME_CLASS[storedFrame.frameClass], storedFrame.frameHash)
        if (!equal(observed, frameBytes)) fail('CONFLICT', 'APPEND retry changed exact frame bytes')
        return this.#appendResult(disposition.spend, storedFrame)
      }
      if (!this.#publiclyVisible(record)) fail('NOT_FOUND', 'inbox is absent')
      if ((record.frameClassBits & (1 << (request.frameClass - 1))) === 0) fail('TOO_LARGE', 'frame class is not enabled by this inbox')
      this.checkCapacity({ operationId: OPERATION.INBOX.APPEND, request, preparedAdmission: input.preparedAdmission })
      const profileId = prepared.value.profileId
      this.#addStaging(profileId, frameBytes.byteLength)
      let staged
      let published
      try {
        staged = await this.transactionStore.stageOpaque({
          expectedLength: frameBytes.byteLength,
          expectedHash: request.frameHash,
          source: (async function * () { yield frameBytes })(),
          deadlineUnixMillis: u64(this.nowUnixMillis(), 'nowUnixMillis') + 15_000n,
          nowUnixMillis: this.nowUnixMillis,
          signal: input.signal
        })
        published = await this.transactionStore.publishOpaque(staged, record.metadataVirtualBucket)
        staged = null
        const base = operationSpendBase(OPERATION.INBOX.APPEND, prepared, request, this.nowUnixMillis(), this.epochFloor)
        const revision = record.allocatedAppendRevision + 1n
        const expires = Math.min(record.leaseEpoch, this.epochFloor + LEASE_EPOCHS[record.retentionClass])
        if (expires <= this.epochFloor) fail('EXPIRED', 'inbox lease does not permit a new retained frame')
        const identity = resultIdentity(OPERATION.INBOX.APPEND, topic, prepared.value.requestCommitment,
          revision, request.frameHash, this.epochFloor)
        await this.#appendAndApply(BLIND_INBOX_WAL_TYPE.APPEND_COMMITTED,
          this.transactionStore.newTransactionId(), record.metadataVirtualBucket, {
            version: 1,
            ...base,
            resultBindingBytes: this.#resultBindingBytes(input.resultBinding),
            physicalTopic: topic,
            frameClass: request.frameClass,
            frameHash: request.frameHash,
            frameObjectId: published.objectId,
            clientNonce: request.clientNonce,
            appendRevision: revision,
            appendLeaseEpoch: record.leaseEpoch,
            expiresAtEpoch: expires,
            resultIdentity: identity
          })
        return this.#appendResult(this.spends.get(hex(prepared.value.spendTag)), this.frames.get(frameKey(topic, revision)))
      } catch (error) {
        if (staged) await this.transactionStore.discardStaged(staged).catch(() => {})
        throw error
      } finally {
        this.#removeStaging(profileId, frameBytes.byteLength)
      }
    })
  }

  #addStaging (profileId, bytes) {
    this.accounting.stagingFrameBytes += bytes
    this.accounting.reservedFrames++
    this.accounting.stagingByProfile.set(profileId, (this.accounting.stagingByProfile.get(profileId) || 0) + bytes)
  }

  #removeStaging (profileId, bytes) {
    this.accounting.stagingFrameBytes -= bytes
    this.accounting.reservedFrames--
    const next = (this.accounting.stagingByProfile.get(profileId) || 0) - bytes
    if (next === 0) this.accounting.stagingByProfile.delete(profileId)
    else this.accounting.stagingByProfile.set(profileId, next)
  }

  #mutationResult (spend, record) {
    return Object.freeze({
      replay: true,
      receiptEpoch: spend.committedEpoch,
      resultBindingBytes: b4a.from(spend.resultBindingBytes),
      clientNonce: b4a.from(spend.clientNonce),
      requestCommitment: b4a.from(spend.requestCommitment),
      stateRevision: spend.resultRevision,
      leaseClass: spend.resultLeaseClass,
      leaseEpoch: spend.resultLeaseEpoch,
      inbox: publicInbox(record)
    })
  }

  #closeResult (result, record) {
    return Object.freeze({
      replay: true,
      receiptEpoch: result.committedEpoch,
      resultBindingBytes: b4a.from(result.resultBindingBytes),
      clientNonce: b4a.from(result.clientNonce),
      requestCommitment: b4a.from(result.requestCommitment),
      stateRevision: result.resultRevision,
      leaseClass: result.resultLeaseClass,
      leaseEpoch: result.resultLeaseEpoch,
      inbox: publicInbox(record)
    })
  }

  #appendResult (spend, frame) {
    return Object.freeze({
      replay: true,
      receiptEpoch: spend.committedEpoch,
      resultBindingBytes: b4a.from(spend.resultBindingBytes),
      clientNonce: b4a.from(spend.clientNonce),
      requestCommitment: b4a.from(spend.requestCommitment),
      spendTag: b4a.from(spend.spendTag),
      ackSignature: cloneBytes(spend.ackSignature),
      resultCommitment: cloneBytes(spend.resultCommitment),
      frame: cloneValue(frame)
    })
  }

  finalizeAppendAck (input) {
    return this.#runOperation(async () => {
      this.#assertWritable(false)
      const spendTag = fixed(input.spendTag, 32, 'spendTag', true)
      const requestCommitment = fixed(input.requestCommitment, 32, 'requestCommitment', true)
      const ackSignature = fixed(input.ackSignature, sodium.crypto_sign_BYTES, 'ackSignature', true)
      const resultCommitment = fixed(input.resultCommitment, 32, 'resultCommitment', true)
      return this.transactionStore.withLocks([`spend:${hex(spendTag)}`], async () => {
        const spend = this.spends.get(hex(spendTag))
        if (!spend || spend.operation !== OPERATION.INBOX.APPEND ||
            !equal(spend.requestCommitment, requestCommitment)) {
          fail('SPEND_REPLAY', 'Inbox APPEND finalization does not match its spend')
        }
        if (spend.status === 'committed' || spend.status === 'expired-append') {
          if (!equal(spend.ackSignature, ackSignature) || !equal(spend.resultCommitment, resultCommitment)) {
            fail('CONFLICT', 'Inbox APPEND retry changed its signed acknowledgement')
          }
          return true
        }
        if (spend.status !== 'append-provisional') fail('RETRY_TERMINAL', 'Inbox APPEND cannot be finalized')
        const body = this.#appendAckBytes(spend, ackSignature)
        if (!equal(blake2b256(body), resultCommitment)) {
          fail('CONFLICT', 'Inbox APPEND result commitment does not match signed acknowledgement')
        }
        await this.#appendAndApply(BLIND_INBOX_WAL_TYPE.APPEND_ACK_FINALIZED,
          this.transactionStore.newTransactionId(),
          this.transactionStore.virtualBucket(BLIND_STORE_SERVICE_TAG.INBOX, spend.physicalTopic), {
            version: 1,
            spendTag,
            requestCommitment,
            ackSignature,
            resultCommitment,
            finalizedEpoch: this.epochFloor
          })
        return true
      })
    })
  }

  readPage (input) {
    return this.#runOperation(() => this.#readPage(input, false))
  }

  async #readPage (input, watch) {
    this.#assertOpen()
    const request = input.request
    const topic = fixed(request.physicalTopic, 32, 'physicalTopic', true)
    return this.transactionStore.withLocks([`inbox:${hex(topic)}`], async () => {
      const record = this.inboxes.get(hex(topic))
      if (!this.#publiclyVisible(record)) fail('NOT_FOUND', 'inbox is absent')
      const cursor = watch
        ? { lastPosition: u64(request.afterRevision, 'afterRevision'), snapshotRevision: record.appendRevision, expiryMinute: minuteFromMillis(this.nowUnixMillis()) + CURSOR_MINUTES }
        : this.#decodeReadCursor(topic, request.cursor, record.appendRevision)
      return this.#materializePage(record, cursor, request.limit)
    })
  }

  watchPage (input) {
    return this.#runOperation(() => this.#watchPage(input))
  }

  async #watchPage (input) {
    this.#assertOpen()
    const request = input.request
    const topic = fixed(request.physicalTopic, 32, 'physicalTopic', true)
    const topicKey = hex(topic)
    let wait = null
    await this.transactionStore.withLocks([`inbox:${topicKey}`], async () => {
      const record = this.inboxes.get(topicKey)
      if (!this.#publiclyVisible(record)) fail('NOT_FOUND', 'inbox is absent')
      if (record.appendRevision <= u64(request.afterRevision, 'afterRevision')) wait = this.#registerWaiter(topicKey, request.maxWaitMillis, input.signal)
    })
    if (wait) await wait
    return this.#readPage(input, true)
  }

  #registerWaiter (topicKey, maxWaitMillis, signal) {
    if (signal && signal.aborted) {
      const error = new Error('Inbox WATCH aborted')
      error.code = 'ABORT_ERR'
      throw error
    }
    if (this.waiterCount >= this.quota.maxGlobalWaiters) fail('BUSY', 'global Inbox WATCH waiter capacity is full', true)
    const topic = this.waitersByTopic.get(topicKey) || new Set()
    if (topic.size >= this.quota.maxWaitersPerTopic) fail('BUSY', 'topic Inbox WATCH waiter capacity is full', true)
    let done = false
    let timer
    let abort
    const waiter = { finish: null }
    const promise = new Promise((resolve, reject) => {
      const finish = (error = null) => {
        if (done) return
        done = true
        clearTimeout(timer)
        if (signal && abort) signal.removeEventListener('abort', abort)
        topic.delete(waiter)
        this.waiterCount--
        if (topic.size === 0) this.waitersByTopic.delete(topicKey)
        if (error) reject(error)
        else resolve()
      }
      waiter.finish = finish
      timer = setTimeout(finish, integer(maxWaitMillis, 1, 30000, 'maxWaitMillis'))
      abort = () => {
        const error = new Error('Inbox WATCH aborted')
        error.code = 'ABORT_ERR'
        finish(error)
      }
      if (signal) {
        signal.addEventListener('abort', abort, { once: true })
      }
    })
    topic.add(waiter)
    this.waitersByTopic.set(topicKey, topic)
    this.waiterCount++
    return promise
  }

  #notifyTopic (topicKey, closed) {
    const waiters = this.waitersByTopic.get(topicKey)
    if (!waiters) return
    for (const waiter of [...waiters]) {
      if (closed) {
        const error = new BlindInboxStorageError('NOT_FOUND', 'inbox closed while WATCH was waiting')
        waiter.finish(error)
      } else waiter.finish()
    }
  }

  #decodeReadCursor (topic, raw, currentRevision) {
    if (!raw || raw.byteLength === 0) {
      return { lastPosition: 0n, snapshotRevision: currentRevision, expiryMinute: minuteFromMillis(this.nowUnixMillis()) + CURSOR_MINUTES }
    }
    const cursor = fixed(raw, CURSOR_BYTES, 'cursor')
    if (!equal(cursor.subarray(0, 4), CURSOR_MAGIC) || !equal(cursor.subarray(4, 36), topic)) {
      fail('BAD_ENCODING', 'Inbox cursor has the wrong version or topic')
    }
    const prefix = cursor.subarray(0, 60)
    const expected = createHmac('sha256', this.cursorKey).update(CURSOR_DOMAIN).update(prefix).digest()
    if (!equal(expected, cursor.subarray(60))) fail('BAD_ENCODING', 'Inbox cursor authentication failed')
    const lastPosition = readU64be(cursor, 36)
    const snapshotRevision = readU64be(cursor, 44)
    const expiryMinute = readU64be(cursor, 52)
    const nowMinute = minuteFromMillis(this.nowUnixMillis())
    if (expiryMinute < nowMinute) fail('EXPIRED', 'Inbox cursor expired')
    if (expiryMinute > nowMinute + CURSOR_MINUTES || lastPosition > snapshotRevision || snapshotRevision > currentRevision) {
      fail('BAD_ENCODING', 'Inbox cursor snapshot tuple is invalid')
    }
    return { lastPosition, snapshotRevision, expiryMinute }
  }

  #encodeCursor (topic, lastPosition, snapshotRevision, expiryMinute) {
    const cursor = b4a.alloc(CURSOR_BYTES)
    b4a.copy(CURSOR_MAGIC, cursor, 0)
    b4a.copy(topic, cursor, 4)
    b4a.copy(u64bytes(lastPosition), cursor, 36)
    b4a.copy(u64bytes(snapshotRevision), cursor, 44)
    b4a.copy(u64bytes(expiryMinute), cursor, 52)
    b4a.copy(createHmac('sha256', this.cursorKey).update(CURSOR_DOMAIN).update(cursor.subarray(0, 60)).digest(), cursor, 60)
    return cursor
  }

  async #materializePage (record, cursor, limit) {
    limit = integer(limit, 1, 64, 'limit')
    const topicFrames = this.framesByTopic.get(hex(record.physicalTopic)) || new Map()
    const candidates = [...topicFrames.values()]
      .filter(frame => frame.appendRevision > cursor.lastPosition && frame.appendRevision <= cursor.snapshotRevision &&
        frame.expiresAtEpoch > this.epochFloor &&
        this.spends.get(hex(frame.spendTag))?.status === 'committed')
      .sort((left, right) => left.appendRevision < right.appendRevision ? -1 : 1)
    const selected = candidates.slice(0, limit)
    const entries = []
    for (const frame of selected) {
      const bytes = await this.transactionStore.readOpaque({
        virtualBucket: frame.frameVirtualBucket,
        objectId: frame.frameObjectId
      }, INBOX_FRAME_CLASS[frame.frameClass], frame.frameHash)
      entries.push({
        appendRevision: frame.appendRevision,
        frameHash: b4a.from(frame.frameHash),
        frameClass: frame.frameClass,
        frame: bytes,
        frameObjectId: b4a.from(frame.frameObjectId)
      })
    }
    const last = selected.length === 0 ? cursor.lastPosition : selected[selected.length - 1].appendRevision
    const nextCursor = candidates.length > selected.length
      ? this.#encodeCursor(record.physicalTopic, last, cursor.snapshotRevision, cursor.expiryMinute)
      : null
    return Object.freeze({
      physicalTopic: b4a.from(record.physicalTopic),
      snapshotRevision: cursor.snapshotRevision,
      entries: entries.map(Object.freeze),
      nextCursor,
      cursorExpiryMinute: cursor.expiryMinute
    })
  }

  pinChargedPage (input) {
    return this.#runOperation(() => this.#pinChargedPage(input))
  }

  async #pinChargedPage (input) {
    this.#assertWritable(false)
    const request = input.request
    const operationId = input.operationId
    const topic = fixed(request.physicalTopic, 32, 'physicalTopic', true)
    const prepared = preparedView(input.preparedAdmission)
    if (operationId === OPERATION.INBOX.WATCH) await this.#waitUntilWatchReady(topic, request, input.signal)
    return this.transactionStore.withLocks(this.#topicLocks(topic, prepared), async () => {
      const disposition = this.#spendDisposition(prepared, operationId)
      const record = this.inboxes.get(hex(topic))
      if (!this.#publiclyVisible(record)) fail('NOT_FOUND', 'inbox is absent')
      if (disposition.kind === 'conflict') fail('SPEND_REPLAY', 'charged Inbox read spend conflicts')
      if (disposition.kind === 'terminal') fail('RETRY_TERMINAL', 'charged Inbox read retry is terminal')
      if (disposition.kind === 'replay' || disposition.kind === 'reserved') return this.#pinnedPage(prepared.value.spendTag)
      const cursor = operationId === OPERATION.INBOX.WATCH
        ? {
            lastPosition: u64(request.afterRevision, 'afterRevision'),
            snapshotRevision: record.appendRevision,
            expiryMinute: minuteFromMillis(this.nowUnixMillis()) + CURSOR_MINUTES
          }
        : this.#decodeReadCursor(topic, request.cursor, record.appendRevision)
      const page = await this.#materializePage(record, cursor, request.limit)
      const entriesCommitment = inboxEntriesCommitment(page.entries)
      const pins = page.entries.map(entry => ({ appendRevision: entry.appendRevision, frameHash: entry.frameHash }))
      const reconstruction = {
        version: 1,
        firstAppendRevision: page.entries.length === 0 ? 0n : page.entries[0].appendRevision,
        lastAppendRevision: page.entries.length === 0 ? 0n : page.entries[page.entries.length - 1].appendRevision,
        entryCount: page.entries.length,
        nextCursorHash: page.nextCursor == null ? b4a.from(ZERO32) : blake2b256(page.nextCursor)
      }
      const sourceCommitment = retrySourceCommitment(topic, page.snapshotRevision, reconstruction, pins)
      const base = operationSpendBase(operationId, prepared, request, this.nowUnixMillis(), this.epochFloor)
      const retryExpiresMinute = minuteFromMillis(this.nowUnixMillis()) + CURSOR_MINUTES
      await this.#appendAndApply(BLIND_INBOX_WAL_TYPE.READ_PIN_COMMITTED,
        this.transactionStore.newTransactionId(), record.metadataVirtualBucket, {
          version: 1,
          operationId,
          ...base,
          resultBindingBytes: this.#resultBindingBytes(input.resultBinding),
          physicalTopic: topic,
          clientNonce: request.clientNonce,
          snapshotRevision: page.snapshotRevision,
          entries: page.entries.map(entry => ({
            appendRevision: entry.appendRevision,
            frameHash: entry.frameHash,
            frameClass: entry.frameClass,
            frameObjectId: entry.frameObjectId
          })),
          entriesCommitment,
          nextCursor: page.nextCursor,
          sourceCommitment,
          retryExpiresMinute
        })
      return this.#pinnedPage(prepared.value.spendTag)
    })
  }

  async #waitUntilWatchReady (topic, request, signal) {
    const topicKey = hex(topic)
    let wait = null
    await this.transactionStore.withLocks([`inbox:${topicKey}`], async () => {
      const record = this.inboxes.get(topicKey)
      if (!this.#publiclyVisible(record)) fail('NOT_FOUND', 'inbox is absent')
      if (record.appendRevision <= u64(request.afterRevision, 'afterRevision')) {
        wait = this.#registerWaiter(topicKey, request.maxWaitMillis, signal)
      }
    })
    if (wait) await wait
  }

  chargedPageState (input) {
    this.#assertOpen()
    const prepared = preparedView(input.preparedAdmission)
    const disposition = this.#spendDisposition(prepared, input.operationId)
    return spendViewOrFresh(disposition)
  }

  readPinnedPage (input) {
    return this.#runOperation(async () => {
      this.#assertOpen()
      const spendTag = fixed(input.spendTag, 32, 'spendTag', true)
      const pin = this.retryPins.get(hex(spendTag))
      const spend = this.spends.get(hex(spendTag))
      if (!pin || !spend || (spend.status !== 'reserved' && spend.status !== 'committed')) {
        fail('RETRY_TERMINAL', 'charged Inbox page is no longer replayable')
      }
      const record = this.inboxes.get(hex(pin.physicalTopic))
      if (!this.#publiclyVisible(record)) fail('NOT_FOUND', 'inbox is absent')
      return this.#pinnedPage(spendTag)
    })
  }

  async #pinnedPage (spendTag) {
    const pin = this.retryPins.get(hex(spendTag))
    const spend = this.spends.get(hex(spendTag))
    if (!pin || !spend) fail('RETRY_TERMINAL', 'Inbox retry pin is absent')
    if (pin.retryExpiresMinute < minuteFromMillis(this.nowUnixMillis())) fail('RETRY_TERMINAL', 'Inbox retry pin expired')
    const entries = []
    for (const entry of pin.pinnedEntries) {
      const frame = this.frames.get(frameKey(pin.physicalTopic, entry.appendRevision))
      if (!frame || !equal(frame.frameHash, entry.frameHash) || !equal(frame.frameObjectId, entry.frameObjectId)) {
        fail('INTERNAL', 'Inbox retry pin lost its immutable frame')
      }
      const body = await this.transactionStore.readOpaque({
        virtualBucket: frame.frameVirtualBucket, objectId: frame.frameObjectId
      }, INBOX_FRAME_CLASS[frame.frameClass], frame.frameHash)
      entries.push({ appendRevision: frame.appendRevision, frameHash: b4a.from(frame.frameHash), frameClass: frame.frameClass, frame: body })
    }
    if (!equal(inboxEntriesCommitment(entries), pin.entriesCommitment)) fail('INTERNAL', 'Inbox retry entries commitment changed')
    return Object.freeze({
      spendTag: b4a.from(spend.spendTag),
      requestCommitment: b4a.from(spend.requestCommitment),
      operationId: spend.operation,
      clientNonce: b4a.from(pin.clientNonce),
      resultBindingBytes: b4a.from(pin.resultBindingBytes),
      snapshotRevision: pin.sourceRevision,
      entries: entries.map(Object.freeze),
      nextCursor: cloneBytes(pin.nextCursor),
      entriesCommitment: b4a.from(pin.entriesCommitment),
      resultCommitment: cloneBytes(pin.resultCommitment)
    })
  }

  finalizeChargedPage (input) {
    return this.#runOperation(async () => {
      this.#assertWritable(false)
      const spendTag = fixed(input.spendTag, 32, 'spendTag', true)
      const requestCommitment = fixed(input.requestCommitment, 32, 'requestCommitment', true)
      const resultCommitment = fixed(input.resultCommitment, 32, 'resultCommitment', true)
      return this.transactionStore.withLocks([`spend:${hex(spendTag)}`], async () => {
        const spend = this.spends.get(hex(spendTag))
        const pin = this.retryPins.get(hex(spendTag))
        if (!spend || !pin || !equal(spend.requestCommitment, requestCommitment)) fail('SPEND_REPLAY', 'Inbox read finalization does not match its spend')
        if (spend.status === 'committed') {
          if (!equal(spend.resultCommitment, resultCommitment)) fail('CONFLICT', 'Inbox read retry changed signed result bytes')
          return true
        }
        const identity = resultIdentity(spend.operation, spend.physicalTopic, requestCommitment,
          pin.sourceRevision, resultCommitment, pin.committedEpoch)
        await this.#appendAndApply(BLIND_INBOX_WAL_TYPE.READ_PIN_FINALIZED,
          this.transactionStore.newTransactionId(), this.transactionStore.virtualBucket(BLIND_STORE_SERVICE_TAG.INBOX, spend.physicalTopic), {
            version: 1,
            spendTag,
            requestCommitment,
            resultCommitment,
            resultIdentity: identity,
            finalizedEpoch: this.epochFloor
          })
        return true
      })
    })
  }

  async advanceEpochFloor (next) {
    this.#assertOpen()
    next = integer(next, 0, MAX_U32, 'nextEpochFloor')
    while (this.epochFloor < next) {
      const step = Math.min(next, this.epochFloor + 4)
      await this.#appendAndApply(BLIND_INBOX_WAL_TYPE.FLOOR_ADVANCE,
        this.transactionStore.newTransactionId(), 0, {
          version: 1, oldEpochFloor: this.epochFloor, newEpochFloor: step
        })
    }
    return this.epochFloor
  }

  sweepExpired (limit = 4096) {
    return this.#runOperation(async () => {
      await this.#sweepExpiredRetryPins(limit)
      return this.#sweepExpired(limit)
    })
  }

  async #sweepExpiredRetryPins (limit) {
    if (this.readOnlyReason) return 0
    const nowMinute = minuteFromMillis(this.nowUnixMillis())
    let swept = 0
    for (const pin of [...this.retryPins.values()]) {
      if (swept >= limit) break
      const spend = this.spends.get(hex(pin.spendTag))
      if (!spend || (spend.status !== 'committed' && spend.status !== 'reserved') || pin.retryExpiresMinute >= nowMinute) continue
      await this.#appendAndApply(BLIND_INBOX_WAL_TYPE.READ_PIN_EXPIRED,
        this.transactionStore.newTransactionId(), this.transactionStore.virtualBucket(BLIND_STORE_SERVICE_TAG.INBOX, pin.physicalTopic), {
          version: 1,
          spendTag: pin.spendTag,
          requestCommitment: pin.requestCommitment,
          retryExpiresMinute: pin.retryExpiresMinute,
          terminalEpoch: this.epochFloor
        })
      swept++
    }
    return swept
  }

  async #sweepExpired (limit) {
    if (this.readOnlyReason) return 0
    let swept = 0
    for (const frame of [...this.frames.values()]) {
      if (swept >= limit) break
      if (frame.expiresAtEpoch > this.epochFloor || this.#framePinned(frame)) continue
      const spend = this.spends.get(hex(frame.spendTag))
      if (!spend || spend.status !== 'committed' || !spend.ackSignature || !spend.resultCommitment) continue
      const transactionId = this.transactionStore.newTransactionId()
      await this.#appendAndApply(BLIND_INBOX_WAL_TYPE.APPEND_EXPIRED,
        transactionId, frame.frameVirtualBucket, {
          version: 1,
          transactionId: spend.transactionId,
          spendTag: spend.spendTag,
          requestCommitment: spend.requestCommitment,
          requestFingerprint: spend.requestFingerprint,
          physicalTopic: frame.physicalTopic,
          profileId: spend.profileId,
          appendRevision: frame.appendRevision,
          frameHash: frame.frameHash,
          frameClass: frame.frameClass,
          declaredBytes: spend.declaredBytes,
          deadlineUnixMillis: spend.deadlineUnixMillis,
          remainingAttempts: spend.remainingAttempts,
          reservedEpoch: spend.reservedEpoch,
          resultIdentity: spend.resultIdentity,
          frameObjectId: frame.frameObjectId,
          storedAtEpoch: frame.storedAtEpoch,
          retentionClassAtAppend: spend.retentionClassAtAppend,
          appendLeaseEpoch: frame.appendLeaseEpoch,
          expiresAtEpoch: frame.expiresAtEpoch,
          expiredEpoch: this.epochFloor,
          clientNonce: spend.clientNonce,
          resultBindingBytes: spend.resultBindingBytes,
          ackSignature: spend.ackSignature,
          resultCommitment: spend.resultCommitment
        })
      await this.transactionStore.removeOpaque({ virtualBucket: frame.frameVirtualBucket, objectId: frame.frameObjectId })
      swept++
    }
    for (const record of this.inboxes.values()) {
      if (swept >= limit) break
      if (record.objectState !== OBJECT_STATE.PRESENT || this.epochFloor <= record.leaseEpoch + 4) continue
      await this.#appendAndApply(BLIND_INBOX_WAL_TYPE.INBOX_GC,
        this.transactionStore.newTransactionId(), record.metadataVirtualBucket, {
          version: 1,
          physicalTopic: record.physicalTopic,
          oldStateRevision: record.stateRevision,
          newStateRevision: record.stateRevision + 1n,
          expectedLeaseEpoch: record.leaseEpoch,
          terminalEpoch: this.epochFloor
        })
      swept++
    }
    return swept
  }

  #framePinned (frame) {
    for (const pin of this.retryPins.values()) {
      if (pin.entries.some(entry => entry.appendRevision === frame.appendRevision &&
          equal(pin.physicalTopic, frame.physicalTopic) && equal(entry.frameHash, frame.frameHash))) return true
    }
    return false
  }

  setPolicy (input) {
    return this.#runOperation(async () => {
      this.#assertWritable(false)
      const topic = fixed(input.physicalTopic, 32, 'physicalTopic', true)
      const policyState = integer(input.policyState, 1, 2, 'policyState')
      return this.transactionStore.withLocks([`inbox:${hex(topic)}`], async () => {
        const record = this.inboxes.get(hex(topic))
        if (!record) fail('NOT_FOUND', 'inbox is absent')
        await this.#appendAndApply(BLIND_INBOX_WAL_TYPE.POLICY_COMMITTED,
          this.transactionStore.newTransactionId(), record.metadataVirtualBucket, {
            version: 1,
            physicalTopic: topic,
            oldPolicyRevision: record.policyRevision,
            newPolicyRevision: record.policyRevision + 1n,
            policyState,
            committedEpoch: this.epochFloor
          })
        return record.policyRevision
      })
    })
  }

  #liveReferenceKeys () {
    return new Set([...this.frames.values()].map(frame => this.transactionStore.referenceKey({
      virtualBucket: frame.frameVirtualBucket, objectId: frame.frameObjectId
    })))
  }

  async #verifyFrameBodies () {
    if (this.frames.size > this.quota.maxStartupReferences) {
      this.readOnlyReason = 'STARTUP_REFERENCE_BOUND_EXCEEDED'
      return
    }
    for (const frame of this.frames.values()) {
      const inspection = await this.transactionStore.inspectOpaque({
        virtualBucket: frame.frameVirtualBucket, objectId: frame.frameObjectId
      }, INBOX_FRAME_CLASS[frame.frameClass], frame.frameHash)
      if (!inspection.ok) {
        const reason = INTEGRITY_REASON[inspection.reason] || INTEGRITY_REASON.HASH
        const evidenceHash = hashParts(INTEGRITY_EVIDENCE_DOMAIN, frame.physicalTopic,
          u64bytes(frame.appendRevision), frame.frameHash, b4a.from([reason]))
        this.readOnlyReason = 'RECOVERY_GAP_READ_ONLY'
        if (this.integrityEvidence.some(entry => equal(entry.evidenceHash, evidenceHash))) return
        await this.#appendAndApply(BLIND_INBOX_WAL_TYPE.INTEGRITY_FAILED,
          this.transactionStore.newTransactionId(), 0, {
            version: 1, reason, detectedEpoch: this.epochFloor, evidenceHash
          })
        return
      }
    }
  }

  snapshotState () {
    this.#assertOpen()
    if (this.activeOperations !== 0 || this.waiterCount !== 0 || this.accounting.stagingFrameBytes !== 0 ||
        [...this.spends.values()].some(spend => spend.status === 'reserved' || spend.status === 'append-provisional')) {
      fail('BUSY', 'Inbox snapshot requires a drained engine and no WATCH waiters', true)
    }
    return {
      relayPublicKey: b4a.from(this.relayPublicKey),
      storeId: cloneBytes(this.storeId),
      durabilityContinuityHash: b4a.from(this.durabilityContinuityHash),
      durabilityProfileHash: cloneBytes(this.durabilityProfileHash),
      spends: cloneValue(this.spends),
      commitments: cloneValue(this.commitments),
      requestResults: cloneValue(this.requestResults),
      inboxes: cloneValue(this.inboxes),
      frames: cloneValue(this.frames),
      retryPins: cloneValue(this.retryPins),
      accounting: cloneValue(this.accounting),
      epochFloor: this.epochFloor,
      clockUnsafe: this.clockUnsafe,
      readOnlyReason: this.readOnlyReason,
      integrityEvidence: cloneValue(this.integrityEvidence)
    }
  }

  close () {
    if (this.closePromise) return this.closePromise
    this.closing = true
    if (this.clockTimer) clearInterval(this.clockTimer)
    this.clockTimer = null
    for (const topic of this.waitersByTopic.keys()) this.#notifyTopic(topic, true)
    this.closePromise = (async () => {
      await this.#waitForDrain()
      this.opened = false
      await this.transactionStore.close()
    })()
    return this.closePromise
  }
}

function spendViewOrFresh (disposition) {
  if (disposition.kind === 'fresh') return Object.freeze({ kind: 'fresh' })
  if (disposition.kind === 'conflict') return Object.freeze({ kind: 'conflict' })
  if (disposition.kind === 'terminal') return Object.freeze({ kind: 'terminal' })
  return Object.freeze({ kind: disposition.kind === 'replay' ? 'replay' : 'reserved' })
}

function verifyEd25519 (publicKey, message, signature) {
  try {
    const sig = fixed(signature, 64, 'signature')
    return sodium.crypto_sign_verify_detached(sig, message, publicKey)
  } catch {
    return false
  }
}

export function inboxEntriesCommitment (entries) {
  const canonicalEntries = entries.map(entry => ({
    appendRevision: entry.appendRevision,
    frameHash: entry.frameHash,
    frameClass: entry.frameClass,
    frame: entry.frame
  }))
  return inboxReadEntriesCommitment(canonicalEntries)
}
