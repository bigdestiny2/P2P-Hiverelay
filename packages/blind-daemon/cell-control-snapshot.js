import b4a from 'b4a'
import { createHmac } from 'node:crypto'
import {
  BLIND_CELL_CHARGED_READ_LIFECYCLE_STATE,
  CELL_SIZE_CLASS,
  FAMILY,
  OPERATION,
  allocationCommitment,
  arrayOf,
  blindCellAtomicCommittedPutSpendSnapshotV1,
  blindCellChargedReadPinEntrySnapshotV1,
  blindCellChargedReadRetrySnapshotV1,
  blindCellCommittedPutSpendSnapshotV1,
  blindCellCommittedRenewSpendSnapshotV1,
  blindCellControlGlobalSnapshotV1,
  blindCellIntegrityEvidenceSnapshotV1,
  blindCellProfileStagingSnapshotV1,
  blindCellRecordSnapshotV1,
  blindCellRequestResultSnapshotV1,
  blindCellReservedSpendSnapshotV1,
  blindCellTerminalSpendSnapshotV1,
  blindPreparedAdmissionStoreV1,
  blake2b256,
  boundedBytes,
  cellStorageSlot,
  constant,
  decodeCanonical,
  encodeCanonical,
  fixedBytes,
  ranged,
  relayResultBindingV1,
  struct,
  u8,
  u32be,
  u64be
} from '@hiverelay/blind-protocol'
import { verifyBlindCellStorageControlSnapshotState } from './storage-engine.js'

const CONTROL_RECORD_BYTES = 512
const TOMBSTONE_RECORD_BYTES = 512
const MAX_U64 = (1n << 64n) - 1n
const FINGERPRINT_DOMAIN = b4a.from('hiverelay.blind.store-request-fingerprint.v1', 'ascii')
const RESULT_IDENTITY_DOMAIN = b4a.from('hiverelay.blind.store-result-identity.v1', 'ascii')
const MAX_CHARGED_READ_PIN_CONTROL_BYTES = 32 * 1024
const AUTHORITIES = new WeakMap()
const VERIFIERS = new WeakMap()
const VERIFIED_RESULTS = new WeakMap()

const ENTRY_KIND = Object.freeze({
  SPEND_IDEMPOTENCY: 1,
  RESERVATION_ATTEMPT: 2,
  CELL: 3,
  CELL_GLOBAL: 6,
  CHARGED_RETRY: 8
})

const SUBTYPE = Object.freeze({
  COMMITTED_PUT_SPEND: 1,
  COMMITTED_RENEW_SPEND: 2,
  TERMINAL_PUT_SPEND: 3,
  REQUEST_RESULT: 4,
  ATOMIC_COMMITTED_PUT_SPEND: 5,
  RESERVED_PUT_SPEND: 1,
  CELL_RECORD: 1,
  GLOBAL: 1,
  PROFILE_STAGING: 2,
  INTEGRITY_EVIDENCE: 3,
  CHARGED_READ_RETRY: 1
})

const version1 = constant(u8, 1, 'version')
const bytes32 = fixedBytes(32)
const chargedReadPinEntriesV1 = arrayOf(
  blindCellChargedReadPinEntrySnapshotV1,
  1,
  64,
  'charged read pin entries'
)
const chargedReadPinCommittedStoreV1 = struct([
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
], { name: 'BlindChargedReadPinCommittedStoreV1' })
const chargedReadPinFinalizedStoreV1 = struct([
  ['version', version1],
  ['spendTag', bytes32],
  ['requestCommitment', bytes32],
  ['resultCommitment', bytes32],
  ['finalizedEpoch', u32be]
], { name: 'BlindChargedReadPinFinalizedStoreV1' })
const CHARGED_READ_FINALIZATION_CONTROL_BYTES = encodeCanonical(chargedReadPinFinalizedStoreV1, {
  version: 1,
  spendTag: b4a.alloc(32),
  requestCommitment: b4a.alloc(32),
  resultCommitment: b4a.alloc(32),
  finalizedEpoch: 0
}).byteLength

export const BLIND_CELL_CONTROL_SNAPSHOT_KEYSPACE = Object.freeze({
  familyPrefix: FAMILY.CELL,
  entryKind: ENTRY_KIND,
  subtype: SUBTYPE,
  keyFormat: 'family:u8 || subtype:u8 || identity bytes',
  globalKey: Object.freeze([FAMILY.CELL, SUBTYPE.GLOBAL])
})

export const BLIND_CELL_CONTROL_SNAPSHOT_STATUS = Object.freeze({
  recoverySemanticAuthorityImplemented: true,
  chargedReadCheckpointStateImplemented: true,
  engineBoundRecoveryCaptureImplemented: true,
  privatePartitionBucketMappingVerified: true,
  deterministicBoundedCandidateSerializationImplemented: true,
  scalableCandidateEntryStreamingImplemented: false,
  engineBoundPublicationAuthorityImplemented: false,
  productionComplete: false,
  exclusions: Object.freeze([
    'INBOX_CONTROL_SNAPSHOT_UNIMPLEMENTED',
    'CORE_CONTROL_SNAPSHOT_UNIMPLEMENTED',
    'DESCRIPTOR_IDENTITY_FLOOR_SNAPSHOT_UNIMPLEMENTED',
    'CROSS_SERVICE_GLOBAL_SNAPSHOT_COMPOSITION_UNIMPLEMENTED',
    'SCALABLE_EXTERNAL_SORTED_CANDIDATE_STREAM_UNIMPLEMENTED',
    'ENGINE_INSTANCE_WAL_BARRIER_PUBLICATION_AUTHORITY_UNIMPLEMENTED'
  ])
})

export class BlindCellControlSnapshotIntegrityError extends Error {
  constructor (message) {
    super(message)
    this.name = 'BlindCellControlSnapshotIntegrityError'
    this.code = 'RECOVERY_GAP_READ_ONLY'
  }
}

function fail (message) {
  throw new BlindCellControlSnapshotIntegrityError(message)
}

function asBytes (value, length, field, nonzero = false) {
  if (!value || typeof value.byteLength !== 'number') fail(`${field} must be bytes`)
  value = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (length != null && value.byteLength !== length) fail(`${field} must be exactly ${length} bytes`)
  if (nonzero && isZero(value)) fail(`${field} must be nonzero`)
  return value
}

function isZero (value) {
  for (const byte of value) if (byte !== 0) return false
  return true
}

function asU64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${field} must be an unsigned safe integer or bigint`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) fail(`${field} is outside u64`)
  return value
}

function safeNumber (value, field) {
  value = asU64(value, field)
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) fail(`${field} exceeds the JavaScript safe-integer bound`)
  return Number(value)
}

function integer (value, minimum, maximum, field) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${field} is outside ${minimum}..${maximum}`)
  }
  return value
}

function hex (value) {
  return b4a.toString(value, 'hex')
}

function u16bytes (value) {
  value = integer(value, 0, 0xffff, 'u16')
  return b4a.from([value >>> 8, value])
}

function u32bytes (value) {
  value = integer(value, 0, 0xffffffff, 'u32')
  return b4a.from([value >>> 24, value >>> 16, value >>> 8, value])
}

function u64bytes (value) {
  value = asU64(value, 'u64')
  const output = b4a.alloc(8)
  for (let index = 7; index >= 0; index--) {
    output[index] = Number(value & 0xffn)
    value >>= 8n
  }
  return output
}

function hashParts (domain, ...parts) {
  return blake2b256(b4a.concat([domain, ...parts]))
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

function chargedReadOperationId (value) {
  if (typeof value.operation !== 'string' || !/^read-[0-9]+$/.test(value.operation)) {
    fail('charged-read spend operation is invalid')
  }
  const operationId = Number(value.operation.slice(5))
  if (operationId !== OPERATION.CELL.GET && operationId !== OPERATION.CELL.PROVE &&
      operationId !== OPERATION.CELL.BATCH_GET) {
    fail('charged-read spend operation is outside GET/PROVE/BATCH_GET')
  }
  return operationId
}

function chargedReadLifecycleState (status) {
  if (status === 'read-pinned') return BLIND_CELL_CHARGED_READ_LIFECYCLE_STATE.PINNED
  if (status === 'read-finalized') return BLIND_CELL_CHARGED_READ_LIFECYCLE_STATE.FINALIZED
  if (status === 'read-expired') return BLIND_CELL_CHARGED_READ_LIFECYCLE_STATE.EXPIRED
  return null
}

function chargedReadControlBytes (value) {
  if (value.lifecycleState === BLIND_CELL_CHARGED_READ_LIFECYCLE_STATE.EXPIRED) {
    return CONTROL_RECORD_BYTES
  }
  const payloadBytes = encodeCanonical(chargedReadPinCommittedStoreV1, {
    version: 1,
    operationId: value.operationId,
    spendTag: value.spendTag,
    requestCommitment: value.requestCommitment,
    requestFingerprint: value.requestFingerprint,
    preparedAdmissionBytes: value.preparedAdmissionBytes,
    resultBindingBytes: value.resultBindingBytes,
    receiptEpoch: value.receiptEpoch,
    retryExpiresUnixMillis: value.retryExpiresUnixMillis,
    entries: value.entries,
    committedEpoch: value.committedEpoch
  }).byteLength
  if (payloadBytes > MAX_CHARGED_READ_PIN_CONTROL_BYTES) {
    fail('charged-read retry pin exceeds the frozen control-record bound')
  }
  return payloadBytes + CHARGED_READ_FINALIZATION_CONTROL_BYTES
}

function chargedBatchResultBytes (resultBindingBytes, entries) {
  let bytes = 162 + resultBindingBytes.byteLength
  for (const entry of entries) bytes += entry.present === 0 ? 1 : 2 + CELL_SIZE_CLASS[entry.sizeClass]
  return bytes
}

function chargedResultBand (bytes) {
  if (bytes <= 4 * 1024) return 1
  if (bytes <= 16 * 1024) return 2
  if (bytes <= 64 * 1024) return 3
  if (bytes <= 256 * 1024) return 4
  if (bytes <= 1024 * 1024) return 5
  if (bytes <= 4 * 1024 * 1024) return 6
  fail('charged batch result exceeds the operation result cap')
}

function virtualBucket (partitionKey, storageSlot) {
  const digest = createHmac('sha256', partitionKey)
    .update(b4a.from([FAMILY.CELL]))
    .update(storageSlot)
    .digest()
  return digest[0] * 0x100 + digest[1]
}

function cloneBytes (value) {
  return value == null ? null : b4a.from(value)
}

function cloneStateValue (value) {
  if (value == null || typeof value !== 'object') return value
  if (typeof value.byteLength === 'number') return cloneBytes(value)
  if (value instanceof Map) {
    return new Map([...value].map(([key, child]) => [key, cloneStateValue(child)]))
  }
  if (Array.isArray(value)) return value.map(cloneStateValue)
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, cloneStateValue(child)]))
}

function requireMap (value, field) {
  if (!(value instanceof Map)) fail(`${field} must be a Map`)
  return value
}

function mapKeyMatches (mapKey, bytes, field) {
  if (typeof mapKey !== 'string' || mapKey !== hex(bytes)) fail(`${field} map key does not match its canonical bytes`)
}

function decodeValue (codec, value, field) {
  value = asBytes(value, null, `${field} bytes`)
  let decoded
  try {
    decoded = decodeCanonical(codec, value, { copyBytes: true })
  } catch (error) {
    fail(`${field} is not canonical: ${error.message}`)
  }
  if (!b4a.equals(encodeCanonical(codec, decoded), value)) fail(`${field} canonical bytes changed on re-encoding`)
  return decoded
}

function entryKey (subtype, identity = null) {
  return identity == null
    ? b4a.from([FAMILY.CELL, subtype])
    : b4a.concat([b4a.from([FAMILY.CELL, subtype]), identity])
}

function encodedEntry (entryKind, subtype, identity, codec, value) {
  const key = entryKey(subtype, identity)
  const encoded = encodeCanonical(codec, value)
  if (key.byteLength > 256 || encoded.byteLength > 0xffff) fail('Cell snapshot entry exceeds the control snapshot bounds')
  return Object.freeze({ entryKind, key, value: encoded })
}

function compareEntries (left, right) {
  return left.entryKind - right.entryKind || b4a.compare(left.key, right.key)
}

function ingressSnapshotValue (entry) {
  return {
    version: 1,
    transactionId: entry.transactionId,
    spendTag: entry.spendTag,
    requestCommitment: entry.requestCommitment,
    requestFingerprint: entry.requestFingerprint,
    storageSlot: entry.storageSlot,
    allocationEpoch: entry.allocationEpoch,
    sizeClass: entry.sizeClass,
    leaseClass: entry.leaseClass,
    declaredBlobHash: entry.declaredBlobHash,
    createPublicKey: entry.createPublicKey,
    renewPublicKey: entry.renewPublicKey,
    dropPublicKey: entry.dropPublicKey,
    allocationCommitment: entry.allocationCommitment,
    profileId: entry.profileId,
    preparedAdmissionBytes: entry.preparedAdmissionBytes,
    resultBindingBytes: entry.resultBindingBytes,
    declaredBytes: entry.declaredBytes,
    deadlineUnixMillis: entry.deadlineUnixMillis,
    remainingAttempts: entry.remainingAttempts,
    reservedEpoch: entry.reservedEpoch
  }
}

function atomicCommittedPutSnapshotValue (entry) {
  return {
    version: 1,
    transactionId: entry.transactionId,
    spendTag: entry.spendTag,
    requestCommitment: entry.requestCommitment,
    requestFingerprint: entry.requestFingerprint,
    storageSlot: entry.storageSlot,
    allocationEpoch: entry.allocationEpoch,
    sizeClass: entry.sizeClass,
    leaseClass: entry.leaseClass,
    declaredBlobHash: entry.declaredBlobHash,
    createPublicKey: entry.createPublicKey,
    renewPublicKey: entry.renewPublicKey,
    dropPublicKey: entry.dropPublicKey,
    allocationCommitment: entry.allocationCommitment,
    profileId: entry.profileId,
    preparedAdmissionBytes: entry.preparedAdmissionBytes,
    resultBindingBytes: entry.resultBindingBytes,
    declaredBytes: entry.declaredBytes,
    resultIdentity: entry.resultIdentity,
    committedEpoch: entry.committedEpoch,
    resultCell: historicalResultSnapshotValue(entry.resultCell)
  }
}

function historicalResultSnapshotValue (value) {
  if (!value || typeof value !== 'object') fail('historical Cell result is required')
  const objectState = value.objectState === 'PRESENT' || value.objectState === 1
    ? 1
    : value.objectState === 'TOMBSTONE' || value.objectState === 2
      ? 2
      : 0
  const policyState = value.policyState === 'VISIBLE' || value.policyState === 1
    ? 1
    : value.policyState === 'SUPPRESSED' || value.policyState === 2
      ? 2
      : 0
  if (objectState === 0 || policyState === 0) fail('historical Cell result state is invalid')
  return {
    storageSlot: value.storageSlot,
    allocationEpoch: value.allocationEpoch,
    sizeClass: value.sizeClass,
    leaseClass: value.leaseClass,
    leaseEpoch: value.leaseEpoch,
    stateRevision: value.stateRevision,
    policyRevision: value.policyRevision,
    cellBlobHash: value.cellBlobHash,
    allocationCommitment: value.allocationCommitment,
    objectState,
    policyState
  }
}

function reconstructedHistoricalResult (value) {
  return {
    storageSlot: cloneBytes(value.storageSlot),
    allocationEpoch: value.allocationEpoch,
    sizeClass: value.sizeClass,
    leaseClass: value.leaseClass,
    leaseEpoch: value.leaseEpoch,
    stateRevision: value.stateRevision,
    policyRevision: value.policyRevision,
    cellBlobHash: cloneBytes(value.cellBlobHash),
    allocationCommitment: cloneBytes(value.allocationCommitment),
    objectState: value.objectState === 1 ? 'PRESENT' : 'TOMBSTONE',
    policyState: value.policyState === 1 ? 'VISIBLE' : 'SUPPRESSED'
  }
}

function allocationForCell (relayPublicKey, value, leaseClass) {
  return allocationCommitment({
    relayPublicKey,
    storageSlot: value.storageSlot,
    allocationEpoch: value.allocationEpoch,
    sizeClass: value.sizeClass,
    leaseClass,
    declaredCellBlobHash: value.cellBlobHash,
    createPublicKey: value.createPublicKey,
    renewPublicKey: value.renewPublicKey,
    dropPublicKey: value.dropPublicKey
  })
}

function deriveAllocationLeaseClass (relayPublicKey, value) {
  const matches = []
  for (let leaseClass = 1; leaseClass <= 4; leaseClass++) {
    let candidate
    try {
      candidate = allocationForCell(relayPublicKey, value, leaseClass)
    } catch (error) {
      fail(`cell allocation fields are invalid: ${error.message}`)
    }
    if (b4a.equals(candidate, value.allocationCommitment)) matches.push(leaseClass)
  }
  if (matches.length !== 1) {
    fail('cell allocation commitment does not identify exactly one allocation lease class')
  }
  return matches[0]
}

function candidateEntries (state) {
  if (!state || typeof state !== 'object' || Array.isArray(state)) fail('Cell snapshot state must be an object')
  const relayPublicKey = asBytes(state.relayPublicKey, 32, 'relayPublicKey', true)
  const spends = requireMap(state.spends, 'spends')
  const commitments = requireMap(state.commitments, 'commitments')
  const requestResults = requireMap(state.requestResults, 'requestResults')
  const cells = requireMap(state.cells, 'cells')
  if (!state.accounting || typeof state.accounting !== 'object') fail('accounting must be an object')
  const stagingByProfile = requireMap(state.accounting.stagingByProfile, 'accounting.stagingByProfile')
  if (!Array.isArray(state.integrityEvidence)) fail('integrityEvidence must be an array')
  integer(state.epochFloor, 0, 0xffffffff, 'epochFloor')
  if (typeof state.clockUnsafe !== 'boolean') fail('clockUnsafe must be a boolean')
  if (state.readOnlyReason != null && state.readOnlyReason !== 'RECOVERY_GAP_READ_ONLY') {
    fail('only the persistent recovery-gap read-only state can enter a Cell checkpoint')
  }

  const output = []
  for (const [mapKey, value] of spends) {
    if (!value || typeof value !== 'object') fail('spend entry must be an object')
    mapKeyMatches(mapKey, asBytes(value.spendTag, 32, 'spendTag', true), 'spend')
    if (value.inFlight === true) fail('in-flight Cell reservations cannot enter a checkpoint')
    const chargedLifecycle = chargedReadLifecycleState(value.status)
    if (chargedLifecycle != null) {
      const active = chargedLifecycle !== BLIND_CELL_CHARGED_READ_LIFECYCLE_STATE.EXPIRED
      const operationId = chargedReadOperationId(value)
      const snapshotValue = {
        version: 1,
        lifecycleState: chargedLifecycle,
        operationId,
        transactionId: value.transactionId,
        spendTag: value.spendTag,
        requestCommitment: value.requestCommitment,
        requestFingerprint: value.requestFingerprint,
        preparedAdmissionBytes: active ? value.preparedAdmissionBytes : null,
        resultBindingBytes: active ? value.resultBindingBytes : null,
        receiptEpoch: active ? value.receiptEpoch : null,
        retryExpiresUnixMillis: value.retryExpiresUnixMillis,
        entries: active ? value.entries : null,
        resultCommitment: chargedLifecycle === BLIND_CELL_CHARGED_READ_LIFECYCLE_STATE.FINALIZED
          ? value.resultCommitment
          : null,
        committedEpoch: value.committedEpoch,
        terminalEpoch: chargedLifecycle === BLIND_CELL_CHARGED_READ_LIFECYCLE_STATE.EXPIRED
          ? value.terminalEpoch
          : null
      }
      const expectedControlBytes = chargedReadControlBytes(snapshotValue)
      if (value.controlBytes !== expectedControlBytes) {
        fail('charged-read retry pin control accounting does not match its canonical WAL payload')
      }
      output.push(encodedEntry(ENTRY_KIND.CHARGED_RETRY, SUBTYPE.CHARGED_READ_RETRY,
        value.spendTag, blindCellChargedReadRetrySnapshotV1, snapshotValue))
    } else if (value.status === 'reserved') {
      output.push(encodedEntry(ENTRY_KIND.RESERVATION_ATTEMPT, SUBTYPE.RESERVED_PUT_SPEND,
        value.spendTag, blindCellReservedSpendSnapshotV1, ingressSnapshotValue(value)))
    } else if (value.status === 'terminal') {
      output.push(encodedEntry(ENTRY_KIND.SPEND_IDEMPOTENCY, SUBTYPE.TERMINAL_PUT_SPEND,
        value.spendTag, blindCellTerminalSpendSnapshotV1, {
          ...ingressSnapshotValue(value),
          terminalReason: value.terminalReason,
          terminalEpoch: value.terminalEpoch
        }))
    } else if (value.status === 'committed' && value.operation === 'renew') {
      output.push(encodedEntry(ENTRY_KIND.SPEND_IDEMPOTENCY, SUBTYPE.COMMITTED_RENEW_SPEND,
        value.spendTag, blindCellCommittedRenewSpendSnapshotV1, {
          version: 1,
          transactionId: value.transactionId,
          spendTag: value.spendTag,
          requestCommitment: value.requestCommitment,
          requestFingerprint: value.requestFingerprint,
          storageSlot: value.storageSlot,
          expectedStateRevision: value.expectedStateRevision,
          expectedLeaseEpoch: value.expectedLeaseEpoch,
          requestedLeaseClass: value.requestedLeaseClass,
          profileId: value.profileId,
          preparedAdmissionBytes: value.preparedAdmissionBytes,
          resultBindingBytes: value.resultBindingBytes,
          resultIdentity: value.resultIdentity,
          committedEpoch: value.committedEpoch,
          resultCell: historicalResultSnapshotValue(value.resultCell)
        }))
    } else if (value.status === 'committed' && value.operation == null && value.atomicCommitted === true) {
      output.push(encodedEntry(ENTRY_KIND.SPEND_IDEMPOTENCY, SUBTYPE.ATOMIC_COMMITTED_PUT_SPEND,
        value.spendTag, blindCellAtomicCommittedPutSpendSnapshotV1,
        atomicCommittedPutSnapshotValue(value)))
    } else if (value.status === 'committed' && value.operation == null && value.atomicCommitted !== true) {
      output.push(encodedEntry(ENTRY_KIND.SPEND_IDEMPOTENCY, SUBTYPE.COMMITTED_PUT_SPEND,
        value.spendTag, blindCellCommittedPutSpendSnapshotV1, {
          ...ingressSnapshotValue(value),
          resultIdentity: value.resultIdentity,
          committedEpoch: value.committedEpoch,
          resultCell: historicalResultSnapshotValue(value.resultCell)
        }))
    } else {
      fail('Cell spend has an unknown status or operation')
    }
  }

  const chargedReadPinned = [...spends.values()].filter(value => value.status === 'read-pinned')
  const chargedReadFinalized = [...spends.values()].filter(value => value.status === 'read-finalized')
  const chargedReadExpired = [...spends.values()].filter(value => value.status === 'read-expired')
  const chargedReadPinnedEntryCount = [...chargedReadPinned, ...chargedReadFinalized]
    .reduce((sum, value) => sum + value.entries.length, 0)

  for (const [mapKey, value] of requestResults) {
    if (!value || value.operation !== 'drop') fail('Cell request result has an unknown operation')
    mapKeyMatches(mapKey, asBytes(value.requestCommitment, 32, 'requestCommitment', true), 'request result')
    output.push(encodedEntry(ENTRY_KIND.SPEND_IDEMPOTENCY, SUBTYPE.REQUEST_RESULT,
      value.requestCommitment, blindCellRequestResultSnapshotV1, {
        version: 1,
        transactionId: value.transactionId,
        requestCommitment: value.requestCommitment,
        requestFingerprint: value.requestFingerprint,
        storageSlot: value.storageSlot,
        resultBindingBytes: value.resultBindingBytes,
        resultIdentity: value.resultIdentity,
        committedEpoch: value.committedEpoch,
        resultCell: historicalResultSnapshotValue(value.resultCell)
      }))
  }

  for (const [mapKey, value] of cells) {
    if (!value || typeof value !== 'object') fail('cell entry must be an object')
    mapKeyMatches(mapKey, asBytes(value.storageSlot, 32, 'storageSlot', true), 'cell')
    if (!value.blobReference || typeof value.blobReference !== 'object') fail('cell blobReference must be an object')
    output.push(encodedEntry(ENTRY_KIND.CELL, SUBTYPE.CELL_RECORD,
      value.storageSlot, blindCellRecordSnapshotV1, {
        version: 1,
        storageSlot: value.storageSlot,
        allocationEpoch: value.allocationEpoch,
        allocationLeaseClass: deriveAllocationLeaseClass(relayPublicKey, value),
        sizeClass: value.sizeClass,
        leaseClass: value.leaseClass,
        leaseEpoch: value.leaseEpoch,
        stateRevision: value.stateRevision,
        policyRevision: value.policyRevision,
        cellBlobHash: value.cellBlobHash,
        blobVirtualBucket: value.blobReference.virtualBucket,
        blobObjectId: value.blobReference.objectId,
        createPublicKey: value.createPublicKey,
        renewPublicKey: value.renewPublicKey,
        dropPublicKey: value.dropPublicKey,
        allocationCommitment: value.allocationCommitment,
        objectState: value.objectState,
        policyState: value.policyState,
        tombstoneReason: value.tombstoneReason,
        terminalEpoch: value.terminalEpoch,
        createSpendTag: value.createSpendTag,
        resultIdentity: value.resultIdentity,
        createdEpoch: value.createdEpoch
      }))
  }

  output.push(encodedEntry(ENTRY_KIND.CELL_GLOBAL, SUBTYPE.GLOBAL, null,
    blindCellControlGlobalSnapshotV1, {
      version: 1,
      epochFloor: state.epochFloor,
      clockUnsafe: state.clockUnsafe === true ? 1 : 0,
      recoveryGap: state.readOnlyReason === 'RECOVERY_GAP_READ_ONLY' ? 1 : 0,
      storedBytes: asU64(state.accounting.storedBytes, 'accounting.storedBytes'),
      stagingBytes: asU64(state.accounting.stagingBytes, 'accounting.stagingBytes'),
      controlBytes: asU64(state.accounting.controlBytes, 'accounting.controlBytes'),
      tombstoneBytes: asU64(state.accounting.tombstoneBytes, 'accounting.tombstoneBytes'),
      reservedCells: asU64(state.accounting.reservedCells, 'accounting.reservedCells'),
      cellCount: BigInt(cells.size),
      spendCount: BigInt(spends.size),
      commitmentCount: BigInt(commitments.size),
      requestResultCount: BigInt(requestResults.size),
      chargedReadPinnedCount: BigInt(chargedReadPinned.length),
      chargedReadFinalizedCount: BigInt(chargedReadFinalized.length),
      chargedReadExpiredCount: BigInt(chargedReadExpired.length),
      chargedReadPinnedEntryCount: BigInt(chargedReadPinnedEntryCount),
      profileStagingCount: stagingByProfile.size,
      integrityEvidenceCount: state.integrityEvidence.length,
      controlRecordAccountingBytes: CONTROL_RECORD_BYTES,
      tombstoneRecordAccountingBytes: TOMBSTONE_RECORD_BYTES
    }))

  for (const [profileId, stagingBytes] of stagingByProfile) {
    const canonicalProfileId = typeof profileId === 'string' && /^[1-9][0-9]*$/.test(profileId)
      ? Number(profileId)
      : profileId
    integer(canonicalProfileId, 1, 0xffff, 'staging profileId')
    output.push(encodedEntry(ENTRY_KIND.CELL_GLOBAL, SUBTYPE.PROFILE_STAGING,
      u16bytes(canonicalProfileId), blindCellProfileStagingSnapshotV1, {
        version: 1,
        profileId: canonicalProfileId,
        stagingBytes: asU64(stagingBytes, 'profile stagingBytes')
      }))
  }

  for (const evidence of state.integrityEvidence) {
    if (!evidence || typeof evidence !== 'object') fail('integrity evidence must be an object')
    output.push(encodedEntry(ENTRY_KIND.CELL_GLOBAL, SUBTYPE.INTEGRITY_EVIDENCE,
      evidence.evidenceHash, blindCellIntegrityEvidenceSnapshotV1, {
        version: 1,
        reason: evidence.reason,
        detectedEpoch: evidence.detectedEpoch,
        evidenceHash: evidence.evidenceHash
      }))
  }
  output.sort(compareEntries)
  for (let index = 1; index < output.length; index++) {
    if (compareEntries(output[index - 1], output[index]) >= 0) fail('Cell candidate snapshot entries collide')
  }
  return output
}

function assertAuthority (authority) {
  const state = AUTHORITIES.get(authority)
  if (!state) throw new TypeError('a branded Cell control snapshot semantic authority is required')
  return state
}

function keyIdentity (entry, expectedKind, expectedSubtype, length, field) {
  if (entry.entryKind !== expectedKind || entry.key.byteLength !== length + 2 ||
      entry.key[0] !== FAMILY.CELL || entry.key[1] !== expectedSubtype) {
    fail(`${field} uses an invalid Cell control snapshot key`)
  }
  return entry.key.subarray(2)
}

function commonIngressEntry (value, status) {
  return {
    status,
    transactionId: cloneBytes(value.transactionId),
    spendTag: cloneBytes(value.spendTag),
    requestCommitment: cloneBytes(value.requestCommitment),
    requestFingerprint: cloneBytes(value.requestFingerprint),
    storageSlot: cloneBytes(value.storageSlot),
    allocationEpoch: value.allocationEpoch,
    sizeClass: value.sizeClass,
    leaseClass: value.leaseClass,
    declaredBlobHash: cloneBytes(value.declaredBlobHash),
    createPublicKey: cloneBytes(value.createPublicKey),
    renewPublicKey: cloneBytes(value.renewPublicKey),
    dropPublicKey: cloneBytes(value.dropPublicKey),
    allocationCommitment: cloneBytes(value.allocationCommitment),
    profileId: value.profileId,
    preparedAdmissionBytes: cloneBytes(value.preparedAdmissionBytes),
    resultBindingBytes: cloneBytes(value.resultBindingBytes),
    declaredBytes: value.declaredBytes,
    deadlineUnixMillis: value.deadlineUnixMillis,
    remainingAttempts: value.remainingAttempts,
    reservedEpoch: value.reservedEpoch,
    terminalEpoch: null,
    resultIdentity: null,
    committedEpoch: null,
    inFlight: false
  }
}

function atomicCommittedPutEntry (value) {
  return {
    status: 'committed',
    operation: null,
    atomicCommitted: true,
    transactionId: cloneBytes(value.transactionId),
    spendTag: cloneBytes(value.spendTag),
    requestCommitment: cloneBytes(value.requestCommitment),
    requestFingerprint: cloneBytes(value.requestFingerprint),
    storageSlot: cloneBytes(value.storageSlot),
    allocationEpoch: value.allocationEpoch,
    sizeClass: value.sizeClass,
    leaseClass: value.leaseClass,
    declaredBlobHash: cloneBytes(value.declaredBlobHash),
    createPublicKey: cloneBytes(value.createPublicKey),
    renewPublicKey: cloneBytes(value.renewPublicKey),
    dropPublicKey: cloneBytes(value.dropPublicKey),
    allocationCommitment: cloneBytes(value.allocationCommitment),
    profileId: value.profileId,
    preparedAdmissionBytes: cloneBytes(value.preparedAdmissionBytes),
    resultBindingBytes: cloneBytes(value.resultBindingBytes),
    declaredBytes: value.declaredBytes,
    terminalEpoch: null,
    resultIdentity: cloneBytes(value.resultIdentity),
    committedEpoch: value.committedEpoch,
    resultCell: reconstructedHistoricalResult(value.resultCell),
    inFlight: false
  }
}

function assertPreparedAdmissionAndBinding (value, context, field) {
  const prepared = decodeValue(blindPreparedAdmissionStoreV1, value.preparedAdmissionBytes,
    `${field} prepared admission`)
  if (!b4a.equals(prepared.spendTag, value.spendTag) ||
      !b4a.equals(prepared.requestCommitment, value.requestCommitment) ||
      prepared.profileId !== value.profileId) {
    fail(`${field} prepared admission does not bind its spend, request, and profile`)
  }
  if (value.resultBindingBytes != null) validateProfile1ResultBinding(value.resultBindingBytes, context, field)
  return prepared
}

function assertIngressSemantics (value, relayPublicKey, context) {
  if (value.declaredBytes !== CELL_SIZE_CLASS[value.sizeClass]) fail('Cell ingress declaredBytes does not match sizeClass')
  if (!b4a.equals(cellStorageSlot(value), value.storageSlot)) fail('Cell ingress storageSlot is not self-certifying')
  if (new Set([value.createPublicKey, value.renewPublicKey, value.dropPublicKey].map(hex)).size !== 3) {
    fail('Cell ingress management keys are not distinct')
  }
  const allocation = allocationCommitment({
    relayPublicKey,
    storageSlot: value.storageSlot,
    allocationEpoch: value.allocationEpoch,
    sizeClass: value.sizeClass,
    leaseClass: value.leaseClass,
    declaredCellBlobHash: value.declaredBlobHash,
    createPublicKey: value.createPublicKey,
    renewPublicKey: value.renewPublicKey,
    dropPublicKey: value.dropPublicKey
  })
  if (!b4a.equals(allocation, value.allocationCommitment)) fail('Cell ingress allocation commitment does not match')
  assertPreparedAdmissionAndBinding(value, context, 'Cell ingress')
  const fingerprint = requestFingerprint([
    value.spendTag,
    value.requestCommitment,
    value.storageSlot,
    value.allocationCommitment,
    value.declaredBlobHash,
    u32bytes(value.declaredBytes),
    b4a.from([value.leaseClass]),
    u32bytes(value.profileId),
    blake2b256(value.preparedAdmissionBytes)
  ])
  if (!b4a.equals(fingerprint, value.requestFingerprint)) fail('Cell ingress request fingerprint does not match')
}

function addSpend (state, value) {
  const spendKey = hex(value.spendTag)
  const commitmentKey = hex(value.requestCommitment)
  if (state.spends.has(spendKey)) fail('Cell snapshot redefines a spend tag')
  if (state.commitments.has(commitmentKey)) fail('Cell snapshot redefines a request commitment')
  state.spends.set(spendKey, value)
  state.commitments.set(commitmentKey, { spendKey, fingerprint: hex(value.requestFingerprint) })
}

function cloneChargedReadPinEntry (value) {
  return {
    storageSlot: cloneBytes(value.storageSlot),
    present: value.present,
    sizeClass: value.sizeClass,
    allocationEpoch: value.allocationEpoch,
    leaseClass: value.leaseClass,
    leaseEpoch: value.leaseEpoch,
    stateRevision: value.stateRevision,
    policyRevision: value.policyRevision,
    cellBlobHash: cloneBytes(value.cellBlobHash),
    allocationCommitment: cloneBytes(value.allocationCommitment)
  }
}

function validateChargedReadPinSources (value, state) {
  const seen = new Set()
  for (const pinned of value.entries) {
    const slotKey = hex(pinned.storageSlot)
    if (seen.has(slotKey)) fail('charged-read retry pin repeats a storage slot')
    seen.add(slotKey)
    if (pinned.present === 0) continue
    const cell = state.cells.get(slotKey)
    if (!cell) fail('charged-read retry pin references a missing retained Cell record')
    if (pinned.allocationEpoch !== cell.allocationEpoch || pinned.sizeClass !== cell.sizeClass ||
        pinned.stateRevision > cell.stateRevision || pinned.policyRevision > cell.policyRevision ||
        !b4a.equals(pinned.cellBlobHash, cell.cellBlobHash) ||
        !b4a.equals(pinned.allocationCommitment, cell.allocationCommitment)) {
      fail('charged-read retry pin is inconsistent with its retained Cell history')
    }
    if (pinned.stateRevision === cell.stateRevision &&
        (pinned.leaseClass !== cell.leaseClass || pinned.leaseEpoch !== cell.leaseEpoch)) {
      fail('charged-read retry pin changes lease state without a later Cell revision')
    }
  }
}

function assertHistoricalResultAgainstCell (state, historical, field) {
  if (!historical || typeof historical !== 'object') fail(`${field} historical result is absent`)
  const cell = state.cells.get(hex(historical.storageSlot))
  if (!cell) fail(`${field} references no retained authoritative Cell state`)
  if (historical.allocationEpoch !== cell.allocationEpoch || historical.sizeClass !== cell.sizeClass ||
      historical.stateRevision > cell.stateRevision || historical.policyRevision > cell.policyRevision ||
      !b4a.equals(historical.cellBlobHash, cell.cellBlobHash) ||
      !b4a.equals(historical.allocationCommitment, cell.allocationCommitment)) {
    fail(`${field} is inconsistent with retained authoritative Cell state`)
  }
  if (historical.stateRevision === cell.stateRevision &&
      (historical.leaseClass !== cell.leaseClass || historical.leaseEpoch !== cell.leaseEpoch ||
       historical.objectState !== (cell.objectState === 1 ? 'PRESENT' : 'TOMBSTONE'))) {
    fail(`${field} changes object state without a later Cell revision`)
  }
  if (historical.policyRevision === cell.policyRevision &&
      historical.policyState !== (cell.policyState === 1 ? 'VISIBLE' : 'SUPPRESSED')) {
    fail(`${field} changes policy state without a later policy revision`)
  }
  return cell
}

function validateProfile1ResultBinding (bytes, context, field = 'charged-read') {
  const binding = decodeValue(relayResultBindingV1, bytes, `${field} result binding`)
  if (binding.durabilityProfileId !== 1 || binding.externalCommitWitness != null ||
      !b4a.equals(binding.relayPublicKey, context.relayPublicKey) ||
      !context.storeId || !b4a.equals(binding.storeId, context.storeId) ||
      !context.durabilityContinuityHash ||
      !b4a.equals(binding.durabilityContinuityHash, context.durabilityContinuityHash)) {
    fail(`${field} result binding does not bind this profile-1 relay/store checkpoint`)
  }
}

function reconstructChargedReadSpend (value, state, context) {
  const active = value.lifecycleState !== BLIND_CELL_CHARGED_READ_LIFECYCLE_STATE.EXPIRED
  const status = value.lifecycleState === BLIND_CELL_CHARGED_READ_LIFECYCLE_STATE.PINNED
    ? 'read-pinned'
    : value.lifecycleState === BLIND_CELL_CHARGED_READ_LIFECYCLE_STATE.FINALIZED
      ? 'read-finalized'
      : 'read-expired'
  let preparedAdmissionBytes = null
  let resultBindingBytes = null
  let entries = null
  let receiptEpoch = null
  let resultCommitment = null
  if (active) {
    const prepared = decodeValue(blindPreparedAdmissionStoreV1, value.preparedAdmissionBytes,
      'charged-read prepared admission')
    if (!b4a.equals(prepared.spendTag, value.spendTag) ||
        !b4a.equals(prepared.requestCommitment, value.requestCommitment) ||
        isZero(prepared.parameterHash)) {
      fail('charged-read prepared admission does not bind its spend and request')
    }
    const expectedFingerprint = requestFingerprint([
      b4a.from([value.operationId]),
      value.spendTag,
      value.requestCommitment,
      blake2b256(value.preparedAdmissionBytes)
    ])
    if (!b4a.equals(expectedFingerprint, value.requestFingerprint)) {
      fail('charged-read request fingerprint does not match its prepared admission')
    }
    validateProfile1ResultBinding(value.resultBindingBytes, context)
    const expectedResourceClass = value.operationId === OPERATION.CELL.BATCH_GET
      ? chargedResultBand(chargedBatchResultBytes(value.resultBindingBytes, value.entries))
      : value.entries[0].sizeClass
    if (prepared.resourceClass !== expectedResourceClass || prepared.leaseClass !== 0) {
      fail('charged-read prepared admission cost does not match its pinned result')
    }
    if (value.receiptEpoch !== value.committedEpoch) {
      fail('charged-read receipt epoch does not match its commit epoch')
    }
    validateChargedReadPinSources(value, state)
    preparedAdmissionBytes = cloneBytes(value.preparedAdmissionBytes)
    resultBindingBytes = cloneBytes(value.resultBindingBytes)
    entries = value.entries.map(cloneChargedReadPinEntry)
    receiptEpoch = value.receiptEpoch
    resultCommitment = cloneBytes(value.resultCommitment)
  } else if (value.terminalEpoch < value.committedEpoch) {
    fail('charged-read expired tombstone predates its committed spend')
  }
  const controlBytes = chargedReadControlBytes(value)
  return {
    status,
    operation: `read-${value.operationId}`,
    transactionId: cloneBytes(value.transactionId),
    spendTag: cloneBytes(value.spendTag),
    requestCommitment: cloneBytes(value.requestCommitment),
    requestFingerprint: cloneBytes(value.requestFingerprint),
    preparedAdmissionBytes,
    resultBindingBytes,
    receiptEpoch,
    retryExpiresUnixMillis: value.retryExpiresUnixMillis,
    entries,
    resultCommitment,
    committedEpoch: value.committedEpoch,
    terminalEpoch: value.terminalEpoch,
    controlBytes
  }
}

function readEntry (raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) fail('snapshot entry must be an object')
  const entryKind = integer(raw.entryKind, 1, 8, 'entryKind')
  const key = asBytes(raw.key, null, 'entry key')
  const value = asBytes(raw.value, null, 'entry value')
  if (key.byteLength < 2 || key.byteLength > 256 || value.byteLength > 0xffff) fail('snapshot entry is outside its byte bounds')
  if (key[0] !== FAMILY.CELL) fail('Cell-only semantic authority rejects non-Cell snapshot entries')
  return { entryKind, key, value }
}

async function reconstructEntries (source, context = {}) {
  if (!source || (typeof source[Symbol.asyncIterator] !== 'function' && typeof source[Symbol.iterator] !== 'function')) {
    fail('Cell snapshot entries must be iterable')
  }
  const relayPublicKey = asBytes(context.relayPublicKey, 32, 'relayPublicKey', true)
  const partitionKey = asBytes(context.partitionKey, 32, 'partitionKey', true)
  const state = {
    spends: new Map(),
    commitments: new Map(),
    requestResults: new Map(),
    cells: new Map(),
    accounting: null,
    epochFloor: null,
    clockUnsafe: false,
    readOnlyReason: null,
    integrityEvidence: [],
    chargedReadExpiryHeap: []
  }
  const profiles = new Map()
  const evidenceByHash = new Map()
  let global = null
  let count = 0
  let previous = null
  for await (const raw of source) {
    const entry = readEntry(raw)
    if (previous != null && compareEntries(previous, entry) >= 0) {
      fail('Cell snapshot entries are not strictly sorted and duplicate-free')
    }
    previous = entry
    count++
    const subtype = entry.key[1]
    if (entry.entryKind === ENTRY_KIND.RESERVATION_ATTEMPT && subtype === SUBTYPE.RESERVED_PUT_SPEND) {
      const identity = keyIdentity(entry, ENTRY_KIND.RESERVATION_ATTEMPT, subtype, 32, 'reserved spend')
      const value = decodeValue(blindCellReservedSpendSnapshotV1, entry.value, 'reserved spend')
      if (!b4a.equals(identity, value.spendTag)) fail('reserved spend key does not match spendTag')
      assertIngressSemantics(value, relayPublicKey, context)
      addSpend(state, commonIngressEntry(value, 'reserved'))
      continue
    }
    if (entry.entryKind === ENTRY_KIND.SPEND_IDEMPOTENCY && subtype === SUBTYPE.COMMITTED_PUT_SPEND) {
      const identity = keyIdentity(entry, ENTRY_KIND.SPEND_IDEMPOTENCY, subtype, 32, 'committed put spend')
      const value = decodeValue(blindCellCommittedPutSpendSnapshotV1, entry.value, 'committed put spend')
      if (!b4a.equals(identity, value.spendTag)) fail('committed put spend key does not match spendTag')
      assertIngressSemantics(value, relayPublicKey, context)
      const expectedLease = value.committedEpoch + [0, 4, 28, 120, 360][value.leaseClass]
      const expectedResult = resultIdentity('stored', value.storageSlot, value.requestCommitment,
        value.declaredBlobHash, value.leaseClass, expectedLease, 0n)
      if (!b4a.equals(expectedResult, value.resultIdentity)) fail('committed put result identity does not match')
      const reconstructed = commonIngressEntry(value, 'committed')
      reconstructed.resultIdentity = cloneBytes(value.resultIdentity)
      reconstructed.committedEpoch = value.committedEpoch
      reconstructed.resultCell = reconstructedHistoricalResult(value.resultCell)
      addSpend(state, reconstructed)
      continue
    }
    if (entry.entryKind === ENTRY_KIND.SPEND_IDEMPOTENCY && subtype === SUBTYPE.ATOMIC_COMMITTED_PUT_SPEND) {
      const identity = keyIdentity(entry, ENTRY_KIND.SPEND_IDEMPOTENCY, subtype, 32,
        'atomic committed put spend')
      const value = decodeValue(blindCellAtomicCommittedPutSpendSnapshotV1, entry.value,
        'atomic committed put spend')
      if (!b4a.equals(identity, value.spendTag)) fail('atomic committed put spend key does not match spendTag')
      assertIngressSemantics(value, relayPublicKey, context)
      const expectedLease = value.committedEpoch + [0, 4, 28, 120, 360][value.leaseClass]
      const expectedResult = resultIdentity('stored', value.storageSlot, value.requestCommitment,
        value.declaredBlobHash, value.leaseClass, expectedLease, 0n)
      if (!b4a.equals(expectedResult, value.resultIdentity)) {
        fail('atomic committed put result identity does not match')
      }
      addSpend(state, atomicCommittedPutEntry(value))
      continue
    }
    if (entry.entryKind === ENTRY_KIND.SPEND_IDEMPOTENCY && subtype === SUBTYPE.COMMITTED_RENEW_SPEND) {
      const identity = keyIdentity(entry, ENTRY_KIND.SPEND_IDEMPOTENCY, subtype, 32, 'committed renew spend')
      const value = decodeValue(blindCellCommittedRenewSpendSnapshotV1, entry.value, 'committed renew spend')
      if (!b4a.equals(identity, value.spendTag)) fail('committed renew spend key does not match spendTag')
      assertPreparedAdmissionAndBinding(value, context, 'committed renew spend')
      if (value.resultCell.stateRevision === 0n) fail('Cell drop result has no predecessor revision')
      const expectedFingerprint = requestFingerprint([
        value.spendTag,
        value.requestCommitment,
        value.storageSlot,
        u64bytes(value.expectedStateRevision),
        u32bytes(value.expectedLeaseEpoch),
        b4a.from([value.requestedLeaseClass]),
        u32bytes(value.profileId),
        blake2b256(value.preparedAdmissionBytes)
      ])
      if (!b4a.equals(expectedFingerprint, value.requestFingerprint)) {
        fail('committed renew spend request fingerprint does not match')
      }
      addSpend(state, {
        status: 'committed',
        operation: 'renew',
        transactionId: cloneBytes(value.transactionId),
        spendTag: cloneBytes(value.spendTag),
        requestCommitment: cloneBytes(value.requestCommitment),
        requestFingerprint: cloneBytes(value.requestFingerprint),
        storageSlot: cloneBytes(value.storageSlot),
        expectedStateRevision: value.expectedStateRevision,
        expectedLeaseEpoch: value.expectedLeaseEpoch,
        requestedLeaseClass: value.requestedLeaseClass,
        profileId: value.profileId,
        preparedAdmissionBytes: cloneBytes(value.preparedAdmissionBytes),
        resultBindingBytes: cloneBytes(value.resultBindingBytes),
        resultIdentity: cloneBytes(value.resultIdentity),
        committedEpoch: value.committedEpoch,
        terminalEpoch: null,
        resultCell: reconstructedHistoricalResult(value.resultCell)
      })
      continue
    }
    if (entry.entryKind === ENTRY_KIND.SPEND_IDEMPOTENCY && subtype === SUBTYPE.TERMINAL_PUT_SPEND) {
      const identity = keyIdentity(entry, ENTRY_KIND.SPEND_IDEMPOTENCY, subtype, 32, 'terminal put spend')
      const value = decodeValue(blindCellTerminalSpendSnapshotV1, entry.value, 'terminal put spend')
      if (!b4a.equals(identity, value.spendTag)) fail('terminal put spend key does not match spendTag')
      assertIngressSemantics(value, relayPublicKey, context)
      const reconstructed = commonIngressEntry(value, 'terminal')
      reconstructed.terminalReason = value.terminalReason
      reconstructed.terminalEpoch = value.terminalEpoch
      addSpend(state, reconstructed)
      continue
    }
    if (entry.entryKind === ENTRY_KIND.SPEND_IDEMPOTENCY && subtype === SUBTYPE.REQUEST_RESULT) {
      const identity = keyIdentity(entry, ENTRY_KIND.SPEND_IDEMPOTENCY, subtype, 32, 'request result')
      const value = decodeValue(blindCellRequestResultSnapshotV1, entry.value, 'request result')
      if (!b4a.equals(identity, value.requestCommitment)) fail('request result key does not match requestCommitment')
      if (value.resultBindingBytes != null) {
        validateProfile1ResultBinding(value.resultBindingBytes, context, 'Cell drop result')
      }
      const expectedFingerprint = requestFingerprint([
        value.requestCommitment,
        value.storageSlot,
        u64bytes(value.resultCell.stateRevision - 1n),
        u32bytes(value.resultCell.leaseEpoch)
      ])
      if (!b4a.equals(expectedFingerprint, value.requestFingerprint)) {
        fail('Cell drop result request fingerprint does not match')
      }
      const key = hex(value.requestCommitment)
      if (state.requestResults.has(key)) fail('Cell snapshot redefines a request result')
      state.requestResults.set(key, {
        operation: 'drop',
        transactionId: cloneBytes(value.transactionId),
        requestCommitment: cloneBytes(value.requestCommitment),
        requestFingerprint: cloneBytes(value.requestFingerprint),
        storageSlot: cloneBytes(value.storageSlot),
        resultBindingBytes: cloneBytes(value.resultBindingBytes),
        resultIdentity: cloneBytes(value.resultIdentity),
        committedEpoch: value.committedEpoch,
        resultCell: reconstructedHistoricalResult(value.resultCell)
      })
      continue
    }
    if (entry.entryKind === ENTRY_KIND.CELL && subtype === SUBTYPE.CELL_RECORD) {
      const identity = keyIdentity(entry, ENTRY_KIND.CELL, subtype, 32, 'cell record')
      const value = decodeValue(blindCellRecordSnapshotV1, entry.value, 'cell record')
      if (!b4a.equals(identity, value.storageSlot)) fail('cell record key does not match storageSlot')
      if (!b4a.equals(cellStorageSlot(value), value.storageSlot)) fail('cell record storageSlot is not self-certifying')
      if (new Set([value.createPublicKey, value.renewPublicKey, value.dropPublicKey].map(hex)).size !== 3) {
        fail('cell record management keys are not distinct')
      }
      if (value.blobVirtualBucket !== virtualBucket(partitionKey, value.storageSlot)) {
        fail('cell blob virtual bucket does not match the private partition mapping')
      }
      const expectedAllocation = allocationForCell(relayPublicKey, value, value.allocationLeaseClass)
      if (!b4a.equals(expectedAllocation, value.allocationCommitment)) fail('cell allocation commitment does not match')
      const key = hex(value.storageSlot)
      if (state.cells.has(key)) fail('Cell snapshot redefines a storage slot')
      state.cells.set(key, {
        storageSlot: cloneBytes(value.storageSlot),
        allocationEpoch: value.allocationEpoch,
        allocationLeaseClass: value.allocationLeaseClass,
        sizeClass: value.sizeClass,
        leaseClass: value.leaseClass,
        leaseEpoch: value.leaseEpoch,
        stateRevision: value.stateRevision,
        policyRevision: value.policyRevision,
        cellBlobHash: cloneBytes(value.cellBlobHash),
        blobReference: { virtualBucket: value.blobVirtualBucket, objectId: cloneBytes(value.blobObjectId) },
        createPublicKey: cloneBytes(value.createPublicKey),
        renewPublicKey: cloneBytes(value.renewPublicKey),
        dropPublicKey: cloneBytes(value.dropPublicKey),
        allocationCommitment: cloneBytes(value.allocationCommitment),
        objectState: value.objectState,
        policyState: value.policyState,
        tombstoneReason: value.tombstoneReason,
        terminalEpoch: value.terminalEpoch,
        createSpendTag: cloneBytes(value.createSpendTag),
        resultIdentity: cloneBytes(value.resultIdentity),
        createdEpoch: value.createdEpoch
      })
      continue
    }
    if (entry.entryKind === ENTRY_KIND.CELL_GLOBAL && subtype === SUBTYPE.GLOBAL) {
      keyIdentity(entry, ENTRY_KIND.CELL_GLOBAL, subtype, 0, 'Cell global record')
      if (global != null) fail('Cell snapshot contains more than one global record')
      global = decodeValue(blindCellControlGlobalSnapshotV1, entry.value, 'Cell global record')
      continue
    }
    if (entry.entryKind === ENTRY_KIND.CELL_GLOBAL && subtype === SUBTYPE.PROFILE_STAGING) {
      const identity = keyIdentity(entry, ENTRY_KIND.CELL_GLOBAL, subtype, 2, 'profile staging record')
      const value = decodeValue(blindCellProfileStagingSnapshotV1, entry.value, 'profile staging record')
      const profileId = identity[0] * 0x100 + identity[1]
      if (profileId !== value.profileId || profiles.has(profileId)) fail('profile staging key is duplicate or mismatched')
      profiles.set(profileId, safeNumber(value.stagingBytes, 'profile staging bytes'))
      continue
    }
    if (entry.entryKind === ENTRY_KIND.CELL_GLOBAL && subtype === SUBTYPE.INTEGRITY_EVIDENCE) {
      const identity = keyIdentity(entry, ENTRY_KIND.CELL_GLOBAL, subtype, 32, 'integrity evidence')
      const value = decodeValue(blindCellIntegrityEvidenceSnapshotV1, entry.value, 'integrity evidence')
      if (!b4a.equals(identity, value.evidenceHash)) fail('integrity evidence key does not match evidenceHash')
      const key = hex(value.evidenceHash)
      if (evidenceByHash.has(key)) fail('Cell snapshot repeats integrity evidence')
      evidenceByHash.set(key, {
        reason: value.reason,
        detectedEpoch: value.detectedEpoch,
        evidenceHash: cloneBytes(value.evidenceHash)
      })
      continue
    }
    if (entry.entryKind === ENTRY_KIND.CHARGED_RETRY && subtype === SUBTYPE.CHARGED_READ_RETRY) {
      const identity = keyIdentity(entry, ENTRY_KIND.CHARGED_RETRY, subtype, 32, 'charged-read retry')
      const value = decodeValue(blindCellChargedReadRetrySnapshotV1, entry.value, 'charged-read retry')
      if (!b4a.equals(identity, value.spendTag)) fail('charged-read retry key does not match spendTag')
      const reconstructed = reconstructChargedReadSpend(value, state, context)
      addSpend(state, reconstructed)
      if (reconstructed.status !== 'read-expired') {
        state.chargedReadExpiryHeap.push({
          retryExpiresUnixMillis: reconstructed.retryExpiresUnixMillis,
          spendKey: hex(reconstructed.spendTag),
          transactionId: hex(reconstructed.transactionId)
        })
      }
      continue
    }
    fail(`unknown Cell control snapshot entry kind/subtype ${entry.entryKind}/${subtype}`)
  }

  if (context.declaredEntryCount != null && count !== context.declaredEntryCount) {
    fail('Cell semantic entry count does not match the declared snapshot count')
  }
  if (global == null) fail('Cell snapshot is incomplete without its global record')
  const epochFloor = global.epochFloor
  for (const spend of state.spends.values()) {
    if (spend.reservedEpoch != null && spend.reservedEpoch > epochFloor) fail('Cell spend reservedEpoch exceeds the checkpoint floor')
    if (spend.committedEpoch != null && spend.committedEpoch > epochFloor) fail('Cell spend committedEpoch exceeds the checkpoint floor')
    if (spend.terminalEpoch != null && spend.terminalEpoch > epochFloor) fail('Cell spend terminalEpoch exceeds the checkpoint floor')
  }
  for (const result of state.requestResults.values()) {
    if (result.committedEpoch > epochFloor) fail('Cell request result committedEpoch exceeds the checkpoint floor')
  }
  for (const cell of state.cells.values()) {
    if (cell.createdEpoch > epochFloor || (cell.terminalEpoch != null && cell.terminalEpoch > epochFloor)) {
      fail('Cell record epoch exceeds the checkpoint floor')
    }
    const initialLeaseEpoch = cell.createdEpoch + [0, 4, 28, 120, 360][cell.allocationLeaseClass]
    if (cell.leaseEpoch < initialLeaseEpoch) fail('Cell record leaseEpoch is below its initial allocation lease')
    if (cell.objectState === 2 && cell.stateRevision === 0n) {
      fail('Cell tombstone must have a nonzero state revision')
    }
    const createSpend = state.spends.get(hex(cell.createSpendTag))
    if (createSpend && (createSpend.operation != null || createSpend.status !== 'committed')) {
      fail('Cell createSpendTag resolves to a non-create spend')
    }
    if (createSpend && (
      createSpend.allocationEpoch !== cell.allocationEpoch ||
      createSpend.sizeClass !== cell.sizeClass ||
      createSpend.leaseClass !== cell.allocationLeaseClass ||
      createSpend.committedEpoch !== cell.createdEpoch ||
      !b4a.equals(createSpend.storageSlot, cell.storageSlot) ||
      !b4a.equals(createSpend.declaredBlobHash, cell.cellBlobHash) ||
      !b4a.equals(createSpend.createPublicKey, cell.createPublicKey) ||
      !b4a.equals(createSpend.renewPublicKey, cell.renewPublicKey) ||
      !b4a.equals(createSpend.dropPublicKey, cell.dropPublicKey) ||
      !b4a.equals(createSpend.allocationCommitment, cell.allocationCommitment) ||
      !b4a.equals(createSpend.resultIdentity, cell.resultIdentity))) {
      fail('Cell record does not match its retained committed create spend')
    }
    if (createSpend) {
      const historical = createSpend.resultCell
      assertHistoricalResultAgainstCell(state, historical, 'committed Cell PUT result')
      const expectedLeaseEpoch = createSpend.committedEpoch + [0, 4, 28, 120, 360][createSpend.leaseClass]
      if (historical.objectState !== 'PRESENT' || historical.policyState !== 'VISIBLE' ||
          historical.stateRevision !== 0n || historical.policyRevision !== 0n ||
          historical.allocationEpoch !== createSpend.allocationEpoch ||
          historical.sizeClass !== createSpend.sizeClass || historical.leaseClass !== createSpend.leaseClass ||
          historical.leaseEpoch !== expectedLeaseEpoch ||
          !b4a.equals(historical.storageSlot, createSpend.storageSlot) ||
          !b4a.equals(historical.cellBlobHash, createSpend.declaredBlobHash) ||
          !b4a.equals(historical.allocationCommitment, createSpend.allocationCommitment)) {
        fail('committed Cell PUT historical result is inconsistent with its allocation')
      }
    }
  }
  for (const spend of state.spends.values()) {
    if (spend.status === 'terminal' && spend.terminalReason === 2 && spend.remainingAttempts !== 0) {
      fail('attempts-exhausted Cell terminal spend must have zero remaining attempts')
    }
    if ((spend.status === 'reserved' || spend.status === 'terminal') &&
        state.cells.has(hex(spend.storageSlot))) {
      fail('reserved or terminal Cell spend collides with an allocated cell')
    }
    if (spend.status === 'committed' && spend.operation === 'renew') {
      const historical = spend.resultCell
      assertHistoricalResultAgainstCell(state, historical, 'committed Cell RENEW result')
      const expectedLeaseEpoch = Math.max(
        spend.expectedLeaseEpoch,
        spend.committedEpoch + [0, 4, 28, 120, 360][spend.requestedLeaseClass]
      )
      const expectedIdentity = resultIdentity(
        'renewed',
        spend.storageSlot,
        spend.requestCommitment,
        historical.cellBlobHash,
        spend.requestedLeaseClass,
        expectedLeaseEpoch,
        spend.expectedStateRevision + 1n
      )
      if (historical.objectState !== 'PRESENT' || historical.storageSlot == null ||
          historical.stateRevision !== spend.expectedStateRevision + 1n ||
          historical.leaseClass !== spend.requestedLeaseClass ||
          historical.leaseEpoch !== expectedLeaseEpoch ||
          !b4a.equals(historical.storageSlot, spend.storageSlot) ||
          !b4a.equals(expectedIdentity, spend.resultIdentity)) {
        fail('committed Cell RENEW historical result or identity is inconsistent')
      }
    }
  }
  for (const result of state.requestResults.values()) {
    const cell = state.cells.get(hex(result.storageSlot))
    if (cell && (cell.objectState !== 2 || cell.tombstoneReason !== 1 ||
        cell.terminalEpoch !== result.committedEpoch ||
        !b4a.equals(result.resultIdentity, resultIdentity(
          'dropped', cell.storageSlot, result.requestCommitment, cell.cellBlobHash,
          0, cell.leaseEpoch, cell.stateRevision)))) {
      fail('Cell drop result does not match its retained owner-drop tombstone')
    }
    const historical = result.resultCell
    assertHistoricalResultAgainstCell(state, historical, 'committed Cell DROP result')
    const expectedIdentity = resultIdentity(
      'dropped',
      historical.storageSlot,
      result.requestCommitment,
      historical.cellBlobHash,
      0,
      historical.leaseEpoch,
      historical.stateRevision
    )
    if (historical.objectState !== 'TOMBSTONE' ||
        !b4a.equals(historical.storageSlot, result.storageSlot) ||
        !b4a.equals(expectedIdentity, result.resultIdentity)) {
      fail('committed Cell DROP historical result or identity is inconsistent')
    }
  }
  for (const evidence of evidenceByHash.values()) {
    if (evidence.detectedEpoch > epochFloor) fail('Cell integrity evidence exceeds the checkpoint floor')
  }

  const reserved = [...state.spends.values()].filter(value => value.status === 'reserved')
  const expectedProfiles = new Map()
  for (const value of reserved) {
    expectedProfiles.set(value.profileId,
      (expectedProfiles.get(value.profileId) || 0) + value.declaredBytes)
  }
  if (profiles.size !== expectedProfiles.size) fail('Cell profile staging index count is incomplete')
  for (const [profileId, bytes] of expectedProfiles) {
    if (profiles.get(profileId) !== bytes) fail('Cell profile staging accounting does not match reservations')
  }
  const expectedControlBytes = [...state.spends.values()].reduce((sum, value) =>
    sum + (chargedReadLifecycleState(value.status) == null ? CONTROL_RECORD_BYTES : value.controlBytes), 0)
  const expectedAccounting = {
    storedBytes: [...state.cells.values()].reduce((sum, value) =>
      sum + (value.objectState === 1 ? CELL_SIZE_CLASS[value.sizeClass] : 0), 0),
    stagingBytes: reserved.reduce((sum, value) => sum + value.declaredBytes, 0),
    controlBytes: expectedControlBytes,
    tombstoneBytes: (state.cells.size + reserved.length) * TOMBSTONE_RECORD_BYTES,
    reservedCells: reserved.length
  }
  const actualAccounting = {
    storedBytes: safeNumber(global.storedBytes, 'storedBytes'),
    stagingBytes: safeNumber(global.stagingBytes, 'stagingBytes'),
    controlBytes: safeNumber(global.controlBytes, 'controlBytes'),
    tombstoneBytes: safeNumber(global.tombstoneBytes, 'tombstoneBytes'),
    reservedCells: safeNumber(global.reservedCells, 'reservedCells')
  }
  for (const field of Object.keys(expectedAccounting)) {
    if (actualAccounting[field] !== expectedAccounting[field]) fail(`Cell ${field} accounting does not reconstruct exactly`)
  }
  const expectedCounts = {
    cellCount: state.cells.size,
    spendCount: state.spends.size,
    commitmentCount: state.commitments.size,
    requestResultCount: state.requestResults.size,
    chargedReadPinnedCount: [...state.spends.values()].filter(value => value.status === 'read-pinned').length,
    chargedReadFinalizedCount: [...state.spends.values()].filter(value => value.status === 'read-finalized').length,
    chargedReadExpiredCount: [...state.spends.values()].filter(value => value.status === 'read-expired').length,
    chargedReadPinnedEntryCount: [...state.spends.values()].reduce((sum, value) =>
      sum + (value.status === 'read-pinned' || value.status === 'read-finalized' ? value.entries.length : 0), 0),
    profileStagingCount: profiles.size,
    integrityEvidenceCount: evidenceByHash.size
  }
  for (const [field, expected] of Object.entries(expectedCounts)) {
    const actual = field.endsWith('Count') && typeof global[field] === 'number'
      ? global[field]
      : safeNumber(global[field], field)
    if (actual !== expected) fail(`Cell global ${field} does not match reconstructed state`)
  }
  if ((global.recoveryGap === 1) !== (evidenceByHash.size > 0)) {
    fail('Cell recovery-gap state does not match integrity evidence')
  }
  if (context.checkpointEpochFloor != null && epochFloor !== context.checkpointEpochFloor) {
    fail('Cell epoch floor does not match the checkpoint header')
  }
  state.accounting = {
    ...actualAccounting,
    stagingByProfile: profiles
  }
  state.epochFloor = epochFloor
  state.clockUnsafe = global.clockUnsafe === 1
  state.readOnlyReason = global.recoveryGap === 1 ? 'RECOVERY_GAP_READ_ONLY' : null
  state.integrityEvidence = [...evidenceByHash.values()]
  state.chargedReadExpiryHeap.sort((left, right) =>
    left.retryExpiresUnixMillis < right.retryExpiresUnixMillis
      ? -1
      : left.retryExpiresUnixMillis > right.retryExpiresUnixMillis
        ? 1
        : left.spendKey.localeCompare(right.spendKey))
  return { state, count }
}

function assertCommitmentMap (expected, actual) {
  expected = requireMap(expected, 'commitments')
  if (expected.size !== actual.size) fail('Cell commitment index count does not match spends')
  for (const [key, value] of actual) {
    const supplied = expected.get(key)
    if (!supplied || supplied.spendKey !== value.spendKey || supplied.fingerprint !== value.fingerprint) {
      fail('Cell commitment index does not match reconstructed spends')
    }
  }
}

function assertChargedReadExpiryIndex (expected, actual) {
  if (expected == null) return
  if (!Array.isArray(expected)) fail('chargedReadExpiryHeap must be an array')
  const normalized = new Map()
  for (const value of expected) {
    if (!value || typeof value !== 'object' || typeof value.spendKey !== 'string' ||
        !/^[0-9a-f]{64}$/.test(value.spendKey) || typeof value.transactionId !== 'string' ||
        !/^[0-9a-f]{64}$/.test(value.transactionId)) {
      fail('charged-read expiry index contains an invalid key')
    }
    const retryExpiresUnixMillis = asU64(value.retryExpiresUnixMillis,
      'charged-read expiry retryExpiresUnixMillis')
    if (normalized.has(value.spendKey)) fail('charged-read expiry index repeats a spend')
    normalized.set(value.spendKey, `${retryExpiresUnixMillis}:${value.transactionId}`)
  }
  if (normalized.size !== actual.length) fail('charged-read expiry index count does not match active retry pins')
  for (const value of actual) {
    if (normalized.get(value.spendKey) !== `${value.retryExpiresUnixMillis}:${value.transactionId}`) {
      fail('charged-read expiry index does not match reconstructed active retry pins')
    }
  }
}

function ownedTuple (header) {
  if (!header || typeof header !== 'object') fail('snapshot semantic header is required')
  return {
    relayPublicKey: cloneBytes(asBytes(header.relayPublicKey, 32, 'header relayPublicKey', true)),
    storeId: cloneBytes(asBytes(header.storeId, 32, 'header storeId', true)),
    durabilityContinuityHash: cloneBytes(asBytes(header.durabilityContinuityHash, 32, 'header durabilityContinuityHash', true)),
    walSequence: asU64(header.walSequence, 'header walSequence'),
    walHash: cloneBytes(asBytes(header.walHash, 32, 'header walHash', true))
  }
}

export function createBlindCellControlSnapshotSemanticAuthority (options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('Cell semantic authority options must be an object')
  }
  const partitionKey = cloneBytes(asBytes(options.partitionKey, 32, 'partitionKey', true))
  const authority = Object.freeze({
    kind: 'BLIND_CELL_CONTROL_SNAPSHOT_RECOVERY_SEMANTIC_AUTHORITY_V1',
    productionComplete: false,
    publicationAuthorized: false
  })
  AUTHORITIES.set(authority, Object.freeze({ partitionKey }))
  return authority
}

export async function * streamBlindCellControlSnapshotEntries (authority, engineState) {
  const authorityState = assertAuthority(authority)
  const entries = candidateEntries(engineState)
  const reconstructed = await reconstructEntries(entries, {
    relayPublicKey: engineState.relayPublicKey,
    storeId: engineState.storeId,
    durabilityContinuityHash: engineState.durabilityContinuityHash,
    partitionKey: authorityState.partitionKey,
    checkpointEpochFloor: engineState.epochFloor,
    declaredEntryCount: entries.length
  })
  assertCommitmentMap(engineState.commitments, reconstructed.state.commitments)
  assertChargedReadExpiryIndex(engineState.chargedReadExpiryHeap,
    reconstructed.state.chargedReadExpiryHeap)
  for (const entry of entries) yield entry
}

export async function captureBlindCellStorageEngineControlSnapshot (authority, engine) {
  assertAuthority(authority)
  if (!engine || typeof engine.captureControlSnapshotState !== 'function') {
    throw new TypeError('a live BlindCellStorageEngine is required')
  }
  const brandedState = await engine.captureControlSnapshotState()
  const state = verifyBlindCellStorageControlSnapshotState(brandedState)
  const entries = candidateEntries(state)
  const authorityState = assertAuthority(authority)
  const reconstructed = await reconstructEntries(entries, {
    relayPublicKey: state.relayPublicKey,
    storeId: state.storeId,
    durabilityContinuityHash: state.durabilityContinuityHash,
    partitionKey: authorityState.partitionKey,
    checkpointEpochFloor: state.epochFloor,
    declaredEntryCount: entries.length
  })
  assertCommitmentMap(state.commitments, reconstructed.state.commitments)
  assertChargedReadExpiryIndex(state.chargedReadExpiryHeap,
    reconstructed.state.chargedReadExpiryHeap)
  const header = Object.freeze({
    relayPublicKey: cloneBytes(state.relayPublicKey),
    storeId: cloneBytes(state.storeId),
    durabilityContinuityHash: cloneBytes(state.durabilityContinuityHash),
    walSequence: state.walSequence,
    walHash: cloneBytes(state.walHash)
  })
  const checkpointHeader = Object.freeze({
    relayPublicKey: cloneBytes(state.relayPublicKey),
    storeId: cloneBytes(state.storeId),
    durabilityContinuityHash: cloneBytes(state.durabilityContinuityHash),
    coveredWalSequence: state.walSequence,
    coveredWalHash: cloneBytes(state.walHash),
    epochFloor: state.epochFloor
  })
  return Object.freeze({
    header,
    checkpointHeader,
    declaredEntryCount: entries.length,
    entries: Object.freeze(entries.map(entry => Object.freeze({
      entryKind: entry.entryKind,
      key: cloneBytes(entry.key),
      value: cloneBytes(entry.value)
    }))),
    publicationAuthorized: false,
    productionComplete: false
  })
}

export async function reconstructBlindCellControlSnapshot (authority, input = {}) {
  const authorityState = assertAuthority(authority)
  const tuple = ownedTuple(input.header)
  const checkpointHeader = input.checkpointHeader
  if (!checkpointHeader || typeof checkpointHeader !== 'object') fail('checkpointHeader is required for Cell reconstruction')
  if (!b4a.equals(tuple.relayPublicKey, asBytes(checkpointHeader.relayPublicKey, 32, 'checkpoint relayPublicKey', true)) ||
      !b4a.equals(tuple.storeId, asBytes(checkpointHeader.storeId, 32, 'checkpoint storeId', true)) ||
      !b4a.equals(tuple.durabilityContinuityHash,
        asBytes(checkpointHeader.durabilityContinuityHash, 32, 'checkpoint durabilityContinuityHash', true)) ||
      tuple.walSequence !== asU64(checkpointHeader.coveredWalSequence, 'checkpoint coveredWalSequence') ||
      !b4a.equals(tuple.walHash, asBytes(checkpointHeader.coveredWalHash, 32, 'checkpoint coveredWalHash', true))) {
    fail('Cell semantic snapshot tuple does not match its checkpoint header')
  }
  const declaredEntryCount = integer(input.declaredEntryCount, 1, 0x1000000, 'declaredEntryCount')
  const reconstructed = await reconstructEntries(input.entries, {
    relayPublicKey: tuple.relayPublicKey,
    storeId: tuple.storeId,
    durabilityContinuityHash: tuple.durabilityContinuityHash,
    partitionKey: authorityState.partitionKey,
    checkpointEpochFloor: integer(checkpointHeader.epochFloor, 0, 0xffffffff, 'checkpoint epochFloor'),
    declaredEntryCount
  })
  const verified = Object.freeze({
    ...tuple,
    entryCount: reconstructed.count,
    cellState: reconstructed.state,
    cellComplete: true,
    recoveryVerified: true,
    publicationAuthorized: false,
    productionComplete: false,
    exclusions: BLIND_CELL_CONTROL_SNAPSHOT_STATUS.exclusions
  })
  const result = {}
  for (const field of ['relayPublicKey', 'storeId', 'durabilityContinuityHash', 'walHash']) {
    Object.defineProperty(result, field, {
      enumerable: true,
      get: () => cloneBytes(verified[field])
    })
  }
  Object.defineProperty(result, 'cellState', {
    enumerable: true,
    get: () => cloneStateValue(verified.cellState)
  })
  for (const field of [
    'walSequence', 'entryCount', 'cellComplete', 'recoveryVerified',
    'publicationAuthorized', 'productionComplete', 'exclusions'
  ]) {
    Object.defineProperty(result, field, { enumerable: true, value: verified[field] })
  }
  Object.freeze(result)
  VERIFIED_RESULTS.set(result, verified)
  return result
}

export function createBlindCellControlSnapshotSemanticVerifier (authority) {
  const state = assertAuthority(authority)
  const verifier = input => reconstructBlindCellControlSnapshot(authority, input)
  VERIFIERS.set(verifier, state)
  return verifier
}

export function verifyBlindCellControlSnapshotSemanticVerifier (verifier) {
  if (!VERIFIERS.has(verifier)) throw new TypeError('a branded Cell control snapshot semantic verifier is required')
  return verifier
}

export function verifyBlindCellControlSnapshotSemanticVerifierPartitionKey (verifier, partitionKey) {
  const state = VERIFIERS.get(verifier)
  if (!state) throw new TypeError('a branded Cell control snapshot semantic verifier is required')
  if (!b4a.equals(state.partitionKey, asBytes(partitionKey, 32, 'partitionKey', true))) {
    fail('Cell control snapshot semantic verifier partition key does not match')
  }
  return verifier
}

export function verifyBlindCellControlSnapshotSemanticResult (result, expected = {}) {
  const verified = VERIFIED_RESULTS.get(result)
  if (!verified) throw new TypeError('a branded Cell control snapshot semantic result is required')
  if (expected.entryCount != null && verified.entryCount !== expected.entryCount) fail('Cell semantic result entryCount does not match')
  if (expected.walSequence != null && verified.walSequence !== asU64(expected.walSequence, 'expected walSequence')) {
    fail('Cell semantic result walSequence does not match')
  }
  for (const field of ['relayPublicKey', 'storeId', 'durabilityContinuityHash', 'walHash']) {
    if (expected[field] != null && !b4a.equals(verified[field], asBytes(expected[field], 32, `expected ${field}`))) {
      fail(`Cell semantic result ${field} does not match`)
    }
  }
  if (verified.publicationAuthorized !== false || verified.productionComplete !== false) {
    fail('Cell semantic result must not claim publication or complete-daemon authority')
  }
  return result
}
