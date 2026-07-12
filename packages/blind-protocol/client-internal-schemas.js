import b4a from 'b4a'
import {
  arrayOf,
  boundedBytes,
  canonicalAsciiBytes,
  constant,
  constantBytes,
  exactBytesByClass,
  fixedBytes,
  optional,
  ranged,
  struct,
  u8,
  u16be,
  u32be,
  u64be
} from './codec.js'
import { protocolError } from './errors.js'
import { CELL_SIZE_CLASS, CORE_SESSION_CLASS, INBOX_FRAME_CLASS, OPERATION } from './registry.js'
import {
  blindCoreReadCapV1,
  readCellCapV1
} from './client-composition-external-codecs.js'

export { blindCoreReadCapV1, readCellCapV1 }

const bytes12 = fixedBytes(12)
const bytes32 = fixedBytes(32)
const bytes64 = fixedBytes(64)
const version1 = constant(u8, 1, 'version')
const version2 = constant(u8, 2, 'version')
const booleanU8 = ranged(u8, 0, 1, 'boolean')

function fail (message) {
  protocolError('BAD_ENCODING', message)
}

function isZero (value) {
  for (const byte of value) if (byte !== 0) return false
  return true
}

function nonzero (value, field) {
  if (isZero(value)) fail(`${field} must be nonzero`)
}

function asU64 (value, field) {
  if (typeof value === 'number') value = BigInt(value)
  if (typeof value !== 'bigint' || value < 0n || value > ((1n << 64n) - 1n)) fail(`${field} is outside u64`)
  return value
}

function compareBytes (left, right) {
  return b4a.compare(left, right)
}

function assertSorted (values, compare, name) {
  for (let index = 1; index < values.length; index++) {
    if (compare(values[index - 1], values[index]) >= 0) fail(`${name} must be strictly sorted and duplicate-free`)
  }
}

function capped (encoding, maximum, name) {
  return {
    preencode (state, value) {
      const start = state.end
      encoding.preencode(state, value)
      if (state.end - start > maximum) fail(`${name} exceeds ${maximum} bytes`)
    },
    encode (state, value) { encoding.encode(state, value) },
    decode (state) {
      const start = state.start
      const value = encoding.decode(state)
      if (state.start - start > maximum) fail(`${name} exceeds ${maximum} bytes`)
      return value
    }
  }
}

export const writeCellCapV1 = struct([
  ['readCap', readCellCapV1],
  ['allocationEpoch', u32be],
  ['createPrivateKey', bytes32],
  ['renewPrivateKey', bytes32],
  ['dropPrivateKey', bytes32]
], {
  name: 'WriteCellCapV1',
  validate (value) {
    for (const field of ['createPrivateKey', 'renewPrivateKey', 'dropPrivateKey']) nonzero(value[field], field)
    const keys = [value.createPrivateKey, value.renewPrivateKey, value.dropPrivateKey]
    if (new Set(keys.map(key => b4a.toString(key, 'hex'))).size !== keys.length) fail('write capability private keys must be distinct')
  }
})

// CellBlobV1 is intentionally contextual: sizeClass is carried by the enclosing
// capability/record, not serialized into the blob. Calling the factory freezes
// the only byte length a decoder may accept.
export function cellBlobV1 (sizeClass) {
  const totalLength = CELL_SIZE_CLASS[sizeClass]
  if (!totalLength) throw new RangeError('CellBlobV1 sizeClass must be 1..5')
  return struct([
    ['formatVersion', version1],
    ['nonce', bytes12],
    ['sealed', fixedBytes(totalLength - 13, `sealed class ${sizeClass}`)]
  ], { name: `CellBlobV1(class=${sizeClass})` })
}

export const CELL_BLOB_V1_BY_SIZE_CLASS = Object.freeze(Object.fromEntries(
  Object.keys(CELL_SIZE_CLASS).map(sizeClass => [sizeClass, cellBlobV1(Number(sizeClass))])
))

const frontierEntryV1 = struct([
  ['chainId', bytes32],
  ['sequence', u64be],
  ['frameHash', bytes32]
], {
  name: 'OpaqueChainFrontierEntryV1',
  validate (value) {
    nonzero(value.chainId, 'chainId')
    nonzero(value.frameHash, 'frameHash')
  }
})

export const opaqueChainCheckpointV1 = struct([
  ['version', version1],
  ['coveredFrontier', arrayOf(frontierEntryV1, 1, 1024, 'coveredFrontier')],
  ['opaqueStateCommitment', bytes32],
  ['snapshotPayloadHash', bytes32],
  ['snapshotReadCaps', arrayOf(readCellCapV1, 1, 16, 'snapshotReadCaps')]
], {
  name: 'OpaqueChainCheckpointV1',
  validate (value) {
    assertSorted(value.coveredFrontier, (left, right) => compareBytes(left.chainId, right.chainId), 'coveredFrontier')
    assertSorted(value.snapshotReadCaps, (left, right) => {
      const relay = compareBytes(left.relayPublicKey, right.relayPublicKey)
      return relay || compareBytes(left.storageSlot, right.storageSlot)
    }, 'snapshotReadCaps')
    nonzero(value.opaqueStateCommitment, 'opaqueStateCommitment')
    nonzero(value.snapshotPayloadHash, 'snapshotPayloadHash')
  }
})

export const opaqueChainFrameV1 = struct([
  ['version', version1],
  ['chainId', bytes32],
  ['sequence', u64be],
  ['previousFrameHash', optional(bytes32, 'previousFrameHash')],
  ['transportVerifyKey', bytes32],
  ['opaquePayloads', arrayOf(boundedBytes(0, 256 * 1024, 'opaquePayload'), 0, 256, 'opaquePayloads')],
  ['nextReadCellCaps', arrayOf(readCellCapV1, 0, 16, 'nextReadCellCaps')],
  ['checkpoint', optional(opaqueChainCheckpointV1, 'checkpoint')],
  ['transportSignature', bytes64]
], {
  name: 'OpaqueChainFrameV1',
  validate (value) {
    nonzero(value.chainId, 'chainId')
    nonzero(value.transportVerifyKey, 'transportVerifyKey')
    const sequence = asU64(value.sequence, 'sequence')
    if ((sequence === 0n) !== (value.previousFrameHash == null)) {
      fail('previousFrameHash is absent exactly at sequence zero')
    }
    assertSorted(value.nextReadCellCaps, (left, right) => {
      const relay = compareBytes(left.relayPublicKey, right.relayPublicKey)
      return relay || compareBytes(left.storageSlot, right.storageSlot)
    }, 'nextReadCellCaps')
    if (value.opaquePayloads.length === 0 && value.checkpoint == null) fail('opaque chain frame needs a payload or checkpoint')
  }
})

const cellBlob = exactBytesByClass('sizeClass', CELL_SIZE_CLASS, 'cellBlob')

export const cellRecordV1 = struct([
  ['version', version1],
  ['slot', bytes32],
  ['allocationEpoch', u32be],
  ['sizeClass', ranged(u8, 1, 5, 'sizeClass')],
  ['leaseClass', ranged(u8, 1, 4, 'leaseClass')],
  ['leaseEpoch', u32be],
  ['stateRevision', u64be],
  ['policyRevision', u64be],
  ['cellBlobHash', bytes32],
  ['cellBlob', cellBlob],
  ['createPublicKey', bytes32],
  ['renewPublicKey', bytes32],
  ['dropPublicKey', bytes32],
  ['allocationCommitment', bytes32]
], {
  name: 'CellRecordV1',
  validate (value) {
    for (const field of [
      'slot', 'cellBlobHash', 'createPublicKey', 'renewPublicKey', 'dropPublicKey', 'allocationCommitment'
    ]) nonzero(value[field], field)
  }
})

export const chargedUnaryRetryV1 = capped(struct([
  ['version', version1],
  ['spendTag', bytes32],
  ['requestCommitment', bytes32],
  ['familyId', ranged(u8, 1, 5, 'familyId')],
  ['operationId', ranged(u8, 1, 255, 'operationId')],
  ['locatorCommitment', bytes32],
  ['sourceRevision', u64be],
  ['sourceCommitment', bytes32],
  ['resultCommitment', bytes32],
  ['reconstruction', boundedBytes(0, 96, 'reconstruction')],
  ['retryExpiresMinute', u64be],
  ['retryState', ranged(u8, 1, 3, 'retryState')]
], {
  name: 'ChargedUnaryRetryV1',
  validate (value) {
    for (const field of ['spendTag', 'requestCommitment', 'locatorCommitment', 'sourceCommitment', 'resultCommitment']) {
      nonzero(value[field], field)
    }
  }
}), 256, 'ChargedUnaryRetryV1')

const controlStateEntryV1 = struct([
  ['entryKind', ranged(u8, 1, 8, 'entryKind')],
  ['key', boundedBytes(1, 256, 'key')],
  ['value', boundedBytes(0, 0xffff, 'value')]
], { name: 'BlindControlStateSnapshotEntryV1' })

export const blindPreparedAdmissionStoreV1 = struct([
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
], {
  name: 'BlindPreparedAdmissionStoreV1',
  validate (value) {
    for (const field of ['spendTag', 'requestCommitment', 'parameterHash']) nonzero(value[field], field)
  }
})

const cellIngressSnapshotFields = remainingAttempts => [
  ['version', version1],
  ['transactionId', bytes32],
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
  ['remainingAttempts', remainingAttempts],
  ['reservedEpoch', u32be]
]

function validateCellIngressSnapshot (value, extra = []) {
  for (const field of [
    'transactionId', 'spendTag', 'requestCommitment', 'requestFingerprint', 'storageSlot',
    'declaredBlobHash', 'createPublicKey', 'renewPublicKey', 'dropPublicKey', 'allocationCommitment',
    ...extra
  ]) nonzero(value[field], field)
  if (asU64(value.deadlineUnixMillis, 'deadlineUnixMillis') === 0n) fail('deadlineUnixMillis must be nonzero')
}

export const blindCellHistoricalResultSnapshotV1 = struct([
  ['storageSlot', bytes32],
  ['allocationEpoch', u32be],
  ['sizeClass', ranged(u8, 1, 5, 'sizeClass')],
  ['leaseClass', ranged(u8, 1, 4, 'leaseClass')],
  ['leaseEpoch', u32be],
  ['stateRevision', u64be],
  ['policyRevision', u64be],
  ['cellBlobHash', bytes32],
  ['allocationCommitment', bytes32],
  ['objectState', ranged(u8, 1, 2, 'objectState')],
  ['policyState', ranged(u8, 1, 2, 'policyState')]
], {
  name: 'BlindCellHistoricalResultSnapshotV1',
  validate (value) {
    for (const field of ['storageSlot', 'cellBlobHash', 'allocationCommitment']) nonzero(value[field], field)
  }
})

export const blindCellReservedSpendSnapshotV1 = struct([
  ...cellIngressSnapshotFields(ranged(u8, 0, 2, 'remainingAttempts'))
], {
  name: 'BlindCellReservedSpendSnapshotV1',
  validate (value) { validateCellIngressSnapshot(value) }
})

export const blindCellCommittedPutSpendSnapshotV1 = struct([
  ...cellIngressSnapshotFields(ranged(u8, 0, 1, 'remainingAttempts')),
  ['resultIdentity', bytes32],
  ['committedEpoch', u32be],
  ['resultCell', blindCellHistoricalResultSnapshotV1]
], {
  name: 'BlindCellCommittedPutSpendSnapshotV1',
  validate (value) { validateCellIngressSnapshot(value, ['resultIdentity']) }
})

export const blindCellTerminalSpendSnapshotV1 = struct([
  ...cellIngressSnapshotFields(ranged(u8, 0, 2, 'remainingAttempts')),
  ['terminalReason', ranged(u8, 1, 3, 'terminalReason')],
  ['terminalEpoch', u32be]
], {
  name: 'BlindCellTerminalSpendSnapshotV1',
  validate (value) { validateCellIngressSnapshot(value) }
})

export const BLIND_CELL_CHARGED_READ_LIFECYCLE_STATE = Object.freeze({
  PINNED: 1,
  FINALIZED: 2,
  EXPIRED: 3
})

export const blindCellChargedReadPinEntrySnapshotV1 = struct([
  ['storageSlot', bytes32],
  ['present', booleanU8],
  ['sizeClass', ranged(u8, 0, 5, 'sizeClass')],
  ['allocationEpoch', u32be],
  ['leaseClass', ranged(u8, 0, 4, 'leaseClass')],
  ['leaseEpoch', u32be],
  ['stateRevision', u64be],
  ['policyRevision', u64be],
  ['cellBlobHash', bytes32],
  ['allocationCommitment', bytes32]
], {
  name: 'BlindCellChargedReadPinEntrySnapshotV1',
  validate (value) {
    nonzero(value.storageSlot, 'storageSlot')
    if (value.present === 0) {
      if (value.sizeClass !== 0 || value.allocationEpoch !== 0 || value.leaseClass !== 0 ||
          value.leaseEpoch !== 0 || asU64(value.stateRevision, 'stateRevision') !== 0n ||
          asU64(value.policyRevision, 'policyRevision') !== 0n || !isZero(value.cellBlobHash) ||
          !isZero(value.allocationCommitment)) {
        fail('absent charged-read pin entry must use its exact zero state')
      }
      return
    }
    if (value.sizeClass === 0 || value.leaseClass === 0 || isZero(value.cellBlobHash) ||
        isZero(value.allocationCommitment)) {
      fail('present charged-read pin entry is incomplete')
    }
  }
})

const blindCellChargedReadPinEntriesSnapshotV1 = arrayOf(
  blindCellChargedReadPinEntrySnapshotV1,
  1,
  64,
  'charged read pin entries'
)

export const blindCellChargedReadRetrySnapshotV1 = struct([
  ['version', version1],
  ['lifecycleState', ranged(u8, 1, 3, 'lifecycleState')],
  ['operationId', ranged(u8, OPERATION.CELL.GET, OPERATION.CELL.BATCH_GET, 'operationId')],
  ['transactionId', bytes32],
  ['spendTag', bytes32],
  ['requestCommitment', bytes32],
  ['requestFingerprint', bytes32],
  ['preparedAdmissionBytes', optional(boundedBytes(1, 17408, 'preparedAdmissionBytes'), 'preparedAdmissionBytes')],
  ['resultBindingBytes', optional(boundedBytes(1, 1024, 'resultBindingBytes'), 'resultBindingBytes')],
  ['receiptEpoch', optional(u32be, 'receiptEpoch')],
  ['retryExpiresUnixMillis', u64be],
  ['entries', optional(blindCellChargedReadPinEntriesSnapshotV1, 'entries')],
  ['resultCommitment', optional(bytes32, 'resultCommitment')],
  ['committedEpoch', u32be],
  ['terminalEpoch', optional(u32be, 'terminalEpoch')]
], {
  name: 'BlindCellChargedReadRetrySnapshotV1',
  validate (value) {
    if (value.operationId !== OPERATION.CELL.GET && value.operationId !== OPERATION.CELL.PROVE &&
        value.operationId !== OPERATION.CELL.BATCH_GET) fail('unknown charged CELL read operation')
    for (const field of ['transactionId', 'spendTag', 'requestCommitment', 'requestFingerprint']) {
      nonzero(value[field], field)
    }
    if (asU64(value.retryExpiresUnixMillis, 'retryExpiresUnixMillis') === 0n) {
      fail('retryExpiresUnixMillis must be nonzero')
    }
    const active = value.lifecycleState !== BLIND_CELL_CHARGED_READ_LIFECYCLE_STATE.EXPIRED
    if (active !== (value.preparedAdmissionBytes != null) ||
        active !== (value.resultBindingBytes != null) ||
        active !== (value.receiptEpoch != null) ||
        active !== (value.entries != null)) {
      fail('charged-read retry active fields do not match lifecycleState')
    }
    if (active && value.operationId !== OPERATION.CELL.BATCH_GET && value.entries.length !== 1) {
      fail('charged unary CELL read must pin exactly one entry')
    }
    if (active && value.operationId !== OPERATION.CELL.BATCH_GET && value.entries[0].present !== 1) {
      fail('charged unary CELL read must pin a present cell')
    }
    const finalized = value.lifecycleState === BLIND_CELL_CHARGED_READ_LIFECYCLE_STATE.FINALIZED
    if (finalized !== (value.resultCommitment != null)) {
      fail('charged-read result commitment does not match lifecycleState')
    }
    if (value.resultCommitment != null) nonzero(value.resultCommitment, 'resultCommitment')
    const expired = value.lifecycleState === BLIND_CELL_CHARGED_READ_LIFECYCLE_STATE.EXPIRED
    if (expired !== (value.terminalEpoch != null)) {
      fail('charged-read terminal epoch does not match lifecycleState')
    }
  }
})

export const blindCellCommittedRenewSpendSnapshotV1 = struct([
  ['version', version1],
  ['transactionId', bytes32],
  ['spendTag', bytes32],
  ['requestCommitment', bytes32],
  ['requestFingerprint', bytes32],
  ['storageSlot', bytes32],
  ['expectedStateRevision', u64be],
  ['expectedLeaseEpoch', u32be],
  ['requestedLeaseClass', ranged(u8, 1, 4, 'requestedLeaseClass')],
  ['profileId', ranged(u16be, 1, 0xffff, 'profileId')],
  ['preparedAdmissionBytes', boundedBytes(1, 17408, 'preparedAdmissionBytes')],
  ['resultBindingBytes', optional(boundedBytes(1, 1024, 'resultBindingBytes'), 'resultBindingBytes')],
  ['resultIdentity', bytes32],
  ['committedEpoch', u32be],
  ['resultCell', blindCellHistoricalResultSnapshotV1]
], {
  name: 'BlindCellCommittedRenewSpendSnapshotV1',
  validate (value) {
    for (const field of [
      'transactionId', 'spendTag', 'requestCommitment', 'requestFingerprint', 'storageSlot', 'resultIdentity'
    ]) nonzero(value[field], field)
  }
})

export const blindCellRequestResultSnapshotV1 = struct([
  ['version', version1],
  ['transactionId', bytes32],
  ['requestCommitment', bytes32],
  ['requestFingerprint', bytes32],
  ['storageSlot', bytes32],
  ['resultBindingBytes', optional(boundedBytes(1, 1024, 'resultBindingBytes'), 'resultBindingBytes')],
  ['resultIdentity', bytes32],
  ['committedEpoch', u32be],
  ['resultCell', blindCellHistoricalResultSnapshotV1]
], {
  name: 'BlindCellRequestResultSnapshotV1',
  validate (value) {
    for (const field of [
      'transactionId', 'requestCommitment', 'requestFingerprint', 'storageSlot', 'resultIdentity'
    ]) nonzero(value[field], field)
  }
})

export const blindCellRecordSnapshotV1 = struct([
  ['version', version1],
  ['storageSlot', bytes32],
  ['allocationEpoch', u32be],
  // leaseClass is mutable on renew; allocationLeaseClass is the immutable
  // allocation-commitment input needed to revalidate a recovered record.
  ['allocationLeaseClass', ranged(u8, 1, 4, 'allocationLeaseClass')],
  ['sizeClass', ranged(u8, 1, 5, 'sizeClass')],
  ['leaseClass', ranged(u8, 1, 4, 'leaseClass')],
  ['leaseEpoch', u32be],
  ['stateRevision', u64be],
  ['policyRevision', u64be],
  ['cellBlobHash', bytes32],
  ['blobVirtualBucket', u16be],
  ['blobObjectId', bytes32],
  ['createPublicKey', bytes32],
  ['renewPublicKey', bytes32],
  ['dropPublicKey', bytes32],
  ['allocationCommitment', bytes32],
  ['objectState', ranged(u8, 1, 2, 'objectState')],
  ['policyState', ranged(u8, 1, 2, 'policyState')],
  ['tombstoneReason', optional(ranged(u8, 1, 2, 'tombstoneReason'), 'tombstoneReason')],
  ['terminalEpoch', optional(u32be, 'terminalEpoch')],
  ['createSpendTag', bytes32],
  ['resultIdentity', bytes32],
  ['createdEpoch', u32be]
], {
  name: 'BlindCellRecordSnapshotV1',
  validate (value) {
    for (const field of [
      'storageSlot', 'cellBlobHash', 'blobObjectId', 'createPublicKey', 'renewPublicKey',
      'dropPublicKey', 'allocationCommitment', 'createSpendTag', 'resultIdentity'
    ]) nonzero(value[field], field)
    const tombstone = value.objectState === 2
    if (tombstone !== (value.tombstoneReason != null) || tombstone !== (value.terminalEpoch != null)) {
      fail('cell snapshot tombstone fields do not match objectState')
    }
  }
})

export const blindCellControlGlobalSnapshotV1 = struct([
  ['version', version1],
  ['epochFloor', u32be],
  ['clockUnsafe', booleanU8],
  ['recoveryGap', booleanU8],
  ['storedBytes', u64be],
  ['stagingBytes', u64be],
  ['controlBytes', u64be],
  ['tombstoneBytes', u64be],
  ['reservedCells', u64be],
  ['cellCount', u64be],
  ['spendCount', u64be],
  ['commitmentCount', u64be],
  ['requestResultCount', u64be],
  ['chargedReadPinnedCount', u64be],
  ['chargedReadFinalizedCount', u64be],
  ['chargedReadExpiredCount', u64be],
  ['chargedReadPinnedEntryCount', u64be],
  ['profileStagingCount', u32be],
  ['integrityEvidenceCount', u32be],
  ['controlRecordAccountingBytes', constant(u16be, 512, 'controlRecordAccountingBytes')],
  ['tombstoneRecordAccountingBytes', constant(u16be, 512, 'tombstoneRecordAccountingBytes')]
], { name: 'BlindCellControlGlobalSnapshotV1' })

export const blindCellProfileStagingSnapshotV1 = struct([
  ['version', version1],
  ['profileId', ranged(u16be, 1, 0xffff, 'profileId')],
  ['stagingBytes', u64be]
], {
  name: 'BlindCellProfileStagingSnapshotV1',
  validate (value) {
    if (asU64(value.stagingBytes, 'stagingBytes') === 0n) fail('profile staging bytes must be nonzero')
  }
})

export const blindCellIntegrityEvidenceSnapshotV1 = struct([
  ['version', version1],
  ['reason', ranged(u8, 1, 3, 'reason')],
  ['detectedEpoch', u32be],
  ['evidenceHash', bytes32]
], {
  name: 'BlindCellIntegrityEvidenceSnapshotV1',
  validate (value) { nonzero(value.evidenceHash, 'evidenceHash') }
})

export const BLIND_CORE_OPEN_REPLICATION_LIFECYCLE_STATE = Object.freeze({
  RESERVED: 1,
  LIVE: 2,
  TERMINAL: 3
})

export const blindCoreOpenReplicationRetrySnapshotV1 = struct([
  ['version', version1],
  ['lifecycleState', ranged(u8, 1, 3, 'lifecycleState')],
  ['logicalRetryKey', bytes32],
  ['spendTag', boundedBytes(1, 128, 'spendTag')],
  ['requestCommitment', bytes32],
  ['wireProfileHash', bytes32],
  ['sessionClass', ranged(u8, 1, 3, 'sessionClass')],
  ['clientNonce', bytes32],
  ['parentSessionId', boundedBytes(1, 256, 'parentSessionId')],
  ['controlChannelId', u64be],
  ['parentChannelBinding', bytes32],
  ['streamId', u64be],
  ['maxSessionBytes', u64be],
  ['idleMillis', u32be],
  ['lifetimeMillis', u32be],
  ['openedAtEpoch', u32be],
  ['recordVirtualBucket', u16be],
  ['resultBytes', optional(boundedBytes(1, 16384, 'resultBytes'), 'resultBytes')],
  ['terminalReason', optional(canonicalAsciiBytes(1, 64, 'terminalReason'), 'terminalReason')]
], {
  name: 'BlindCoreOpenReplicationRetrySnapshotV1',
  validate (value) {
    for (const field of [
      'logicalRetryKey', 'spendTag', 'requestCommitment', 'wireProfileHash',
      'parentSessionId', 'parentChannelBinding'
    ]) nonzero(value[field], field)
    if (asU64(value.controlChannelId, 'controlChannelId') === 0n ||
        asU64(value.streamId, 'streamId') === 0n) {
      fail('Core retry controlChannelId and streamId must be nonzero')
    }
    const limits = CORE_SESSION_CLASS[value.sessionClass]
    if (!limits || asU64(value.maxSessionBytes, 'maxSessionBytes') !== BigInt(limits.maxSessionBytes) ||
        value.idleMillis !== limits.idleMillis || value.lifetimeMillis !== limits.lifetimeMillis) {
      fail('Core retry limits do not match sessionClass')
    }
    const terminal = value.lifecycleState === BLIND_CORE_OPEN_REPLICATION_LIFECYCLE_STATE.TERMINAL
    if (terminal !== (value.terminalReason != null)) {
      fail('Core retry terminalReason presence does not match lifecycleState')
    }
    if (!terminal && value.resultBytes == null) {
      fail('Core reserved/live retry records require their signed result')
    }
  }
})

export const blindCoreControlGlobalSnapshotV1 = struct([
  ['version', version1],
  ['epochFloor', u32be],
  ['clockUnsafe', booleanU8],
  ['recordCount', u64be],
  ['reservedCount', u64be],
  ['liveCount', u64be],
  ['terminalCount', u64be],
  ['spendIndexCount', u64be],
  ['logicalIndexCount', u64be],
  ['channelIndexCount', u64be],
  ['resultCount', u64be],
  ['snapshotRecordBytes', u64be]
], { name: 'BlindCoreControlGlobalSnapshotV1' })

const inboxSnapshotOperation = ranged(u8, 1, 6, 'operation')
const inboxSnapshotFrameClass = ranged(u8, 0, 3, 'frameClass')
const inboxSnapshotLeaseClass = ranged(u8, 0, 4, 'requestedLeaseClass')

function validateInboxSpendSnapshot (value, extra = []) {
  for (const field of [
    'transactionId', 'spendTag', 'requestCommitment', 'requestFingerprint', 'physicalTopic',
    ...extra
  ]) nonzero(value[field], field)
  if (asU64(value.deadlineUnixMillis, 'deadlineUnixMillis') === 0n) fail('deadlineUnixMillis must be nonzero')
  const operation = value.operation
  if (![OPERATION.INBOX.CREATE, OPERATION.INBOX.RENEW, OPERATION.INBOX.APPEND,
    OPERATION.INBOX.READ, OPERATION.INBOX.WATCH].includes(operation)) {
    fail('Inbox spend snapshot operation is not charged by the Inbox family')
  }
  const append = operation === OPERATION.INBOX.APPEND
  if (append !== (value.frameHash != null) || append !== (value.frameClass !== 0)) {
    fail('Inbox spend frame fields do not match APPEND')
  }
  if (append) {
    nonzero(value.frameHash, 'frameHash')
    if (value.declaredBytes !== INBOX_FRAME_CLASS[value.frameClass]) {
      fail('Inbox APPEND declaredBytes does not match frameClass')
    }
  } else if (value.declaredBytes !== 0) {
    fail('non-APPEND Inbox spend must declare zero staged frame bytes')
  }
  const leased = operation === OPERATION.INBOX.CREATE || operation === OPERATION.INBOX.RENEW
  if (leased !== (value.requestedLeaseClass !== 0)) {
    fail('Inbox spend requestedLeaseClass does not match CREATE/RENEW')
  }
}

const inboxSpendSnapshotFields = remainingAttempts => [
  ['version', version1],
  ['transactionId', bytes32],
  ['spendTag', bytes32],
  ['requestCommitment', bytes32],
  ['requestFingerprint', bytes32],
  ['physicalTopic', bytes32],
  ['operation', inboxSnapshotOperation],
  ['profileId', ranged(u16be, 1, 0xffff, 'profileId')],
  ['frameClass', inboxSnapshotFrameClass],
  ['frameHash', optional(bytes32, 'frameHash')],
  ['requestedLeaseClass', inboxSnapshotLeaseClass],
  ['declaredBytes', u32be],
  ['deadlineUnixMillis', u64be],
  ['remainingAttempts', remainingAttempts],
  ['reservedEpoch', u32be]
]

export const blindInboxReservedSpendSnapshotV1 = struct([
  ...inboxSpendSnapshotFields(ranged(u8, 0, 2, 'remainingAttempts'))
], {
  name: 'BlindInboxReservedSpendSnapshotV1',
  validate (value) { validateInboxSpendSnapshot(value) }
})

export const blindInboxCommittedSpendSnapshotV1 = struct([
  ...inboxSpendSnapshotFields(ranged(u8, 0, 1, 'remainingAttempts')),
  ['resultIdentity', bytes32],
  ['resultRevision', u64be],
  ['committedEpoch', u32be],
  ['resultLeaseClass', optional(ranged(u8, 1, 4, 'resultLeaseClass'), 'resultLeaseClass')],
  ['resultLeaseEpoch', optional(u32be, 'resultLeaseEpoch')],
  ['resultBindingBytes', boundedBytes(1, 1024, 'resultBindingBytes')],
  ['clientNonce', bytes32],
  ['retentionClassAtAppend', optional(ranged(u8, 1, 4, 'retentionClassAtAppend'), 'retentionClassAtAppend')],
  ['appendLeaseEpoch', optional(u32be, 'appendLeaseEpoch')],
  ['expiresAtEpoch', optional(u32be, 'expiresAtEpoch')],
  ['ackSignature', optional(bytes64, 'ackSignature')],
  ['resultCommitment', optional(bytes32, 'resultCommitment')],
  ['retryState', ranged(u8, 0, 3, 'retryState')]
], {
  name: 'BlindInboxCommittedSpendSnapshotV1',
  validate (value) {
    validateInboxSpendSnapshot(value, ['resultIdentity'])
    const retryOperation = value.operation === OPERATION.INBOX.READ || value.operation === OPERATION.INBOX.WATCH
    const append = value.operation === OPERATION.INBOX.APPEND
    const leaseMutation = value.operation === OPERATION.INBOX.CREATE || value.operation === OPERATION.INBOX.RENEW
    if (retryOperation !== (value.retryState !== 0)) {
      fail('Inbox committed retryState does not match READ/WATCH')
    }
    if ((retryOperation || append) !== (value.resultCommitment != null)) {
      fail('Inbox committed resultCommitment does not match READ/WATCH/APPEND')
    }
    if (value.resultCommitment != null) nonzero(value.resultCommitment, 'resultCommitment')
    nonzero(value.clientNonce, 'clientNonce')
    if (leaseMutation !== (value.resultLeaseClass != null) ||
        leaseMutation !== (value.resultLeaseEpoch != null)) {
      fail('Inbox committed lease result presence does not match CREATE/RENEW')
    }
    if (leaseMutation && (value.resultLeaseClass !== value.requestedLeaseClass ||
        value.resultLeaseEpoch <= value.committedEpoch)) {
      fail('Inbox committed lease result does not match its request and commit epoch')
    }
    for (const field of [
      'retentionClassAtAppend', 'appendLeaseEpoch', 'expiresAtEpoch', 'ackSignature'
    ]) {
      if (append !== (value[field] != null)) fail(`Inbox committed ${field} presence does not match APPEND`)
    }
    if (append) {
      nonzero(value.clientNonce, 'clientNonce')
      nonzero(value.ackSignature, 'ackSignature')
      const expiresAtEpoch = Math.min(value.appendLeaseEpoch,
        value.committedEpoch + [0, 4, 28, 120, 360][value.retentionClassAtAppend])
      if (value.expiresAtEpoch !== expiresAtEpoch || value.expiresAtEpoch <= value.committedEpoch) {
        fail('Inbox committed APPEND expiry does not match retention and append lease')
      }
    }
  }
})

export const blindInboxExpiredAppendSpendSnapshotV1 = struct([
  ['version', version1],
  ['transactionId', bytes32],
  ['spendTag', bytes32],
  ['requestCommitment', bytes32],
  ['requestFingerprint', bytes32],
  ['physicalTopic', bytes32],
  ['profileId', ranged(u16be, 1, 0xffff, 'profileId')],
  ['frameClass', ranged(u8, 1, 3, 'frameClass')],
  ['frameHash', bytes32],
  ['declaredBytes', u32be],
  ['deadlineUnixMillis', u64be],
  ['remainingAttempts', ranged(u8, 0, 1, 'remainingAttempts')],
  ['reservedEpoch', u32be],
  ['resultIdentity', bytes32],
  ['appendRevision', u64be],
  ['storedAtEpoch', u32be],
  ['retentionClassAtAppend', ranged(u8, 1, 4, 'retentionClassAtAppend')],
  ['appendLeaseEpoch', u32be],
  ['expiresAtEpoch', u32be],
  ['expiredEpoch', u32be],
  ['clientNonce', bytes32],
  ['resultBindingBytes', boundedBytes(1, 1024, 'resultBindingBytes')],
  ['ackSignature', bytes64],
  ['resultCommitment', bytes32]
], {
  name: 'BlindInboxExpiredAppendSpendSnapshotV1',
  validate (value) {
    for (const field of [
      'transactionId', 'spendTag', 'requestCommitment', 'requestFingerprint', 'physicalTopic',
      'frameHash', 'resultIdentity', 'clientNonce', 'ackSignature', 'resultCommitment'
    ]) nonzero(value[field], field)
    if (value.declaredBytes !== INBOX_FRAME_CLASS[value.frameClass]) {
      fail('expired Inbox APPEND declaredBytes does not match frameClass')
    }
    if (asU64(value.deadlineUnixMillis, 'deadlineUnixMillis') === 0n ||
        asU64(value.appendRevision, 'appendRevision') === 0n) {
      fail('expired Inbox APPEND deadline and revision must be nonzero')
    }
    const expiresAtEpoch = Math.min(value.appendLeaseEpoch,
      value.storedAtEpoch + [0, 4, 28, 120, 360][value.retentionClassAtAppend])
    if (value.expiresAtEpoch !== expiresAtEpoch || value.expiresAtEpoch <= value.storedAtEpoch ||
        value.expiredEpoch < value.expiresAtEpoch) {
      fail('expired Inbox APPEND epoch facts are inconsistent')
    }
  }
})

export const blindInboxTerminalSpendSnapshotV1 = struct([
  ...inboxSpendSnapshotFields(ranged(u8, 0, 2, 'remainingAttempts')),
  ['terminalReason', ranged(u8, 1, 3, 'terminalReason')],
  ['terminalEpoch', u32be]
], {
  name: 'BlindInboxTerminalSpendSnapshotV1',
  validate (value) { validateInboxSpendSnapshot(value) }
})

export const blindInboxRequestResultSnapshotV1 = struct([
  ['version', version1],
  ['transactionId', bytes32],
  ['requestCommitment', bytes32],
  ['physicalTopic', bytes32],
  ['resultIdentity', bytes32],
  ['resultRevision', u64be],
  ['committedEpoch', u32be],
  ['resultBindingBytes', boundedBytes(1, 1024, 'resultBindingBytes')],
  ['clientNonce', bytes32],
  ['resultLeaseClass', constant(u8, 0, 'resultLeaseClass')],
  ['resultLeaseEpoch', u32be]
], {
  name: 'BlindInboxRequestResultSnapshotV1',
  validate (value) {
    for (const field of ['transactionId', 'requestCommitment', 'physicalTopic', 'resultIdentity']) {
      nonzero(value[field], field)
    }
    nonzero(value.clientNonce, 'clientNonce')
    if (asU64(value.resultRevision, 'resultRevision') === 0n) fail('Inbox close resultRevision must be nonzero')
  }
})

export const blindInboxRecordSnapshotV1 = struct([
  ['version', version1],
  ['physicalTopic', bytes32],
  ['metadataVirtualBucket', u16be],
  ['allocationEpoch', u32be],
  ['allocationLeaseClass', ranged(u8, 1, 4, 'allocationLeaseClass')],
  ['frameClassBits', ranged(u8, 1, 7, 'frameClassBits')],
  ['appendAuthMode', booleanU8],
  ['appendPublicKey', optional(bytes32, 'appendPublicKey')],
  ['createPublicKey', bytes32],
  ['renewPublicKey', bytes32],
  ['closePublicKey', bytes32],
  ['retentionClass', ranged(u8, 1, 4, 'retentionClass')],
  ['leaseClass', ranged(u8, 1, 4, 'leaseClass')],
  ['leaseEpoch', u32be],
  ['stateRevision', u64be],
  ['policyRevision', u64be],
  ['appendRevision', u64be],
  ['createCommitment', bytes32],
  ['objectState', ranged(u8, 1, 2, 'objectState')],
  ['policyState', ranged(u8, 1, 2, 'policyState')],
  ['tombstoneReason', optional(ranged(u8, 1, 2, 'tombstoneReason'), 'tombstoneReason')],
  ['terminalEpoch', optional(u32be, 'terminalEpoch')],
  ['createSpendTag', bytes32],
  ['createRequestCommitment', bytes32],
  ['resultIdentity', bytes32],
  ['createdEpoch', u32be]
], {
  name: 'BlindInboxRecordSnapshotV1',
  validate (value) {
    for (const field of [
      'physicalTopic', 'createPublicKey', 'renewPublicKey', 'closePublicKey', 'createCommitment',
      'createSpendTag', 'createRequestCommitment', 'resultIdentity'
    ]) nonzero(value[field], field)
    if ((value.appendAuthMode === 1) !== (value.appendPublicKey != null)) {
      fail('Inbox snapshot appendPublicKey presence does not match appendAuthMode')
    }
    if (value.appendPublicKey != null) nonzero(value.appendPublicKey, 'appendPublicKey')
    const keys = [value.createPublicKey, value.renewPublicKey, value.closePublicKey]
    if (value.appendPublicKey != null) keys.push(value.appendPublicKey)
    if (new Set(keys.map(key => b4a.toString(key, 'hex'))).size !== keys.length) {
      fail('Inbox snapshot management keys must be distinct')
    }
    const tombstone = value.objectState === 2
    if (tombstone !== (value.tombstoneReason != null) || tombstone !== (value.terminalEpoch != null)) {
      fail('Inbox snapshot tombstone fields do not match objectState')
    }
  }
})

export const blindInboxFrameSnapshotV1 = struct([
  ['version', version1],
  ['physicalTopic', bytes32],
  ['appendRevision', u64be],
  ['frameHash', bytes32],
  ['frameClass', ranged(u8, 1, 3, 'frameClass')],
  ['frameVirtualBucket', u16be],
  ['frameObjectId', bytes32],
  ['appendLeaseEpoch', u32be],
  ['storedAtEpoch', u32be],
  ['expiresAtEpoch', u32be],
  ['spendTag', bytes32],
  ['requestCommitment', bytes32],
  ['resultIdentity', bytes32]
], {
  name: 'BlindInboxFrameSnapshotV1',
  validate (value) {
    for (const field of [
      'physicalTopic', 'frameHash', 'frameObjectId', 'spendTag', 'requestCommitment', 'resultIdentity'
    ]) nonzero(value[field], field)
    if (asU64(value.appendRevision, 'appendRevision') === 0n) fail('Inbox appendRevision must be nonzero')
    if (value.expiresAtEpoch <= value.storedAtEpoch) fail('Inbox frame expiresAtEpoch must follow storedAtEpoch')
  }
})

export const blindInboxRetryReconstructionV1 = struct([
  ['version', version1],
  ['firstAppendRevision', u64be],
  ['lastAppendRevision', u64be],
  ['entryCount', ranged(u8, 0, 64, 'entryCount')],
  ['nextCursorHash', bytes32]
], {
  name: 'BlindInboxRetryReconstructionV1',
  validate (value) {
    const first = asU64(value.firstAppendRevision, 'firstAppendRevision')
    const last = asU64(value.lastAppendRevision, 'lastAppendRevision')
    const empty = value.entryCount === 0
    if (empty !== (first === 0n && last === 0n)) {
      fail('Inbox retry empty range does not match entryCount')
    }
    if (!empty && (first === 0n || last < first)) {
      fail('Inbox retry append range is invalid')
    }
  }
})

export const blindInboxRetryFramePinSnapshotV1 = struct([
  ['version', version1],
  ['spendTag', bytes32],
  ['physicalTopic', bytes32],
  ['appendRevision', u64be],
  ['frameHash', bytes32]
], {
  name: 'BlindInboxRetryFramePinSnapshotV1',
  validate (value) {
    for (const field of ['spendTag', 'physicalTopic', 'frameHash']) nonzero(value[field], field)
    if (asU64(value.appendRevision, 'appendRevision') === 0n) fail('Inbox retry pin appendRevision must be nonzero')
  }
})

export const blindInboxRetryMaterialSnapshotV1 = struct([
  ['version', version1],
  ['spendTag', bytes32],
  ['entriesCommitment', bytes32],
  ['nextCursor', optional(boundedBytes(1, 128, 'nextCursor'), 'nextCursor')]
], {
  name: 'BlindInboxRetryMaterialSnapshotV1',
  validate (value) {
    nonzero(value.spendTag, 'spendTag')
    nonzero(value.entriesCommitment, 'entriesCommitment')
  }
})

export const blindInboxControlGlobalSnapshotV1 = struct([
  ['version', version1],
  ['epochFloor', u32be],
  ['clockUnsafe', booleanU8],
  ['recoveryGap', booleanU8],
  ['storedFrameBytes', u64be],
  ['stagingFrameBytes', u64be],
  ['controlBytes', u64be],
  ['tombstoneBytes', u64be],
  ['frameIndexBytes', u64be],
  ['reservedFrames', u64be],
  ['inboxCount', u64be],
  ['frameCount', u64be],
  ['spendCount', u64be],
  ['commitmentCount', u64be],
  ['requestResultCount', u64be],
  ['retryRecordCount', u64be],
  ['retryFramePinCount', u64be],
  ['profileStagingCount', u32be],
  ['integrityEvidenceCount', u32be],
  ['controlRecordAccountingBytes', constant(u16be, 512, 'controlRecordAccountingBytes')],
  ['tombstoneRecordAccountingBytes', constant(u16be, 512, 'tombstoneRecordAccountingBytes')],
  ['frameIndexAccountingBytes', constant(u16be, 256, 'frameIndexAccountingBytes')],
  ['retryRecordAccountingBytes', constant(u16be, 256, 'retryRecordAccountingBytes')]
], { name: 'BlindInboxControlGlobalSnapshotV1' })

export const blindInboxProfileStagingSnapshotV1 = struct([
  ['version', version1],
  ['profileId', ranged(u16be, 1, 0xffff, 'profileId')],
  ['stagingFrameBytes', u64be]
], {
  name: 'BlindInboxProfileStagingSnapshotV1',
  validate (value) {
    if (asU64(value.stagingFrameBytes, 'stagingFrameBytes') === 0n) fail('Inbox profile staging bytes must be nonzero')
  }
})

export const blindInboxIntegrityEvidenceSnapshotV1 = struct([
  ['version', version1],
  ['reason', ranged(u8, 1, 3, 'reason')],
  ['detectedEpoch', u32be],
  ['evidenceHash', bytes32]
], {
  name: 'BlindInboxIntegrityEvidenceSnapshotV1',
  validate (value) { nonzero(value.evidenceHash, 'evidenceHash') }
})

export const blindControlStateSnapshotV1 = struct([
  ['version', version1],
  ['relayPublicKey', bytes32],
  ['storeId', bytes32],
  ['durabilityContinuityHash', bytes32],
  ['walSequence', u64be],
  ['walHash', bytes32],
  ['entries', arrayOf(controlStateEntryV1, 0, 0x1000000, 'entries')]
], {
  name: 'BlindControlStateSnapshotV1',
  validate (value) {
    for (const field of ['relayPublicKey', 'storeId', 'durabilityContinuityHash', 'walHash']) nonzero(value[field], field)
    assertSorted(value.entries, (left, right) => left.entryKind - right.entryKind || compareBytes(left.key, right.key), 'control state entries')
  }
})

export const blindExternalAckFloorV1 = struct([
  ['version', version1],
  ['relayPublicKey', bytes32],
  ['storeId', bytes32],
  ['externalJournalId', bytes32],
  ['durabilityContinuityHash', bytes32],
  ['floorRevision', u64be],
  ['previousFloorHash', optional(bytes32, 'previousFloorHash')],
  ['writerEpoch', u64be],
  ['writerFenceTokenHash', bytes32],
  ['externalLeaseRevision', u64be],
  ['walSequence', u64be],
  ['walHash', bytes32],
  ['descriptorSequence', u64be],
  ['descriptorHash', bytes32],
  ['witnessedUnixMillis', u64be],
  ['witnessPublicKey', bytes32],
  ['signature', bytes64]
], {
  name: 'BlindExternalAckFloorV1',
  validate (value) {
    for (const field of [
      'relayPublicKey', 'storeId', 'externalJournalId', 'durabilityContinuityHash',
      'writerFenceTokenHash', 'walHash', 'descriptorHash', 'witnessPublicKey'
    ]) nonzero(value[field], field)
    const revision = asU64(value.floorRevision, 'floorRevision')
    if (revision === 0n || (revision === 1n) !== (value.previousFloorHash == null)) {
      fail('floor predecessor presence does not match floorRevision')
    }
  }
})

export const blindExternalControlCheckpointV1 = struct([
  ['version', version1],
  ['relayPublicKey', bytes32],
  ['storeId', bytes32],
  ['externalJournalId', bytes32],
  ['durabilityContinuityHash', bytes32],
  ['checkpointRevision', u64be],
  ['previousCheckpointHash', optional(bytes32, 'previousCheckpointHash')],
  ['baseFloorRevision', u64be],
  ['baseFloorHash', bytes32],
  ['writerEpoch', u64be],
  ['writerFenceTokenHash', bytes32],
  ['externalLeaseRevision', u64be],
  ['walSequence', u64be],
  ['walHash', bytes32],
  ['descriptorSequence', u64be],
  ['descriptorHash', bytes32],
  ['snapshotByteLength', u64be],
  ['snapshotHash', bytes32],
  ['oldestRetainedFloorRevision', u64be],
  ['createdUnixMillis', u64be],
  ['witnessPublicKey', bytes32],
  ['signature', bytes64]
], {
  name: 'BlindExternalControlCheckpointV1',
  validate (value) {
    for (const field of [
      'relayPublicKey', 'storeId', 'externalJournalId', 'durabilityContinuityHash', 'baseFloorHash',
      'writerFenceTokenHash', 'walHash', 'descriptorHash', 'snapshotHash', 'witnessPublicKey'
    ]) nonzero(value[field], field)
    const revision = asU64(value.checkpointRevision, 'checkpointRevision')
    if (revision === 0n || (revision === 1n) !== (value.previousCheckpointHash == null)) {
      fail('checkpoint predecessor presence does not match checkpointRevision')
    }
  }
})

// Exact fixed prefix of every version-2 local WAL frame. The variable payload
// and trailing checksum follow this 192-byte canonical header; the store-format
// registry therefore changes whenever this crash-recovery authority changes.
export const blindWalHeaderV2 = struct([
  ['magic', constantBytes(b4a.from('HRWL', 'ascii'), 'magic')],
  ['walVersion', version2],
  ['recordType', ranged(u8, 1, 0xff, 'recordType')],
  ['totalLength', u32be],
  ['walSequence', u64be],
  ['transactionId', bytes32],
  ['virtualBucket', u16be],
  ['mapGeneration', u64be],
  ['writerFenceTokenHash', bytes32],
  ['payloadLength', u32be],
  ['previousWalHash', bytes32],
  ['durabilityContinuityHash', bytes32],
  ['payloadHash', bytes32]
], {
  name: 'BlindWalHeaderV2',
  validate (value) {
    for (const field of [
      'transactionId', 'writerFenceTokenHash', 'durabilityContinuityHash', 'payloadHash'
    ]) nonzero(value[field], field)
    const sequence = asU64(value.walSequence, 'walSequence')
    const generation = asU64(value.mapGeneration, 'mapGeneration')
    if (sequence === 0n || generation === 0n) fail('WAL sequence and map generation must be nonzero')
    if (value.totalLength !== 224 + value.payloadLength) fail('WAL total and payload lengths disagree')
    if ((sequence === 1n) !== isZero(value.previousWalHash)) {
      fail('WAL predecessor hash zero state does not match its sequence')
    }
  }
})

export const blindLocalCheckpointV1 = struct([
  ['magic', constantBytes(b4a.from('HRBCKP01', 'ascii'), 'magic')],
  ['checkpointVersion', constant(u16be, 1, 'checkpointVersion')],
  ['relayPublicKey', bytes32],
  ['storeId', bytes32],
  ['durabilityProfileId', ranged(u8, 1, 2, 'durabilityProfileId')],
  ['durabilityContinuityHash', bytes32],
  ['durabilityProfileHash', bytes32],
  ['formatMajor', u16be],
  ['formatMinor', u16be],
  ['storeFormatHash', bytes32],
  ['specHash', bytes32],
  ['abiHash', bytes32],
  ['mapGeneration', u64be],
  ['bucketMapHash', bytes32],
  ['writerEpoch', u64be],
  ['writerFenceTokenHash', bytes32],
  ['checkpointRevision', u64be],
  ['previousCheckpointHash', optional(bytes32, 'previousCheckpointHash')],
  ['coveredWalSequence', u64be],
  ['coveredWalHash', bytes32],
  ['epochFloor', u32be],
  ['descriptorSequenceFloor', u64be],
  ['descriptorHashFloor', bytes32],
  ['snapshotByteLength', u64be],
  ['snapshotHash', bytes32]
], {
  name: 'BlindLocalCheckpointV1',
  validate (value) {
    for (const field of [
      'relayPublicKey', 'storeId', 'durabilityContinuityHash', 'durabilityProfileHash',
      'storeFormatHash', 'specHash', 'abiHash', 'bucketMapHash', 'writerFenceTokenHash',
      'coveredWalHash', 'descriptorHashFloor', 'snapshotHash'
    ]) nonzero(value[field], field)
    const revision = asU64(value.checkpointRevision, 'checkpointRevision')
    if (revision === 0n || (revision === 1n) !== (value.previousCheckpointHash == null)) {
      fail('local checkpoint predecessor presence does not match checkpointRevision')
    }
    if (asU64(value.mapGeneration, 'mapGeneration') === 0n ||
        asU64(value.writerEpoch, 'writerEpoch') === 0n ||
        asU64(value.coveredWalSequence, 'coveredWalSequence') === 0n ||
        asU64(value.snapshotByteLength, 'snapshotByteLength') === 0n) {
      fail('local checkpoint generation, writer, WAL, and snapshot values must be nonzero')
    }
  }
})

export const blindStoreManifestV1 = struct([
  ['magic', constantBytes(b4a.from('HRBLIND1', 'ascii'), 'magic')],
  ['manifestVersion', constant(u16be, 1, 'manifestVersion')],
  ['storeId', bytes32],
  ['relayPublicKey', bytes32],
  ['durabilityProfileId', ranged(u8, 1, 2, 'durabilityProfileId')],
  ['durabilityContinuityHash', bytes32],
  ['durabilityProfileHash', bytes32],
  ['formatMajor', u16be],
  ['formatMinor', u16be],
  ['storeFormatHash', bytes32],
  ['specHash', bytes32],
  ['abiHash', bytes32],
  ['mapGeneration', u64be],
  ['bucketMapHash', bytes32],
  ['checkpointWalSequence', u64be],
  ['checkpointHash', bytes32],
  ['epochFloor', u32be],
  ['writerEpoch', u64be],
  ['writerFenceTokenHash', bytes32],
  ['externalLeaseRevision', u64be],
  ['externalJournalId', bytes32],
  ['externalWitnessPublicKey', bytes32],
  ['restoreEvidenceFeedId', bytes32],
  ['lastAckWalSequence', u64be],
  ['lastAckWalHash', bytes32],
  ['externalCheckpointRevision', u64be],
  ['externalCheckpointHash', bytes32],
  ['descriptorSequenceFloor', u64be],
  ['descriptorHashFloor', bytes32],
  ['migrationState', ranged(u8, 0, 4, 'migrationState')],
  ['sourceFormatMajor', u16be],
  ['targetFormatMajor', u16be],
  ['migrationCursorHash', bytes32],
  ['previousManifestHash', optional(bytes32, 'previousManifestHash')],
  ['manifestRevision', u64be],
  ['mac', bytes32]
], {
  name: 'BlindStoreManifestV1',
  validate (value) {
    for (const field of [
      'storeId', 'relayPublicKey', 'durabilityContinuityHash', 'durabilityProfileHash', 'storeFormatHash',
      'specHash', 'abiHash', 'bucketMapHash', 'checkpointHash', 'writerFenceTokenHash',
      'descriptorHashFloor', 'mac'
    ]) nonzero(value[field], field)
    const revision = asU64(value.manifestRevision, 'manifestRevision')
    if ((revision === 0n) !== (value.previousManifestHash == null)) {
      fail('manifest predecessor presence does not match manifestRevision')
    }
    const profile1 = value.durabilityProfileId === 1
    const profileExternal = [
      value.externalJournalId, value.externalWitnessPublicKey, value.restoreEvidenceFeedId,
      value.lastAckWalHash, value.externalCheckpointHash
    ]
    if (profile1 && (profileExternal.some(value => !isZero(value)) ||
      asU64(value.externalLeaseRevision, 'externalLeaseRevision') !== 0n ||
      asU64(value.lastAckWalSequence, 'lastAckWalSequence') !== 0n ||
      asU64(value.externalCheckpointRevision, 'externalCheckpointRevision') !== 0n)) {
      fail('profile 1 manifest must contain zero external continuity state')
    }
    if (!profile1 && (isZero(value.externalJournalId) || isZero(value.externalWitnessPublicKey))) {
      fail('profile 2 manifest requires external journal and witness identities')
    }
    if (value.migrationState === 0) {
      if (value.sourceFormatMajor !== 0 || value.targetFormatMajor !== 0 || !isZero(value.migrationCursorHash)) {
        fail('stable manifest must contain zero migration fields')
      }
    } else {
      if (value.sourceFormatMajor === 0 || value.targetFormatMajor <= value.sourceFormatMajor) {
        fail('migration source and target format majors are invalid')
      }
      if (value.migrationState === 1 ? !isZero(value.migrationCursorHash) : isZero(value.migrationCursorHash)) {
        fail('migration cursor presence does not match migration phase')
      }
    }
  }
})
