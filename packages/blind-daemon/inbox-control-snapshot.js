import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  FAMILY,
  INBOX_APPEND_RESULT,
  INBOX_FRAME_CLASS,
  OPERATION,
  RESULT_SIGNATURE_DOMAIN_ID,
  blindInboxCommittedSpendSnapshotV1,
  blindInboxControlGlobalSnapshotV1,
  blindInboxExpiredAppendSpendSnapshotV1,
  blindInboxFrameSnapshotV1,
  blindInboxIntegrityEvidenceSnapshotV1,
  blindInboxProfileStagingSnapshotV1,
  blindInboxRecordSnapshotV1,
  blindInboxRequestResultSnapshotV1,
  blindInboxReservedSpendSnapshotV1,
  blindInboxRetryFramePinSnapshotV1,
  blindInboxRetryMaterialSnapshotV1,
  blindInboxRetryReconstructionV1,
  blindInboxTerminalSpendSnapshotV1,
  blake2b256,
  chargedUnaryRetryV1,
  decodeCanonical,
  encodeCanonical,
  inboxAppendAckV1,
  inboxCreateCommitment,
  inboxPhysicalTopic,
  relayResultBindingV1,
  resultSignaturePayload
} from '@hiverelay/blind-protocol'
import { deriveBlindVirtualBucket } from './virtual-bucket.js'

const CONTROL_RECORD_BYTES = 512
const TOMBSTONE_RECORD_BYTES = 512
const FRAME_INDEX_RECORD_BYTES = 256
const RETRY_RECORD_BYTES = 256
const MAX_U64 = (1n << 64n) - 1n
const ZERO32 = b4a.alloc(32)
const LEASE_EPOCHS = Object.freeze({ 1: 4, 2: 28, 3: 120, 4: 360 })
const FINGERPRINT_DOMAIN = b4a.from('hiverelay.blind.inbox-store-request-fingerprint.v1', 'ascii')
const RESULT_IDENTITY_DOMAIN = b4a.from('hiverelay.blind.inbox-store-result-identity.v1', 'ascii')
const RETRY_SOURCE_DOMAIN = b4a.from('hiverelay.blind.inbox-retry-source.v1', 'ascii')
const AUTHORITIES = new WeakMap()
const VERIFIERS = new WeakMap()
const VERIFIED_RESULTS = new WeakMap()

const ENTRY_KIND = Object.freeze({
  SPEND_IDEMPOTENCY: 1,
  RESERVATION_ATTEMPT: 2,
  INBOX: 4,
  INBOX_GLOBAL: 6,
  RETRY_PIN: 8
})

const SUBTYPE = Object.freeze({
  COMMITTED_SPEND: 1,
  TERMINAL_SPEND: 2,
  REQUEST_RESULT: 3,
  EXPIRED_APPEND_SPEND: 4,
  RESERVED_SPEND: 1,
  INBOX_RECORD: 1,
  FRAME_RECORD: 2,
  GLOBAL: 1,
  PROFILE_STAGING: 2,
  INTEGRITY_EVIDENCE: 3,
  RETRY_RECORD: 1,
  RETRY_FRAME_PIN: 2,
  RETRY_MATERIAL: 3
})

export const BLIND_INBOX_CONTROL_SNAPSHOT_KEYSPACE = Object.freeze({
  familyPrefix: FAMILY.INBOX,
  entryKind: ENTRY_KIND,
  subtype: SUBTYPE,
  keyFormat: 'family:u8 || subtype:u8 || identity bytes',
  globalKey: Object.freeze([FAMILY.INBOX, SUBTYPE.GLOBAL])
})

export const BLIND_INBOX_CONTROL_SNAPSHOT_STATUS = Object.freeze({
  recoverySemanticAuthorityImplemented: true,
  privatePartitionBucketMappingVerified: true,
  deterministicBoundedCandidateSerializationImplemented: true,
  exactRetryFramePinIndexReconstructed: true,
  scalableCandidateEntryStreamingImplemented: false,
  frameBodyAvailabilityAndHashVerificationImplemented: false,
  engineBoundPublicationAuthorityImplemented: false,
  productionComplete: false,
  exclusions: Object.freeze([
    'CELL_CONTROL_SNAPSHOT_SEPARATE_AUTHORITY_REQUIRED',
    'CORE_CONTROL_SNAPSHOT_UNIMPLEMENTED',
    'DESCRIPTOR_IDENTITY_FLOOR_SNAPSHOT_UNIMPLEMENTED',
    'CROSS_SERVICE_GLOBAL_SNAPSHOT_COMPOSITION_UNIMPLEMENTED',
    'INBOX_FRAME_BODY_AVAILABILITY_AND_HASH_VERIFICATION_UNIMPLEMENTED',
    'INBOX_WAL_STATE_MACHINE_AND_ENGINE_RESTORE_UNIMPLEMENTED',
    'SCALABLE_EXTERNAL_SORTED_CANDIDATE_STREAM_UNIMPLEMENTED',
    'ENGINE_INSTANCE_WAL_BARRIER_PUBLICATION_AUTHORITY_UNIMPLEMENTED'
  ])
})

export class BlindInboxControlSnapshotIntegrityError extends Error {
  constructor (message) {
    super(message)
    this.name = 'BlindInboxControlSnapshotIntegrityError'
    this.code = 'RECOVERY_GAP_READ_ONLY'
  }
}

function fail (message) {
  throw new BlindInboxControlSnapshotIntegrityError(message)
}

function isZero (value) {
  for (const byte of value) if (byte !== 0) return false
  return true
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

function integer (value, minimum, maximum, field) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${field} is outside ${minimum}..${maximum}`)
  }
  return value
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

function hex (value) {
  return b4a.toString(value, 'hex')
}

function hashParts (domain, ...parts) {
  return blake2b256(b4a.concat([domain, ...parts]))
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

function mapKeyMatches (mapKey, expected, field) {
  if (typeof mapKey !== 'string' || mapKey !== expected) fail(`${field} map key does not match its canonical identity`)
}

function frameMapKey (physicalTopic, appendRevision) {
  return `${hex(physicalTopic)}:${asU64(appendRevision, 'appendRevision').toString()}`
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

function topicCommitment (physicalTopic) {
  return blake2b256(physicalTopic)
}

function verifiedResultBinding (bytes, context, field) {
  let binding
  try {
    binding = decodeCanonical(relayResultBindingV1, bytes, { copyBytes: true })
    if (!b4a.equals(encodeCanonical(relayResultBindingV1, binding), bytes)) {
      throw new Error('non-canonical binding')
    }
  } catch (error) {
    fail(`${field} result binding is invalid: ${error.message}`)
  }
  if (!context.storeId || !context.durabilityContinuityHash ||
      binding.durabilityProfileId !== 1 || binding.externalCommitWitness != null ||
      !b4a.equals(binding.relayPublicKey, context.relayPublicKey) ||
      !b4a.equals(binding.storeId, context.storeId) ||
      !b4a.equals(binding.durabilityContinuityHash, context.durabilityContinuityHash)) {
    fail(`${field} result binding substitutes another relay/store authority`)
  }
  return binding
}

function verifiedAppendAck (value, context, field) {
  const binding = verifiedResultBinding(value.resultBindingBytes, context, field)
  const appendRevision = value.appendRevision == null ? value.resultRevision : value.appendRevision
  const storedAtEpoch = value.storedAtEpoch == null ? value.committedEpoch : value.storedAtEpoch
  const ack = {
    version: 1,
    relayBinding: binding,
    topicCommitment: topicCommitment(value.physicalTopic),
    frameHash: value.frameHash,
    appendRevision,
    storedAtEpoch,
    expiresAtEpoch: value.expiresAtEpoch,
    requestNonce: value.clientNonce,
    requestCommitment: value.requestCommitment,
    result: INBOX_APPEND_RESULT.STORED,
    signature: value.ackSignature
  }
  const body = encodeCanonical(inboxAppendAckV1, ack)
  const unsigned = body.subarray(0, body.byteLength - sodium.crypto_sign_BYTES)
  if (!sodium.crypto_sign_verify_detached(
    ack.signature,
    resultSignaturePayload(RESULT_SIGNATURE_DOMAIN_ID.INBOX_APPEND_ACK, unsigned),
    binding.relayPublicKey
  )) {
    fail(`${field} signature is invalid`)
  }
  if (!b4a.equals(blake2b256(body), value.resultCommitment)) {
    fail(`${field} result commitment does not match its exact signed ACK`)
  }
  const expectedIdentity = resultIdentity(
    OPERATION.INBOX.APPEND,
    value.physicalTopic,
    value.requestCommitment,
    appendRevision,
    value.frameHash,
    storedAtEpoch
  )
  if (!b4a.equals(expectedIdentity, value.resultIdentity)) {
    fail(`${field} result identity does not match`)
  }
  return body
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

function entryKey (subtype, ...identityParts) {
  return b4a.concat([b4a.from([FAMILY.INBOX, subtype]), ...identityParts])
}

function encodedEntry (entryKind, subtype, identityParts, codec, value) {
  const key = entryKey(subtype, ...identityParts)
  const encoded = encodeCanonical(codec, value)
  if (key.byteLength > 256 || encoded.byteLength > 0xffff) fail('Inbox snapshot entry exceeds the control snapshot bounds')
  return Object.freeze({ entryKind, key, value: encoded })
}

function compareEntries (left, right) {
  return left.entryKind - right.entryKind || b4a.compare(left.key, right.key)
}

function commonSpendValue (entry) {
  return {
    version: 1,
    transactionId: entry.transactionId,
    spendTag: entry.spendTag,
    requestCommitment: entry.requestCommitment,
    requestFingerprint: entry.requestFingerprint,
    physicalTopic: entry.physicalTopic,
    operation: entry.operation,
    profileId: entry.profileId,
    frameClass: entry.frameClass,
    frameHash: entry.frameHash,
    requestedLeaseClass: entry.requestedLeaseClass,
    declaredBytes: entry.declaredBytes,
    deadlineUnixMillis: entry.deadlineUnixMillis,
    remainingAttempts: entry.remainingAttempts,
    reservedEpoch: entry.reservedEpoch
  }
}

function recordCreateCommitment (relayPublicKey, value, leaseClass) {
  return inboxCreateCommitment({
    relayPublicKey,
    physicalTopic: value.physicalTopic,
    allocationEpoch: value.allocationEpoch,
    frameClassBits: value.frameClassBits,
    appendAuthMode: value.appendAuthMode,
    appendPublicKey: value.appendPublicKey,
    createPublicKey: value.createPublicKey,
    renewPublicKey: value.renewPublicKey,
    closePublicKey: value.closePublicKey,
    retentionClass: value.retentionClass,
    leaseClass
  })
}

function deriveAllocationLeaseClass (relayPublicKey, value) {
  const matches = []
  for (let leaseClass = 1; leaseClass <= 4; leaseClass++) {
    let candidate
    try {
      candidate = recordCreateCommitment(relayPublicKey, value, leaseClass)
    } catch (error) {
      fail(`Inbox allocation fields are invalid: ${error.message}`)
    }
    if (b4a.equals(candidate, value.createCommitment)) matches.push(leaseClass)
  }
  if (matches.length !== 1) fail('Inbox create commitment does not identify exactly one allocation lease class')
  return matches[0]
}

function retryRecordValue (pin) {
  const reconstruction = encodeCanonical(blindInboxRetryReconstructionV1, pin.reconstruction)
  if (reconstruction.byteLength > 96) fail('Inbox retry reconstruction exceeds ChargedUnaryRetryV1')
  return {
    version: 1,
    spendTag: pin.spendTag,
    requestCommitment: pin.requestCommitment,
    familyId: FAMILY.INBOX,
    operationId: pin.operation,
    locatorCommitment: pin.locatorCommitment,
    sourceRevision: pin.sourceRevision,
    sourceCommitment: pin.sourceCommitment,
    resultCommitment: pin.resultCommitment,
    reconstruction,
    retryExpiresMinute: pin.retryExpiresMinute,
    retryState: pin.retryState
  }
}

function candidateEntries (state, maximumCandidateEntries) {
  if (!state || typeof state !== 'object' || Array.isArray(state)) fail('Inbox snapshot state must be an object')
  const relayPublicKey = asBytes(state.relayPublicKey, 32, 'relayPublicKey', true)
  const spends = requireMap(state.spends, 'spends')
  const commitments = requireMap(state.commitments, 'commitments')
  const requestResults = requireMap(state.requestResults, 'requestResults')
  const inboxes = requireMap(state.inboxes, 'inboxes')
  const frames = requireMap(state.frames, 'frames')
  const retryPins = requireMap(state.retryPins, 'retryPins')
  if (!state.accounting || typeof state.accounting !== 'object') fail('accounting must be an object')
  const stagingByProfile = requireMap(state.accounting.stagingByProfile, 'accounting.stagingByProfile')
  if (!Array.isArray(state.integrityEvidence)) fail('integrityEvidence must be an array')
  integer(state.epochFloor, 0, 0xffffffff, 'epochFloor')
  if (typeof state.clockUnsafe !== 'boolean') fail('clockUnsafe must be a boolean')
  if (state.readOnlyReason != null && state.readOnlyReason !== 'RECOVERY_GAP_READ_ONLY') {
    fail('only the persistent recovery-gap read-only state can enter an Inbox checkpoint')
  }

  let retryFrameEstimate = 0
  for (const pin of retryPins.values()) {
    if (!pin || typeof pin !== 'object' || !Array.isArray(pin.entries)) {
      fail('Inbox retry pin must include entries')
    }
    retryFrameEstimate += pin.entries.length
    if (!Number.isSafeInteger(retryFrameEstimate) || retryFrameEstimate > maximumCandidateEntries) {
      fail('Inbox candidate snapshot exceeds its configured entry bound')
    }
  }
  const estimatedEntryCount = spends.size + requestResults.size + inboxes.size + frames.size +
    retryPins.size * 2 + retryFrameEstimate + 1 + stagingByProfile.size + state.integrityEvidence.length
  if (!Number.isSafeInteger(estimatedEntryCount) || estimatedEntryCount > maximumCandidateEntries) {
    fail('Inbox candidate snapshot exceeds its configured entry bound')
  }

  const output = []
  for (const [mapKey, value] of spends) {
    if (!value || typeof value !== 'object') fail('Inbox spend entry must be an object')
    mapKeyMatches(mapKey, hex(asBytes(value.spendTag, 32, 'spendTag', true)), 'Inbox spend')
    if (value.inFlight === true) fail('in-flight Inbox reservations cannot enter a checkpoint')
    if (value.status === 'reserved') {
      output.push(encodedEntry(ENTRY_KIND.RESERVATION_ATTEMPT, SUBTYPE.RESERVED_SPEND, [value.spendTag],
        blindInboxReservedSpendSnapshotV1, commonSpendValue(value)))
    } else if (value.status === 'committed') {
      output.push(encodedEntry(ENTRY_KIND.SPEND_IDEMPOTENCY, SUBTYPE.COMMITTED_SPEND, [value.spendTag],
        blindInboxCommittedSpendSnapshotV1, {
          ...commonSpendValue(value),
          resultIdentity: value.resultIdentity,
          resultRevision: value.resultRevision,
          committedEpoch: value.committedEpoch,
          resultLeaseClass: value.resultLeaseClass,
          resultLeaseEpoch: value.resultLeaseEpoch,
          resultBindingBytes: value.resultBindingBytes,
          clientNonce: value.clientNonce,
          retentionClassAtAppend: value.retentionClassAtAppend,
          appendLeaseEpoch: value.appendLeaseEpoch,
          expiresAtEpoch: value.expiresAtEpoch,
          ackSignature: value.ackSignature,
          resultCommitment: value.resultCommitment,
          retryState: value.retryState
        }))
    } else if (value.status === 'expired-append') {
      output.push(encodedEntry(ENTRY_KIND.SPEND_IDEMPOTENCY, SUBTYPE.EXPIRED_APPEND_SPEND, [value.spendTag],
        blindInboxExpiredAppendSpendSnapshotV1, {
          version: 1,
          transactionId: value.transactionId,
          spendTag: value.spendTag,
          requestCommitment: value.requestCommitment,
          requestFingerprint: value.requestFingerprint,
          physicalTopic: value.physicalTopic,
          profileId: value.profileId,
          frameClass: value.frameClass,
          frameHash: value.frameHash,
          declaredBytes: value.declaredBytes,
          deadlineUnixMillis: value.deadlineUnixMillis,
          remainingAttempts: value.remainingAttempts,
          reservedEpoch: value.reservedEpoch,
          resultIdentity: value.resultIdentity,
          appendRevision: value.resultRevision,
          storedAtEpoch: value.committedEpoch,
          retentionClassAtAppend: value.retentionClassAtAppend,
          appendLeaseEpoch: value.appendLeaseEpoch,
          expiresAtEpoch: value.expiresAtEpoch,
          expiredEpoch: value.expiredEpoch,
          clientNonce: value.clientNonce,
          resultBindingBytes: value.resultBindingBytes,
          ackSignature: value.ackSignature,
          resultCommitment: value.resultCommitment
        }))
    } else if (value.status === 'terminal') {
      output.push(encodedEntry(ENTRY_KIND.SPEND_IDEMPOTENCY, SUBTYPE.TERMINAL_SPEND, [value.spendTag],
        blindInboxTerminalSpendSnapshotV1, {
          ...commonSpendValue(value),
          terminalReason: value.terminalReason,
          terminalEpoch: value.terminalEpoch
        }))
    } else {
      fail('Inbox spend has an unknown status')
    }
  }

  for (const [mapKey, value] of requestResults) {
    if (!value || value.operation !== 'close') fail('Inbox request result has an unknown operation')
    mapKeyMatches(mapKey, hex(asBytes(value.requestCommitment, 32, 'requestCommitment', true)), 'Inbox request result')
    output.push(encodedEntry(ENTRY_KIND.SPEND_IDEMPOTENCY, SUBTYPE.REQUEST_RESULT, [value.requestCommitment],
      blindInboxRequestResultSnapshotV1, {
        version: 1,
        transactionId: value.transactionId,
        requestCommitment: value.requestCommitment,
        physicalTopic: value.physicalTopic,
        resultIdentity: value.resultIdentity,
        resultRevision: value.resultRevision,
        committedEpoch: value.committedEpoch,
        resultBindingBytes: value.resultBindingBytes,
        clientNonce: value.clientNonce,
        resultLeaseClass: value.resultLeaseClass,
        resultLeaseEpoch: value.resultLeaseEpoch
      }))
  }

  for (const [mapKey, value] of inboxes) {
    if (!value || typeof value !== 'object') fail('Inbox record must be an object')
    mapKeyMatches(mapKey, hex(asBytes(value.physicalTopic, 32, 'physicalTopic', true)), 'Inbox record')
    output.push(encodedEntry(ENTRY_KIND.INBOX, SUBTYPE.INBOX_RECORD, [value.physicalTopic],
      blindInboxRecordSnapshotV1, {
        version: 1,
        physicalTopic: value.physicalTopic,
        metadataVirtualBucket: value.metadataVirtualBucket,
        allocationEpoch: value.allocationEpoch,
        allocationLeaseClass: deriveAllocationLeaseClass(relayPublicKey, value),
        frameClassBits: value.frameClassBits,
        appendAuthMode: value.appendAuthMode,
        appendPublicKey: value.appendPublicKey,
        createPublicKey: value.createPublicKey,
        renewPublicKey: value.renewPublicKey,
        closePublicKey: value.closePublicKey,
        retentionClass: value.retentionClass,
        leaseClass: value.leaseClass,
        leaseEpoch: value.leaseEpoch,
        stateRevision: value.stateRevision,
        policyRevision: value.policyRevision,
        appendRevision: value.appendRevision,
        createCommitment: value.createCommitment,
        objectState: value.objectState,
        policyState: value.policyState,
        tombstoneReason: value.tombstoneReason,
        terminalEpoch: value.terminalEpoch,
        createSpendTag: value.createSpendTag,
        createRequestCommitment: value.createRequestCommitment,
        resultIdentity: value.resultIdentity,
        createdEpoch: value.createdEpoch
      }))
  }

  for (const [mapKey, value] of frames) {
    if (!value || typeof value !== 'object') fail('Inbox frame record must be an object')
    mapKeyMatches(mapKey, frameMapKey(value.physicalTopic, value.appendRevision), 'Inbox frame')
    output.push(encodedEntry(ENTRY_KIND.INBOX, SUBTYPE.FRAME_RECORD,
      [value.physicalTopic, u64bytes(value.appendRevision)], blindInboxFrameSnapshotV1, {
        version: 1,
        physicalTopic: value.physicalTopic,
        appendRevision: value.appendRevision,
        frameHash: value.frameHash,
        frameClass: value.frameClass,
        frameVirtualBucket: value.frameVirtualBucket,
        frameObjectId: value.frameObjectId,
        appendLeaseEpoch: value.appendLeaseEpoch,
        storedAtEpoch: value.storedAtEpoch,
        expiresAtEpoch: value.expiresAtEpoch,
        spendTag: value.spendTag,
        requestCommitment: value.requestCommitment,
        resultIdentity: value.resultIdentity
      }))
  }

  let retryFramePinCount = 0
  for (const [mapKey, pin] of retryPins) {
    mapKeyMatches(mapKey, hex(asBytes(pin.spendTag, 32, 'retry spendTag', true)), 'Inbox retry')
    output.push(encodedEntry(ENTRY_KIND.RETRY_PIN, SUBTYPE.RETRY_RECORD, [pin.spendTag],
      chargedUnaryRetryV1, retryRecordValue(pin)))
    output.push(encodedEntry(ENTRY_KIND.RETRY_PIN, SUBTYPE.RETRY_MATERIAL, [pin.spendTag],
      blindInboxRetryMaterialSnapshotV1, {
        version: 1,
        spendTag: pin.spendTag,
        entriesCommitment: pin.entriesCommitment,
        nextCursor: pin.nextCursor
      }))
    let previousRevision = -1n
    for (const entry of pin.entries) {
      const revision = asU64(entry.appendRevision, 'retry appendRevision')
      if (revision <= previousRevision) fail('Inbox retry frame pins must be strictly increasing')
      previousRevision = revision
      output.push(encodedEntry(ENTRY_KIND.RETRY_PIN, SUBTYPE.RETRY_FRAME_PIN,
        [pin.spendTag, u64bytes(revision)], blindInboxRetryFramePinSnapshotV1, {
          version: 1,
          spendTag: pin.spendTag,
          physicalTopic: pin.physicalTopic,
          appendRevision: revision,
          frameHash: entry.frameHash
        }))
      retryFramePinCount++
    }
  }

  output.push(encodedEntry(ENTRY_KIND.INBOX_GLOBAL, SUBTYPE.GLOBAL, [],
    blindInboxControlGlobalSnapshotV1, {
      version: 1,
      epochFloor: state.epochFloor,
      clockUnsafe: state.clockUnsafe ? 1 : 0,
      recoveryGap: state.readOnlyReason === 'RECOVERY_GAP_READ_ONLY' ? 1 : 0,
      storedFrameBytes: asU64(state.accounting.storedFrameBytes, 'accounting.storedFrameBytes'),
      stagingFrameBytes: asU64(state.accounting.stagingFrameBytes, 'accounting.stagingFrameBytes'),
      controlBytes: asU64(state.accounting.controlBytes, 'accounting.controlBytes'),
      tombstoneBytes: asU64(state.accounting.tombstoneBytes, 'accounting.tombstoneBytes'),
      frameIndexBytes: asU64(state.accounting.frameIndexBytes, 'accounting.frameIndexBytes'),
      reservedFrames: asU64(state.accounting.reservedFrames, 'accounting.reservedFrames'),
      inboxCount: BigInt(inboxes.size),
      frameCount: BigInt(frames.size),
      spendCount: BigInt(spends.size),
      commitmentCount: BigInt(commitments.size),
      requestResultCount: BigInt(requestResults.size),
      retryRecordCount: BigInt(retryPins.size),
      retryFramePinCount: BigInt(retryFramePinCount),
      profileStagingCount: stagingByProfile.size,
      integrityEvidenceCount: state.integrityEvidence.length,
      controlRecordAccountingBytes: CONTROL_RECORD_BYTES,
      tombstoneRecordAccountingBytes: TOMBSTONE_RECORD_BYTES,
      frameIndexAccountingBytes: FRAME_INDEX_RECORD_BYTES,
      retryRecordAccountingBytes: RETRY_RECORD_BYTES
    }))

  for (const [profileId, stagingFrameBytes] of stagingByProfile) {
    const canonicalProfileId = typeof profileId === 'string' && /^[1-9][0-9]*$/.test(profileId)
      ? Number(profileId)
      : profileId
    integer(canonicalProfileId, 1, 0xffff, 'Inbox staging profileId')
    output.push(encodedEntry(ENTRY_KIND.INBOX_GLOBAL, SUBTYPE.PROFILE_STAGING, [u16bytes(canonicalProfileId)],
      blindInboxProfileStagingSnapshotV1, {
        version: 1,
        profileId: canonicalProfileId,
        stagingFrameBytes: asU64(stagingFrameBytes, 'profile stagingFrameBytes')
      }))
  }

  for (const evidence of state.integrityEvidence) {
    if (!evidence || typeof evidence !== 'object') fail('Inbox integrity evidence must be an object')
    output.push(encodedEntry(ENTRY_KIND.INBOX_GLOBAL, SUBTYPE.INTEGRITY_EVIDENCE, [evidence.evidenceHash],
      blindInboxIntegrityEvidenceSnapshotV1, {
        version: 1,
        reason: evidence.reason,
        detectedEpoch: evidence.detectedEpoch,
        evidenceHash: evidence.evidenceHash
      }))
  }

  if (output.length > maximumCandidateEntries) fail('Inbox candidate snapshot exceeds its configured entry bound')
  output.sort(compareEntries)
  for (let index = 1; index < output.length; index++) {
    if (compareEntries(output[index - 1], output[index]) >= 0) fail('Inbox candidate snapshot entries collide')
  }
  return output
}

function assertAuthority (authority) {
  const state = AUTHORITIES.get(authority)
  if (!state) throw new TypeError('a branded Inbox control snapshot semantic authority is required')
  return state
}

function keyIdentity (entry, expectedKind, expectedSubtype, length, field) {
  if (entry.entryKind !== expectedKind || entry.key.byteLength !== length + 2 ||
      entry.key[0] !== FAMILY.INBOX || entry.key[1] !== expectedSubtype) {
    fail(`${field} uses an invalid Inbox control snapshot key`)
  }
  return entry.key.subarray(2)
}

function readEntry (raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) fail('snapshot entry must be an object')
  const entryKind = integer(raw.entryKind, 1, 8, 'entryKind')
  const key = asBytes(raw.key, null, 'entry key')
  const value = asBytes(raw.value, null, 'entry value')
  if (key.byteLength < 2 || key.byteLength > 256 || value.byteLength > 0xffff) fail('snapshot entry is outside its byte bounds')
  if (key[0] !== FAMILY.INBOX) fail('Inbox-only semantic authority rejects non-Inbox snapshot entries')
  return { entryKind, key, value }
}

function assertSpendSemantics (value) {
  if (!b4a.equals(requestFingerprint(value), value.requestFingerprint)) {
    fail('Inbox spend request fingerprint does not match')
  }
}

function reconstructSpend (value, status) {
  return {
    status,
    transactionId: cloneBytes(value.transactionId),
    spendTag: cloneBytes(value.spendTag),
    requestCommitment: cloneBytes(value.requestCommitment),
    requestFingerprint: cloneBytes(value.requestFingerprint),
    physicalTopic: cloneBytes(value.physicalTopic),
    operation: value.operation,
    profileId: value.profileId,
    frameClass: value.frameClass,
    frameHash: cloneBytes(value.frameHash),
    requestedLeaseClass: value.requestedLeaseClass,
    declaredBytes: value.declaredBytes,
    deadlineUnixMillis: value.deadlineUnixMillis,
    remainingAttempts: value.remainingAttempts,
    reservedEpoch: value.reservedEpoch,
    resultIdentity: null,
    resultRevision: null,
    committedEpoch: null,
    resultLeaseClass: null,
    resultLeaseEpoch: null,
    resultBindingBytes: null,
    clientNonce: null,
    retentionClassAtAppend: null,
    appendLeaseEpoch: null,
    expiresAtEpoch: null,
    ackSignature: null,
    resultCommitment: null,
    retryState: 0,
    terminalReason: null,
    terminalEpoch: null,
    expiredEpoch: null,
    inFlight: false
  }
}

function addSpend (state, value) {
  const spendKey = hex(value.spendTag)
  const commitmentKey = hex(value.requestCommitment)
  if (state.spends.has(spendKey)) fail('Inbox snapshot redefines a spend tag')
  if (state.commitments.has(commitmentKey)) fail('Inbox snapshot redefines a request commitment')
  state.spends.set(spendKey, value)
  state.commitments.set(commitmentKey, { spendKey, fingerprint: hex(value.requestFingerprint) })
}

async function reconstructEntries (source, context = {}) {
  if (!source || (typeof source[Symbol.asyncIterator] !== 'function' && typeof source[Symbol.iterator] !== 'function')) {
    fail('Inbox snapshot entries must be iterable')
  }
  const relayPublicKey = asBytes(context.relayPublicKey, 32, 'relayPublicKey', true)
  const state = {
    spends: new Map(),
    commitments: new Map(),
    requestResults: new Map(),
    inboxes: new Map(),
    frames: new Map(),
    retryPins: new Map(),
    accounting: null,
    epochFloor: null,
    clockUnsafe: false,
    readOnlyReason: null,
    integrityEvidence: []
  }
  const profiles = new Map()
  const evidenceByHash = new Map()
  const retryRecords = new Map()
  const retryFramePins = new Map()
  const retryMaterials = new Map()
  let global = null
  let count = 0
  let previous = null
  for await (const raw of source) {
    const entry = readEntry(raw)
    if (previous != null && compareEntries(previous, entry) >= 0) {
      fail('Inbox snapshot entries are not strictly sorted and duplicate-free')
    }
    previous = entry
    count++
    const subtype = entry.key[1]

    if (entry.entryKind === ENTRY_KIND.RESERVATION_ATTEMPT && subtype === SUBTYPE.RESERVED_SPEND) {
      const identity = keyIdentity(entry, ENTRY_KIND.RESERVATION_ATTEMPT, subtype, 32, 'Inbox reserved spend')
      const value = decodeValue(blindInboxReservedSpendSnapshotV1, entry.value, 'Inbox reserved spend')
      if (!b4a.equals(identity, value.spendTag)) fail('Inbox reserved spend key does not match spendTag')
      assertSpendSemantics(value)
      addSpend(state, reconstructSpend(value, 'reserved'))
      continue
    }
    if (entry.entryKind === ENTRY_KIND.SPEND_IDEMPOTENCY && subtype === SUBTYPE.COMMITTED_SPEND) {
      const identity = keyIdentity(entry, ENTRY_KIND.SPEND_IDEMPOTENCY, subtype, 32, 'Inbox committed spend')
      const value = decodeValue(blindInboxCommittedSpendSnapshotV1, entry.value, 'Inbox committed spend')
      if (!b4a.equals(identity, value.spendTag)) fail('Inbox committed spend key does not match spendTag')
      assertSpendSemantics(value)
      const reconstructed = reconstructSpend(value, 'committed')
      reconstructed.resultIdentity = cloneBytes(value.resultIdentity)
      reconstructed.resultRevision = value.resultRevision
      reconstructed.committedEpoch = value.committedEpoch
      reconstructed.resultLeaseClass = value.resultLeaseClass
      reconstructed.resultLeaseEpoch = value.resultLeaseEpoch
      reconstructed.resultBindingBytes = cloneBytes(value.resultBindingBytes)
      reconstructed.clientNonce = cloneBytes(value.clientNonce)
      reconstructed.retentionClassAtAppend = value.retentionClassAtAppend
      reconstructed.appendLeaseEpoch = value.appendLeaseEpoch
      reconstructed.expiresAtEpoch = value.expiresAtEpoch
      reconstructed.ackSignature = cloneBytes(value.ackSignature)
      reconstructed.resultCommitment = cloneBytes(value.resultCommitment)
      reconstructed.retryState = value.retryState
      verifiedResultBinding(value.resultBindingBytes, context, 'Inbox committed spend')
      if (value.operation === OPERATION.INBOX.APPEND) {
        verifiedAppendAck(value, context, 'Inbox committed APPEND')
      }
      addSpend(state, reconstructed)
      continue
    }
    if (entry.entryKind === ENTRY_KIND.SPEND_IDEMPOTENCY && subtype === SUBTYPE.EXPIRED_APPEND_SPEND) {
      const identity = keyIdentity(entry, ENTRY_KIND.SPEND_IDEMPOTENCY, subtype, 32, 'Inbox expired APPEND spend')
      const value = decodeValue(blindInboxExpiredAppendSpendSnapshotV1, entry.value, 'Inbox expired APPEND spend')
      if (!b4a.equals(identity, value.spendTag)) fail('Inbox expired APPEND key does not match spendTag')
      const common = {
        ...value,
        operation: OPERATION.INBOX.APPEND,
        requestedLeaseClass: 0,
        frameHash: value.frameHash
      }
      assertSpendSemantics(common)
      verifiedAppendAck(value, context, 'Inbox expired APPEND')
      const reconstructed = reconstructSpend(common, 'expired-append')
      reconstructed.resultIdentity = cloneBytes(value.resultIdentity)
      reconstructed.resultRevision = value.appendRevision
      reconstructed.committedEpoch = value.storedAtEpoch
      reconstructed.resultBindingBytes = cloneBytes(value.resultBindingBytes)
      reconstructed.clientNonce = cloneBytes(value.clientNonce)
      reconstructed.retentionClassAtAppend = value.retentionClassAtAppend
      reconstructed.appendLeaseEpoch = value.appendLeaseEpoch
      reconstructed.expiresAtEpoch = value.expiresAtEpoch
      reconstructed.expiredEpoch = value.expiredEpoch
      reconstructed.ackSignature = cloneBytes(value.ackSignature)
      reconstructed.resultCommitment = cloneBytes(value.resultCommitment)
      addSpend(state, reconstructed)
      continue
    }
    if (entry.entryKind === ENTRY_KIND.SPEND_IDEMPOTENCY && subtype === SUBTYPE.TERMINAL_SPEND) {
      const identity = keyIdentity(entry, ENTRY_KIND.SPEND_IDEMPOTENCY, subtype, 32, 'Inbox terminal spend')
      const value = decodeValue(blindInboxTerminalSpendSnapshotV1, entry.value, 'Inbox terminal spend')
      if (!b4a.equals(identity, value.spendTag)) fail('Inbox terminal spend key does not match spendTag')
      assertSpendSemantics(value)
      const reconstructed = reconstructSpend(value, 'terminal')
      reconstructed.terminalReason = value.terminalReason
      reconstructed.terminalEpoch = value.terminalEpoch
      addSpend(state, reconstructed)
      continue
    }
    if (entry.entryKind === ENTRY_KIND.SPEND_IDEMPOTENCY && subtype === SUBTYPE.REQUEST_RESULT) {
      const identity = keyIdentity(entry, ENTRY_KIND.SPEND_IDEMPOTENCY, subtype, 32, 'Inbox request result')
      const value = decodeValue(blindInboxRequestResultSnapshotV1, entry.value, 'Inbox request result')
      if (!b4a.equals(identity, value.requestCommitment)) fail('Inbox request result key does not match requestCommitment')
      verifiedResultBinding(value.resultBindingBytes, context, 'Inbox CLOSE result')
      const key = hex(value.requestCommitment)
      if (state.requestResults.has(key)) fail('Inbox snapshot redefines a request result')
      state.requestResults.set(key, {
        operation: 'close',
        transactionId: cloneBytes(value.transactionId),
        requestCommitment: cloneBytes(value.requestCommitment),
        physicalTopic: cloneBytes(value.physicalTopic),
        resultIdentity: cloneBytes(value.resultIdentity),
        resultRevision: value.resultRevision,
        committedEpoch: value.committedEpoch,
        resultBindingBytes: cloneBytes(value.resultBindingBytes),
        clientNonce: cloneBytes(value.clientNonce),
        resultLeaseClass: value.resultLeaseClass,
        resultLeaseEpoch: value.resultLeaseEpoch
      })
      continue
    }
    if (entry.entryKind === ENTRY_KIND.INBOX && subtype === SUBTYPE.INBOX_RECORD) {
      const identity = keyIdentity(entry, ENTRY_KIND.INBOX, subtype, 32, 'Inbox record')
      const value = decodeValue(blindInboxRecordSnapshotV1, entry.value, 'Inbox record')
      if (!b4a.equals(identity, value.physicalTopic)) fail('Inbox record key does not match physicalTopic')
      if (!b4a.equals(inboxPhysicalTopic(value), value.physicalTopic)) fail('Inbox physicalTopic is not self-certifying')
      if (value.metadataVirtualBucket !== deriveBlindVirtualBucket(FAMILY.INBOX, value.physicalTopic)) {
        fail('Inbox metadata virtual bucket does not match the public deterministic mapping')
      }
      const expectedCreate = recordCreateCommitment(relayPublicKey, value, value.allocationLeaseClass)
      if (!b4a.equals(expectedCreate, value.createCommitment)) fail('Inbox create commitment does not match')
      const key = hex(value.physicalTopic)
      if (state.inboxes.has(key)) fail('Inbox snapshot redefines a physicalTopic')
      state.inboxes.set(key, {
        physicalTopic: cloneBytes(value.physicalTopic),
        metadataVirtualBucket: value.metadataVirtualBucket,
        allocationEpoch: value.allocationEpoch,
        allocationLeaseClass: value.allocationLeaseClass,
        frameClassBits: value.frameClassBits,
        appendAuthMode: value.appendAuthMode,
        appendPublicKey: cloneBytes(value.appendPublicKey),
        createPublicKey: cloneBytes(value.createPublicKey),
        renewPublicKey: cloneBytes(value.renewPublicKey),
        closePublicKey: cloneBytes(value.closePublicKey),
        retentionClass: value.retentionClass,
        leaseClass: value.leaseClass,
        leaseEpoch: value.leaseEpoch,
        stateRevision: value.stateRevision,
        policyRevision: value.policyRevision,
        appendRevision: value.appendRevision,
        createCommitment: cloneBytes(value.createCommitment),
        objectState: value.objectState,
        policyState: value.policyState,
        tombstoneReason: value.tombstoneReason,
        terminalEpoch: value.terminalEpoch,
        createSpendTag: cloneBytes(value.createSpendTag),
        createRequestCommitment: cloneBytes(value.createRequestCommitment),
        resultIdentity: cloneBytes(value.resultIdentity),
        createdEpoch: value.createdEpoch
      })
      continue
    }
    if (entry.entryKind === ENTRY_KIND.INBOX && subtype === SUBTYPE.FRAME_RECORD) {
      const identity = keyIdentity(entry, ENTRY_KIND.INBOX, subtype, 40, 'Inbox frame record')
      const value = decodeValue(blindInboxFrameSnapshotV1, entry.value, 'Inbox frame record')
      if (!b4a.equals(identity.subarray(0, 32), value.physicalTopic) ||
          !b4a.equals(identity.subarray(32), u64bytes(value.appendRevision))) {
        fail('Inbox frame record key does not match topic/revision')
      }
      if (value.frameVirtualBucket !== deriveBlindVirtualBucket(FAMILY.INBOX, value.physicalTopic)) {
        fail('Inbox frame virtual bucket does not match the public deterministic mapping')
      }
      const key = frameMapKey(value.physicalTopic, value.appendRevision)
      if (state.frames.has(key)) fail('Inbox snapshot redefines a frame revision')
      state.frames.set(key, {
        physicalTopic: cloneBytes(value.physicalTopic),
        appendRevision: value.appendRevision,
        frameHash: cloneBytes(value.frameHash),
        frameClass: value.frameClass,
        frameVirtualBucket: value.frameVirtualBucket,
        frameObjectId: cloneBytes(value.frameObjectId),
        appendLeaseEpoch: value.appendLeaseEpoch,
        storedAtEpoch: value.storedAtEpoch,
        expiresAtEpoch: value.expiresAtEpoch,
        spendTag: cloneBytes(value.spendTag),
        requestCommitment: cloneBytes(value.requestCommitment),
        resultIdentity: cloneBytes(value.resultIdentity)
      })
      continue
    }
    if (entry.entryKind === ENTRY_KIND.INBOX_GLOBAL && subtype === SUBTYPE.GLOBAL) {
      keyIdentity(entry, ENTRY_KIND.INBOX_GLOBAL, subtype, 0, 'Inbox global record')
      if (global != null) fail('Inbox snapshot contains more than one global record')
      global = decodeValue(blindInboxControlGlobalSnapshotV1, entry.value, 'Inbox global record')
      continue
    }
    if (entry.entryKind === ENTRY_KIND.INBOX_GLOBAL && subtype === SUBTYPE.PROFILE_STAGING) {
      const identity = keyIdentity(entry, ENTRY_KIND.INBOX_GLOBAL, subtype, 2, 'Inbox profile staging')
      const value = decodeValue(blindInboxProfileStagingSnapshotV1, entry.value, 'Inbox profile staging')
      const profileId = identity[0] * 0x100 + identity[1]
      if (profileId !== value.profileId || profiles.has(profileId)) fail('Inbox profile staging key is duplicate or mismatched')
      profiles.set(profileId, safeNumber(value.stagingFrameBytes, 'profile stagingFrameBytes'))
      continue
    }
    if (entry.entryKind === ENTRY_KIND.INBOX_GLOBAL && subtype === SUBTYPE.INTEGRITY_EVIDENCE) {
      const identity = keyIdentity(entry, ENTRY_KIND.INBOX_GLOBAL, subtype, 32, 'Inbox integrity evidence')
      const value = decodeValue(blindInboxIntegrityEvidenceSnapshotV1, entry.value, 'Inbox integrity evidence')
      if (!b4a.equals(identity, value.evidenceHash)) fail('Inbox integrity evidence key does not match evidenceHash')
      const key = hex(value.evidenceHash)
      if (evidenceByHash.has(key)) fail('Inbox snapshot repeats integrity evidence')
      evidenceByHash.set(key, {
        reason: value.reason,
        detectedEpoch: value.detectedEpoch,
        evidenceHash: cloneBytes(value.evidenceHash)
      })
      continue
    }
    if (entry.entryKind === ENTRY_KIND.RETRY_PIN && subtype === SUBTYPE.RETRY_RECORD) {
      const identity = keyIdentity(entry, ENTRY_KIND.RETRY_PIN, subtype, 32, 'Inbox retry record')
      const value = decodeValue(chargedUnaryRetryV1, entry.value, 'Inbox retry record')
      if (!b4a.equals(identity, value.spendTag)) fail('Inbox retry record key does not match spendTag')
      if (value.familyId !== FAMILY.INBOX ||
          (value.operationId !== OPERATION.INBOX.READ && value.operationId !== OPERATION.INBOX.WATCH)) {
        fail('Inbox retry record uses the wrong family or operation')
      }
      const key = hex(value.spendTag)
      if (retryRecords.has(key)) fail('Inbox snapshot repeats a retry record')
      const reconstruction = decodeValue(blindInboxRetryReconstructionV1, value.reconstruction,
        'Inbox retry reconstruction')
      retryRecords.set(key, { value, reconstruction })
      continue
    }
    if (entry.entryKind === ENTRY_KIND.RETRY_PIN && subtype === SUBTYPE.RETRY_FRAME_PIN) {
      const identity = keyIdentity(entry, ENTRY_KIND.RETRY_PIN, subtype, 40, 'Inbox retry frame pin')
      const value = decodeValue(blindInboxRetryFramePinSnapshotV1, entry.value, 'Inbox retry frame pin')
      if (!b4a.equals(identity.subarray(0, 32), value.spendTag) ||
          !b4a.equals(identity.subarray(32), u64bytes(value.appendRevision))) {
        fail('Inbox retry frame pin key does not match spend/revision')
      }
      const key = hex(value.spendTag)
      const pins = retryFramePins.get(key) || []
      if (pins.length > 0 && value.appendRevision <= pins[pins.length - 1].appendRevision) {
        fail('Inbox retry frame pins are not strictly increasing')
      }
      pins.push({
        physicalTopic: cloneBytes(value.physicalTopic),
        appendRevision: value.appendRevision,
        frameHash: cloneBytes(value.frameHash)
      })
      retryFramePins.set(key, pins)
      continue
    }
    if (entry.entryKind === ENTRY_KIND.RETRY_PIN && subtype === SUBTYPE.RETRY_MATERIAL) {
      const identity = keyIdentity(entry, ENTRY_KIND.RETRY_PIN, subtype, 32, 'Inbox retry material')
      const value = decodeValue(blindInboxRetryMaterialSnapshotV1, entry.value, 'Inbox retry material')
      if (!b4a.equals(identity, value.spendTag)) fail('Inbox retry material key does not match spendTag')
      const key = hex(value.spendTag)
      if (retryMaterials.has(key)) fail('Inbox retry material repeats a spendTag')
      retryMaterials.set(key, {
        entriesCommitment: cloneBytes(value.entriesCommitment),
        nextCursor: cloneBytes(value.nextCursor)
      })
      continue
    }
    fail(`unknown Inbox control snapshot entry kind/subtype ${entry.entryKind}/${subtype}`)
  }

  if (context.declaredEntryCount != null && count !== context.declaredEntryCount) {
    fail('Inbox semantic entry count does not match the declared snapshot count')
  }
  if (global == null) fail('Inbox snapshot is incomplete without its global record')
  const epochFloor = global.epochFloor

  for (const spend of state.spends.values()) {
    if (spend.reservedEpoch > epochFloor || (spend.committedEpoch != null && spend.committedEpoch > epochFloor) ||
        (spend.terminalEpoch != null && spend.terminalEpoch > epochFloor) ||
        (spend.expiredEpoch != null && spend.expiredEpoch > epochFloor)) {
      fail('Inbox spend epoch exceeds the checkpoint floor')
    }
    if (spend.status === 'terminal' && spend.terminalReason === 2 && spend.remainingAttempts !== 0) {
      fail('attempts-exhausted Inbox terminal spend must have zero remaining attempts')
    }
  }

  for (const inbox of state.inboxes.values()) {
    if (inbox.createdEpoch > epochFloor || (inbox.terminalEpoch != null && inbox.terminalEpoch > epochFloor)) {
      fail('Inbox record epoch exceeds the checkpoint floor')
    }
    const initialLeaseEpoch = inbox.createdEpoch + LEASE_EPOCHS[inbox.allocationLeaseClass]
    if (inbox.leaseEpoch < initialLeaseEpoch) fail('Inbox leaseEpoch is below its initial allocation lease')
    if (inbox.leaseEpoch > Math.min(0xffffffff, epochFloor + LEASE_EPOCHS[4])) {
      fail('Inbox leaseEpoch exceeds the maximum lease horizon at the checkpoint floor')
    }
    if (inbox.objectState === 2 && inbox.stateRevision === 0n) fail('Inbox tombstone must have a nonzero state revision')
    const expectedCreateResult = resultIdentity(OPERATION.INBOX.CREATE, inbox.physicalTopic,
      inbox.createRequestCommitment, 0n, inbox.createCommitment, inbox.createdEpoch)
    if (!b4a.equals(expectedCreateResult, inbox.resultIdentity)) {
      fail('Inbox create result identity does not match its retained request commitment')
    }
    const createSpend = state.spends.get(hex(inbox.createSpendTag))
    if (createSpend) {
      if (createSpend.status !== 'committed' || createSpend.operation !== OPERATION.INBOX.CREATE ||
          createSpend.committedEpoch !== inbox.createdEpoch || createSpend.resultRevision !== 0n ||
          createSpend.requestedLeaseClass !== inbox.allocationLeaseClass ||
          createSpend.resultLeaseClass !== inbox.allocationLeaseClass ||
          createSpend.resultLeaseEpoch !== inbox.createdEpoch + LEASE_EPOCHS[inbox.allocationLeaseClass] ||
          !b4a.equals(createSpend.physicalTopic, inbox.physicalTopic) ||
          !b4a.equals(createSpend.requestCommitment, inbox.createRequestCommitment) ||
          !b4a.equals(createSpend.resultIdentity, inbox.resultIdentity) ||
          !b4a.equals(expectedCreateResult, inbox.resultIdentity)) {
        fail('Inbox record does not match its retained committed create spend')
      }
    }
  }

  const frameObjectIds = new Set()
  const frameSpendTags = new Set()
  const frameRequestCommitments = new Set()
  for (const frame of state.frames.values()) {
    const inbox = state.inboxes.get(hex(frame.physicalTopic))
    if (!inbox) fail('Inbox frame has no retained inbox record')
    if ((inbox.frameClassBits & (1 << (frame.frameClass - 1))) === 0) fail('Inbox frame class is not allowed by its inbox')
    if (frame.storedAtEpoch < inbox.createdEpoch || frame.storedAtEpoch > epochFloor ||
        frame.appendLeaseEpoch > inbox.leaseEpoch ||
        frame.appendRevision > inbox.appendRevision) {
      fail('Inbox frame exceeds its checkpoint, lease, or append revision floor')
    }
    const expectedExpiry = Math.min(frame.appendLeaseEpoch,
      frame.storedAtEpoch + LEASE_EPOCHS[inbox.retentionClass])
    if (frame.expiresAtEpoch !== expectedExpiry) fail('Inbox frame expiry does not match retention and append lease')
    const expectedResult = resultIdentity(OPERATION.INBOX.APPEND, frame.physicalTopic,
      frame.requestCommitment, frame.appendRevision, frame.frameHash, frame.storedAtEpoch)
    if (!b4a.equals(expectedResult, frame.resultIdentity)) fail('Inbox frame result identity does not match')
    const frameObjectId = hex(frame.frameObjectId)
    if (frameObjectIds.has(frameObjectId)) fail('Inbox frame object reference is aliased by another revision')
    frameObjectIds.add(frameObjectId)
    const frameSpendTag = hex(frame.spendTag)
    const frameRequestCommitment = hex(frame.requestCommitment)
    if (frameSpendTags.has(frameSpendTag) || frameRequestCommitments.has(frameRequestCommitment)) {
      fail('Inbox frame index aliases an append spend or request commitment')
    }
    frameSpendTags.add(frameSpendTag)
    frameRequestCommitments.add(frameRequestCommitment)
    const spend = state.spends.get(hex(frame.spendTag))
    if (spend && (spend.status !== 'committed' || spend.operation !== OPERATION.INBOX.APPEND ||
        spend.resultRevision !== frame.appendRevision || spend.committedEpoch !== frame.storedAtEpoch ||
        !b4a.equals(spend.physicalTopic, frame.physicalTopic) ||
        !b4a.equals(spend.requestCommitment, frame.requestCommitment) ||
        !b4a.equals(spend.frameHash, frame.frameHash) ||
        !b4a.equals(spend.resultIdentity, frame.resultIdentity))) {
      fail('Inbox frame does not match its retained committed append spend')
    }
  }

  for (const result of state.requestResults.values()) {
    if (result.committedEpoch > epochFloor) fail('Inbox close result committedEpoch exceeds the checkpoint floor')
    const inbox = state.inboxes.get(hex(result.physicalTopic))
    if (state.commitments.has(hex(result.requestCommitment))) {
      fail('Inbox close result collides with a charged request commitment')
    }
    if (!inbox || inbox.objectState !== 2 || inbox.tombstoneReason !== 1 ||
        inbox.stateRevision !== result.resultRevision || inbox.terminalEpoch !== result.committedEpoch ||
        result.resultLeaseClass !== 0 || result.resultLeaseEpoch !== inbox.leaseEpoch ||
        !b4a.equals(result.resultIdentity, resultIdentity(OPERATION.INBOX.CLOSE, result.physicalTopic,
          result.requestCommitment, result.resultRevision, inbox.createCommitment, result.committedEpoch))) {
      fail('Inbox close result does not match its retained owner-close tombstone')
    }
  }

  let retryFramePinCount = 0
  for (const [spendKey, wrapper] of retryRecords) {
    const record = wrapper.value
    const reconstruction = wrapper.reconstruction
    const spend = state.spends.get(spendKey)
    const material = retryMaterials.get(spendKey)
    if (record.retryExpiresMinute === 0n) fail('Inbox retry expiry minute must be nonzero')
    if (!spend || spend.status !== 'committed' || spend.operation !== record.operationId ||
        !b4a.equals(spend.requestCommitment, record.requestCommitment) ||
        !b4a.equals(spend.resultCommitment, record.resultCommitment) || spend.retryState !== record.retryState) {
      fail('Inbox retry record does not match its committed spend')
    }
    if (!material) fail('Inbox retry record has no exact retry material')
    const expectedNextCursorHash = material.nextCursor == null ? ZERO32 : blake2b256(material.nextCursor)
    if (!b4a.equals(expectedNextCursorHash, reconstruction.nextCursorHash)) {
      fail('Inbox retry nextCursor does not match its reconstruction hash')
    }
    if (!b4a.equals(record.locatorCommitment, topicCommitment(spend.physicalTopic)) ||
        spend.resultRevision !== record.sourceRevision || reconstruction.lastAppendRevision > record.sourceRevision) {
      fail('Inbox retry record locator or source revision does not match')
    }
    const pins = retryFramePins.get(spendKey) || []
    if (pins.length !== reconstruction.entryCount) fail('Inbox retry frame pin count is incomplete')
    if (pins.length === 0) {
      if (reconstruction.firstAppendRevision !== 0n || reconstruction.lastAppendRevision !== 0n) {
        fail('Inbox empty retry has a nonempty append range')
      }
    } else if (pins[0].appendRevision !== reconstruction.firstAppendRevision ||
        pins[pins.length - 1].appendRevision !== reconstruction.lastAppendRevision) {
      fail('Inbox retry frame pin range does not match reconstruction')
    }
    const pinnedEntries = []
    for (const pin of pins) {
      if (!b4a.equals(pin.physicalTopic, spend.physicalTopic)) fail('Inbox retry frame pin substitutes another topic')
      const frame = state.frames.get(frameMapKey(pin.physicalTopic, pin.appendRevision))
      if (!frame || !b4a.equals(frame.frameHash, pin.frameHash)) {
        fail('Inbox retry frame pin has no matching immutable frame reference')
      }
      pinnedEntries.push({
        appendRevision: frame.appendRevision,
        frameHash: cloneBytes(frame.frameHash),
        frameClass: frame.frameClass,
        frameObjectId: cloneBytes(frame.frameObjectId)
      })
    }
    if (!b4a.equals(record.sourceCommitment,
      retrySourceCommitment(spend.physicalTopic, record.sourceRevision, reconstruction, pins))) {
      fail('Inbox retry source commitment does not match its exact pinned frame index')
    }
    const expectedResult = resultIdentity(spend.operation, spend.physicalTopic, spend.requestCommitment,
      spend.resultRevision, spend.resultCommitment, spend.committedEpoch)
    if (!b4a.equals(expectedResult, spend.resultIdentity)) fail('Inbox retry spend result identity does not match')
    retryFramePinCount += pins.length
    state.retryPins.set(spendKey, {
      spendTag: cloneBytes(record.spendTag),
      requestCommitment: cloneBytes(record.requestCommitment),
      physicalTopic: cloneBytes(spend.physicalTopic),
      operation: record.operationId,
      locatorCommitment: cloneBytes(record.locatorCommitment),
      sourceRevision: record.sourceRevision,
      sourceCommitment: cloneBytes(record.sourceCommitment),
      resultCommitment: cloneBytes(record.resultCommitment),
      reconstruction: cloneStateValue(reconstruction),
      retryExpiresMinute: record.retryExpiresMinute,
      retryState: record.retryState,
      entries: pins.map(cloneStateValue),
      pinnedEntries,
      entriesCommitment: cloneBytes(material.entriesCommitment),
      nextCursor: cloneBytes(material.nextCursor),
      resultBindingBytes: cloneBytes(spend.resultBindingBytes),
      clientNonce: cloneBytes(spend.clientNonce),
      committedEpoch: spend.committedEpoch
    })
  }
  for (const spendKey of retryFramePins.keys()) {
    if (!retryRecords.has(spendKey)) fail('Inbox retry frame pin has no parent retry record')
  }
  for (const spendKey of retryMaterials.keys()) {
    if (!retryRecords.has(spendKey)) fail('Inbox retry material has no parent retry record')
  }

  for (const spend of state.spends.values()) {
    const inbox = state.inboxes.get(hex(spend.physicalTopic))
    if (spend.operation !== OPERATION.INBOX.CREATE && !inbox) {
      fail('non-CREATE Inbox spend has no retained inbox record')
    }
    if (spend.status === 'reserved' || spend.status === 'terminal') {
      if (spend.status === 'reserved' && spend.operation !== OPERATION.INBOX.CREATE && inbox?.objectState === 2) {
        fail('live non-CREATE Inbox reservation points at a closed inbox')
      }
      continue
    }
    if (spend.operation === OPERATION.INBOX.RENEW) {
      if (spend.resultRevision === 0n || spend.resultRevision > inbox.stateRevision ||
          spend.resultLeaseClass !== spend.requestedLeaseClass || spend.resultLeaseEpoch == null ||
          spend.resultLeaseEpoch > inbox.leaseEpoch ||
          !b4a.equals(spend.resultIdentity, resultIdentity(spend.operation, spend.physicalTopic,
            spend.requestCommitment, spend.resultRevision, inbox.createCommitment, spend.committedEpoch))) {
        fail('Inbox renew spend does not match its retained inbox revision')
      }
    } else if (spend.operation === OPERATION.INBOX.APPEND) {
      const frame = state.frames.get(frameMapKey(spend.physicalTopic, spend.resultRevision))
      if (spend.status === 'expired-append') {
        if (frame) fail('expired Inbox APPEND still retains a live frame reference')
        if (spend.expiredEpoch < spend.expiresAtEpoch || spend.retryState !== 0) {
          fail('expired Inbox APPEND has invalid expiry or retry state')
        }
      } else if (!frame) {
        fail('Inbox append spend has no retained frame reference')
      } else if (spend.retentionClassAtAppend == null ||
          spend.appendLeaseEpoch !== frame.appendLeaseEpoch ||
          spend.expiresAtEpoch !== frame.expiresAtEpoch) {
        fail('Inbox append spend expiry authority does not match its retained frame')
      }
    } else if (spend.operation === OPERATION.INBOX.READ || spend.operation === OPERATION.INBOX.WATCH) {
      const hasRetry = state.retryPins.has(hex(spend.spendTag))
      if (spend.retryState === 1 && !hasRetry) fail('replayable Inbox read/watch spend has no retry record')
      if (!hasRetry && spend.retryState !== 3) fail('nonterminal Inbox read/watch spend has no retry record')
      if (!hasRetry && !b4a.equals(spend.resultIdentity, resultIdentity(spend.operation, spend.physicalTopic,
        spend.requestCommitment, spend.resultRevision, spend.resultCommitment, spend.committedEpoch))) {
        fail('terminal Inbox read/watch spend result identity does not match')
      }
    }
  }

  for (const evidence of evidenceByHash.values()) {
    if (evidence.detectedEpoch > epochFloor) fail('Inbox integrity evidence exceeds the checkpoint floor')
  }

  const reservedAppends = [...state.spends.values()].filter(value =>
    value.status === 'reserved' && value.operation === OPERATION.INBOX.APPEND)
  const reservedCreates = [...state.spends.values()].filter(value =>
    value.status === 'reserved' && value.operation === OPERATION.INBOX.CREATE)
  const expectedProfiles = new Map()
  for (const value of reservedAppends) {
    expectedProfiles.set(value.profileId, (expectedProfiles.get(value.profileId) || 0) + value.declaredBytes)
  }
  if (profiles.size !== expectedProfiles.size) fail('Inbox profile staging index count is incomplete')
  for (const [profileId, bytes] of expectedProfiles) {
    if (profiles.get(profileId) !== bytes) fail('Inbox profile staging accounting does not match reservations')
  }

  const expectedAccounting = {
    storedFrameBytes: [...state.frames.values()].reduce((sum, value) => sum + INBOX_FRAME_CLASS[value.frameClass], 0),
    stagingFrameBytes: reservedAppends.reduce((sum, value) => sum + value.declaredBytes, 0),
    controlBytes: (state.spends.size + state.requestResults.size) * CONTROL_RECORD_BYTES +
      (retryRecords.size + retryFramePinCount) * RETRY_RECORD_BYTES,
    tombstoneBytes: (state.inboxes.size + reservedCreates.length) * TOMBSTONE_RECORD_BYTES,
    frameIndexBytes: state.frames.size * FRAME_INDEX_RECORD_BYTES,
    reservedFrames: reservedAppends.length
  }
  const actualAccounting = Object.fromEntries(Object.keys(expectedAccounting).map(field => [
    field, safeNumber(global[field], field)
  ]))
  for (const [field, expected] of Object.entries(expectedAccounting)) {
    if (actualAccounting[field] !== expected) fail(`Inbox ${field} accounting does not reconstruct exactly`)
  }

  const expectedCounts = {
    inboxCount: state.inboxes.size,
    frameCount: state.frames.size,
    spendCount: state.spends.size,
    commitmentCount: state.commitments.size,
    requestResultCount: state.requestResults.size,
    retryRecordCount: retryRecords.size,
    retryFramePinCount,
    profileStagingCount: profiles.size,
    integrityEvidenceCount: evidenceByHash.size
  }
  for (const [field, expected] of Object.entries(expectedCounts)) {
    const actual = typeof global[field] === 'number' ? global[field] : safeNumber(global[field], field)
    if (actual !== expected) fail(`Inbox global ${field} does not match reconstructed state`)
  }
  if ((global.recoveryGap === 1) !== (evidenceByHash.size > 0)) {
    fail('Inbox recovery-gap state does not match integrity evidence')
  }
  if (context.checkpointEpochFloor != null && epochFloor !== context.checkpointEpochFloor) {
    fail('Inbox epoch floor does not match the checkpoint header')
  }

  state.accounting = { ...actualAccounting, stagingByProfile: profiles }
  state.epochFloor = epochFloor
  state.clockUnsafe = global.clockUnsafe === 1
  state.readOnlyReason = global.recoveryGap === 1 ? 'RECOVERY_GAP_READ_ONLY' : null
  state.integrityEvidence = [...evidenceByHash.values()]
  return { state, count }
}

function assertCommitmentMap (expected, actual) {
  expected = requireMap(expected, 'commitments')
  if (expected.size !== actual.size) fail('Inbox commitment index count does not match spends')
  for (const [key, value] of actual) {
    const supplied = expected.get(key)
    if (!supplied || supplied.spendKey !== value.spendKey || supplied.fingerprint !== value.fingerprint) {
      fail('Inbox commitment index does not match reconstructed spends')
    }
  }
}

function assertRetryPinMap (expected, actual) {
  expected = requireMap(expected, 'retryPins')
  if (expected.size !== actual.size) fail('Inbox retry pin index count does not match its canonical records')
  for (const [key, recovered] of actual) {
    const supplied = expected.get(key)
    if (!supplied || supplied.operation !== recovered.operation ||
        asU64(supplied.sourceRevision, 'retry sourceRevision') !== recovered.sourceRevision ||
        asU64(supplied.retryExpiresMinute, 'retry retryExpiresMinute') !== recovered.retryExpiresMinute ||
        supplied.retryState !== recovered.retryState || !Array.isArray(supplied.entries)) {
      fail('Inbox retry pin index does not match reconstructed records')
    }
    for (const field of [
      'spendTag', 'requestCommitment', 'physicalTopic', 'locatorCommitment',
      'sourceCommitment', 'resultCommitment', 'entriesCommitment',
      'resultBindingBytes', 'clientNonce'
    ]) {
      const length = field === 'resultBindingBytes' ? null : 32
      if (!b4a.equals(asBytes(supplied[field], length, `retry ${field}`), recovered[field])) {
        fail(`Inbox retry pin ${field} does not match reconstructed records`)
      }
    }
    if (asU64(supplied.committedEpoch, 'retry committedEpoch') !== BigInt(recovered.committedEpoch) ||
        !b4a.equals(cloneBytes(supplied.nextCursor) || b4a.alloc(0),
          cloneBytes(recovered.nextCursor) || b4a.alloc(0)) ||
        !Array.isArray(supplied.pinnedEntries) ||
        supplied.pinnedEntries.length !== recovered.pinnedEntries.length) {
      fail('Inbox retry exact material does not match reconstructed records')
    }
    const suppliedReconstruction = supplied.reconstruction
    if (!suppliedReconstruction || suppliedReconstruction.version !== 1 ||
        asU64(suppliedReconstruction.firstAppendRevision, 'retry firstAppendRevision') !==
          recovered.reconstruction.firstAppendRevision ||
        asU64(suppliedReconstruction.lastAppendRevision, 'retry lastAppendRevision') !==
          recovered.reconstruction.lastAppendRevision ||
        suppliedReconstruction.entryCount !== recovered.reconstruction.entryCount ||
        !b4a.equals(asBytes(suppliedReconstruction.nextCursorHash, 32, 'retry nextCursorHash'),
          recovered.reconstruction.nextCursorHash) || supplied.entries.length !== recovered.entries.length) {
      fail('Inbox retry reconstruction does not match reconstructed records')
    }
    for (let index = 0; index < recovered.entries.length; index++) {
      const suppliedEntry = supplied.entries[index]
      const recoveredEntry = recovered.entries[index]
      if (!suppliedEntry || asU64(suppliedEntry.appendRevision, 'retry appendRevision') !==
        recoveredEntry.appendRevision ||
          !b4a.equals(asBytes(suppliedEntry.frameHash, 32, 'retry frameHash'), recoveredEntry.frameHash)) {
        fail('Inbox retry frame pin list does not match reconstructed records')
      }
      const suppliedPinned = supplied.pinnedEntries[index]
      const recoveredPinned = recovered.pinnedEntries[index]
      if (!suppliedPinned || suppliedPinned.frameClass !== recoveredPinned.frameClass ||
          asU64(suppliedPinned.appendRevision, 'retry pinned appendRevision') !== recoveredPinned.appendRevision ||
          !b4a.equals(asBytes(suppliedPinned.frameHash, 32, 'retry pinned frameHash'), recoveredPinned.frameHash) ||
          !b4a.equals(asBytes(suppliedPinned.frameObjectId, 32, 'retry pinned frameObjectId'),
            recoveredPinned.frameObjectId)) {
        fail('Inbox retry pinned entry material does not match reconstructed records')
      }
    }
  }
}

function ownedTuple (header) {
  if (!header || typeof header !== 'object') fail('snapshot semantic header is required')
  return {
    relayPublicKey: cloneBytes(asBytes(header.relayPublicKey, 32, 'header relayPublicKey', true)),
    storeId: cloneBytes(asBytes(header.storeId, 32, 'header storeId', true)),
    durabilityContinuityHash: cloneBytes(asBytes(header.durabilityContinuityHash, 32,
      'header durabilityContinuityHash', true)),
    walSequence: asU64(header.walSequence, 'header walSequence'),
    walHash: cloneBytes(asBytes(header.walHash, 32, 'header walHash', true))
  }
}

export function createBlindInboxControlSnapshotSemanticAuthority (options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('Inbox semantic authority options must be an object')
  }
  const maximumCandidateEntries = options.maximumCandidateEntries == null
    ? 1000000
    : integer(options.maximumCandidateEntries, 1, 0x1000000, 'maximumCandidateEntries')
  const authority = Object.freeze({
    kind: 'BLIND_INBOX_CONTROL_SNAPSHOT_RECOVERY_SEMANTIC_AUTHORITY_V1',
    productionComplete: false,
    publicationAuthorized: false
  })
  AUTHORITIES.set(authority, Object.freeze({ maximumCandidateEntries }))
  return authority
}

export async function * streamBlindInboxControlSnapshotEntries (authority, engineState) {
  const authorityState = assertAuthority(authority)
  const entries = candidateEntries(engineState, authorityState.maximumCandidateEntries)
  const reconstructed = await reconstructEntries(entries, {
    relayPublicKey: engineState.relayPublicKey,
    storeId: engineState.storeId,
    durabilityContinuityHash: engineState.durabilityContinuityHash,
    checkpointEpochFloor: engineState.epochFloor,
    declaredEntryCount: entries.length
  })
  assertCommitmentMap(engineState.commitments, reconstructed.state.commitments)
  assertRetryPinMap(engineState.retryPins, reconstructed.state.retryPins)
  for (const entry of entries) yield entry
}

export async function reconstructBlindInboxControlSnapshot (authority, input = {}) {
  assertAuthority(authority)
  const tuple = ownedTuple(input.header)
  const checkpointHeader = input.checkpointHeader
  if (!checkpointHeader || typeof checkpointHeader !== 'object') fail('checkpointHeader is required for Inbox reconstruction')
  if (!b4a.equals(tuple.relayPublicKey, asBytes(checkpointHeader.relayPublicKey, 32,
    'checkpoint relayPublicKey', true)) ||
      !b4a.equals(tuple.storeId, asBytes(checkpointHeader.storeId, 32, 'checkpoint storeId', true)) ||
      !b4a.equals(tuple.durabilityContinuityHash,
        asBytes(checkpointHeader.durabilityContinuityHash, 32, 'checkpoint durabilityContinuityHash', true)) ||
      tuple.walSequence !== asU64(checkpointHeader.coveredWalSequence, 'checkpoint coveredWalSequence') ||
      !b4a.equals(tuple.walHash, asBytes(checkpointHeader.coveredWalHash, 32,
        'checkpoint coveredWalHash', true))) {
    fail('Inbox semantic snapshot tuple does not match its checkpoint header')
  }
  const declaredEntryCount = integer(input.declaredEntryCount, 1, 0x1000000, 'declaredEntryCount')
  const reconstructed = await reconstructEntries(input.entries, {
    relayPublicKey: tuple.relayPublicKey,
    storeId: tuple.storeId,
    durabilityContinuityHash: tuple.durabilityContinuityHash,
    checkpointEpochFloor: integer(checkpointHeader.epochFloor, 0, 0xffffffff, 'checkpoint epochFloor'),
    declaredEntryCount
  })
  const verified = Object.freeze({
    ...tuple,
    entryCount: reconstructed.count,
    inboxState: reconstructed.state,
    inboxComplete: true,
    recoveryVerified: true,
    publicationAuthorized: false,
    productionComplete: false,
    exclusions: BLIND_INBOX_CONTROL_SNAPSHOT_STATUS.exclusions
  })
  const result = {}
  for (const field of ['relayPublicKey', 'storeId', 'durabilityContinuityHash', 'walHash']) {
    Object.defineProperty(result, field, { enumerable: true, get: () => cloneBytes(verified[field]) })
  }
  Object.defineProperty(result, 'inboxState', {
    enumerable: true,
    get: () => cloneStateValue(verified.inboxState)
  })
  for (const field of [
    'walSequence', 'entryCount', 'inboxComplete', 'recoveryVerified',
    'publicationAuthorized', 'productionComplete', 'exclusions'
  ]) {
    Object.defineProperty(result, field, { enumerable: true, value: verified[field] })
  }
  Object.freeze(result)
  VERIFIED_RESULTS.set(result, verified)
  return result
}

export function createBlindInboxControlSnapshotSemanticVerifier (authority) {
  const state = assertAuthority(authority)
  const verifier = input => reconstructBlindInboxControlSnapshot(authority, input)
  VERIFIERS.set(verifier, state)
  return verifier
}

export function verifyBlindInboxControlSnapshotSemanticVerifier (verifier) {
  if (!VERIFIERS.has(verifier)) throw new TypeError('a branded Inbox control snapshot semantic verifier is required')
  return verifier
}

export function verifyBlindInboxControlSnapshotSemanticResult (result, expected = {}) {
  const verified = VERIFIED_RESULTS.get(result)
  if (!verified) throw new TypeError('a branded Inbox control snapshot semantic result is required')
  if (expected.entryCount != null && verified.entryCount !== expected.entryCount) {
    fail('Inbox semantic result entryCount does not match')
  }
  if (expected.walSequence != null && verified.walSequence !== asU64(expected.walSequence, 'expected walSequence')) {
    fail('Inbox semantic result walSequence does not match')
  }
  for (const field of ['relayPublicKey', 'storeId', 'durabilityContinuityHash', 'walHash']) {
    if (expected[field] != null && !b4a.equals(verified[field], asBytes(expected[field], 32, `expected ${field}`))) {
      fail(`Inbox semantic result ${field} does not match`)
    }
  }
  if (verified.publicationAuthorized !== false || verified.productionComplete !== false) {
    fail('Inbox semantic result must not claim publication or complete-daemon authority')
  }
  return result
}
