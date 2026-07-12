import b4a from 'b4a'
import {
  ADMISSION_MODE,
  COST_CLASS_RULE_ID,
  DRAFT_SCHEMA_CATALOG,
  EXECUTABLE_SCHEMA_CODECS,
  FAMILY,
  OPERATION,
  OPERATION_PROFILE_ROWS,
  SCHEMA_CATEGORY,
  allocationCommitment,
  cellBatchGetRequestCommitment,
  cellGetRequestCommitment,
  cellManageRequestCommitment,
  cellProveRequestCommitment,
  cellPutRequestCommitment,
  coreMirrorRequestCommitment,
  coreOpenReplicationRequestCommitment,
  coreServeRequestCommitment,
  forwardOpenRequestCommitment,
  inboxAppendRequestCommitment,
  inboxCreateCommitment,
  inboxCreateRequestCommitment,
  inboxManageRequestCommitment,
  inboxReadRequestCommitment,
  inboxWatchRequestCommitment
} from '@hiverelay/blind-protocol'

const MiB = 1024 * 1024
const ZERO_COST = Object.freeze({ resourceClass: 0, leaseClass: 0 })

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function pairKey (familyId, operationId) {
  return `${familyId}:${operationId}`
}

const wireSchemaNames = new Map(DRAFT_SCHEMA_CATALOG
  .filter(entry => entry.category === SCHEMA_CATEGORY.WIRE)
  .map(entry => [entry.categoryLocalSchemaId, entry.schemaName]))

export const OPERATION_CATALOG = Object.freeze(OPERATION_PROFILE_ROWS.map((profile, ordinal) => {
  const requestSchemaName = wireSchemaNames.get(profile.requestSchemaId)
  const resultSchemaName = profile.resultSchemaId === 0 ? null : wireSchemaNames.get(profile.resultSchemaId)
  const requestCodec = requestSchemaName == null ? null : EXECUTABLE_SCHEMA_CODECS[requestSchemaName]
  const resultCodec = resultSchemaName == null ? null : EXECUTABLE_SCHEMA_CODECS[resultSchemaName]
  if (!requestCodec || (resultSchemaName != null && !resultCodec)) {
    throw new Error(`operation ${pairKey(profile.familyId, profile.operationId)} has no executable WIRE codec`)
  }
  return Object.freeze({
    ...profile,
    ordinal,
    operationBit: 1 << ordinal,
    requestSchemaName,
    requestCodec,
    resultSchemaName,
    resultCodec
  })
}))

if (OPERATION_CATALOG.length !== 22 || OPERATION_CATALOG.some((entry, index) => entry.ordinal !== index)) {
  throw new Error('blind daemon operation catalog must contain the exact 22-row ABI projection')
}

const operationByPair = new Map(OPERATION_CATALOG.map(entry => [pairKey(entry.familyId, entry.operationId), entry]))

export function daemonOperationProfile (familyId, operationId) {
  return operationByPair.get(pairKey(familyId, operationId)) || null
}

export function daemonOperationBit (familyId, operationId) {
  const profile = daemonOperationProfile(familyId, operationId)
  return profile == null ? 0 : profile.operationBit
}

export function admissionFromRequest (profile, request) {
  const ordinary = request && request.admission != null ? request.admission : null
  const hop = request && request.hopAdmission != null ? request.hopAdmission : null
  if (ordinary != null && hop != null) fail('BAD_ENCODING', 'request contains more than one admission value')
  const admission = ordinary == null ? hop : ordinary
  if (profile.admissionMode === ADMISSION_MODE.NONE && admission != null) {
    fail('BAD_ENCODING', 'operation forbids admission')
  }
  return admission
}

export function assertOperationBodyRelation (profile, request) {
  if (profile.familyId === FAMILY.INBOX &&
      (profile.operationId === OPERATION.INBOX.RENEW || profile.operationId === OPERATION.INBOX.CLOSE)) {
    const expected = profile.operationId === OPERATION.INBOX.RENEW ? 1 : 2
    if (request.operation !== expected) fail('BAD_ENCODING', 'inbox management body does not match dispatch operation')
  }
}

function relayKeyInput (descriptor) {
  if (!descriptor || !descriptor.relayPublicKey) fail('INTERNAL', 'active descriptor has no relay key')
  return descriptor.relayPublicKey
}

const requestCommitmentByPair = new Map([
  [pairKey(FAMILY.CELL, OPERATION.CELL.PUT), (request, descriptor) => {
    const committedAllocation = allocationCommitment({
      ...request,
      relayPublicKey: relayKeyInput(descriptor),
      declaredCellBlobHash: request.declaredBlobHash
    })
    return cellPutRequestCommitment({
      allocationCommitment: committedAllocation,
      clientNonce: request.clientNonce
    })
  }],
  [pairKey(FAMILY.CELL, OPERATION.CELL.GET), (request, descriptor) => cellGetRequestCommitment({
    ...request,
    relayPublicKey: relayKeyInput(descriptor)
  })],
  [pairKey(FAMILY.CELL, OPERATION.CELL.RENEW), (request, descriptor) => cellManageRequestCommitment({
    ...request,
    relayPublicKey: relayKeyInput(descriptor),
    operation: 'cell-renew',
    requestedLeaseClass: request.leaseClass
  })],
  [pairKey(FAMILY.CELL, OPERATION.CELL.DROP), (request, descriptor) => cellManageRequestCommitment({
    ...request,
    relayPublicKey: relayKeyInput(descriptor),
    operation: 'cell-drop',
    requestedLeaseClass: 0
  })],
  [pairKey(FAMILY.CELL, OPERATION.CELL.PROVE), (request, descriptor) => cellProveRequestCommitment({
    ...request,
    relayPublicKey: relayKeyInput(descriptor)
  })],
  [pairKey(FAMILY.CELL, OPERATION.CELL.BATCH_GET), (request, descriptor) => cellBatchGetRequestCommitment({
    ...request,
    relayPublicKey: relayKeyInput(descriptor)
  })],
  [pairKey(FAMILY.INBOX, OPERATION.INBOX.CREATE), (request, descriptor) => {
    const committedCreate = inboxCreateCommitment({
      ...request,
      relayPublicKey: relayKeyInput(descriptor)
    })
    return inboxCreateRequestCommitment({
      inboxCreateCommitment: committedCreate,
      clientNonce: request.clientNonce
    })
  }],
  [pairKey(FAMILY.INBOX, OPERATION.INBOX.RENEW), (request, descriptor) => inboxManageRequestCommitment({
    ...request,
    relayPublicKey: relayKeyInput(descriptor),
    operation: 'inbox-renew',
    requestedLeaseClass: request.leaseClass
  })],
  [pairKey(FAMILY.INBOX, OPERATION.INBOX.CLOSE), (request, descriptor) => inboxManageRequestCommitment({
    ...request,
    relayPublicKey: relayKeyInput(descriptor),
    operation: 'inbox-close',
    requestedLeaseClass: 0
  })],
  [pairKey(FAMILY.INBOX, OPERATION.INBOX.APPEND), (request, descriptor) => inboxAppendRequestCommitment({
    ...request,
    relayPublicKey: relayKeyInput(descriptor)
  })],
  [pairKey(FAMILY.INBOX, OPERATION.INBOX.READ), (request, descriptor) => inboxReadRequestCommitment({
    ...request,
    relayPublicKey: relayKeyInput(descriptor)
  })],
  [pairKey(FAMILY.INBOX, OPERATION.INBOX.WATCH), (request, descriptor) => inboxWatchRequestCommitment({
    ...request,
    relayPublicKey: relayKeyInput(descriptor)
  })],
  [pairKey(FAMILY.CORE, OPERATION.CORE.MIRROR), (request, descriptor) => coreMirrorRequestCommitment({
    ...request,
    relayPublicKey: relayKeyInput(descriptor)
  })],
  [pairKey(FAMILY.CORE, OPERATION.CORE.PROVE), (request, descriptor) => coreServeRequestCommitment({
    ...request,
    relayPublicKey: relayKeyInput(descriptor)
  })],
  [pairKey(FAMILY.CORE, OPERATION.CORE.OPEN_REPLICATION), (request, descriptor) => coreOpenReplicationRequestCommitment({
    ...request,
    relayPublicKey: relayKeyInput(descriptor)
  })],
  [pairKey(FAMILY.FORWARD, OPERATION.FORWARD.OPEN), (request, descriptor, context) => forwardOpenRequestCommitment({
    ...request,
    previousRelayKey: context.adjacentRelayKey
  })]
])

const commitmentPairs = OPERATION_CATALOG.filter(profile => profile.requestCommitmentDomainId !== 0)
if (commitmentPairs.some(profile => !requestCommitmentByPair.has(pairKey(profile.familyId, profile.operationId))) ||
    requestCommitmentByPair.size !== commitmentPairs.length) {
  throw new Error('request commitment implementation is not the exact ABI projection')
}

export function operationRequestCommitment (profile, request, descriptor, context = {}) {
  if (profile.requestCommitmentDomainId === 0) return null
  const derive = requestCommitmentByPair.get(pairKey(profile.familyId, profile.operationId))
  try {
    return derive(request, descriptor, context)
  } catch (error) {
    if (error && error.code) throw error
    fail('BAD_ENCODING', 'request commitment derivation failed')
  }
}

function integerClass (value, minimum, maximum, field) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    fail('SPEND_INVALID', `${field} is outside its admission class range`)
  }
  return value
}

function positiveBigInt (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 1) fail('SPEND_INVALID', `${field} is not a positive integer`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 1n || value > ((1n << 64n) - 1n)) {
    fail('SPEND_INVALID', `${field} is outside u64`)
  }
  return value
}

function highestFrameClass (bits) {
  integerClass(bits, 1, 7, 'frameClassBits')
  if ((bits & ~0x07) !== 0) fail('SPEND_INVALID', 'frameClassBits contains an unknown class')
  return bits & 4 ? 3 : bits & 2 ? 2 : 1
}

function resultBand (bytes, maximum, field) {
  if (!Number.isSafeInteger(bytes) || bytes < 1 || bytes > maximum) {
    fail('SPEND_INVALID', `${field} is outside the operation result cap`)
  }
  if (bytes <= 4 * 1024) return 1
  if (bytes <= 16 * 1024) return 2
  if (bytes <= 64 * 1024) return 3
  if (bytes <= 256 * 1024) return 4
  if (bytes <= MiB) return 5
  if (bytes <= 4 * MiB) return 6
  fail('SPEND_INVALID', `${field} exceeds the largest admission band`)
}

function waitBand (millis) {
  integerClass(millis, 1, 30000, 'maxWaitMillis')
  if (millis <= 1000) return 1
  if (millis <= 5000) return 2
  if (millis <= 15000) return 3
  return 4
}

function logarithmicLengthClass (bytes) {
  let units = (positiveBigInt(bytes, 'coreBillableBytes') + BigInt(MiB - 1)) / BigInt(MiB)
  let value = 1
  while (units > 1n) {
    units >>= 1n
    value++
  }
  return integerClass(value, 1, 45, 'core mirror resource class')
}

export function deriveAdmissionCost (profile, request, authenticatedState = {}) {
  const rule = profile.costClassRuleId
  if (rule === 0) return ZERO_COST
  let resourceClass
  let leaseClass
  switch (rule) {
    case COST_CLASS_RULE_ID.CELL_PUT_CLASS_LEASE:
      resourceClass = integerClass(request.sizeClass, 1, 5, 'sizeClass')
      leaseClass = integerClass(request.leaseClass, 1, 4, 'leaseClass')
      break
    case COST_CLASS_RULE_ID.STORED_CELL_CLASS_NONE:
      resourceClass = authenticatedState.absent === true
        ? 1
        : integerClass(authenticatedState.storedCellSizeClass, 1, 5, 'storedCellSizeClass')
      leaseClass = 0
      break
    case COST_CLASS_RULE_ID.STORED_CELL_CLASS_REQUEST_LEASE:
      resourceClass = integerClass(authenticatedState.storedCellSizeClass, 1, 5, 'storedCellSizeClass')
      leaseClass = integerClass(request.leaseClass, 1, 4, 'leaseClass')
      break
    case COST_CLASS_RULE_ID.CANONICAL_RESULT_BAND_NONE:
      resourceClass = authenticatedState.absent === true
        ? 1
        : resultBand(authenticatedState.canonicalResultBytes, profile.maxResultBodyBytes, 'canonicalResultBytes')
      leaseClass = 0
      break
    case COST_CLASS_RULE_ID.INBOX_CREATE_SHAPE_LEASE:
      resourceClass = (integerClass(request.retentionClass, 1, 4, 'retentionClass') - 1) * 3 +
        highestFrameClass(request.frameClassBits)
      leaseClass = integerClass(request.leaseClass, 1, 4, 'leaseClass')
      break
    case COST_CLASS_RULE_ID.INBOX_STORED_SHAPE_REQUEST_LEASE:
      resourceClass = (integerClass(authenticatedState.inboxRetentionClass, 1, 4, 'inboxRetentionClass') - 1) * 3 +
        highestFrameClass(authenticatedState.inboxFrameClassBits)
      leaseClass = integerClass(request.leaseClass, 1, 4, 'leaseClass')
      break
    case COST_CLASS_RULE_ID.INBOX_APPEND_FRAME_RETENTION:
      resourceClass = integerClass(request.frameClass, 1, 3, 'frameClass')
      leaseClass = integerClass(authenticatedState.inboxRetentionClass, 1, 4, 'inboxRetentionClass')
      break
    case COST_CLASS_RULE_ID.INBOX_WATCH_BOUND_WAIT:
      resourceClass = (waitBand(request.maxWaitMillis) - 1) * 6 +
        resultBand(authenticatedState.canonicalResultBytes, profile.maxResultBodyBytes, 'canonicalResultBytes')
      leaseClass = 0
      break
    case COST_CLASS_RULE_ID.CORE_MIRROR_LENGTH_LEASE:
      resourceClass = logarithmicLengthClass(authenticatedState.coreBillableBytes)
      leaseClass = integerClass(request.leaseClass, 1, 4, 'leaseClass')
      break
    case COST_CLASS_RULE_ID.CORE_SESSION_CLASS_NONE:
      resourceClass = integerClass(request.sessionClass, 1, 3, 'sessionClass')
      leaseClass = 0
      break
    case COST_CLASS_RULE_ID.FORWARD_CIRCUIT_CLASS_NONE:
      resourceClass = integerClass(request.circuitClass, 1, 3, 'circuitClass')
      leaseClass = 0
      break
    default:
      fail('INTERNAL', 'operation references an unknown admission cost rule')
  }
  return Object.freeze({ resourceClass, leaseClass })
}

export function resultBindingFromValue (value) {
  if (!value || typeof value !== 'object') return null
  if (value.relayBinding) return value.relayBinding
  if (value.receipt && value.receipt.relayBinding) return value.receipt.relayBinding
  if (value.acknowledgement && value.acknowledgement.relayBinding) return value.acknowledgement.relayBinding
  return null
}

export function requestNonceFromResult (value) {
  if (!value || typeof value !== 'object') return null
  if (value.requestNonce) return value.requestNonce
  if (value.receipt && value.receipt.requestNonce) return value.receipt.requestNonce
  if (value.acknowledgement && value.acknowledgement.requestNonce) return value.acknowledgement.requestNonce
  return null
}

export function requestCommitmentFromResult (value) {
  if (!value || typeof value !== 'object') return null
  if (value.requestCommitment) return value.requestCommitment
  if (value.receipt && value.receipt.requestCommitment) return value.receipt.requestCommitment
  if (value.acknowledgement && value.acknowledgement.requestCommitment) return value.acknowledgement.requestCommitment
  return null
}

export function sameBytes (left, right) {
  return Boolean(left && right && left.byteLength === right.byteLength && b4a.equals(left, right))
}
