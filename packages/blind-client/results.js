import b4a from 'b4a'
import {
  AUXILIARY_SIGNATURE_DOMAIN_ID,
  CELL_RECEIPT_RESULT,
  CORE_ACK_RESULT,
  FAMILY,
  INBOX_APPEND_RESULT,
  INBOX_RECEIPT_RESULT,
  OPERATION,
  RESULT_SIGNATURE_DOMAIN_ID
} from '@hiverelay/blind-protocol/wire-runtime-authority'
import {
  batchGetResultV1,
  blindCoreAckV1,
  blindForwardHopAcceptV1,
  blindForwardOpenResultV1,
  blindReceiptV1,
  coreOpenReplicationResultV1,
  coreServeResultV1,
  getCellResultV1,
  inboxAppendAckV1,
  inboxReadResultV1,
  inboxReceiptV1,
  proveCellResultV1
} from '@hiverelay/blind-protocol/schemas'
import { encodeCanonical } from '@hiverelay/blind-protocol/codec'
import {
  allocationCommitment,
  blake2b256,
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
  inboxWatchRequestCommitment,
  persistentResultCommitment
} from '@hiverelay/blind-protocol/hashes'
import { blindExternalCommitWitnessV1 } from '@hiverelay/blind-protocol/result-binding'
import { asBytes } from './bytes.js'
import { verifiedEndpointContext } from './verified-endpoint.js'
import { fail } from './errors.js'
import {
  decodeCanonicalCopy,
  sameBytes,
  verifyAuxiliarySignedValue,
  verifyResultSignedValue
} from './signed.js'

const VERIFIED_RESULT = Symbol('VerifiedOperationResult')
const resultInternals = new WeakMap()

function key (familyId, operationId) {
  return `${familyId}:${operationId}`
}

function requireSame (actual, expected, field) {
  if (!sameBytes(actual, expected)) fail('RELAY_PROTOCOL_VIOLATION', `${field} does not match the attempted request`)
}

function requestNonce (request) {
  return asBytes(request.clientNonce, 'request clientNonce', 32)
}

const OPTIONAL_EXTERNAL_WITNESS = new Set([
  key(FAMILY.CELL, OPERATION.CELL.PROVE),
  key(FAMILY.CELL, OPERATION.CELL.BATCH_GET),
  key(FAMILY.INBOX, OPERATION.INBOX.READ),
  key(FAMILY.CORE, OPERATION.CORE.PROVE)
])

function requiresExternalWitness (context, request) {
  if (context.durabilityProfileId !== 2) return false
  if (OPTIONAL_EXTERNAL_WITNESS.has(key(context.familyId, context.operationId))) {
    return request != null && request.admission != null
  }
  return true
}

function verifyBinding (binding, context, options, resultCommitment) {
  const scalar = [
    ['descriptorSequence', context.descriptorSequence],
    ['durabilityProfileId', context.durabilityProfileId],
    ['restoreEvidenceHeadSequence', context.restoreEvidenceHeadSequence]
  ]
  for (const [field, expected] of scalar) {
    if (BigInt(binding[field]) !== BigInt(expected)) {
      fail('RELAY_PROTOCOL_VIOLATION', `relay binding ${field} does not match the qualified descriptor`)
    }
  }
  for (const field of [
    'relayPublicKey',
    'storeId',
    'descriptorHash',
    'durabilityContinuityHash',
    'durabilityProfileHash',
    'restoreEvidenceHeadHash'
  ]) {
    if (!sameBytes(binding[field], context[field])) {
      fail('RELAY_PROTOCOL_VIOLATION', `relay binding ${field} does not match the qualified descriptor`)
    }
  }
  const witness = binding.externalCommitWitness
  const required = requiresExternalWitness(context, options.request)
  if (witness == null) {
    if (required) {
      fail('RELAY_PROTOCOL_VIOLATION', 'profile-2 result omitted its external commit witness')
    }
    return
  }
  if (!required) fail('RELAY_PROTOCOL_VIOLATION', 'uncharged result carried an external commit witness')
  if (context.durabilityProfileId !== 2 ||
      !sameBytes(witness.witnessPublicKey, context.externalWitnessPublicKey)) {
    fail('RELAY_PROTOCOL_VIOLATION', 'external commit witness is not bound to the descriptor witness key')
  }
  if (witness.familyId !== context.familyId || witness.operationId !== context.operationId ||
      !sameBytes(witness.requestCommitment, options.requestCommitment) ||
      !sameBytes(witness.externalJournalId, context.externalJournalId) ||
      !sameBytes(witness.resultCommitment, resultCommitment)) {
    fail('RELAY_PROTOCOL_VIOLATION', 'external commit witness does not bind the attempted operation')
  }
  verifyAuxiliarySignedValue(blindExternalCommitWitnessV1, witness,
    AUXILIARY_SIGNATURE_DOMAIN_ID.EXTERNAL_COMMIT_WITNESS,
    context.externalWitnessPublicKey, 'external commit witness')
  if (typeof options.externalWitnessVerifier !== 'function' ||
      options.externalWitnessVerifier(Object.freeze({ witness, context, resultCommitment: b4a.from(resultCommitment) })) !== true) {
    fail('RELAY_PROTOCOL_VIOLATION', 'external commit witness policy verification failed')
  }
}

function signed (encoding, value, domainId, context, label, binding, options) {
  verifyResultSignedValue(encoding, value, domainId, context.relayPublicKey, label)
  if (binding != null) {
    const withoutWitness = encodeCanonical(encoding, {
      ...value,
      relayBinding: { ...binding, externalCommitWitness: null }
    })
    const unsigned = withoutWitness.subarray(0, withoutWitness.byteLength - 64)
    verifyBinding(binding, context, options,
      persistentResultCommitment(context.familyId, context.operationId, unsigned))
  }
}

function verifyNextHopAccept (next, previousContext, request, result, options) {
  const nextContext = verifiedEndpointContext(options.nextHopEndpoint)
  if (nextContext.familyId !== FAMILY.FORWARD || nextContext.operationId !== OPERATION.FORWARD.OPEN) {
    fail('RELAY_PROTOCOL_VIOLATION', 'next-hop endpoint is not qualified for FORWARD.OPEN')
  }
  if (!sameBytes(next.previousRelayKey, previousContext.relayPublicKey) ||
      BigInt(next.previousDescriptorSequence) !== BigInt(previousContext.descriptorSequence) ||
      !sameBytes(next.previousDescriptorHash, previousContext.descriptorHash)) {
    fail('RELAY_PROTOCOL_VIOLATION', 'next-hop accept does not bind the qualified previous relay')
  }
  if (!sameBytes(next.nextRelayKey, nextContext.relayPublicKey) ||
      BigInt(next.nextDescriptorSequence) !== BigInt(nextContext.descriptorSequence) ||
      !sameBytes(next.nextDescriptorHash, nextContext.descriptorHash)) {
    fail('RELAY_PROTOCOL_VIOLATION', 'next-hop accept does not bind the qualified next relay')
  }
  verifyAuxiliarySignedValue(blindForwardHopAcceptV1, next,
    AUXILIARY_SIGNATURE_DOMAIN_ID.FORWARD_HOP_ACCEPT,
    nextContext.relayPublicKey, 'forward next-hop accept', 64, next.nextSignature)
  const absent = encodeCanonical(blindForwardHopAcceptV1, {
    ...next,
    nextRelayBinding: { ...next.nextRelayBinding, externalCommitWitness: null }
  })
  verifyBinding(next.nextRelayBinding, nextContext, {
    request,
    requestCommitment: next.hopOpenCommitment,
    externalWitnessVerifier: options.nextExternalWitnessVerifier
  }, persistentResultCommitment(FAMILY.FORWARD, OPERATION.FORWARD.OPEN,
    absent.subarray(0, absent.byteLength - 64)))
  if (typeof options.nextHopVerifier !== 'function' ||
      options.nextHopVerifier(Object.freeze({
        request,
        result,
        nextHopAccept: next,
        nextHopEndpoint: options.nextHopEndpoint
      })) !== true) {
    fail('RELAY_PROTOCOL_VIOLATION', 'forward next-hop descriptor/route verification failed')
  }
}

function commonCorrelation (value, request, requestCommitment) {
  requireSame(value.requestNonce, requestNonce(request), 'result requestNonce')
  requireSame(value.requestCommitment, requestCommitment, 'result requestCommitment')
}

function putAllocationCommitment (context, request) {
  return allocationCommitment({
    relayPublicKey: context.relayPublicKey,
    storageSlot: request.storageSlot,
    allocationEpoch: request.allocationEpoch,
    sizeClass: request.sizeClass,
    leaseClass: request.leaseClass,
    declaredCellBlobHash: request.declaredBlobHash,
    createPublicKey: request.createPublicKey,
    renewPublicKey: request.renewPublicKey,
    dropPublicKey: request.dropPublicKey
  })
}

function recomputeRequestCommitment (context, request) {
  const relayPublicKey = context.relayPublicKey
  switch (key(context.familyId, context.operationId)) {
    case key(FAMILY.CELL, OPERATION.CELL.PUT): {
      const allocation = putAllocationCommitment(context, request)
      return cellPutRequestCommitment({ allocationCommitment: allocation, clientNonce: request.clientNonce })
    }
    case key(FAMILY.CELL, OPERATION.CELL.GET):
      return cellGetRequestCommitment({ relayPublicKey, storageSlot: request.storageSlot, clientNonce: request.clientNonce })
    case key(FAMILY.CELL, OPERATION.CELL.RENEW):
      return cellManageRequestCommitment({
        operation: 'cell-renew',
        relayPublicKey,
        storageSlot: request.storageSlot,
        expectedRevision: request.expectedRevision,
        expectedLeaseEpoch: request.expectedLeaseEpoch,
        requestedLeaseClass: request.leaseClass,
        clientNonce: request.clientNonce
      })
    case key(FAMILY.CELL, OPERATION.CELL.DROP):
      return cellManageRequestCommitment({
        operation: 'cell-drop',
        relayPublicKey,
        storageSlot: request.storageSlot,
        expectedRevision: request.expectedRevision,
        expectedLeaseEpoch: request.expectedLeaseEpoch,
        requestedLeaseClass: 0,
        clientNonce: request.clientNonce
      })
    case key(FAMILY.CELL, OPERATION.CELL.PROVE):
      return cellProveRequestCommitment({ relayPublicKey, storageSlot: request.storageSlot, clientNonce: request.clientNonce })
    case key(FAMILY.CELL, OPERATION.CELL.BATCH_GET):
      return cellBatchGetRequestCommitment({ relayPublicKey, slots: request.slots, clientNonce: request.clientNonce })
    case key(FAMILY.INBOX, OPERATION.INBOX.CREATE): {
      const create = inboxCreateCommitment({ ...request, relayPublicKey })
      return inboxCreateRequestCommitment({ inboxCreateCommitment: create, clientNonce: request.clientNonce })
    }
    case key(FAMILY.INBOX, OPERATION.INBOX.RENEW):
    case key(FAMILY.INBOX, OPERATION.INBOX.CLOSE):
      return inboxManageRequestCommitment({
        operation: context.operationId === OPERATION.INBOX.RENEW ? 'inbox-renew' : 'inbox-close',
        relayPublicKey,
        physicalTopic: request.physicalTopic,
        expectedRevision: request.expectedRevision,
        expectedLeaseEpoch: request.expectedLeaseEpoch,
        requestedLeaseClass: request.leaseClass,
        clientNonce: request.clientNonce
      })
    case key(FAMILY.INBOX, OPERATION.INBOX.APPEND):
      return inboxAppendRequestCommitment({
        relayPublicKey,
        physicalTopic: request.physicalTopic,
        frameClass: request.frameClass,
        frameHash: request.frameHash,
        clientNonce: request.clientNonce
      })
    case key(FAMILY.INBOX, OPERATION.INBOX.READ):
      return inboxReadRequestCommitment({
        relayPublicKey,
        physicalTopic: request.physicalTopic,
        cursor: request.cursor,
        limit: request.limit,
        clientNonce: request.clientNonce
      })
    case key(FAMILY.INBOX, OPERATION.INBOX.WATCH):
      return inboxWatchRequestCommitment({
        relayPublicKey,
        physicalTopic: request.physicalTopic,
        afterRevision: request.afterRevision,
        limit: request.limit,
        maxWaitMillis: request.maxWaitMillis,
        clientNonce: request.clientNonce
      })
    case key(FAMILY.CORE, OPERATION.CORE.MIRROR):
      return coreMirrorRequestCommitment({ ...request, relayPublicKey })
    case key(FAMILY.CORE, OPERATION.CORE.PROVE):
      return coreServeRequestCommitment({ ...request, relayPublicKey })
    case key(FAMILY.CORE, OPERATION.CORE.OPEN_REPLICATION):
      return coreOpenReplicationRequestCommitment({ ...request, relayPublicKey })
    case key(FAMILY.FORWARD, OPERATION.FORWARD.OPEN):
      return forwardOpenRequestCommitment({ ...request, previousRelayKey: relayPublicKey })
    default:
      fail('BAD_CLIENT_INPUT', 'operation has no closed request commitment verifier')
  }
}

const RESULT_TABLE = new Map([
  [key(FAMILY.CELL, OPERATION.CELL.PUT), {
    encoding: blindReceiptV1,
    verify (value, request, commitment, context, options) {
      signed(blindReceiptV1, value, RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT,
        context, 'cell PUT receipt', value.relayBinding, options)
      commonCorrelation(value, request, commitment)
      requireSame(value.slotCommitment, blake2b256(request.storageSlot), 'cell receipt slotCommitment')
      requireSame(value.cellBlobHash, request.declaredBlobHash, 'cell receipt cellBlobHash')
      requireSame(value.allocationCommitment, putAllocationCommitment(context, request),
        'cell receipt allocationCommitment')
      if (value.sizeClass !== request.sizeClass || value.allocationEpoch !== request.allocationEpoch ||
          value.leaseClass !== request.leaseClass || BigInt(value.stateRevision) !== 0n ||
          value.result !== CELL_RECEIPT_RESULT.STORED) {
        fail('RELAY_PROTOCOL_VIOLATION', 'cell PUT receipt shape does not match the request')
      }
    }
  }],
  [key(FAMILY.CELL, OPERATION.CELL.GET), {
    encoding: getCellResultV1,
    verify () {}
  }],
  [key(FAMILY.CELL, OPERATION.CELL.RENEW), {
    encoding: blindReceiptV1,
    verify (value, request, commitment, context, options) {
      signed(blindReceiptV1, value, RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT,
        context, 'cell RENEW receipt', value.relayBinding, options)
      commonCorrelation(value, request, commitment)
      requireSame(value.slotCommitment, blake2b256(request.storageSlot), 'cell receipt slotCommitment')
      if (value.result !== CELL_RECEIPT_RESULT.RENEWED || value.leaseClass !== request.leaseClass ||
          BigInt(value.stateRevision) !== BigInt(request.expectedRevision) + 1n ||
          value.leaseEpoch <= request.expectedLeaseEpoch) {
        fail('RELAY_PROTOCOL_VIOLATION', 'cell RENEW receipt shape does not match the request')
      }
    }
  }],
  [key(FAMILY.CELL, OPERATION.CELL.DROP), {
    encoding: blindReceiptV1,
    verify (value, request, commitment, context, options) {
      signed(blindReceiptV1, value, RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT,
        context, 'cell DROP receipt', value.relayBinding, options)
      commonCorrelation(value, request, commitment)
      requireSame(value.slotCommitment, blake2b256(request.storageSlot), 'cell receipt slotCommitment')
      if (value.result !== CELL_RECEIPT_RESULT.DROPPED || value.leaseClass !== 0 ||
          BigInt(value.stateRevision) !== BigInt(request.expectedRevision) + 1n) {
        fail('RELAY_PROTOCOL_VIOLATION', 'cell DROP receipt shape does not match the request')
      }
    }
  }],
  [key(FAMILY.CELL, OPERATION.CELL.PROVE), {
    encoding: proveCellResultV1,
    verify (value, request, commitment, context, options) {
      signed(blindReceiptV1, value.receipt, RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT,
        context, 'cell PROVE receipt', value.receipt.relayBinding, options)
      commonCorrelation(value.receipt, request, commitment)
      requireSame(value.receipt.slotCommitment, blake2b256(request.storageSlot), 'cell proof slotCommitment')
    }
  }],
  [key(FAMILY.CELL, OPERATION.CELL.BATCH_GET), {
    encoding: batchGetResultV1,
    verify (value, request, commitment, context, options) {
      signed(batchGetResultV1, value, RESULT_SIGNATURE_DOMAIN_ID.BATCH_GET_RESULT,
        context, 'batch GET result', value.relayBinding, options)
      commonCorrelation(value, request, commitment)
      if (value.entries.length !== request.slots.length) {
        fail('RELAY_PROTOCOL_VIOLATION', 'batch GET result count does not match request slots')
      }
    }
  }],
  [key(FAMILY.INBOX, OPERATION.INBOX.CREATE), inboxReceiptVerifier(INBOX_RECEIPT_RESULT.CREATED)],
  [key(FAMILY.INBOX, OPERATION.INBOX.RENEW), inboxReceiptVerifier(INBOX_RECEIPT_RESULT.RENEWED)],
  [key(FAMILY.INBOX, OPERATION.INBOX.CLOSE), inboxReceiptVerifier(INBOX_RECEIPT_RESULT.CLOSED)],
  [key(FAMILY.INBOX, OPERATION.INBOX.APPEND), {
    encoding: inboxAppendAckV1,
    verify (value, request, commitment, context, options) {
      signed(inboxAppendAckV1, value, RESULT_SIGNATURE_DOMAIN_ID.INBOX_APPEND_ACK,
        context, 'inbox APPEND acknowledgement', value.relayBinding, options)
      commonCorrelation(value, request, commitment)
      requireSame(value.topicCommitment, blake2b256(request.physicalTopic), 'inbox topicCommitment')
      requireSame(value.frameHash, request.frameHash, 'inbox frameHash')
      if (value.result !== INBOX_APPEND_RESULT.STORED) fail('RELAY_PROTOCOL_VIOLATION', 'inbox append was not stored')
    }
  }],
  [key(FAMILY.INBOX, OPERATION.INBOX.READ), inboxReadVerifier()],
  [key(FAMILY.INBOX, OPERATION.INBOX.WATCH), inboxReadVerifier()],
  [key(FAMILY.CORE, OPERATION.CORE.MIRROR), coreAckVerifier(CORE_ACK_RESULT.MIRROR_ACCEPTED)],
  [key(FAMILY.CORE, OPERATION.CORE.PROVE), {
    encoding: coreServeResultV1,
    verify (value, request, commitment, context, options) {
      const ack = value.acknowledgement
      signed(blindCoreAckV1, ack, RESULT_SIGNATURE_DOMAIN_ID.CORE_ACK,
        context, 'core PROVE acknowledgement', ack.relayBinding, options)
      commonCorrelation(ack, request, commitment)
      coreHeadCorrelation(ack, request)
      if (ack.result !== CORE_ACK_RESULT.RECENTLY_SERVED || typeof options.coreProofVerifier !== 'function' ||
          options.coreProofVerifier(Object.freeze({ request, acknowledgement: ack, proofsAndBlocks: value.proofsAndBlocks })) !== true) {
        fail('RELAY_PROTOCOL_VIOLATION', 'core proof verification failed')
      }
    }
  }],
  [key(FAMILY.CORE, OPERATION.CORE.OPEN_REPLICATION), {
    encoding: coreOpenReplicationResultV1,
    verify (value, request, commitment, context, options) {
      signed(coreOpenReplicationResultV1, value, RESULT_SIGNATURE_DOMAIN_ID.CORE_OPEN_RESULT,
        context, 'core OPEN result', value.relayBinding, options)
      commonCorrelation(value, request, commitment)
      for (const field of ['wireProfileHash', 'parentChannelBinding']) requireSame(value[field], request[field], `core OPEN ${field}`)
      if (value.sessionClass !== request.sessionClass || BigInt(value.controlChannelId) !== BigInt(request.controlChannelId)) {
        fail('RELAY_PROTOCOL_VIOLATION', 'core OPEN result changed the requested session tuple')
      }
    }
  }],
  [key(FAMILY.FORWARD, OPERATION.FORWARD.OPEN), {
    encoding: blindForwardOpenResultV1,
    verify (value, request, commitment, context, options) {
      signed(blindForwardOpenResultV1, value, RESULT_SIGNATURE_DOMAIN_ID.FORWARD_OPEN_RESULT,
        context, 'forward OPEN result', value.relayBinding, options)
      requireSame(value.requestCommitment, commitment, 'forward OPEN requestCommitment')
      for (const field of ['routeId', 'nextDescriptorHash', 'circuitNonce']) requireSame(value[field], request[field], `forward OPEN ${field}`)
      if (BigInt(value.nextDescriptorSequence) !== BigInt(request.nextDescriptorSequence) ||
          value.grantedWireClass !== request.requestedWireClass || value.circuitClass !== request.circuitClass) {
        fail('RELAY_PROTOCOL_VIOLATION', 'forward OPEN result changed the requested route tuple')
      }
      const next = value.nextHopAccept
      verifyNextHopAccept(next, context, request, value, options)
    }
  }]
])

function inboxReceiptVerifier (expectedResult) {
  return {
    encoding: inboxReceiptV1,
    verify (value, request, commitment, context, options) {
      signed(inboxReceiptV1, value, RESULT_SIGNATURE_DOMAIN_ID.INBOX_RECEIPT,
        context, 'inbox management receipt', value.relayBinding, options)
      commonCorrelation(value, request, commitment)
      requireSame(value.topicCommitment, blake2b256(request.physicalTopic), 'inbox topicCommitment')
      const expectedRevision = expectedResult === INBOX_RECEIPT_RESULT.CREATED
        ? 0n
        : BigInt(request.expectedRevision) + 1n
      if (value.result !== expectedResult || BigInt(value.stateRevision) !== expectedRevision ||
          value.leaseClass !== request.leaseClass) {
        fail('RELAY_PROTOCOL_VIOLATION', 'inbox receipt result does not match operation')
      }
    }
  }
}

function inboxReadVerifier () {
  return {
    encoding: inboxReadResultV1,
    verify (value, request, commitment, context, options) {
      signed(inboxReadResultV1, value, RESULT_SIGNATURE_DOMAIN_ID.INBOX_READ_RESULT,
        context, 'inbox read result', value.relayBinding, options)
      commonCorrelation(value, request, commitment)
    }
  }
}

function coreHeadCorrelation (value, request) {
  for (const field of ['corePublicKey', 'signedHeadHash']) requireSame(value[field], request[field], `core result ${field}`)
  if (BigInt(value.fork) !== BigInt(request.fork) || BigInt(value.length) !== BigInt(request.length)) {
    fail('RELAY_PROTOCOL_VIOLATION', 'core result head does not match request')
  }
}

function coreAckVerifier (expectedResult) {
  return {
    encoding: blindCoreAckV1,
    verify (value, request, commitment, context, options) {
      signed(blindCoreAckV1, value, RESULT_SIGNATURE_DOMAIN_ID.CORE_ACK,
        context, 'core acknowledgement', value.relayBinding, options)
      commonCorrelation(value, request, commitment)
      coreHeadCorrelation(value, request)
      if (value.result !== expectedResult) fail('RELAY_PROTOCOL_VIOLATION', 'core acknowledgement result does not match operation')
    }
  }
}

export class VerifiedOperationResult {
  constructor (token, fields) {
    if (token !== VERIFIED_RESULT) throw new TypeError('VerifiedOperationResult is not directly constructible')
    resultInternals.set(this, fields)
    Object.freeze(this)
  }

  get familyId () { return resultInternals.get(this).context.familyId }
  get operationId () { return resultInternals.get(this).context.operationId }
  snapshotBytes () { return b4a.from(resultInternals.get(this).bytes) }
}

export function verifyOperationResult (options) {
  if (!options || typeof options !== 'object') fail('BAD_CLIENT_INPUT', 'operation result verification options are required')
  const context = verifiedEndpointContext(options.endpoint)
  const entry = RESULT_TABLE.get(key(context.familyId, context.operationId))
  if (!entry) fail('BAD_CLIENT_INPUT', 'qualified endpoint has no closed result verifier')
  const requestCommitment = b4a.from(asBytes(options.requestCommitment, 'requestCommitment', 32))
  let recomputed
  try {
    recomputed = recomputeRequestCommitment(context, options.request)
  } catch (error) {
    if (error && error.code === 'BAD_CLIENT_INPUT') throw error
    fail('BAD_CLIENT_INPUT', 'request cannot reproduce its frozen commitment', { cause: error })
  }
  if (!sameBytes(requestCommitment, recomputed)) {
    fail('BAD_CLIENT_INPUT', 'requestCommitment does not match the canonical attempted request')
  }
  const decoded = decodeCanonicalCopy(entry.encoding, options.resultBytes, 'operation result')
  entry.verify(decoded.value, options.request, requestCommitment, context, {
    ...options,
    requestCommitment
  })
  return new VerifiedOperationResult(VERIFIED_RESULT, {
    bytes: decoded.bytes,
    value: decoded.value,
    context
  })
}

export const RESULT_VERIFIER_STATUS = Object.freeze({
  expectedOperationCount: 19,
  implementedOperationCount: RESULT_TABLE.size,
  missingStreamingOperations: Object.freeze([
    key(FAMILY.FORWARD, OPERATION.FORWARD.DATA),
    key(FAMILY.FORWARD, OPERATION.FORWARD.WINDOW),
    key(FAMILY.FORWARD, OPERATION.FORWARD.CLOSE)
  ]),
  completeForUnaryAndOpen: RESULT_TABLE.size === 19
})
