import b4a from 'b4a'
import {
  FAMILY,
  OPERATION
} from '@hiverelay/blind-protocol/wire-runtime-authority'
import {
  batchGetV1,
  blindAdmissionParametersRequestV1,
  blindDescribeGetV1,
  blindHealthChallengeV1,
  coreMirrorRequestV1,
  coreServeChallengeV1,
  dropCellV1,
  getCellV1,
  inboxAppendV1,
  inboxCreateV1,
  inboxManageV1,
  inboxReadV1,
  inboxWatchV1,
  proveCellV1,
  putCellV1,
  renewCellV1
} from '@hiverelay/blind-protocol/schemas'
import { decodeCanonical } from '@hiverelay/blind-protocol/codec'
import { asBytes } from './bytes.js'
import { verifiedEndpointContext } from './verified-endpoint.js'
import { fail } from './errors.js'
import { INTENT_STATE } from './intent.js'
import { verifyOperationResult } from './results.js'
import { selectedOperationProfile } from './selected-operation-profile.js'

function pair (familyId, operationId) {
  return `${familyId}:${operationId}`
}

const requestCodecByPair = new Map([
  [pair(FAMILY.DESCRIBE, OPERATION.DESCRIBE.GET), blindDescribeGetV1],
  [pair(FAMILY.DESCRIBE, OPERATION.DESCRIBE.CHALLENGE), blindHealthChallengeV1],
  [pair(FAMILY.DESCRIBE, OPERATION.DESCRIBE.ADMISSION_PARAMETERS), blindAdmissionParametersRequestV1],
  [pair(FAMILY.CELL, OPERATION.CELL.PUT), putCellV1],
  [pair(FAMILY.CELL, OPERATION.CELL.GET), getCellV1],
  [pair(FAMILY.CELL, OPERATION.CELL.RENEW), renewCellV1],
  [pair(FAMILY.CELL, OPERATION.CELL.DROP), dropCellV1],
  [pair(FAMILY.CELL, OPERATION.CELL.PROVE), proveCellV1],
  [pair(FAMILY.CELL, OPERATION.CELL.BATCH_GET), batchGetV1],
  [pair(FAMILY.INBOX, OPERATION.INBOX.CREATE), inboxCreateV1],
  [pair(FAMILY.INBOX, OPERATION.INBOX.RENEW), inboxManageV1],
  [pair(FAMILY.INBOX, OPERATION.INBOX.CLOSE), inboxManageV1],
  [pair(FAMILY.INBOX, OPERATION.INBOX.APPEND), inboxAppendV1],
  [pair(FAMILY.INBOX, OPERATION.INBOX.READ), inboxReadV1],
  [pair(FAMILY.INBOX, OPERATION.INBOX.WATCH), inboxWatchV1],
  [pair(FAMILY.CORE, OPERATION.CORE.MIRROR), coreMirrorRequestV1],
  [pair(FAMILY.CORE, OPERATION.CORE.PROVE), coreServeChallengeV1]
])

function requestCodec (familyId, operationId) {
  const key = pair(familyId, operationId)
  const codec = requestCodecByPair.get(key)
  if (!codec) fail('BAD_CLIENT_INPUT', 'intent operation has no closed request codec')
  return codec
}

function same (left, right) {
  return left.byteLength === right.byteLength && b4a.equals(left, right)
}

function assertDestination (intent, context) {
  for (const field of ['continuityRoot', 'storeId', 'descriptorHash']) {
    if (!same(intent[field], context[field])) fail('INTENT_DESTINATION_DRIFT', `${field} changed after intent journaling`)
  }
  for (const field of [
    'descriptorSequence', 'endpointId', 'transportId', 'transportSupportBit', 'privacyProfileBit', 'familyId', 'operationId'
  ]) {
    if (BigInt(intent[field]) !== BigInt(context[field])) fail('INTENT_DESTINATION_DRIFT', `${field} changed after intent journaling`)
  }
}

function decodeRequest (intent) {
  try {
    return decodeCanonical(requestCodec(intent.familyId, intent.operationId), intent.operationBytes, { copyBytes: true })
  } catch (error) {
    fail('INTENT_CORRUPT', 'journaled operation bytes are not canonical for their frozen operation', { cause: error })
  }
}

async function setState (store, intentId, state, fields = {}) {
  return store.update(intentId, value => ({ ...value, ...fields, state }))
}

function pendingUnknownFailure (error) {
  if (error != null && (typeof error === 'object' || typeof error === 'function')) {
    try {
      error.intentState = INTENT_STATE.PENDING_UNKNOWN
      if (error.intentState === INTENT_STATE.PENDING_UNKNOWN) return error
    } catch {}
  }
  const wrapped = new Error(error instanceof Error ? error.message : 'durable attempt outcome is unknown', { cause: error })
  if (error && typeof error.name === 'string') wrapped.name = error.name
  if (error && typeof error.code === 'string') wrapped.code = error.code
  wrapped.intentState = INTENT_STATE.PENDING_UNKNOWN
  return wrapped
}

export class DurableAttempt {
  constructor (options) {
    if (!options || !options.store || !options.transport || typeof options.transport.request !== 'function') {
      fail('BAD_CLIENT_INPUT', 'DurableAttempt requires an encrypted intent store and transport')
    }
    this.store = options.store
    this.transport = options.transport
  }

  async execute (options) {
    if (!options || !options.intentId || !options.endpoint) {
      fail('BAD_CLIENT_INPUT', 'attempt intentId and VerifiedEndpoint are required')
    }
    const intentId = b4a.from(asBytes(options.intentId, 'intentId', 32))
    const context = verifiedEndpointContext(options.endpoint)
    let record = await this.store.read(intentId)
    if (record == null) fail('INTENT_NOT_FOUND', 'intent does not exist')
    const profile = selectedOperationProfile(record.value.familyId, record.value.operationId)
    assertDestination(record.value, context)
    const request = decodeRequest(record.value)
    if (!same(asBytes(request.clientNonce, 'request clientNonce', 32), record.value.clientNonce)) {
      fail('INTENT_CORRUPT', 'journaled client nonce does not match operation bytes')
    }

    if (record.value.state === INTENT_STATE.RESULT_VERIFIED) {
      const verifiedResult = verifyOperationResult({
        ...options,
        endpoint: options.endpoint,
        request,
        requestCommitment: record.value.requestCommitment,
        resultBytes: record.value.resultBytes
      })
      return Object.freeze({ intent: record.value, verifiedResult, replayed: true })
    }
    if (record.value.state === INTENT_STATE.TERMINAL) {
      fail('INTENT_TERMINAL', 'terminal intent cannot be attempted')
    }
    if (record.value.state === INTENT_STATE.SENT || record.value.state === INTENT_STATE.ACKNOWLEDGED) {
      record = await setState(this.store, intentId, INTENT_STATE.PENDING_UNKNOWN, { mayHaveCommitted: true })
    }
    if (record.value.state === INTENT_STATE.JOURNALED || record.value.state === INTENT_STATE.RETRYABLE ||
        record.value.state === INTENT_STATE.PENDING_UNKNOWN) {
      record = await setState(this.store, intentId, INTENT_STATE.TARGET_PREPARED)
    }
    if (record.value.state !== INTENT_STATE.TARGET_PREPARED) {
      fail('INTENT_TRANSITION_INVALID', 'intent is not sendable from its persisted state')
    }

    record = await setState(this.store, intentId, INTENT_STATE.SENT, {
      mayHaveCommitted: true,
      attemptCount: record.value.attemptCount + 1,
      lastErrorCode: 0
    })
    let response
    try {
      response = await this.transport.request({
        endpoint: options.endpoint,
        familyId: record.value.familyId,
        operationId: record.value.operationId,
        expectedResultBodyBytes: profile.maxResultBodyBytes,
        body: b4a.from(record.value.operationBytes),
        signal: options.signal,
        timeoutMillis: options.timeoutMillis
      })
    } catch (error) {
      await setState(this.store, intentId, INTENT_STATE.PENDING_UNKNOWN, { mayHaveCommitted: true })
      throw pendingUnknownFailure(error)
    }

    if (!response || response.ok !== true) {
      const remote = response && response.error
      const retryable = remote && remote.retryable === 1
      const state = retryable ? INTENT_STATE.RETRYABLE : INTENT_STATE.TERMINAL
      const updated = await setState(this.store, intentId, state, {
        mayHaveCommitted: true,
        lastErrorCode: remote && Number.isSafeInteger(remote.code) ? remote.code : 0
      })
      return Object.freeze({ intent: updated.value, remoteError: remote || null, verifiedResult: null, replayed: false })
    }

    let verifiedResult
    try {
      verifiedResult = verifyOperationResult({
        ...options,
        endpoint: options.endpoint,
        request,
        requestCommitment: record.value.requestCommitment,
        resultBytes: response.body
      })
    } catch (error) {
      await setState(this.store, intentId, INTENT_STATE.PENDING_UNKNOWN, { mayHaveCommitted: true })
      throw pendingUnknownFailure(error)
    }
    const completed = await setState(this.store, intentId, INTENT_STATE.RESULT_VERIFIED, {
      mayHaveCommitted: true,
      resultBytes: verifiedResult.snapshotBytes(),
      lastErrorCode: 0
    })
    return Object.freeze({ intent: completed.value, verifiedResult, replayed: false })
  }
}
