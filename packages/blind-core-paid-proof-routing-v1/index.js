import b4a from 'b4a'
import {
  FAMILY, OPERATION, coreServeChallengeV1, coreServeRequestCommitment,
  decodeCanonical, encodeCanonical
} from '../blind-protocol/index.js'
import { BlindCoreStorageEngine } from '../blind-daemon/core-storage-engine-checkpoint-v1.js'
import { BlindCoreRuntimeAdapter } from '../blind-daemon/core-runtime-adapter.js'

const MAX_PROOF_BYTES = 4 * 1024 * 1024 - 256
const same = (a, b) => Boolean(a && b && a.byteLength === b.byteLength && b4a.equals(a, b))
const hex = value => b4a.toString(value, 'hex')
function fail (code, message) { const error = new Error(message); error.code = code; throw error }
function checkSignal (signal) { if (signal?.aborted) fail('CORE_ABORTED', 'CORE proof operation cancelled') }
function owned (value) { return value == null ? value : b4a.from(value) }
function requestCopy (request) {
  return decodeCanonical(coreServeChallengeV1, encodeCanonical(coreServeChallengeV1, request), { copyBytes: true })
}
function capture (input) {
  if (!input || input.profile?.familyId !== FAMILY.CORE || input.profile.operationId !== OPERATION.CORE.PROVE) {
    fail('INTERNAL', 'private paid-proof route requires CORE.PROVE')
  }
  checkSignal(input.signal)
  const prepared = input.preparedAdmission
  return {
    ...input,
    profile: { ...input.profile },
    request: requestCopy(input.request),
    requestCommitment: owned(input.requestCommitment),
    authenticatedState: input.authenticatedState == null ? null : { ...input.authenticatedState },
    preparedAdmission: prepared == null
      ? null
      : {
          ...prepared,
          spendTag: owned(prepared.spendTag),
          requestCommitment: owned(prepared.requestCommitment),
          parameterHash: owned(prepared.parameterHash),
          walCommitRecord: owned(prepared.walCommitRecord),
          costClass: prepared.costClass == null ? null : { ...prepared.costClass }
        }
  }
}
function lengthPrefix (length) { return length <= 0xfc ? 1 : length <= 0xffff ? 3 : 5 }
function sizeView (pin) {
  if (!Number.isSafeInteger(pin.proofByteLength) || pin.proofByteLength < 1 || pin.proofByteLength > MAX_PROOF_BYTES) {
    fail('INTERNAL', 'committed proof size is outside the result bound')
  }
  const resultBytes = 1 + pin.acknowledgementBytes.byteLength + lengthPrefix(pin.proofByteLength) + pin.proofByteLength
  return Object.freeze({ coreProofBytes: pin.proofByteLength, canonicalResultBytes: resultBytes, predictedResultBodyBytes: resultBytes })
}

// This is a source-only subclass of the exact accepted checkpoint engine. The
// parent still owns every WAL write, pin, corpus read, durability and replay check.
export class BlindCorePaidProofStorageV1 extends BlindCoreStorageEngine {
  #request (input) {
    if (!this.opened) fail('INTERNAL', 'CORE storage engine is not open')
    const request = requestCopy(input.request)
    const commitment = coreServeRequestCommitment({ ...request, relayPublicKey: this.relayPublicKey })
    if (!same(commitment, input.requestCommitment)) fail('INTERNAL', 'CORE proof request commitment mismatch')
    return { request, commitment, bytes: encodeCanonical(coreServeChallengeV1, request) }
  }

  // Used before admission.prepare: bounded metadata only. The commitment does
  // not include admission, so compare full canonical bytes, including the token.
  inspectPaidProofRequest (raw) {
    const input = capture(raw)
    const authority = this.#request(input)
    if (authority.request.admission == null) return null
    if (this.proofPins.size > this.maximumProofPins) fail('INTERNAL', 'CORE proof pin bound was exceeded')
    for (const pin of this.proofPins.values()) {
      if (!same(pin.requestCommitment, authority.commitment) ||
          !same(encodeCanonical(coreServeChallengeV1, pin.request), authority.bytes)) continue
      if (pin.expiresAtUnixMillis <= BigInt(this.nowUnixMillis())) fail('RETRY_TERMINAL', 'CORE proof retry has expired')
      return sizeView(pin)
    }
    return null
  }

  async inspectPreparedProofRetry (raw) {
    const input = capture(raw)
    const authority = this.#request(input)
    if (input.preparedAdmission == null) return null
    if (authority.request.admission == null) fail('SPEND_INVALID', 'paid CORE proof requires its request admission')
    const ticket = authority.request.admission
    const prepared = input.preparedAdmission
    if (prepared.profileId !== ticket.profileId || prepared.schemeId !== ticket.schemeId ||
        !same(prepared.parameterHash, ticket.parameterHash)) {
      fail('SPEND_INVALID', 'prepared CORE proof admission profile does not match its request')
    }
    const state = await super.proveState(input)
    checkSignal(input.signal)
    if (!this.opened) fail('INTERNAL', 'CORE storage engine closed during proof lookup')
    if (state.kind === 'conflict') fail('SPEND_REPLAY', 'CORE proof spend belongs to another operation or request')
    if (state.kind === 'terminal') fail('RETRY_TERMINAL', 'CORE proof retry is terminal')
    if (state.kind === 'fresh') return null
    const pin = this.proofPins.get(hex(input.preparedAdmission.spendTag))
    if (!pin) fail('RETRY_TERMINAL', 'CORE proof retry pin was retired')
    if (!same(pin.requestCommitment, authority.commitment) ||
        !same(encodeCanonical(coreServeChallengeV1, pin.request), authority.bytes)) {
      fail('SPEND_REPLAY', 'CORE proof retry does not match its complete admitted request')
    }
    if (pin.expiresAtUnixMillis <= BigInt(this.nowUnixMillis())) fail('RETRY_TERMINAL', 'CORE proof retry has expired')
    return sizeView(pin)
  }

  async serveProof (raw) {
    const input = capture(raw)
    // Recheck after runtime sizing/coalescing and before the parent can read a
    // retired body. The parent then locks and revalidates expiry/hash/fences.
    await this.inspectPreparedProofRetry(input)
    checkSignal(input.signal)
    return super.serveProof(input)
  }
}

export class BlindCorePaidProofRuntimeV1 extends BlindCoreRuntimeAdapter {
  constructor (options) {
    if (!(options?.storage instanceof BlindCorePaidProofStorageV1)) {
      throw new TypeError('private paid-proof storage successor is required')
    }
    super(options)
  }

  status () {
    return Object.freeze({ ...super.status(), paidProofRoutingProfile: 'hiverelay.private.core-paid-proof-routing.v1', paidProofRetryAfterHeadAdvance: true, productionReady: false, defaultSelected: false })
  }

  async inspectCheapState (raw) {
    if (raw?.profile?.operationId !== OPERATION.CORE.PROVE) return super.inspectCheapState(raw)
    const input = capture(raw)
    const retained = this.storage.inspectPaidProofRequest(input)
    return retained || super.inspectCheapState(input)
  }

  async execute (raw) {
    if (raw?.profile?.operationId !== OPERATION.CORE.PROVE) return super.execute(raw)
    const input = capture(raw)
    const retained = await this.storage.inspectPreparedProofRetry(input)
    checkSignal(input.signal)
    if (retained) {
      for (const field of ['coreProofBytes', 'canonicalResultBytes', 'predictedResultBodyBytes']) {
        const reserved = input.authenticatedState?.[field]
        if (reserved != null && reserved !== retained[field]) {
          fail('INTERNAL', 'reserved CORE proof size disagrees with the committed retry: ' + field)
        }
      }
      input.authenticatedState = { ...input.authenticatedState, ...retained }
    } else {
      this.storage.inspectProofSource(input.request)
    }
    // Retain the original committed-result WeakSet and storage-owned replay.
    // Fresh requests keep the original active-source and exact-size checks.
    const result = await super.execute(input)
    checkSignal(input.signal)
    return result
  }
}
