import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  CORE_ACK_RESULT,
  FAMILY,
  OPERATION,
  RESULT_SIGNATURE_DOMAIN_ID,
  blindCoreAckV1,
  coreServeResultV1,
  decodeCanonical,
  encodeCanonical,
  relayResultBindingV1,
  resultSignaturePayload
} from '@hiverelay/blind-protocol'

const SIGNATURE_BYTES = sodium.crypto_sign_BYTES
const MAX_PROOF_BYTES = 4 * 1024 * 1024 - 256

export const BLIND_CORE_RUNTIME_BLOCKERS = Object.freeze([
  'PINNED_BLIND_PEER_HYPERCORE_INTEROP_UNPROVEN',
  'CORE_UPSTREAM_SIGNED_HEAD_PROOF_AUTHORITY_UNASSEMBLED',
  'CORE_NATIVE_CHILD_PRIVATE_IPC_HANDOFF_UNASSEMBLED',
  'CORE_ALL_FAMILY_CHECKPOINT_COMPOSITION_UNASSEMBLED'
])

export const BLIND_CORE_RUNTIME_STATUS = Object.freeze({
  family: 'CORE',
  operations: Object.freeze(['MIRROR', 'PROVE', 'OPEN_REPLICATION']),
  mirrorAdmissionBeforeActivation: true,
  deterministicMirrorResultReplay: true,
  deterministicProofRetrySourcePin: true,
  immutableEncryptedCorpusBoundary: true,
  openReplicationStreamEngineComposed: true,
  openReplicationCoordinatorHandoffComplete: false,
  admissionWalCommitRecordPersisted: true,
  productionReady: false,
  blockers: BLIND_CORE_RUNTIME_BLOCKERS
})

const COMMITTED_CORE_RESULTS = new WeakSet()

function committedCoreResult (body) {
  const value = Object.freeze({ body: b4a.from(body) })
  COMMITTED_CORE_RESULTS.add(value)
  return value
}

export function isCommittedCoreResult (value) {
  return Boolean(value && typeof value === 'object' && COMMITTED_CORE_RESULTS.has(value))
}

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function same (left, right) {
  return Boolean(left && right && left.byteLength === right.byteLength && b4a.equals(left, right))
}

function nonzero (value) {
  if (!value || typeof value.byteLength !== 'number') return false
  for (const byte of value) if (byte !== 0) return true
  return false
}

function coreInput (input) {
  if (!input || !input.profile || input.profile.familyId !== FAMILY.CORE || !input.request) {
    fail('INTERNAL', 'CORE runtime hook received another family or no request')
  }
  return input
}

function isChargedProve (input) {
  return input.profile.operationId === OPERATION.CORE.PROVE && input.request.admission != null
}

function isAdmittedCoreTransaction (input) {
  return input.profile.operationId === OPERATION.CORE.MIRROR ||
    input.profile.operationId === OPERATION.CORE.OPEN_REPLICATION || isChargedProve(input)
}

function signedBytes (codec, value) {
  const complete = encodeCanonical(codec, value)
  if (complete.byteLength <= SIGNATURE_BYTES || !value.signature ||
      value.signature.byteLength !== SIGNATURE_BYTES) {
    fail('INTERNAL', 'signed CORE result has no canonical trailing signature')
  }
  return { complete, unsigned: complete.subarray(0, complete.byteLength - SIGNATURE_BYTES) }
}

async function signValue (signer, codec, value, domainId, publicKey, signal) {
  value.signature = b4a.alloc(SIGNATURE_BYTES)
  const { unsigned } = signedBytes(codec, value)
  value.signature = b4a.from(await signer.sign({
    domainId,
    publicKey: b4a.from(publicKey),
    payload: resultSignaturePayload(domainId, unsigned),
    canonicalUnsignedBytes: b4a.from(unsigned),
    signal
  }))
  if (value.signature.byteLength !== SIGNATURE_BYTES) fail('INTERNAL', 'CORE signer returned an invalid signature')
  return encodeCanonical(codec, value)
}

function verifyAckSignature (ack, publicKey) {
  try {
    const { unsigned } = signedBytes(blindCoreAckV1, ack)
    return sodium.crypto_sign_verify_detached(
      ack.signature,
      resultSignaturePayload(RESULT_SIGNATURE_DOMAIN_ID.CORE_ACK, unsigned),
      publicKey
    )
  } catch {
    return false
  }
}

function compactLengthBytes (value) {
  if (value <= 0xfc) return 1
  if (value <= 0xffff) return 3
  return 5
}

function predictedProofResultBytes (binding, request, proofBytes) {
  const ackBytes = encodeCanonical(blindCoreAckV1, {
    version: 1,
    relayBinding: binding,
    corePublicKey: b4a.from(request.corePublicKey),
    fork: request.fork,
    length: request.length,
    signedHeadHash: b4a.from(request.signedHeadHash),
    observedAtEpoch: 0,
    leaseEpoch: 0,
    result: CORE_ACK_RESULT.RECENTLY_SERVED,
    requestNonce: b4a.from(request.clientNonce),
    requestCommitment: b4a.alloc(32, 1),
    signature: b4a.alloc(64)
  })
  return 1 + ackBytes.byteLength + compactLengthBytes(proofBytes) + proofBytes
}

export class BlindCoreRuntimeAdapter {
  constructor (options = {}) {
    if (!options.storage || typeof options.storage.acceptMirror !== 'function' ||
        typeof options.storage.completeMirror !== 'function' ||
        typeof options.storage.serveProof !== 'function' ||
        typeof options.storage.mirrorState !== 'function' ||
        typeof options.storage.proveState !== 'function' ||
        typeof options.storage.inspectCoreFloor !== 'function' ||
        typeof options.storage.inspectProofSource !== 'function' ||
        typeof options.storage.mirrorBillableBytes !== 'function' ||
        typeof options.storage.mirrorAcceptedBillableLength !== 'function') {
      throw new TypeError('complete BlindCoreStorageEngine authority is required')
    }
    if (!options.descriptorState || typeof options.descriptorState.resultBinding !== 'function') {
      throw new TypeError('descriptorState is required')
    }
    if (!options.signer || typeof options.signer.sign !== 'function') throw new TypeError('CORE signer is required')
    if (!options.upstream || typeof options.upstream.activateMirror !== 'function' ||
        typeof options.upstream.serveProof !== 'function' ||
        typeof options.upstream.estimateProofBytes !== 'function') {
      throw new TypeError('bounded pinned upstream CORE adapter is required')
    }
    if (options.replicationService != null &&
        (typeof options.replicationService.open !== 'function' ||
         typeof options.replicationService.attach !== 'function')) {
      throw new TypeError('replicationService must be a CoreReplicationStreamService')
    }
    this.storage = options.storage
    this.descriptorState = options.descriptorState
    this.signer = options.signer
    this.upstream = options.upstream
    this.replicationService = options.replicationService || null
    this.activationFlights = new Map()
    this.proofFlights = new Map()
    this.maximumFlights = options.maximumFlights == null ? 1024 : options.maximumFlights
    if (!Number.isSafeInteger(this.maximumFlights) || this.maximumFlights < 1 || this.maximumFlights > 65536) {
      throw new TypeError('maximumFlights is outside 1..65536')
    }

    this.relationVerifier = Object.freeze({ verify: input => this.verifyRelation(input) })
    this.capabilityVerifier = Object.freeze({ verify: input => this.verifyCapability(input) })
    this.cheapStateVerifier = Object.freeze({ inspect: input => this.inspectCheapState(input) })
    this.terminalStateVerifier = Object.freeze({ check: input => this.checkTerminalState(input) })
    this.capacityGuard = Object.freeze({ check: input => this.checkCapacity(input) })
    this.operationExecutor = Object.freeze({ execute: input => this.execute(input) })
    this.transactionCoordinator = Object.freeze({
      lookup: input => this.lookupTransaction(input),
      run: (input, execute) => this.runTransaction(input, execute),
      replay: input => this.replayTransaction(input)
    })
    this.resultVerifier = Object.freeze({ verify: input => this.verifyResult(input) })
  }

  status () {
    return BLIND_CORE_RUNTIME_STATUS
  }

  async verifyRelation (raw) {
    const input = coreInput(raw)
    if (input.profile.operationId === OPERATION.CORE.OPEN_REPLICATION) {
      return nonzero(input.request.wireProfileHash) && nonzero(input.request.parentChannelBinding) &&
        input.request.controlChannelId !== 0n
    }
    return nonzero(input.request.corePublicKey) &&
      (input.request.signedHeadHash == null || nonzero(input.request.signedHeadHash))
  }

  async verifyCapability (raw) {
    coreInput(raw)
    return true
  }

  async inspectCheapState (raw) {
    const input = coreInput(raw)
    if (input.profile.operationId === OPERATION.CORE.MIRROR) {
      try {
        return { coreBillableBytes: this.storage.mirrorBillableBytes(input.request) }
      } catch (error) {
        if (!error || error.code !== 'RENEW_NOT_DUE') throw error
        const replayed = this.storage.mirrorAcceptedBillableLength(input.request)
        if (replayed == null) throw error
        return { coreBillableBytes: replayed }
      }
    }
    if (input.profile.operationId === OPERATION.CORE.PROVE) {
      this.storage.inspectProofSource(input.request)
      const estimatedProofBytes = await this.upstream.estimateProofBytes({
        request: input.request,
        signal: input.signal
      })
      if (!Number.isSafeInteger(estimatedProofBytes) || estimatedProofBytes < 1 ||
          estimatedProofBytes > MAX_PROOF_BYTES) {
        fail('TOO_LARGE', 'upstream CORE proof estimate is outside the frozen result bound')
      }
      const binding = this.descriptorState.resultBinding(input.descriptorSnapshot)
      return {
        coreProofBytes: estimatedProofBytes,
        canonicalResultBytes: predictedProofResultBytes(binding, input.request, estimatedProofBytes),
        predictedResultBodyBytes: predictedProofResultBytes(binding, input.request, estimatedProofBytes)
      }
    }
    return {}
  }

  async checkTerminalState (raw) {
    const input = coreInput(raw)
    if (input.profile.operationId === OPERATION.CORE.MIRROR) {
      const state = await this.storage.mirrorState(input)
      if (state.kind === 'conflict') fail('SPEND_REPLAY', 'CORE.MIRROR spend is already bound elsewhere')
      return
    }
    if (input.profile.operationId === OPERATION.CORE.PROVE && input.preparedAdmission) {
      const state = await this.storage.proveState(input)
      if (state.kind === 'conflict') fail('SPEND_REPLAY', 'CORE.PROVE spend is already bound elsewhere')
      if (state.kind === 'terminal') fail('RETRY_TERMINAL', 'CORE.PROVE retry pin is terminal')
    }
  }

  async checkCapacity (raw) {
    const input = coreInput(raw)
    if (input.profile.operationId === OPERATION.CORE.MIRROR &&
        input.request.length > this.storage.maximumSponsoredCoreLength) {
      fail('TOO_LARGE', 'CORE.MIRROR length exceeds the signed capacity')
    }
  }

  async lookupTransaction (raw) {
    const input = coreInput(raw)
    if (!isAdmittedCoreTransaction(input)) fail('INTERNAL', 'CORE transaction lookup is not admitted')
    if (input.profile.operationId === OPERATION.CORE.MIRROR) {
      const state = await this.storage.mirrorState(input)
      return Object.freeze({ kind: state.kind === 'replay' ? 'replay' : 'fresh' })
    }
    if (isChargedProve(input)) {
      const state = await this.storage.proveState(input)
      return Object.freeze({ kind: state.kind === 'replay' ? 'replay' : 'fresh' })
    }
    return Object.freeze({ kind: 'fresh' })
  }

  async runTransaction (raw, execute) {
    const input = coreInput(raw)
    if (!isAdmittedCoreTransaction(input) || typeof execute !== 'function') {
      fail('INTERNAL', 'CORE transaction invocation is invalid')
    }
    return execute(Object.freeze({ kind: 'blind-core-storage-owned' }))
  }

  async replayTransaction (raw) {
    return this.execute(coreInput(raw))
  }

  async execute (raw) {
    const input = coreInput(raw)
    if (input.profile.operationId === OPERATION.CORE.MIRROR) {
      const accepted = await this.storage.acceptMirror({
        ...input,
        resultBinding: this.descriptorState.resultBinding(input.descriptorSnapshot),
        buildAcknowledgement: fields => this.buildAcknowledgement(fields, input.signal)
      })
      if (accepted.state === 'ACCEPTED' || accepted.state === 'RETRY_PENDING') {
        await this.activateAcceptedMirror(accepted, input)
      }
      return committedCoreResult(accepted.resultBytes)
    }
    if (input.profile.operationId === OPERATION.CORE.PROVE) {
      const expectedProofBytes = input.authenticatedState && input.authenticatedState.coreProofBytes != null
        ? input.authenticatedState.coreProofBytes
        : await this.upstream.estimateProofBytes({ request: input.request, signal: input.signal })
      if (!Number.isSafeInteger(expectedProofBytes) || expectedProofBytes < 1 ||
          expectedProofBytes > MAX_PROOF_BYTES) {
        fail('INTERNAL', 'CORE proof execution has no bounded exact upstream size')
      }
      const execute = () => this.storage.serveProof({
        ...input,
        resultBinding: this.descriptorState.resultBinding(input.descriptorSnapshot),
        buildAcknowledgement: fields => this.buildAcknowledgement(fields, input.signal),
        serveProof: async fields => {
          const proof = b4a.from(await this.upstream.serveProof(fields))
          if (proof.byteLength !== expectedProofBytes) {
            fail('INTERNAL', 'upstream CORE proof length changed after capacity reservation')
          }
          return proof
        }
      })
      const served = input.preparedAdmission
        ? await this.coalesce(this.proofFlights,
          b4a.toString(input.preparedAdmission.spendTag, 'hex'),
          input.requestCommitment,
          execute)
        : await execute()
      return input.preparedAdmission ? committedCoreResult(served.body) : { body: served.body }
    }
    fail('INTERNAL', 'CORE operation executor handles MIRROR and PROVE only')
  }

  async openReplication (request, context = {}) {
    if (!this.replicationService) fail('INTERNAL', 'CORE replication stream service is unavailable')
    return this.replicationService.open(request, context)
  }

  attachReplication (ticket, input) {
    if (!this.replicationService) fail('INTERNAL', 'CORE replication stream service is unavailable')
    return this.replicationService.attach(ticket, input)
  }

  async activateAcceptedMirror (accepted, input) {
    const key = b4a.toString(accepted.spendTag, 'hex')
    return this.coalesce(this.activationFlights, key, input.requestCommitment, async () => {
      const active = this.storage.inspectCore(input.request.corePublicKey)
      let activation
      if (active && active.fork === input.request.fork && active.length === input.request.length &&
          same(active.signedHeadHash, input.request.signedHeadHash)) {
        activation = { verified: true, reuseActive: true }
      } else {
        try {
          activation = await this.upstream.activateMirror({
            request: input.request,
            requestCommitment: b4a.from(input.requestCommitment),
            previousGeneration: this.storage.inspectCoreFloor(input.request.corePublicKey),
            signal: input.signal
          })
        } catch {
          activation = { verified: false, unavailable: true }
        }
      }
      return this.storage.completeMirror(accepted.spendTag, activation, {
        signal: input.signal
      })
    })
  }

  coalesce (flights, key, binding, operation) {
    const existing = flights.get(key)
    if (existing) {
      if (!same(existing.binding, binding)) fail('SPEND_REPLAY', 'in-flight CORE spend is bound to another request')
      return existing.promise
    }
    if (flights.size >= this.maximumFlights) fail('BUSY', 'in-flight CORE work capacity is exhausted')
    const pending = Promise.resolve().then(operation)
    const record = { binding: b4a.from(binding), promise: pending }
    flights.set(key, record)
    pending.finally(() => {
      if (flights.get(key) === record) flights.delete(key)
    }).catch(() => {})
    return pending
  }

  buildAcknowledgement (fields, signal) {
    return signValue(this.signer, blindCoreAckV1, {
      version: 1,
      relayBinding: fields.relayBinding,
      corePublicKey: b4a.from(fields.request.corePublicKey),
      fork: fields.request.fork,
      length: fields.request.length,
      signedHeadHash: b4a.from(fields.request.signedHeadHash),
      observedAtEpoch: fields.observedAtEpoch,
      leaseEpoch: fields.leaseEpoch,
      result: fields.result,
      requestNonce: b4a.from(fields.request.clientNonce),
      requestCommitment: b4a.from(fields.requestCommitment),
      signature: b4a.alloc(SIGNATURE_BYTES)
    }, RESULT_SIGNATURE_DOMAIN_ID.CORE_ACK, fields.relayBinding.relayPublicKey, signal)
  }

  async verifyResult (input) {
    if (!input || input.familyId !== FAMILY.CORE || !input.result || !input.request) return false
    let ack
    if (input.operationId === OPERATION.CORE.MIRROR) ack = input.result
    if (input.operationId === OPERATION.CORE.PROVE) {
      try {
        const result = decodeCanonical(coreServeResultV1,
          encodeCanonical(coreServeResultV1, input.result), { copyBytes: true })
        ack = result.acknowledgement
      } catch {
        return false
      }
    }
    if (!ack || !input.expectedRelayBinding ||
        !same(encodeCanonical(relayResultBindingV1, ack.relayBinding),
          encodeCanonical(relayResultBindingV1, input.expectedRelayBinding)) ||
        !same(ack.corePublicKey, input.request.corePublicKey) || ack.fork !== input.request.fork ||
        ack.length !== input.request.length || !same(ack.signedHeadHash, input.request.signedHeadHash) ||
        !same(ack.requestNonce, input.request.clientNonce) ||
        !same(ack.requestCommitment, input.requestCommitment)) return false
    const expectedResult = input.operationId === OPERATION.CORE.MIRROR
      ? CORE_ACK_RESULT.MIRROR_ACCEPTED
      : CORE_ACK_RESULT.RECENTLY_SERVED
    return ack.result === expectedResult &&
      verifyAckSignature(ack, input.expectedRelayBinding.relayPublicKey)
  }
}
