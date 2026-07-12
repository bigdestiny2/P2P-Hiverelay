import b4a from 'b4a'
import {
  ENDPOINT_LIMITS,
  HEALTH_CLOCK_STATE,
  HEALTH_INTEGRITY_STATE,
  HEALTH_REBALANCE_STATE,
  PUBLIC_PROFILE_LIMITS,
  RESULT_SIGNATURE_DOMAIN_ID,
  STORE_LIFECYCLE_STATE,
  TRANSPORT_SUPPORT,
  blindHealthResultV1,
  blindServiceDescriptorV1,
  decodeCanonical,
  encodeCanonical,
  resultSignaturePayload
} from '@hiverelay/blind-protocol'
import {
  DESCRIPTOR_CLOSED_REASON,
  DESCRIPTOR_STATE_KIND
} from './descriptor-state.js'
import { OPERATION_CATALOG, daemonOperationBit } from './operation-catalog.js'

const ZERO_SIGNATURE = b4a.alloc(64)
const REQUIRED_DESCRIBE_BITS = 0x00000007
export const CLOCK_UNSAFE_OPERATION_BITS = 0x00009628
const KNOWN_TRANSPORT_SUPPORT_BITS = TRANSPORT_SUPPORT.DIRECT_HTTP | TRANSPORT_SUPPORT.DIRECT_NATIVE |
  TRANSPORT_SUPPORT.OHTTP | TRANSPORT_SUPPORT.TOR_HTTP | TRANSPORT_SUPPORT.TOR_NATIVE |
  TRANSPORT_SUPPORT.MASQUE_NATIVE

export const READINESS_STATE_KIND = Object.freeze({
  READY: 1,
  CLOSED: 2
})

export const READINESS_CLOSED_REASON = Object.freeze({
  NO_DESCRIPTOR: 1,
  DESCRIPTOR_NOT_CURRENT: 2,
  ENDPOINT_NOT_ADVERTISED: 3,
  DEPENDENCY_UNVERIFIED: 4,
  DESCRIBE_UNAVAILABLE: 5,
  ADMISSION_PARAMETERS_UNAVAILABLE: 6,
  RETIRED: 7,
  SHUTTING_DOWN: 8,
  TRANSPORT_UNVERIFIED: 9,
  CONTINUITY_UNVERIFIED: 10
})

function protocolFailure (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function asBytes (value, field, length) {
  if (!value || typeof value.byteLength !== 'number') throw new TypeError(`${field} must be bytes`)
  const bytes = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (bytes.byteLength !== length) throw new TypeError(`${field} must be exactly ${length} bytes`)
  return bytes
}

function sameBytes (left, right) {
  return Boolean(left && right && left.byteLength === right.byteLength && b4a.equals(left, right))
}

function nonzero (bytes) {
  for (const byte of bytes) if (byte !== 0) return true
  return false
}

function integer (value, minimum, maximum, field) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${field} is outside ${minimum}..${maximum}`)
  }
  return value
}

function u32 (value, field) {
  return integer(value, 0, 0xffffffff, field)
}

function u64 (value, field) {
  if (typeof value === 'number') value = BigInt(value)
  if (typeof value !== 'bigint' || value < 0n || value > ((1n << 64n) - 1n)) {
    throw new TypeError(`${field} is outside u64`)
  }
  return value
}

function exactTransportSupportBit (value) {
  if (!Number.isInteger(value) || value === 0 || (value & (value - 1)) !== 0 ||
      (value & ~KNOWN_TRANSPORT_SUPPORT_BITS) !== 0) {
    throw new TypeError('transportSupportBit must be one frozen support bit')
  }
  return value
}

function closed (reason) {
  return Object.freeze({ kind: READINESS_STATE_KIND.CLOSED, reason })
}

function descriptorClosedReason (reason) {
  if (reason === DESCRIPTOR_CLOSED_REASON.RETIRED) return READINESS_CLOSED_REASON.RETIRED
  if (reason === DESCRIPTOR_CLOSED_REASON.NO_DESCRIPTOR) return READINESS_CLOSED_REASON.NO_DESCRIPTOR
  return READINESS_CLOSED_REASON.DESCRIPTOR_NOT_CURRENT
}

function dependencyFields (input) {
  if (!input || typeof input !== 'object' || input.selfVerified !== true) return null
  const readyRoleBits = integer(input.readyRoleBits, 0, ENDPOINT_LIMITS.ROLE_BITS_MASK, 'readyRoleBits')
  const readyOperationBits = u32(input.readyOperationBits, 'readyOperationBits')
  if ((readyOperationBits & ~PUBLIC_PROFILE_LIMITS.ENABLED_OPERATION_BITS_MASK) !== 0) {
    throw new TypeError('readyOperationBits contains a reserved bit')
  }
  return {
    descriptorSequence: u64(input.descriptorSequence, 'descriptorSequence'),
    descriptorHash: b4a.from(asBytes(input.descriptorHash, 'descriptorHash', 32)),
    endpointId: integer(input.endpointId, 1, 255, 'endpointId'),
    transportSupportBit: exactTransportSupportBit(input.transportSupportBit),
    fullStoreVerified: input.fullStoreVerified === true,
    readyRoleBits,
    readyOperationBits,
    clockState: integer(input.clockState, HEALTH_CLOCK_STATE.READY, HEALTH_CLOCK_STATE.VERIFYING, 'clockState'),
    effectiveEpochFloor: u32(input.effectiveEpochFloor, 'effectiveEpochFloor'),
    integrityState: integer(input.integrityState, HEALTH_INTEGRITY_STATE.VERIFIED,
      HEALTH_INTEGRITY_STATE.FAILED, 'integrityState'),
    checkpointAgeBand: integer(input.checkpointAgeBand, 0, 7, 'checkpointAgeBand'),
    scrubAgeBand: integer(input.scrubAgeBand, 0, 7, 'scrubAgeBand'),
    rebalanceState: integer(input.rebalanceState, HEALTH_REBALANCE_STATE.STABLE,
      HEALTH_REBALANCE_STATE.FENCED, 'rebalanceState'),
    capacityBand: integer(input.capacityBand, 0, 7, 'capacityBand')
  }
}

function unsupportedAdapterClaim (operationBits, supportBit) {
  for (const profile of OPERATION_CATALOG) {
    if (profile.ordinal < 3 || (operationBits & profile.operationBit) === 0) continue
    if ((profile.transportSupportBits & supportBit) === 0) return true
  }
  return false
}

function supportedOperationSubset (operationBits, supportBit) {
  let subset = 0
  for (const profile of OPERATION_CATALOG) {
    if ((operationBits & profile.operationBit) !== 0 &&
        (profile.transportSupportBits & supportBit) !== 0) subset |= profile.operationBit
  }
  return subset
}

function sameReadiness (left, right) {
  if (left.kind !== READINESS_STATE_KIND.READY || right.kind !== READINESS_STATE_KIND.READY) return false
  for (const field of [
    'descriptorSequence', 'readyRoleBits', 'readyOperationBits', 'clockState', 'effectiveEpochFloor',
    'integrityState', 'checkpointAgeBand', 'scrubAgeBand', 'rebalanceState', 'capacityBand',
    'transportSupportBit'
  ]) {
    if (left[field] !== right[field]) return false
  }
  return sameBytes(left.descriptorHash, right.descriptorHash) && left.endpoint.endpointId === right.endpoint.endpointId
}

export class ReadinessCoordinator {
  constructor (options = {}) {
    if (!options.descriptorState || typeof options.descriptorState.state !== 'function') {
      throw new TypeError('descriptorState is required')
    }
    if (!options.admission || typeof options.admission.descriptorProfilesReady !== 'function') {
      throw new TypeError('admission coordinator is required')
    }
    if (typeof options.dependencySnapshot !== 'function') {
      throw new TypeError('dependencySnapshot is required')
    }
    if (!options.signer || typeof options.signer.sign !== 'function' || typeof options.signer.verify !== 'function') {
      throw new TypeError('readiness signer must expose sign and verify')
    }
    this.descriptorState = options.descriptorState
    this.admission = options.admission
    this.dependencySnapshot = options.dependencySnapshot
    this.signer = options.signer
    this.closed = false
  }

  close () {
    this.closed = true
  }

  async evaluate (input = {}) {
    if (this.closed) return closed(READINESS_CLOSED_REASON.SHUTTING_DOWN)
    let supportBit
    try {
      supportBit = exactTransportSupportBit(input.transportSupportBit)
    } catch {
      return closed(READINESS_CLOSED_REASON.TRANSPORT_UNVERIFIED)
    }
    const descriptorState = this.descriptorState.state()
    if (descriptorState.kind !== DESCRIPTOR_STATE_KIND.READY) {
      return closed(descriptorClosedReason(descriptorState.reason))
    }
    const snapshot = descriptorState.snapshot
    const descriptor = snapshot.descriptor
    const descriptorSequence = snapshot.descriptorSequence
    const descriptorHash = b4a.from(snapshot.hash)
    const lifecycleFence = snapshot.lifecycleFence
    if (descriptor.storeLifecycleState === STORE_LIFECYCLE_STATE.RETIRED) {
      return closed(READINESS_CLOSED_REASON.RETIRED)
    }
    const endpoint = descriptor.endpoints.find(entry => entry.endpointId === input.endpointId)
    if (!endpoint) return closed(READINESS_CLOSED_REASON.ENDPOINT_NOT_ADVERTISED)

    let raw
    try {
      const dependencyDescriptor = decodeCanonical(blindServiceDescriptorV1,
        snapshot.canonicalBytes, { copyBytes: true })
      const dependencyEndpoint = dependencyDescriptor.endpoints.find(entry => entry.endpointId === endpoint.endpointId)
      raw = await this.dependencySnapshot({
        descriptor: dependencyDescriptor,
        descriptorHash: b4a.from(descriptorHash),
        descriptorSequence,
        endpoint: dependencyEndpoint,
        endpointId: endpoint.endpointId,
        transportSupportBit: supportBit,
        signal: input.signal
      })
    } catch {
      return closed(READINESS_CLOSED_REASON.DEPENDENCY_UNVERIFIED)
    }
    let fields
    try {
      fields = dependencyFields(raw)
    } catch {
      return closed(READINESS_CLOSED_REASON.DEPENDENCY_UNVERIFIED)
    }
    if (!fields || fields.readyRoleBits === 0 || fields.descriptorSequence !== descriptorSequence ||
        !sameBytes(fields.descriptorHash, descriptorHash) || fields.endpointId !== endpoint.endpointId ||
        fields.transportSupportBit !== supportBit || fields.capacityBand !== descriptor.capacityBand ||
        (fields.readyRoleBits & ~endpoint.roleBits) !== 0 ||
        (fields.readyOperationBits & ~descriptor.enabledOperationBits) !== 0 ||
        unsupportedAdapterClaim(fields.readyOperationBits, supportBit)) {
      return closed(READINESS_CLOSED_REASON.DEPENDENCY_UNVERIFIED)
    }
    if (snapshot.fullStoreVerificationRequired && !fields.fullStoreVerified) {
      return closed(READINESS_CLOSED_REASON.CONTINUITY_UNVERIFIED)
    }
    const after = this.descriptorState.state()
    if (after.kind !== DESCRIPTOR_STATE_KIND.READY ||
        after.snapshot.descriptorSequence !== descriptorSequence ||
        !sameBytes(after.snapshot.hash, descriptorHash) ||
        after.snapshot.lifecycleFence !== lifecycleFence) {
      return closed(READINESS_CLOSED_REASON.DESCRIPTOR_NOT_CURRENT)
    }

    let readyOperationBits = fields.readyOperationBits & descriptor.enabledOperationBits
    const admissionSnapshot = this.descriptorState.selected(descriptorHash)
    if (!admissionSnapshot) return closed(READINESS_CLOSED_REASON.DESCRIPTOR_NOT_CURRENT)
    const parametersAvailable = typeof this.admission.descriptorParametersAvailable === 'function'
      ? this.admission.descriptorParametersAvailable(admissionSnapshot)
      : this.admission.descriptorProfilesReady(admissionSnapshot)
    if (parametersAvailable !== true) {
      readyOperationBits &= ~daemonOperationBit(1, 3)
      return closed(READINESS_CLOSED_REASON.ADMISSION_PARAMETERS_UNAVAILABLE)
    }
    if (this.admission.descriptorProfilesReady(this.descriptorState.selected(descriptorHash)) !== true) {
      for (const profile of OPERATION_CATALOG) {
        if (profile.admissionMode !== 0) readyOperationBits &= ~profile.operationBit
      }
    }
    if (fields.clockState !== HEALTH_CLOCK_STATE.READY) {
      readyOperationBits &= ~CLOCK_UNSAFE_OPERATION_BITS
    }
    if (fields.integrityState === HEALTH_INTEGRITY_STATE.FAILED) readyOperationBits &= REQUIRED_DESCRIBE_BITS
    if ((readyOperationBits & REQUIRED_DESCRIBE_BITS) !== REQUIRED_DESCRIBE_BITS) {
      return closed(READINESS_CLOSED_REASON.DESCRIBE_UNAVAILABLE)
    }
    return Object.freeze({
      kind: READINESS_STATE_KIND.READY,
      selfVerified: true,
      snapshot: this.descriptorState.selected(descriptorHash),
      endpoint: { ...endpoint },
      descriptorSequence,
      descriptorHash: b4a.from(descriptorHash),
      transportSupportBit: supportBit,
      readyRoleBits: fields.readyRoleBits,
      readyOperationBits,
      clockState: fields.clockState,
      effectiveEpochFloor: fields.effectiveEpochFloor,
      integrityState: fields.integrityState,
      checkpointAgeBand: fields.checkpointAgeBand,
      scrubAgeBand: fields.scrubAgeBand,
      rebalanceState: fields.rebalanceState,
      capacityBand: fields.capacityBand
    })
  }

  _validateChallengeBeforeReadiness (challenge, input) {
    if (!challenge || typeof challenge !== 'object') protocolFailure('BAD_ENCODING', 'health challenge is missing')
    let clientNonce
    let descriptorHash
    let endpointId
    let transportSupportBit
    let requestedRoleBits
    let requestedOperationBits
    let descriptorSequence
    try {
      clientNonce = b4a.from(asBytes(challenge.clientNonce, 'clientNonce', 32))
      descriptorHash = b4a.from(asBytes(challenge.descriptorHash, 'descriptorHash', 32))
      endpointId = integer(challenge.endpointId, 1, 255, 'endpointId')
      transportSupportBit = exactTransportSupportBit(challenge.transportSupportBit)
      requestedRoleBits = integer(challenge.requestedRoleBits, 1, ENDPOINT_LIMITS.ROLE_BITS_MASK,
        'requestedRoleBits')
      requestedOperationBits = u32(challenge.requestedOperationBits, 'requestedOperationBits')
      descriptorSequence = u64(challenge.descriptorSequence, 'descriptorSequence')
      if (endpointId !== integer(input.endpointId, 1, 255, 'accepted endpointId') ||
          transportSupportBit !== exactTransportSupportBit(input.transportSupportBit)) {
        throw new TypeError('health challenge endpoint/transport does not match the accepted channel')
      }
    } catch {
      protocolFailure('BAD_ENCODING', 'health challenge scalar or byte fields are malformed')
    }
    if (!nonzero(clientNonce) || requestedOperationBits === 0 ||
        (requestedOperationBits & ~PUBLIC_PROFILE_LIMITS.ENABLED_OPERATION_BITS_MASK) !== 0) {
      protocolFailure('BAD_ENCODING', 'health challenge nonce/operation set is empty or reserved')
    }
    const descriptorState = this.descriptorState.state()
    if (descriptorState.kind !== DESCRIPTOR_STATE_KIND.READY) protocolFailure('BUSY', 'health path is not ready')
    const snapshot = descriptorState.snapshot
    const descriptor = snapshot.descriptor
    const endpoint = descriptor.endpoints.find(entry => entry.endpointId === endpointId)
    if (!endpoint) protocolFailure('BAD_ENCODING', 'health challenge endpoint is not advertised')
    if (descriptorSequence !== descriptor.descriptorSequence ||
        !sameBytes(descriptorHash, snapshot.hash) || (requestedRoleBits & ~endpoint.roleBits) !== 0 ||
        (requestedOperationBits & ~descriptor.enabledOperationBits) !== 0 ||
        unsupportedAdapterClaim(requestedOperationBits, transportSupportBit)) {
      protocolFailure('BAD_ENCODING', 'health challenge does not bind the current endpoint descriptor')
    }
    return {
      clientNonce,
      descriptorHash,
      endpointId,
      transportSupportBit,
      requestedRoleBits,
      requestedOperationBits
    }
  }

  async healthResult (challenge, input) {
    const validated = this._validateChallengeBeforeReadiness(challenge, input)
    const state = await this.evaluate(input)
    if (state.kind !== READINESS_STATE_KIND.READY) protocolFailure('BUSY', 'health path is not ready')
    if (state.endpoint.endpointId !== validated.endpointId ||
        state.transportSupportBit !== validated.transportSupportBit) {
      protocolFailure('INTERNAL', 'health readiness changed its bound endpoint tuple')
    }
    const descriptor = state.snapshot.descriptor
    const challengeEpoch = this.descriptorState.epochNow()
    const unsignedValue = {
      version: 1,
      relayPublicKey: b4a.from(descriptor.relayPublicKey),
      storeId: b4a.from(descriptor.storeId),
      descriptorSequence: descriptor.descriptorSequence,
      descriptorHash: b4a.from(state.snapshot.hash),
      endpointId: validated.endpointId,
      transportSupportBit: validated.transportSupportBit,
      durabilityContinuityHash: b4a.from(descriptor.durabilityContinuityHash),
      durabilityProfileHash: b4a.from(descriptor.durabilityProfileHash),
      clientNonce: b4a.from(validated.clientNonce),
      readyRoleBits: state.readyRoleBits & validated.requestedRoleBits,
      readyOperationBits: state.readyOperationBits & validated.requestedOperationBits,
      clockState: state.clockState,
      effectiveEpochFloor: state.effectiveEpochFloor,
      integrityState: state.integrityState,
      checkpointAgeBand: state.checkpointAgeBand,
      scrubAgeBand: state.scrubAgeBand,
      rebalanceState: state.rebalanceState,
      capacityBand: state.capacityBand,
      challengeEpoch,
      signature: ZERO_SIGNATURE
    }
    const placeholderBytes = encodeCanonical(blindHealthResultV1, unsignedValue)
    const unsignedBytes = placeholderBytes.subarray(0, placeholderBytes.byteLength - 64)
    const payload = resultSignaturePayload(RESULT_SIGNATURE_DOMAIN_ID.HEALTH_RESULT, unsignedBytes)
    const signatureValue = await this.signer.sign({
      domainId: RESULT_SIGNATURE_DOMAIN_ID.HEALTH_RESULT,
      publicKey: b4a.from(descriptor.relayPublicKey),
      payload: b4a.from(payload),
      descriptor: decodeCanonical(blindServiceDescriptorV1, state.snapshot.canonicalBytes, { copyBytes: true }),
      signal: input.signal
    })
    let signature
    try {
      signature = b4a.from(asBytes(signatureValue, 'health signature', 64))
    } catch {
      protocolFailure('INTERNAL', 'health signer returned an invalid signature')
    }
    const verified = await this.signer.verify({
      domainId: RESULT_SIGNATURE_DOMAIN_ID.HEALTH_RESULT,
      publicKey: b4a.from(descriptor.relayPublicKey),
      payload: b4a.from(payload),
      signature: b4a.from(signature),
      signal: input.signal
    })
    if (verified !== true) protocolFailure('INTERNAL', 'health result failed local signature verification')
    const after = await this.evaluate(input)
    if (!sameReadiness(state, after) || this.descriptorState.epochNow() !== challengeEpoch) {
      protocolFailure('INTERNAL', 'health readiness changed while its signed result was produced')
    }
    const canonicalBytes = encodeCanonical(blindHealthResultV1, { ...unsignedValue, signature })
    const value = decodeCanonical(blindHealthResultV1, canonicalBytes, { copyBytes: true })
    return Object.freeze({ value, canonicalBytes: b4a.from(canonicalBytes) })
  }

  async serverSnapshot (input) {
    const edgeInstanceNonce = b4a.from(asBytes(input.edgeInstanceNonce, 'edgeInstanceNonce', 32))
    if (!nonzero(edgeInstanceNonce)) protocolFailure('BAD_ENCODING', 'edgeInstanceNonce must be nonzero')
    const state = this.descriptorState.state()
    if (state.kind !== DESCRIPTOR_STATE_KIND.READY) protocolFailure('BUSY', 'daemon readiness is closed')
    const endpoint = state.snapshot.descriptor.endpoints.find(entry => entry.endpointId === input.endpointId)
    if (!endpoint) protocolFailure('BUSY', 'daemon endpoint readiness is closed')
    const transportSupportBit = exactTransportSupportBit(input.transportSupportBit)
    const result = await this.healthResult({
      version: 1,
      descriptorSequence: state.snapshot.descriptorSequence,
      descriptorHash: b4a.from(state.snapshot.hash),
      endpointId: endpoint.endpointId,
      transportSupportBit,
      requestedRoleBits: endpoint.roleBits,
      requestedOperationBits: supportedOperationSubset(
        state.snapshot.descriptor.enabledOperationBits, transportSupportBit),
      clientNonce: b4a.from(edgeInstanceNonce)
    }, input)
    const value = decodeCanonical(blindHealthResultV1, result.canonicalBytes, { copyBytes: true })
    if (!sameBytes(value.clientNonce, edgeInstanceNonce) || value.endpointId !== endpoint.endpointId ||
        value.transportSupportBit !== transportSupportBit) {
      protocolFailure('INTERNAL', 'signed health result did not echo the edge readiness endpoint tuple')
    }
    return Object.freeze({
      selfVerified: true,
      edgeInstanceNonce: b4a.from(value.clientNonce),
      descriptorSequence: value.descriptorSequence,
      descriptorHash: b4a.from(value.descriptorHash),
      endpointId: value.endpointId,
      readyRoleBits: value.readyRoleBits,
      readyOperationBits: value.readyOperationBits,
      transportSupportBit: value.transportSupportBit,
      canonicalHealthResult: b4a.from(result.canonicalBytes)
    })
  }
}
