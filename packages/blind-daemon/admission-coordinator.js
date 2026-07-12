import b4a from 'b4a'
import {
  ADMISSION_MODE,
  RESULT_SIGNATURE_DOMAIN_ID,
  admissionParametersHash,
  admissionParametersV1,
  decodeCanonical,
  encodeCanonical,
  resultSignaturePayload
} from '@hiverelay/blind-protocol'
import { DESCRIPTOR_STATE_KIND } from './descriptor-state.js'

const MAX_U64 = (1n << 64n) - 1n
const MAX_WAL_COMMIT_RECORD_BYTES = 16 * 1024

function protocolFailure (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function asBytes (value, field, limits = null) {
  if (!value || typeof value.byteLength !== 'number') protocolFailure('SPEND_INVALID', `${field} must be bytes`)
  const bytes = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (limits && (bytes.byteLength < limits[0] || bytes.byteLength > limits[1])) {
    protocolFailure('SPEND_INVALID', `${field} is outside its byte bound`)
  }
  return bytes
}

function sameBytes (left, right) {
  return Boolean(left && right && left.byteLength === right.byteLength && b4a.equals(left, right))
}

function nonzero (bytes) {
  for (const byte of bytes) if (byte !== 0) return true
  return false
}

function byteKey (bytes) {
  return b4a.toString(bytes, 'hex')
}

function epoch (descriptorState) {
  const value = descriptorState.epochNow()
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    protocolFailure('SPEND_INVALID', 'descriptor epoch is outside u32')
  }
  return value
}

function u64 (value, field) {
  if (typeof value === 'number') value = BigInt(value)
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
    protocolFailure('SPEND_INVALID', `${field} is outside u64`)
  }
  return value
}

function decodeExact (canonicalBytes) {
  let value
  try {
    value = decodeCanonical(admissionParametersV1, canonicalBytes, { copyBytes: true })
    if (!sameBytes(canonicalBytes, encodeCanonical(admissionParametersV1, value))) throw new Error('non-canonical')
  } catch {
    protocolFailure('SPEND_INVALID', 'admission parameters are not canonical')
  }
  return value
}

function profileCopy (profile) {
  return Object.freeze({
    ...profile,
    parameterUrl: profile.parameterUrl == null ? null : b4a.from(profile.parameterUrl),
    parameterHash: b4a.from(profile.parameterHash)
  })
}

function recordView (record) {
  return Object.freeze({
    value: decodeExact(record.canonicalBytes),
    hash: b4a.from(record.hash),
    canonicalBytes: b4a.from(record.canonicalBytes)
  })
}

function currentSnapshot (descriptorState, candidate = null) {
  if (candidate != null) {
    if (candidate.hash == null) protocolFailure('SPEND_INVALID', 'descriptor snapshot has no signed hash')
    const selected = descriptorState.selected(candidate.hash)
    if (selected != null && descriptorState.remainsUsable(selected)) return selected
    protocolFailure('SPEND_INVALID', 'descriptor snapshot is no longer retained or usable')
  }
  const state = descriptorState.state()
  if (state.kind !== DESCRIPTOR_STATE_KIND.READY) protocolFailure('SPEND_INVALID', 'descriptor is not current')
  return state.snapshot
}

function parameterMatchesProfile (record, profile, descriptor) {
  const value = decodeExact(record.canonicalBytes)
  return value.profileId === profile.profileId && value.schemeId === profile.schemeId &&
    value.conformanceClass === profile.conformanceClass && value.roleBits === profile.roleBits &&
    sameBytes(record.hash, profile.parameterHash) && sameBytes(value.relayPublicKey, descriptor.relayPublicKey) &&
    value.validFromEpoch < descriptor.expiresEpoch && value.expiresEpoch > descriptor.issuedEpoch
}

export class AdmissionCoordinator {
  #recordsByHash
  #parameterBytes
  #serial

  constructor (options = {}) {
    if (!options.descriptorState || typeof options.descriptorState.state !== 'function' ||
        typeof options.descriptorState.selected !== 'function' ||
        typeof options.descriptorState.remainsUsable !== 'function') {
      throw new TypeError('descriptorState is required')
    }
    if (typeof options.verifySignature !== 'function') {
      throw new TypeError('verifySignature is required for admission parameters')
    }
    if (typeof options.resolveAdapter !== 'function') {
      throw new TypeError('resolveAdapter is required for admission redemption')
    }
    this.descriptorState = options.descriptorState
    this.verifySignature = options.verifySignature
    this.resolveAdapter = options.resolveAdapter
    this.maxRecords = options.maxRecords == null ? 64 : options.maxRecords
    this.maxParameterBytes = options.maxParameterBytes == null ? 1024 * 1024 : options.maxParameterBytes
    if (!Number.isSafeInteger(this.maxRecords) || this.maxRecords < 1 || this.maxRecords > 4096) {
      throw new TypeError('maxRecords must be within 1..4096')
    }
    if (!Number.isSafeInteger(this.maxParameterBytes) || this.maxParameterBytes < 16 * 1024 ||
        this.maxParameterBytes > 64 * 1024 * 1024) {
      throw new TypeError('maxParameterBytes must be within 16KiB..64MiB')
    }
    this.#recordsByHash = new Map()
    this.#parameterBytes = 0
    this.#serial = Promise.resolve()
  }

  _serialized (operation) {
    const result = this.#serial.then(operation)
    this.#serial = result.catch(() => {})
    return result
  }

  installParameters (input, options = {}) {
    const canonicalBytes = b4a.from(asBytes(input, 'admission parameter bytes'))
    return this._serialized(() => this._installParameters(canonicalBytes, options.signal))
  }

  async _installParameters (canonicalBytes, signal) {
    let value = decodeExact(canonicalBytes)
    const hash = admissionParametersHash(canonicalBytes)
    const unsignedBytes = canonicalBytes.subarray(0, canonicalBytes.byteLength - 64)
    const payload = resultSignaturePayload(RESULT_SIGNATURE_DOMAIN_ID.ADMISSION_PARAMETERS, unsignedBytes)
    const verified = await this.verifySignature({
      domainId: RESULT_SIGNATURE_DOMAIN_ID.ADMISSION_PARAMETERS,
      publicKey: b4a.from(value.relayPublicKey),
      signature: b4a.from(value.signature),
      payload: b4a.from(payload),
      canonicalBytes: b4a.from(canonicalBytes),
      parameters: decodeExact(canonicalBytes),
      signal
    })
    if (verified !== true) protocolFailure('SPEND_INVALID', 'admission parameter signature verification failed')
    value = decodeExact(canonicalBytes)

    const key = byteKey(hash)
    const existing = this.#recordsByHash.get(key)
    if (existing) {
      if (!sameBytes(existing.canonicalBytes, canonicalBytes)) {
        protocolFailure('SPEND_INVALID', 'admission parameter hash was rebound to different bytes')
      }
      return recordView(existing)
    }
    this._sweep(epoch(this.descriptorState))
    if (this.#recordsByHash.size >= this.maxRecords ||
        this.#parameterBytes + canonicalBytes.byteLength > this.maxParameterBytes) {
      protocolFailure('BUSY', 'bounded admission-parameter storage is full')
    }
    const record = Object.freeze({
      hash: b4a.from(hash),
      canonicalBytes: b4a.from(canonicalBytes),
      expiresEpoch: value.expiresEpoch
    })
    this.#recordsByHash.set(key, record)
    this.#parameterBytes += canonicalBytes.byteLength
    return recordView(record)
  }

  _sweep (now) {
    for (const [key, record] of this.#recordsByHash) {
      if (record.expiresEpoch <= now) {
        this.#recordsByHash.delete(key)
        this.#parameterBytes -= record.canonicalBytes.byteLength
      }
    }
  }

  profileRecord (descriptorSnapshot, profileId, schemeId, options = {}) {
    if (!descriptorSnapshot || !descriptorSnapshot.hash) return null
    const selectedSnapshot = this.descriptorState.selected(descriptorSnapshot.hash)
    if (!selectedSnapshot) return null
    const descriptor = selectedSnapshot.descriptor
    const profile = descriptor.admissionProfiles.find(entry => entry.profileId === profileId)
    if (!profile || profile.schemeId !== schemeId) return null
    const record = this.#recordsByHash.get(byteKey(profile.parameterHash))
    if (!record || !parameterMatchesProfile(record, profile, descriptor)) return null
    const value = decodeExact(record.canonicalBytes)
    const now = epoch(this.descriptorState)
    const available = value.expiresEpoch > now
    const redeemable = available && value.validFromEpoch <= now
    if (!available || (options.redeemable === true && !redeemable)) return null
    return Object.freeze({
      profile: profileCopy(profile),
      record: recordView(record),
      redeemable
    })
  }

  descriptorParametersAvailable (descriptorSnapshot = null) {
    try {
      descriptorSnapshot = currentSnapshot(this.descriptorState, descriptorSnapshot)
    } catch {
      return false
    }
    return descriptorSnapshot.descriptor.admissionProfiles.every(profile =>
      this.profileRecord(descriptorSnapshot, profile.profileId, profile.schemeId) != null)
  }

  descriptorProfilesReady (descriptorSnapshot = null) {
    try {
      descriptorSnapshot = currentSnapshot(this.descriptorState, descriptorSnapshot)
    } catch {
      return false
    }
    return descriptorSnapshot.descriptor.admissionProfiles.every(profile =>
      this.profileRecord(descriptorSnapshot, profile.profileId, profile.schemeId, { redeemable: true }) != null)
  }

  parametersForRequest (request, descriptorSnapshot = null) {
    descriptorSnapshot = currentSnapshot(this.descriptorState, descriptorSnapshot)
    const selected = this.profileRecord(descriptorSnapshot, request.profileId, request.schemeId)
    return selected == null ? null : b4a.from(selected.record.canonicalBytes)
  }

  async prepare (input) {
    const { profile, signal } = input
    const admission = input.admission == null
      ? null
      : Object.freeze({
        profileId: input.admission.profileId,
        schemeId: input.admission.schemeId,
        parameterHash: b4a.from(asBytes(input.admission.parameterHash, 'parameterHash', [32, 32])),
        token: b4a.from(asBytes(input.admission.token, 'token', [1, 65535]))
      })
    if (profile.admissionMode === ADMISSION_MODE.NONE) {
      if (admission != null) protocolFailure('BAD_ENCODING', 'operation forbids admission')
      return null
    }
    if (admission == null) {
      if (profile.admissionMode === ADMISSION_MODE.REQUIRED) {
        protocolFailure('SPEND_REQUIRED', 'operation requires admission')
      }
      return null
    }
    const requestCommitment = b4a.from(asBytes(input.requestCommitment,
      'requestCommitment', [32, 32]))
    const descriptorSnapshot = currentSnapshot(this.descriptorState, input.descriptorSnapshot)
    const selected = this.profileRecord(descriptorSnapshot, admission.profileId, admission.schemeId,
      { redeemable: true })
    if (!selected || !sameBytes(admission.parameterHash, selected.profile.parameterHash)) {
      protocolFailure('SPEND_INVALID', 'admission profile, scheme, or parameter hash is not current')
    }
    const endpoint = descriptorSnapshot.descriptor.endpoints.find(entry => entry.endpointId === input.endpoint.endpointId)
    if (!endpoint || (selected.record.value.roleBits & endpoint.roleBits) === 0) {
      protocolFailure('SPEND_INVALID', 'admission profile is not bound to the selected endpoint role')
    }
    const cost = input.cost
    if (!cost || !Number.isInteger(cost.resourceClass) || !Number.isInteger(cost.leaseClass)) {
      protocolFailure('SPEND_INVALID', 'admission cost class is unavailable')
    }
    let parameters = selected.record.value
    const now = epoch(this.descriptorState)
    if (now < parameters.validFromEpoch || now >= parameters.expiresEpoch ||
        admission.token.byteLength > parameters.tokenMaxBytes) {
      protocolFailure('SPEND_INVALID', 'admission parameters are not redeemable at the current epoch')
    }
    let row = parameters.resourceCosts.find(entry => entry.familyId === profile.familyId &&
      entry.operationId === profile.operationId && entry.resourceClass === cost.resourceClass &&
      entry.leaseClass === cost.leaseClass)
    if (!row) protocolFailure('SPEND_INVALID', 'admission parameters contain no exact resource-cost tuple')

    const adapter = await this.resolveAdapter({
      profileId: admission.profileId,
      schemeId: admission.schemeId,
      parameterHash: b4a.from(admission.parameterHash),
      descriptor: currentSnapshot(this.descriptorState, descriptorSnapshot).descriptor,
      parameters: decodeExact(selected.record.canonicalBytes),
      endpointId: endpoint.endpointId,
      endpointRoleBits: endpoint.roleBits,
      signal
    })
    if (!adapter || typeof adapter.prepare !== 'function' ||
        !this.descriptorState.remainsUsable(descriptorSnapshot)) {
      protocolFailure('SPEND_INVALID', 'admission verifier is unavailable or descriptor advanced across a fence')
    }
    parameters = decodeExact(selected.record.canonicalBytes)
    row = parameters.resourceCosts.find(entry => entry.familyId === profile.familyId &&
      entry.operationId === profile.operationId && entry.resourceClass === cost.resourceClass &&
      entry.leaseClass === cost.leaseClass)
    if (!row) protocolFailure('SPEND_INVALID', 'admission cost tuple changed during verification')

    const prepared = await adapter.prepare({
      admission: {
        profileId: admission.profileId,
        schemeId: admission.schemeId,
        parameterHash: b4a.from(admission.parameterHash),
        token: b4a.from(admission.token)
      },
      familyId: profile.familyId,
      operationId: profile.operationId,
      costClass: Object.freeze({
        resourceClass: cost.resourceClass,
        leaseClass: cost.leaseClass,
        costUnits: row.costUnits
      }),
      requestCommitment: b4a.from(requestCommitment),
      parameters: decodeExact(selected.record.canonicalBytes),
      endpointId: endpoint.endpointId,
      signal
    })
    if (!prepared || typeof prepared !== 'object' || !this.descriptorState.remainsUsable(descriptorSnapshot)) {
      protocolFailure('SPEND_INVALID', 'admission proof is invalid or crossed a descriptor fence')
    }
    const spendTag = asBytes(prepared.spendTag, 'spendTag', [32, 32])
    const preparedCommitment = asBytes(prepared.requestCommitment, 'prepared requestCommitment', [32, 32])
    const parameterHash = asBytes(prepared.parameterHash, 'prepared parameterHash', [32, 32])
    const walCommitRecord = asBytes(prepared.walCommitRecord, 'walCommitRecord', [1, MAX_WAL_COMMIT_RECORD_BYTES])
    const preparedCost = prepared.costClass
    if (!nonzero(spendTag) || !sameBytes(preparedCommitment, requestCommitment) ||
        prepared.profileId !== admission.profileId || prepared.schemeId !== admission.schemeId ||
        !sameBytes(parameterHash, admission.parameterHash) || !preparedCost ||
        preparedCost.resourceClass !== cost.resourceClass || preparedCost.leaseClass !== cost.leaseClass ||
        u64(preparedCost.costUnits, 'prepared costUnits') !== row.costUnits ||
        epoch(this.descriptorState) < parameters.validFromEpoch ||
        epoch(this.descriptorState) >= parameters.expiresEpoch) {
      protocolFailure('SPEND_INVALID', 'admission proof did not echo its exact current binding and cost')
    }
    return Object.freeze({
      spendTag: b4a.from(spendTag),
      requestCommitment: b4a.from(preparedCommitment),
      costClass: Object.freeze({
        resourceClass: cost.resourceClass,
        leaseClass: cost.leaseClass,
        costUnits: row.costUnits
      }),
      walCommitRecord: b4a.from(walCommitRecord),
      profileId: admission.profileId,
      schemeId: admission.schemeId,
      parameterHash: b4a.from(admission.parameterHash)
    })
  }
}
