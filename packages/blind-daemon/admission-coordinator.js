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
const PREFLIGHT_AUTHORITIES = new WeakMap()

// The production daemon assembly injects the server-owned PostEOF issuer's
// consumer. Individual coordinators still fail closed when no consumer is
// supplied; a caller assertion or public-field object is never EOF authority.
export const ADMISSION_PREFLIGHT_SPLIT_STATUS = Object.freeze({
  wired: true,
  daemonPrivatePostEofBrandRequired: true,
  postEofAuthorityRequired: true,
  productionReady: false,
  blocker: 'PRODUCTION_ADMISSION_ADAPTER_CAPTURE_REQUIRED'
})

function protocolFailure (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function abortFailure () {
  const error = new Error('admission preflight crossed its abort fence')
  error.code = 'ABORT_ERR'
  return error
}

function assertLiveSignal (signal) {
  if (signal == null) return
  if (typeof signal !== 'object' || typeof signal.aborted !== 'boolean' ||
      typeof signal.addEventListener !== 'function' || typeof signal.removeEventListener !== 'function') {
    protocolFailure('SPEND_INVALID', 'admission preflight signal must be an AbortSignal')
  }
  if (signal.aborted) throw abortFailure()
}

async function abortableCall (operation, signal) {
  assertLiveSignal(signal)
  if (signal == null) return operation()
  let onAbort
  const aborted = new Promise((resolve, reject) => {
    onAbort = () => reject(abortFailure())
    signal.addEventListener('abort', onAbort, { once: true })
  })
  try {
    return await Promise.race([Promise.resolve().then(operation), aborted])
  } finally {
    signal.removeEventListener('abort', onAbort)
  }
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

function admissionCopy (input) {
  if (!input || typeof input !== 'object') protocolFailure('SPEND_REQUIRED', 'operation requires admission')
  return Object.freeze({
    profileId: input.profileId,
    schemeId: input.schemeId,
    parameterHash: b4a.from(asBytes(input.parameterHash, 'parameterHash', [32, 32])),
    token: b4a.from(asBytes(input.token, 'token', [1, 65535]))
  })
}

function operationBinding (profile) {
  if (!profile || !Number.isInteger(profile.familyId) || !Number.isInteger(profile.operationId) ||
      !Number.isInteger(profile.admissionMode) || profile.admissionMode === ADMISSION_MODE.NONE) {
    protocolFailure('SPEND_INVALID', 'admission preflight requires one admitted operation profile')
  }
  return Object.freeze({
    familyId: profile.familyId,
    operationId: profile.operationId,
    admissionMode: profile.admissionMode
  })
}

function costBinding (cost) {
  if (!cost || !Number.isInteger(cost.resourceClass) || !Number.isInteger(cost.leaseClass)) {
    protocolFailure('SPEND_INVALID', 'admission cost class is unavailable')
  }
  return Object.freeze({ resourceClass: cost.resourceClass, leaseClass: cost.leaseClass })
}

function sameOperationBinding (left, right) {
  return left.familyId === right.familyId && left.operationId === right.operationId &&
    left.admissionMode === right.admissionMode
}

function sameAdmissionBinding (left, right) {
  return left.profileId === right.profileId && left.schemeId === right.schemeId &&
    sameBytes(left.parameterHash, right.parameterHash) && sameBytes(left.token, right.token)
}

function sameCostBinding (left, right) {
  return left.resourceClass === right.resourceClass && left.leaseClass === right.leaseClass &&
    left.costUnits === right.costUnits
}

function opaqueFrozenCapability (value) {
  try {
    return Boolean(value && typeof value === 'object' && Object.isFrozen(value) &&
      Reflect.ownKeys(value).length === 0)
  } catch {
    return false
  }
}

export class AdmissionCoordinator {
  #recordsByHash
  #parameterBytes
  #serial
  #consumePostEofAuthority

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
    if (options.consumePostEofAuthority != null && typeof options.consumePostEofAuthority !== 'function') {
      throw new TypeError('consumePostEofAuthority must be a function')
    }
    this.#consumePostEofAuthority = options.consumePostEofAuthority || null
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

  _preflightBinding (input) {
    if (!input || typeof input !== 'object') protocolFailure('SPEND_INVALID', 'admission preflight input is required')
    const operation = operationBinding(input.profile)
    const admission = admissionCopy(input.admission)
    const requestCommitment = b4a.from(asBytes(input.requestCommitment,
      'requestCommitment', [32, 32]))
    const requestId = b4a.from(asBytes(input.requestId, 'requestId', [16, 16]))
    const requestedCost = costBinding(input.cost)
    const descriptorSnapshot = currentSnapshot(this.descriptorState, input.descriptorSnapshot)
    const current = currentSnapshot(this.descriptorState)
    if (descriptorSnapshot.descriptorSequence !== current.descriptorSequence ||
        !sameBytes(descriptorSnapshot.hash, current.hash)) {
      protocolFailure('SPEND_INVALID', 'admission preflight requires the exact current descriptor')
    }
    const selected = this.profileRecord(descriptorSnapshot, admission.profileId, admission.schemeId,
      { redeemable: true })
    if (!selected || !sameBytes(admission.parameterHash, selected.profile.parameterHash)) {
      protocolFailure('SPEND_INVALID', 'admission profile, scheme, or parameter hash is not current')
    }
    const endpoint = descriptorSnapshot.descriptor.endpoints.find(entry =>
      input.endpoint && entry.endpointId === input.endpoint.endpointId)
    if (!endpoint || input.endpoint.roleBits !== endpoint.roleBits ||
        (selected.record.value.roleBits & endpoint.roleBits) === 0) {
      protocolFailure('SPEND_INVALID', 'admission profile is not bound to the exact selected endpoint')
    }
    const parameters = selected.record.value
    const now = epoch(this.descriptorState)
    if (now < parameters.validFromEpoch || now >= parameters.expiresEpoch ||
        admission.token.byteLength > parameters.tokenMaxBytes) {
      protocolFailure('SPEND_INVALID', 'admission parameters are not redeemable at the current epoch')
    }
    const row = parameters.resourceCosts.find(entry => entry.familyId === operation.familyId &&
      entry.operationId === operation.operationId && entry.resourceClass === requestedCost.resourceClass &&
      entry.leaseClass === requestedCost.leaseClass)
    if (!row) protocolFailure('SPEND_INVALID', 'admission parameters contain no exact resource-cost tuple')
    return Object.freeze({
      operation,
      admission,
      requestId,
      requestCommitment,
      descriptorSequence: descriptorSnapshot.descriptorSequence,
      descriptorHash: b4a.from(descriptorSnapshot.hash),
      endpointId: endpoint.endpointId,
      endpointRoleBits: endpoint.roleBits,
      cost: Object.freeze({
        resourceClass: requestedCost.resourceClass,
        leaseClass: requestedCost.leaseClass,
        costUnits: row.costUnits
      }),
      parameterCanonicalBytes: b4a.from(selected.record.canonicalBytes)
    })
  }

  _revalidatePreflight (binding) {
    const descriptorSnapshot = currentSnapshot(this.descriptorState)
    if (descriptorSnapshot.descriptorSequence !== binding.descriptorSequence ||
        !sameBytes(descriptorSnapshot.hash, binding.descriptorHash) ||
        !this.descriptorState.remainsUsable(descriptorSnapshot)) {
      protocolFailure('SPEND_INVALID', 'admission preflight descriptor advanced across its fence')
    }
    const selected = this.profileRecord(descriptorSnapshot,
      binding.admission.profileId, binding.admission.schemeId, { redeemable: true })
    if (!selected || !sameBytes(selected.profile.parameterHash, binding.admission.parameterHash) ||
        !sameBytes(selected.record.canonicalBytes, binding.parameterCanonicalBytes)) {
      protocolFailure('SPEND_INVALID', 'admission preflight parameter authority changed')
    }
    const endpoint = descriptorSnapshot.descriptor.endpoints.find(entry => entry.endpointId === binding.endpointId)
    if (!endpoint || endpoint.roleBits !== binding.endpointRoleBits ||
        (selected.record.value.roleBits & endpoint.roleBits) === 0) {
      protocolFailure('SPEND_INVALID', 'admission preflight endpoint authority changed')
    }
    const parameters = selected.record.value
    const now = epoch(this.descriptorState)
    if (now < parameters.validFromEpoch || now >= parameters.expiresEpoch ||
        binding.admission.token.byteLength > parameters.tokenMaxBytes) {
      protocolFailure('SPEND_INVALID', 'admission preflight expired before confirmation')
    }
    const row = parameters.resourceCosts.find(entry => entry.familyId === binding.operation.familyId &&
      entry.operationId === binding.operation.operationId &&
      entry.resourceClass === binding.cost.resourceClass && entry.leaseClass === binding.cost.leaseClass)
    if (!row || row.costUnits !== binding.cost.costUnits) {
      protocolFailure('SPEND_INVALID', 'admission preflight cost authority changed')
    }
    return { descriptorSnapshot, endpoint, parameters }
  }

  _adapterPreflightInput (binding, signal, adapterPreflight = null) {
    // mutationAllowed is a contract marker, not a sandbox. Both split adapter
    // methods may validate and prepare owned proof bytes only; they must not
    // contact an issuer, consume a spend, append WAL, publish, or mutate state.
    return {
      admission: {
        profileId: binding.admission.profileId,
        schemeId: binding.admission.schemeId,
        parameterHash: b4a.from(binding.admission.parameterHash),
        token: b4a.from(binding.admission.token)
      },
      familyId: binding.operation.familyId,
      operationId: binding.operation.operationId,
      costClass: Object.freeze({
        resourceClass: binding.cost.resourceClass,
        leaseClass: binding.cost.leaseClass,
        costUnits: binding.cost.costUnits
      }),
      requestCommitment: b4a.from(binding.requestCommitment),
      parameters: decodeExact(binding.parameterCanonicalBytes),
      endpointId: binding.endpointId,
      endpointRoleBits: binding.endpointRoleBits,
      descriptorSequence: binding.descriptorSequence,
      descriptorHash: b4a.from(binding.descriptorHash),
      mutationAllowed: false,
      adapterPreflight,
      signal
    }
  }

  async preparePreflight (input) {
    const signal = input && input.signal
    assertLiveSignal(signal)
    const binding = this._preflightBinding(input)
    if (this.#consumePostEofAuthority == null) {
      protocolFailure('SPEND_INVALID', 'admission preflight is disabled without a post-EOF authority consumer')
    }
    const live = this._revalidatePreflight(binding)
    const adapter = await abortableCall(() => this.resolveAdapter({
      profileId: binding.admission.profileId,
      schemeId: binding.admission.schemeId,
      parameterHash: b4a.from(binding.admission.parameterHash),
      descriptor: live.descriptorSnapshot.descriptor,
      parameters: decodeExact(binding.parameterCanonicalBytes),
      endpointId: binding.endpointId,
      endpointRoleBits: binding.endpointRoleBits,
      signal
    }), signal)
    const adapterReceiver = adapter
    const preparePreflight = adapterReceiver == null ? null : adapterReceiver.preparePreflight
    const confirmAfterEof = adapterReceiver == null ? null : adapterReceiver.confirmAfterEof
    if (typeof preparePreflight !== 'function' || typeof confirmAfterEof !== 'function') {
      protocolFailure('SPEND_INVALID', 'admission adapter has no explicit side-effect-free preflight and confirmation split')
    }
    const adapterPreflight = await abortableCall(() => preparePreflight.call(
      adapterReceiver, this._adapterPreflightInput(binding, signal)), signal)
    if (!opaqueFrozenCapability(adapterPreflight)) {
      protocolFailure('SPEND_INVALID', 'admission adapter returned no empty frozen opaque preflight capability')
    }
    this._revalidatePreflight(binding)
    assertLiveSignal(signal)
    const authority = Object.freeze({})
    PREFLIGHT_AUTHORITIES.set(authority, Object.freeze({
      owner: this,
      binding,
      adapterReceiver,
      confirmAfterEof,
      adapterPreflight
    }))
    return authority
  }

  async confirmAfterEof (authority, input) {
    const retained = authority && PREFLIGHT_AUTHORITIES.get(authority)
    if (!retained || retained.owner !== this) {
      protocolFailure('SPEND_INVALID', 'admission confirmation requires one live branded preflight authority')
    }
    // Every confirmation attempt burns the authority before validating any
    // caller echo or invoking an adapter. Failed substitutions cannot retry it.
    PREFLIGHT_AUTHORITIES.delete(authority)
    const signal = input && input.signal
    assertLiveSignal(signal)
    const echoed = this._preflightBinding(input)
    const binding = retained.binding
    if (!sameOperationBinding(echoed.operation, binding.operation) ||
        !sameAdmissionBinding(echoed.admission, binding.admission) ||
        !sameBytes(echoed.requestId, binding.requestId) ||
        !sameBytes(echoed.requestCommitment, binding.requestCommitment) ||
        echoed.descriptorSequence !== binding.descriptorSequence ||
        !sameBytes(echoed.descriptorHash, binding.descriptorHash) ||
        echoed.endpointId !== binding.endpointId || echoed.endpointRoleBits !== binding.endpointRoleBits ||
        !sameCostBinding(echoed.cost, binding.cost) ||
        !sameBytes(echoed.parameterCanonicalBytes, binding.parameterCanonicalBytes)) {
      protocolFailure('SPEND_INVALID', 'admission confirmation changed its preflight binding')
    }
    this._revalidatePreflight(binding)
    if (this.#consumePostEofAuthority == null) {
      protocolFailure('SPEND_INVALID', 'admission confirmation is disabled without a post-EOF authority consumer')
    }
    if (!opaqueFrozenCapability(input.postEofAuthority)) {
      protocolFailure('SPEND_INVALID', 'post-EOF authority must be an empty frozen daemon-private capability')
    }
    const postEofConsumed = await abortableCall(() => this.#consumePostEofAuthority({
      authority: input.postEofAuthority,
      descriptorSequence: binding.descriptorSequence,
      descriptorHash: b4a.from(binding.descriptorHash),
      endpointId: binding.endpointId,
      familyId: binding.operation.familyId,
      operationId: binding.operation.operationId,
      requestId: b4a.from(binding.requestId),
      requestCommitment: b4a.from(binding.requestCommitment),
      signal
    }), signal)
    if (postEofConsumed !== true) {
      protocolFailure('SPEND_INVALID', 'admission confirmation has no exact consumed post-EOF authority')
    }
    this._revalidatePreflight(binding)
    const prepared = await abortableCall(() => retained.confirmAfterEof.call(
      retained.adapterReceiver,
      this._adapterPreflightInput(binding, signal, retained.adapterPreflight)), signal)
    this._revalidatePreflight(binding)
    assertLiveSignal(signal)
    if (!prepared || typeof prepared !== 'object') {
      protocolFailure('SPEND_INVALID', 'admission adapter returned no confirmed proof')
    }
    const spendTag = asBytes(prepared.spendTag, 'spendTag', [32, 32])
    const requestCommitment = asBytes(prepared.requestCommitment,
      'prepared requestCommitment', [32, 32])
    const parameterHash = asBytes(prepared.parameterHash, 'prepared parameterHash', [32, 32])
    const walCommitRecord = asBytes(prepared.walCommitRecord,
      'walCommitRecord', [1, MAX_WAL_COMMIT_RECORD_BYTES])
    const preparedCost = prepared.costClass
    if (!nonzero(spendTag) || !sameBytes(requestCommitment, binding.requestCommitment) ||
        prepared.profileId !== binding.admission.profileId || prepared.schemeId !== binding.admission.schemeId ||
        !sameBytes(parameterHash, binding.admission.parameterHash) || !preparedCost ||
        preparedCost.resourceClass !== binding.cost.resourceClass ||
        preparedCost.leaseClass !== binding.cost.leaseClass ||
        u64(preparedCost.costUnits, 'prepared costUnits') !== binding.cost.costUnits) {
      protocolFailure('SPEND_INVALID', 'confirmed admission proof changed its exact preflight binding and cost')
    }
    return Object.freeze({
      spendTag: b4a.from(spendTag),
      requestCommitment: b4a.from(requestCommitment),
      costClass: Object.freeze({
        resourceClass: binding.cost.resourceClass,
        leaseClass: binding.cost.leaseClass,
        costUnits: binding.cost.costUnits
      }),
      walCommitRecord: b4a.from(walCommitRecord),
      profileId: binding.admission.profileId,
      schemeId: binding.admission.schemeId,
      parameterHash: b4a.from(binding.admission.parameterHash)
    })
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
