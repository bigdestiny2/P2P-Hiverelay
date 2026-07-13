import b4a from 'b4a'
import {
  ADMISSION_MODE,
  DISPATCH_LIMITS,
  ERROR_CODE,
  ERROR_PROFILE_ID,
  FAMILY,
  FRAME_KIND,
  OPERATION,
  OUTER_CLASS,
  OUTER_ENVELOPE_HEADER_BYTES,
  STORE_LIFECYCLE_STATE,
  STREAM_TRANSITION,
  TRANSPORT_SUPPORT,
  blindErrorV1,
  decodeCanonical,
  decodeDispatchFrame,
  encodeCanonical,
  encodeDispatchFrame,
  errorProfileEntry
} from '@hiverelay/blind-protocol'
import { READINESS_STATE_KIND } from './readiness-coordinator.js'
import { assertPrecommitCellPutResultFitV2 } from '@hiverelay/blind-ipc/private-ipc-v2-contract'
import {
  admissionFromRequest,
  assertOperationBodyRelation,
  daemonOperationProfile,
  deriveAdmissionCost,
  operationRequestCommitment,
  requestCommitmentFromResult,
  requestNonceFromResult,
  resultBindingFromValue,
  sameBytes
} from './operation-catalog.js'
import {
  DescriptorStateError,
  assertRelayResultBinding
} from './descriptor-state.js'
import { stagedCellPutAuthority } from './staged-put.js'
import { isCommittedCellResult } from './cell-runtime-adapter.js'
import { isCommittedInboxResult } from './inbox-runtime-adapter.js'

const MAX_U64 = (1n << 64n) - 1n
const ORDINARY_DEADLINE_MILLIS = 15_000n
const INBOX_DEADLINE_MILLIS = 35_000n
const WATCH_RESPONSE_RESERVE_MILLIS = 2_000n
const MAX_AUTHENTICATED_SESSION_CONTEXT_BYTES = 64 * 1024
const KNOWN_TRANSPORT_SUPPORT_BITS = TRANSPORT_SUPPORT.DIRECT_HTTP | TRANSPORT_SUPPORT.DIRECT_NATIVE |
  TRANSPORT_SUPPORT.OHTTP | TRANSPORT_SUPPORT.TOR_HTTP | TRANSPORT_SUPPORT.TOR_NATIVE |
  TRANSPORT_SUPPORT.MASQUE_NATIVE
const VERIFIED_SESSION_HANDLES = new WeakSet()
const STAGED_CELL_PUT_CONTEXT = Symbol('staged CELL.PUT context')

export const COORDINATOR_RELEASE_BLOCKERS = Object.freeze({})

const PROFILE2_WITNESS_ALWAYS = new Set([
  `${FAMILY.CELL}:${OPERATION.CELL.PUT}`,
  `${FAMILY.CELL}:${OPERATION.CELL.RENEW}`,
  `${FAMILY.CELL}:${OPERATION.CELL.DROP}`,
  `${FAMILY.INBOX}:${OPERATION.INBOX.CREATE}`,
  `${FAMILY.INBOX}:${OPERATION.INBOX.RENEW}`,
  `${FAMILY.INBOX}:${OPERATION.INBOX.CLOSE}`,
  `${FAMILY.INBOX}:${OPERATION.INBOX.APPEND}`,
  `${FAMILY.INBOX}:${OPERATION.INBOX.WATCH}`,
  `${FAMILY.CORE}:${OPERATION.CORE.MIRROR}`,
  `${FAMILY.CORE}:${OPERATION.CORE.OPEN_REPLICATION}`,
  `${FAMILY.FORWARD}:${OPERATION.FORWARD.OPEN}`
])

const PROFILE2_WITNESS_IF_ADMITTED = new Set([
  `${FAMILY.CELL}:${OPERATION.CELL.PROVE}`,
  `${FAMILY.CELL}:${OPERATION.CELL.BATCH_GET}`,
  `${FAMILY.INBOX}:${OPERATION.INBOX.READ}`,
  `${FAMILY.CORE}:${OPERATION.CORE.PROVE}`
])

function protocolFailure (code, message, fields = {}) {
  const error = new Error(message)
  error.code = code
  Object.assign(error, fields)
  throw error
}

function asBytes (value, field, minimum = null, maximum = null) {
  if (!value || typeof value.byteLength !== 'number') protocolFailure('BAD_ENCODING', `${field} must be bytes`)
  const bytes = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if ((minimum != null && bytes.byteLength < minimum) || (maximum != null && bytes.byteLength > maximum)) {
    protocolFailure('BAD_ENCODING', `${field} is outside its byte bound`)
  }
  return bytes
}

function asU64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) protocolFailure('BAD_ENCODING', `${field} is invalid`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
    protocolFailure('BAD_ENCODING', `${field} is outside u64`)
  }
  return value
}

function checkedAdd (left, right, field) {
  left = asU64(left, field)
  right = asU64(right, field)
  if (left > MAX_U64 - right) protocolFailure('BAD_ENCODING', `${field} overflows u64`)
  return left + right
}

function minimum (...values) {
  return values.reduce((result, value) => value < result ? value : result)
}

function exactTransportSupportBit (value) {
  if (!Number.isInteger(value) || value === 0 || (value & (value - 1)) !== 0 ||
      (value & ~KNOWN_TRANSPORT_SUPPORT_BITS) !== 0) {
    protocolFailure('TRANSPORT_UNSUPPORTED', 'authenticated transport context has no exact frozen support bit')
  }
  return value
}

function clonePlain (value, field = 'hook value', depth = 0) {
  if (depth > 32) protocolFailure('INTERNAL', `${field} exceeds the closed hook depth`)
  if (value === undefined || value == null || typeof value === 'string' || typeof value === 'boolean' ||
      typeof value === 'number' || typeof value === 'bigint') return value
  if (value && typeof value.byteLength === 'number') return b4a.from(asBytes(value, field))
  if (Array.isArray(value)) return Object.freeze(value.map((entry, index) => clonePlain(entry, `${field}[${index}]`, depth + 1)))
  if (typeof value !== 'object' || (Object.getPrototypeOf(value) !== Object.prototype &&
      Object.getPrototypeOf(value) !== null)) {
    protocolFailure('INTERNAL', `${field} is not a closed plain value`)
  }
  const output = {}
  for (const [key, entry] of Object.entries(value)) output[key] = clonePlain(entry, `${field}.${key}`, depth + 1)
  return Object.freeze(output)
}

export function deriveOperationDeadline (profile, request, context, dispatchMonotonicMillis) {
  const accepted = asU64(context.acceptedMonotonicMillis, 'acceptedMonotonicMillis')
  const outerDeadline = asU64(context.absoluteDeadlineMonotonicMillis, 'absoluteDeadlineMonotonicMillis')
  const now = asU64(dispatchMonotonicMillis, 'dispatchMonotonicMillis')
  if (accepted > now || outerDeadline <= now || outerDeadline <= accepted) {
    protocolFailure('BAD_ENCODING', 'request monotonic deadline is future, elapsed, or inverted')
  }
  const familyCap = profile.familyId === FAMILY.INBOX ? INBOX_DEADLINE_MILLIS : ORDINARY_DEADLINE_MILLIS
  if (outerDeadline > checkedAdd(accepted, familyCap, 'family deadline')) {
    protocolFailure('BAD_ENCODING', 'request monotonic deadline exceeds its family cap')
  }
  let effectiveDeadline = minimum(outerDeadline, checkedAdd(accepted, ORDINARY_DEADLINE_MILLIS, 'operation deadline'))
  let waiterDeadline = null
  if (profile.familyId === FAMILY.INBOX && profile.operationId === OPERATION.INBOX.WATCH) {
    effectiveDeadline = minimum(
      outerDeadline,
      checkedAdd(accepted, BigInt(request.maxWaitMillis) + 5_000n, 'watch deadline'),
      checkedAdd(accepted, INBOX_DEADLINE_MILLIS, 'inbox deadline')
    )
    const responseFloor = effectiveDeadline > WATCH_RESPONSE_RESERVE_MILLIS
      ? effectiveDeadline - WATCH_RESPONSE_RESERVE_MILLIS
      : 0n
    waiterDeadline = minimum(
      checkedAdd(now, BigInt(request.maxWaitMillis), 'watch waiter deadline'),
      responseFloor
    )
    if (waiterDeadline <= now) waiterDeadline = now
  }
  return Object.freeze({ acceptedMonotonicMillis: accepted, effectiveDeadline, waiterDeadline })
}

function deadlineSignal (parent, deadline, now) {
  const remaining = deadline > now ? deadline - now : 0n
  const timeout = AbortSignal.timeout(Math.max(1, Number(remaining)))
  return parent ? AbortSignal.any([parent, timeout]) : timeout
}

async function waitForSignalBoundPromise (value, signal) {
  if (!value || typeof value.then !== 'function') {
    protocolFailure('INTERNAL', 'staged CELL.PUT has no same-stream PostEOF promise')
  }
  if (signal.aborted) protocolFailure('INTERNAL', 'staged CELL.PUT crossed its abort fence')
  let onAbort
  const aborted = new Promise((resolve, reject) => {
    onAbort = () => {
      const error = new Error('staged CELL.PUT crossed its abort fence')
      error.code = 'ABORT_ERR'
      reject(error)
    }
    signal.addEventListener('abort', onAbort, { once: true })
  })
  try {
    return await Promise.race([value, aborted])
  } finally {
    signal.removeEventListener('abort', onAbort)
  }
}

function validateEndpoint (profile, context, descriptorSnapshot) {
  const descriptor = descriptorSnapshot.descriptor
  const endpoint = descriptor.endpoints.find(entry => entry.endpointId === context.endpointId)
  if (!endpoint || endpoint.transportId !== context.transportId) {
    protocolFailure('TRANSPORT_UNSUPPORTED', 'request does not match an authenticated descriptor endpoint')
  }
  const supportBit = exactTransportSupportBit(context.transportSupportBit)
  if (endpoint.transportSupportBit != null && endpoint.transportSupportBit !== supportBit) {
    protocolFailure('TRANSPORT_UNSUPPORTED', 'authenticated adapter support does not match the signed endpoint')
  }
  if ((profile.transportSupportBits & supportBit) === 0) {
    protocolFailure('TRANSPORT_UNSUPPORTED', 'operation is unsupported by the authenticated transport adapter')
  }
  if (context.outerClass != null) {
    if (!Number.isInteger(context.outerClass) || !OUTER_CLASS[context.outerClass] ||
        (endpoint.envelopeClassBits & (1 << context.outerClass)) === 0) {
      protocolFailure('TRANSPORT_UNSUPPORTED', 'request outer class is not enabled on the endpoint')
    }
  }
  return { endpoint, supportBit }
}

function authorizationError (profile) {
  if ((profile.familyId === FAMILY.CELL && profile.operationId === OPERATION.CELL.PUT) ||
      (profile.familyId === FAMILY.INBOX && profile.operationId === OPERATION.INBOX.CREATE)) return 'BAD_CREATE_SIG'
  if ((profile.familyId === FAMILY.CELL &&
       (profile.operationId === OPERATION.CELL.RENEW || profile.operationId === OPERATION.CELL.DROP)) ||
      (profile.familyId === FAMILY.INBOX &&
       (profile.operationId === OPERATION.INBOX.RENEW || profile.operationId === OPERATION.INBOX.CLOSE)) ||
      profile.familyId === FAMILY.FORWARD) return 'BAD_MANAGEMENT_SIG'
  return 'NOT_FOUND'
}

function criticalOperation (profile) {
  if (profile.familyId === FAMILY.DESCRIBE) return true
  if (profile.familyId === FAMILY.CELL) {
    return profile.operationId === OPERATION.CELL.RENEW || profile.operationId === OPERATION.CELL.DROP
  }
  if (profile.familyId === FAMILY.INBOX) {
    return profile.operationId === OPERATION.INBOX.RENEW || profile.operationId === OPERATION.INBOX.CLOSE
  }
  return false
}

function safeError (error, effectiveEpochFloor = 0) {
  let codeName = error && typeof error.code === 'string' && ERROR_CODE[error.code] ? error.code : 'INTERNAL'
  if (error instanceof DescriptorStateError) codeName = 'INTERNAL'
  const code = ERROR_CODE[codeName]
  const profile = errorProfileEntry(ERROR_PROFILE_ID.CANONICAL_V1, code)
  let retryAfterEpoch = null
  if (codeName === 'RENEW_NOT_DUE' && Number.isInteger(error.retryAfterEpoch) &&
      error.retryAfterEpoch > effectiveEpochFloor && error.retryAfterEpoch <= 0xffffffff) {
    retryAfterEpoch = error.retryAfterEpoch
  } else if (profile.retryAfterMode === 1) {
    codeName = 'INTERNAL'
  }
  const resolvedCode = ERROR_CODE[codeName]
  const resolvedProfile = errorProfileEntry(ERROR_PROFILE_ID.CANONICAL_V1, resolvedCode)
  return {
    version: 1,
    code: resolvedCode,
    retryable: resolvedProfile.retryable,
    retryAfterEpoch: resolvedProfile.retryAfterMode === 1 ? retryAfterEpoch : null
  }
}

function errorDispatch (request, error, effectiveEpochFloor) {
  return encodeDispatchFrame({
    frameKind: FRAME_KIND.ERROR,
    familyId: request.familyId,
    operationId: request.operationId,
    requestId: request.requestId,
    streamId: 0n,
    sequence: 0n,
    body: encodeCanonical(blindErrorV1, safeError(error, effectiveEpochFloor))
  })
}

function requestAuthority (profile, body) {
  if (body.byteLength === 0) protocolFailure('BAD_ENCODING', 'request body is empty')
  if (body[0] !== 1) protocolFailure('BAD_VERSION', 'operation body version must be 1')
  let value
  try {
    value = decodeCanonical(profile.requestCodec, body, { copyBytes: true })
    if (!sameBytes(body, encodeCanonical(profile.requestCodec, value))) throw new Error('non-canonical')
    assertOperationBodyRelation(profile, value)
  } catch (error) {
    if (error && typeof error.code === 'string') throw error
    protocolFailure('BAD_ENCODING', 'operation body is not canonical')
  }
  return b4a.from(body)
}

function compactUintPrefix (body, offset, minimum, maximum, field) {
  if (offset >= body.byteLength) protocolFailure('BAD_ENCODING', `truncated ${field}`)
  const marker = body[offset++]
  let value
  if (marker <= 0xfc) {
    value = marker
  } else if (marker === 0xfd) {
    if (offset + 2 > body.byteLength) protocolFailure('BAD_ENCODING', `truncated ${field}`)
    value = body[offset] | (body[offset + 1] << 8)
    offset += 2
    if (value <= 0xfc) protocolFailure('BAD_ENCODING', `${field} is not canonical`)
  } else if (marker === 0xfe) {
    if (offset + 4 > body.byteLength) protocolFailure('BAD_ENCODING', `truncated ${field}`)
    value = body[offset] + body[offset + 1] * 0x100 + body[offset + 2] * 0x10000 +
      body[offset + 3] * 0x1000000
    offset += 4
    if (value <= 0xffff) protocolFailure('BAD_ENCODING', `${field} is not canonical`)
  } else {
    // Every count or byte string before an optional admission is capped far
    // below u32. Refuse the nine-byte form without reading or allocating from
    // an attacker-controlled declared length.
    protocolFailure('BAD_ENCODING', `${field} exceeds its canonical bound`)
  }
  if (value < minimum || value > maximum) {
    protocolFailure('BAD_ENCODING', `${field} is outside ${minimum}..${maximum}`)
  }
  return { value, offset }
}

function requirePrefixSpan (body, offset, length, field) {
  if (!Number.isSafeInteger(length) || length < 0 || offset + length > body.byteLength) {
    protocolFailure('BAD_ENCODING', `truncated ${field}`)
  }
  return offset + length
}

function optionalAdmissionTagOffset (profile, body) {
  let offset
  if (profile.familyId === FAMILY.CELL &&
      (profile.operationId === OPERATION.CELL.GET || profile.operationId === OPERATION.CELL.PROVE)) {
    offset = requirePrefixSpan(body, 0, 1 + 32 + 32, 'CELL read prefix')
  } else if (profile.familyId === FAMILY.CELL && profile.operationId === OPERATION.CELL.BATCH_GET) {
    offset = requirePrefixSpan(body, 0, 1 + 32, 'CELL batch prefix')
    const count = compactUintPrefix(body, offset, 1, 64, 'CELL batch slot count')
    offset = requirePrefixSpan(body, count.offset, count.value * 32, 'CELL batch slots')
  } else if (profile.familyId === FAMILY.INBOX && profile.operationId === OPERATION.INBOX.READ) {
    offset = requirePrefixSpan(body, 0, 1 + 32, 'INBOX read prefix')
    const cursor = compactUintPrefix(body, offset, 0, 128, 'INBOX cursor length')
    offset = requirePrefixSpan(body, cursor.offset, cursor.value + 2 + 32, 'INBOX read fields')
  } else if (profile.familyId === FAMILY.CORE && profile.operationId === OPERATION.CORE.PROVE) {
    offset = requirePrefixSpan(body, 0, 1 + 32 + 8 + 8 + 32, 'CORE proof prefix')
    const count = compactUintPrefix(body, offset, 1, 16, 'CORE block-index count')
    offset = requirePrefixSpan(body, count.offset, count.value * 8 + 32, 'CORE proof fields')
  } else {
    protocolFailure('INTERNAL', 'optional-admission operation has no frozen prefix parser')
  }
  if (offset >= body.byteLength) protocolFailure('BAD_ENCODING', 'truncated admission presence tag')
  if (body[offset] !== 0 && body[offset] !== 1) {
    protocolFailure('BAD_ENCODING', 'admission presence tag must be 0 or 1')
  }
  return offset
}

// Validate every canonical field before an optional admission without touching
// its length or token bytes. This is the DRAINING lifecycle authority: a token
// may be deliberately malformed after a present tag and must still be rejected
// as BUSY before the admission parser or verifier is reached.
export function preparseOptionalAdmissionPresence (profile, input) {
  if (!profile || profile.admissionMode !== ADMISSION_MODE.OPTIONAL) {
    protocolFailure('INTERNAL', 'optional admission pre-parser requires an OPTIONAL operation')
  }
  const body = asBytes(input, 'request body')
  if (body.byteLength === 0) protocolFailure('BAD_ENCODING', 'request body is empty')
  if (body[0] !== 1) protocolFailure('BAD_VERSION', 'operation body version must be 1')
  const tagOffset = optionalAdmissionTagOffset(profile, body)
  const prefix = b4a.from(body.subarray(0, tagOffset + 1))
  const present = prefix[prefix.byteLength - 1] === 1
  prefix[prefix.byteLength - 1] = 0
  try {
    const value = decodeCanonical(profile.requestCodec, prefix, { copyBytes: true })
    if (!sameBytes(prefix, encodeCanonical(profile.requestCodec, value))) throw new Error('non-canonical')
    assertOperationBodyRelation(profile, value)
  } catch (error) {
    if (error && typeof error.code === 'string') throw error
    protocolFailure('BAD_ENCODING', 'operation prefix before admission is not canonical')
  }
  return present
}

function decodeRequest (authority) {
  if (authority.requestValue != null) return clonePlain(authority.requestValue, 'staged request')
  return decodeCanonical(authority.profile.requestCodec, authority.requestBytes, { copyBytes: true })
}

function frameCopy (frame, body = frame.body) {
  return Object.freeze({
    version: frame.version,
    frameKind: frame.frameKind,
    familyId: frame.familyId,
    operationId: frame.operationId,
    flags: frame.flags,
    requestId: b4a.from(frame.requestId),
    streamId: frame.streamId,
    sequence: frame.sequence,
    body: b4a.from(body)
  })
}

function normalizeResult (profile, raw) {
  const candidate = raw && typeof raw === 'object' && raw.body != null ? raw.body : raw
  let body
  let value
  if (candidate && typeof candidate.byteLength === 'number') {
    body = b4a.from(asBytes(candidate, 'operation result'))
    try {
      value = decodeCanonical(profile.resultCodec, body, { copyBytes: true })
      if (!sameBytes(body, encodeCanonical(profile.resultCodec, value))) throw new Error('non-canonical')
    } catch {
      protocolFailure('INTERNAL', 'operation executor returned non-canonical result bytes')
    }
  } else {
    try {
      body = encodeCanonical(profile.resultCodec, candidate)
      value = decodeCanonical(profile.resultCodec, body, { copyBytes: true })
    } catch {
      protocolFailure('INTERNAL', 'operation executor returned an invalid result value')
    }
  }
  const executorStreamId = raw && typeof raw === 'object' && raw.streamId != null
    ? asU64(raw.streamId, 'executor streamId')
    : null
  return Object.freeze({
    body: b4a.from(body),
    value,
    executorStreamId,
    committedStoreResult: isCommittedCellResult(raw) || isCommittedInboxResult(raw)
  })
}

function committedStoreBindingSnapshot (descriptorState, authoritySnapshot, binding) {
  if (!binding || !binding.descriptorHash) {
    protocolFailure('INTERNAL', 'committed store result has no persisted descriptor binding')
  }
  const historical = descriptorState.selected(binding.descriptorHash)
  if (!historical || historical.descriptorSequence !== binding.descriptorSequence ||
      historical.lifecycleFence !== authoritySnapshot.lifecycleFence) {
    protocolFailure('INTERNAL', 'committed store result binding is not retained under the active lifecycle fence')
  }
  const active = authoritySnapshot.descriptor
  const committed = historical.descriptor
  if (!sameBytes(active.relayPublicKey, committed.relayPublicKey) ||
      !sameBytes(active.storeId, committed.storeId) ||
      !sameBytes(active.durabilityContinuityHash, committed.durabilityContinuityHash) ||
      active.durability.profileId !== committed.durability.profileId) {
    protocolFailure('INTERNAL', 'committed store result crossed relay, store, continuity, or durability authority')
  }
  return historical
}

function responseStreamId (profile, value, executorStreamId) {
  if (profile.streamTransition !== STREAM_TRANSITION.CORE_CHILD &&
      profile.streamTransition !== STREAM_TRANSITION.FORWARD_OPEN) return 0n
  const valueId = asU64(value.streamId, 'result streamId')
  if (valueId === 0n) protocolFailure('INTERNAL', 'stream-opening result has a zero streamId')
  if (executorStreamId != null && executorStreamId !== valueId) {
    protocolFailure('INTERNAL', 'executor streamId does not match its canonical result')
  }
  return valueId
}

function outerBodyCapacity (outerClass) {
  if (outerClass == null) return Number.MAX_SAFE_INTEGER
  const bytes = OUTER_CLASS[outerClass]
  if (!bytes) protocolFailure('TRANSPORT_UNSUPPORTED', 'unknown outer response class')
  return bytes - OUTER_ENVELOPE_HEADER_BYTES - DISPATCH_LIMITS.PREFIX_BYTES - DISPATCH_LIMITS.HEADER_BYTES
}

function assertOuterFit (dispatchBytes, outerClass) {
  if (outerClass != null && OUTER_ENVELOPE_HEADER_BYTES + dispatchBytes.byteLength > OUTER_CLASS[outerClass]) {
    protocolFailure('TOO_LARGE', 'canonical response does not fit the selected outer class')
  }
}

function predictedResultBytes (authenticatedState, profile, descriptor, outerClass) {
  const value = authenticatedState && authenticatedState.predictedResultBodyBytes != null
    ? authenticatedState.predictedResultBodyBytes
    : null
  if (value == null) return null
  if (!Number.isSafeInteger(value) || value < 1 || value > profile.maxResultBodyBytes ||
      value > descriptor.maxResponseBytes || value > outerBodyCapacity(outerClass)) {
    protocolFailure('TOO_LARGE', 'authenticated predicted result does not fit the response bounds')
  }
  return value
}

function responseReservationBytes (profile, descriptor, outerClass, predictedBytes) {
  if (predictedBytes != null) return predictedBytes + DISPATCH_LIMITS.PREFIX_BYTES + DISPATCH_LIMITS.HEADER_BYTES
  return Math.min(profile.maxResultBodyBytes, descriptor.maxResponseBytes, outerBodyCapacity(outerClass)) +
    DISPATCH_LIMITS.PREFIX_BYTES + DISPATCH_LIMITS.HEADER_BYTES
}

export function profile2WitnessRequired (profile, admissionPresent) {
  const key = `${profile.familyId}:${profile.operationId}`
  return PROFILE2_WITNESS_ALWAYS.has(key) || (admissionPresent && PROFILE2_WITNESS_IF_ADMITTED.has(key))
}

export function assertResultWitnessPolicy (profile, relayBinding, durabilityProfileId, admissionPresent) {
  const witness = relayBinding && relayBinding.externalCommitWitness
  if (durabilityProfileId === 1) {
    if (witness != null) protocolFailure('INTERNAL', 'durability profile 1 forbids an external commit witness')
    return false
  }
  const required = profile2WitnessRequired(profile, admissionPresent)
  if (required !== (witness != null)) {
    protocolFailure('INTERNAL', 'profile-2 result witness presence violates the closed operation table')
  }
  return required
}

function assertWitnessBase (witness, profile, requestCommitment) {
  if (!witness) return
  if (witness.familyId !== profile.familyId || witness.operationId !== profile.operationId ||
      !requestCommitment || !sameBytes(witness.requestCommitment, requestCommitment)) {
    protocolFailure('INTERNAL', 'external witness does not bind the exact operation request')
  }
}

function canonicalStreamFrame (bytes, terminal) {
  bytes = b4a.from(asBytes(bytes, 'stream disposition dispatch'))
  let frame
  try {
    frame = decodeDispatchFrame(bytes, { copyBody: true })
    if (!sameBytes(bytes, encodeDispatchFrame(frame))) throw new Error('non-canonical')
    const profile = daemonOperationProfile(frame.familyId, frame.operationId)
    if (!profile || profile.streamTransition !== STREAM_TRANSITION.FORWARD_ACTIVE) throw new Error('not active')
    const value = decodeCanonical(profile.requestCodec, frame.body, { copyBytes: true })
    if (!sameBytes(frame.body, encodeCanonical(profile.requestCodec, value))) throw new Error('body')
  } catch {
    protocolFailure('INTERNAL', 'stream service returned a non-canonical active frame')
  }
  if (frame.frameKind !== FRAME_KIND.STREAM || frame.familyId !== FAMILY.FORWARD ||
      (terminal && frame.operationId !== OPERATION.FORWARD.CLOSE)) {
    protocolFailure('INTERNAL', 'stream disposition kind does not match its canonical frame')
  }
  return bytes
}

function normalizeStreamDisposition (raw) {
  if (!raw || typeof raw !== 'object') protocolFailure('INTERNAL', 'stream service returned no closed disposition')
  if (raw.kind === 'consumed' && raw.dispatch == null) {
    return Object.freeze({ kind: 'consumed', dispatch: null })
  }
  if (raw.kind === 'outbound') {
    return Object.freeze({ kind: 'outbound', dispatch: canonicalStreamFrame(raw.dispatch, false) })
  }
  if (raw.kind === 'terminal') {
    return Object.freeze({ kind: 'terminal', dispatch: canonicalStreamFrame(raw.dispatch, true) })
  }
  protocolFailure('INTERNAL', 'stream service returned an unknown or ambiguous disposition')
}

export class BlindOperationCoordinator {
  constructor (options = {}) {
    for (const field of ['descriptorState', 'admission', 'readiness', 'budget']) {
      if (!options[field]) throw new TypeError(`${field} is required`)
    }
    for (const [field, method] of [
      ['operationExecutor', 'execute'],
      ['capabilityVerifier', 'verify'],
      ['cheapStateVerifier', 'inspect'],
      ['terminalStateVerifier', 'check'],
      ['capacityGuard', 'check'],
      ['resultVerifier', 'verify'],
      ['authenticatedSessionVerifier', 'verify']
    ]) {
      if (!options[field] || typeof options[field][method] !== 'function') {
        throw new TypeError(`${field}.${method} is required`)
      }
    }
    this.descriptorState = options.descriptorState
    this.admission = options.admission
    this.readiness = options.readiness
    this.budget = options.budget
    this.operationExecutor = options.operationExecutor
    this.capabilityVerifier = options.capabilityVerifier
    this.relationVerifier = options.relationVerifier || { verify: async () => true }
    this.cheapStateVerifier = options.cheapStateVerifier
    this.terminalStateVerifier = options.terminalStateVerifier
    this.capacityGuard = options.capacityGuard
    this.resultVerifier = options.resultVerifier
    this.authenticatedSessionVerifier = options.authenticatedSessionVerifier
    this.transactionCoordinator = options.transactionCoordinator || null
    this.streamExecutor = options.streamExecutor || null
    this.resultBindingSnapshot = typeof options.resultBindingSnapshot === 'function'
      ? options.resultBindingSnapshot
      : async () => ({ restoreEvidenceHeadSequence: 0n, restoreEvidenceHeadHash: b4a.alloc(32) })
    this.monotonicMillis = typeof options.monotonicMillis === 'function'
      ? options.monotonicMillis
      : () => process.hrtime.bigint() / 1_000_000n
    this.maxAuthenticatedSessionContextBytes = options.maxAuthenticatedSessionContextBytes == null
      ? MAX_AUTHENTICATED_SESSION_CONTEXT_BYTES
      : options.maxAuthenticatedSessionContextBytes
    if (!Number.isSafeInteger(this.maxAuthenticatedSessionContextBytes) ||
        this.maxAuthenticatedSessionContextBytes < 1 ||
        this.maxAuthenticatedSessionContextBytes > MAX_AUTHENTICATED_SESSION_CONTEXT_BYTES) {
      throw new TypeError('maxAuthenticatedSessionContextBytes is outside 1..64KiB')
    }
    asU64(this.monotonicMillis(), 'monotonicMillis')
  }

  _hookContext (authority, extras = {}) {
    const descriptorSnapshot = this.descriptorState.selected(authority.descriptorHash)
    if (!descriptorSnapshot) protocolFailure('INTERNAL', 'operation descriptor snapshot is no longer retained')
    const endpoint = descriptorSnapshot.descriptor.endpoints.find(entry => entry.endpointId === authority.endpointId)
    if (!endpoint) protocolFailure('INTERNAL', 'operation endpoint is absent from its descriptor snapshot')
    return Object.freeze({
      profile: authority.profile,
      request: decodeRequest(authority),
      requestFrame: frameCopy(authority.frame, authority.requestBytes),
      descriptorSnapshot,
      descriptor: descriptorSnapshot.descriptor,
      endpoint: clonePlain(endpoint, 'endpoint'),
      transportSupportBit: authority.transportSupportBit,
      adjacentRelayKey: authority.adjacentRelayKey == null ? null : b4a.from(authority.adjacentRelayKey),
      acceptedMonotonicMillis: authority.timing.acceptedMonotonicMillis,
      effectiveDeadlineMonotonicMillis: authority.timing.effectiveDeadline,
      waiterDeadlineMonotonicMillis: authority.timing.waiterDeadline,
      signal: authority.signal,
      ...clonePlain(extras, 'hook context')
    })
  }

  _checkDeadline (authority) {
    const now = asU64(this.monotonicMillis(), 'monotonicMillis')
    if (authority.signal.aborted || now >= authority.timing.effectiveDeadline ||
        !this.descriptorState.remainsUsable(this.descriptorState.selected(authority.descriptorHash))) {
      protocolFailure('INTERNAL', 'operation crossed its deadline or descriptor lifecycle fence')
    }
    return now
  }

  async _verifiedSession (authority, context) {
    if (authority.profile.streamTransition !== STREAM_TRANSITION.CORE_CHILD &&
        authority.profile.streamTransition !== STREAM_TRANSITION.FORWARD_OPEN) return null
    let canonicalBytes
    try {
      canonicalBytes = b4a.from(asBytes(context.authenticatedSessionContextBytes,
        'authenticatedSessionContextBytes', 1, this.maxAuthenticatedSessionContextBytes))
    } catch {
      protocolFailure('TRANSPORT_UNSUPPORTED', 'stream OPEN has no bounded authenticated session context')
    }
    let handle
    try {
      handle = await this.authenticatedSessionVerifier.verify({
        canonicalBytes: b4a.from(canonicalBytes),
        canonicalRequestBytes: b4a.from(authority.requestBytes),
        familyId: authority.profile.familyId,
        operationId: authority.profile.operationId,
        endpointId: authority.endpointId,
        transportSupportBit: authority.transportSupportBit,
        descriptorSequence: authority.descriptorSequence,
        descriptorHash: b4a.from(authority.descriptorHash),
        signal: authority.signal
      })
    } catch {
      protocolFailure('TRANSPORT_UNSUPPORTED', 'authenticated stream session verification failed')
    }
    if (!handle || typeof handle !== 'object' || !Object.isFrozen(handle)) {
      protocolFailure('TRANSPORT_UNSUPPORTED', 'session verifier returned no immutable closed handle')
    }
    VERIFIED_SESSION_HANDLES.add(handle)
    this._checkDeadline(authority)
    return handle
  }

  async dispatchStagedCellPut (input, context = {}) {
    const staged = stagedCellPutAuthority(input)
    if (context.outerClass == null) {
      protocolFailure('BAD_ENCODING', 'staged CELL.PUT requires a non-null authenticated outer class')
    }
    let bodyValidationRequired = true
    try {
      assertPrecommitCellPutResultFitV2(context.outerClass)
    } catch {
      // Preserve the class-2 precommit defence: dispatch owns its canonical
      // TOO_LARGE result, but no opaque body may be pulled for that result.
      bodyValidationRequired = false
    }
    const abort = new Error('staged CELL.PUT dispatch no longer accepts body bytes')
    abort.code = 'ABORT_ERR'
    try {
      const result = await this.dispatch(null, { ...context, [STAGED_CELL_PUT_CONTEXT]: staged })
      // A canonical error discovered from the bounded request prefix must not
      // abort the producer and turn that error into a socket close. Discard the
      // queued body while ingress continues its exact length/hash validation;
      // only then may the original correlated result be released.
      if (bodyValidationRequired) await staged.ensureBodyValidated()
      return result
    } finally {
      staged.abort(abort)
    }
  }

  async dispatch (inputFrame, context = {}) {
    let request
    let effectiveEpochFloor = 0
    let activeStream = false
    try {
      const stagedPut = context[STAGED_CELL_PUT_CONTEXT] || null
      let profile
      if (stagedPut) {
        request = Object.freeze({
          ...stagedPut.frame,
          body: b4a.from(stagedPut.canonicalRequestPrefixBytes)
        })
        profile = daemonOperationProfile(request.familyId, request.operationId)
        try {
          assertPrecommitCellPutResultFitV2(context.outerClass)
        } catch {
          protocolFailure('TOO_LARGE', 'staged CELL.PUT worst-case result does not fit its authenticated outer class')
        }
      } else {
        const rawProfile = inputFrame && daemonOperationProfile(inputFrame.familyId, inputFrame.operationId)
        const rawBody = inputFrame && inputFrame.body
        if (rawProfile && rawBody && typeof rawBody.byteLength === 'number' &&
            rawBody.byteLength > rawProfile.maxRequestBodyBytes) {
          protocolFailure('TOO_LARGE', 'request exceeds operation cap')
        }
        request = decodeDispatchFrame(encodeDispatchFrame(inputFrame), { copyBody: true })
        profile = daemonOperationProfile(request.familyId, request.operationId)
      }
      if (!profile || (request.frameKind !== FRAME_KIND.REQUEST && request.frameKind !== FRAME_KIND.STREAM)) {
        protocolFailure('BAD_ENCODING', 'coordinator accepts only registered request and stream frames')
      }
      const requestBodyBytes = stagedPut ? stagedPut.frame.bodyLength : request.body.byteLength
      if (requestBodyBytes > profile.maxRequestBodyBytes) protocolFailure('TOO_LARGE', 'request exceeds operation cap')
      const isActiveStream = profile.streamTransition === STREAM_TRANSITION.FORWARD_ACTIVE
      if (isActiveStream) activeStream = true
      if (isActiveStream && request.frameKind !== FRAME_KIND.STREAM) {
        const error = new Error('active FORWARD operation must use a stream frame')
        error.code = 'BAD_ENCODING'
        return await this._dispatchActiveStream(request, request.body, context, error)
      }
      if (!isActiveStream && profile.admissionMode === ADMISSION_MODE.OPTIONAL) {
        // A synchronous descriptor snapshot is enough to establish the signed
        // DRAINING fence for this dispatch turn. Only under that fence do we
        // invoke the bounded prefix authority before the full request decoder.
        // ACTIVE requests retain the frozen full-canonical-decode precedence.
        let earlySnapshot = null
        try { earlySnapshot = this.descriptorState.requireCurrent() } catch {}
        if (earlySnapshot && earlySnapshot.descriptor.storeLifecycleState === STORE_LIFECYCLE_STATE.DRAINING) {
          const admissionPresent = preparseOptionalAdmissionPresence(profile, request.body)
          const enabled = (earlySnapshot.descriptor.enabledOperationBits & profile.operationBit) !== 0
          if (!enabled) protocolFailure('BUSY', 'operation is disabled by the DRAINING lifecycle fence')
          if (admissionPresent) protocolFailure('BUSY', 'DRAINING permits this operation only without admission')
        }
      }
      let canonicalRequestBytes
      try {
        canonicalRequestBytes = stagedPut
          ? b4a.from(stagedPut.canonicalRequestPrefixBytes)
          : requestAuthority(profile, request.body)
      } catch (error) {
        if (!isActiveStream) throw error
        return await this._dispatchActiveStream(request, request.body, context, error)
      }
      if (isActiveStream) return await this._dispatchActiveStream(request, canonicalRequestBytes, context)
      if (request.frameKind !== FRAME_KIND.REQUEST) {
        protocolFailure('BAD_ENCODING', 'unary operation must use a request frame')
      }

      const decodedRequest = stagedPut
        ? clonePlain(stagedPut.request, 'staged request')
        : decodeCanonical(profile.requestCodec, canonicalRequestBytes, { copyBytes: true })
      const now = asU64(this.monotonicMillis(), 'monotonicMillis')
      const timing = deriveOperationDeadline(profile, decodedRequest, context, now)
      const signal = deadlineSignal(context.signal, timing.effectiveDeadline, now)
      let descriptorSnapshot
      try {
        descriptorSnapshot = this.descriptorState.requireCurrent()
      } catch {
        protocolFailure('BUSY', 'no current descriptor is available')
      }
      const descriptor = descriptorSnapshot.descriptor
      const enabled = (descriptor.enabledOperationBits & profile.operationBit) !== 0
      if (!enabled) {
        if (descriptor.storeLifecycleState === STORE_LIFECYCLE_STATE.DRAINING) {
          protocolFailure('BUSY', 'operation is disabled by the DRAINING lifecycle fence')
        }
        protocolFailure('TRANSPORT_UNSUPPORTED', 'operation is absent from the active signed descriptor')
      }
      if (descriptor.storeLifecycleState === STORE_LIFECYCLE_STATE.DRAINING &&
          profile.admissionMode === ADMISSION_MODE.OPTIONAL &&
          admissionFromRequest(profile, decodedRequest) != null) {
        protocolFailure('BUSY', 'DRAINING permits this operation only without admission')
      }
      const { endpoint, supportBit } = validateEndpoint(profile, context, descriptorSnapshot)
      const authority = Object.freeze({
        profile,
        frame: frameCopy(request, canonicalRequestBytes),
        requestBytes: b4a.from(canonicalRequestBytes),
        descriptorHash: b4a.from(descriptorSnapshot.hash),
        descriptorSequence: descriptorSnapshot.descriptorSequence,
        endpointId: endpoint.endpointId,
        transportSupportBit: supportBit,
        outerClass: context.outerClass == null ? null : context.outerClass,
        adjacentRelayKey: context.adjacentRelayKey == null ? null : b4a.from(context.adjacentRelayKey),
        requestValue: stagedPut == null ? null : clonePlain(stagedPut.request, 'staged request'),
        requestBodyBytes,
        requestWireBytes: stagedPut == null
          ? request.body.byteLength + DISPATCH_LIMITS.PREFIX_BYTES + DISPATCH_LIMITS.HEADER_BYTES
          : stagedPut.frame.dispatchBytes,
        requestCanonicalComplete: stagedPut == null,
        opaqueBodySource: stagedPut == null ? null : stagedPut.source,
        opaqueBodyByteLength: stagedPut == null ? null : stagedPut.sourceByteLength,
        ensureOpaqueBodyValidated: stagedPut == null ? null : stagedPut.ensureBodyValidated,
        postEofAuthorityPromise: stagedPut == null ? null : context.postEofAuthority,
        timing,
        signal
      })
      const verifiedSessionHandle = await this._verifiedSession(authority, context)

      if (profile.familyId === FAMILY.DESCRIBE) {
        const raw = await this._describe(authority)
        const dispatch = await this._validatedSuccess(authority, raw, null, null, null)
        return { dispatch, outerClass: context.outerClass == null ? null : context.outerClass }
      }

      const relation = await this.relationVerifier.verify(this._hookContext(authority))
      if (relation !== true) protocolFailure('BAD_SLOT', 'derived locator or topic relation is invalid')
      const requestValue = decodeRequest(authority)
      const requestCommitmentValue = operationRequestCommitment(profile, requestValue,
        descriptorSnapshot.descriptor, {
          adjacentRelayKey: authority.adjacentRelayKey == null ? null : b4a.from(authority.adjacentRelayKey)
        })
      const requestCommitment = requestCommitmentValue == null ? null : b4a.from(requestCommitmentValue)
      const authorized = await this.capabilityVerifier.verify(this._hookContext(authority, {
        requestCommitment
      }))
      if (authorized !== true) protocolFailure(authorizationError(profile), 'operation authorization failed')
      const rawAuthenticatedState = await this.cheapStateVerifier.inspect(this._hookContext(authority, {
        requestCommitment
      }))
      const authenticatedState = clonePlain(rawAuthenticatedState || {}, 'authenticated state')
      const predictedBytes = predictedResultBytes(authenticatedState, profile,
        descriptorSnapshot.descriptor, context.outerClass)
      const admission = admissionFromRequest(profile, decodeRequest(authority))
      if (stagedPut && profile.familyId === FAMILY.CELL && profile.operationId === OPERATION.CELL.PUT) {
        return await this._dispatchStagedAtomicPut({
          authority,
          context,
          endpoint,
          supportBit,
          descriptorSnapshot,
          requestCommitment,
          authenticatedState,
          predictedBytes,
          admission
        })
      }
      let preparedAdmission = null
      if (admission == null && profile.admissionMode === ADMISSION_MODE.REQUIRED) {
        protocolFailure('SPEND_REQUIRED', 'operation requires admission')
      }
      if (admission != null) {
        const cost = deriveAdmissionCost(profile, decodeRequest(authority), authenticatedState)
        preparedAdmission = await this.admission.prepare({
          profile,
          admission,
          cost,
          requestCommitment: requestCommitment == null ? null : b4a.from(requestCommitment),
          descriptorSnapshot: this.descriptorState.selected(authority.descriptorHash),
          endpoint: clonePlain(endpoint, 'endpoint'),
          signal
        })
        preparedAdmission = clonePlain(preparedAdmission, 'prepared admission')
      }

      let spendKind = null
      if (preparedAdmission) {
        if (!this.transactionCoordinator || typeof this.transactionCoordinator.lookup !== 'function' ||
            typeof this.transactionCoordinator.run !== 'function' ||
            typeof this.transactionCoordinator.replay !== 'function') {
          protocolFailure('INTERNAL', 'admission operation has no complete atomic transaction coordinator')
        }
        const lookup = await this.transactionCoordinator.lookup(this._hookContext(authority, {
          requestCommitment,
          preparedAdmission,
          authenticatedState
        }))
        if (!lookup || (lookup.kind !== 'fresh' && lookup.kind !== 'replay')) {
          protocolFailure('INTERNAL', 'transaction lookup returned an invalid closed variant')
        }
        spendKind = lookup.kind
      }

      await this.terminalStateVerifier.check(this._hookContext(authority, {
        requestCommitment,
        preparedAdmission,
        authenticatedState,
        spendLookup: spendKind == null ? null : { kind: spendKind }
      }))
      const readiness = await this.readiness.evaluate({
        endpointId: endpoint.endpointId,
        transportSupportBit: supportBit,
        signal
      })
      if (readiness.kind !== READINESS_STATE_KIND.READY ||
          readiness.descriptorSequence !== authority.descriptorSequence ||
          !sameBytes(readiness.descriptorHash, authority.descriptorHash) ||
          !readiness.endpoint || readiness.endpoint.endpointId !== endpoint.endpointId ||
          readiness.transportSupportBit !== supportBit ||
          !Number.isInteger(readiness.readyRoleBits) || readiness.readyRoleBits === 0 ||
          (readiness.readyRoleBits & ~endpoint.roleBits) !== 0 ||
          readiness.capacityBand !== descriptor.capacityBand ||
          (readiness.readyOperationBits & profile.operationBit) === 0) {
        protocolFailure('BUSY', 'operation path is not ready')
      }
      effectiveEpochFloor = readiness.effectiveEpochFloor
      if (!this.descriptorState.remainsUsable(this.descriptorState.selected(authority.descriptorHash))) {
        protocolFailure('BUSY', 'operation descriptor crossed a lifecycle fence')
      }
      await this.capacityGuard.check(this._hookContext(authority, {
        requestCommitment,
        preparedAdmission,
        authenticatedState,
        spendLookup: spendKind == null ? null : { kind: spendKind },
        readiness: {
          descriptorSequence: readiness.descriptorSequence,
          descriptorHash: b4a.from(readiness.descriptorHash),
          readyRoleBits: readiness.readyRoleBits,
          readyOperationBits: readiness.readyOperationBits
        }
      }))
      const reservation = this.budget.acquire({
        familyId: profile.familyId,
        operationId: profile.operationId,
        requestBytes: authority.requestWireBytes,
        responseBytes: responseReservationBytes(profile, descriptorSnapshot.descriptor,
          context.outerClass, predictedBytes),
        stagingBytes: preparedAdmission == null ? 0 : preparedAdmission.walCommitRecord.byteLength,
        critical: criticalOperation(profile)
      })
      try {
        this._checkDeadline(authority)
        let raw
        if (spendKind === 'replay') {
          raw = (profile.streamTransition === STREAM_TRANSITION.CORE_CHILD ||
            profile.streamTransition === STREAM_TRANSITION.FORWARD_OPEN)
            ? await this._execute(authority, requestCommitment, preparedAdmission,
              authenticatedState, null, verifiedSessionHandle, true)
            : await this.transactionCoordinator.replay(this._hookContext(authority, {
              requestCommitment,
              preparedAdmission,
              authenticatedState,
              spendLookup: { kind: 'replay' }
            }))
        } else {
          let executed = false
          const execute = transaction => {
            if (executed) protocolFailure('INTERNAL', 'atomic transaction invoked its operation more than once')
            executed = true
            return this._execute(authority, requestCommitment,
              preparedAdmission, authenticatedState, transaction, verifiedSessionHandle, false)
          }
          raw = preparedAdmission
            ? await this.transactionCoordinator.run(this._hookContext(authority, {
              requestCommitment,
              preparedAdmission,
              authenticatedState,
              spendLookup: { kind: 'fresh' }
            }), execute)
            : await execute(null)
        }
        return {
          dispatch: await this._validatedSuccess(authority, raw, requestCommitment,
            preparedAdmission, authenticatedState),
          outerClass: context.outerClass == null ? null : context.outerClass
        }
      } finally {
        reservation.release()
      }
    } catch (error) {
      if (activeStream || !request) throw error
      const dispatch = errorDispatch(request, error, effectiveEpochFloor)
      assertOuterFit(dispatch, context.outerClass)
      return {
        dispatch,
        outerClass: context.outerClass == null ? null : context.outerClass
      }
    }
  }

  async _dispatchStagedAtomicPut (input) {
    const {
      authority,
      context,
      endpoint,
      supportBit,
      descriptorSnapshot,
      requestCommitment,
      authenticatedState,
      predictedBytes,
      admission
    } = input
    if (admission == null) protocolFailure('SPEND_REQUIRED', 'staged CELL.PUT requires admission')
    if (typeof this.admission.preparePreflight !== 'function' ||
        typeof this.admission.confirmAfterEof !== 'function') {
      protocolFailure('INTERNAL', 'staged CELL.PUT requires the explicit admission preflight split')
    }
    for (const method of ['stageAtomicPut', 'commitAtomicPut', 'cancelAtomicPut']) {
      if (typeof this.operationExecutor[method] !== 'function') {
        protocolFailure('INTERNAL', `staged CELL.PUT operation executor has no ${method}`)
      }
    }
    const request = decodeRequest(authority)
    const cost = deriveAdmissionCost(authority.profile, request, authenticatedState)
    const preflightInput = {
      profile: authority.profile,
      admission,
      cost,
      requestId: b4a.from(authority.frame.requestId),
      requestCommitment: b4a.from(requestCommitment),
      descriptorSnapshot: this.descriptorState.selected(authority.descriptorHash),
      endpoint: clonePlain(endpoint, 'endpoint'),
      signal: authority.signal
    }
    const preflight = await this.admission.preparePreflight(preflightInput)

    const readiness = await this.readiness.evaluate({
      endpointId: endpoint.endpointId,
      transportSupportBit: supportBit,
      signal: authority.signal
    })
    const descriptor = descriptorSnapshot.descriptor
    if (readiness.kind !== READINESS_STATE_KIND.READY ||
        readiness.descriptorSequence !== authority.descriptorSequence ||
        !sameBytes(readiness.descriptorHash, authority.descriptorHash) ||
        !readiness.endpoint || readiness.endpoint.endpointId !== endpoint.endpointId ||
        readiness.transportSupportBit !== supportBit ||
        !Number.isInteger(readiness.readyRoleBits) || readiness.readyRoleBits === 0 ||
        (readiness.readyRoleBits & ~endpoint.roleBits) !== 0 ||
        readiness.capacityBand !== descriptor.capacityBand ||
        (readiness.readyOperationBits & authority.profile.operationBit) === 0) {
      protocolFailure('BUSY', 'staged CELL.PUT path is not ready')
    }
    if (!this.descriptorState.remainsUsable(this.descriptorState.selected(authority.descriptorHash))) {
      protocolFailure('BUSY', 'staged CELL.PUT descriptor crossed a lifecycle fence')
    }

    const reservation = this.budget.acquire({
      familyId: authority.profile.familyId,
      operationId: authority.profile.operationId,
      requestBytes: authority.requestWireBytes,
      responseBytes: responseReservationBytes(authority.profile, descriptor,
        context.outerClass, predictedBytes),
      stagingBytes: authority.opaqueBodyByteLength,
      critical: false
    })
    let stagedAuthority = null
    try {
      this._checkDeadline(authority)
      stagedAuthority = await this.operationExecutor.stageAtomicPut({
        ...this._hookContext(authority, {
          requestCommitment,
          authenticatedState,
          admissionProfileId: admission.profileId
        }),
        opaqueBodySource: authority.opaqueBodySource,
        opaqueBodyByteLength: authority.opaqueBodyByteLength
      })
      await authority.ensureOpaqueBodyValidated()
      const postEofAuthority = await waitForSignalBoundPromise(
        authority.postEofAuthorityPromise, authority.signal)
      const preparedAdmission = clonePlain(await this.admission.confirmAfterEof(preflight, {
        ...preflightInput,
        postEofAuthority
      }), 'prepared admission')
      await this.terminalStateVerifier.check(this._hookContext(authority, {
        requestCommitment,
        preparedAdmission,
        authenticatedState,
        spendLookup: { kind: 'fresh' }
      }))
      await this.capacityGuard.check(this._hookContext(authority, {
        requestCommitment,
        preparedAdmission,
        authenticatedState,
        atomicStaged: true,
        spendLookup: { kind: 'fresh' },
        readiness: {
          descriptorSequence: readiness.descriptorSequence,
          descriptorHash: b4a.from(readiness.descriptorHash),
          readyRoleBits: readiness.readyRoleBits,
          readyOperationBits: readiness.readyOperationBits
        }
      }))
      this._checkDeadline(authority)
      const raw = await this.operationExecutor.commitAtomicPut({
        ...this._hookContext(authority, {
          requestCommitment,
          preparedAdmission,
          authenticatedState
        }),
        atomicStagedAuthority: stagedAuthority,
        preCommitFence: () => {
          let current
          try {
            current = this.descriptorState.requireCurrent()
          } catch {
            protocolFailure('BUSY', 'staged CELL.PUT descriptor is no longer current at commit')
          }
          const selected = this.descriptorState.selected(authority.descriptorHash)
          if (!selected || current.descriptorSequence !== authority.descriptorSequence ||
              !sameBytes(current.hash, authority.descriptorHash) ||
              !this.descriptorState.remainsUsable(selected)) {
            protocolFailure('BUSY', 'staged CELL.PUT descriptor changed at its final commit fence')
          }
          this._checkDeadline(authority)
          return true
        }
      })
      stagedAuthority = null
      return {
        dispatch: await this._validatedSuccess(authority, raw, requestCommitment,
          preparedAdmission, authenticatedState),
        outerClass: context.outerClass == null ? null : context.outerClass
      }
    } finally {
      if (stagedAuthority) await this.operationExecutor.cancelAtomicPut(stagedAuthority).catch(() => {})
      reservation.release()
    }
  }

  async _describe (authority) {
    const profile = authority.profile
    const request = decodeRequest(authority)
    const descriptorSnapshot = this.descriptorState.selected(authority.descriptorHash)
    if (profile.operationId === OPERATION.DESCRIBE.CHALLENGE) {
      const result = await this.readiness.healthResult(request, {
        endpointId: authority.endpointId,
        transportSupportBit: authority.transportSupportBit,
        signal: authority.signal
      })
      return { body: result.canonicalBytes }
    }
    const readiness = await this.readiness.evaluate({
      endpointId: authority.endpointId,
      transportSupportBit: authority.transportSupportBit,
      signal: authority.signal
    })
    if (readiness.kind !== READINESS_STATE_KIND.READY ||
        (readiness.readyOperationBits & profile.operationBit) === 0) {
      protocolFailure('BUSY', 'DESCRIBE operation path is not ready')
    }
    if (profile.operationId === OPERATION.DESCRIBE.GET) {
      const selected = this.descriptorState.selected(request.descriptorHash)
      if (!selected) protocolFailure('NOT_FOUND', 'descriptor history entry is unavailable')
      return { body: b4a.from(selected.canonicalBytes) }
    }
    if (profile.operationId === OPERATION.DESCRIBE.ADMISSION_PARAMETERS) {
      const body = this.admission.parametersForRequest(request, descriptorSnapshot)
      if (!body) protocolFailure('NOT_FOUND', 'admission parameters are unavailable')
      return { body }
    }
    protocolFailure('INTERNAL', 'registered DESCRIBE operation has no coordinator implementation')
  }

  async _execute (authority, requestCommitment, preparedAdmission, authenticatedState,
    transaction, verifiedSessionHandle, replay) {
    const context = this._hookContext(authority, {
      requestCommitment,
      preparedAdmission,
      authenticatedState,
      transaction: null,
      replay
    })
    if (authority.profile.streamTransition === STREAM_TRANSITION.CORE_CHILD ||
        authority.profile.streamTransition === STREAM_TRANSITION.FORWARD_OPEN) {
      if (!this.streamExecutor || typeof this.streamExecutor.open !== 'function' ||
          !verifiedSessionHandle || !VERIFIED_SESSION_HANDLES.has(verifiedSessionHandle)) {
        protocolFailure('INTERNAL', 'stream OPEN has no verified stream service/session handle')
      }
      return this.streamExecutor.open({
        ...context,
        transaction,
        verifiedSessionHandle
      })
    }
    return this.operationExecutor.execute({
      ...context,
      transaction,
      opaqueBodySource: authority.opaqueBodySource,
      opaqueBodyByteLength: authority.opaqueBodyByteLength,
      ensureOpaqueBodyValidated: authority.ensureOpaqueBodyValidated
    })
  }

  async _validatedSuccess (authority, raw, requestCommitment, preparedAdmission, authenticatedState) {
    if (authority.ensureOpaqueBodyValidated) await authority.ensureOpaqueBodyValidated()
    this._checkDeadline(authority)
    let normalized = normalizeResult(authority.profile, raw)
    const executorStreamId = normalized.executorStreamId
    const descriptorSnapshot = this.descriptorState.selected(authority.descriptorHash)
    const descriptor = descriptorSnapshot.descriptor
    if (normalized.body.byteLength > authority.profile.maxResultBodyBytes ||
        normalized.body.byteLength > descriptor.maxResponseBytes) {
      protocolFailure('TOO_LARGE', 'operation result exceeds the signed response cap')
    }
    let value = decodeCanonical(authority.profile.resultCodec, normalized.body, { copyBytes: true })
    let expectedBinding = null
    let witnessRequired = false
    if (authority.profile.familyId !== FAMILY.DESCRIBE &&
        authority.profile.resultSignatureDomainId !== 0) {
      const binding = resultBindingFromValue(value)
      if (!binding) protocolFailure('INTERNAL', 'operation result omitted its relay/store descriptor binding')
      const bindingSnapshot = normalized.committedStoreResult
        ? committedStoreBindingSnapshot(this.descriptorState, descriptorSnapshot, binding)
        : descriptorSnapshot
      const restoreEvidenceRaw = await this.resultBindingSnapshot(this._hookContext(authority, {
        requestCommitment,
        authenticatedState: authenticatedState || {}
      }))
      const restoreEvidence = clonePlain(restoreEvidenceRaw || {}, 'restore evidence snapshot')
      expectedBinding = this.descriptorState.resultBinding(bindingSnapshot, restoreEvidence)
      assertRelayResultBinding(binding, expectedBinding)
      witnessRequired = assertResultWitnessPolicy(authority.profile, binding,
        expectedBinding.durabilityProfileId, preparedAdmission != null)
      assertWitnessBase(binding.externalCommitWitness, authority.profile, requestCommitment)
    }
    const resultCommitment = requestCommitmentFromResult(value)
    if (resultCommitment && (!requestCommitment || !sameBytes(resultCommitment, requestCommitment))) {
      protocolFailure('INTERNAL', 'operation result is bound to a different request commitment')
    }
    const resultNonce = requestNonceFromResult(value)
    const request = decodeRequest(authority)
    if (resultNonce && (!request.clientNonce || !sameBytes(resultNonce, request.clientNonce))) {
      protocolFailure('INTERNAL', 'operation result is bound to a different client nonce')
    }
    const verified = await this.resultVerifier.verify({
      familyId: authority.profile.familyId,
      operationId: authority.profile.operationId,
      resultSignatureDomainId: authority.profile.resultSignatureDomainId,
      canonicalResultBytes: b4a.from(normalized.body),
      result: decodeCanonical(authority.profile.resultCodec, normalized.body, { copyBytes: true }),
      request: decodeRequest(authority),
      canonicalRequestBytes: authority.requestCanonicalComplete ? b4a.from(authority.requestBytes) : null,
      canonicalRequestPrefixBytes: authority.requestCanonicalComplete ? null : b4a.from(authority.requestBytes),
      opaqueRequestBodyBytes: authority.opaqueBodyByteLength,
      requestCommitment: requestCommitment == null ? null : b4a.from(requestCommitment),
      expectedRelayBinding: expectedBinding == null ? null : clonePlain(expectedBinding, 'expected relay binding'),
      witnessRequired,
      descriptorSequence: authority.descriptorSequence,
      descriptorHash: b4a.from(authority.descriptorHash),
      signal: authority.signal
    })
    if (verified !== true) protocolFailure('INTERNAL', 'operation result signature or semantic echo verification failed')
    this._checkDeadline(authority)
    normalized = normalizeResult(authority.profile, normalized.body)
    value = normalized.value
    if (expectedBinding != null) {
      const binding = resultBindingFromValue(value)
      assertRelayResultBinding(binding, expectedBinding)
      assertResultWitnessPolicy(authority.profile, binding, expectedBinding.durabilityProfileId,
        preparedAdmission != null)
      assertWitnessBase(binding.externalCommitWitness, authority.profile, requestCommitment)
    }
    const finalCommitment = requestCommitmentFromResult(value)
    if (finalCommitment && (!requestCommitment || !sameBytes(finalCommitment, requestCommitment))) {
      protocolFailure('INTERNAL', 'verified result commitment changed after verification')
    }
    const finalNonce = requestNonceFromResult(value)
    if (finalNonce && (!request.clientNonce || !sameBytes(finalNonce, request.clientNonce))) {
      protocolFailure('INTERNAL', 'verified result nonce changed after verification')
    }
    const streamId = responseStreamId(authority.profile, value, executorStreamId)
    const dispatch = encodeDispatchFrame({
      frameKind: FRAME_KIND.RESPONSE,
      familyId: authority.frame.familyId,
      operationId: authority.frame.operationId,
      requestId: authority.frame.requestId,
      streamId,
      body: normalized.body
    })
    assertOuterFit(dispatch, authority.outerClass)
    return dispatch
  }

  async _dispatchActiveStream (request, canonicalRequestBytes, context, frameError = null) {
    if (!this.streamExecutor || typeof this.streamExecutor.handleFrame !== 'function') {
      protocolFailure('INTERNAL', 'active FORWARD frame has no pinned stream service')
    }
    const canonicalFrame = encodeDispatchFrame(frameCopy(request, canonicalRequestBytes))
    let raw
    try {
      if (frameError) throw frameError
      raw = await this.streamExecutor.handleFrame({
        canonicalFrame: b4a.from(canonicalFrame),
        frame: frameCopy(request, canonicalRequestBytes),
        streamSide: context.streamSide,
        signal: context.signal
      })
    } catch (error) {
      if (typeof this.streamExecutor.terminate !== 'function') throw error
      raw = await this.streamExecutor.terminate({
        canonicalFrame: b4a.from(canonicalFrame),
        frame: frameCopy(request, canonicalRequestBytes),
        streamSide: context.streamSide,
        error,
        signal: context.signal
      })
    }
    const disposition = normalizeStreamDisposition(raw)
    return Object.freeze({
      dispatch: disposition.dispatch,
      outerClass: null,
      streamDisposition: disposition.kind
    })
  }
}
