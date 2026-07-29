import b4a from 'b4a'
import { decodeCanonical } from '../blind-protocol/codec.js'
import {
  FORWARD_HTTPS_REQUEST_KIND_V1,
  FORWARD_HTTPS_REQUEST_ROLE_V1,
  FORWARD_HTTPS_RESPONSE_KIND_V1,
  FORWARD_HTTPS_RESULT_ROLE_V1,
  assertForwardHttpsResultForOriginRequestV1,
  blindForwardHttpsOriginForwardTurnRequestV1,
  blindForwardHttpsOriginForwardTurnResultV1,
  forwardHttpsCapabilityPrefixHashV1,
  forwardHttpsOriginRequestCommitmentV1,
  forwardHttpsParentCapabilityPrefixHashV1,
  forwardHttpsStableSessionIdV1,
  forwardHttpsTargetResultChainHashV1,
  verifyForwardHttpsParentCapabilitySignatureV1,
  verifyForwardHttpsResultSignatureV1
} from '../blind-protocol/wire-v3.js'
import {
  FORWARD_HTTPS_OUTSTANDING_STATE_V3,
  assertForwardHttpsSessionV3,
  assertForwardHttpsVerifiedEndpointV3
} from '../blind-protocol/client-composition-v3.js'

const MAX_U64 = (1n << 64n) - 1n
const STORE_V3 = 'forwardHttpsSessionsV3'

export const BLIND_CLIENT_CONTROL_V3_AUTHORITY = Object.freeze({
  profile: 'blind-client-control-v3',
  wireV3AbiHash: 'c15c6a994d3bc2e54a397446b475a12d7f27e04be68e6e3eb86b28d518752881',
  clientCompositionV3FormatHash: '12d588b87c596a7a55ed64ee731fc32779d48a08285dcf0e4f7bcfb9ceb46b0d',
  releaseProfileId: 2,
  routeKind: 7,
  exactRequestBytes: 65_536,
  exactResultBytes: 65_536,
  forwardDescriptorOperationBits: 0,
  forwardAdvertisedOperationBits: 0,
  forwardReadinessOperationBits: 0,
  runtimeReady: false,
  realBrowserEvidenceAccepted: false,
  authorizesRelease: false
})

export const FORWARD_HTTPS_BROWSER_TERMINAL_KIND_V3 = Object.freeze({
  NONE: 'NONE',
  NORMAL_CLOSE: 'NORMAL_CLOSE',
  CORRECTNESS: 'CORRECTNESS'
})

export const FORWARD_HTTPS_BROWSER_TERMINAL_EVIDENCE_KIND_V3 = Object.freeze({
  OUTSTANDING_CONFLICT: 'OUTSTANDING_CONFLICT'
})

const WIRE_V3_ABI_HASH = b4a.from(BLIND_CLIENT_CONTROL_V3_AUTHORITY.wireV3AbiHash, 'hex')

const ENDPOINT_FIELDS = Object.freeze([
  'version', 'releaseProfileId', 'routeKind', 'wireV3AbiHash', 'verifiedEndpointHandleHash',
  'sourceRelayPublicKey', 'sourceDescriptorSequence', 'sourceDescriptorHash', 'targetCatalogEntryId',
  'targetRelayPublicKey', 'targetDescriptorSequence', 'targetDescriptorHash', 'signedDescriptorHash',
  'signedHealthHash', 'descriptorFresh', 'signedHealthFresh', 'credentialFreeHttps', 'cookies',
  'authorization', 'referrer', 'redirect', 'exactRequestBytes', 'exactResultBytes', 'continuityBackend'
])

const RECORD_FIELDS = Object.freeze([
  'recordVersion', 'sessionKey', 'verifiedEndpoint', 'stableSessionId', 'capabilityPrefixHash',
  'clientSessionNonce', 'nextSequence', 'previousTargetResultHash', 'terminal', 'terminalKind',
  'outstandingState', 'outstandingOriginRequestCommitment', 'outstandingOriginRequest',
  'lastDefinitiveTargetResult', 'targetFin', 'terminalEvidence'
])

const TERMINAL_EVIDENCE_FIELDS = Object.freeze([
  'kind', 'originalOutstandingState', 'sequence', 'originRequestCommitment', 'originRequest'
])

function fail (message, code = 'BAD_BROWSER_FORWARD_STATE_V3') {
  const error = new Error(message)
  error.code = code
  throw error
}

function terminalFail (message = 'browser FORWARD session is terminal') {
  fail(message, 'TERMINAL_BROWSER_FORWARD_SESSION')
}

function bytes (value, length, field, nonzero = false) {
  if (!value || typeof value.byteLength !== 'number') fail(`${field} must be ArrayBuffer-backed bytes`)
  value = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (value.byteLength !== length) fail(`${field} must be exactly ${length} bytes`)
  if (nonzero && isZero(value)) fail(`${field} must be nonzero`)
  return b4a.from(value)
}

function variableBytes (value, field) {
  if (!value || typeof value.byteLength !== 'number') fail(`${field} must be ArrayBuffer-backed bytes`)
  return b4a.isBuffer(value)
    ? b4a.from(value)
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
}

function isZero (value) {
  for (const byte of value) if (byte !== 0) return false
  return true
}

function exactKeys (value, expected, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${field} must be an object`)
  const actual = Object.keys(value).sort()
  const wanted = [...expected].sort()
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail(`${field} has an unknown or missing field`)
  }
}

function sessionKey (value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 256) fail('sessionKey must be a nonempty string of at most 256 characters')
  return value
}

function decimalU64 (value, field) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) fail(`${field} must be a canonical decimal u64 string`)
  const decoded = BigInt(value)
  if (decoded < 0n || decoded > MAX_U64) fail(`${field} is outside u64`)
  return decoded
}

function sameEndpoint (left, right) {
  for (const field of ENDPOINT_FIELDS) {
    if (typeof left[field] === 'bigint') {
      if (left[field] !== right[field]) return false
    } else if (left[field] && typeof left[field].byteLength === 'number') {
      if (!b4a.equals(left[field], right[field])) return false
    } else if (left[field] !== right[field]) return false
  }
  return true
}

function copyEndpoint (value) {
  const endpoint = assertForwardHttpsVerifiedEndpointV3(value, WIRE_V3_ABI_HASH)
  exactKeys(value, ENDPOINT_FIELDS, 'verifiedEndpoint')
  return Object.freeze({
    ...endpoint,
    wireV3AbiHash: b4a.from(endpoint.wireV3AbiHash),
    verifiedEndpointHandleHash: b4a.from(endpoint.verifiedEndpointHandleHash),
    sourceRelayPublicKey: b4a.from(endpoint.sourceRelayPublicKey),
    sourceDescriptorHash: b4a.from(endpoint.sourceDescriptorHash),
    targetCatalogEntryId: b4a.from(endpoint.targetCatalogEntryId),
    targetRelayPublicKey: b4a.from(endpoint.targetRelayPublicKey),
    targetDescriptorHash: b4a.from(endpoint.targetDescriptorHash),
    signedDescriptorHash: b4a.from(endpoint.signedDescriptorHash),
    signedHealthHash: b4a.from(endpoint.signedHealthHash)
  })
}

function assertCapabilityMatchesEndpoint (capability, endpoint) {
  for (const field of ['sourceRelayPublicKey', 'sourceDescriptorHash', 'targetRelayPublicKey', 'targetDescriptorHash', 'targetCatalogEntryId']) {
    if (!b4a.equals(capability[field], endpoint[field])) fail(`parent capability ${field} does not match verifiedEndpoint`)
  }
  if (capability.sourceDescriptorSequence !== endpoint.sourceDescriptorSequence ||
      capability.targetDescriptorSequence !== endpoint.targetDescriptorSequence) {
    fail('parent capability descriptor sequence does not match verifiedEndpoint')
  }
}

function assertResultMatchesEndpoint (assertion, endpoint) {
  assertCapabilityMatchesEndpoint(assertion.forwarded.parentCapability, endpoint)
  const result = assertion.result
  const sourceResult = result.resultRole !== FORWARD_HTTPS_RESULT_ROLE_V1.TARGET_RESULT
  const expectedPublicKey = sourceResult ? endpoint.sourceRelayPublicKey : endpoint.targetRelayPublicKey
  const expectedSequence = sourceResult ? endpoint.sourceDescriptorSequence : endpoint.targetDescriptorSequence
  const expectedHash = sourceResult ? endpoint.sourceDescriptorHash : endpoint.targetDescriptorHash
  if (!b4a.equals(result.signerPublicKey, expectedPublicKey) ||
      result.signerDescriptorSequence !== expectedSequence ||
      !b4a.equals(result.signerDescriptorHash, expectedHash)) {
    fail('result signer does not match complete verifiedEndpoint authority')
  }
}

function decodeOrigin (value, field = 'origin request') {
  const requestBytes = bytes(value, 65_536, field)
  const request = decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, requestBytes, { copyBytes: true })
  if (request.requestRole !== FORWARD_HTTPS_REQUEST_ROLE_V1.ORIGIN_TEMPLATE) fail(`${field} must be an ORIGIN_TEMPLATE ID76`)
  return Object.freeze({ request, requestBytes })
}

function assertOriginBindsState (decoded, state, endpoint) {
  const { request, requestBytes } = decoded
  if (!b4a.equals(request.stableSessionId, state.stableSessionId) ||
      !b4a.equals(request.clientSessionNonce, state.clientSessionNonce) ||
      request.sequence !== state.nextSequence ||
      !b4a.equals(request.previousTargetResultHash, state.previousTargetResultHash) ||
      !b4a.equals(forwardHttpsOriginRequestCommitmentV1(requestBytes), state.outstandingOriginRequestCommitment) ||
      !b4a.equals(forwardHttpsCapabilityPrefixHashV1(requestBytes), state.capabilityPrefixHash) ||
      !b4a.equals(forwardHttpsStableSessionIdV1(request.parentCapability, request.clientSessionNonce), state.stableSessionId)) {
    fail('origin request does not bind the exact durable session state')
  }
  assertCapabilityMatchesEndpoint(request.parentCapability, endpoint)
  if ((request.sequence === 0n) !== (request.requestKind === FORWARD_HTTPS_REQUEST_KIND_V1.OPEN)) {
    fail('only the sequence-zero origin request may be OPEN')
  }
}

function assertLastResult (resultBytes, state, endpoint) {
  const result = decodeCanonical(blindForwardHttpsOriginForwardTurnResultV1, resultBytes, { copyBytes: true })
  if (result.resultRole !== FORWARD_HTTPS_RESULT_ROLE_V1.TARGET_RESULT ||
      result.sequence !== state.nextSequence - 1n ||
      !b4a.equals(result.stableSessionId, state.stableSessionId) ||
      !b4a.equals(forwardHttpsStableSessionIdV1(result.finalizedParentCapability, state.clientSessionNonce), state.stableSessionId) ||
      !b4a.equals(forwardHttpsParentCapabilityPrefixHashV1(result.finalizedParentCapability), state.capabilityPrefixHash) ||
      !b4a.equals(forwardHttpsTargetResultChainHashV1(resultBytes), state.previousTargetResultHash) ||
      !b4a.equals(result.signerPublicKey, endpoint.targetRelayPublicKey) ||
      result.signerDescriptorSequence !== endpoint.targetDescriptorSequence ||
      !b4a.equals(result.signerDescriptorHash, endpoint.targetDescriptorHash) ||
      !verifyForwardHttpsParentCapabilitySignatureV1(result.finalizedParentCapability) ||
      !verifyForwardHttpsResultSignatureV1(resultBytes)) {
    fail('lastDefinitiveTargetResult does not bind the durable target-result chain')
  }
  assertCapabilityMatchesEndpoint(result.finalizedParentCapability, endpoint)
  return result
}

function copyEvidence (value) {
  if (value == null) return null
  exactKeys(value, TERMINAL_EVIDENCE_FIELDS, 'terminalEvidence')
  if (value.kind !== FORWARD_HTTPS_BROWSER_TERMINAL_EVIDENCE_KIND_V3.OUTSTANDING_CONFLICT ||
      ![FORWARD_HTTPS_OUTSTANDING_STATE_V3.PERSISTED_BEFORE_FETCH, FORWARD_HTTPS_OUTSTANDING_STATE_V3.AWAITING_DEFINITIVE_TARGET].includes(value.originalOutstandingState)) {
    fail('terminalEvidence has an invalid closed kind or outstanding state')
  }
  return Object.freeze({
    kind: value.kind,
    originalOutstandingState: value.originalOutstandingState,
    sequence: decimalU64(value.sequence, 'terminalEvidence.sequence').toString(),
    originRequestCommitment: bytes(value.originRequestCommitment, 32, 'terminalEvidence.originRequestCommitment', true),
    originRequest: bytes(value.originRequest, 65_536, 'terminalEvidence.originRequest')
  })
}

function snapshotRecord (value) {
  return Object.freeze({
    recordVersion: 3,
    sessionKey: value.sessionKey,
    verifiedEndpoint: copyEndpoint(value.verifiedEndpoint),
    stableSessionId: b4a.from(value.stableSessionId),
    capabilityPrefixHash: b4a.from(value.capabilityPrefixHash),
    clientSessionNonce: b4a.from(value.clientSessionNonce),
    nextSequence: value.nextSequence,
    previousTargetResultHash: b4a.from(value.previousTargetResultHash),
    terminal: value.terminal,
    terminalKind: value.terminalKind,
    outstandingState: value.outstandingState,
    outstandingOriginRequestCommitment: b4a.from(value.outstandingOriginRequestCommitment),
    outstandingOriginRequest: b4a.from(value.outstandingOriginRequest),
    lastDefinitiveTargetResult: b4a.from(value.lastDefinitiveTargetResult),
    targetFin: value.targetFin,
    terminalEvidence: copyEvidence(value.terminalEvidence)
  })
}

export function assertForwardHttpsPersistedSessionRecordV3 (value) {
  exactKeys(value, RECORD_FIELDS, 'persisted browser session')
  if (value.recordVersion !== 3) fail('persisted browser session recordVersion must be 3')
  const endpoint = copyEndpoint(value.verifiedEndpoint)
  const normalized = {
    recordVersion: 3,
    sessionKey: sessionKey(value.sessionKey),
    verifiedEndpoint: endpoint,
    stableSessionId: bytes(value.stableSessionId, 32, 'stableSessionId', true),
    capabilityPrefixHash: bytes(value.capabilityPrefixHash, 32, 'capabilityPrefixHash', true),
    clientSessionNonce: bytes(value.clientSessionNonce, 32, 'clientSessionNonce', true),
    nextSequence: decimalU64(value.nextSequence, 'nextSequence'),
    previousTargetResultHash: bytes(value.previousTargetResultHash, 32, 'previousTargetResultHash'),
    terminal: value.terminal,
    terminalKind: value.terminalKind,
    outstandingState: value.outstandingState,
    outstandingOriginRequestCommitment: bytes(value.outstandingOriginRequestCommitment, 32, 'outstandingOriginRequestCommitment'),
    outstandingOriginRequest: variableBytes(value.outstandingOriginRequest, 'outstandingOriginRequest'),
    lastDefinitiveTargetResult: variableBytes(value.lastDefinitiveTargetResult, 'lastDefinitiveTargetResult'),
    targetFin: value.targetFin,
    terminalEvidence: copyEvidence(value.terminalEvidence)
  }
  if (normalized.terminal !== 0 && normalized.terminal !== 1) fail('terminal must be 0 or 1')
  if (!Object.values(FORWARD_HTTPS_BROWSER_TERMINAL_KIND_V3).includes(normalized.terminalKind)) fail('terminalKind is outside the closed registry')
  if (![0, 1, 2].includes(normalized.outstandingState)) fail('outstandingState is outside the closed registry')
  if (normalized.targetFin !== true && normalized.targetFin !== false) fail('targetFin must be boolean')
  if (normalized.nextSequence === 0n && normalized.targetFin) fail('sequence-zero session cannot record targetFin')
  if ((normalized.nextSequence === 0n) !== isZero(normalized.previousTargetResultHash)) {
    fail('previousTargetResultHash must be zero iff nextSequence is zero')
  }

  const hasOutstanding = normalized.outstandingState !== FORWARD_HTTPS_OUTSTANDING_STATE_V3.NONE
  if (hasOutstanding) {
    if (isZero(normalized.outstandingOriginRequestCommitment) || normalized.outstandingOriginRequest.byteLength !== 65_536) {
      fail('live outstanding state requires an exact request and nonzero commitment')
    }
    const decoded = decodeOrigin(normalized.outstandingOriginRequest, 'outstandingOriginRequest')
    assertOriginBindsState(decoded, normalized, endpoint)
  } else if (!isZero(normalized.outstandingOriginRequestCommitment) || normalized.outstandingOriginRequest.byteLength !== 0) {
    fail('NONE outstanding state requires zero live outstanding fields')
  }

  let lastResult = null
  if (normalized.nextSequence === 0n) {
    if (normalized.lastDefinitiveTargetResult.byteLength !== 0) fail('sequence zero cannot retain a definitive target result')
  } else {
    if (normalized.lastDefinitiveTargetResult.byteLength !== 65_536) fail('advanced session must retain the exact prior definitive target result')
    lastResult = assertLastResult(normalized.lastDefinitiveTargetResult, normalized, endpoint)
    if (lastResult.responseKind === FORWARD_HTTPS_RESPONSE_KIND_V1.CLOSE && !normalized.targetFin) {
      fail('a retained target CLOSE result requires sticky targetFin')
    }
    if (normalized.nextSequence === 1n && lastResult.responseKind !== FORWARD_HTTPS_RESPONSE_KIND_V1.CLOSE && normalized.targetFin) {
      fail('the first non-CLOSE target result cannot imply targetFin')
    }
  }

  if (normalized.terminalKind === FORWARD_HTTPS_BROWSER_TERMINAL_KIND_V3.NONE) {
    if (normalized.terminal !== 0 || normalized.terminalEvidence !== null) fail('nonterminal record has terminal state or evidence')
    assertForwardHttpsSessionV3({
      version: 3,
      verifiedEndpoint: endpoint,
      stableSessionId: normalized.stableSessionId,
      capabilityPrefixHash: normalized.capabilityPrefixHash,
      clientSessionNonce: normalized.clientSessionNonce,
      nextSequence: normalized.nextSequence,
      previousTargetResultHash: normalized.previousTargetResultHash,
      terminal: 0,
      outstandingState: normalized.outstandingState,
      outstandingOriginRequestCommitment: normalized.outstandingOriginRequestCommitment,
      outstandingOriginRequest: normalized.outstandingOriginRequest,
      lastDefinitiveTargetResult: normalized.lastDefinitiveTargetResult
    }, WIRE_V3_ABI_HASH)
  } else if (normalized.terminalKind === FORWARD_HTTPS_BROWSER_TERMINAL_KIND_V3.NORMAL_CLOSE) {
    if (normalized.terminal !== 1 || normalized.terminalEvidence !== null || hasOutstanding ||
        !lastResult || lastResult.requestKind !== FORWARD_HTTPS_REQUEST_KIND_V1.CLOSE) {
      fail('normal-close terminal state is inconsistent')
    }
    assertForwardHttpsSessionV3({
      version: 3,
      verifiedEndpoint: endpoint,
      stableSessionId: normalized.stableSessionId,
      capabilityPrefixHash: normalized.capabilityPrefixHash,
      clientSessionNonce: normalized.clientSessionNonce,
      nextSequence: normalized.nextSequence,
      previousTargetResultHash: normalized.previousTargetResultHash,
      terminal: 1,
      outstandingState: normalized.outstandingState,
      outstandingOriginRequestCommitment: normalized.outstandingOriginRequestCommitment,
      outstandingOriginRequest: normalized.outstandingOriginRequest,
      lastDefinitiveTargetResult: normalized.lastDefinitiveTargetResult
    }, WIRE_V3_ABI_HASH)
  } else {
    if (normalized.terminal !== 1 || hasOutstanding || normalized.terminalEvidence === null) {
      fail('correctness terminal must clear live outstanding state and retain evidence')
    }
    const evidence = normalized.terminalEvidence
    if (decimalU64(evidence.sequence, 'terminalEvidence.sequence') !== normalized.nextSequence ||
        !b4a.equals(forwardHttpsOriginRequestCommitmentV1(evidence.originRequest), evidence.originRequestCommitment)) {
      fail('correctness terminal evidence does not bind the retained original request')
    }
    assertOriginBindsState(decodeOrigin(evidence.originRequest, 'terminalEvidence.originRequest'), {
      ...normalized,
      outstandingOriginRequestCommitment: evidence.originRequestCommitment
    }, endpoint)
    assertForwardHttpsSessionV3({
      version: 3,
      verifiedEndpoint: endpoint,
      stableSessionId: normalized.stableSessionId,
      capabilityPrefixHash: normalized.capabilityPrefixHash,
      clientSessionNonce: normalized.clientSessionNonce,
      nextSequence: normalized.nextSequence,
      previousTargetResultHash: normalized.previousTargetResultHash,
      terminal: 1,
      outstandingState: normalized.outstandingState,
      outstandingOriginRequestCommitment: normalized.outstandingOriginRequestCommitment,
      outstandingOriginRequest: normalized.outstandingOriginRequest,
      lastDefinitiveTargetResult: normalized.lastDefinitiveTargetResult
    }, WIRE_V3_ABI_HASH)
  }
  return snapshotRecord({ ...normalized, nextSequence: normalized.nextSequence.toString() })
}

function assertStoredRecordForKey (value, key) {
  const record = assertForwardHttpsPersistedSessionRecordV3(value)
  if (record.sessionKey !== key) fail('persisted browser sessionKey does not match its IndexedDB object-store key')
  return record
}

function assertPersistenceInput (value) {
  exactKeys(value, ['sessionKey', 'verifiedEndpoint', 'requestBytes'], 'origin persistence input')
  const key = sessionKey(value.sessionKey)
  const endpoint = copyEndpoint(value.verifiedEndpoint)
  const decoded = decodeOrigin(value.requestBytes)
  assertCapabilityMatchesEndpoint(decoded.request.parentCapability, endpoint)
  const stableSessionId = bytes(decoded.request.stableSessionId, 32, 'origin stableSessionId', true)
  const clientSessionNonce = bytes(decoded.request.clientSessionNonce, 32, 'origin clientSessionNonce', true)
  if (!b4a.equals(stableSessionId, forwardHttpsStableSessionIdV1(decoded.request.parentCapability, clientSessionNonce))) {
    fail('origin stableSessionId is not derived from its capability and client nonce')
  }
  return Object.freeze({
    sessionKey: key,
    verifiedEndpoint: endpoint,
    request: decoded.request,
    requestBytes: decoded.requestBytes,
    stableSessionId,
    capabilityPrefixHash: forwardHttpsCapabilityPrefixHashV1(decoded.requestBytes),
    clientSessionNonce,
    originRequestCommitment: forwardHttpsOriginRequestCommitmentV1(decoded.requestBytes)
  })
}

export function terminalizeForwardHttpsOriginConflictV3 (record) {
  record = assertForwardHttpsPersistedSessionRecordV3(record)
  if (record.terminalKind === FORWARD_HTTPS_BROWSER_TERMINAL_KIND_V3.CORRECTNESS) return record
  if (record.terminalKind !== FORWARD_HTTPS_BROWSER_TERMINAL_KIND_V3.NONE ||
      record.outstandingState === FORWARD_HTTPS_OUTSTANDING_STATE_V3.NONE) {
    terminalFail()
  }
  return assertForwardHttpsPersistedSessionRecordV3({
    ...record,
    terminal: 1,
    terminalKind: FORWARD_HTTPS_BROWSER_TERMINAL_KIND_V3.CORRECTNESS,
    outstandingState: FORWARD_HTTPS_OUTSTANDING_STATE_V3.NONE,
    outstandingOriginRequestCommitment: b4a.alloc(32),
    outstandingOriginRequest: b4a.alloc(0),
    terminalEvidence: {
      kind: FORWARD_HTTPS_BROWSER_TERMINAL_EVIDENCE_KIND_V3.OUTSTANDING_CONFLICT,
      originalOutstandingState: record.outstandingState,
      sequence: record.nextSequence,
      originRequestCommitment: record.outstandingOriginRequestCommitment,
      originRequest: record.outstandingOriginRequest
    }
  })
}

export function prepareForwardHttpsOriginPersistenceV3 (existing, value) {
  const current = existing == null ? null : assertForwardHttpsPersistedSessionRecordV3(existing)
  if (current && current.terminalKind !== FORWARD_HTTPS_BROWSER_TERMINAL_KIND_V3.NONE) terminalFail()
  let input
  try {
    input = assertPersistenceInput(value)
  } catch (error) {
    if (current && current.outstandingState !== FORWARD_HTTPS_OUTSTANDING_STATE_V3.NONE) {
      return Object.freeze({ disposition: 'CONFLICT_TERMINAL', record: terminalizeForwardHttpsOriginConflictV3(current), cause: error })
    }
    throw error
  }

  if (current && current.outstandingState !== FORWARD_HTTPS_OUTSTANDING_STATE_V3.NONE) {
    if (current.sessionKey === input.sessionKey && sameEndpoint(current.verifiedEndpoint, input.verifiedEndpoint) &&
        b4a.equals(current.outstandingOriginRequest, input.requestBytes)) {
      return Object.freeze({ disposition: 'EXACT_RETRY', record: current })
    }
    return Object.freeze({ disposition: 'CONFLICT_TERMINAL', record: terminalizeForwardHttpsOriginConflictV3(current) })
  }

  if (current == null) {
    if (input.request.sequence !== 0n || input.request.requestKind !== FORWARD_HTTPS_REQUEST_KIND_V1.OPEN ||
        !isZero(input.request.previousTargetResultHash)) {
      fail('new browser session requires canonical OPEN sequence zero with a zero previous chain')
    }
    const record = {
      recordVersion: 3,
      sessionKey: input.sessionKey,
      verifiedEndpoint: input.verifiedEndpoint,
      stableSessionId: input.stableSessionId,
      capabilityPrefixHash: input.capabilityPrefixHash,
      clientSessionNonce: input.clientSessionNonce,
      nextSequence: '0',
      previousTargetResultHash: b4a.alloc(32),
      terminal: 0,
      terminalKind: FORWARD_HTTPS_BROWSER_TERMINAL_KIND_V3.NONE,
      outstandingState: FORWARD_HTTPS_OUTSTANDING_STATE_V3.PERSISTED_BEFORE_FETCH,
      outstandingOriginRequestCommitment: input.originRequestCommitment,
      outstandingOriginRequest: input.requestBytes,
      lastDefinitiveTargetResult: b4a.alloc(0),
      targetFin: false,
      terminalEvidence: null
    }
    return Object.freeze({ disposition: 'PERSISTED', record: assertForwardHttpsPersistedSessionRecordV3(record) })
  }

  const nextSequence = decimalU64(current.nextSequence, 'nextSequence')
  if (input.sessionKey !== current.sessionKey || !sameEndpoint(input.verifiedEndpoint, current.verifiedEndpoint) ||
      !b4a.equals(input.stableSessionId, current.stableSessionId) ||
      !b4a.equals(input.capabilityPrefixHash, current.capabilityPrefixHash) ||
      !b4a.equals(input.clientSessionNonce, current.clientSessionNonce) ||
      input.request.sequence !== nextSequence || input.request.requestKind === FORWARD_HTTPS_REQUEST_KIND_V1.OPEN ||
      !b4a.equals(input.request.previousTargetResultHash, current.previousTargetResultHash)) {
    fail('later origin request does not preserve the exact endpoint, session, sequence and chain anchors')
  }
  const record = {
    ...current,
    outstandingState: FORWARD_HTTPS_OUTSTANDING_STATE_V3.PERSISTED_BEFORE_FETCH,
    outstandingOriginRequestCommitment: input.originRequestCommitment,
    outstandingOriginRequest: input.requestBytes
  }
  return Object.freeze({ disposition: 'PERSISTED', record: assertForwardHttpsPersistedSessionRecordV3(record) })
}

export function markForwardHttpsAwaitingDefinitiveTargetV3 (record) {
  record = assertForwardHttpsPersistedSessionRecordV3(record)
  if (record.terminalKind !== FORWARD_HTTPS_BROWSER_TERMINAL_KIND_V3.NONE) terminalFail()
  if (record.outstandingState === FORWARD_HTTPS_OUTSTANDING_STATE_V3.NONE) fail('no exact outstanding origin request exists')
  return assertForwardHttpsPersistedSessionRecordV3({
    ...record,
    outstandingState: FORWARD_HTTPS_OUTSTANDING_STATE_V3.AWAITING_DEFINITIVE_TARGET
  })
}

function verifiedOutcome (assertion, resultBytes, advanced, record) {
  return Object.freeze({
    verified: true,
    advanced,
    resultRole: assertion.result.resultRole,
    requestKind: assertion.result.requestKind,
    responseKind: assertion.result.responseKind,
    sequence: assertion.result.sequence.toString(),
    targetResultChainHash: assertion.targetResultChainHash == null ? null : b4a.from(assertion.targetResultChainHash),
    targetFin: record.targetFin || assertion.targetFin,
    normalClose: assertion.normalClose,
    nextSequence: record.nextSequence,
    terminal: record.terminal,
    terminalKind: record.terminalKind,
    resultBytes: b4a.from(resultBytes)
  })
}

export function applyForwardHttpsResultV3 (record, exactResultBytes) {
  record = assertForwardHttpsPersistedSessionRecordV3(record)
  if (record.terminalKind !== FORWARD_HTTPS_BROWSER_TERMINAL_KIND_V3.NONE) terminalFail()
  if (record.outstandingState === FORWARD_HTTPS_OUTSTANDING_STATE_V3.NONE) fail('result has no exact outstanding origin request')
  const resultBytes = bytes(exactResultBytes, 65_536, 'resultBytes')
  const assertion = assertForwardHttpsResultForOriginRequestV1(record.outstandingOriginRequest, resultBytes)
  assertResultMatchesEndpoint(assertion, record.verifiedEndpoint)
  if (assertion.result.resultRole !== FORWARD_HTTPS_RESULT_ROLE_V1.TARGET_RESULT) {
    return Object.freeze({ record, outcome: verifiedOutcome(assertion, resultBytes, false, record) })
  }
  const next = assertForwardHttpsPersistedSessionRecordV3({
    ...record,
    nextSequence: (decimalU64(record.nextSequence, 'nextSequence') + 1n).toString(),
    previousTargetResultHash: assertion.targetResultChainHash,
    terminal: assertion.normalClose ? 1 : 0,
    terminalKind: assertion.normalClose
      ? FORWARD_HTTPS_BROWSER_TERMINAL_KIND_V3.NORMAL_CLOSE
      : FORWARD_HTTPS_BROWSER_TERMINAL_KIND_V3.NONE,
    outstandingState: FORWARD_HTTPS_OUTSTANDING_STATE_V3.NONE,
    outstandingOriginRequestCommitment: b4a.alloc(32),
    outstandingOriginRequest: b4a.alloc(0),
    lastDefinitiveTargetResult: resultBytes,
    targetFin: record.targetFin || assertion.targetFin,
    terminalEvidence: null
  })
  return Object.freeze({ record: next, outcome: verifiedOutcome(assertion, resultBytes, true, next) })
}

function requestV3 (request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error || new Error('IndexedDB request failed'))
  })
}

function transactionV3 (transaction) {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve()
    transaction.onabort = () => reject(transaction.error || new Error('IndexedDB transaction aborted'))
    transaction.onerror = () => reject(transaction.error || new Error('IndexedDB transaction failed'))
  })
}

async function abortTransaction (transaction, done, error) {
  try { transaction.abort() } catch {}
  try { await done } catch {}
  throw error
}

export function openForwardHttpsIndexedDbV3 (name = 'hiverelay-blind-forward-v3') {
  if (!globalThis.indexedDB) fail('IndexedDB is required')
  if (typeof name !== 'string' || name.length === 0) fail('IndexedDB name must be nonempty')
  return new Promise((resolve, reject) => {
    const request = globalThis.indexedDB.open(name, 1)
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_V3)) request.result.createObjectStore(STORE_V3)
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error || new Error('IndexedDB open failed'))
  })
}

export async function persistForwardHttpsOriginBeforeFetchV3 (database, value) {
  if (!database || typeof database.transaction !== 'function') fail('IndexedDB database is required')
  const key = sessionKey(value && value.sessionKey)
  const transaction = database.transaction(STORE_V3, 'readwrite')
  const done = transactionV3(transaction)
  const store = transaction.objectStore(STORE_V3)
  let prepared
  try {
    const existing = await requestV3(store.get(key))
    prepared = prepareForwardHttpsOriginPersistenceV3(existing == null ? null : assertStoredRecordForKey(existing, key), value)
    store.put(prepared.record, key)
  } catch (error) {
    return abortTransaction(transaction, done, error)
  }
  await done
  if (prepared.disposition === 'CONFLICT_TERMINAL') terminalFail('changed or causally invalid bytes terminalized the outstanding browser request')
  return b4a.from(prepared.record.outstandingOriginRequest)
}

export async function loadForwardHttpsSessionV3 (database, key) {
  if (!database || typeof database.transaction !== 'function') fail('IndexedDB database is required')
  key = sessionKey(key)
  const transaction = database.transaction(STORE_V3, 'readonly')
  const done = transactionV3(transaction)
  const value = await requestV3(transaction.objectStore(STORE_V3).get(key))
  await done
  return value == null ? null : assertStoredRecordForKey(value, key)
}

async function markPersistedForwardHttpsAwaitingV3 (database, key) {
  key = sessionKey(key)
  const transaction = database.transaction(STORE_V3, 'readwrite')
  const done = transactionV3(transaction)
  const store = transaction.objectStore(STORE_V3)
  let next
  try {
    const existing = await requestV3(store.get(key))
    if (existing == null) fail('no persisted browser session exists')
    next = markForwardHttpsAwaitingDefinitiveTargetV3(assertStoredRecordForKey(existing, key))
    store.put(next, key)
  } catch (error) {
    return abortTransaction(transaction, done, error)
  }
  await done
  return b4a.from(next.outstandingOriginRequest)
}

export async function commitVerifiedForwardHttpsResultV3 (database, key, exactResultBytes) {
  if (!database || typeof database.transaction !== 'function') fail('IndexedDB database is required')
  key = sessionKey(key)
  const resultBytes = bytes(exactResultBytes, 65_536, 'resultBytes')
  const transaction = database.transaction(STORE_V3, 'readwrite')
  const done = transactionV3(transaction)
  const store = transaction.objectStore(STORE_V3)
  let applied
  try {
    const existing = await requestV3(store.get(key))
    if (existing == null) fail('result has no persisted browser session')
    applied = applyForwardHttpsResultV3(assertStoredRecordForKey(existing, key), resultBytes)
    if (applied.outcome.advanced) store.put(applied.record, key)
  } catch (error) {
    return abortTransaction(transaction, done, error)
  }
  await done
  return applied.outcome
}

async function verifiedTransportV3 (database, key, requestBytes, transport) {
  if (typeof transport !== 'function') fail('opaque transport callback is required')
  const exact = b4a.from(requestBytes)
  const returned = await transport(b4a.from(exact))
  return commitVerifiedForwardHttpsResultV3(database, key, bytes(returned, 65_536, 'transport result'))
}

export async function fetchPersistedForwardHttpsOriginV3 (database, value, transport) {
  await persistForwardHttpsOriginBeforeFetchV3(database, value)
  const exact = await markPersistedForwardHttpsAwaitingV3(database, value.sessionKey)
  return verifiedTransportV3(database, value.sessionKey, exact, transport)
}

export async function retryPersistedForwardHttpsOriginV3 (database, key, transport) {
  const exact = await markPersistedForwardHttpsAwaitingV3(database, key)
  return verifiedTransportV3(database, key, exact, transport)
}

export {
  FORWARD_HTTPS_OUTSTANDING_STATE_V3,
  FORWARD_HTTPS_REQUEST_KIND_V1,
  FORWARD_HTTPS_RESPONSE_KIND_V1,
  FORWARD_HTTPS_RESULT_ROLE_V1
}
