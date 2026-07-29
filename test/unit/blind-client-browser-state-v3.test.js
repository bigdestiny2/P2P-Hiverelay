import test from 'brittle'
import b4a from 'b4a'
import fs from 'node:fs'
import path from 'node:path'
import { decodeCanonical } from '../../packages/blind-protocol/codec.js'
import {
  FORWARD_HTTPS_REQUEST_KIND_V1,
  FORWARD_HTTPS_RESPONSE_KIND_V1,
  blindForwardHttpsOriginForwardTurnRequestV1
} from '../../packages/blind-protocol/wire-v3.js'
import { assertForwardHttpsSessionV3 } from '../../packages/blind-protocol/client-composition-v3.js'
import {
  BLIND_CLIENT_CONTROL_V3_AUTHORITY,
  FORWARD_HTTPS_BROWSER_TERMINAL_KIND_V3,
  FORWARD_HTTPS_OUTSTANDING_STATE_V3,
  applyForwardHttpsResultV3,
  assertForwardHttpsPersistedSessionRecordV3,
  markForwardHttpsAwaitingDefinitiveTargetV3,
  prepareForwardHttpsOriginPersistenceV3
} from '../../packages/blind-client/browser-forward-state-v3.js'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../..')
const vector = name => fs.readFileSync(path.join(root, 'packages/blind-protocol/vectors-v3/wire/positive', name))

function endpointFor (originBytes) {
  const origin = decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, originBytes, { copyBytes: true })
  const capability = origin.parentCapability
  return {
    version: 3,
    releaseProfileId: 2,
    routeKind: 7,
    wireV3AbiHash: b4a.from(BLIND_CLIENT_CONTROL_V3_AUTHORITY.wireV3AbiHash, 'hex'),
    verifiedEndpointHandleHash: b4a.alloc(32, 0xa1),
    sourceRelayPublicKey: capability.sourceRelayPublicKey,
    sourceDescriptorSequence: capability.sourceDescriptorSequence,
    sourceDescriptorHash: capability.sourceDescriptorHash,
    targetCatalogEntryId: capability.targetCatalogEntryId,
    targetRelayPublicKey: capability.targetRelayPublicKey,
    targetDescriptorSequence: capability.targetDescriptorSequence,
    targetDescriptorHash: capability.targetDescriptorHash,
    signedDescriptorHash: b4a.alloc(32, 0xa2),
    signedHealthHash: b4a.alloc(32, 0xa3),
    descriptorFresh: true,
    signedHealthFresh: true,
    credentialFreeHttps: true,
    cookies: false,
    authorization: false,
    referrer: false,
    redirect: false,
    exactRequestBytes: 65_536,
    exactResultBytes: 65_536,
    continuityBackend: 'INDEXEDDB_PERSISTENT'
  }
}

function input (sessionKey, endpoint, requestBytes) {
  return { sessionKey, verifiedEndpoint: endpoint, requestBytes }
}

function publicSession (record, overrides = {}) {
  return {
    version: 3,
    verifiedEndpoint: record.verifiedEndpoint,
    stableSessionId: record.stableSessionId,
    capabilityPrefixHash: record.capabilityPrefixHash,
    clientSessionNonce: record.clientSessionNonce,
    nextSequence: BigInt(record.nextSequence),
    previousTargetResultHash: record.previousTargetResultHash,
    terminal: record.terminal,
    outstandingState: record.outstandingState,
    outstandingOriginRequestCommitment: record.outstandingOriginRequestCommitment,
    outstandingOriginRequest: record.outstandingOriginRequest,
    lastDefinitiveTargetResult: record.lastDefinitiveTargetResult,
    ...overrides
  }
}

function openedRecord () {
  const origin = vector('open-origin.bin')
  const endpoint = endpointFor(origin)
  const persisted = prepareForwardHttpsOriginPersistenceV3(null, input('session', endpoint, origin))
  return { endpoint, origin, record: persisted.record }
}

test('browser v3 state derives full ID10 from exact signed-vector authority and retries idempotently', t => {
  const { endpoint, origin, record } = openedRecord()
  t.is(record.outstandingState, FORWARD_HTTPS_OUTSTANDING_STATE_V3.PERSISTED_BEFORE_FETCH)
  t.is(record.nextSequence, '0')
  t.alike(record.outstandingOriginRequest, origin)
  t.alike(record.verifiedEndpoint, endpoint)
  t.ok(assertForwardHttpsSessionV3(publicSession(record)))

  const retry = prepareForwardHttpsOriginPersistenceV3(record, input('session', endpoint, origin))
  t.is(retry.disposition, 'EXACT_RETRY')
  t.alike(retry.record.outstandingOriginRequest, origin)
  t.alike(retry.record.verifiedEndpoint, endpoint)
})

test('browser v3 changed outstanding bytes atomically retain closed terminal evidence and absorb all mutation', t => {
  const { endpoint, origin, record } = openedRecord()
  const changed = b4a.from(origin)
  changed[100] ^= 1
  const conflict = prepareForwardHttpsOriginPersistenceV3(record, input('session', endpoint, changed))
  t.is(conflict.disposition, 'CONFLICT_TERMINAL')
  t.is(conflict.record.terminal, 1)
  t.is(conflict.record.terminalKind, FORWARD_HTTPS_BROWSER_TERMINAL_KIND_V3.CORRECTNESS)
  t.is(conflict.record.outstandingState, FORWARD_HTTPS_OUTSTANDING_STATE_V3.NONE)
  t.is(conflict.record.outstandingOriginRequest.byteLength, 0)
  t.alike(conflict.record.terminalEvidence.originRequest, origin)
  t.alike(conflict.record.terminalEvidence.originRequestCommitment, record.outstandingOriginRequestCommitment)
  t.ok(assertForwardHttpsSessionV3(publicSession(conflict.record)))
  t.exception(() => markForwardHttpsAwaitingDefinitiveTargetV3(conflict.record), /terminal/)
  t.exception(() => applyForwardHttpsResultV3(conflict.record, vector('open-target-result.bin')), /terminal/)
  t.exception(() => prepareForwardHttpsOriginPersistenceV3(conflict.record, input('session', endpoint, origin)), /terminal/)
  t.exception(() => assertForwardHttpsPersistedSessionRecordV3({
    ...conflict.record,
    terminalEvidence: { ...conflict.record.terminalEvidence, callerReason: 'forged' }
  }), /unknown or missing/)
})

test('browser v3 verifies exact ID77 internally, retains source results, and advances target atomically', t => {
  const { record } = openedRecord()
  const awaiting = markForwardHttpsAwaitingDefinitiveTargetV3(record)
  const source = applyForwardHttpsResultV3(awaiting, vector('open-source-pre-forward-error.bin'))
  t.is(source.outcome.verified, true)
  t.is(source.outcome.advanced, false)
  t.is(source.record.nextSequence, '0')
  t.is(source.record.outstandingState, FORWARD_HTTPS_OUTSTANDING_STATE_V3.AWAITING_DEFINITIVE_TARGET)
  t.alike(source.record.outstandingOriginRequest, record.outstandingOriginRequest)

  t.exception(() => applyForwardHttpsResultV3(awaiting, b4a.alloc(65_536)), /magic|invalid/)
  t.exception(() => applyForwardHttpsResultV3(awaiting, vector('data-target-ack.bin')), /bind|provenance|commitment/)
  t.is(awaiting.nextSequence, '0')
  t.is(awaiting.outstandingState, FORWARD_HTTPS_OUTSTANDING_STATE_V3.AWAITING_DEFINITIVE_TARGET)

  const target = applyForwardHttpsResultV3(awaiting, vector('open-target-result.bin'))
  t.is(target.outcome.verified, true)
  t.is(target.outcome.advanced, true)
  t.is(target.record.nextSequence, '1')
  t.is(target.record.outstandingState, FORWARD_HTTPS_OUTSTANDING_STATE_V3.NONE)
  t.is(target.record.terminal, 0)
  t.is(target.record.targetFin, false)
  t.alike(target.record.lastDefinitiveTargetResult, vector('open-target-result.bin'))
  t.ok(assertForwardHttpsSessionV3(publicSession(target.record)))
})

test('browser v3 preserves later-turn history and separates target FIN from normal close', t => {
  const opened = openedRecord()
  const first = applyForwardHttpsResultV3(
    markForwardHttpsAwaitingDefinitiveTargetV3(opened.record),
    vector('open-target-result.bin')
  ).record
  const data = vector('data-origin-max.bin')
  const later = prepareForwardHttpsOriginPersistenceV3(first, input('session', opened.endpoint, data)).record
  t.alike(later.lastDefinitiveTargetResult, vector('open-target-result.bin'))
  const fin = applyForwardHttpsResultV3(later, vector('data-target-close.bin'))
  t.is(fin.outcome.responseKind, FORWARD_HTTPS_RESPONSE_KIND_V1.CLOSE)
  t.is(fin.outcome.targetFin, true)
  t.is(fin.outcome.normalClose, false)
  t.is(fin.record.targetFin, true)
  t.is(fin.record.terminal, 0)
  t.is(fin.record.terminalKind, FORWARD_HTTPS_BROWSER_TERMINAL_KIND_V3.NONE)

  const closeOrigin = vector('close-origin.bin')
  const closeOutstanding = prepareForwardHttpsOriginPersistenceV3(first, input('session', opened.endpoint, closeOrigin)).record
  const closed = applyForwardHttpsResultV3(closeOutstanding, vector('close-target-ack.bin'))
  t.is(closed.outcome.requestKind, FORWARD_HTTPS_REQUEST_KIND_V1.CLOSE)
  t.is(closed.outcome.normalClose, true)
  t.is(closed.outcome.targetFin, false)
  t.is(closed.record.terminal, 1)
  t.is(closed.record.terminalKind, FORWARD_HTTPS_BROWSER_TERMINAL_KIND_V3.NORMAL_CLOSE)
  t.ok(assertForwardHttpsSessionV3(publicSession(closed.record)))
})

test('browser v3 recovered advanced state rejects forged close, targetFin, session and prefix before transport', t => {
  const opened = openedRecord()
  let transportCalls = 0
  const beforeTransport = record => {
    assertForwardHttpsPersistedSessionRecordV3(record)
    transportCalls++
  }
  t.exception(() => beforeTransport({ ...opened.record, targetFin: true }), /sequence-zero/)
  const advanced = applyForwardHttpsResultV3(opened.record, vector('open-target-result.bin')).record
  t.exception(() => beforeTransport({ ...advanced, terminal: 1, terminalKind: 'NORMAL_CLOSE' }), /iff|normal-close/)
  t.exception(() => beforeTransport({ ...advanced, targetFin: true }), /sequence-zero|targetFin|CLOSE/)
  t.exception(() => beforeTransport({ ...advanced, stableSessionId: b4a.alloc(32, 0xf1) }), /bind|session/)
  t.exception(() => beforeTransport({ ...advanced, capabilityPrefixHash: b4a.alloc(32, 0xf2) }), /prefix|bind/)
  t.is(transportCalls, 0)

  const closeOutstanding = prepareForwardHttpsOriginPersistenceV3(advanced, input('session', opened.endpoint, vector('close-origin.bin'))).record
  const closed = applyForwardHttpsResultV3(closeOutstanding, vector('close-target-close.bin')).record
  t.exception(() => beforeTransport({ ...closed, terminal: 0, terminalKind: 'NONE' }), /iff|CLOSE/)
  t.exception(() => beforeTransport({ ...closed, targetFin: false }), /targetFin/)
  t.is(transportCalls, 0)
})
