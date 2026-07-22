import fs from 'node:fs'
import test from 'brittle'
import b4a from 'b4a'
import {
  ERROR_CODE,
  FAMILY,
  FRAME_KIND,
  OPERATION,
  STORE_LIFECYCLE_STATE,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  blindErrorV1,
  coreOpenReplicationV1,
  coreServeChallengeV1,
  coreServeResultV1,
  decodeCanonical,
  decodeDispatchFrame,
  encodeCanonical,
  encodeDispatchFrame,
  getCellResultV1,
  getCellV1,
  inboxReadResultV1,
  inboxWatchV1
} from '@hiverelay/blind-protocol'
import {
  BlindOperationCoordinator,
  COORDINATOR_RELEASE_BLOCKERS,
  assertResultWitnessPolicy,
  deriveOperationDeadline,
  profile2WitnessRequired
} from '../coordinator.js'
import { DescriptorState } from '../descriptor-state.js'
import { daemonOperationProfile } from '../operation-catalog.js'
import { ResourceBudget } from '../resource-budget.js'
import { fixtureCoreOpen } from './stream-fixtures.js'
import {
  descriptorBytes,
  fixtureBytes,
  successorBytes
} from './coordinator-fixtures.js'

const coreRequest = fs.readFileSync(new URL(
  '../../blind-protocol/vectors/draft/core/serve-challenge.bin', import.meta.url))
const coreMirrorRequest = fs.readFileSync(new URL(
  '../../blind-protocol/vectors/draft/core/mirror-request.bin', import.meta.url))
const coreResult = fs.readFileSync(new URL(
  '../../blind-protocol/vectors/draft/core/serve-result.bin', import.meta.url))
const forwardData = fs.readFileSync(new URL(
  '../../blind-protocol/vectors/draft/forward/data-body.bin', import.meta.url))
const forwardClose = fs.readFileSync(new URL(
  '../../blind-protocol/vectors/draft/forward/close.bin', import.meta.url))
const inboxReadResult = fs.readFileSync(new URL(
  '../../blind-protocol/vectors/draft/inbox/read-result-empty.bin', import.meta.url))

function requestFrame (familyId, operationId, body) {
  return {
    frameKind: FRAME_KIND.REQUEST,
    familyId,
    operationId,
    requestId: fixtureBytes(16, 0x11),
    body
  }
}

function context (overrides = {}) {
  return {
    endpointId: 1,
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    outerClass: 6,
    acceptedMonotonicMillis: 1000n,
    absoluteDeadlineMonotonicMillis: 15000n,
    ...overrides
  }
}

async function activeDescriptor (overrides = {}) {
  const state = new DescriptorState({
    epochNow: () => 101,
    verifySignature: async () => true
  })
  await state.activate(descriptorBytes(overrides))
  return state
}

function errorName (dispatch) {
  const frame = decodeDispatchFrame(dispatch, { copyBody: true })
  const value = decodeCanonical(blindErrorV1, frame.body)
  return Object.keys(ERROR_CODE).find(name => ERROR_CODE[name] === value.code)
}

function resultFor (requestCommitment, descriptorState) {
  const value = decodeCanonical(coreServeResultV1, coreResult, { copyBytes: true })
  const request = decodeCanonical(coreServeChallengeV1, coreRequest)
  const snapshot = descriptorState.requireCurrent()
  value.acknowledgement.relayBinding = descriptorState.resultBinding(snapshot)
  value.acknowledgement.requestCommitment = b4a.from(requestCommitment)
  value.acknowledgement.requestNonce = b4a.from(request.clientNonce)
  return encodeCanonical(coreServeResultV1, value)
}

function harness (options = {}) {
  let now = 1001n
  const events = []
  const descriptorState = options.descriptorState
  const coordinator = new BlindOperationCoordinator({
    descriptorState,
    admission: options.admission || {
      async prepare () { events.push('admission'); return null },
      parametersForRequest: () => null
    },
    readiness: options.readiness || {
      async evaluate () {
        events.push('readiness')
        const snapshot = descriptorState.requireCurrent()
        return {
          kind: 1,
          endpoint: { endpointId: 1 },
          descriptorSequence: snapshot.descriptorSequence,
          descriptorHash: snapshot.hash,
          transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
          readyRoleBits: 1,
          readyOperationBits: snapshot.descriptor.enabledOperationBits,
          effectiveEpochFloor: 101,
          capacityBand: snapshot.descriptor.capacityBand
        }
      }
    },
    budget: options.budget || new ResourceBudget({ maxItems: 32, maxBytes: 32 * 1024 * 1024 }),
    relationVerifier: options.relationVerifier || {
      async verify (input) { events.push('relation'); return true }
    },
    capabilityVerifier: options.capabilityVerifier || {
      async verify () { events.push('authorization'); return true }
    },
    cheapStateVerifier: options.cheapStateVerifier || {
      async inspect () { events.push('cheap'); return { canonicalResultBytes: coreResult.byteLength } }
    },
    terminalStateVerifier: options.terminalStateVerifier || {
      async check () { events.push('terminal') }
    },
    capacityGuard: options.capacityGuard || {
      async check () { events.push('capacity') }
    },
    operationExecutor: options.operationExecutor || {
      async execute (input) {
        events.push('execute')
        return resultFor(input.requestCommitment, descriptorState)
      }
    },
    resultVerifier: options.resultVerifier || {
      async verify (input) {
        events.push('result')
        input.result.acknowledgement.requestCommitment.fill(0)
        return true
      }
    },
    authenticatedSessionVerifier: options.authenticatedSessionVerifier || {
      async verify () { return Object.freeze({ kind: 'verified-session' }) }
    },
    transactionCoordinator: options.transactionCoordinator,
    streamExecutor: options.streamExecutor,
    monotonicMillis: () => now
  })
  return { coordinator, events, setNow: value => { now = value } }
}

test('coordinator success preserves canonical authority across hostile hooks and frozen stage order', async t => {
  const state = await activeDescriptor()
  const relationVerifier = {
    async verify (input) {
      input.request.corePublicKey.fill(0)
      input.descriptor.relayPublicKey.fill(0)
      return true
    }
  }
  const h = harness({ descriptorState: state, relationVerifier })
  const result = await h.coordinator.dispatch(requestFrame(FAMILY.CORE, OPERATION.CORE.PROVE, coreRequest), context())
  const response = decodeDispatchFrame(result.dispatch, { copyBody: true })
  t.is(response.frameKind, FRAME_KIND.RESPONSE)
  const decoded = decodeCanonical(coreServeResultV1, response.body)
  t.not(decoded.acknowledgement.requestCommitment[0], 0)
  t.alike(h.events, ['authorization', 'cheap', 'terminal', 'readiness', 'capacity', 'execute', 'result'])
})

test('unsigned CELL.GET result is verified without fabricating a relay binding', async t => {
  const state = await activeDescriptor()
  const request = {
    version: 1,
    storageSlot: fixtureBytes(32, 0x91),
    clientNonce: fixtureBytes(32, 0x92),
    admission: null
  }
  const body = encodeCanonical(getCellResultV1, {
    version: 1,
    sizeClass: 1,
    cellBlob: fixtureBytes(4096, 0x93)
  })
  let verified = false
  const h = harness({
    descriptorState: state,
    cheapStateVerifier: {
      async inspect () { return { predictedResultBodyBytes: body.byteLength } }
    },
    operationExecutor: { async execute () { return body } },
    resultVerifier: {
      async verify (input) {
        t.is(input.resultSignatureDomainId, 0)
        t.is(input.expectedRelayBinding, null)
        verified = true
        return true
      }
    }
  })
  const result = await h.coordinator.dispatch(requestFrame(
    FAMILY.CELL, OPERATION.CELL.GET, encodeCanonical(getCellV1, request)), context())
  const response = decodeDispatchFrame(result.dispatch, { copyBody: true })
  t.is(response.frameKind, FRAME_KIND.RESPONSE)
  t.alike(response.body, body)
  t.is(verified, true)
})

test('coordinator frozen failures stop later hooks and ACTIVE/DRAINING use distinct codes', async t => {
  const active = await activeDescriptor()
  let authorization = 0
  const relation = harness({
    descriptorState: active,
    relationVerifier: { async verify () { return false } },
    capabilityVerifier: { async verify () { authorization++; return false } }
  })
  const badSlot = await relation.coordinator.dispatch(
    requestFrame(FAMILY.CORE, OPERATION.CORE.PROVE, coreRequest), context())
  t.is(errorName(badSlot.dispatch), 'BAD_SLOT')
  t.is(authorization, 0)

  const disabled = await activeDescriptor({ enabledOperationBits: 0x00000007 })
  const unsupported = await harness({ descriptorState: disabled }).coordinator.dispatch(
    requestFrame(FAMILY.CORE, OPERATION.CORE.PROVE, coreRequest), context())
  t.is(errorName(unsupported.dispatch), 'TRANSPORT_UNSUPPORTED')

  const drainState = await activeDescriptor()
  const initial = drainState.requireCurrent()
  await drainState.activate(successorBytes(initial, {
    storeLifecycleState: STORE_LIFECYCLE_STATE.DRAINING,
    drainStartedEpoch: 101,
    enabledOperationBits: 0x000129d7
  }))
  const draining = await harness({ descriptorState: drainState }).coordinator.dispatch(
    requestFrame(FAMILY.CORE, OPERATION.CORE.MIRROR, coreMirrorRequest), context())
  t.is(errorName(draining.dispatch), 'BUSY')

  const chargedRead = decodeCanonical(coreServeChallengeV1, coreRequest, { copyBytes: true })
  chargedRead.admission = {
    profileId: 7,
    schemeId: 9,
    parameterHash: fixtureBytes(32, 0xa1),
    token: fixtureBytes(8, 0xa2)
  }
  let relationCalls = 0
  const chargedHarness = harness({
    descriptorState: drainState,
    relationVerifier: { async verify () { relationCalls++; return true } }
  })
  const charged = await chargedHarness.coordinator.dispatch(
    requestFrame(FAMILY.CORE, OPERATION.CORE.PROVE,
      encodeCanonical(coreServeChallengeV1, chargedRead)), context())
  t.is(errorName(charged.dispatch), 'BUSY')
  t.is(relationCalls, 0)
})

test('multiple simultaneous faults always select the frozen earliest stage', async t => {
  const state = await activeDescriptor()
  let later = 0
  const authorization = harness({
    descriptorState: state,
    capabilityVerifier: { async verify () { return false } },
    cheapStateVerifier: { async inspect () { later++; throw new Error('later cheap fault') } }
  })
  let result = await authorization.coordinator.dispatch(
    requestFrame(FAMILY.CORE, OPERATION.CORE.MIRROR, coreMirrorRequest), context())
  t.is(errorName(result.dispatch), 'NOT_FOUND')
  t.is(later, 0)

  const cheap = harness({
    descriptorState: state,
    cheapStateVerifier: {
      async inspect () {
        const error = new Error('cheap state wins')
        error.code = 'STALE_REVISION'
        throw error
      }
    },
    admission: { async prepare () { later++; throw new Error('later admission fault') } }
  })
  result = await cheap.coordinator.dispatch(
    requestFrame(FAMILY.CORE, OPERATION.CORE.MIRROR, coreMirrorRequest), context())
  t.is(errorName(result.dispatch), 'STALE_REVISION')
  t.is(later, 0)

  const admission = harness({
    descriptorState: state,
    cheapStateVerifier: { async inspect () { return { coreBillableBytes: 16n } } },
    admission: {
      async prepare () {
        const error = new Error('admission wins')
        error.code = 'SPEND_INVALID'
        throw error
      }
    },
    terminalStateVerifier: { async check () { later++; throw new Error('later terminal fault') } }
  })
  result = await admission.coordinator.dispatch(
    requestFrame(FAMILY.CORE, OPERATION.CORE.MIRROR, coreMirrorRequest), context())
  t.is(errorName(result.dispatch), 'SPEND_INVALID')
  t.is(later, 0)

  const prepared = {
    spendTag: fixtureBytes(32, 1),
    requestCommitment: fixtureBytes(32, 2),
    costClass: { resourceClass: 1, leaseClass: 1, costUnits: 1n },
    walCommitRecord: fixtureBytes(1, 3),
    profileId: 7,
    schemeId: 9,
    parameterHash: fixtureBytes(32, 4)
  }
  const transactionCoordinator = {
    async lookup () { return { kind: 'fresh' } },
    async run (input, execute) { return execute({}) },
    async replay () { later++; throw new Error('later replay fault') }
  }
  const terminal = harness({
    descriptorState: state,
    cheapStateVerifier: { async inspect () { return { coreBillableBytes: 16n } } },
    admission: { async prepare () { return prepared } },
    transactionCoordinator,
    terminalStateVerifier: {
      async check () {
        const error = new Error('terminal wins')
        error.code = 'EXPIRED'
        throw error
      }
    },
    readiness: { async evaluate () { later++; return { kind: 2 } } }
  })
  result = await terminal.coordinator.dispatch(
    requestFrame(FAMILY.CORE, OPERATION.CORE.MIRROR, coreMirrorRequest), context())
  t.is(errorName(result.dispatch), 'EXPIRED')
  t.is(later, 0)

  const readiness = harness({
    descriptorState: state,
    cheapStateVerifier: { async inspect () { return { coreBillableBytes: 16n } } },
    admission: { async prepare () { return prepared } },
    transactionCoordinator,
    readiness: { async evaluate () { return { kind: 2 } } },
    capacityGuard: { async check () { later++; throw new Error('later capacity fault') } }
  })
  result = await readiness.coordinator.dispatch(
    requestFrame(FAMILY.CORE, OPERATION.CORE.MIRROR, coreMirrorRequest), context())
  t.is(errorName(result.dispatch), 'BUSY')
  t.is(later, 0)

  let executed = 0
  const capacity = harness({
    descriptorState: state,
    cheapStateVerifier: { async inspect () { return { coreBillableBytes: 16n } } },
    admission: { async prepare () { return prepared } },
    transactionCoordinator,
    capacityGuard: {
      async check () {
        const error = new Error('capacity wins')
        error.code = 'BUSY'
        throw error
      }
    },
    operationExecutor: { async execute () { executed++; throw new Error('later executor fault') } }
  })
  result = await capacity.coordinator.dispatch(
    requestFrame(FAMILY.CORE, OPERATION.CORE.MIRROR, coreMirrorRequest), context())
  t.is(errorName(result.dispatch), 'BUSY')
  t.is(executed, 0)
})

test('committed replay remains readiness, capacity, and resource-budget gated before regeneration', async t => {
  const state = await activeDescriptor()
  let regenerated = 0
  const prepared = {
    spendTag: fixtureBytes(32, 1),
    requestCommitment: fixtureBytes(32, 2),
    costClass: { resourceClass: 1, leaseClass: 1, costUnits: 1n },
    walCommitRecord: fixtureBytes(1, 3),
    profileId: 7,
    schemeId: 9,
    parameterHash: fixtureBytes(32, 4)
  }
  const transactionCoordinator = {
    async lookup () { return { kind: 'replay' } },
    async run () { throw new Error('replay entered fresh run') },
    async replay () { regenerated++; throw new Error('regenerated too early') }
  }
  const shared = {
    descriptorState: state,
    cheapStateVerifier: { async inspect () { return { coreBillableBytes: 16n } } },
    admission: { async prepare () { return prepared } },
    transactionCoordinator
  }
  let h = harness({ ...shared, readiness: { async evaluate () { return { kind: 2 } } } })
  let result = await h.coordinator.dispatch(
    requestFrame(FAMILY.CORE, OPERATION.CORE.MIRROR, coreMirrorRequest), context())
  t.is(errorName(result.dispatch), 'BUSY')
  t.is(regenerated, 0)

  h = harness({
    ...shared,
    budget: {
      acquire () {
        const error = new Error('budget saturated')
        error.code = 'BUSY'
        throw error
      }
    }
  })
  result = await h.coordinator.dispatch(
    requestFrame(FAMILY.CORE, OPERATION.CORE.MIRROR, coreMirrorRequest), context())
  t.is(errorName(result.dispatch), 'BUSY')
  t.is(regenerated, 0)
})

test('readiness for a successor descriptor cannot release a result pinned to its predecessor', async t => {
  const state = await activeDescriptor()
  const pinned = state.requireCurrent()
  let capacity = 0
  const h = harness({
    descriptorState: state,
    readiness: {
      async evaluate () {
        return {
          kind: 1,
          endpoint: { endpointId: 1 },
          descriptorSequence: pinned.descriptorSequence + 1n,
          descriptorHash: fixtureBytes(32, 0xfe),
          transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
          readyRoleBits: 1,
          readyOperationBits: pinned.descriptor.enabledOperationBits,
          effectiveEpochFloor: 101,
          capacityBand: pinned.descriptor.capacityBand
        }
      }
    },
    capacityGuard: { async check () { capacity++ } }
  })
  const result = await h.coordinator.dispatch(
    requestFrame(FAMILY.CORE, OPERATION.CORE.PROVE, coreRequest), context())
  t.is(errorName(result.dispatch), 'BUSY')
  t.is(capacity, 0)
})

test('known-pair body cap wins before body version and canonical decoding', async t => {
  const state = await activeDescriptor()
  const h = harness({ descriptorState: state })
  const profile = daemonOperationProfile(FAMILY.CORE, OPERATION.CORE.PROVE)
  const body = fixtureBytes(profile.maxRequestBodyBytes + 1, 0xff)
  body[0] = 2
  let failure
  try {
    await h.coordinator.dispatch(requestFrame(FAMILY.CORE, OPERATION.CORE.PROVE, body), context())
  } catch (error) {
    failure = error
  }
  t.is(failure.code, 'TOO_LARGE')
})

test('executable staged-token and streamed-PUT proofs close coordinator release blockers', t => {
  t.alike(COORDINATOR_RELEASE_BLOCKERS, {})
})

test('DRAINING charged optional read returns BUSY before malformed admission token parsing', async t => {
  const drainState = await activeDescriptor()
  const initial = drainState.requireCurrent()
  await drainState.activate(successorBytes(initial, {
    storeLifecycleState: STORE_LIFECYCLE_STATE.DRAINING,
    drainStartedEpoch: 101,
    enabledOperationBits: 0x000129d7
  }))
  // The frozen CORE.PROVE vector ends with the optional-admission presence
  // byte. Flip it to PRESENT but provide none of AdmissionV1. A full canonical
  // decoder necessarily reports BAD_ENCODING; the DRAINING prefix authority
  // must return BUSY without touching those missing token fields.
  const malformedCharged = b4a.from(coreRequest)
  t.is(malformedCharged[malformedCharged.byteLength - 1], 0)
  malformedCharged[malformedCharged.byteLength - 1] = 1
  let admissionCalls = 0
  let relationCalls = 0
  const h = harness({
    descriptorState: drainState,
    admission: {
      async prepare () { admissionCalls++; throw new Error('must not parse or prepare admission') },
      parametersForRequest: () => null
    },
    relationVerifier: { async verify () { relationCalls++; return true } }
  })
  const result = await h.coordinator.dispatch(
    requestFrame(FAMILY.CORE, OPERATION.CORE.PROVE, malformedCharged), context())
  t.is(errorName(result.dispatch), 'BUSY')
  t.is(admissionCalls, 0)
  t.is(relationCalls, 0)

  const active = await activeDescriptor()
  const activeResult = await harness({ descriptorState: active }).coordinator.dispatch(
    requestFrame(FAMILY.CORE, OPERATION.CORE.PROVE, malformedCharged), context())
  t.is(errorName(activeResult.dispatch), 'BAD_ENCODING')
})

test('optional uncharged operation never derives admission cost and terminal precedes readiness/capacity', async t => {
  const state = await activeDescriptor()
  const h = harness({
    descriptorState: state,
    cheapStateVerifier: {
      async inspect () { return {} }
    },
    terminalStateVerifier: {
      async check () { h.events.push('terminal') }
    },
    readiness: {
      async evaluate () { h.events.push('readiness'); return { kind: 2 } }
    },
    capacityGuard: {
      async check () { h.events.push('capacity') }
    }
  })
  const result = await h.coordinator.dispatch(
    requestFrame(FAMILY.CORE, OPERATION.CORE.PROVE, coreRequest), context())
  t.is(errorName(result.dispatch), 'BUSY')
  t.alike(h.events, ['relation', 'authorization', 'terminal', 'readiness'])
})

test('reserved stream OPEN fails before session verification, admission, or generic hooks', async t => {
  const state = await activeDescriptor()
  const open = fixtureCoreOpen(fixtureBytes(32, 0x12))
  const body = encodeCanonical(coreOpenReplicationV1, open)
  let verified = 0
  let leaked = false
  const admission = {
    async prepare () {
      const error = new Error('stop after session/generic isolation checks')
      error.code = 'SPEND_INVALID'
      throw error
    },
    parametersForRequest: () => null
  }
  const h = harness({
    descriptorState: state,
    admission,
    authenticatedSessionVerifier: {
      async verify (input) {
        verified++
        t.ok(b4a.equals(input.canonicalBytes, fixtureBytes(8, 0x77)))
        return Object.freeze({ kind: 'verified-session' })
      }
    },
    relationVerifier: {
      async verify (input) {
        leaked = 'authenticatedSessionContextBytes' in input || 'verifiedSessionHandle' in input
        return true
      }
    }
  })
  await t.exception(h.coordinator.dispatch(
    requestFrame(FAMILY.CORE, OPERATION.CORE.OPEN_REPLICATION, body),
    context({ transportSupportBit: TRANSPORT_SUPPORT.DIRECT_NATIVE })), /advertised release profile/)
  await t.exception(h.coordinator.dispatch(
    requestFrame(FAMILY.CORE, OPERATION.CORE.OPEN_REPLICATION, body),
    context({
      transportSupportBit: TRANSPORT_SUPPORT.DIRECT_NATIVE,
      authenticatedSessionContextBytes: fixtureBytes(8, 0x77)
    })), /advertised release profile/)
  t.is(verified, 0)
  t.absent(leaked)
})

test('reserved active FORWARD frames fail before unary or stream execution', async t => {
  const state = await activeDescriptor()
  let delegated
  const h = harness({
    descriptorState: state,
    streamExecutor: {
      async handleFrame (input) {
        delegated = input
        return { kind: 'consumed' }
      }
    },
    budget: { acquire () { throw new Error('active stream touched unary budget') } },
    readiness: { evaluate () { throw new Error('active stream touched unary readiness') } }
  })
  await t.exception(h.coordinator.dispatch({
    frameKind: FRAME_KIND.STREAM,
    familyId: FAMILY.FORWARD,
    operationId: OPERATION.FORWARD.DATA,
    requestId: fixtureBytes(16, 0),
    streamId: 9n,
    sequence: 0n,
    body: forwardData
  }, {
    get acceptedMonotonicMillis () { throw new Error('active stream read unary accepted time') },
    get absoluteDeadlineMonotonicMillis () { throw new Error('active stream read unary deadline') },
    streamSide: 1
  }), /advertised release profile/)
  t.absent(delegated)
})

test.skip('latent FORWARD terminal CLOSE vectors are inactive while the family is reserved', async t => {
  const state = await activeDescriptor()
  let terminations = 0
  const h = harness({
    descriptorState: state,
    streamExecutor: {
      async handleFrame () { throw new Error('pinned circuit fault') },
      async terminate () {
        terminations++
        return {
          kind: 'terminal',
          dispatch: encodeDispatchFrame({
            frameKind: FRAME_KIND.STREAM,
            familyId: FAMILY.FORWARD,
            operationId: OPERATION.FORWARD.CLOSE,
            requestId: fixtureBytes(16, 0),
            streamId: 9n,
            sequence: 1n,
            body: forwardClose
          })
        }
      }
    }
  })
  const result = await h.coordinator.dispatch({
    frameKind: FRAME_KIND.STREAM,
    familyId: FAMILY.FORWARD,
    operationId: OPERATION.FORWARD.DATA,
    requestId: fixtureBytes(16, 0),
    streamId: 9n,
    sequence: 0n,
    body: forwardData
  }, { streamSide: 1 })
  t.is(result.streamDisposition, 'terminal')
  t.is(decodeDispatchFrame(result.dispatch).operationId, OPERATION.FORWARD.CLOSE)
  t.is(terminations, 1)
})

test.skip('latent malformed FORWARD stream vectors are inactive while the family is reserved', async t => {
  const state = await activeDescriptor()
  let handled = 0
  let terminalError = null
  const h = harness({
    descriptorState: state,
    streamExecutor: {
      async handleFrame () {
        handled++
        throw new Error('malformed active frame reached the stream handler')
      },
      async terminate (input) {
        terminalError = input.error
        return {
          kind: 'terminal',
          dispatch: encodeDispatchFrame({
            frameKind: FRAME_KIND.STREAM,
            familyId: FAMILY.FORWARD,
            operationId: OPERATION.FORWARD.CLOSE,
            requestId: fixtureBytes(16, 0),
            streamId: 9n,
            sequence: 1n,
            body: forwardClose
          })
        }
      }
    }
  })
  const result = await h.coordinator.dispatch({
    frameKind: FRAME_KIND.STREAM,
    familyId: FAMILY.FORWARD,
    operationId: OPERATION.FORWARD.DATA,
    requestId: fixtureBytes(16, 0),
    streamId: 9n,
    sequence: 0n,
    body: b4a.from([2])
  }, { streamSide: 1 })
  t.is(result.streamDisposition, 'terminal')
  t.is(decodeDispatchFrame(result.dispatch).operationId, OPERATION.FORWARD.CLOSE)
  t.is(terminalError.code, 'BAD_VERSION')
  t.is(handled, 0)
})

test.skip('latent FORWARD request-frame vectors are inactive while the family is reserved', async t => {
  const state = await activeDescriptor()
  let called = 0
  const h = harness({
    descriptorState: state,
    streamExecutor: {
      async handleFrame () { called++ },
      async terminate () { called++ }
    }
  })
  await t.exception(h.coordinator.dispatch({
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.FORWARD,
    operationId: OPERATION.FORWARD.DATA,
    requestId: fixtureBytes(16, 0),
    body: forwardData
  }, { streamSide: 1 }), /frame kind is not allowed/)
  t.is(called, 0)
})

test('watch deadlines use effective response reserve rather than only the outer deadline', t => {
  const profile = daemonOperationProfile(FAMILY.INBOX, OPERATION.INBOX.WATCH)
  const timing = deriveOperationDeadline(profile, { maxWaitMillis: 1000 }, {
    acceptedMonotonicMillis: 1000n,
    absoluteDeadlineMonotonicMillis: 36000n
  }, 1001n)
  t.is(timing.effectiveDeadline, 7000n)
  t.is(timing.waiterDeadline, 2001n)
})

test('result release rechecks the tightened WATCH deadline after async verification', async t => {
  const state = await activeDescriptor()
  const watch = {
    version: 1,
    physicalTopic: fixtureBytes(32, 0xe1),
    afterRevision: 0n,
    limit: 1,
    maxWaitMillis: 1000,
    clientNonce: fixtureBytes(32, 0xe2),
    admission: {
      profileId: 7,
      schemeId: 9,
      parameterHash: fixtureBytes(32, 0xe3),
      token: fixtureBytes(8, 0xe4)
    }
  }
  const prepared = {
    spendTag: fixtureBytes(32, 1),
    requestCommitment: fixtureBytes(32, 2),
    costClass: { resourceClass: 1, leaseClass: 0, costUnits: 1n },
    walCommitRecord: fixtureBytes(1, 3),
    profileId: 7,
    schemeId: 9,
    parameterHash: fixtureBytes(32, 4)
  }
  let setNow = () => {}
  const h = harness({
    descriptorState: state,
    admission: { async prepare () { return prepared } },
    cheapStateVerifier: { async inspect () { return { canonicalResultBytes: inboxReadResult.byteLength } } },
    transactionCoordinator: {
      async lookup () { return { kind: 'fresh' } },
      async run (input, execute) { return execute({}) },
      async replay () { throw new Error('unexpected replay') }
    },
    operationExecutor: {
      async execute (input) {
        const value = decodeCanonical(inboxReadResultV1, inboxReadResult, { copyBytes: true })
        value.relayBinding = state.resultBinding(state.requireCurrent())
        value.requestNonce = b4a.from(watch.clientNonce)
        value.requestCommitment = b4a.from(input.requestCommitment)
        return encodeCanonical(inboxReadResultV1, value)
      }
    },
    resultVerifier: {
      async verify () {
        setNow(8000n)
        return true
      }
    }
  })
  setNow = h.setNow
  const result = await h.coordinator.dispatch(
    requestFrame(FAMILY.INBOX, OPERATION.INBOX.WATCH, encodeCanonical(inboxWatchV1, watch)),
    context({ absoluteDeadlineMonotonicMillis: 36000n }))
  t.is(errorName(result.dispatch), 'INTERNAL')
})

test('response outer-class fit is final and returns TOO_LARGE rather than INTERNAL', async t => {
  const state = await activeDescriptor()
  const h = harness({
    descriptorState: state,
    operationExecutor: {
      async execute (input) {
        const value = decodeCanonical(coreServeResultV1, resultFor(input.requestCommitment, state),
          { copyBytes: true })
        value.proofsAndBlocks = fixtureBytes(5000, 0xee)
        return encodeCanonical(coreServeResultV1, value)
      }
    }
  })
  const result = await h.coordinator.dispatch(
    requestFrame(FAMILY.CORE, OPERATION.CORE.PROVE, coreRequest), context({ outerClass: 1 }))
  t.is(errorName(result.dispatch), 'TOO_LARGE')
})

test('exact authenticated response prediction rejects before admission spend work', async t => {
  const state = await activeDescriptor()
  let admissions = 0
  const h = harness({
    descriptorState: state,
    admission: {
      async prepare () { admissions++; return null },
      parametersForRequest: () => null
    },
    cheapStateVerifier: {
      async inspect () {
        return { coreBillableBytes: 16n, predictedResultBodyBytes: 5000 }
      }
    }
  })
  const result = await h.coordinator.dispatch(
    requestFrame(FAMILY.CORE, OPERATION.CORE.MIRROR, coreMirrorRequest), context({ outerClass: 1 }))
  t.is(errorName(result.dispatch), 'TOO_LARGE')
  t.is(admissions, 0)
})

test('profile-2 witness presence follows the closed operation/admission table', t => {
  const admittedPairs = new Set([
    `${FAMILY.CELL}:${OPERATION.CELL.PROVE}`,
    `${FAMILY.CELL}:${OPERATION.CELL.BATCH_GET}`,
    `${FAMILY.INBOX}:${OPERATION.INBOX.READ}`,
    `${FAMILY.CORE}:${OPERATION.CORE.PROVE}`
  ])
  for (const familyId of Object.values(FAMILY)) {
    const operations = Object.values(OPERATION[Object.keys(FAMILY).find(name => FAMILY[name] === familyId)] || {})
    for (const operationId of operations) {
      const profile = daemonOperationProfile(familyId, operationId)
      if (!profile || profile.streamTransition === 3) continue
      const conditional = admittedPairs.has(`${familyId}:${operationId}`)
      const required = profile2WitnessRequired(profile, conditional)
      const binding = { externalCommitWitness: required ? {} : null }
      t.is(assertResultWitnessPolicy(profile, binding, 2, conditional), required)
      t.absent(assertResultWitnessPolicy(profile, { externalCommitWitness: null }, 1, conditional))
    }
  }
})
