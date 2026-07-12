import fs from 'node:fs'
import test from 'brittle'
import b4a from 'b4a'
import {
  CELL_RECEIPT_RESULT,
  ERROR_CODE,
  FAMILY,
  FRAME_KIND,
  OPERATION,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  allocationCommitment,
  blindErrorV1,
  blindReceiptV1,
  decodeCanonical,
  decodeDispatchFrame,
  encodeCanonical,
  encodeDispatchFrame,
  putCellV1
} from '@hiverelay/blind-protocol'
import { BlindOperationCoordinator } from '../coordinator.js'
import { DescriptorState } from '../descriptor-state.js'
import { ResourceBudget } from '../resource-budget.js'
import { StagedCellPutDispatchIngestor } from '../staged-put.js'
import { descriptorBytes } from './coordinator-fixtures.js'

const putBody = fs.readFileSync(new URL(
  '../../blind-protocol/vectors/draft/cell/put-class-1.bin', import.meta.url))

function requestDispatch (body = putBody) {
  return encodeDispatchFrame({
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    requestId: b4a.alloc(16, 0x61),
    body
  })
}

async function descriptorState () {
  const state = new DescriptorState({ epochNow: () => 101, verifySignature: async () => true })
  await state.activate(descriptorBytes())
  return state
}

function context () {
  return {
    endpointId: 1,
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    outerClass: 6,
    acceptedMonotonicMillis: 1000n,
    absoluteDeadlineMonotonicMillis: 15000n
  }
}

function errorName (dispatch) {
  const frame = decodeDispatchFrame(dispatch, { copyBody: true })
  const value = decodeCanonical(blindErrorV1, frame.body)
  return Object.keys(ERROR_CODE).find(name => ERROR_CODE[name] === value.code)
}

function receipt (request, requestCommitment, state) {
  const snapshot = state.requireCurrent()
  const allocation = allocationCommitment({
    ...request,
    relayPublicKey: snapshot.descriptor.relayPublicKey,
    declaredCellBlobHash: request.declaredBlobHash
  })
  return encodeCanonical(blindReceiptV1, {
    version: 1,
    protocol: b4a.from('hiverelay-blind-cell-v1', 'ascii'),
    relayBinding: state.resultBinding(snapshot),
    slotCommitment: b4a.alloc(32, 0x62),
    cellBlobHash: request.declaredBlobHash,
    allocationCommitment: allocation,
    requestCommitment,
    sizeClass: request.sizeClass,
    allocationEpoch: request.allocationEpoch,
    leaseClass: request.leaseClass,
    leaseEpoch: 105,
    stateRevision: 0n,
    receiptEpoch: 101,
    requestNonce: request.clientNonce,
    result: CELL_RECEIPT_RESULT.STORED,
    signature: b4a.alloc(64, 0x63)
  })
}

function coordinatorHarness (state, hooks = {}) {
  const events = []
  let enteredExecuteResolve
  const enteredExecute = new Promise(resolve => { enteredExecuteResolve = resolve })
  const coordinator = new BlindOperationCoordinator({
    descriptorState: state,
    admission: {
      async prepare (input) {
        events.push('admission')
        return {
          spendTag: b4a.alloc(32, 0x64),
          requestCommitment: b4a.from(input.requestCommitment),
          costClass: b4a.from([1]),
          walCommitRecord: b4a.from([1]),
          profileId: 7,
          schemeId: 9,
          parameterHash: b4a.alloc(32, 0x65)
        }
      },
      parametersForRequest: () => null
    },
    readiness: {
      async evaluate () {
        const snapshot = state.requireCurrent()
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
    budget: new ResourceBudget({ maxItems: 8, maxBytes: 8 * 1024 * 1024 }),
    relationVerifier: { async verify () { events.push('relation'); return true } },
    capabilityVerifier: { async verify () { events.push('authorization'); return true } },
    cheapStateVerifier: { async inspect () { events.push('cheap'); return {} } },
    terminalStateVerifier: { async check () { events.push('terminal') } },
    capacityGuard: { async check () { events.push('capacity') } },
    transactionCoordinator: {
      async lookup () { return { kind: 'fresh' } },
      async run (_input, execute) { return execute({}) },
      async replay () { throw new Error('unexpected replay') }
    },
    operationExecutor: {
      async execute (input) {
        events.push('execute')
        enteredExecuteResolve()
        let total = 0
        for await (const chunk of input.opaqueBodySource) total += chunk.byteLength
        events.push('body')
        if (hooks.bodyBytes) hooks.bodyBytes(total)
        return receipt(input.request, input.requestCommitment, state)
      }
    },
    resultVerifier: {
      async verify (input) {
        events.push('result')
        if (hooks.result) hooks.result(input)
        return true
      }
    },
    authenticatedSessionVerifier: { async verify () { return Object.freeze({}) } },
    monotonicMillis: () => 1001n
  })
  return { coordinator, events, enteredExecute }
}

test('coordinator admits staged PUT metadata before pulling body and gates success on streamed hash', async t => {
  const state = await descriptorState()
  const canonical = requestDispatch()
  const decoded = decodeCanonical(putCellV1, putBody, { copyBytes: true })
  const metadataBytes = canonical.byteLength - decoded.cellBlob.byteLength
  const ingestor = new StagedCellPutDispatchIngestor({ maxQueuedBodyBytes: 1024 })
  await ingestor.push(canonical.subarray(0, metadataBytes))
  const staged = await ingestor.ready
  let observedBodyBytes = 0
  let resultShape = null
  const h = coordinatorHarness(state, {
    bodyBytes: bytes => { observedBodyBytes = bytes },
    result: input => { resultShape = input }
  })
  const dispatched = h.coordinator.dispatchStagedCellPut(staged, context())
  await h.enteredExecute
  t.alike(h.events, ['relation', 'authorization', 'cheap', 'admission', 'terminal', 'capacity', 'execute'])
  t.is(observedBodyBytes, 0)

  const producer = (async () => {
    await ingestor.push(canonical.subarray(metadataBytes))
    ingestor.finish()
  })()
  const result = await dispatched
  await producer
  t.is(decodeDispatchFrame(result.dispatch).frameKind, FRAME_KIND.RESPONSE)
  t.is(observedBodyBytes, decoded.cellBlob.byteLength)
  t.is(resultShape.canonicalRequestBytes, null)
  t.alike(resultShape.canonicalRequestPrefixBytes, staged.canonicalRequestPrefixBytes)
  t.is(resultShape.opaqueRequestBodyBytes, decoded.cellBlob.byteLength)
  t.alike(h.events, ['relation', 'authorization', 'cheap', 'admission', 'terminal', 'capacity', 'execute', 'body', 'result'])
})
test('coordinator cannot release staged PUT success when streamed body hash is wrong', async t => {
  const state = await descriptorState()
  const canonical = requestDispatch()
  const decoded = decodeCanonical(putCellV1, putBody, { copyBytes: true })
  const metadataBytes = canonical.byteLength - decoded.cellBlob.byteLength
  const changed = b4a.from(canonical)
  changed[changed.byteLength - 1] ^= 1
  const ingestor = new StagedCellPutDispatchIngestor()
  await ingestor.push(changed.subarray(0, metadataBytes))
  const staged = await ingestor.ready
  const h = coordinatorHarness(state)
  const dispatched = h.coordinator.dispatchStagedCellPut(staged, context())
  await h.enteredExecute
  let producerError = null
  try {
    await ingestor.push(changed.subarray(metadataBytes))
    ingestor.finish()
  } catch (error) {
    producerError = error
  }
  t.is(producerError.code, 'BAD_ENCODING')
  const result = await dispatched
  t.is(errorName(result.dispatch), 'BAD_ENCODING')
  t.is(h.events.includes('result'), false)
})
