import fs from 'node:fs/promises'
import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  CELL_RECEIPT_RESULT,
  CELL_SIZE_CLASS,
  ERROR_CODE,
  FAMILY,
  FRAME_KIND,
  OPERATION,
  RESULT_SIGNATURE_DOMAIN_ID,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  admissionParametersHash,
  allocationCommitment,
  batchGetV1,
  batchGetResultV1,
  blake2b256,
  blindErrorV1,
  blindReceiptV1,
  cellManageRequestCommitment,
  cellStorageSlot,
  decodeCanonical,
  decodeDispatchFrame,
  dropCellV1,
  encodeCanonical,
  encodeDispatchFrame,
  getCellResultV1,
  getCellV1,
  operationProfile,
  proveCellResultV1,
  proveCellV1,
  putCellV1,
  renewCellV1
} from '@hiverelay/blind-protocol'
import { AdmissionCoordinator } from '../admission-coordinator.js'
import {
  BLIND_CELL_RUNTIME_BLOCKERS,
  BlindCellRuntimeAdapter
} from '../cell-runtime-adapter.js'
import {
  captureBlindCellStorageEngineControlSnapshot,
  createBlindCellControlSnapshotSemanticAuthority,
  reconstructBlindCellControlSnapshot
} from '../cell-control-snapshot.js'
import { BlindOperationCoordinator } from '../coordinator.js'
import { DescriptorState } from '../descriptor-state.js'
import { ResourceBudget } from '../resource-budget.js'
import { BlindCellStorageEngine } from '../storage-engine.js'
import { StagedCellPutDispatchIngestor } from '../staged-put.js'
import { descriptorAndParameters, descriptorBytes, successorBytes } from './coordinator-fixtures.js'

const EPOCH = 101
const EPOCH_MILLIS = 21600000n
const MAX_ADMISSION_TOKEN_BYTES = 4096
const MAX_CANONICAL_CELL_PUT_METADATA_BYTES = 263 + 36 + 3 + MAX_ADMISSION_TOKEN_BYTES

function keyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

function signature (secretKey, message) {
  const output = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(output, message, secretKey)
  return output
}

function admission (spendByte) {
  return {
    profileId: 7,
    schemeId: 9,
    parameterHash: b4a.alloc(32, 0xa7),
    token: b4a.alloc(32, spendByte)
  }
}

function cellFixture (relayPublicKey, overrides = {}) {
  const create = keyPair()
  const renew = keyPair()
  const drop = keyPair()
  const allocationEpoch = EPOCH
  const sizeClass = overrides.sizeClass || 1
  const leaseClass = 1
  const cellBlob = b4a.alloc(CELL_SIZE_CLASS[sizeClass], overrides.blobByte || 0xb1)
  const storageSlot = cellStorageSlot({ allocationEpoch, createPublicKey: create.publicKey })
  const declaredBlobHash = blake2b256(cellBlob)
  const allocation = allocationCommitment({
    relayPublicKey,
    storageSlot,
    allocationEpoch,
    sizeClass,
    leaseClass,
    declaredCellBlobHash: declaredBlobHash,
    createPublicKey: create.publicKey,
    renewPublicKey: renew.publicKey,
    dropPublicKey: drop.publicKey
  })
  const clientNonce = b4a.alloc(32, overrides.nonceByte || 0xb2)
  const request = {
    version: 1,
    storageSlot,
    allocationEpoch,
    sizeClass,
    leaseClass,
    clientNonce,
    createPublicKey: create.publicKey,
    renewPublicKey: renew.publicKey,
    dropPublicKey: drop.publicKey,
    declaredBlobHash,
    createSignature: signature(create.secretKey, allocation),
    admission: overrides.admission || admission(overrides.spendByte || 0xb3),
    cellBlob
  }
  return { request, cellBlob, allocation, create, renew, drop }
}

function frame (operationId, codec, request, requestByte = 0xc1) {
  return {
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.CELL,
    operationId,
    requestId: b4a.alloc(16, requestByte),
    body: encodeCanonical(codec, request)
  }
}

function context () {
  return {
    endpointId: 1,
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    outerClass: null,
    acceptedMonotonicMillis: 1000n,
    absoluteDeadlineMonotonicMillis: 15000n
  }
}

function responseValue (result, codec) {
  const decoded = decodeDispatchFrame(result.dispatch, { copyBody: true })
  if (decoded.frameKind !== FRAME_KIND.RESPONSE) throw new Error('expected response frame')
  return decodeCanonical(codec, decoded.body, { copyBytes: true })
}

function errorName (result) {
  const decoded = decodeDispatchFrame(result.dispatch, { copyBody: true })
  const value = decodeCanonical(blindErrorV1, decoded.body)
  return Object.keys(ERROR_CODE).find(name => ERROR_CODE[name] === value.code)
}

async function harness (t, overrides = {}) {
  const root = await fs.mkdtemp('/private/tmp/blind-cell-runtime-')
  t.teardown(async () => fs.rm(root, { recursive: true, force: true }))
  const relay = keyPair()
  const state = new DescriptorState({ epochNow: () => EPOCH, verifySignature: async () => true })
  const admissionAuthority = overrides.authoritativeAdmission === true
    ? descriptorAndParameters({
      relayPublicKey: relay.publicKey,
      ...(overrides.admissionAuthorityOverrides || {})
    })
    : null
  await state.activate(admissionAuthority == null
    ? descriptorBytes({ relayPublicKey: relay.publicKey })
    : admissionAuthority.descriptor)
  let nowUnixMillis = BigInt(EPOCH) * EPOCH_MILLIS
  const storageOptions = {
    root,
    relayPublicKey: relay.publicKey,
    storeId: state.requireCurrent().descriptor.storeId,
    partitionKey: b4a.alloc(32, 0xd1),
    ownerFenceTokenHash: b4a.alloc(32, 0xd2),
    durabilityContinuityHash: state.requireCurrent().descriptor.durabilityContinuityHash,
    durabilityProfileHash: state.requireCurrent().descriptor.durabilityProfileHash,
    durabilityProfileId: 1,
    initialEpochFloor: EPOCH,
    nowUnixMillis: () => nowUnixMillis,
    autoClock: false,
    ...(overrides.storageOptions || {})
  }
  const storage = new BlindCellStorageEngine(storageOptions)
  await storage.open()
  t.teardown(() => storage.close())
  const signer = Object.freeze({
    async sign (input) {
      if (!same(input.publicKey, relay.publicKey) ||
          (input.domainId !== RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT &&
            input.domainId !== RESULT_SIGNATURE_DOMAIN_ID.BATCH_GET_RESULT)) {
        throw new Error('unbound test signing request')
      }
      return signature(relay.secretKey, input.payload)
    }
  })
  const admissionCoordinator = overrides.admissionCoordinatorFactory == null
    ? {
        async prepare (input) {
          return {
            spendTag: blake2b256(input.admission.token),
            requestCommitment: b4a.from(input.requestCommitment),
            costClass: { ...input.cost, costUnits: 1n },
            walCommitRecord: b4a.from(input.admission.token),
            profileId: input.admission.profileId,
            schemeId: input.admission.schemeId,
            parameterHash: b4a.from(input.admission.parameterHash)
          }
        },
        parametersForRequest: () => null
      }
    : await overrides.admissionCoordinatorFactory({ state, admissionAuthority })
  const readiness = {
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
        effectiveEpochFloor: EPOCH,
        capacityBand: snapshot.descriptor.capacityBand
      }
    }
  }
  const assemble = activeStorage => {
    const adapter = new BlindCellRuntimeAdapter({ storage: activeStorage, descriptorState: state, signer })
    const coordinator = new BlindOperationCoordinator({
      descriptorState: state,
      admission: admissionCoordinator,
      readiness,
      budget: new ResourceBudget({ maxItems: 64, maxBytes: 64 * 1024 * 1024 }),
      relationVerifier: adapter.relationVerifier,
      capabilityVerifier: adapter.capabilityVerifier,
      cheapStateVerifier: adapter.cheapStateVerifier,
      terminalStateVerifier: adapter.terminalStateVerifier,
      capacityGuard: adapter.capacityGuard,
      operationExecutor: adapter.operationExecutor,
      transactionCoordinator: adapter.transactionCoordinator,
      resultVerifier: adapter.resultVerifier,
      authenticatedSessionVerifier: { async verify () { return Object.freeze({}) } },
      monotonicMillis: () => 1001n
    })
    return { adapter, coordinator }
  }
  return {
    root,
    relay,
    state,
    admissionAuthority,
    storage,
    storageOptions,
    assemble,
    advanceMillis (millis) { nowUnixMillis += BigInt(millis) },
    ...assemble(storage)
  }
}

function same (left, right) {
  return Boolean(left && right && left.byteLength === right.byteLength && b4a.equals(left, right))
}

function renewRequest (fixture, receipt, relayPublicKey, spendByte = 0xe1) {
  const request = {
    version: 1,
    storageSlot: fixture.request.storageSlot,
    expectedRevision: receipt.stateRevision,
    expectedLeaseEpoch: receipt.leaseEpoch,
    leaseClass: 2,
    clientNonce: b4a.alloc(32, 0xe2),
    admission: admission(spendByte),
    signature: b4a.alloc(64)
  }
  const commitment = cellManageRequestCommitment({
    operation: 'cell-renew',
    relayPublicKey,
    storageSlot: request.storageSlot,
    expectedRevision: request.expectedRevision,
    expectedLeaseEpoch: request.expectedLeaseEpoch,
    requestedLeaseClass: request.leaseClass,
    clientNonce: request.clientNonce
  })
  request.signature = signature(fixture.renew.secretKey, commitment)
  return request
}

function dropRequest (fixture, receipt, relayPublicKey) {
  const request = {
    version: 1,
    storageSlot: fixture.request.storageSlot,
    expectedRevision: receipt.stateRevision,
    expectedLeaseEpoch: receipt.leaseEpoch,
    clientNonce: b4a.alloc(32, 0xf1),
    signature: b4a.alloc(64)
  }
  const commitment = cellManageRequestCommitment({
    operation: 'cell-drop',
    relayPublicKey,
    storageSlot: request.storageSlot,
    expectedRevision: request.expectedRevision,
    expectedLeaseEpoch: request.expectedLeaseEpoch,
    requestedLeaseClass: 0,
    clientNonce: request.clientNonce
  })
  request.signature = signature(fixture.drop.secretKey, commitment)
  return request
}

test('CELL adapter executes signed mutation lifecycle and immutable exact retries through the coordinator', async t => {
  const h = await harness(t)
  let coordinator = h.coordinator
  const fixture = cellFixture(h.relay.publicKey)
  const putFrame = frame(OPERATION.CELL.PUT, putCellV1, fixture.request)
  const firstPut = responseValue(await coordinator.dispatch(putFrame, context()), blindReceiptV1)
  t.is(firstPut.result, CELL_RECEIPT_RESULT.STORED)
  t.is(firstPut.stateRevision, 0n)
  t.alike(firstPut.cellBlobHash, fixture.request.declaredBlobHash)

  const renew = renewRequest(fixture, firstPut, h.relay.publicKey)
  const renewFrame = frame(OPERATION.CELL.RENEW, renewCellV1, renew)
  const firstRenew = responseValue(await coordinator.dispatch(renewFrame, context()), blindReceiptV1)
  t.is(firstRenew.result, CELL_RECEIPT_RESULT.RENEWED)
  t.is(firstRenew.stateRevision, 1n)
  t.ok(firstRenew.leaseEpoch > firstPut.leaseEpoch)

  await h.state.activate(successorBytes(h.state.requireCurrent()))
  const retriedPut = responseValue(await coordinator.dispatch(putFrame, context()), blindReceiptV1)
  t.alike(retriedPut, firstPut, 'PUT retry keeps its exact committed binding across descriptor refresh')
  const retriedRenew = responseValue(await coordinator.dispatch(renewFrame, context()), blindReceiptV1)
  t.alike(retriedRenew, firstRenew, 'RENEW retry keeps its exact committed binding across descriptor refresh')

  await h.storage.close()
  const reopenedStorage = new BlindCellStorageEngine(h.storageOptions)
  await reopenedStorage.open()
  t.teardown(() => reopenedStorage.close())
  coordinator = h.assemble(reopenedStorage).coordinator
  t.alike(responseValue(await coordinator.dispatch(putFrame, context()), blindReceiptV1), firstPut,
    'PUT retry keeps its exact committed binding across restart')
  t.alike(responseValue(await coordinator.dispatch(renewFrame, context()), blindReceiptV1), firstRenew,
    'RENEW retry keeps its exact committed binding across restart')

  const drop = dropRequest(fixture, firstRenew, h.relay.publicKey)
  const dropFrame = frame(OPERATION.CELL.DROP, dropCellV1, drop)
  const firstDrop = responseValue(await coordinator.dispatch(dropFrame, context()), blindReceiptV1)
  t.is(firstDrop.result, CELL_RECEIPT_RESULT.DROPPED)
  t.is(firstDrop.stateRevision, 2n)
  const retriedDrop = responseValue(await coordinator.dispatch(dropFrame, context()), blindReceiptV1)
  t.alike(retriedDrop, firstDrop, 'DROP retry remains byte-semantic')

  t.is(errorName(await coordinator.dispatch(putFrame, context())), 'RETRY_TERMINAL',
    'a terminal cell revokes old byte-serving mutation replay')

  const snapshotAuthority = createBlindCellControlSnapshotSemanticAuthority({
    partitionKey: h.storageOptions.partitionKey
  })
  const captured = await captureBlindCellStorageEngineControlSnapshot(snapshotAuthority, reopenedStorage)
  const recovered = await reconstructBlindCellControlSnapshot(snapshotAuthority, captured)
  const recoveredRenew = [...recovered.cellState.spends.values()]
    .find(value => value.operation === 'renew')
  const recoveredDrop = [...recovered.cellState.requestResults.values()][0]
  t.ok(recoveredRenew.preparedAdmissionBytes.byteLength > 0)
  t.ok(recoveredRenew.resultBindingBytes.byteLength > 0)
  t.is(recoveredRenew.resultCell.stateRevision, 1n)
  t.ok(recoveredDrop.resultBindingBytes.byteLength > 0)
  t.is(recoveredDrop.resultCell.objectState, 'TOMBSTONE')
  t.is(recoveredDrop.resultCell.stateRevision, 2n)

  const tampered = {
    ...captured,
    entries: captured.entries.map(entry => ({
      ...entry,
      key: b4a.from(entry.key),
      value: b4a.from(entry.value)
    }))
  }
  const renewSnapshotIndex = tampered.entries.findIndex(entry => entry.entryKind === 1 && entry.key[1] === 2)
  tampered.entries[renewSnapshotIndex].value[170] ^= 1
  await t.exception(reconstructBlindCellControlSnapshot(snapshotAuthority, tampered),
    /renew|prepared admission|result binding|canonical|fingerprint/i)
  t.alike(h.adapter.status().blockers, BLIND_CELL_RUNTIME_BLOCKERS)
})

test('CELL adapter preserves the uncharged GET, signed PROVE and ordered atomic BATCH_GET paths', async t => {
  const h = await harness(t)
  const first = cellFixture(h.relay.publicKey, { blobByte: 0x31, nonceByte: 0x32, spendByte: 0x33 })
  const second = cellFixture(h.relay.publicKey, { blobByte: 0x41, nonceByte: 0x42, spendByte: 0x43 })
  await h.coordinator.dispatch(frame(OPERATION.CELL.PUT, putCellV1, first.request), context())
  await h.coordinator.dispatch(frame(OPERATION.CELL.PUT, putCellV1, second.request), context())

  const get = {
    version: 1,
    storageSlot: first.request.storageSlot,
    clientNonce: b4a.alloc(32, 0x51),
    admission: null
  }
  const got = responseValue(await h.coordinator.dispatch(frame(OPERATION.CELL.GET, getCellV1, get), context()),
    getCellResultV1)
  t.alike(got.cellBlob, first.cellBlob)

  const prove = { ...get, clientNonce: b4a.alloc(32, 0x52) }
  const proved = responseValue(await h.coordinator.dispatch(
    frame(OPERATION.CELL.PROVE, proveCellV1, prove), context()), proveCellResultV1)
  t.is(proved.receipt.result, CELL_RECEIPT_RESULT.SERVED)
  t.alike(proved.cellBlob, first.cellBlob)

  const batch = {
    version: 1,
    clientNonce: b4a.alloc(32, 0x53),
    slots: [second.request.storageSlot, b4a.alloc(32, 0x99), first.request.storageSlot],
    admission: null
  }
  const batched = responseValue(await h.coordinator.dispatch(
    frame(OPERATION.CELL.BATCH_GET, batchGetV1, batch), context()), batchGetResultV1)
  t.alike(batched.entries.map(entry => entry.status), [1, 0, 1])
  t.alike(batched.entries[0].cellBlob, second.cellBlob)
  t.alike(batched.entries[2].cellBlob, first.cellBlob)
})

test('charged CELL reads pin exact GET, PROVE and BATCH_GET results across retries, refresh and restart', async t => {
  const h = await harness(t)
  let coordinator = h.coordinator
  const first = cellFixture(h.relay.publicKey, { blobByte: 0x21, nonceByte: 0x22, spendByte: 0x23 })
  const future = cellFixture(h.relay.publicKey, { blobByte: 0x31, nonceByte: 0x32, spendByte: 0x33 })
  await coordinator.dispatch(frame(OPERATION.CELL.PUT, putCellV1, first.request, 0xa1), context())

  const get = {
    version: 1,
    storageSlot: first.request.storageSlot,
    clientNonce: b4a.alloc(32, 0x41),
    admission: admission(0x42)
  }
  const prove = { ...get, clientNonce: b4a.alloc(32, 0x43), admission: admission(0x44) }
  const batch = {
    version: 1,
    clientNonce: b4a.alloc(32, 0x45),
    slots: [first.request.storageSlot, future.request.storageSlot],
    admission: admission(0x46)
  }
  const getFrame = frame(OPERATION.CELL.GET, getCellV1, get, 0xb1)
  const proveFrame = frame(OPERATION.CELL.PROVE, proveCellV1, prove, 0xb2)
  const batchFrame = frame(OPERATION.CELL.BATCH_GET, batchGetV1, batch, 0xb3)
  const controlBefore = h.storage.status().accounting.controlBytes

  const firstGet = await coordinator.dispatch(getFrame, context())
  const firstProve = await coordinator.dispatch(proveFrame, context())
  const firstBatch = await coordinator.dispatch(batchFrame, context())
  t.alike(responseValue(firstGet, getCellResultV1).cellBlob, first.cellBlob)
  t.alike(responseValue(firstProve, proveCellResultV1).cellBlob, first.cellBlob)
  t.alike(responseValue(firstBatch, batchGetResultV1).entries.map(entry => entry.status), [1, 0])
  t.is(h.storage.status().accounting.chargedReadFinalized, 3)

  await coordinator.dispatch(frame(OPERATION.CELL.PUT, putCellV1, future.request, 0xa2), context())
  t.alike((await coordinator.dispatch(batchFrame, context())).dispatch, firstBatch.dispatch,
    'an absent batch entry stays absent after its slot is populated')
  t.alike((await coordinator.dispatch(getFrame, context())).dispatch, firstGet.dispatch)
  t.alike((await coordinator.dispatch(proveFrame, context())).dispatch, firstProve.dispatch)

  const alteredAdmission = {
    ...get,
    admission: { ...get.admission, schemeId: get.admission.schemeId + 1 }
  }
  t.is(errorName(await coordinator.dispatch(
    frame(OPERATION.CELL.GET, getCellV1, alteredAdmission, 0xb4), context())), 'CONFLICT',
  'the same spend and request cannot substitute prepared admission authority')

  await h.state.activate(successorBytes(h.state.requireCurrent()))
  t.alike((await coordinator.dispatch(getFrame, context())).dispatch, firstGet.dispatch)
  t.alike((await coordinator.dispatch(proveFrame, context())).dispatch, firstProve.dispatch)
  t.alike((await coordinator.dispatch(batchFrame, context())).dispatch, firstBatch.dispatch)

  const realSigner = h.adapter.signer
  h.adapter.signer = { async sign () { return b4a.alloc(64, 0x7e) } }
  t.is(errorName(await coordinator.dispatch(proveFrame, context())), 'INTERNAL',
    'a reconstructed result cannot substitute another result hash')
  h.adapter.signer = realSigner

  await h.storage.close()
  const reopenedStorage = new BlindCellStorageEngine(h.storageOptions)
  await reopenedStorage.open()
  t.teardown(() => reopenedStorage.close())
  coordinator = h.assemble(reopenedStorage).coordinator
  t.alike((await coordinator.dispatch(getFrame, context())).dispatch, firstGet.dispatch)
  t.alike((await coordinator.dispatch(proveFrame, context())).dispatch, firstProve.dispatch)
  t.alike((await coordinator.dispatch(batchFrame, context())).dispatch, firstBatch.dispatch)
  t.is(reopenedStorage.status().accounting.chargedReadFinalized, 3)

  const snapshotAuthority = createBlindCellControlSnapshotSemanticAuthority({
    partitionKey: h.storageOptions.partitionKey
  })
  const captured = await captureBlindCellStorageEngineControlSnapshot(snapshotAuthority, reopenedStorage)
  const recovered = await reconstructBlindCellControlSnapshot(snapshotAuthority, captured)
  const recoveredCharged = [...recovered.cellState.spends.values()]
    .filter(value => value.status === 'read-finalized')
  t.is(recoveredCharged.length, 3)
  t.is(recovered.cellState.chargedReadExpiryHeap.length, 3)
  t.ok(recoveredCharged.every(value => value.resultCommitment && value.entries.length > 0))
  t.is(recovered.cellState.accounting.controlBytes,
    reopenedStorage.status().accounting.controlBytes)
  t.alike((await coordinator.dispatch(getFrame, context())).dispatch, firstGet.dispatch,
    'engine-bound checkpoint capture cannot perturb exact retry replay')

  const omitted = {
    ...captured,
    entries: captured.entries.filter(entry => entry.entryKind !== 8 ||
      !same(entry.key.subarray(2), recoveredCharged[0].spendTag))
  }
  await t.exception(reconstructBlindCellControlSnapshot(snapshotAuthority, omitted),
    /entry count does not match/)

  const substituted = {
    ...captured,
    entries: captured.entries.map(entry => ({
      ...entry,
      key: b4a.from(entry.key),
      value: b4a.from(entry.value)
    }))
  }
  const chargedIndex = substituted.entries.findIndex(entry => entry.entryKind === 8)
  substituted.entries[chargedIndex].key[substituted.entries[chargedIndex].key.byteLength - 1] ^= 1
  await t.exception(reconstructBlindCellControlSnapshot(snapshotAuthority, substituted),
    /key does not match spendTag/)

  const mutated = {
    ...captured,
    entries: captured.entries.map(entry => ({
      ...entry,
      key: b4a.from(entry.key),
      value: b4a.from(entry.value)
    }))
  }
  const chargedMutationIndex = mutated.entries.findIndex(entry => entry.entryKind === 8)
  mutated.entries[chargedMutationIndex].value[120] ^= 1
  await t.exception(reconstructBlindCellControlSnapshot(snapshotAuthority, mutated),
    /charged-read|canonical|fingerprint|admission/i)

  const wal = await fs.readFile(`${h.root}/control/wal.v2`)
  t.is(wal.indexOf(first.cellBlob.subarray(0, 256)), -1,
    'charged read response bytes never enter the control WAL')
  const chargedControlBytes = reopenedStorage.status().accounting.controlBytes - controlBefore - 512
  t.ok(chargedControlBytes > 0 && chargedControlBytes < 3 * 32 * 1024,
    'charged result identity uses bounded control records rather than response-sized WAL records')
})

test('charged read finalization loses to an owner drop between materialization and commit', async t => {
  const h = await harness(t)
  const fixture = cellFixture(h.relay.publicKey, { blobByte: 0x51, nonceByte: 0x52, spendByte: 0x53 })
  const put = responseValue(await h.coordinator.dispatch(
    frame(OPERATION.CELL.PUT, putCellV1, fixture.request, 0xc1), context()), blindReceiptV1)
  const request = {
    version: 1,
    storageSlot: fixture.request.storageSlot,
    clientNonce: b4a.alloc(32, 0x54),
    admission: admission(0x55)
  }
  const requestFrame = frame(OPERATION.CELL.GET, getCellV1, request, 0xc2)
  const finalize = h.storage.finalizeChargedCellRead.bind(h.storage)
  let raced = false
  h.storage.finalizeChargedCellRead = async input => {
    if (!raced) {
      raced = true
      await h.storage.dropCell({
        request: dropRequest(fixture, put, h.relay.publicKey),
        resultBinding: h.state.resultBinding(h.state.requireCurrent())
      })
    }
    return finalize(input)
  }
  const rejected = await h.coordinator.dispatch(requestFrame, context())
  h.storage.finalizeChargedCellRead = finalize
  t.is(errorName(rejected), 'NOT_FOUND')
  const decoded = decodeDispatchFrame(rejected.dispatch, { copyBody: true })
  t.is(decoded.frameKind, FRAME_KIND.ERROR)
  t.ok(decoded.body.byteLength < fixture.cellBlob.byteLength,
    'the materialized bytes are not released when the terminal cell transition wins')
  t.is(h.storage.status().accounting.chargedReadPins, 1)
  t.is(h.storage.status().accounting.chargedReadFinalized, 0)
  t.is(errorName(await h.coordinator.dispatch(requestFrame, context())), 'RETRY_TERMINAL')
})

test('unfinalized charged pins expire durably, release bounded pin accounting and never recharge', async t => {
  const h = await harness(t)
  const fixture = cellFixture(h.relay.publicKey, { blobByte: 0x61, nonceByte: 0x62, spendByte: 0x63 })
  await h.coordinator.dispatch(frame(OPERATION.CELL.PUT, putCellV1, fixture.request, 0xd1), context())
  const request = {
    version: 1,
    storageSlot: fixture.request.storageSlot,
    clientNonce: b4a.alloc(32, 0x64),
    admission: admission(0x65)
  }
  const requestFrame = frame(OPERATION.CELL.GET, getCellV1, request, 0xd2)
  const finalize = h.storage.finalizeChargedCellRead.bind(h.storage)
  h.storage.finalizeChargedCellRead = async () => {
    const error = new Error('simulated crash before charged result finalization')
    error.code = 'INTERNAL'
    throw error
  }
  t.is(errorName(await h.coordinator.dispatch(requestFrame, context())), 'INTERNAL')
  h.storage.finalizeChargedCellRead = finalize
  const pinned = h.storage.status()
  t.is(pinned.accounting.chargedReadPins, 1)
  t.is(pinned.accounting.chargedReadFinalized, 0)

  h.advanceMillis(15n * 60n * 1000n)
  await h.storage.close()
  const reopenedStorage = new BlindCellStorageEngine(h.storageOptions)
  await reopenedStorage.open()
  t.teardown(() => reopenedStorage.close())
  const afterExpiry = reopenedStorage.status()
  t.is(afterExpiry.accounting.chargedReadPins, 0)
  t.is(afterExpiry.accounting.chargedReadExpired, 1)
  t.ok(afterExpiry.accounting.controlBytes < pinned.accounting.controlBytes,
    'expiry releases the variable retry pin while retaining a bounded spent tombstone')
  const coordinator = h.assemble(reopenedStorage).coordinator
  const snapshotAuthority = createBlindCellControlSnapshotSemanticAuthority({
    partitionKey: h.storageOptions.partitionKey
  })
  const captured = await captureBlindCellStorageEngineControlSnapshot(snapshotAuthority, reopenedStorage)
  const recovered = await reconstructBlindCellControlSnapshot(snapshotAuthority, captured)
  const expiredSpend = [...recovered.cellState.spends.values()]
    .find(value => value.status === 'read-expired')
  t.ok(expiredSpend)
  t.is(expiredSpend.controlBytes, 512)
  t.is(expiredSpend.entries, null)
  t.is(expiredSpend.preparedAdmissionBytes, null)
  t.is(recovered.cellState.chargedReadExpiryHeap.length, 0)
  const spendCount = afterExpiry.accounting.spends
  t.is(errorName(await coordinator.dispatch(requestFrame, context())), 'RETRY_TERMINAL')
  t.is(reopenedStorage.status().accounting.spends, spendCount,
    'an expired charged-read spend cannot be charged or inserted again')
})

test('charged read control quota rejects before reading an opaque response body', async t => {
  const h = await harness(t, { storageOptions: { maxControlBytes: 1024 } })
  const fixture = cellFixture(h.relay.publicKey, { blobByte: 0x71, nonceByte: 0x72, spendByte: 0x73 })
  await h.coordinator.dispatch(frame(OPERATION.CELL.PUT, putCellV1, fixture.request, 0xe1), context())
  const readOpaque = h.storage.transactionStore.readOpaque.bind(h.storage.transactionStore)
  let reads = 0
  h.storage.transactionStore.readOpaque = async (...args) => {
    reads++
    return readOpaque(...args)
  }
  const request = {
    version: 1,
    storageSlot: fixture.request.storageSlot,
    clientNonce: b4a.alloc(32, 0x74),
    admission: admission(0x75)
  }
  t.is(errorName(await h.coordinator.dispatch(
    frame(OPERATION.CELL.GET, getCellV1, request, 0xe2), context())), 'BUSY')
  t.is(reads, 0)
  t.is(h.storage.status().accounting.chargedReadPins, 0)
  t.is(h.storage.status().accounting.spends, 1)
})

test('staged CELL.PUT reaches storage without coordinator body buffering and rejects a bad streamed hash', async t => {
  const h = await harness(t)
  const fixture = cellFixture(h.relay.publicKey, { blobByte: 0x71, nonceByte: 0x72, spendByte: 0x73 })
  const dispatch = encodeDispatchFrame(frame(OPERATION.CELL.PUT, putCellV1, fixture.request))
  const metadataBytes = dispatch.byteLength - fixture.cellBlob.byteLength
  const ingestor = new StagedCellPutDispatchIngestor({ maxQueuedBodyBytes: 1024 })
  await ingestor.push(dispatch.subarray(0, metadataBytes))
  const staged = await ingestor.ready
  const pending = h.coordinator.dispatchStagedCellPut(staged, context())
  await ingestor.push(dispatch.subarray(metadataBytes))
  ingestor.finish()
  const receipt = responseValue(await pending, blindReceiptV1)
  t.is(receipt.result, CELL_RECEIPT_RESULT.STORED)

  const changed = b4a.from(dispatch)
  changed[changed.byteLength - 1] ^= 1
  const bad = new StagedCellPutDispatchIngestor()
  await bad.push(changed.subarray(0, metadataBytes))
  const badStaged = await bad.ready
  const rejected = h.coordinator.dispatchStagedCellPut(badStaged, context())
  try {
    await bad.push(changed.subarray(metadataBytes))
    bad.finish()
  } catch {}
  t.is(errorName(await rejected), 'BAD_ENCODING')
})

test('V-3 rejects a maximum-shape staged CELL.PUT proof before body, staging, WAL, or fsync work', async t => {
  let observeOperationIo = false
  let proofChecks = 0
  let walRecords = 0
  let fsyncs = 0
  const h = await harness(t, {
    authoritativeAdmission: true,
    admissionAuthorityOverrides: {
      parameters: {
        resourceCosts: [{
          familyId: FAMILY.CELL,
          operationId: OPERATION.CELL.PUT,
          resourceClass: 5,
          leaseClass: 1,
          costUnits: 50n
        }]
      }
    },
    admissionCoordinatorFactory: async ({ state, admissionAuthority }) => {
      const coordinator = new AdmissionCoordinator({
        descriptorState: state,
        verifySignature: async () => true,
        resolveAdapter: async () => ({
          async prepare () {
            proofChecks++
            return null
          }
        })
      })
      await coordinator.installParameters(admissionAuthority.parameters)
      return coordinator
    },
    storageOptions: {
      faultInjector (point) {
        if (!observeOperationIo) return
        if (point === 'wal:after-write') walRecords++
        if (point === 'wal:after-sync' || point === 'body:after-fsync' ||
            point === 'body:after-publish') fsyncs++
      }
    }
  })
  const fixture = cellFixture(h.relay.publicKey, {
    sizeClass: 5,
    admission: {
      profileId: 7,
      schemeId: 9,
      parameterHash: admissionParametersHash(h.admissionAuthority.parameters),
      token: b4a.alloc(MAX_ADMISSION_TOKEN_BYTES, 0xe7)
    }
  })
  const requestBody = encodeCanonical(putCellV1, fixture.request)
  const profile = operationProfile(FAMILY.CELL, OPERATION.CELL.PUT)
  t.is(fixture.cellBlob.byteLength, CELL_SIZE_CLASS[5])
  t.is(fixture.request.admission.token.byteLength, MAX_ADMISSION_TOKEN_BYTES)
  t.is(requestBody.byteLength, CELL_SIZE_CLASS[5] + MAX_CANONICAL_CELL_PUT_METADATA_BYTES)
  t.ok(requestBody.byteLength <= profile.maxRequestBodyBytes)

  const canonical = encodeDispatchFrame({
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    requestId: b4a.alloc(16, 0xf3),
    body: requestBody
  })
  const metadataBytes = canonical.byteLength - fixture.cellBlob.byteLength
  const ingestor = new StagedCellPutDispatchIngestor()
  await ingestor.push(canonical.subarray(0, metadataBytes))
  const staged = await ingestor.ready
  t.is(staged.sourceByteLength, CELL_SIZE_CLASS[5])
  t.is(ingestor.bodyPullCount, 0)

  const stageOpaque = h.storage.transactionStore.stageOpaque.bind(h.storage.transactionStore)
  let stageOpaqueCalls = 0
  h.storage.transactionStore.stageOpaque = async options => {
    stageOpaqueCalls++
    return stageOpaque(options)
  }
  const before = h.storage.status()
  const walBefore = await fs.stat(`${h.root}/control/wal.v2`)
  t.alike(await fs.readdir(`${h.root}/staging`), [])
  t.is(h.adapter.storage, h.storage)

  observeOperationIo = true
  const rejected = await h.coordinator.dispatchStagedCellPut(staged, context())
  observeOperationIo = false
  const after = h.storage.status()
  const walAfter = await fs.stat(`${h.root}/control/wal.v2`)

  t.is(errorName(rejected), 'SPEND_INVALID')
  t.is(proofChecks, 1)
  t.is(ingestor.bodyPullCount, 0)
  t.is(stageOpaqueCalls, 0)
  t.is(after.accounting.stagingBytes, 0)
  t.is(after.accounting.stagingBytes, before.accounting.stagingBytes)
  t.is(after.walSequence - before.walSequence, 0n)
  t.is(walAfter.size, walBefore.size)
  t.is(walRecords, 0)
  t.is(fsyncs, 0)
  t.alike(await fs.readdir(`${h.root}/staging`), [])
})
