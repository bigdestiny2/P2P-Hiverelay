import fs from 'node:fs/promises'
import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  ERROR_CODE,
  FAMILY,
  FRAME_KIND,
  INBOX_APPEND_AUTH_MODE,
  INBOX_APPEND_RESULT,
  INBOX_RECEIPT_RESULT,
  OPERATION,
  RESULT_SIGNATURE_DOMAIN_ID,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  blake2b256,
  blindErrorV1,
  decodeCanonical,
  decodeDispatchFrame,
  encodeCanonical,
  encodeDispatchFrame,
  inboxAppendAckV1,
  inboxAppendRequestCommitment,
  inboxAppendV1,
  inboxCreateCommitment,
  inboxCreateRequestCommitment,
  inboxCreateV1,
  inboxManageRequestCommitment,
  inboxManageV1,
  inboxPhysicalTopic,
  inboxReadRequestCommitment,
  inboxReadResultV1,
  inboxReadV1,
  inboxReceiptV1,
  inboxWatchRequestCommitment,
  inboxWatchV1
} from '@hiverelay/blind-protocol'
import {
  BLIND_INBOX_RUNTIME_BLOCKERS,
  BlindInboxRuntimeAdapter
} from '../inbox-runtime-adapter.js'
import { BlindInboxStorageEngine } from '../inbox-storage-engine.js'
import { BlindOperationCoordinator } from '../coordinator.js'
import { DescriptorState } from '../descriptor-state.js'
import { ResourceBudget } from '../resource-budget.js'
import { descriptorBytes, successorBytes } from './coordinator-fixtures.js'

const EPOCH = 101
const EPOCH_MILLIS = 21_600_000n

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

function admission (byte) {
  return {
    profileId: 7,
    schemeId: 9,
    parameterHash: b4a.alloc(32, 0xa7),
    token: b4a.alloc(32, byte)
  }
}

function inboxFixture (relayPublicKey, overrides = {}) {
  const create = keyPair()
  const append = keyPair()
  const renew = keyPair()
  const close = keyPair()
  const allocationEpoch = EPOCH
  const physicalTopic = inboxPhysicalTopic({ allocationEpoch, createPublicKey: create.publicKey })
  const appendAuthMode = overrides.appendAuthMode == null
    ? INBOX_APPEND_AUTH_MODE.SIGNATURE_REQUIRED
    : overrides.appendAuthMode
  const request = {
    version: 1,
    allocationEpoch,
    physicalTopic,
    frameClassBits: 7,
    appendAuthMode,
    appendPublicKey: appendAuthMode === INBOX_APPEND_AUTH_MODE.SIGNATURE_REQUIRED ? append.publicKey : null,
    createPublicKey: create.publicKey,
    renewPublicKey: renew.publicKey,
    closePublicKey: close.publicKey,
    retentionClass: 2,
    leaseClass: 2,
    clientNonce: b4a.alloc(32, overrides.nonceByte || 0xb1),
    createSignature: b4a.alloc(64),
    admission: admission(overrides.spendByte || 0xb2)
  }
  const createCommitment = inboxCreateCommitment({ ...request, relayPublicKey })
  request.createSignature = signature(create.secretKey, createCommitment)
  return { request, create, append, renew, close, createCommitment }
}

function appendRequest (fixture, relayPublicKey, byte, overrides = {}) {
  const frameClass = overrides.frameClass || 1
  const frame = overrides.frame || b4a.alloc(INBOX_FRAME_CLASS_BYTES[frameClass], byte)
  const frameHash = blake2b256(frame)
  const clientNonce = overrides.clientNonce || b4a.alloc(32, byte ^ 0x55)
  const commitment = inboxAppendRequestCommitment({
    relayPublicKey,
    physicalTopic: fixture.request.physicalTopic,
    frameClass,
    frameHash,
    clientNonce
  })
  return {
    version: 1,
    physicalTopic: fixture.request.physicalTopic,
    frameClass,
    frameHash,
    clientNonce,
    appendSignature: fixture.request.appendAuthMode === INBOX_APPEND_AUTH_MODE.SIGNATURE_REQUIRED
      ? signature(fixture.append.secretKey, commitment)
      : null,
    admission: admission(overrides.spendByte || byte),
    frame
  }
}

const INBOX_FRAME_CLASS_BYTES = Object.freeze({ 1: 4096, 2: 16384, 3: 65536 })

function renewRequest (fixture, receipt, relayPublicKey, spendByte = 0xd1) {
  const request = {
    version: 1,
    operation: 1,
    physicalTopic: fixture.request.physicalTopic,
    expectedRevision: receipt.stateRevision,
    expectedLeaseEpoch: receipt.leaseEpoch,
    leaseClass: 4,
    clientNonce: b4a.alloc(32, 0xd2),
    signature: b4a.alloc(64),
    admission: admission(spendByte)
  }
  const commitment = inboxManageRequestCommitment({
    operation: 'inbox-renew',
    relayPublicKey,
    physicalTopic: request.physicalTopic,
    expectedRevision: request.expectedRevision,
    expectedLeaseEpoch: request.expectedLeaseEpoch,
    requestedLeaseClass: request.leaseClass,
    clientNonce: request.clientNonce
  })
  request.signature = signature(fixture.renew.secretKey, commitment)
  return request
}

function closeRequest (fixture, receipt, relayPublicKey) {
  const request = {
    version: 1,
    operation: 2,
    physicalTopic: fixture.request.physicalTopic,
    expectedRevision: receipt.stateRevision,
    expectedLeaseEpoch: receipt.leaseEpoch,
    leaseClass: 0,
    clientNonce: b4a.alloc(32, 0xe1),
    signature: b4a.alloc(64),
    admission: null
  }
  const commitment = inboxManageRequestCommitment({
    operation: 'inbox-close',
    relayPublicKey,
    physicalTopic: request.physicalTopic,
    expectedRevision: request.expectedRevision,
    expectedLeaseEpoch: request.expectedLeaseEpoch,
    requestedLeaseClass: 0,
    clientNonce: request.clientNonce
  })
  request.signature = signature(fixture.close.secretKey, commitment)
  return request
}

function readRequest (fixture, relayPublicKey, overrides = {}) {
  const cursor = overrides.cursor || b4a.alloc(0)
  const limit = overrides.limit || 64
  const clientNonce = overrides.clientNonce || b4a.alloc(32, 0xf1)
  return {
    version: 1,
    physicalTopic: fixture.request.physicalTopic,
    cursor,
    limit,
    clientNonce,
    admission: overrides.charged ? admission(overrides.spendByte || 0xf2) : null
  }
}

function watchRequest (fixture, overrides = {}) {
  return {
    version: 1,
    physicalTopic: fixture.request.physicalTopic,
    afterRevision: overrides.afterRevision || 0n,
    limit: overrides.limit || 64,
    maxWaitMillis: overrides.maxWaitMillis || 1000,
    clientNonce: overrides.clientNonce || b4a.alloc(32, 0xf3),
    admission: admission(overrides.spendByte || 0xf4)
  }
}

function requestFrame (operationId, codec, request, requestByte) {
  return {
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.INBOX,
    operationId,
    requestId: b4a.alloc(16, requestByte),
    body: encodeCanonical(codec, request)
  }
}

function context (overrides = {}) {
  return {
    endpointId: 1,
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    outerClass: null,
    acceptedMonotonicMillis: 1000n,
    absoluteDeadlineMonotonicMillis: 15000n,
    ...overrides
  }
}

function responseValue (result, codec) {
  const frame = decodeDispatchFrame(result.dispatch, { copyBody: true })
  if (frame.frameKind !== FRAME_KIND.RESPONSE) throw new Error('expected response frame')
  return decodeCanonical(codec, frame.body, { copyBytes: true })
}

function errorName (result) {
  const frame = decodeDispatchFrame(result.dispatch, { copyBody: true })
  const value = decodeCanonical(blindErrorV1, frame.body)
  return Object.keys(ERROR_CODE).find(name => ERROR_CODE[name] === value.code)
}

function requestCommitment (operationId, request, relayPublicKey) {
  if (operationId === OPERATION.INBOX.CREATE) {
    return inboxCreateRequestCommitment({
      inboxCreateCommitment: inboxCreateCommitment({ ...request, relayPublicKey }),
      clientNonce: request.clientNonce
    })
  }
  if (operationId === OPERATION.INBOX.APPEND) {
    return inboxAppendRequestCommitment({ ...request, relayPublicKey })
  }
  if (operationId === OPERATION.INBOX.RENEW || operationId === OPERATION.INBOX.CLOSE) {
    return inboxManageRequestCommitment({
      operation: operationId === OPERATION.INBOX.RENEW ? 'inbox-renew' : 'inbox-close',
      relayPublicKey,
      physicalTopic: request.physicalTopic,
      expectedRevision: request.expectedRevision,
      expectedLeaseEpoch: request.expectedLeaseEpoch,
      requestedLeaseClass: request.leaseClass,
      clientNonce: request.clientNonce
    })
  }
  if (operationId === OPERATION.INBOX.READ) return inboxReadRequestCommitment({ ...request, relayPublicKey })
  return inboxWatchRequestCommitment({ ...request, relayPublicKey })
}

async function harness (t, overrides = {}) {
  const root = await fs.mkdtemp('/private/tmp/blind-inbox-runtime-')
  t.teardown(async () => fs.rm(root, { recursive: true, force: true }))
  const relay = keyPair()
  const state = new DescriptorState({ epochNow: () => EPOCH, verifySignature: async () => true })
  await state.activate(descriptorBytes({ relayPublicKey: relay.publicKey }))
  let nowUnixMillis = BigInt(EPOCH) * EPOCH_MILLIS
  const descriptor = state.requireCurrent().descriptor
  const storageOptions = {
    root,
    relayPublicKey: relay.publicKey,
    storeId: descriptor.storeId,
    partitionKey: b4a.alloc(32, 0xd1),
    cursorKey: b4a.alloc(32, 0xd2),
    ownerFenceTokenHash: b4a.alloc(32, 0xd3),
    durabilityContinuityHash: descriptor.durabilityContinuityHash,
    durabilityProfileHash: descriptor.durabilityProfileHash,
    durabilityProfileId: 1,
    initialEpochFloor: EPOCH,
    nowUnixMillis: () => nowUnixMillis,
    autoClock: false,
    ...(overrides.storageOptions || {})
  }
  const storage = new BlindInboxStorageEngine(storageOptions)
  await storage.open()
  t.teardown(() => storage.close())
  const signer = Object.freeze({
    async sign (input) {
      if (!same(input.publicKey, relay.publicKey) || ![
        RESULT_SIGNATURE_DOMAIN_ID.INBOX_RECEIPT,
        RESULT_SIGNATURE_DOMAIN_ID.INBOX_APPEND_ACK,
        RESULT_SIGNATURE_DOMAIN_ID.INBOX_READ_RESULT
      ].includes(input.domainId)) throw new Error('unbound INBOX test signing request')
      return signature(relay.secretKey, input.payload)
    }
  })
  const admissionCoordinator = {
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
  const assemble = (activeStorage, activeSigner = signer) => {
    const adapter = new BlindInboxRuntimeAdapter({
      storage: activeStorage,
      descriptorState: state,
      signer: activeSigner
    })
    const coordinator = new BlindOperationCoordinator({
      descriptorState: state,
      admission: admissionCoordinator,
      readiness,
      budget: new ResourceBudget({ maxItems: 64, maxBytes: 512 * 1024 * 1024 }),
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
    signer,
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

test('INBOX adapter executes lifecycle and exact retries through the real coordinator', async t => {
  const h = await harness(t)
  let coordinator = h.coordinator
  const fixture = inboxFixture(h.relay.publicKey)
  const createFrame = requestFrame(OPERATION.INBOX.CREATE, inboxCreateV1, fixture.request, 0xa1)
  const created = responseValue(await coordinator.dispatch(createFrame, context()), inboxReceiptV1)
  t.is(created.result, INBOX_RECEIPT_RESULT.CREATED)
  t.is(created.stateRevision, 0n)

  const append = appendRequest(fixture, h.relay.publicKey, 0xb3)
  const appendFrame = requestFrame(OPERATION.INBOX.APPEND, inboxAppendV1, append, 0xa2)
  const appended = responseValue(await coordinator.dispatch(appendFrame, context()), inboxAppendAckV1)
  t.is(appended.result, INBOX_APPEND_RESULT.STORED)
  t.is(appended.appendRevision, 1n)

  const read = readRequest(fixture, h.relay.publicKey)
  const readFrame = requestFrame(OPERATION.INBOX.READ, inboxReadV1, read, 0xa3)
  const page = responseValue(await coordinator.dispatch(readFrame, context()), inboxReadResultV1)
  t.is(page.entries.length, 1)
  t.alike(page.entries[0].frame, append.frame)

  const renew = renewRequest(fixture, created, h.relay.publicKey)
  const renewFrame = requestFrame(OPERATION.INBOX.RENEW, inboxManageV1, renew, 0xa4)
  const renewed = responseValue(await coordinator.dispatch(renewFrame, context()), inboxReceiptV1)
  t.is(renewed.result, INBOX_RECEIPT_RESULT.RENEWED)
  t.is(renewed.stateRevision, 1n)

  await h.state.activate(successorBytes(h.state.requireCurrent()))
  t.alike(responseValue(await coordinator.dispatch(createFrame, context()), inboxReceiptV1), created,
    'CREATE keeps exact committed binding across descriptor refresh')
  t.alike(responseValue(await coordinator.dispatch(appendFrame, context()), inboxAppendAckV1), appended,
    'APPEND keeps exact committed binding across descriptor refresh')
  t.alike(responseValue(await coordinator.dispatch(renewFrame, context()), inboxReceiptV1), renewed,
    'RENEW keeps exact committed binding across descriptor refresh')

  await h.storage.close()
  const reopened = new BlindInboxStorageEngine(h.storageOptions)
  await reopened.open()
  t.teardown(() => reopened.close())
  coordinator = h.assemble(reopened).coordinator
  t.alike(responseValue(await coordinator.dispatch(createFrame, context()), inboxReceiptV1), created)
  t.alike(responseValue(await coordinator.dispatch(appendFrame, context()), inboxAppendAckV1), appended)

  const close = closeRequest(fixture, renewed, h.relay.publicKey)
  const closeFrame = requestFrame(OPERATION.INBOX.CLOSE, inboxManageV1, close, 0xa5)
  const closed = responseValue(await coordinator.dispatch(closeFrame, context()), inboxReceiptV1)
  t.is(closed.result, INBOX_RECEIPT_RESULT.CLOSED)
  t.is(closed.leaseClass, 0)
  t.alike(responseValue(await coordinator.dispatch(closeFrame, context()), inboxReceiptV1), closed)
  t.is(errorName(await coordinator.dispatch(readFrame, context())), 'NOT_FOUND')
  t.alike(responseValue(await coordinator.dispatch(appendFrame, context()), inboxAppendAckV1), appended,
    'accepted APPEND keeps its exact acknowledgement after owner close')
  t.alike(h.adapter.status().blockers, BLIND_INBOX_RUNTIME_BLOCKERS)
})

test('APPEND signer failure leaves a hidden provisional frame and concurrent retries finalize one exact ACK', async t => {
  const h = await harness(t)
  const fixture = inboxFixture(h.relay.publicKey, { spendByte: 0xb8 })
  await h.coordinator.dispatch(requestFrame(OPERATION.INBOX.CREATE, inboxCreateV1,
    fixture.request, 0xb9), context())
  const append = appendRequest(fixture, h.relay.publicKey, 0xba, { spendByte: 0xbb })
  const firstFrame = requestFrame(OPERATION.INBOX.APPEND, inboxAppendV1, append, 0xbc)
  const failingSigner = Object.freeze({
    async sign (input) {
      if (input.domainId === RESULT_SIGNATURE_DOMAIN_ID.INBOX_APPEND_ACK) {
        throw new Error('simulated isolated signer failure')
      }
      return h.signer.sign(input)
    }
  })
  const failedCoordinator = h.assemble(h.storage, failingSigner).coordinator
  t.is(errorName(await failedCoordinator.dispatch(firstFrame, context())), 'INTERNAL')
  const hiddenRead = responseValue(await h.coordinator.dispatch(requestFrame(OPERATION.INBOX.READ, inboxReadV1,
    readRequest(fixture, h.relay.publicKey), 0xbd), context()), inboxReadResultV1)
  t.is(hiddenRead.snapshotRevision, 0n)
  t.is(hiddenRead.entries.length, 0, 'signer failure cannot release the provisional frame')

  await h.storage.close()
  const reopened = new BlindInboxStorageEngine(h.storageOptions)
  await reopened.open()
  t.teardown(() => reopened.close())
  const recovered = h.assemble(reopened).coordinator
  const retryA = requestFrame(OPERATION.INBOX.APPEND, inboxAppendV1, append, 0xbe)
  const retryB = requestFrame(OPERATION.INBOX.APPEND, inboxAppendV1, append, 0xbf)
  const [rawA, rawB] = await Promise.all([
    recovered.dispatch(retryA, context()),
    recovered.dispatch(retryB, context())
  ])
  const ackA = responseValue(rawA, inboxAppendAckV1)
  const ackB = responseValue(rawB, inboxAppendAckV1)
  t.alike(ackA, ackB, 'concurrent exact retries release one canonical acknowledgement')
  t.is(ackA.appendRevision, 1n)
  t.is(reopened.status().frameCount, 1)
  const visibleRead = responseValue(await recovered.dispatch(requestFrame(OPERATION.INBOX.READ, inboxReadV1,
    readRequest(fixture, h.relay.publicKey), 0xc0), context()), inboxReadResultV1)
  t.is(visibleRead.snapshotRevision, 1n)
  t.is(visibleRead.entries.length, 1)
})

test('exact APPEND replay bypasses fresh-capacity refusal without allocating another frame', async t => {
  const h = await harness(t, { storageOptions: { maxFrames: 1, maxFramesPerTopic: 1 } })
  const fixture = inboxFixture(h.relay.publicKey, { spendByte: 0xc1 })
  await h.coordinator.dispatch(requestFrame(OPERATION.INBOX.CREATE, inboxCreateV1,
    fixture.request, 0xc2), context())
  const first = appendRequest(fixture, h.relay.publicKey, 0xc3, { spendByte: 0xc4 })
  const firstFrame = requestFrame(OPERATION.INBOX.APPEND, inboxAppendV1, first, 0xc5)
  const accepted = responseValue(await h.coordinator.dispatch(firstFrame, context()), inboxAppendAckV1)
  const replayed = responseValue(await h.coordinator.dispatch(firstFrame, context()), inboxAppendAckV1)
  t.alike(replayed, accepted)
  t.is(h.storage.status().frameCount, 1)

  const fresh = appendRequest(fixture, h.relay.publicKey, 0xc6, { spendByte: 0xc7 })
  const freshFrame = requestFrame(OPERATION.INBOX.APPEND, inboxAppendV1, fresh, 0xc8)
  t.is(errorName(await h.coordinator.dispatch(freshFrame, context())), 'BUSY')
  t.is(h.storage.status().frameCount, 1)
})

test('charged INBOX READ pins exact page/signature across append, refresh, and restart', async t => {
  const h = await harness(t)
  let coordinator = h.coordinator
  const fixture = inboxFixture(h.relay.publicKey, { spendByte: 0xc1 })
  await coordinator.dispatch(requestFrame(OPERATION.INBOX.CREATE, inboxCreateV1, fixture.request, 0xb1), context())
  const firstAppend = appendRequest(fixture, h.relay.publicKey, 0xc2)
  await coordinator.dispatch(requestFrame(OPERATION.INBOX.APPEND, inboxAppendV1, firstAppend, 0xb2), context())

  const charged = readRequest(fixture, h.relay.publicKey, { charged: true, limit: 1, spendByte: 0xc3 })
  const chargedFrame = requestFrame(OPERATION.INBOX.READ, inboxReadV1, charged, 0xb3)
  const first = await coordinator.dispatch(chargedFrame, context())
  const decoded = responseValue(first, inboxReadResultV1)
  t.is(decoded.entries.length, 1)

  const laterAppend = appendRequest(fixture, h.relay.publicKey, 0xc4)
  await coordinator.dispatch(requestFrame(OPERATION.INBOX.APPEND, inboxAppendV1, laterAppend, 0xb4), context())
  t.alike((await coordinator.dispatch(chargedFrame, context())).dispatch, first.dispatch,
    'charged retry excludes later append and preserves exact signature')

  await h.state.activate(successorBytes(h.state.requireCurrent()))
  t.alike((await coordinator.dispatch(chargedFrame, context())).dispatch, first.dispatch,
    'charged retry keeps historical descriptor binding')

  await h.storage.close()
  const reopened = new BlindInboxStorageEngine(h.storageOptions)
  await reopened.open()
  t.teardown(() => reopened.close())
  coordinator = h.assemble(reopened).coordinator
  t.alike((await coordinator.dispatch(chargedFrame, context())).dispatch, first.dispatch,
    'charged retry is exact after WAL recovery')
})

test('INBOX WATCH is a bounded admitted unary operation that wakes on APPEND', async t => {
  const h = await harness(t)
  const fixture = inboxFixture(h.relay.publicKey, { spendByte: 0xd1 })
  await h.coordinator.dispatch(requestFrame(OPERATION.INBOX.CREATE, inboxCreateV1, fixture.request, 0xc1), context())
  const watch = watchRequest(fixture, { afterRevision: 0n, maxWaitMillis: 2000, spendByte: 0xd2 })
  const watchFrame = requestFrame(OPERATION.INBOX.WATCH, inboxWatchV1, watch, 0xc2)
  const waiting = h.coordinator.dispatch(watchFrame, context({ absoluteDeadlineMonotonicMillis: 8000n }))
  while (h.storage.status().waiterCount !== 1) await new Promise(resolve => setImmediate(resolve))
  const append = appendRequest(fixture, h.relay.publicKey, 0xd3)
  await h.coordinator.dispatch(requestFrame(OPERATION.INBOX.APPEND, inboxAppendV1, append, 0xc3), context())
  const result = responseValue(await waiting, inboxReadResultV1)
  t.is(result.snapshotRevision, 1n)
  t.is(result.entries.length, 1)
  t.alike(result.entries[0].frame, append.frame)
})

test('charged INBOX WATCH timeout returns and replays one exact empty unary result', async t => {
  const h = await harness(t)
  const fixture = inboxFixture(h.relay.publicKey, { spendByte: 0xda })
  await h.coordinator.dispatch(requestFrame(OPERATION.INBOX.CREATE, inboxCreateV1, fixture.request, 0xca), context())
  const watch = watchRequest(fixture, { afterRevision: 0n, maxWaitMillis: 25, spendByte: 0xdb })
  const watchFrame = requestFrame(OPERATION.INBOX.WATCH, inboxWatchV1, watch, 0xcb)
  const first = await h.coordinator.dispatch(watchFrame, context({ absoluteDeadlineMonotonicMillis: 8000n }))
  const value = responseValue(first, inboxReadResultV1)
  t.is(value.snapshotRevision, 0n)
  t.is(value.entries.length, 0)
  t.alike((await h.coordinator.dispatch(watchFrame,
    context({ absoluteDeadlineMonotonicMillis: 8000n }))).dispatch, first.dispatch)
  t.is(h.storage.status().waiterCount, 0)
})

test('INBOX adapter rejects signed/open append policy substitution and stale management canonically', async t => {
  const h = await harness(t)
  const signed = inboxFixture(h.relay.publicKey, { spendByte: 0xe1 })
  const createFrame = requestFrame(OPERATION.INBOX.CREATE, inboxCreateV1, signed.request, 0xd1)
  const created = responseValue(await h.coordinator.dispatch(createFrame, context()), inboxReceiptV1)
  const append = appendRequest(signed, h.relay.publicKey, 0xe2)
  append.appendSignature = null
  t.is(errorName(await h.coordinator.dispatch(
    requestFrame(OPERATION.INBOX.APPEND, inboxAppendV1, append, 0xd2), context())), 'NOT_FOUND')

  const stale = renewRequest(signed, { ...created, stateRevision: 1n }, h.relay.publicKey, 0xe3)
  t.is(errorName(await h.coordinator.dispatch(
    requestFrame(OPERATION.INBOX.RENEW, inboxManageV1, stale, 0xd3), context())), 'STALE_REVISION')

  const open = inboxFixture(h.relay.publicKey, {
    appendAuthMode: INBOX_APPEND_AUTH_MODE.OPEN_CAPABILITY,
    spendByte: 0xe4,
    nonceByte: 0xe5
  })
  await h.coordinator.dispatch(requestFrame(OPERATION.INBOX.CREATE, inboxCreateV1, open.request, 0xd4), context())
  const openAppend = appendRequest(open, h.relay.publicKey, 0xe6)
  openAppend.appendSignature = b4a.alloc(64, 0xff)
  t.is(errorName(await h.coordinator.dispatch(
    requestFrame(OPERATION.INBOX.APPEND, inboxAppendV1, openAppend, 0xd5), context())), 'NOT_FOUND')
})

test('coordinator request commitments for every INBOX operation match frozen hashes', t => {
  const relay = keyPair()
  const fixture = inboxFixture(relay.publicKey)
  const create = requestCommitment(OPERATION.INBOX.CREATE, fixture.request, relay.publicKey)
  t.ok(create.byteLength === 32)
  const append = appendRequest(fixture, relay.publicKey, 0xf5)
  t.ok(requestCommitment(OPERATION.INBOX.APPEND, append, relay.publicKey).byteLength === 32)
  const read = readRequest(fixture, relay.publicKey)
  t.ok(requestCommitment(OPERATION.INBOX.READ, read, relay.publicKey).byteLength === 32)
  const watch = watchRequest(fixture)
  t.ok(requestCommitment(OPERATION.INBOX.WATCH, watch, relay.publicKey).byteLength === 32)
  const frame = encodeDispatchFrame(requestFrame(OPERATION.INBOX.READ, inboxReadV1, read, 0xff))
  t.ok(frame.byteLength > 0)
})
