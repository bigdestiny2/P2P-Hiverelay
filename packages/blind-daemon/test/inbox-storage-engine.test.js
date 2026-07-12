import fs from 'node:fs/promises'
import path from 'node:path'
import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  INBOX_APPEND_AUTH_MODE,
  INBOX_APPEND_RESULT,
  OPERATION,
  RESULT_SIGNATURE_DOMAIN_ID,
  blake2b256,
  decodeCanonical,
  encodeCanonical,
  inboxAppendAckV1,
  inboxAppendRequestCommitment,
  inboxCreateCommitment,
  inboxCreateRequestCommitment,
  inboxManageRequestCommitment,
  inboxPhysicalTopic,
  inboxReadRequestCommitment,
  relayResultBindingV1,
  resultSignaturePayload,
  inboxWatchRequestCommitment
} from '@hiverelay/blind-protocol'
import {
  BlindInboxStorageEngine,
  BlindInboxStorageError,
  inboxEntriesCommitment
} from '../inbox-storage-engine.js'
import {
  createBlindInboxControlSnapshotSemanticAuthority,
  reconstructBlindInboxControlSnapshot,
  streamBlindInboxControlSnapshotEntries
} from '../inbox-control-snapshot.js'

const EPOCH_MILLIS = 21_600_000n
const RELAY_AUTHORITY = (() => {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
})()
const RELAY = RELAY_AUTHORITY.publicKey
const STORE_ID = b4a.alloc(32, 0x72)
const CONTINUITY = b4a.alloc(32, 0x73)
const PROFILE_HASH = b4a.alloc(32, 0x74)
const PARTITION = b4a.alloc(32, 0x75)
const CURSOR_KEY = b4a.alloc(32, 0x76)
const FENCE = b4a.alloc(32, 0x77)

function keys () {
  const output = {}
  for (const name of ['create', 'append', 'renew', 'close']) {
    const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
    const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
    sodium.crypto_sign_keypair(publicKey, secretKey)
    output[name] = { publicKey, secretKey }
  }
  return output
}

function sign (secretKey, message) {
  const signature = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(signature, message, secretKey)
  return signature
}

function clock (epoch = 100) {
  return {
    epoch,
    extra: 0n,
    now () { return BigInt(this.epoch) * EPOCH_MILLIS + this.extra }
  }
}

function binding (descriptorSequence = 1n) {
  return {
    version: 1,
    relayPublicKey: RELAY,
    storeId: STORE_ID,
    descriptorSequence,
    descriptorHash: b4a.alloc(32, Number(0x80n + descriptorSequence)),
    durabilityProfileId: 1,
    durabilityContinuityHash: CONTINUITY,
    durabilityProfileHash: PROFILE_HASH,
    restoreEvidenceHeadSequence: 0n,
    restoreEvidenceHeadHash: b4a.alloc(32),
    externalCommitWitness: null
  }
}

function engineOptions (root, time, overrides = {}) {
  return {
    root,
    relayPublicKey: RELAY,
    storeId: STORE_ID,
    durabilityContinuityHash: CONTINUITY,
    durabilityProfileHash: PROFILE_HASH,
    durabilityProfileId: 1,
    partitionKey: PARTITION,
    cursorKey: CURSOR_KEY,
    ownerFenceTokenHash: FENCE,
    initialEpochFloor: time.epoch,
    nowUnixMillis: () => time.now(),
    autoClock: false,
    ...overrides
  }
}

function admission (requestCommitment, byte, leaseClass = 0) {
  return {
    spendTag: b4a.alloc(32, byte),
    requestCommitment,
    profileId: 7,
    schemeId: 9,
    parameterHash: b4a.alloc(32, 0xa7),
    costClass: { resourceClass: 1, leaseClass, costUnits: 1n },
    walCommitRecord: b4a.alloc(48, byte ^ 0xff)
  }
}

function createFixture (overrides = {}) {
  const capability = overrides.capability || keys()
  const allocationEpoch = overrides.allocationEpoch == null ? 100 : overrides.allocationEpoch
  const physicalTopic = inboxPhysicalTopic({ allocationEpoch, createPublicKey: capability.create.publicKey })
  const request = {
    version: 1,
    allocationEpoch,
    physicalTopic,
    frameClassBits: overrides.frameClassBits == null ? 7 : overrides.frameClassBits,
    appendAuthMode: overrides.appendAuthMode == null
      ? INBOX_APPEND_AUTH_MODE.SIGNATURE_REQUIRED
      : overrides.appendAuthMode,
    appendPublicKey: overrides.appendAuthMode === INBOX_APPEND_AUTH_MODE.OPEN_CAPABILITY
      ? null
      : capability.append.publicKey,
    createPublicKey: capability.create.publicKey,
    renewPublicKey: capability.renew.publicKey,
    closePublicKey: capability.close.publicKey,
    retentionClass: overrides.retentionClass == null ? 2 : overrides.retentionClass,
    leaseClass: overrides.leaseClass == null ? 2 : overrides.leaseClass,
    clientNonce: overrides.clientNonce || b4a.alloc(32, 0xb1)
  }
  const commitment = inboxCreateCommitment({ ...request, relayPublicKey: RELAY })
  const requestCommitment = inboxCreateRequestCommitment({
    inboxCreateCommitment: commitment,
    clientNonce: request.clientNonce
  })
  request.createSignature = sign(capability.create.secretKey, commitment)
  return {
    capability,
    request,
    requestCommitment,
    preparedAdmission: admission(requestCommitment, overrides.spendByte || 0xb2, request.leaseClass)
  }
}

function appendFixture (created, byte, overrides = {}) {
  const frameClass = overrides.frameClass == null ? 1 : overrides.frameClass
  const frame = overrides.frame || b4a.alloc({ 1: 4096, 2: 16384, 3: 65536 }[frameClass], byte)
  const frameHash = blake2b256(frame)
  const clientNonce = overrides.clientNonce || b4a.alloc(32, byte ^ 0x55)
  const requestCommitment = inboxAppendRequestCommitment({
    relayPublicKey: RELAY,
    physicalTopic: created.request.physicalTopic,
    frameClass,
    frameHash,
    clientNonce
  })
  return {
    request: {
      version: 1,
      physicalTopic: created.request.physicalTopic,
      frameClass,
      frameHash,
      clientNonce,
      appendSignature: sign(created.capability.append.secretKey, requestCommitment),
      frame
    },
    requestCommitment,
    preparedAdmission: admission(requestCommitment, overrides.spendByte || byte)
  }
}

function readFixture (created, overrides = {}) {
  const cursor = overrides.cursor || b4a.alloc(0)
  const limit = overrides.limit == null ? 64 : overrides.limit
  const clientNonce = overrides.clientNonce || b4a.alloc(32, 0xd1)
  const requestCommitment = inboxReadRequestCommitment({
    relayPublicKey: RELAY,
    physicalTopic: created.request.physicalTopic,
    cursor,
    limit,
    clientNonce
  })
  return {
    request: { version: 1, physicalTopic: created.request.physicalTopic, cursor, limit, clientNonce },
    requestCommitment,
    preparedAdmission: admission(requestCommitment, overrides.spendByte || 0xd2)
  }
}

function watchFixture (created, overrides = {}) {
  const afterRevision = overrides.afterRevision == null ? 0n : overrides.afterRevision
  const limit = overrides.limit == null ? 64 : overrides.limit
  const maxWaitMillis = overrides.maxWaitMillis == null ? 100 : overrides.maxWaitMillis
  const clientNonce = overrides.clientNonce || b4a.alloc(32, 0xe1)
  const requestCommitment = inboxWatchRequestCommitment({
    relayPublicKey: RELAY,
    physicalTopic: created.request.physicalTopic,
    afterRevision,
    limit,
    maxWaitMillis,
    clientNonce
  })
  return {
    request: { version: 1, physicalTopic: created.request.physicalTopic, afterRevision, limit, maxWaitMillis, clientNonce },
    requestCommitment,
    preparedAdmission: admission(requestCommitment, overrides.spendByte || 0xe2)
  }
}

async function temporaryRoot (t, name = 'blind-inbox-store') {
  const root = await fs.mkdtemp(`/private/tmp/${name}-`)
  t.teardown(async () => fs.rm(root, { recursive: true, force: true }))
  return root
}

async function rejectsCode (t, promise, code) {
  try {
    await promise
    t.fail(`expected ${code}`)
  } catch (error) {
    t.is(error.code, code)
    return error
  }
}

async function checkpointRoundTrip (engine) {
  const authority = createBlindInboxControlSnapshotSemanticAuthority({ partitionKey: PARTITION })
  const state = engine.snapshotState()
  const entries = []
  for await (const entry of streamBlindInboxControlSnapshotEntries(authority, state)) entries.push(entry)
  const status = engine.status()
  const header = {
    relayPublicKey: RELAY,
    storeId: STORE_ID,
    durabilityContinuityHash: CONTINUITY,
    walSequence: status.walSequence,
    walHash: status.walHash
  }
  const result = await reconstructBlindInboxControlSnapshot(authority, {
    header,
    checkpointHeader: {
      relayPublicKey: header.relayPublicKey,
      storeId: header.storeId,
      durabilityContinuityHash: header.durabilityContinuityHash,
      coveredWalSequence: header.walSequence,
      coveredWalHash: header.walHash,
      epochFloor: status.epochFloor
    },
    declaredEntryCount: entries.length,
    entries
  })
  return { entries, sourceState: state, state: result.inboxState }
}

function appendAckFinalization (stored) {
  const value = {
    version: 1,
    relayBinding: decodeCanonical(relayResultBindingV1, stored.resultBindingBytes, { copyBytes: true }),
    topicCommitment: blake2b256(stored.frame.physicalTopic),
    frameHash: b4a.from(stored.frame.frameHash),
    appendRevision: stored.frame.appendRevision,
    storedAtEpoch: stored.frame.storedAtEpoch,
    expiresAtEpoch: stored.frame.expiresAtEpoch,
    requestNonce: b4a.from(stored.clientNonce),
    requestCommitment: b4a.from(stored.requestCommitment),
    result: INBOX_APPEND_RESULT.STORED,
    signature: b4a.alloc(sodium.crypto_sign_BYTES)
  }
  const unsigned = encodeCanonical(inboxAppendAckV1, value).subarray(0, -sodium.crypto_sign_BYTES)
  value.signature = sign(RELAY_AUTHORITY.secretKey,
    resultSignaturePayload(RESULT_SIGNATURE_DOMAIN_ID.INBOX_APPEND_ACK, unsigned))
  const body = encodeCanonical(inboxAppendAckV1, value)
  return { value, body, resultCommitment: blake2b256(body) }
}

async function appendAndFinalize (engine, input) {
  const stored = await engine.appendFrame(input)
  if (stored.ackSignature == null) {
    const finalized = appendAckFinalization(stored)
    await engine.finalizeAppendAck({
      spendTag: stored.spendTag,
      requestCommitment: stored.requestCommitment,
      ackSignature: finalized.value.signature,
      resultCommitment: finalized.resultCommitment
    })
  }
  return engine.appendFrame(input)
}

test('Inbox engine persists CREATE/APPEND and recovers exact immutable frame/replay state', async t => {
  const root = await temporaryRoot(t)
  const time = clock()
  const created = createFixture()
  let engine = new BlindInboxStorageEngine(engineOptions(root, time))
  await engine.open()
  const createResult = await engine.createInbox({ ...created, resultBinding: binding() })
  t.is(createResult.inbox.stateRevision, 0n)
  t.is(createResult.inbox.leaseEpoch, 128)

  const appended = appendFixture(created, 0xc1)
  const first = await appendAndFinalize(engine, { ...appended, resultBinding: binding() })
  t.is(first.frame.appendRevision, 1n)
  t.is(first.frame.expiresAtEpoch, 128)
  const replay = await appendAndFinalize(engine, { ...appended, resultBinding: binding(2n) })
  t.is(replay.frame.appendRevision, 1n)
  t.ok(b4a.equals(replay.resultBindingBytes, first.resultBindingBytes), 'retry retains committed descriptor binding')

  await engine.close()
  engine = new BlindInboxStorageEngine(engineOptions(root, time))
  await engine.open()
  t.is(engine.status().inboxCount, 1)
  t.is(engine.status().frameCount, 1)
  const page = await engine.readPage({ request: readFixture(created).request })
  t.is(page.snapshotRevision, 1n)
  t.is(page.entries.length, 1)
  t.ok(b4a.equals(page.entries[0].frame, appended.request.frame))
  t.ok(b4a.equals(inboxEntriesCommitment(page.entries), inboxEntriesCommitment(page.entries)))
  await engine.close()
})

test('Inbox engine serializes concurrent APPEND revisions and enforces management CAS', async t => {
  const root = await temporaryRoot(t)
  const time = clock()
  const created = createFixture()
  const engine = new BlindInboxStorageEngine(engineOptions(root, time))
  await engine.open()
  t.teardown(() => engine.close())
  const createdResult = await engine.createInbox({ ...created, resultBinding: binding() })
  const appends = await Promise.all([
    appendAndFinalize(engine, { ...appendFixture(created, 0xc2), resultBinding: binding() }),
    appendAndFinalize(engine, { ...appendFixture(created, 0xc3), resultBinding: binding() })
  ])
  t.alike(appends.map(result => result.frame.appendRevision).sort(), [1n, 2n])

  const request = {
    version: 1,
    operation: 1,
    physicalTopic: created.request.physicalTopic,
    expectedRevision: createdResult.inbox.stateRevision,
    expectedLeaseEpoch: createdResult.inbox.leaseEpoch,
    leaseClass: 4,
    clientNonce: b4a.alloc(32, 0xc4)
  }
  const requestCommitment = inboxManageRequestCommitment({
    operation: 'inbox-renew',
    relayPublicKey: RELAY,
    physicalTopic: request.physicalTopic,
    expectedRevision: request.expectedRevision,
    expectedLeaseEpoch: request.expectedLeaseEpoch,
    requestedLeaseClass: request.leaseClass,
    clientNonce: request.clientNonce
  })
  const renewal = { request, requestCommitment, preparedAdmission: admission(requestCommitment, 0xc5, 4) }
  const renewed = await engine.renewInbox({ ...renewal, resultBinding: binding() })
  t.is(renewed.inbox.stateRevision, 1n)
  const staleRequest = { ...request, clientNonce: b4a.alloc(32, 0xc7) }
  const staleCommitment = inboxManageRequestCommitment({
    operation: 'inbox-renew',
    relayPublicKey: RELAY,
    physicalTopic: staleRequest.physicalTopic,
    expectedRevision: staleRequest.expectedRevision,
    expectedLeaseEpoch: staleRequest.expectedLeaseEpoch,
    requestedLeaseClass: staleRequest.leaseClass,
    clientNonce: staleRequest.clientNonce
  })
  await rejectsCode(t, engine.renewInbox({
    request: staleRequest,
    requestCommitment: staleCommitment,
    preparedAdmission: admission(staleCommitment, 0xc6, 4),
    resultBinding: binding()
  }), 'STALE_REVISION')
})

test('Inbox cursor freezes snapshot, authenticates every field, and excludes later appends', async t => {
  const root = await temporaryRoot(t)
  const time = clock()
  const created = createFixture()
  const engine = new BlindInboxStorageEngine(engineOptions(root, time))
  await engine.open()
  t.teardown(() => engine.close())
  await engine.createInbox({ ...created, resultBinding: binding() })
  await appendAndFinalize(engine, { ...appendFixture(created, 0xc7), resultBinding: binding() })
  await appendAndFinalize(engine, { ...appendFixture(created, 0xc8), resultBinding: binding() })
  const first = await engine.readPage({ request: readFixture(created, { limit: 1 }).request })
  t.is(first.entries.length, 1)
  t.ok(first.nextCursor)
  await appendAndFinalize(engine, { ...appendFixture(created, 0xc9), resultBinding: binding() })
  const second = await engine.readPage({ request: readFixture(created, { cursor: first.nextCursor, limit: 4 }).request })
  t.is(second.snapshotRevision, 2n)
  t.alike(second.entries.map(entry => entry.appendRevision), [2n])

  const tampered = b4a.from(first.nextCursor)
  tampered[48] ^= 1
  await rejectsCode(t, engine.readPage({ request: readFixture(created, { cursor: tampered }).request }), 'BAD_ENCODING')
  time.extra += 16n * 60_000n
  await rejectsCode(t, engine.readPage({ request: readFixture(created, { cursor: first.nextCursor }).request }), 'EXPIRED')
})

test('charged READ pin survives restart, detects result drift, and expires without restoring spend', async t => {
  const root = await temporaryRoot(t)
  const time = clock()
  const created = createFixture()
  let engine = new BlindInboxStorageEngine(engineOptions(root, time))
  await engine.open()
  await engine.createInbox({ ...created, resultBinding: binding() })
  await appendAndFinalize(engine, { ...appendFixture(created, 0xd3), resultBinding: binding() })
  const read = readFixture(created)
  const pinned = await engine.pinChargedPage({
    operationId: OPERATION.INBOX.READ,
    ...read,
    resultBinding: binding()
  })
  t.is(pinned.entries.length, 1)
  await engine.close()

  engine = new BlindInboxStorageEngine(engineOptions(root, time))
  await engine.open()
  const replay = await engine.readPinnedPage({ spendTag: read.preparedAdmission.spendTag })
  t.ok(b4a.equals(replay.entries[0].frame, pinned.entries[0].frame))
  const commitment = blake2b256(b4a.from('signed-result'))
  await engine.finalizeChargedPage({
    spendTag: read.preparedAdmission.spendTag,
    requestCommitment: read.requestCommitment,
    resultCommitment: commitment
  })
  await rejectsCode(t, engine.finalizeChargedPage({
    spendTag: read.preparedAdmission.spendTag,
    requestCommitment: read.requestCommitment,
    resultCommitment: b4a.alloc(32, 0xff)
  }), 'CONFLICT')
  time.extra += 16n * 60_000n
  await engine.sweepExpired()
  t.is(engine.chargedPageState({
    operationId: OPERATION.INBOX.READ,
    preparedAdmission: read.preparedAdmission
  }).kind, 'replay', 'long-lived spent tag remains committed')
  await rejectsCode(t, engine.readPinnedPage({ spendTag: read.preparedAdmission.spendTag }), 'RETRY_TERMINAL')
  await engine.close()
})

test('WATCH is bounded, wakes on append, tears down on abort/close, and applies waiter quota', async t => {
  const root = await temporaryRoot(t)
  const time = clock()
  const created = createFixture()
  const engine = new BlindInboxStorageEngine(engineOptions(root, time, {
    maxGlobalWaiters: 2,
    maxWaitersPerTopic: 1
  }))
  await engine.open()
  await engine.createInbox({ ...created, resultBinding: binding() })
  const watch = watchFixture(created, { maxWaitMillis: 2000 })
  const waiting = engine.watchPage({ request: watch.request })
  while (engine.status().waiterCount !== 1) await new Promise(resolve => setImmediate(resolve))
  await rejectsCode(t, engine.watchPage({ request: watchFixture(created, { spendByte: 0xe3 }).request }), 'BUSY')
  await appendAndFinalize(engine, { ...appendFixture(created, 0xe4), resultBinding: binding() })
  const woke = await waiting
  t.is(woke.entries.length, 1)
  t.is(engine.status().waiterCount, 0)

  const abort = new AbortController()
  const aborted = engine.watchPage({ request: watchFixture(created, { afterRevision: 1n, maxWaitMillis: 2000 }).request, signal: abort.signal })
  while (engine.status().waiterCount !== 1) await new Promise(resolve => setImmediate(resolve))
  abort.abort()
  await rejectsCode(t, aborted, 'ABORT_ERR')
  t.is(engine.status().waiterCount, 0)

  const closing = engine.watchPage({ request: watchFixture(created, { afterRevision: 1n, maxWaitMillis: 2000 }).request })
  while (engine.status().waiterCount !== 1) await new Promise(resolve => setImmediate(resolve))
  const close = engine.close()
  await rejectsCode(t, closing, 'NOT_FOUND')
  await close
})

test('owner CLOSE wins over READ/retry and exact CLOSE response is idempotent', async t => {
  const root = await temporaryRoot(t)
  const time = clock()
  const created = createFixture()
  const engine = new BlindInboxStorageEngine(engineOptions(root, time))
  await engine.open()
  t.teardown(() => engine.close())
  const state = await engine.createInbox({ ...created, resultBinding: binding() })
  const request = {
    version: 1,
    operation: 2,
    physicalTopic: created.request.physicalTopic,
    expectedRevision: state.inbox.stateRevision,
    expectedLeaseEpoch: state.inbox.leaseEpoch,
    leaseClass: 0,
    clientNonce: b4a.alloc(32, 0xf1)
  }
  const requestCommitment = inboxManageRequestCommitment({
    operation: 'inbox-close',
    relayPublicKey: RELAY,
    physicalTopic: request.physicalTopic,
    expectedRevision: request.expectedRevision,
    expectedLeaseEpoch: request.expectedLeaseEpoch,
    requestedLeaseClass: 0,
    clientNonce: request.clientNonce
  })
  const closed = await engine.closeInbox({ request, requestCommitment, resultBinding: binding() })
  const replay = await engine.closeInbox({ request, requestCommitment, resultBinding: binding(2n) })
  t.is(closed.inbox.stateRevision, 1n)
  t.ok(b4a.equals(closed.resultBindingBytes, replay.resultBindingBytes))
  const recovered = await checkpointRoundTrip(engine)
  const recoveredClose = recovered.state.requestResults.get(b4a.toString(requestCommitment, 'hex'))
  t.ok(b4a.equals(recoveredClose.resultBindingBytes, closed.resultBindingBytes))
  t.ok(b4a.equals(recoveredClose.clientNonce, request.clientNonce))
  t.is(recoveredClose.resultLeaseClass, 0)
  t.is(recoveredClose.resultLeaseEpoch, state.inbox.leaseEpoch)
  await rejectsCode(t, engine.readPage({ request: readFixture(created).request }), 'NOT_FOUND')
})

test('frame tamper on restart fails closed with persisted recovery-gap evidence', async t => {
  const root = await temporaryRoot(t)
  const time = clock()
  const created = createFixture()
  let engine = new BlindInboxStorageEngine(engineOptions(root, time))
  await engine.open()
  await engine.createInbox({ ...created, resultBinding: binding() })
  await appendAndFinalize(engine, { ...appendFixture(created, 0xf2), resultBinding: binding() })
  await engine.close()
  const buckets = await fs.readdir(path.join(root, 'blobs'))
  const blob = path.join(root, 'blobs', buckets[0], (await fs.readdir(path.join(root, 'blobs', buckets[0])))[0])
  const bytes = await fs.readFile(blob)
  bytes[0] ^= 1
  await fs.writeFile(blob, bytes)

  engine = new BlindInboxStorageEngine(engineOptions(root, time))
  await engine.open()
  t.is(engine.status().readOnlyReason, 'RECOVERY_GAP_READ_ONLY')
  await rejectsCode(t, engine.appendFrame({ ...appendFixture(created, 0xf3), resultBinding: binding() }), 'INTERNAL')
  await engine.close()

  engine = new BlindInboxStorageEngine(engineOptions(root, time))
  await engine.open()
  t.is(engine.status().readOnlyReason, 'RECOVERY_GAP_READ_ONLY')
  await engine.close()
})

test('capacity refuses APPEND without eviction and frame retention/GC respects active retry pins', async t => {
  const root = await temporaryRoot(t)
  const time = clock()
  const created = createFixture({ retentionClass: 1, leaseClass: 2 })
  const engine = new BlindInboxStorageEngine(engineOptions(root, time, {
    maxStoredFrameBytes: 4096,
    maxFrames: 2,
    maxFramesPerTopic: 2
  }))
  await engine.open()
  t.teardown(() => engine.close())
  await engine.createInbox({ ...created, resultBinding: binding() })
  await appendAndFinalize(engine, { ...appendFixture(created, 0xf4), resultBinding: binding() })
  await rejectsCode(t, engine.appendFrame({ ...appendFixture(created, 0xf5), resultBinding: binding() }), 'BUSY')
  const read = readFixture(created)
  await engine.pinChargedPage({ operationId: OPERATION.INBOX.READ, ...read, resultBinding: binding() })
  await engine.finalizeChargedPage({
    spendTag: read.preparedAdmission.spendTag,
    requestCommitment: read.requestCommitment,
    resultCommitment: blake2b256(b4a.from('result'))
  })
  await engine.advanceEpochFloor(105)
  await engine.sweepExpired()
  t.is(engine.status().frameCount, 1, 'charged retry pin prevents early physical GC')
  time.extra += 16n * 60_000n
  await engine.sweepExpired()
  t.is(engine.status().frameCount, 0)
})

test('storage errors expose only canonical protocol codes', t => {
  const error = new BlindInboxStorageError('BUSY', 'bounded')
  t.is(error.code, 'BUSY')
  t.is(error.name, 'BlindInboxStorageError')
})

test('live Inbox engine state is accepted by the frozen bounded snapshot authority', async t => {
  const root = await temporaryRoot(t)
  const time = clock()
  const created = createFixture()
  const engine = new BlindInboxStorageEngine(engineOptions(root, time))
  await engine.open()
  t.teardown(() => engine.close())
  const createdState = await engine.createInbox({ ...created, resultBinding: binding() })
  const renewRequest = {
    version: 1,
    operation: 1,
    physicalTopic: created.request.physicalTopic,
    expectedRevision: createdState.inbox.stateRevision,
    expectedLeaseEpoch: createdState.inbox.leaseEpoch,
    leaseClass: 4,
    clientNonce: b4a.alloc(32, 0x6e)
  }
  const renewCommitment = inboxManageRequestCommitment({
    operation: 'inbox-renew',
    relayPublicKey: RELAY,
    physicalTopic: renewRequest.physicalTopic,
    expectedRevision: renewRequest.expectedRevision,
    expectedLeaseEpoch: renewRequest.expectedLeaseEpoch,
    requestedLeaseClass: renewRequest.leaseClass,
    clientNonce: renewRequest.clientNonce
  })
  await engine.renewInbox({
    request: renewRequest,
    preparedAdmission: admission(renewCommitment, 0x6f, renewRequest.leaseClass),
    resultBinding: binding()
  })
  await appendAndFinalize(engine, { ...appendFixture(created, 0xfa), resultBinding: binding() })
  await appendAndFinalize(engine, { ...appendFixture(created, 0x6d), resultBinding: binding() })
  const read = readFixture(created, { limit: 1 })
  await engine.pinChargedPage({ operationId: OPERATION.INBOX.READ, ...read, resultBinding: binding() })
  await engine.finalizeChargedPage({
    spendTag: read.preparedAdmission.spendTag,
    requestCommitment: read.requestCommitment,
    resultCommitment: blake2b256(b4a.from('snapshot-result'))
  })
  const recovered = await checkpointRoundTrip(engine)
  const entries = recovered.entries
  t.ok(entries.length >= 7, 'snapshot contains global, inbox, frame, spends, and retry pins')
  const createSpend = [...recovered.state.spends.values()]
    .find(value => value.operation === OPERATION.INBOX.CREATE)
  t.is(createSpend.resultLeaseClass, created.request.leaseClass)
  t.is(createSpend.resultLeaseEpoch, 128)
  t.ok(b4a.equals(createSpend.resultBindingBytes, encodeCanonical(relayResultBindingV1, binding())))
  const renewSpend = [...recovered.state.spends.values()]
    .find(value => value.operation === OPERATION.INBOX.RENEW)
  t.is(renewSpend.resultLeaseClass, renewRequest.leaseClass)
  t.is(renewSpend.resultLeaseEpoch, 460)
  const pinKey = b4a.toString(read.preparedAdmission.spendTag, 'hex')
  const sourcePin = recovered.sourceState.retryPins.get(pinKey)
  const recoveredPin = recovered.state.retryPins.get(pinKey)
  t.ok(sourcePin.nextCursor != null, 'fixture exercises exact nonempty cursor recovery')
  t.ok(b4a.equals(recoveredPin.nextCursor, sourcePin.nextCursor))
  t.ok(b4a.equals(recoveredPin.entriesCommitment, sourcePin.entriesCommitment))
  t.alike(recoveredPin.pinnedEntries, sourcePin.pinnedEntries)
})

test('response loss after WAL fsync recovers one APPEND and its admission commit record', async t => {
  const root = await temporaryRoot(t)
  const time = clock()
  const created = createFixture()
  let failAfterSync = false
  let injected = false
  let engine = new BlindInboxStorageEngine(engineOptions(root, time, {
    faultInjector: async point => {
      if (failAfterSync && !injected && point === 'wal:after-sync') {
        injected = true
        throw new Error('simulated response-loss crash')
      }
    }
  }))
  await engine.open()
  await engine.createInbox({ ...created, resultBinding: binding() })
  const appended = appendFixture(created, 0xfb)
  failAfterSync = true
  try {
    await engine.appendFrame({ ...appended, resultBinding: binding() })
    t.fail('expected post-fsync fault')
  } catch (error) {
    t.is(error.message, 'simulated response-loss crash')
  }
  await engine.close()

  engine = new BlindInboxStorageEngine(engineOptions(root, time))
  await engine.open()
  const replay = await appendAndFinalize(engine, { ...appended, resultBinding: binding(2n) })
  t.is(replay.frame.appendRevision, 1n)
  t.is(engine.status().frameCount, 1, 'durable WAL applies exactly one frame after response loss')
  await engine.close()
})

test('APPEND remains non-releasable until exact ACK finalization and replays after retention and inbox GC', async t => {
  const root = await temporaryRoot(t, 'blind-inbox-append-finalization')
  const time = clock()
  const created = createFixture()
  const appended = appendFixture(created, 0x6b)
  let engine = new BlindInboxStorageEngine(engineOptions(root, time))
  await engine.open()
  await engine.createInbox({ ...created, resultBinding: binding() })

  const provisional = await engine.appendFrame({ ...appended, resultBinding: binding() })
  t.is(provisional.ackSignature, null)
  t.is((await engine.readPage({ request: readFixture(created).request })).snapshotRevision, 0n,
    'provisional APPEND is not visible')
  try {
    engine.snapshotState()
    t.fail('expected provisional checkpoint refusal')
  } catch (error) {
    t.is(error.code, 'BUSY')
  }

  const signedBeforeRestart = appendAckFinalization(provisional)
  await engine.close()
  engine = new BlindInboxStorageEngine(engineOptions(root, time))
  await engine.open()
  const recoveredProvisional = await engine.appendFrame({ ...appended, resultBinding: binding(2n) })
  t.is(recoveredProvisional.ackSignature, null, 'crash after signing but before finalization remains provisional')
  const recoveredSigned = appendAckFinalization(recoveredProvisional)
  t.alike(recoveredSigned.body, signedBeforeRestart.body, 'recovered signer reconstructs the exact acknowledgement')
  await engine.finalizeAppendAck({
    spendTag: recoveredProvisional.spendTag,
    requestCommitment: recoveredProvisional.requestCommitment,
    ackSignature: recoveredSigned.value.signature,
    resultCommitment: recoveredSigned.resultCommitment
  })
  const finalized = await engine.appendFrame({ ...appended, resultBinding: binding(3n) })
  t.alike(finalized.ackSignature, recoveredSigned.value.signature)
  t.alike(finalized.resultCommitment, recoveredSigned.resultCommitment)
  t.is((await engine.readPage({ request: readFixture(created).request })).snapshotRevision, 1n)

  await engine.advanceEpochFloor(128)
  await engine.sweepExpired()
  t.is(engine.status().frameCount, 0, 'retention removes body and frame index')
  const expiredReplay = await engine.appendFrame({ ...appended, resultBinding: binding(4n) })
  t.alike(expiredReplay.ackSignature, finalized.ackSignature)
  t.alike(expiredReplay.resultCommitment, finalized.resultCommitment)
  t.is(expiredReplay.frame.appendRevision, 1n)

  await engine.advanceEpochFloor(133)
  await engine.sweepExpired()
  t.is(engine.inspectInboxState(created.request.physicalTopic), null, 'inbox lease GC makes new traffic absent')
  const tombstoneReplay = await engine.appendFrame({ ...appended, resultBinding: binding(5n) })
  t.alike(tombstoneReplay.ackSignature, finalized.ackSignature,
    'long-lived spent state replays the exact ACK after inbox GC')
  const authority = createBlindInboxControlSnapshotSemanticAuthority({ partitionKey: PARTITION })
  const checkpointEntries = []
  for await (const entry of streamBlindInboxControlSnapshotEntries(authority, engine.snapshotState())) {
    checkpointEntries.push(entry)
  }
  t.ok(checkpointEntries.length > 0, 'expired APPEND compact spend enters the bounded checkpoint authority')
  await engine.close()

  engine = new BlindInboxStorageEngine(engineOptions(root, time))
  await engine.open()
  const restartReplay = await engine.appendFrame({ ...appended, resultBinding: binding(6n) })
  t.alike(restartReplay.ackSignature, finalized.ackSignature)
  t.alike(restartReplay.resultCommitment, finalized.resultCommitment)
  t.is(engine.status().frameCount, 0)
  await engine.close()
})

test('crash after ACK-finalization fsync recovers one exact releasable APPEND', async t => {
  const root = await temporaryRoot(t, 'blind-inbox-ack-fsync-crash')
  const time = clock()
  const created = createFixture()
  const appended = appendFixture(created, 0x6c)
  let crashFinalization = false
  let injected = false
  let engine = new BlindInboxStorageEngine(engineOptions(root, time, {
    faultInjector: async point => {
      if (crashFinalization && !injected && point === 'wal:after-sync') {
        injected = true
        throw new Error('simulated ACK-finalization response loss')
      }
    }
  }))
  await engine.open()
  await engine.createInbox({ ...created, resultBinding: binding() })
  const provisional = await engine.appendFrame({ ...appended, resultBinding: binding() })
  const finalized = appendAckFinalization(provisional)
  crashFinalization = true
  await t.exception(engine.finalizeAppendAck({
    spendTag: provisional.spendTag,
    requestCommitment: provisional.requestCommitment,
    ackSignature: finalized.value.signature,
    resultCommitment: finalized.resultCommitment
  }), /simulated ACK-finalization response loss/)
  await engine.close()

  engine = new BlindInboxStorageEngine(engineOptions(root, time))
  await engine.open()
  const replay = await engine.appendFrame({ ...appended, resultBinding: binding(2n) })
  t.alike(replay.ackSignature, finalized.value.signature)
  t.alike(replay.resultCommitment, finalized.resultCommitment)
  t.is((await engine.readPage({ request: readFixture(created).request })).snapshotRevision, 1n)
  await engine.finalizeAppendAck({
    spendTag: replay.spendTag,
    requestCommitment: replay.requestCommitment,
    ackSignature: replay.ackSignature,
    resultCommitment: replay.resultCommitment
  })
  await engine.close()
})

test('same admission spend cannot be rebound to another APPEND request', async t => {
  const root = await temporaryRoot(t)
  const time = clock()
  const created = createFixture()
  const engine = new BlindInboxStorageEngine(engineOptions(root, time))
  await engine.open()
  t.teardown(() => engine.close())
  await engine.createInbox({ ...created, resultBinding: binding() })
  const first = appendFixture(created, 0xfc, { spendByte: 0xfd })
  await appendAndFinalize(engine, { ...first, resultBinding: binding() })
  const conflict = appendFixture(created, 0xfe, { spendByte: 0xfd })
  conflict.preparedAdmission.spendTag = b4a.from(first.preparedAdmission.spendTag)
  await rejectsCode(t, engine.appendFrame({ ...conflict, resultBinding: binding() }), 'SPEND_REPLAY')
  t.is(engine.status().frameCount, 1)
})
