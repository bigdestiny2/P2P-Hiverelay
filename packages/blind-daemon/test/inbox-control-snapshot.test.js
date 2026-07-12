import b4a from 'b4a'
import test from 'brittle'
import { createHmac } from 'node:crypto'
import sodium from 'sodium-universal'
import {
  FAMILY,
  INBOX_APPEND_RESULT,
  INBOX_FRAME_CLASS,
  OPERATION,
  RESULT_SIGNATURE_DOMAIN_ID,
  blindInboxControlGlobalSnapshotV1,
  blindInboxRetryReconstructionV1,
  blake2b256,
  chargedUnaryRetryV1,
  decodeCanonical,
  encodeCanonical,
  inboxAppendAckV1,
  inboxCreateCommitment,
  inboxPhysicalTopic,
  relayResultBindingV1,
  resultSignaturePayload
} from '@hiverelay/blind-protocol'
import {
  BLIND_INBOX_CONTROL_SNAPSHOT_STATUS,
  createBlindInboxControlSnapshotSemanticAuthority,
  createBlindInboxControlSnapshotSemanticVerifier,
  reconstructBlindInboxControlSnapshot,
  streamBlindInboxControlSnapshotEntries,
  verifyBlindInboxControlSnapshotSemanticResult,
  verifyBlindInboxControlSnapshotSemanticVerifier
} from '../inbox-control-snapshot.js'
import { verifyBlindLocalCheckpointSnapshotSemanticAuthority } from '../local-checkpoint-store.js'

const PARTITION_KEY = b4a.alloc(32, 0x25)
const FINGERPRINT_DOMAIN = b4a.from('hiverelay.blind.inbox-store-request-fingerprint.v1', 'ascii')
const RESULT_IDENTITY_DOMAIN = b4a.from('hiverelay.blind.inbox-store-result-identity.v1', 'ascii')
const RETRY_SOURCE_DOMAIN = b4a.from('hiverelay.blind.inbox-retry-source.v1', 'ascii')
const ZERO32 = b4a.alloc(32)
const RELAY_SEED = b4a.alloc(sodium.crypto_sign_SEEDBYTES, 0x01)
const RELAY_PUBLIC_KEY = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
const RELAY_SECRET_KEY = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
sodium.crypto_sign_seed_keypair(RELAY_PUBLIC_KEY, RELAY_SECRET_KEY, RELAY_SEED)
const STORE_ID = b4a.alloc(32, 0x02)
const DURABILITY_CONTINUITY = b4a.alloc(32, 0x03)

function bytes (fill) {
  return b4a.alloc(32, fill)
}

function u16bytes (value) {
  return b4a.from([value >>> 8, value])
}

function u32bytes (value) {
  return b4a.from([value >>> 24, value >>> 16, value >>> 8, value])
}

function u64bytes (value) {
  value = BigInt(value)
  const output = b4a.alloc(8)
  for (let index = 7; index >= 0; index--) {
    output[index] = Number(value & 0xffn)
    value >>= 8n
  }
  return output
}

function hashParts (domain, ...parts) {
  return blake2b256(b4a.concat([domain, ...parts]))
}

function fingerprint (value) {
  return hashParts(
    FINGERPRINT_DOMAIN,
    b4a.from([value.operation]),
    value.spendTag,
    value.requestCommitment,
    value.physicalTopic,
    b4a.from([value.frameClass]),
    value.frameHash == null ? ZERO32 : value.frameHash,
    b4a.from([value.requestedLeaseClass]),
    u16bytes(value.profileId),
    u32bytes(value.declaredBytes)
  )
}

function resultIdentity (operation, physicalTopic, requestCommitment, resultRevision, resultHash, committedEpoch) {
  return hashParts(
    RESULT_IDENTITY_DOMAIN,
    b4a.from([operation]),
    physicalTopic,
    requestCommitment,
    u64bytes(resultRevision),
    resultHash,
    u32bytes(committedEpoch)
  )
}

function retrySourceCommitment (physicalTopic, sourceRevision, reconstruction, pins) {
  const pinBytes = pins.flatMap(pin => [u64bytes(pin.appendRevision), pin.frameHash])
  return hashParts(
    RETRY_SOURCE_DOMAIN,
    physicalTopic,
    u64bytes(sourceRevision),
    u64bytes(reconstruction.firstAppendRevision),
    u64bytes(reconstruction.lastAppendRevision),
    b4a.from([reconstruction.entryCount]),
    reconstruction.nextCursorHash,
    ...pinBytes
  )
}

function virtualBucket (physicalTopic) {
  const digest = createHmac('sha256', PARTITION_KEY)
    .update(b4a.from([FAMILY.INBOX]))
    .update(physicalTopic)
    .digest()
  return digest[0] * 0x100 + digest[1]
}

function authority (overrides = {}) {
  return createBlindInboxControlSnapshotSemanticAuthority({ partitionKey: PARTITION_KEY, ...overrides })
}

function spend (seed, physicalTopic, operation, overrides = {}) {
  const value = {
    status: overrides.status || 'committed',
    transactionId: bytes(0x10 + seed),
    spendTag: bytes(0x20 + seed),
    requestCommitment: bytes(0x30 + seed),
    physicalTopic,
    operation,
    profileId: seed,
    frameClass: overrides.frameClass || 0,
    frameHash: overrides.frameHash || null,
    requestedLeaseClass: overrides.requestedLeaseClass || 0,
    declaredBytes: overrides.declaredBytes || 0,
    deadlineUnixMillis: 100000n + BigInt(seed),
    remainingAttempts: overrides.remainingAttempts == null ? 1 : overrides.remainingAttempts,
    reservedEpoch: 100,
    resultIdentity: overrides.resultIdentity || null,
    resultRevision: overrides.resultRevision == null ? null : BigInt(overrides.resultRevision),
    committedEpoch: overrides.committedEpoch == null ? null : overrides.committedEpoch,
    resultLeaseClass: overrides.resultLeaseClass == null ? null : overrides.resultLeaseClass,
    resultLeaseEpoch: overrides.resultLeaseEpoch == null ? null : overrides.resultLeaseEpoch,
    resultCommitment: overrides.resultCommitment || null,
    retryState: overrides.retryState || 0,
    terminalReason: overrides.terminalReason || null,
    terminalEpoch: overrides.terminalEpoch || null,
    inFlight: false
  }
  value.requestFingerprint = fingerprint(value)
  return value
}

function fixture (reverse = false) {
  const relayPublicKey = b4a.from(RELAY_PUBLIC_KEY)
  const allocationEpoch = 90
  const createPublicKey = bytes(0x41)
  const appendPublicKey = bytes(0x42)
  const renewPublicKey = bytes(0x43)
  const closePublicKey = bytes(0x44)
  const physicalTopic = inboxPhysicalTopic({ allocationEpoch, createPublicKey })
  const createCommitment = inboxCreateCommitment({
    relayPublicKey,
    physicalTopic,
    allocationEpoch,
    frameClassBits: 0x07,
    appendAuthMode: 1,
    appendPublicKey,
    createPublicKey,
    renewPublicKey,
    closePublicKey,
    retentionClass: 1,
    leaseClass: 1
  })

  const createSpend = spend(1, physicalTopic, OPERATION.INBOX.CREATE, {
    requestedLeaseClass: 1,
    resultRevision: 0,
    committedEpoch: 100,
    resultLeaseClass: 1,
    resultLeaseEpoch: 104
  })
  createSpend.resultIdentity = resultIdentity(OPERATION.INBOX.CREATE, physicalTopic,
    createSpend.requestCommitment, 0n, createCommitment, 100)

  const frameHash = bytes(0x51)
  const appendSpend = spend(2, physicalTopic, OPERATION.INBOX.APPEND, {
    frameClass: 1,
    frameHash,
    declaredBytes: INBOX_FRAME_CLASS[1],
    resultRevision: 1,
    committedEpoch: 100
  })
  appendSpend.resultIdentity = resultIdentity(OPERATION.INBOX.APPEND, physicalTopic,
    appendSpend.requestCommitment, 1n, frameHash, 100)
  const relayBinding = {
    version: 1,
    relayPublicKey,
    storeId: STORE_ID,
    descriptorSequence: 1n,
    descriptorHash: bytes(0x05),
    durabilityProfileId: 1,
    durabilityContinuityHash: DURABILITY_CONTINUITY,
    durabilityProfileHash: bytes(0x06),
    restoreEvidenceHeadSequence: 0n,
    restoreEvidenceHeadHash: b4a.alloc(32),
    externalCommitWitness: null
  }
  appendSpend.resultBindingBytes = encodeCanonical(relayResultBindingV1, relayBinding)
  appendSpend.clientNonce = bytes(0x53)
  appendSpend.retentionClassAtAppend = 1
  appendSpend.appendLeaseEpoch = 104
  appendSpend.expiresAtEpoch = 104
  const unsignedAck = encodeCanonical(inboxAppendAckV1, {
    version: 1,
    relayBinding,
    topicCommitment: blake2b256(physicalTopic),
    frameHash,
    appendRevision: 1n,
    storedAtEpoch: 100,
    expiresAtEpoch: 104,
    requestNonce: appendSpend.clientNonce,
    requestCommitment: appendSpend.requestCommitment,
    result: INBOX_APPEND_RESULT.STORED,
    signature: b4a.alloc(64)
  }).subarray(0, -64)
  appendSpend.ackSignature = b4a.alloc(64)
  sodium.crypto_sign_detached(appendSpend.ackSignature,
    resultSignaturePayload(RESULT_SIGNATURE_DOMAIN_ID.INBOX_APPEND_ACK, unsignedAck), RELAY_SECRET_KEY)
  appendSpend.resultCommitment = blake2b256(encodeCanonical(inboxAppendAckV1, {
    version: 1,
    relayBinding,
    topicCommitment: blake2b256(physicalTopic),
    frameHash,
    appendRevision: 1n,
    storedAtEpoch: 100,
    expiresAtEpoch: 104,
    requestNonce: appendSpend.clientNonce,
    requestCommitment: appendSpend.requestCommitment,
    result: INBOX_APPEND_RESULT.STORED,
    signature: appendSpend.ackSignature
  }))
  createSpend.resultBindingBytes = b4a.from(appendSpend.resultBindingBytes)
  createSpend.clientNonce = bytes(0x54)

  const reservedAppend = spend(3, physicalTopic, OPERATION.INBOX.APPEND, {
    status: 'reserved',
    frameClass: 2,
    frameHash: bytes(0x52),
    declaredBytes: INBOX_FRAME_CLASS[2],
    remainingAttempts: 2
  })

  const resultCommitment = bytes(0x61)
  const readSpend = spend(4, physicalTopic, OPERATION.INBOX.READ, {
    resultRevision: 1,
    committedEpoch: 100,
    resultCommitment,
    retryState: 1
  })
  readSpend.resultIdentity = resultIdentity(OPERATION.INBOX.READ, physicalTopic,
    readSpend.requestCommitment, 1n, resultCommitment, 100)
  readSpend.resultBindingBytes = b4a.from(appendSpend.resultBindingBytes)
  readSpend.clientNonce = bytes(0x55)

  const spendRows = [createSpend, appendSpend, reservedAppend, readSpend]
  if (reverse) spendRows.reverse()
  const spends = new Map(spendRows.map(value => [b4a.toString(value.spendTag, 'hex'), value]))
  const commitments = new Map(spendRows.map(value => [
    b4a.toString(value.requestCommitment, 'hex'),
    {
      spendKey: b4a.toString(value.spendTag, 'hex'),
      fingerprint: b4a.toString(value.requestFingerprint, 'hex')
    }
  ]))

  const inbox = {
    physicalTopic,
    metadataVirtualBucket: virtualBucket(physicalTopic),
    allocationEpoch,
    frameClassBits: 0x07,
    appendAuthMode: 1,
    appendPublicKey,
    createPublicKey,
    renewPublicKey,
    closePublicKey,
    retentionClass: 1,
    // Renewed state; the immutable create commitment remains lease class 1.
    leaseClass: 4,
    leaseEpoch: 460,
    stateRevision: 1n,
    policyRevision: 0n,
    appendRevision: 1n,
    createCommitment,
    objectState: 1,
    policyState: 1,
    tombstoneReason: null,
    terminalEpoch: null,
    createSpendTag: createSpend.spendTag,
    createRequestCommitment: createSpend.requestCommitment,
    resultIdentity: createSpend.resultIdentity,
    createdEpoch: 100
  }
  const frame = {
    physicalTopic,
    appendRevision: 1n,
    frameHash,
    frameClass: 1,
    frameVirtualBucket: virtualBucket(physicalTopic),
    frameObjectId: bytes(0x71),
    appendLeaseEpoch: 104,
    storedAtEpoch: 100,
    expiresAtEpoch: 104,
    spendTag: appendSpend.spendTag,
    requestCommitment: appendSpend.requestCommitment,
    resultIdentity: appendSpend.resultIdentity
  }
  const nextCursor = b4a.from('cursor-v1', 'ascii')
  const reconstruction = {
    version: 1,
    firstAppendRevision: 1n,
    lastAppendRevision: 1n,
    entryCount: 1,
    nextCursorHash: blake2b256(nextCursor)
  }
  const pinEntries = [{ physicalTopic, appendRevision: 1n, frameHash }]
  const pin = {
    spendTag: readSpend.spendTag,
    requestCommitment: readSpend.requestCommitment,
    physicalTopic,
    operation: OPERATION.INBOX.READ,
    locatorCommitment: blake2b256(physicalTopic),
    sourceRevision: 1n,
    sourceCommitment: retrySourceCommitment(physicalTopic, 1n, reconstruction, pinEntries),
    resultCommitment,
    reconstruction,
    retryExpiresMinute: 200000n,
    retryState: 1,
    entries: pinEntries,
    pinnedEntries: [{
      appendRevision: frame.appendRevision,
      frameHash: frame.frameHash,
      frameClass: frame.frameClass,
      frameObjectId: frame.frameObjectId
    }],
    entriesCommitment: bytes(0x64),
    nextCursor,
    resultBindingBytes: readSpend.resultBindingBytes,
    clientNonce: readSpend.clientNonce,
    committedEpoch: readSpend.committedEpoch
  }
  return {
    relayPublicKey,
    storeId: STORE_ID,
    durabilityContinuityHash: DURABILITY_CONTINUITY,
    spends,
    commitments,
    requestResults: new Map(),
    inboxes: new Map([[b4a.toString(physicalTopic, 'hex'), inbox]]),
    frames: new Map([[`${b4a.toString(physicalTopic, 'hex')}:1`, frame]]),
    retryPins: new Map([[b4a.toString(readSpend.spendTag, 'hex'), pin]]),
    accounting: {
      storedFrameBytes: INBOX_FRAME_CLASS[1],
      stagingFrameBytes: INBOX_FRAME_CLASS[2],
      controlBytes: 4 * 512 + 2 * 256,
      tombstoneBytes: 512,
      frameIndexBytes: 256,
      reservedFrames: 1,
      stagingByProfile: new Map([[reservedAppend.profileId, INBOX_FRAME_CLASS[2]]])
    },
    epochFloor: 100,
    clockUnsafe: true,
    readOnlyReason: null,
    integrityEvidence: []
  }
}

function terminalFixture () {
  const state = fixture()
  const reserved = [...state.spends.values()].find(value => value.status === 'reserved')
  reserved.status = 'terminal'
  reserved.remainingAttempts = 0
  reserved.terminalReason = 2
  reserved.terminalEpoch = 100
  state.accounting.stagingFrameBytes = 0
  state.accounting.reservedFrames = 0
  state.accounting.stagingByProfile.clear()
  return state
}

function expiredAppendFixture () {
  const state = fixture()
  const append = [...state.spends.values()].find(value => value.operation === OPERATION.INBOX.APPEND &&
    value.status === 'committed')
  const read = [...state.spends.values()].find(value => value.operation === OPERATION.INBOX.READ)
  append.status = 'expired-append'
  append.expiredEpoch = 104
  state.frames.clear()
  state.spends.delete(b4a.toString(read.spendTag, 'hex'))
  state.commitments.delete(b4a.toString(read.requestCommitment, 'hex'))
  state.retryPins.clear()
  state.accounting.storedFrameBytes = 0
  state.accounting.frameIndexBytes = 0
  state.accounting.controlBytes = 3 * 512
  state.epochFloor = 104
  return state
}

function closedFixture () {
  const state = terminalFixture()
  const terminal = [...state.spends.values()].find(value => value.status === 'terminal')
  state.spends.delete(b4a.toString(terminal.spendTag, 'hex'))
  state.commitments.delete(b4a.toString(terminal.requestCommitment, 'hex'))
  const inbox = state.inboxes.values().next().value
  inbox.objectState = 2
  inbox.tombstoneReason = 1
  inbox.terminalEpoch = 100
  inbox.stateRevision = 2n
  const readSpend = [...state.spends.values()].find(value => value.operation === OPERATION.INBOX.READ)
  readSpend.retryState = 2
  state.retryPins.get(b4a.toString(readSpend.spendTag, 'hex')).retryState = 2
  const closeRequest = bytes(0x7a)
  const closeResult = {
    operation: 'close',
    transactionId: bytes(0x79),
    requestCommitment: closeRequest,
    physicalTopic: inbox.physicalTopic,
    resultRevision: 2n,
    committedEpoch: 100,
    resultBindingBytes: b4a.from([...state.spends.values()]
      .find(value => value.status === 'committed').resultBindingBytes),
    clientNonce: bytes(0x7b),
    resultLeaseClass: 0,
    resultLeaseEpoch: inbox.leaseEpoch,
    resultIdentity: resultIdentity(OPERATION.INBOX.CLOSE, inbox.physicalTopic,
      closeRequest, 2n, inbox.createCommitment, 100)
  }
  state.requestResults.set(b4a.toString(closeRequest, 'hex'), closeResult)
  state.accounting.controlBytes = 4 * 512 + 2 * 256
  return state
}

function headers (state) {
  const header = {
    relayPublicKey: state.relayPublicKey,
    storeId: STORE_ID,
    durabilityContinuityHash: DURABILITY_CONTINUITY,
    walSequence: 7n,
    walHash: bytes(0x04)
  }
  return {
    header,
    checkpointHeader: {
      relayPublicKey: header.relayPublicKey,
      storeId: header.storeId,
      durabilityContinuityHash: header.durabilityContinuityHash,
      coveredWalSequence: header.walSequence,
      coveredWalHash: header.walHash,
      epochFloor: state.epochFloor
    }
  }
}

async function entriesFor (semanticAuthority, state) {
  const output = []
  for await (const entry of streamBlindInboxControlSnapshotEntries(semanticAuthority, state)) {
    output.push({ entryKind: entry.entryKind, key: b4a.from(entry.key), value: b4a.from(entry.value) })
  }
  return output
}

async function reconstruct (semanticAuthority, state, entries) {
  return reconstructBlindInboxControlSnapshot(semanticAuthority, {
    ...headers(state),
    declaredEntryCount: entries.length,
    entries
  })
}

test('Inbox recovery snapshots are deterministic, bounded, exact, and preserve immutable allocation history', async t => {
  const semanticAuthority = authority()
  const state = fixture()
  const entries = await entriesFor(semanticAuthority, state)
  const reversedEntries = await entriesFor(semanticAuthority, fixture(true))
  t.alike(reversedEntries, entries)
  const retry = state.retryPins.values().next().value
  const reconstructionBytes = encodeCanonical(blindInboxRetryReconstructionV1, retry.reconstruction)
  t.is(reconstructionBytes.byteLength, 50)
  t.is(encodeCanonical(chargedUnaryRetryV1, {
    version: 1,
    spendTag: retry.spendTag,
    requestCommitment: retry.requestCommitment,
    familyId: FAMILY.INBOX,
    operationId: retry.operation,
    locatorCommitment: retry.locatorCommitment,
    sourceRevision: retry.sourceRevision,
    sourceCommitment: retry.sourceCommitment,
    resultCommitment: retry.resultCommitment,
    reconstruction: reconstructionBytes,
    retryExpiresMinute: retry.retryExpiresMinute,
    retryState: retry.retryState
  }).byteLength, 231)

  const verifier = createBlindInboxControlSnapshotSemanticVerifier(semanticAuthority)
  t.is(verifyBlindInboxControlSnapshotSemanticVerifier(verifier), verifier)
  const result = await verifier({
    ...headers(state),
    declaredEntryCount: entries.length,
    entries
  })
  t.is(verifyBlindInboxControlSnapshotSemanticResult(result), result)
  t.is(result.inboxComplete, true)
  t.is(result.recoveryVerified, true)
  t.is(result.publicationAuthorized, false)
  t.is(result.productionComplete, false)
  t.is(BLIND_INBOX_CONTROL_SNAPSHOT_STATUS.scalableCandidateEntryStreamingImplemented, false)
  t.is(BLIND_INBOX_CONTROL_SNAPSHOT_STATUS.frameBodyAvailabilityAndHashVerificationImplemented, false)
  const recovered = result.inboxState
  const inbox = recovered.inboxes.values().next().value
  t.is(inbox.allocationLeaseClass, 1)
  t.is(inbox.leaseClass, 4)
  t.is(recovered.frames.size, 1)
  t.is(recovered.retryPins.size, 1)
  t.is(recovered.accounting.controlBytes, 2560)
  t.is(recovered.accounting.stagingByProfile.get(3), INBOX_FRAME_CLASS[2])
})

test('Inbox semantic result state, tuple, authority, and verifier branding are private and immutable', async t => {
  await t.exception.all(() => createBlindInboxControlSnapshotSemanticAuthority(), /partitionKey must be bytes/)
  await t.exception.all(() => authority({ maximumCandidateEntries: 0 }), /maximumCandidateEntries is outside/)
  const semanticAuthority = authority()
  const state = fixture()
  const entries = await entriesFor(semanticAuthority, state)
  const result = await reconstruct(semanticAuthority, state, entries)
  const expected = headers(state).header

  result.relayPublicKey.fill(0)
  const exposed = result.inboxState
  exposed.inboxes.clear()
  exposed.frames.clear()
  exposed.retryPins.clear()
  exposed.accounting.stagingByProfile.clear()
  verifyBlindInboxControlSnapshotSemanticResult(result, { ...expected, entryCount: entries.length })
  t.alike(result.relayPublicKey, expected.relayPublicKey)
  t.is(result.inboxState.inboxes.size, 1)
  t.is(result.inboxState.frames.size, 1)
  t.is(result.inboxState.retryPins.size, 1)

  await t.exception.all(() => verifyBlindInboxControlSnapshotSemanticVerifier(() => {}), /branded Inbox/)
  await t.exception.all(() => verifyBlindInboxControlSnapshotSemanticResult({ ...result }), /branded Inbox/)
  await t.exception(verifyBlindLocalCheckpointSnapshotSemanticAuthority(result, {}, '/private/tmp', {}),
    /snapshot semantic authority is forged, expired, or unsupported/)
})

test('Inbox terminal spends and owner-close tombstones reconstruct without losing retained idempotency', async t => {
  const semanticAuthority = authority()
  const terminalState = terminalFixture()
  const terminalEntries = await entriesFor(semanticAuthority, terminalState)
  const terminalResult = await reconstruct(semanticAuthority, terminalState, terminalEntries)
  t.is([...terminalResult.inboxState.spends.values()].filter(value => value.status === 'terminal').length, 1)
  t.is(terminalResult.inboxState.accounting.stagingFrameBytes, 0)
  t.is(terminalResult.inboxState.accounting.reservedFrames, 0)

  const closedState = closedFixture()
  const closedEntries = await entriesFor(semanticAuthority, closedState)
  const closedResult = await reconstruct(semanticAuthority, closedState, closedEntries)
  t.is(closedResult.inboxState.requestResults.size, 1)
  const closedInbox = closedResult.inboxState.inboxes.values().next().value
  t.is(closedInbox.objectState, 2)
  t.is(closedInbox.tombstoneReason, 1)
  t.is(closedResult.inboxState.retryPins.values().next().value.retryState, 2)
})

test('expired Inbox APPEND keeps a fixed anti-replay record and exact signed ACK without a frame', async t => {
  const semanticAuthority = authority()
  const state = expiredAppendFixture()
  const entries = await entriesFor(semanticAuthority, state)
  const result = await reconstruct(semanticAuthority, state, entries)
  const expired = [...result.inboxState.spends.values()]
    .find(value => value.status === 'expired-append')
  t.ok(expired)
  t.is(result.inboxState.frames.size, 0)
  t.is(expired.expiredEpoch, 104)
  t.is(expired.expiresAtEpoch, 104)
  t.ok(expired.resultBindingBytes.byteLength > 0)
  t.is(expired.ackSignature.byteLength, 64)
  t.is(expired.resultCommitment.byteLength, 32)
  t.is(result.inboxState.accounting.controlBytes, 1536)

  const tampered = entries.map(entry => ({
    ...entry,
    key: b4a.from(entry.key),
    value: b4a.from(entry.value)
  }))
  const expiredIndex = tampered.findIndex(entry => entry.entryKind === 1 && entry.key[1] === 4)
  tampered[expiredIndex].value[tampered[expiredIndex].value.byteLength - 40] ^= 1
  await t.exception(reconstruct(semanticAuthority, state, tampered),
    /expired APPEND|signature|commitment|binding|canonical/i)
})

test('Inbox reconstruction rejects unknown, duplicate, incomplete, substituted, and misaccounted control state', async t => {
  const semanticAuthority = authority()
  const state = fixture()
  const entries = await entriesFor(semanticAuthority, state)

  const unknown = entries.map(entry => ({ ...entry, key: b4a.from(entry.key), value: b4a.from(entry.value) }))
  const inboxIndex = unknown.findIndex(entry => entry.entryKind === 4)
  unknown[inboxIndex].key[1] = 0xff
  await t.exception(reconstruct(semanticAuthority, state, unknown), /unknown Inbox control snapshot entry/)

  const duplicate = [...entries]
  duplicate.splice(1, 0, entries[0])
  await t.exception(reconstruct(semanticAuthority, state, duplicate), /strictly sorted and duplicate-free/)

  const incomplete = entries.filter(entry => !(entry.entryKind === 6 && entry.key.byteLength === 2))
  await t.exception(reconstruct(semanticAuthority, state, incomplete), /incomplete without its global record/)

  const substituted = entries.map(entry => ({ ...entry, key: b4a.from(entry.key), value: b4a.from(entry.value) }))
  const reservationIndex = substituted.findIndex(entry => entry.entryKind === 2)
  substituted[reservationIndex].key[substituted[reservationIndex].key.byteLength - 1] ^= 1
  await t.exception(reconstruct(semanticAuthority, state, substituted), /key does not match spendTag/)

  const misaccounted = entries.map(entry => ({ ...entry, key: b4a.from(entry.key), value: b4a.from(entry.value) }))
  const globalIndex = misaccounted.findIndex(entry => entry.entryKind === 6 && entry.key.byteLength === 2)
  const global = decodeCanonical(blindInboxControlGlobalSnapshotV1, misaccounted[globalIndex].value, { copyBytes: true })
  global.storedFrameBytes++
  misaccounted[globalIndex].value = encodeCanonical(blindInboxControlGlobalSnapshotV1, global)
  await t.exception(reconstruct(semanticAuthority, state, misaccounted), /storedFrameBytes accounting does not reconstruct exactly/)

  const nonInbox = entries.map(entry => ({ ...entry, key: b4a.from(entry.key), value: b4a.from(entry.value) }))
  nonInbox[0].key[0] = FAMILY.CELL
  await t.exception(reconstruct(semanticAuthority, state, nonInbox), /rejects non-Inbox snapshot entries/)
})

test('Inbox candidate and retry reconstruction reject in-flight, divergent, substituted, missing, and misbound state', async t => {
  const semanticAuthority = authority()

  const inFlight = fixture()
  for (const value of inFlight.spends.values()) {
    if (value.status === 'reserved') value.inFlight = true
  }
  await t.exception(entriesFor(semanticAuthority, inFlight), /in-flight Inbox reservations/)

  const divergent = fixture()
  divergent.commitments.values().next().value.fingerprint = '00'.repeat(32)
  await t.exception(entriesFor(semanticAuthority, divergent), /commitment index does not match reconstructed spends/)

  const wrongBucket = fixture()
  wrongBucket.inboxes.values().next().value.metadataVirtualBucket ^= 1
  await t.exception(entriesFor(semanticAuthority, wrongBucket), /metadata virtual bucket does not match/)

  const badExpiry = fixture()
  badExpiry.frames.values().next().value.expiresAtEpoch--
  await t.exception(entriesFor(semanticAuthority, badExpiry), /frame expiry does not match/)

  const missingFrame = fixture()
  missingFrame.frames.clear()
  missingFrame.accounting.storedFrameBytes = 0
  missingFrame.accounting.frameIndexBytes = 0
  await t.exception(entriesFor(semanticAuthority, missingFrame), /retry frame pin has no matching immutable frame reference/)

  const substitutedPin = fixture()
  substitutedPin.retryPins.values().next().value.entries[0].frameHash = bytes(0x7f)
  await t.exception(entriesFor(semanticAuthority, substitutedPin), /retry frame pin has no matching immutable frame reference/)

  const badSource = fixture()
  badSource.retryPins.values().next().value.sourceCommitment = bytes(0x7e)
  await t.exception(entriesFor(semanticAuthority, badSource), /retry source commitment does not match/)

  const tooSmall = authority({ maximumCandidateEntries: 1 })
  await t.exception(entriesFor(tooSmall, fixture()), /exceeds its configured entry bound/)
})
