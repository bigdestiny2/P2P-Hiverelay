// Derived from the frozen inbox-control-snapshot.test.js fixture helpers. Synthetic state, no live store.
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { FAMILY, INBOX_APPEND_RESULT, INBOX_FRAME_CLASS, OPERATION, RESULT_SIGNATURE_DOMAIN_ID, blake2b256, encodeCanonical, inboxAppendAckV1, inboxCreateCommitment, inboxPhysicalTopic, relayResultBindingV1, resultSignaturePayload } from '../index.js'
import { deriveBlindVirtualBucket } from '../../blind-daemon/virtual-bucket.js'
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
  return deriveBlindVirtualBucket(FAMILY.INBOX, physicalTopic)
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

export const populatedInboxState = terminalFixture
export function expiredInboxState () {
  // The predecessor's independently tested expired-append fixture, with its remaining
  // reservation drained to a retained terminal row. This is not a new retention rule.
  const state = expiredAppendFixture()
  const pending = [...state.spends.values()].find(s => s.status === 'reserved')
  Object.assign(pending, { status: 'terminal', remainingAttempts: 0, terminalReason: 2, terminalEpoch: 100 })
  state.accounting.stagingFrameBytes = 0
  state.accounting.reservedFrames = 0
  state.accounting.stagingByProfile.clear()
  return state
}
