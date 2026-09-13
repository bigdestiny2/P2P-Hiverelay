// Test-only helper extraction from inbox-storage-engine-checkpoint-v1.test.js.
// Real persisted engine transitions; synthetic upstream payloads do not qualify Hypercore cryptography.
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { INBOX_APPEND_AUTH_MODE, INBOX_APPEND_RESULT, RESULT_SIGNATURE_DOMAIN_ID, blake2b256, decodeCanonical, encodeCanonical, inboxAppendAckV1, inboxAppendRequestCommitment, inboxCreateCommitment, inboxCreateRequestCommitment, inboxPhysicalTopic, inboxReadRequestCommitment, relayResultBindingV1, resultSignaturePayload } from '@hiverelay/blind-protocol'

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

export { clock, binding, engineOptions, createFixture, appendFixture, readFixture, appendAndFinalize }
