import fs from 'node:fs'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import test from 'brittle'
import { durabilityContinuityBindingV1 } from '@hiverelay/blind-protocol'
import { ADVERTISED_OPERATION_BITS } from '@hiverelay/blind-protocol/wire-runtime-authority'
import {
  AUXILIARY_SIGNATURE_DOMAIN_ID,
  FAMILY,
  INBOX_APPEND_AUTH_MODE,
  INBOX_FRAME_CLASS,
  INBOX_MANAGE_OPERATION,
  OPERATION,
  PRIVACY_PROFILE,
  RESULT_SIGNATURE_DOMAIN_ID,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  operationBit
} from '@hiverelay/blind-protocol/registry'
import {
  auxiliarySignaturePayload,
  blake2b256,
  durabilityContinuityHash,
  durabilityProfileHash,
  inboxAppendRequestCommitment,
  inboxCreateCommitment,
  inboxPhysicalTopic,
  inboxReadRequestCommitment,
  persistentResultCommitment,
  resultSignaturePayload,
  serviceDescriptorHash
} from '@hiverelay/blind-protocol/hashes'
import {
  blindHealthResultV1,
  blindServiceDescriptorV1,
  durabilityProfileV1,
  inboxAppendV1,
  inboxCreateV1,
  inboxManageV1,
  inboxReadEntriesCommitment,
  inboxReadResultV1,
  inboxReadV1,
  inboxWatchV1
} from '@hiverelay/blind-protocol/schemas'
import { decodeCanonical, encodeCanonical } from '@hiverelay/blind-protocol/codec'
import {
  blindExternalCommitWitnessV1,
  inboxReadSignaturePayloadV1
} from '@hiverelay/blind-protocol/result-binding'
import {
  BlindClientError,
  createAppendInboxRequest,
  createCloseInboxRequest,
  createInboxReplica,
  createReadInboxRequest,
  createRenewInboxRequest,
  createWatchInboxRequest,
  destroyInboxWriteCapability,
  verifyCapabilitySignature
} from '../index.js'
import {
  DescriptorTrustStore,
  createHealthChallenge,
  qualifyRelay,
  verifyDescriptorBytes,
  verifiedEndpointContext,
  verifyHealthResultBytes,
  verifyOperationResult
} from '../control.js'
import { createNodeCryptoRuntime } from '../runtime/node.js'

const runtime = createNodeCryptoRuntime()
const descriptorVector = fs.readFileSync(new URL(
  '../../blind-protocol/vectors/draft/describe/service-descriptor.bin', import.meta.url))
const relayPublicKey = b4a.alloc(32, 0x71)
const admission = {
  profileId: 1,
  schemeId: 1,
  parameterHash: b4a.alloc(32, 0x72),
  token: b4a.from([0x73])
}

function keyPair (seedByte) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.alloc(32, seedByte))
  return { publicKey, secretKey }
}

function signResult (codec, value, domainId, secretKey, payloadBytes = null) {
  value.signature = b4a.alloc(64)
  const complete = encodeCanonical(codec, value)
  const unsigned = complete.subarray(0, complete.byteLength - 64)
  sodium.crypto_sign_detached(value.signature,
    resultSignaturePayload(domainId, payloadBytes || unsigned), secretKey)
  return encodeCanonical(codec, value)
}

function signAuxiliaryValue (codec, value, domainId, secretKey) {
  value.signature = b4a.alloc(64)
  const complete = encodeCanonical(codec, value)
  const unsigned = complete.subarray(0, complete.byteLength - 64)
  sodium.crypto_sign_detached(value.signature,
    auxiliarySignaturePayload(domainId, unsigned), secretKey)
  return value
}

function continuityBinding (durability) {
  return {
    version: 1,
    profileId: durability.profileId,
    externalJournalId: durability.externalJournalId,
    externalWitnessPublicKey: durability.externalWitnessPublicKey,
    externalJournalReplicationClass: durability.externalJournalReplicationClass,
    externalJournalFailureGroupId: durability.externalJournalFailureGroupId,
    restoreEvidenceFeedId: durability.restoreEvidenceFeedId
  }
}

function profile2Durability (witnessPublicKey) {
  const descriptor = decodeCanonical(blindServiceDescriptorV1, descriptorVector, { copyBytes: true })
  return {
    ...descriptor.durability,
    profileId: 2,
    externalJournalId: b4a.alloc(32, 0xa1),
    externalWitnessPublicKey: b4a.from(witnessPublicKey),
    externalJournalReplicationClass: 1,
    externalJournalFailureGroupId: b4a.alloc(32, 0xa2),
    externalCheckpointAgeBand: 1,
    externalJournalTopologyUrl: b4a.from('https://evidence.example:443/external-journal.cenc'),
    externalJournalTopologyHash: b4a.alloc(32, 0xa3)
  }
}

function supportFor (descriptor) {
  return {
    supportedProtocolProfiles: descriptor.protocols.map(value => ({
      protocolId: value.protocolId,
      major: value.major,
      minimumMinor: value.minor,
      profileHash: value.profileHash
    })),
    supportedTransportProfiles: descriptor.endpoints.map(value => ({
      transportId: value.transportId,
      transportSupportBit: value.transportId === TRANSPORT_ID.HTTPS_DIRECT
        ? TRANSPORT_SUPPORT.DIRECT_HTTP
        : TRANSPORT_SUPPORT.DIRECT_NATIVE,
      transportProfileHash: value.transportProfileHash
    }))
  }
}

async function qualifiedInboxEndpoint (operationId, seedByte, { durability = null } = {}) {
  const keys = keyPair(seedByte)
  const descriptor = decodeCanonical(blindServiceDescriptorV1, descriptorVector, { copyBytes: true })
  if (durability != null) descriptor.durability = durability
  descriptor.relayPublicKey = b4a.from(keys.publicKey)
  descriptor.storeId = b4a.alloc(32, seedByte + 1)
  descriptor.descriptorNonce = b4a.alloc(32, seedByte + 2)
  descriptor.enabledOperationBits &= ADVERTISED_OPERATION_BITS
  descriptor.protocols.push({
    protocolId: FAMILY.INBOX,
    major: 1,
    minor: 0,
    featureBits: 0n,
    profileHash: b4a.alloc(32, seedByte + 3)
  })
  descriptor.endpoints[0].envelopeClassBits = 0x007e
  descriptor.durabilityProfileHash = durabilityProfileHash(
    encodeCanonical(durabilityProfileV1, descriptor.durability))
  descriptor.durabilityContinuityHash = durabilityContinuityHash(encodeCanonical(
    durabilityContinuityBindingV1, continuityBinding(descriptor.durability)))
  const descriptorBytes = signResult(blindServiceDescriptorV1, descriptor,
    RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, keys.secretKey)
  const descriptorHash = serviceDescriptorHash(descriptorBytes)
  const verifiedDescriptor = verifyDescriptorBytes(descriptorBytes, {
    nowEpoch: 101,
    ...supportFor(descriptor)
  })
  const trust = new DescriptorTrustStore()
  const trustedDescriptor = await trust.accept(verifiedDescriptor, { pinnedDescriptorHash: descriptorHash })
  const operation = operationBit(FAMILY.INBOX, operationId)
  const challenge = createHealthChallenge({
    runtime,
    trustedDescriptor,
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    requestedRoleBits: 1,
    requestedOperationBits: operation,
    clientNonce: b4a.alloc(32, seedByte + 4)
  })
  const healthValue = {
    version: 1,
    relayPublicKey: descriptor.relayPublicKey,
    storeId: descriptor.storeId,
    descriptorSequence: descriptor.descriptorSequence,
    descriptorHash,
    endpointId: challenge.request.endpointId,
    transportSupportBit: challenge.request.transportSupportBit,
    durabilityContinuityHash: descriptor.durabilityContinuityHash,
    durabilityProfileHash: descriptor.durabilityProfileHash,
    clientNonce: challenge.request.clientNonce,
    readyRoleBits: challenge.request.requestedRoleBits,
    readyOperationBits: challenge.request.requestedOperationBits,
    clockState: 1,
    effectiveEpochFloor: 100,
    integrityState: 1,
    checkpointAgeBand: 1,
    scrubAgeBand: 1,
    rebalanceState: 0,
    capacityBand: 2,
    challengeEpoch: 101,
    signature: b4a.alloc(64)
  }
  const healthBytes = signResult(blindHealthResultV1, healthValue,
    RESULT_SIGNATURE_DOMAIN_ID.HEALTH_RESULT, keys.secretKey)
  const health = verifyHealthResultBytes(healthBytes, trustedDescriptor, challenge.request, { nowEpoch: 101 })
  const endpoint = qualifyRelay({
    trustedDescriptor,
    health,
    nowEpoch: 101,
    familyId: FAMILY.INBOX,
    operationId,
    endpointId: 1,
    requiredRoleBits: 1,
    privacyProfileBit: PRIVACY_PROFILE.DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
  })
  return { keys, endpoint, context: verifiedEndpointContext(endpoint) }
}

function relayBinding (context) {
  return {
    version: 1,
    relayPublicKey: context.relayPublicKey,
    storeId: context.storeId,
    descriptorSequence: context.descriptorSequence,
    descriptorHash: context.descriptorHash,
    durabilityProfileId: context.durabilityProfileId,
    durabilityContinuityHash: context.durabilityContinuityHash,
    durabilityProfileHash: context.durabilityProfileHash,
    restoreEvidenceHeadSequence: context.restoreEvidenceHeadSequence,
    restoreEvidenceHeadHash: context.restoreEvidenceHeadHash,
    externalCommitWitness: null
  }
}

function signedInboxPage (fixture, request, requestCommitment, entries, nextCursor, snapshotRevision = null) {
  const value = {
    version: 1,
    relayBinding: relayBinding(fixture.context),
    requestNonce: request.clientNonce,
    requestCommitment,
    snapshotRevision: snapshotRevision == null
      ? (entries.length === 0 ? 0n : entries[entries.length - 1].appendRevision)
      : snapshotRevision,
    entries,
    entriesCommitment: inboxReadEntriesCommitment(entries),
    nextCursor,
    signature: b4a.alloc(64)
  }
  const payload = encodeCanonical(inboxReadSignaturePayloadV1, {
    version: value.version,
    relayBinding: value.relayBinding,
    requestNonce: value.requestNonce,
    requestCommitment: value.requestCommitment,
    snapshotRevision: value.snapshotRevision,
    entriesCommitment: value.entriesCommitment,
    nextCursor: value.nextCursor
  })
  return {
    value,
    bytes: signResult(inboxReadResultV1, value,
      RESULT_SIGNATURE_DOMAIN_ID.INBOX_READ_RESULT, fixture.keys.secretKey, payload)
  }
}

function unique (values) {
  return new Set(values.map(value => b4a.toString(value, 'hex'))).size === values.length
}

test('signed inbox creation is self-certifying, relay-bound and app-opaque', async t => {
  const created = await createInboxReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 400,
    frameClassBits: 0x05,
    appendAuthMode: INBOX_APPEND_AUTH_MODE.SIGNATURE_REQUIRED,
    retentionClass: 2,
    leaseClass: 3,
    admission
  })
  const decoded = decodeCanonical(inboxCreateV1, created.requestBytes, { copyBytes: true })
  t.alike(decoded.physicalTopic, inboxPhysicalTopic(decoded))
  t.alike(decoded.physicalTopic, created.readCap.physicalTopic)
  t.ok(unique([decoded.createPublicKey, decoded.appendPublicKey, decoded.renewPublicKey, decoded.closePublicKey, relayPublicKey]))
  const expected = inboxCreateCommitment({ relayPublicKey, ...decoded })
  t.alike(created.createCommitment, expected)
  t.ok(verifyCapabilitySignature(decoded.createPublicKey, expected, decoded.createSignature))
  t.is(created.wire.familyId, FAMILY.INBOX)
  t.is(created.wire.operationId, OPERATION.INBOX.CREATE)
  t.is(created.writeCap.appendPrivateKey.byteLength, 32)
  t.absent(decoded.app)
  t.absent(decoded.namespace)
  t.absent(decoded.author)
})

test('open and signed appends preserve exact fixed opaque frames and authorization mode', async t => {
  const signed = await createInboxReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 401,
    frameClassBits: 0x01,
    retentionClass: 1,
    leaseClass: 1,
    admission
  })
  const signedFrame = b4a.alloc(INBOX_FRAME_CLASS[1], 0x81)
  const signedAppend = await createAppendInboxRequest({
    runtime,
    writeCap: signed.writeCap,
    frameClass: 1,
    frame: signedFrame,
    admission
  })
  const signedDecoded = decodeCanonical(inboxAppendV1, signedAppend.requestBytes, { copyBytes: true })
  const signedCommitment = inboxAppendRequestCommitment({
    relayPublicKey,
    physicalTopic: signed.readCap.physicalTopic,
    frameClass: 1,
    frameHash: blake2b256(signedFrame),
    clientNonce: signedDecoded.clientNonce
  })
  t.alike(signedDecoded.frame, signedFrame)
  t.alike(signedAppend.requestCommitment, signedCommitment)
  t.ok(verifyCapabilitySignature(signed.readCap.appendPublicKey, signedCommitment, signedDecoded.appendSignature))
  await t.exception(createAppendInboxRequest({
    runtime,
    readCap: signed.readCap,
    frameClass: 1,
    frame: signedFrame,
    admission
  }), /requires its append capability/)

  const open = await createInboxReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 402,
    frameClassBits: 0x03,
    appendAuthMode: INBOX_APPEND_AUTH_MODE.OPEN_CAPABILITY,
    retentionClass: 1,
    leaseClass: 1,
    admission
  })
  t.is(open.readCap.appendPublicKey, null)
  t.is(open.writeCap.appendPrivateKey, null)
  const openFrame = b4a.alloc(INBOX_FRAME_CLASS[2], 0x82)
  const openAppend = await createAppendInboxRequest({
    runtime,
    readCap: open.readCap,
    frameClass: 2,
    frame: openFrame,
    admission
  })
  t.is(openAppend.request.appendSignature, null)
  t.alike(openAppend.request.frameHash, blake2b256(openFrame))
})

test('inbox frame bounds fail before admission or request allocation', async t => {
  const created = await createInboxReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 403,
    frameClassBits: 0x01,
    retentionClass: 1,
    leaseClass: 1,
    admission
  })
  let admissionCalls = 0
  await t.exception(createAppendInboxRequest({
    runtime,
    writeCap: created.writeCap,
    frameClass: 2,
    frame: b4a.alloc(INBOX_FRAME_CLASS[2]),
    admissionProvider: async () => { admissionCalls++; return admission }
  }), /not enabled/)
  await t.exception(createAppendInboxRequest({
    runtime,
    writeCap: created.writeCap,
    frameClass: 1,
    frame: b4a.alloc(INBOX_FRAME_CLASS[1] - 1),
    admissionProvider: async () => { admissionCalls++; return admission }
  }), /exactly 4096 bytes/)
  t.is(admissionCalls, 0)
})

test('inbox renew and close bind independent capabilities and exact CAS state', async t => {
  const created = await createInboxReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 404,
    frameClassBits: 0x01,
    retentionClass: 1,
    leaseClass: 1,
    admission
  })
  const renew = await createRenewInboxRequest({
    runtime,
    writeCap: created.writeCap,
    expectedRevision: 3n,
    expectedLeaseEpoch: 410,
    leaseClass: 2,
    admission
  })
  const renewDecoded = decodeCanonical(inboxManageV1, renew.requestBytes, { copyBytes: true })
  t.is(renewDecoded.operation, INBOX_MANAGE_OPERATION.RENEW)
  t.ok(verifyCapabilitySignature(created.request.renewPublicKey, renew.requestCommitment, renewDecoded.signature))
  t.ok(renewDecoded.admission)

  const close = createCloseInboxRequest({
    runtime,
    writeCap: created.writeCap,
    expectedRevision: 4n,
    expectedLeaseEpoch: 438
  })
  const closeDecoded = decodeCanonical(inboxManageV1, close.requestBytes, { copyBytes: true })
  t.is(closeDecoded.operation, INBOX_MANAGE_OPERATION.CLOSE)
  t.is(closeDecoded.leaseClass, 0)
  t.is(closeDecoded.admission, null)
  t.ok(verifyCapabilitySignature(created.request.closePublicKey, close.requestCommitment, closeDecoded.signature))
  t.unlike(renew.requestCommitment, close.requestCommitment)
})

test('inbox read and watch are bounded request identities, not semantic subscriptions', async t => {
  const created = await createInboxReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 405,
    frameClassBits: 0x03,
    retentionClass: 1,
    leaseClass: 1,
    admission
  })
  const cursor = b4a.from([1, 2, 3])
  const read = await createReadInboxRequest({ runtime, readCap: created.readCap, cursor, limit: 2 })
  const readDecoded = decodeCanonical(inboxReadV1, read.requestBytes, { copyBytes: true })
  t.alike(readDecoded.cursor, cursor)
  t.is(readDecoded.limit, 2)
  t.is(readDecoded.admission, null)
  t.alike(read.requestCommitment, inboxReadRequestCommitment({
    relayPublicKey,
    physicalTopic: created.readCap.physicalTopic,
    cursor,
    limit: 2,
    clientNonce: readDecoded.clientNonce
  }))
  t.ok(read.wire.expectedResultBodyBytes < 64 * 1024)

  const watch = await createWatchInboxRequest({
    runtime,
    readCap: created.readCap,
    afterRevision: 7n,
    limit: 3,
    maxWaitMillis: 30000,
    admission
  })
  const watchDecoded = decodeCanonical(inboxWatchV1, watch.requestBytes, { copyBytes: true })
  t.is(watchDecoded.afterRevision, 7n)
  t.is(watchDecoded.maxWaitMillis, 30000)
  t.is(watch.wire.operationId, OPERATION.INBOX.WATCH)
  t.unlike(read.requestCommitment, watch.requestCommitment)
  await t.exception(createWatchInboxRequest({
    runtime,
    readCap: created.readCap,
    afterRevision: 7n,
    limit: 1,
    maxWaitMillis: 30001,
    admission
  }), BlindClientError)
  await t.exception(createReadInboxRequest({
    runtime,
    readCap: created.readCap,
    cursor: b4a.alloc(129),
    limit: 1
  }), /cursor exceeds/)
})

test('inbox READ and WATCH verify only the normative compressed signature payload', async t => {
  const readFixture = await qualifiedInboxEndpoint(OPERATION.INBOX.READ, 0x31)
  const readCap = {
    relayPublicKey: readFixture.keys.publicKey,
    physicalTopic: b4a.alloc(32, 0x81),
    frameClassBits: 1,
    appendAuthMode: INBOX_APPEND_AUTH_MODE.OPEN_CAPABILITY,
    appendPublicKey: null
  }
  const read = await createReadInboxRequest({
    runtime,
    readCap,
    limit: 1,
    clientNonce: b4a.alloc(32, 0x82)
  })
  const frame = b4a.alloc(INBOX_FRAME_CLASS[1], 0x83)
  const entries = [{
    appendRevision: 1n,
    frameHash: blake2b256(frame),
    frameClass: 1,
    frame
  }]
  const nullCursor = signedInboxPage(readFixture, read.request, read.requestCommitment, entries, null)
  const verifyRead = resultBytes => verifyOperationResult({
    endpoint: readFixture.endpoint,
    request: read.request,
    requestCommitment: read.requestCommitment,
    resultBytes
  })
  t.alike(verifyRead(nullCursor.bytes).snapshotBytes(), nullCursor.bytes,
    'READ accepts the signed null-cursor compressed payload')

  const cursor = b4a.from([0x84, 0x85])
  const cursorPage = signedInboxPage(readFixture, read.request, read.requestCommitment, entries, cursor)
  t.alike(verifyRead(cursorPage.bytes).snapshotBytes(), cursorPage.bytes,
    'READ accepts the signed cursor-bearing compressed payload')

  const substitutedFrame = b4a.from(frame)
  substitutedFrame[0] ^= 0xff
  t.exception(() => verifyRead(encodeCanonical(inboxReadResultV1, {
    ...cursorPage.value,
    entries: [{
      ...cursorPage.value.entries[0],
      frame: substitutedFrame,
      frameHash: blake2b256(substitutedFrame)
    }]
  })), /entriesCommitment/, 'raw entry substitution fails before signature acceptance')
  t.exception(() => verifyRead(encodeCanonical(inboxReadResultV1, {
    ...cursorPage.value,
    entriesCommitment: b4a.alloc(32, 0x86)
  })), /entriesCommitment/, 'entries commitment substitution is rejected')
  t.exception(() => verifyRead(encodeCanonical(inboxReadResultV1, {
    ...cursorPage.value,
    nextCursor: b4a.from([0x87])
  })), /signature is invalid/, 'cursor substitution is rejected')
  t.exception(() => verifyRead(encodeCanonical(inboxReadResultV1, {
    ...cursorPage.value,
    signature: b4a.alloc(64, 0x88)
  })), /signature is invalid/, 'detached signature substitution is rejected')

  const legacy = { ...cursorPage.value, signature: b4a.alloc(64) }
  const legacyBytes = signResult(inboxReadResultV1, legacy,
    RESULT_SIGNATURE_DOMAIN_ID.INBOX_READ_RESULT, readFixture.keys.secretKey)
  t.exception(() => verifyRead(legacyBytes), /signature is invalid/,
    'the obsolete full-result signature is rejected')

  const watchFixture = await qualifiedInboxEndpoint(OPERATION.INBOX.WATCH, 0x41)
  const watchCap = { ...readCap, relayPublicKey: watchFixture.keys.publicKey, physicalTopic: b4a.alloc(32, 0x89) }
  const watch = await createWatchInboxRequest({
    runtime,
    readCap: watchCap,
    afterRevision: 7n,
    limit: 1,
    maxWaitMillis: 25,
    clientNonce: b4a.alloc(32, 0x8a),
    admission
  })
  const watchPage = signedInboxPage(watchFixture, watch.request, watch.requestCommitment, [], null, 7n)
  const verifiedWatch = verifyOperationResult({
    endpoint: watchFixture.endpoint,
    request: watch.request,
    requestCommitment: watch.requestCommitment,
    resultBytes: watchPage.bytes
  })
  t.alike(verifiedWatch.snapshotBytes(), watchPage.bytes,
    'WATCH uses the same compressed result-signature contract as READ')
})

test('profile-2 inbox witness commits the full unsigned result, not the compressed signature payload', async t => {
  const witnessKeys = keyPair(0x51)
  const fixture = await qualifiedInboxEndpoint(OPERATION.INBOX.READ, 0x52, {
    durability: profile2Durability(witnessKeys.publicKey)
  })
  const readCap = {
    relayPublicKey: fixture.keys.publicKey,
    physicalTopic: b4a.alloc(32, 0x91),
    frameClassBits: 1,
    appendAuthMode: INBOX_APPEND_AUTH_MODE.OPEN_CAPABILITY,
    appendPublicKey: null
  }
  const read = await createReadInboxRequest({
    runtime,
    readCap,
    limit: 1,
    clientNonce: b4a.alloc(32, 0x92),
    admission
  })
  const frame = b4a.alloc(INBOX_FRAME_CLASS[1], 0x93)
  const entries = [{
    appendRevision: 1n,
    frameHash: blake2b256(frame),
    frameClass: 1,
    frame
  }]
  const value = {
    version: 1,
    relayBinding: relayBinding(fixture.context),
    requestNonce: read.request.clientNonce,
    requestCommitment: read.requestCommitment,
    snapshotRevision: 1n,
    entries,
    entriesCommitment: inboxReadEntriesCommitment(entries),
    nextCursor: b4a.from([0x94]),
    signature: b4a.alloc(64)
  }
  const withoutWitness = encodeCanonical(inboxReadResultV1, value)
  const fullUnsigned = withoutWitness.subarray(0, withoutWitness.byteLength - 64)
  const fullResultCommitment = persistentResultCommitment(
    FAMILY.INBOX,
    OPERATION.INBOX.READ,
    fullUnsigned
  )
  const compressedPayload = encodeCanonical(inboxReadSignaturePayloadV1, {
    version: value.version,
    relayBinding: value.relayBinding,
    requestNonce: value.requestNonce,
    requestCommitment: value.requestCommitment,
    snapshotRevision: value.snapshotRevision,
    entriesCommitment: value.entriesCommitment,
    nextCursor: value.nextCursor
  })
  const compressedPayloadCommitment = persistentResultCommitment(
    FAMILY.INBOX,
    OPERATION.INBOX.READ,
    compressedPayload
  )
  t.unlike(fullResultCommitment, compressedPayloadCommitment,
    'the full persistent result and compressed relay-signature payload are distinct witness inputs')

  const externalWitness = resultCommitment => signAuxiliaryValue(blindExternalCommitWitnessV1, {
    version: 1,
    relayPublicKey: fixture.keys.publicKey,
    storeId: fixture.context.storeId,
    externalJournalId: fixture.context.externalJournalId,
    durabilityContinuityHash: fixture.context.durabilityContinuityHash,
    durabilityProfileHash: fixture.context.durabilityProfileHash,
    restoreEvidenceHeadSequence: fixture.context.restoreEvidenceHeadSequence,
    restoreEvidenceHeadHash: fixture.context.restoreEvidenceHeadHash,
    familyId: FAMILY.INBOX,
    operationId: OPERATION.INBOX.READ,
    requestCommitment: read.requestCommitment,
    resultCommitment,
    commitWalSequence: 10n,
    commitWalHash: b4a.alloc(32, 0x95),
    coveringFloorRevision: 1n,
    coveringFloorHash: b4a.alloc(32, 0x96),
    coveringFloorWalSequence: 11n,
    coveringFloorWalHash: b4a.alloc(32, 0x97),
    writerEpoch: 1n,
    writerFenceTokenHash: b4a.alloc(32, 0x98),
    externalLeaseRevision: 1n,
    witnessedUnixMillis: 1n,
    witnessPublicKey: witnessKeys.publicKey,
    signature: b4a.alloc(64)
  }, AUXILIARY_SIGNATURE_DOMAIN_ID.EXTERNAL_COMMIT_WITNESS, witnessKeys.secretKey)

  const signedWithWitness = witness => {
    const witnessed = {
      ...value,
      relayBinding: { ...value.relayBinding, externalCommitWitness: witness },
      signature: b4a.alloc(64)
    }
    const payload = encodeCanonical(inboxReadSignaturePayloadV1, {
      version: witnessed.version,
      relayBinding: witnessed.relayBinding,
      requestNonce: witnessed.requestNonce,
      requestCommitment: witnessed.requestCommitment,
      snapshotRevision: witnessed.snapshotRevision,
      entriesCommitment: witnessed.entriesCommitment,
      nextCursor: witnessed.nextCursor
    })
    return signResult(inboxReadResultV1, witnessed,
      RESULT_SIGNATURE_DOMAIN_ID.INBOX_READ_RESULT, fixture.keys.secretKey, payload)
  }

  const resultBytes = signedWithWitness(externalWitness(fullResultCommitment))
  let observedCommitment = null
  const verified = verifyOperationResult({
    endpoint: fixture.endpoint,
    request: read.request,
    requestCommitment: read.requestCommitment,
    resultBytes,
    externalWitnessVerifier: ({ resultCommitment }) => {
      observedCommitment = b4a.from(resultCommitment)
      return b4a.equals(resultCommitment, fullResultCommitment)
    }
  })
  t.alike(verified.snapshotBytes(), resultBytes,
    'profile-2 READ accepts a witness over the full unsigned no-witness result')
  t.alike(observedCommitment, fullResultCommitment,
    'the external policy receives the full persistent-result commitment')

  const compressedWitnessBytes = signedWithWitness(externalWitness(compressedPayloadCommitment))
  t.exception(() => verifyOperationResult({
    endpoint: fixture.endpoint,
    request: read.request,
    requestCommitment: read.requestCommitment,
    resultBytes: compressedWitnessBytes,
    externalWitnessVerifier: () => true
  }), /external commit witness does not bind the attempted operation/,
  'a valid witness signature over the compressed payload commitment is rejected')
})

test('destroying an inbox write capability wipes every secret without mutating its read capability', async t => {
  const created = await createInboxReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 406,
    frameClassBits: 0x01,
    retentionClass: 1,
    leaseClass: 1,
    admission
  })
  const topic = b4a.from(created.readCap.physicalTopic)
  destroyInboxWriteCapability(created.writeCap)
  t.alike(created.writeCap.createPrivateKey, b4a.alloc(32))
  t.alike(created.writeCap.appendPrivateKey, b4a.alloc(32))
  t.alike(created.writeCap.renewPrivateKey, b4a.alloc(32))
  t.alike(created.writeCap.closePrivateKey, b4a.alloc(32))
  t.alike(created.readCap.physicalTopic, topic)
})
