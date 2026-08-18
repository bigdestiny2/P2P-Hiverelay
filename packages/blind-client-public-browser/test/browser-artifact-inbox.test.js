import fs from 'node:fs'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import test from 'brittle'
import {
  ADVERTISED_OPERATION_BITS,
  AUXILIARY_SIGNATURE_DOMAIN_ID,
  FAMILY,
  INBOX_APPEND_AUTH_MODE,
  INBOX_FRAME_CLASS,
  OPERATION,
  PRIVACY_PROFILE,
  RESULT_SIGNATURE_DOMAIN_ID,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  operationBit
} from '../../blind-protocol/registry.js'
import {
  auxiliarySignaturePayload,
  inboxAppendRequestCommitment,
  inboxReadRequestCommitment,
  persistentResultCommitment,
  resultSignaturePayload,
  serviceDescriptorHash,
  durabilityContinuityHash,
  durabilityProfileHash,
  blake2b256
} from '../../blind-protocol/hashes.js'
import {
  blindHealthResultV1,
  blindServiceDescriptorV1,
  durabilityProfileV1,
  inboxAppendV1,
  inboxReadEntriesCommitment,
  inboxReadResultV1
} from '../../blind-protocol/schemas.js'
import { decodeCanonical, encodeCanonical } from '../../blind-protocol/codec.js'
import { durabilityContinuityBindingV1 } from '../../blind-protocol/durability-schemas.js'
import {
  blindExternalCommitWitnessV1,
  inboxReadSignaturePayloadV1
} from '../../blind-protocol/result-binding.js'
import {
  createAppendInboxRequest,
  createReadInboxRequest,
  createHealthChallenge,
  DescriptorTrustStore,
  qualifyRelay,
  verifyDescriptorBytes,
  verifiedEndpointContext,
  verifyHealthResultBytes,
  verifyOperationResult
} from '../src/browser-control.js'
import { createInboxReplica } from '../../blind-client/inbox.js'
import { verifyCapabilitySignature } from '../../blind-client/capabilities.js'
import { createNodeCryptoRuntime } from '../../blind-client/runtime/node.js'

const runtime = createNodeCryptoRuntime()
const admission = Object.freeze({
  profileId: 1,
  schemeId: 1,
  parameterHash: b4a.alloc(32, 0x72),
  token: b4a.from([0x73])
})
const descriptorVector = fs.readFileSync(new URL(
  '../../blind-protocol/vectors/draft/describe/service-descriptor.bin', import.meta.url))

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
  sodium.crypto_sign_detached(
    value.signature,
    resultSignaturePayload(domainId, payloadBytes || unsigned),
    secretKey
  )
  return encodeCanonical(codec, value)
}

function signAuxiliaryValue (codec, value, domainId, secretKey) {
  value.signature = b4a.alloc(64)
  const complete = encodeCanonical(codec, value)
  const unsigned = complete.subarray(0, complete.byteLength - 64)
  sodium.crypto_sign_detached(
    value.signature,
    auxiliarySignaturePayload(domainId, unsigned),
    secretKey
  )
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

async function qualifiedReadEndpoint (seedByte, { durability = null } = {}) {
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
  const descriptorBytes = signResult(
    blindServiceDescriptorV1,
    descriptor,
    RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR,
    keys.secretKey
  )
  const descriptorHash = serviceDescriptorHash(descriptorBytes)
  const verifiedDescriptor = verifyDescriptorBytes(descriptorBytes, {
    nowEpoch: 101,
    ...supportFor(descriptor)
  })
  const trust = new DescriptorTrustStore()
  const trustedDescriptor = await trust.accept(verifiedDescriptor, { pinnedDescriptorHash: descriptorHash })
  const challenge = createHealthChallenge({
    runtime,
    trustedDescriptor,
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    requestedRoleBits: 1,
    requestedOperationBits: operationBit(FAMILY.INBOX, OPERATION.INBOX.READ),
    clientNonce: b4a.alloc(32, seedByte + 4)
  })
  const healthBytes = signResult(blindHealthResultV1, {
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
  }, RESULT_SIGNATURE_DOMAIN_ID.HEALTH_RESULT, keys.secretKey)
  const health = verifyHealthResultBytes(
    healthBytes,
    trustedDescriptor,
    challenge.request,
    { nowEpoch: 101 }
  )
  const endpoint = qualifyRelay({
    trustedDescriptor,
    health,
    nowEpoch: 101,
    familyId: FAMILY.INBOX,
    operationId: OPERATION.INBOX.READ,
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

function signedPage (fixture, request, requestCommitment, entries, nextCursor) {
  const value = {
    version: 1,
    relayBinding: relayBinding(fixture.context),
    requestNonce: request.clientNonce,
    requestCommitment,
    snapshotRevision: entries.length === 0 ? 0n : entries[entries.length - 1].appendRevision,
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
    bytes: signResult(
      inboxReadResultV1,
      value,
      RESULT_SIGNATURE_DOMAIN_ID.INBOX_READ_RESULT,
      fixture.keys.secretKey,
      payload
    )
  }
}

test('full successor exposes only APPEND and corrected READ inbox constructors', t => {
  const control = { createAppendInboxRequest, createReadInboxRequest }
  t.is(typeof control.createAppendInboxRequest, 'function')
  t.is(typeof control.createReadInboxRequest, 'function')
  for (const name of [
    'createInboxReplica',
    'createWatchInboxRequest',
    'createRenewInboxRequest',
    'createCloseInboxRequest',
    'destroyInboxWriteCapability'
  ]) t.is(control[name], undefined, name)
})

test('public APPEND constructs the exact signed opaque frame and rejects tamper', async t => {
  const relayPublicKey = b4a.alloc(32, 0x71)
  const created = await createInboxReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 401,
    frameClassBits: 0x01,
    appendAuthMode: INBOX_APPEND_AUTH_MODE.SIGNATURE_REQUIRED,
    retentionClass: 1,
    leaseClass: 1,
    admission
  })
  const frame = b4a.alloc(INBOX_FRAME_CLASS[1], 0x81)
  const append = await createAppendInboxRequest({
    runtime,
    writeCap: created.writeCap,
    frameClass: 1,
    frame,
    clientNonce: b4a.alloc(32, 0x82),
    admission
  })
  const decoded = decodeCanonical(inboxAppendV1, append.requestBytes, { copyBytes: true })
  t.alike(decoded.frame, frame)
  t.alike(append.requestCommitment, inboxAppendRequestCommitment({
    relayPublicKey,
    physicalTopic: created.readCap.physicalTopic,
    frameClass: 1,
    frameHash: decoded.frameHash,
    clientNonce: decoded.clientNonce
  }))
  t.ok(verifyCapabilitySignature(
    created.readCap.appendPublicKey,
    append.requestCommitment,
    decoded.appendSignature
  ))
  const tampered = b4a.from(frame)
  tampered[0] ^= 0xff
  t.unlike(tampered, decoded.frame)
  const tamperedCommitment = inboxAppendRequestCommitment({
    relayPublicKey,
    physicalTopic: created.readCap.physicalTopic,
    frameClass: 1,
    frameHash: blake2b256(tampered),
    clientNonce: decoded.clientNonce
  })
  t.is(verifyCapabilitySignature(
    created.readCap.appendPublicKey,
    tamperedCommitment,
    decoded.appendSignature
  ), false)
  await t.exception(createAppendInboxRequest({
    runtime,
    writeCap: { ...created.writeCap, appendPrivateKey: b4a.alloc(31, 0xff) },
    frameClass: 1,
    frame,
    admission
  }), /appendPrivateKey|private key|bytes/i)
})

test('compressed READ accepts null/present cursors and rejects entry, commitment, cursor and signature tamper', async t => {
  const fixture = await qualifiedReadEndpoint(0x31)
  const readCap = {
    relayPublicKey: fixture.keys.publicKey,
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
  t.alike(read.requestCommitment, inboxReadRequestCommitment({
    relayPublicKey: fixture.keys.publicKey,
    physicalTopic: read.request.physicalTopic,
    cursor: read.request.cursor,
    limit: read.request.limit,
    clientNonce: read.request.clientNonce
  }))
  const frame = b4a.alloc(INBOX_FRAME_CLASS[1], 0x83)
  const entries = [{
    appendRevision: 1n,
    frameHash: blake2b256(frame),
    frameClass: 1,
    frame
  }]
  const verify = resultBytes => verifyOperationResult({
    endpoint: fixture.endpoint,
    request: read.request,
    requestCommitment: read.requestCommitment,
    resultBytes
  })
  const nullCursor = signedPage(fixture, read.request, read.requestCommitment, entries, null)
  t.alike(verify(nullCursor.bytes).snapshotBytes(), nullCursor.bytes)
  const cursorPage = signedPage(
    fixture,
    read.request,
    read.requestCommitment,
    entries,
    b4a.from([0x84, 0x85])
  )
  t.alike(verify(cursorPage.bytes).snapshotBytes(), cursorPage.bytes)

  const substitutedFrame = b4a.from(frame)
  substitutedFrame[0] ^= 0xff
  t.exception(() => verify(encodeCanonical(inboxReadResultV1, {
    ...cursorPage.value,
    entries: [{ ...cursorPage.value.entries[0], frame: substitutedFrame }]
  })), /frameHash|entriesCommitment/)
  t.exception(() => verify(encodeCanonical(inboxReadResultV1, {
    ...cursorPage.value,
    entriesCommitment: b4a.alloc(32, 0x86)
  })), /entriesCommitment/)
  t.exception(() => verify(encodeCanonical(inboxReadResultV1, {
    ...cursorPage.value,
    nextCursor: b4a.from([0x87])
  })), /signature is invalid/)
  t.exception(() => verify(encodeCanonical(inboxReadResultV1, {
    ...cursorPage.value,
    signature: b4a.alloc(64, 0x88)
  })), /signature is invalid/)
})

test('profile-2 READ witness commits the full unsigned result, not its compressed relay payload', async t => {
  const witnessKeys = keyPair(0x51)
  const fixture = await qualifiedReadEndpoint(0x52, {
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
  t.unlike(fullResultCommitment, compressedPayloadCommitment)

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
    return signResult(
      inboxReadResultV1,
      witnessed,
      RESULT_SIGNATURE_DOMAIN_ID.INBOX_READ_RESULT,
      fixture.keys.secretKey,
      payload
    )
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
  t.alike(verified.snapshotBytes(), resultBytes)
  t.alike(observedCommitment, fullResultCommitment)

  const compressedWitnessBytes = signedWithWitness(externalWitness(compressedPayloadCommitment))
  t.exception(() => verifyOperationResult({
    endpoint: fixture.endpoint,
    request: read.request,
    requestCommitment: read.requestCommitment,
    resultBytes: compressedWitnessBytes,
    externalWitnessVerifier: () => true
  }), /external commit witness does not bind the attempted operation/)
})
