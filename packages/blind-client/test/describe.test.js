import fs from 'node:fs'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import test from 'brittle'
import {
  AUXILIARY_SIGNATURE_DOMAIN_ID,
  FAMILY,
  FRAME_KIND,
  OPERATION,
  PRIVACY_PROFILE,
  PROTOCOL,
  RESULT_SIGNATURE_DOMAIN_ID,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  admissionParametersHash,
  auxiliarySignaturePayload,
  blake2b256,
  blindHealthChallengeV1,
  blindHealthResultV1,
  blindExternalCommitWitnessV1,
  blindReceiptV1,
  blindServiceDescriptorV1,
  decodeCanonical,
  decodeOuterEnvelope,
  durabilityContinuityBindingV1,
  durabilityContinuityHash,
  durabilityProfileHash,
  durabilityProfileV1,
  encodeCanonical,
  encodeDispatchFrame,
  encodeOuterEnvelope,
  operationBit,
  persistentResultCommitment,
  relayIdentityTransitionV1,
  resultSignaturePayload,
  serviceDescriptorHash
} from '@hiverelay/blind-protocol'
import {
  admissionParametersV1,
  blindDescribeGetV1
} from '@hiverelay/blind-protocol/schemas'
import {
  BlindDescriptorBootstrapHttpClient,
  BlindDirectHttpClient,
  BlindRelayQualifier,
  DescriptorTrustStore,
  DurableAttempt,
  DurabilityTracker,
  EncryptedIntentStore,
  INTENT_STATE,
  MemoryIntentBackend,
  RelayCandidatePool,
  createCellReplica,
  createAesGcmIntentSealer,
  createClientIntent,
  createHealthChallenge,
  qualifyDescribeControlEndpoint,
  qualifyRelay,
  journalSignedIntent,
  trustedAdmissionProfile,
  trustedDescriptorValidity,
  verifyAdmissionParametersBytes,
  verifyDescriptorBytes,
  verifiedDescriptorLinkage,
  verifiedAdmissionParametersValidity,
  verifyHealthResultBytes,
  verifiedHealthValidity,
  verifyOperationResult,
  verifiedEndpointContext
} from '../control.js'
import { createNodeCryptoRuntime } from '../runtime/node.js'

const runtime = createNodeCryptoRuntime()
const descriptorVector = fs.readFileSync(new URL(
  '../../blind-protocol/vectors/draft/describe/service-descriptor.bin', import.meta.url))
const admissionVector = fs.readFileSync(new URL(
  '../../blind-protocol/vectors/draft/describe/admission-parameters.bin', import.meta.url))

function keyPair (seedByte) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.alloc(32, seedByte))
  return { publicKey, secretKey }
}

function signedValue (encoding, value, domainId, secretKey) {
  value.signature = b4a.alloc(64)
  const complete = encodeCanonical(encoding, value)
  const unsigned = complete.subarray(0, complete.byteLength - 64)
  sodium.crypto_sign_detached(value.signature, resultSignaturePayload(domainId, unsigned), secretKey)
  return encodeCanonical(encoding, value)
}

function signAuxiliaryValue (encoding, value, domainId, secretKey) {
  value.signature = b4a.alloc(64)
  const complete = encodeCanonical(encoding, value)
  const unsigned = complete.subarray(0, complete.byteLength - 64)
  sodium.crypto_sign_detached(value.signature, auxiliarySignaturePayload(domainId, unsigned), secretKey)
  return value
}

function signedIdentityTransition (oldKeys, newKeys, oldIdentitySequence) {
  const value = {
    version: 1,
    oldRelayKey: b4a.from(oldKeys.publicKey),
    newRelayKey: b4a.from(newKeys.publicKey),
    oldIdentitySequence,
    newIdentitySequence: oldIdentitySequence + 1n,
    validFromEpoch: 101,
    reasonCode: 1,
    transitionNonce: b4a.alloc(32, 0x81),
    oldSignature: b4a.alloc(64),
    newSignature: b4a.alloc(64)
  }
  const complete = encodeCanonical(relayIdentityTransitionV1, value)
  const unsigned = complete.subarray(0, complete.byteLength - 128)
  const payload = auxiliarySignaturePayload(AUXILIARY_SIGNATURE_DOMAIN_ID.IDENTITY_TRANSITION, unsigned)
  sodium.crypto_sign_detached(value.oldSignature, payload, oldKeys.secretKey)
  sodium.crypto_sign_detached(value.newSignature, payload, newKeys.secretKey)
  return value
}

function signedAdmission (keys) {
  const value = decodeCanonical(admissionParametersV1, admissionVector, { copyBytes: true })
  value.relayPublicKey = b4a.from(keys.publicKey)
  value.profileId = 7
  value.schemeId = 9
  value.roleBits = 1
  value.validFromEpoch = 100
  value.expiresEpoch = 104
  const bytes = signedValue(admissionParametersV1, value,
    RESULT_SIGNATURE_DOMAIN_ID.ADMISSION_PARAMETERS, keys.secretKey)
  return { bytes, value, hash: admissionParametersHash(bytes) }
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

function signedDescriptor (keys, admission, changes = {}) {
  const value = decodeCanonical(blindServiceDescriptorV1, descriptorVector, { copyBytes: true })
  value.relayPublicKey = b4a.from(keys.publicKey)
  value.protocols.push({
    protocolId: FAMILY.CELL,
    major: 1,
    minor: 0,
    featureBits: 0n,
    profileHash: b4a.alloc(32, 0x27)
  })
  value.admissionProfiles[0].parameterHash = b4a.from(admission.hash)
  value.endpoints[0].envelopeClassBits = 0x007e
  Object.assign(value, changes)
  value.durabilityProfileHash = durabilityProfileHash(encodeCanonical(durabilityProfileV1, value.durability))
  value.durabilityContinuityHash = durabilityContinuityHash(encodeCanonical(
    durabilityContinuityBindingV1, continuityBinding(value.durability)))
  const bytes = signedValue(blindServiceDescriptorV1, value,
    RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, keys.secretKey)
  return { bytes, value, hash: serviceDescriptorHash(bytes) }
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

function signedHealth (keys, descriptor, descriptorHash, challenge, overrides = {}) {
  const value = {
    version: 1,
    relayPublicKey: descriptor.relayPublicKey,
    storeId: descriptor.storeId,
    descriptorSequence: descriptor.descriptorSequence,
    descriptorHash,
    endpointId: challenge.endpointId,
    transportSupportBit: challenge.transportSupportBit,
    durabilityContinuityHash: descriptor.durabilityContinuityHash,
    durabilityProfileHash: descriptor.durabilityProfileHash,
    clientNonce: challenge.clientNonce,
    readyRoleBits: challenge.requestedRoleBits,
    readyOperationBits: challenge.requestedOperationBits,
    clockState: 1,
    effectiveEpochFloor: 100,
    integrityState: 1,
    checkpointAgeBand: 1,
    scrubAgeBand: 1,
    rebalanceState: 0,
    capacityBand: 2,
    challengeEpoch: 101,
    ...overrides,
    signature: b4a.alloc(64)
  }
  return signedValue(blindHealthResultV1, value,
    RESULT_SIGNATURE_DOMAIN_ID.HEALTH_RESULT, keys.secretKey)
}

async function trustedFixture (seedByte = 0x31, descriptorChanges = {}) {
  const keys = keyPair(seedByte)
  const admission = signedAdmission(keys)
  const descriptor = signedDescriptor(keys, admission, {
    storeId: b4a.alloc(32, (seedByte + 1) & 0xff),
    descriptorNonce: b4a.alloc(32, (seedByte + 2) & 0xff),
    ...descriptorChanges
  })
  const verified = verifyDescriptorBytes(descriptor.bytes, {
    nowEpoch: 101,
    ...supportFor(descriptor.value)
  })
  const trust = new DescriptorTrustStore()
  const trusted = await trust.accept(verified, { pinnedDescriptorHash: descriptor.hash })
  return { keys, admission, descriptor, verified, trust, trusted }
}

async function qualifiedCellEndpoint (seedByte, descriptorChanges = {}) {
  const fixture = await trustedFixture(seedByte, descriptorChanges)
  const operation = operationBit(FAMILY.CELL, OPERATION.CELL.PUT)
  const challenge = createHealthChallenge({
    runtime,
    trustedDescriptor: fixture.trusted,
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    requestedRoleBits: 1,
    requestedOperationBits: operation,
    clientNonce: b4a.alloc(32, seedByte)
  })
  const health = verifyHealthResultBytes(signedHealth(fixture.keys, fixture.descriptor.value,
    fixture.descriptor.hash, challenge.request), fixture.trusted, challenge.request, { nowEpoch: 101 })
  return {
    ...fixture,
    endpoint: qualifyRelay({
      trustedDescriptor: fixture.trusted,
      health,
      nowEpoch: 101,
      familyId: FAMILY.CELL,
      operationId: OPERATION.CELL.PUT,
      endpointId: 1,
      requiredRoleBits: 1,
      privacyProfileBit: PRIVACY_PROFILE.DIRECT,
      transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
    })
  }
}

test('descriptor verification binds canonical bytes, durability hashes, signature and authenticated genesis pin', async t => {
  const fixture = await trustedFixture()
  t.alike(fixture.verified.descriptorHash, fixture.descriptor.hash)
  t.is(fixture.verified.descriptorSequence, 0n)
  t.alike(fixture.trusted.rootRelayPublicKey, fixture.keys.publicKey)

  const changedCopy = fixture.verified.snapshotBytes()
  changedCopy.fill(0)
  t.alike(fixture.verified.descriptorHash, fixture.descriptor.hash)

  const missingMinimum = supportFor(fixture.descriptor.value)
  delete missingMinimum.supportedProtocolProfiles[0].minimumMinor
  t.exception(() => verifyDescriptorBytes(fixture.descriptor.bytes, {
    nowEpoch: 101,
    ...missingMinimum
  }), /minimumMinor/)

  const unpinned = verifyDescriptorBytes(fixture.descriptor.bytes, {
    nowEpoch: 101,
    ...supportFor(fixture.descriptor.value)
  })
  await t.exception(new DescriptorTrustStore().accept(unpinned), /authenticated pin/)

  const tampered = b4a.from(fixture.descriptor.bytes)
  tampered[tampered.byteLength - 1] ^= 1
  t.exception(() => verifyDescriptorBytes(tampered, {
    nowEpoch: 101,
    ...supportFor(fixture.descriptor.value)
  }), /signature is invalid/)
})

test('hash-pinned bootstrap fetch returns only a verified descriptor', async t => {
  const fixture = await trustedFixture(0x32)
  let observed
  const client = new BlindDescriptorBootstrapHttpClient({
    runtime,
    fetch: async (url, init) => {
      observed = { url, init }
      const request = decodeOuterEnvelope(init.body, { copyBody: true })
      const response = encodeOuterEnvelope({
        outerClass: request.outerClass,
        innerDispatch: encodeDispatchFrame({
          frameKind: FRAME_KIND.RESPONSE,
          familyId: FAMILY.DESCRIBE,
          operationId: OPERATION.DESCRIBE.GET,
          requestId: request.frame.requestId,
          body: fixture.descriptor.bytes
        })
      })
      return new Response(response, {
        status: 200,
        headers: new Headers([
          ['content-type', PROTOCOL.mediaType],
          ['content-length', String(response.byteLength)]
        ])
      })
    }
  })
  const verified = await client.fetchVerifiedDescriptor({
    canonicalUrl: fixture.descriptor.value.endpoints[0].canonicalUrl,
    expectedDescriptorHash: fixture.descriptor.hash,
    nowEpoch: 101,
    ...supportFor(fixture.descriptor.value)
  })
  t.alike(verified.descriptorHash, fixture.descriptor.hash)
  t.is(observed.url, 'https://relay.example/api/blind/v1/describe')
  t.alike(observed.init.headers, [['content-type', PROTOCOL.mediaType]])
  t.absent(observed.init.headers.find(([name]) => name === 'authorization'))

  await t.exception(client.fetchVerifiedDescriptor({
    canonicalUrl: fixture.descriptor.value.endpoints[0].canonicalUrl,
    nowEpoch: 101,
    ...supportFor(fixture.descriptor.value)
  }), /expectedDescriptorHash/)
})

test('current-head bootstrap is signed/profile-verified and exposes only branded linkage', async t => {
  const fixture = await trustedFixture(0x33)
  let requestedHash = 'unset'
  const client = new BlindDescriptorBootstrapHttpClient({
    runtime,
    fetch: async (_url, init) => {
      const request = decodeOuterEnvelope(init.body, { copyBody: true })
      const decodedRequest = decodeCanonical(blindDescribeGetV1, request.frame.body, { copyBytes: true })
      requestedHash = decodedRequest.descriptorHash
      const response = encodeOuterEnvelope({
        outerClass: request.outerClass,
        innerDispatch: encodeDispatchFrame({
          frameKind: FRAME_KIND.RESPONSE,
          familyId: FAMILY.DESCRIBE,
          operationId: OPERATION.DESCRIBE.GET,
          requestId: request.frame.requestId,
          body: fixture.descriptor.bytes
        })
      })
      return new Response(response, {
        status: 200,
        headers: new Headers([
          ['content-type', PROTOCOL.mediaType],
          ['content-length', String(response.byteLength)]
        ])
      })
    }
  })
  const verified = await client.fetchVerifiedDescriptorHead({
    canonicalUrl: fixture.descriptor.value.endpoints[0].canonicalUrl,
    nowEpoch: 101,
    ...supportFor(fixture.descriptor.value)
  })
  t.is(requestedHash, null)
  const linkage = verifiedDescriptorLinkage(verified)
  t.alike(linkage.descriptorHash, fixture.descriptor.hash)
  t.is(linkage.descriptorSequence, 0n)
  t.is(linkage.previousDescriptorHash, null)
  t.alike(linkage.relayPublicKey, fixture.keys.publicKey)
  t.alike(linkage.storeId, fixture.descriptor.value.storeId)
  linkage.descriptorHash.fill(0)
  t.alike(verified.descriptorHash, fixture.descriptor.hash)
  t.exception(() => verifiedDescriptorLinkage({}), /VerifiedDescriptor/)
  await t.exception(client.fetchVerifiedDescriptorHead({
    canonicalUrl: fixture.descriptor.value.endpoints[0].canonicalUrl,
    nowEpoch: 101,
    history: true,
    ...supportFor(fixture.descriptor.value)
  }), /cannot be a history read/)
})

test('descriptor trust advances exact sequence/hash and quarantines a same-sequence fork', async t => {
  const fixture = await trustedFixture()
  const next = signedDescriptor(fixture.keys, fixture.admission, {
    storeId: fixture.descriptor.value.storeId,
    descriptorSequence: 1n,
    previousDescriptorHash: fixture.descriptor.hash,
    descriptorNonce: b4a.alloc(32, 0x73)
  })
  const verifiedNext = verifyDescriptorBytes(next.bytes, { nowEpoch: 101, ...supportFor(next.value) })
  const continuation = { continuityRootRelayPublicKey: fixture.trusted.rootRelayPublicKey }
  const trustedNext = await fixture.trust.accept(verifiedNext, continuation)
  t.is(trustedNext.descriptorSequence, 1n)

  const fork = signedDescriptor(fixture.keys, fixture.admission, {
    storeId: fixture.descriptor.value.storeId,
    descriptorSequence: 1n,
    previousDescriptorHash: fixture.descriptor.hash,
    descriptorNonce: b4a.alloc(32, 0x74)
  })
  const verifiedFork = verifyDescriptorBytes(fork.bytes, { nowEpoch: 101, ...supportFor(fork.value) })
  await t.exception(fixture.trust.accept(verifiedFork, continuation), /fork detected/)
  await t.exception(fixture.trust.accept(verifiedNext, continuation), /quarantined/)
})

test('relay-chosen store IDs cannot collision-quarantine another continuity root', async t => {
  const storeId = b4a.alloc(32, 0x7a)
  const keysA = keyPair(0x3a)
  const keysB = keyPair(0x3b)
  const admissionA = signedAdmission(keysA)
  const admissionB = signedAdmission(keysB)
  const descriptorA = signedDescriptor(keysA, admissionA, {
    storeId,
    descriptorNonce: b4a.alloc(32, 0x7b)
  })
  const descriptorB = signedDescriptor(keysB, admissionB, {
    storeId,
    descriptorNonce: b4a.alloc(32, 0x7c)
  })
  const verifiedA = verifyDescriptorBytes(descriptorA.bytes, {
    nowEpoch: 101,
    ...supportFor(descriptorA.value)
  })
  const verifiedB = verifyDescriptorBytes(descriptorB.bytes, {
    nowEpoch: 101,
    ...supportFor(descriptorB.value)
  })
  const trust = new DescriptorTrustStore()
  const trustedA = await trust.accept(verifiedA, { pinnedDescriptorHash: descriptorA.hash })
  const trustedB = await trust.accept(verifiedB, { pinnedDescriptorHash: descriptorB.hash })
  t.alike(trustedA.rootRelayPublicKey, keysA.publicKey)
  t.alike(trustedB.rootRelayPublicKey, keysB.publicKey)

  const nextA = signedDescriptor(keysA, admissionA, {
    storeId,
    descriptorSequence: 1n,
    previousDescriptorHash: descriptorA.hash,
    descriptorNonce: b4a.alloc(32, 0x7d)
  })
  const verifiedNextA = verifyDescriptorBytes(nextA.bytes, {
    nowEpoch: 101,
    ...supportFor(nextA.value)
  })
  await t.exception(trust.accept(verifiedNextA), /persisted continuity root/)
  const continuedA = await trust.accept(verifiedNextA, {
    continuityRootRelayPublicKey: trustedA.rootRelayPublicKey
  })
  t.is(continuedA.descriptorSequence, 1n)
})

test('descriptor trust accepts only an exact dual-signed relay identity rotation', async t => {
  const fixture = await trustedFixture(0x34)
  const nextKeys = keyPair(0x35)
  const transition = signedIdentityTransition(
    fixture.keys,
    nextKeys,
    fixture.descriptor.value.identitySequence
  )
  const nextChanges = {
    storeId: fixture.descriptor.value.storeId,
    descriptorSequence: 1n,
    previousDescriptorHash: fixture.descriptor.hash,
    identitySequence: 1n,
    previousRelayKey: fixture.keys.publicKey,
    issuedEpoch: 101,
    expiresEpoch: 105,
    descriptorNonce: b4a.alloc(32, 0x82)
  }
  const invalid = signedDescriptor(nextKeys, fixture.admission, {
    ...nextChanges,
    identityTransition: { ...transition, oldSignature: b4a.alloc(64, 0x83) }
  })
  const invalidVerified = verifyDescriptorBytes(invalid.bytes, {
    nowEpoch: 101,
    ...supportFor(invalid.value)
  })
  const continuation = { continuityRootRelayPublicKey: fixture.trusted.rootRelayPublicKey }
  await t.exception(fixture.trust.accept(invalidVerified, continuation), /old identity transition signature is invalid/)

  const next = signedDescriptor(nextKeys, fixture.admission, {
    ...nextChanges,
    identityTransition: transition
  })
  const verified = verifyDescriptorBytes(next.bytes, { nowEpoch: 101, ...supportFor(next.value) })
  const trusted = await fixture.trust.accept(verified, continuation)
  t.is(trusted.descriptorSequence, 1n)
  t.alike(trusted.rootRelayPublicKey, fixture.keys.publicKey)
})

test('descriptor trust rejects an in-chain durability identity substitution', async t => {
  const fixture = await trustedFixture(0x36)
  const witnessKeys = keyPair(0x37)
  const changed = signedDescriptor(fixture.keys, fixture.admission, {
    storeId: fixture.descriptor.value.storeId,
    descriptorSequence: 1n,
    previousDescriptorHash: fixture.descriptor.hash,
    durability: profile2Durability(witnessKeys.publicKey),
    descriptorNonce: b4a.alloc(32, 0x84)
  })
  const verified = verifyDescriptorBytes(changed.bytes, {
    nowEpoch: 101,
    ...supportFor(changed.value)
  })
  await t.exception(fixture.trust.accept(verified, {
    continuityRootRelayPublicKey: fixture.trusted.rootRelayPublicKey
  }), /changed the trusted durability continuity/)
})

test('fresh signed health and admission parameters qualify one opaque generic endpoint', async t => {
  const fixture = await trustedFixture()
  const operation = operationBit(FAMILY.DESCRIBE, OPERATION.DESCRIBE.GET)
  const challenge = createHealthChallenge({
    runtime,
    trustedDescriptor: fixture.trusted,
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    requestedRoleBits: 1,
    requestedOperationBits: operation,
    clientNonce: b4a.alloc(32, 0x75)
  })
  const healthBytes = signedHealth(fixture.keys, fixture.descriptor.value,
    fixture.descriptor.hash, challenge.request)
  const decodedHealth = decodeCanonical(blindHealthResultV1, healthBytes, { copyBytes: true })
  t.is(challenge.request.endpointId, 1)
  t.is(challenge.request.transportSupportBit, TRANSPORT_SUPPORT.DIRECT_HTTP)
  t.is(decodedHealth.endpointId, challenge.request.endpointId)
  t.is(decodedHealth.transportSupportBit, challenge.request.transportSupportBit)
  const health = verifyHealthResultBytes(healthBytes, fixture.trusted, challenge.request, { nowEpoch: 101 })
  const descriptorValidity = trustedDescriptorValidity(fixture.trusted)
  t.alike(descriptorValidity, {
    issuedEpoch: fixture.descriptor.value.issuedEpoch,
    expiresEpoch: fixture.descriptor.value.expiresEpoch
  })
  t.is(Object.isFrozen(descriptorValidity), true)
  t.exception(() => trustedDescriptorValidity(
    Object.create(Object.getPrototypeOf(fixture.trusted))), /TrustedDescriptor/)
  const healthValidity = verifiedHealthValidity(health)
  t.is(healthValidity.expiresAtMonotonicMillis - healthValidity.verifiedAtMonotonicMillis,
    10 * 60 * 1000)
  t.is(Object.isFrozen(healthValidity), true)
  t.exception(() => verifiedHealthValidity(
    Object.create(Object.getPrototypeOf(health))), /VerifiedHealth/)
  const endpoint = qualifyRelay({
    trustedDescriptor: fixture.trusted,
    health,
    nowEpoch: 101,
    familyId: FAMILY.DESCRIBE,
    operationId: OPERATION.DESCRIBE.GET,
    endpointId: 1,
    requiredRoleBits: 1,
    privacyProfileBit: PRIVACY_PROFILE.DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
  })
  t.alike(endpoint.relayPublicKey, fixture.keys.publicKey)
  t.is(endpoint.familyId, FAMILY.DESCRIBE)

  const unrelated = await trustedFixture(0x38)
  t.exception(() => qualifyRelay({
    trustedDescriptor: unrelated.trusted,
    health,
    nowEpoch: 101,
    familyId: FAMILY.DESCRIBE,
    operationId: OPERATION.DESCRIBE.GET,
    endpointId: 1,
    requiredRoleBits: 1,
    privacyProfileBit: PRIVACY_PROFILE.DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
  }), /fresh health does not prove requested readiness/)

  const verifiedAdmission = verifyAdmissionParametersBytes(fixture.admission.bytes,
    fixture.trusted, fixture.descriptor.value.admissionProfiles[0], { nowEpoch: 101 })
  t.alike(verifiedAdmission.parameterHash, fixture.admission.hash)
  const admissionValidity = verifiedAdmissionParametersValidity(verifiedAdmission)
  t.alike(admissionValidity, {
    validFromEpoch: fixture.admission.value.validFromEpoch,
    expiresEpoch: fixture.admission.value.expiresEpoch
  })
  t.is(Object.isFrozen(admissionValidity), true)
  t.exception(() => verifiedAdmissionParametersValidity(
    Object.create(Object.getPrototypeOf(verifiedAdmission))), /VerifiedAdmissionParameters/)
  t.exception(() => verifyAdmissionParametersBytes(fixture.admission.bytes,
    fixture.trusted, fixture.descriptor.value.admissionProfiles[0],
    { nowEpoch: fixture.admission.value.expiresEpoch }), /outside their signed epoch window/)
  const advertisedAdmission = trustedAdmissionProfile(fixture.trusted, 7)
  t.alike(advertisedAdmission.parameterHash, fixture.admission.hash)
  advertisedAdmission.parameterHash[0] ^= 0xff
  t.alike(trustedAdmissionProfile(fixture.trusted, 7).parameterHash, fixture.admission.hash)
  t.is(trustedAdmissionProfile(fixture.trusted, 0xffff), null)

  const rogueAdmissionValue = {
    ...fixture.admission.value,
    profileId: 8,
    schemeId: 10,
    signature: b4a.alloc(64)
  }
  const rogueAdmissionBytes = signedValue(admissionParametersV1, rogueAdmissionValue,
    RESULT_SIGNATURE_DOMAIN_ID.ADMISSION_PARAMETERS, fixture.keys.secretKey)
  const rogueAdmissionProfile = {
    ...fixture.descriptor.value.admissionProfiles[0],
    profileId: 8,
    schemeId: 10,
    parameterHash: admissionParametersHash(rogueAdmissionBytes)
  }
  t.exception(() => verifyAdmissionParametersBytes(rogueAdmissionBytes,
    fixture.trusted, rogueAdmissionProfile, { nowEpoch: 101 }), /signed descriptor profile/)

  const boundedHealth = verifyHealthResultBytes(healthBytes,
    fixture.trusted, challenge.request, { nowEpoch: 101, observedMonotonicMillis: 1000 })
  t.exception(() => qualifyRelay({
    trustedDescriptor: fixture.trusted,
    health: boundedHealth,
    nowEpoch: 101,
    nowMonotonicMillis: 601001,
    familyId: FAMILY.DESCRIBE,
    operationId: OPERATION.DESCRIBE.GET,
    endpointId: 1,
    requiredRoleBits: 1,
    privacyProfileBit: PRIVACY_PROFILE.DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
  }), /fresh health does not prove requested readiness/)

  t.exception(() => qualifyRelay({
    trustedDescriptor: fixture.trusted,
    health,
    nowEpoch: fixture.descriptor.value.expiresEpoch,
    familyId: FAMILY.DESCRIBE,
    operationId: OPERATION.DESCRIBE.GET,
    endpointId: 1,
    requiredRoleBits: 1,
    privacyProfileBit: PRIVACY_PROFILE.DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
  }), /descriptor is expired/)

  const invalidHealth = b4a.from(healthBytes)
  invalidHealth[invalidHealth.byteLength - 1] ^= 1
  t.exception(() => verifyHealthResultBytes(invalidHealth,
    fixture.trusted, challenge.request, { nowEpoch: 101 }), /signature is invalid/)

  for (const drift of [
    { endpointId: 2 },
    { transportSupportBit: TRANSPORT_SUPPORT.DIRECT_NATIVE }
  ]) {
    const crossEndpointReplay = signedHealth(fixture.keys, fixture.descriptor.value,
      fixture.descriptor.hash, challenge.request, drift)
    t.exception(() => verifyHealthResultBytes(crossEndpointReplay,
      fixture.trusted, challenge.request, { nowEpoch: 101 }), /does not correlate/)
  }

  t.exception(() => createHealthChallenge({
    runtime,
    trustedDescriptor: fixture.trusted,
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    requestedRoleBits: 1,
    requestedOperationBits: operationBit(FAMILY.CORE, OPERATION.CORE.OPEN_REPLICATION)
  }), /unsupported by the bound endpoint transport/)
  t.exception(() => createHealthChallenge({
    runtime,
    trustedDescriptor: fixture.trusted,
    endpointId: 1,
    transportSupportBit: 0x40,
    requestedRoleBits: 1,
    requestedOperationBits: operation
  }), /not in the closed registry/)
})

test('trusted descriptor control endpoint breaks the health cycle without authorizing storage', async t => {
  const fixture = await trustedFixture(0x39)
  const requestedOperation = operationBit(FAMILY.CELL, OPERATION.CELL.PUT)
  const challenge = createHealthChallenge({
    runtime,
    trustedDescriptor: fixture.trusted,
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    requestedRoleBits: 1,
    requestedOperationBits: requestedOperation,
    clientNonce: b4a.alloc(32, 0x77)
  })
  const endpoint = qualifyDescribeControlEndpoint({
    trustedDescriptor: fixture.trusted,
    nowEpoch: 101,
    familyId: FAMILY.DESCRIBE,
    operationId: OPERATION.DESCRIBE.CHALLENGE,
    endpointId: 1,
    requiredRoleBits: 1,
    privacyProfileBit: PRIVACY_PROFILE.DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
  })
  const context = verifiedEndpointContext(endpoint)
  t.is(context.familyId, FAMILY.DESCRIBE)
  t.is(context.operationId, OPERATION.DESCRIBE.CHALLENGE)
  t.exception(() => qualifyDescribeControlEndpoint({
    trustedDescriptor: fixture.trusted,
    nowEpoch: 101,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    endpointId: 1,
    requiredRoleBits: 1,
    privacyProfileBit: PRIVACY_PROFILE.DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
  }), /only a DESCRIBE operation/)

  const direct = new BlindDirectHttpClient({
    runtime,
    fetch: async (_url, init) => {
      const request = decodeOuterEnvelope(init.body, { copyBody: true })
      const response = encodeOuterEnvelope({
        outerClass: request.outerClass,
        innerDispatch: encodeDispatchFrame({
          frameKind: FRAME_KIND.RESPONSE,
          familyId: FAMILY.DESCRIBE,
          operationId: OPERATION.DESCRIBE.CHALLENGE,
          requestId: request.frame.requestId,
          body: signedHealth(fixture.keys, fixture.descriptor.value,
            fixture.descriptor.hash, challenge.request)
        })
      })
      return new Response(response, {
        status: 200,
        headers: new Headers([
          ['content-type', PROTOCOL.mediaType],
          ['content-length', String(response.byteLength)]
        ])
      })
    }
  })
  const response = await direct.request({
    endpoint,
    familyId: FAMILY.DESCRIBE,
    operationId: OPERATION.DESCRIBE.CHALLENGE,
    expectedResultBodyBytes: 16384,
    body: challenge.requestBytes
  })
  const health = verifyHealthResultBytes(response.body,
    fixture.trusted, challenge.request, { nowEpoch: 101 })
  const storage = qualifyRelay({
    trustedDescriptor: fixture.trusted,
    health,
    nowEpoch: 101,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    endpointId: 1,
    requiredRoleBits: 1,
    privacyProfileBit: PRIVACY_PROFILE.DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
  })
  t.is(verifiedEndpointContext(storage).operationId, OPERATION.CELL.PUT)
})

test('verified health cannot replay across two otherwise valid endpoint transports', async t => {
  const base = decodeCanonical(blindServiceDescriptorV1, descriptorVector, { copyBytes: true }).endpoints[0]
  const fixture = await trustedFixture(0x3a, {
    endpoints: [
      { ...base, envelopeClassBits: 0x007e },
      {
        ...base,
        endpointId: 2,
        transportId: TRANSPORT_ID.DIRECT_PROTOMUX_NOISE,
        transportProfileHash: b4a.alloc(32, 0x7a),
        canonicalUrl: b4a.from('https://native-relay.example:443/api/blind/v1/describe')
      }
    ]
  })
  const requestedOperationBits = operationBit(FAMILY.DESCRIBE, OPERATION.DESCRIBE.GET)
  const challenge = createHealthChallenge({
    runtime,
    trustedDescriptor: fixture.trusted,
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    requestedRoleBits: 1,
    requestedOperationBits,
    clientNonce: b4a.alloc(32, 0x7b)
  })
  const health = verifyHealthResultBytes(signedHealth(fixture.keys, fixture.descriptor.value,
    fixture.descriptor.hash, challenge.request), fixture.trusted, challenge.request, { nowEpoch: 101 })
  t.exception(() => qualifyRelay({
    trustedDescriptor: fixture.trusted,
    health,
    nowEpoch: 101,
    familyId: FAMILY.DESCRIBE,
    operationId: OPERATION.DESCRIBE.GET,
    endpointId: 2,
    requiredRoleBits: 1,
    privacyProfileBit: PRIVACY_PROFILE.DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_NATIVE
  }), /fresh health does not prove requested readiness/)
})

test('generic qualifier composes pinned discovery through fresh operation readiness', async t => {
  const fixture = await trustedFixture(0x3c)
  const observedOperations = []
  const fetch = async (_url, init) => {
    const request = decodeOuterEnvelope(init.body, { copyBody: true })
    observedOperations.push(request.frame.operationId)
    let body
    if (request.frame.operationId === OPERATION.DESCRIBE.GET) {
      body = fixture.descriptor.bytes
    } else {
      const challenge = decodeCanonical(blindHealthChallengeV1, request.frame.body, { copyBytes: true })
      body = signedHealth(fixture.keys, fixture.descriptor.value,
        fixture.descriptor.hash, challenge)
    }
    const response = encodeOuterEnvelope({
      outerClass: request.outerClass,
      innerDispatch: encodeDispatchFrame({
        frameKind: FRAME_KIND.RESPONSE,
        familyId: FAMILY.DESCRIBE,
        operationId: request.frame.operationId,
        requestId: request.frame.requestId,
        body
      })
    })
    return new Response(response, {
      status: 200,
      headers: new Headers([
        ['content-type', PROTOCOL.mediaType],
        ['content-length', String(response.byteLength)]
      ])
    })
  }
  const qualifier = new BlindRelayQualifier({
    runtime,
    fetch,
    nowEpoch: () => 101,
    ...supportFor(fixture.descriptor.value)
  })
  const qualified = await qualifier.qualifyCandidate({
    canonicalUrl: fixture.descriptor.value.endpoints[0].canonicalUrl,
    expectedDescriptorHash: fixture.descriptor.hash
  }, {
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    endpointId: 1,
    requiredRoleBits: 1,
    privacyProfileBit: PRIVACY_PROFILE.DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
  })
  t.alike(observedOperations, [OPERATION.DESCRIBE.GET, OPERATION.DESCRIBE.CHALLENGE])
  t.is(verifiedEndpointContext(qualified.endpoint).operationId, OPERATION.CELL.PUT)
  t.alike(qualified.continuityRootRelayPublicKey, fixture.keys.publicKey)
})

test('ordinary direct transport accepts a VerifiedEndpoint and derives the fixed listener route', async t => {
  const fixture = await trustedFixture()
  const operation = operationBit(FAMILY.DESCRIBE, OPERATION.DESCRIBE.GET)
  const challenge = createHealthChallenge({
    runtime,
    trustedDescriptor: fixture.trusted,
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    requestedRoleBits: 1,
    requestedOperationBits: operation,
    clientNonce: b4a.alloc(32, 0x76)
  })
  const health = verifyHealthResultBytes(signedHealth(fixture.keys, fixture.descriptor.value,
    fixture.descriptor.hash, challenge.request), fixture.trusted, challenge.request, { nowEpoch: 101 })
  const endpoint = qualifyRelay({
    trustedDescriptor: fixture.trusted,
    health,
    nowEpoch: 101,
    familyId: FAMILY.DESCRIBE,
    operationId: OPERATION.DESCRIBE.GET,
    endpointId: 1,
    requiredRoleBits: 1,
    privacyProfileBit: PRIVACY_PROFILE.DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
  })
  let observedUrl
  const client = new BlindDirectHttpClient({
    runtime,
    fetch: async (url, init) => {
      observedUrl = url
      const request = decodeOuterEnvelope(init.body, { copyBody: true })
      const response = encodeOuterEnvelope({
        outerClass: request.outerClass,
        innerDispatch: encodeDispatchFrame({
          frameKind: FRAME_KIND.RESPONSE,
          familyId: FAMILY.DESCRIBE,
          operationId: OPERATION.DESCRIBE.GET,
          requestId: request.frame.requestId,
          body: fixture.descriptor.bytes
        })
      })
      return new Response(response, {
        status: 200,
        headers: new Headers([
          ['content-type', PROTOCOL.mediaType],
          ['content-length', String(response.byteLength)]
        ])
      })
    }
  })
  const response = await client.request({
    endpoint,
    familyId: FAMILY.DESCRIBE,
    operationId: OPERATION.DESCRIBE.GET,
    expectedResultBodyBytes: 16384,
    body: b4a.from([1])
  })
  t.ok(response.ok)
  t.alike(response.body, fixture.descriptor.bytes)
  t.is(observedUrl, 'https://relay.example/api/blind/v1/describe')
})

test('closed result verifier accepts one fully bound signed cell receipt and rejects correlation drift', async t => {
  const fixture = await trustedFixture()
  const operation = operationBit(FAMILY.CELL, OPERATION.CELL.PUT)
  const challenge = createHealthChallenge({
    runtime,
    trustedDescriptor: fixture.trusted,
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    requestedRoleBits: 1,
    requestedOperationBits: operation,
    clientNonce: b4a.alloc(32, 0x77)
  })
  const health = verifyHealthResultBytes(signedHealth(fixture.keys, fixture.descriptor.value,
    fixture.descriptor.hash, challenge.request), fixture.trusted, challenge.request, { nowEpoch: 101 })
  const endpoint = qualifyRelay({
    trustedDescriptor: fixture.trusted,
    health,
    nowEpoch: 101,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    endpointId: 1,
    requiredRoleBits: 1,
    privacyProfileBit: PRIVACY_PROFILE.DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
  })
  const created = await createCellReplica({
    runtime,
    relayPublicKey: fixture.keys.publicKey,
    allocationEpoch: 101,
    sizeClass: 1,
    leaseClass: 1,
    structuredContent: b4a.from('opaque result-verifier fixture'),
    admission: {
      profileId: 7,
      schemeId: 9,
      parameterHash: fixture.admission.hash,
      token: b4a.from([1])
    }
  })
  const relayBinding = {
    version: 1,
    relayPublicKey: fixture.keys.publicKey,
    storeId: fixture.descriptor.value.storeId,
    descriptorSequence: fixture.descriptor.value.descriptorSequence,
    descriptorHash: fixture.descriptor.hash,
    durabilityProfileId: 1,
    durabilityContinuityHash: fixture.descriptor.value.durabilityContinuityHash,
    durabilityProfileHash: fixture.descriptor.value.durabilityProfileHash,
    restoreEvidenceHeadSequence: 0n,
    restoreEvidenceHeadHash: b4a.alloc(32),
    externalCommitWitness: null
  }
  const receipt = {
    version: 1,
    protocol: b4a.from('hiverelay-blind-cell-v1', 'ascii'),
    relayBinding,
    slotCommitment: blake2b256(created.request.storageSlot),
    cellBlobHash: created.request.declaredBlobHash,
    allocationCommitment: created.allocationCommitment,
    requestCommitment: created.requestCommitment,
    sizeClass: created.request.sizeClass,
    allocationEpoch: created.request.allocationEpoch,
    leaseClass: created.request.leaseClass,
    leaseEpoch: 105,
    stateRevision: 0n,
    receiptEpoch: 101,
    requestNonce: created.request.clientNonce,
    result: 1,
    signature: b4a.alloc(64)
  }
  const resultBytes = signedValue(blindReceiptV1, receipt,
    RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT, fixture.keys.secretKey)
  const verified = verifyOperationResult({
    endpoint,
    request: created.request,
    requestCommitment: created.requestCommitment,
    resultBytes
  })
  t.is(verified.familyId, FAMILY.CELL)
  t.alike(verified.snapshotBytes(), resultBytes)
  t.exception(() => verifyOperationResult({
    endpoint,
    request: created.request,
    requestCommitment: b4a.alloc(32, 0x7d),
    resultBytes
  }), /canonical attempted request/)

  const endpointContext = verifiedEndpointContext(endpoint)
  const intent = createClientIntent({
    runtime,
    logicalId: b4a.alloc(32, 0x79),
    continuityRoot: endpointContext.continuityRoot,
    storeId: endpointContext.storeId,
    descriptorHash: endpointContext.descriptorHash,
    descriptorSequence: endpointContext.descriptorSequence,
    endpointId: endpointContext.endpointId,
    transportId: endpointContext.transportId,
    transportSupportBit: endpointContext.transportSupportBit,
    privacyProfileBit: endpointContext.privacyProfileBit,
    familyId: endpointContext.familyId,
    operationId: endpointContext.operationId,
    requestCommitment: created.requestCommitment,
    clientNonce: created.request.clientNonce,
    operationBytes: created.requestBytes
  })
  const intentStore = new EncryptedIntentStore({
    backend: new MemoryIntentBackend(),
    sealer: createAesGcmIntentSealer(runtime, b4a.alloc(32, 0x7a))
  })
  await journalSignedIntent(intentStore, intent, {
    ephemeralSecrets: [created.writeCap.createPrivateKey]
  })
  let sends = 0
  const attempt = new DurableAttempt({
    store: intentStore,
    transport: {
      async request (request) {
        sends++
        t.alike(request.body, created.requestBytes)
        return { ok: true, body: resultBytes }
      }
    }
  })
  const completed = await attempt.execute({ intentId: intent.intentId, endpoint })
  t.is(completed.intent.state, INTENT_STATE.RESULT_VERIFIED)
  t.is(sends, 1)
  const replayed = await attempt.execute({ intentId: intent.intentId, endpoint })
  t.is(replayed.replayed, true)
  t.is(sends, 1)

  const retryIntent = createClientIntent({
    runtime,
    intentId: b4a.alloc(32, 0x7b),
    logicalId: b4a.alloc(32, 0x7c),
    continuityRoot: endpointContext.continuityRoot,
    storeId: endpointContext.storeId,
    descriptorHash: endpointContext.descriptorHash,
    descriptorSequence: endpointContext.descriptorSequence,
    endpointId: endpointContext.endpointId,
    transportId: endpointContext.transportId,
    transportSupportBit: endpointContext.transportSupportBit,
    privacyProfileBit: endpointContext.privacyProfileBit,
    familyId: endpointContext.familyId,
    operationId: endpointContext.operationId,
    requestCommitment: created.requestCommitment,
    clientNonce: created.request.clientNonce,
    operationBytes: created.requestBytes
  })
  await intentStore.create(retryIntent)
  const retryBodies = []
  const retryAttempt = new DurableAttempt({
    store: intentStore,
    transport: {
      async request (request) {
        retryBodies.push(b4a.from(request.body))
        if (retryBodies.length === 1) throw Object.freeze(new Error('simulated response loss'))
        return { ok: true, body: resultBytes }
      }
    }
  })
  await t.exception(retryAttempt.execute({ intentId: retryIntent.intentId, endpoint }), /response loss/)
  t.is((await intentStore.read(retryIntent.intentId)).value.state, INTENT_STATE.PENDING_UNKNOWN)
  const retried = await retryAttempt.execute({ intentId: retryIntent.intentId, endpoint })
  t.is(retried.intent.attemptCount, 2)
  t.alike(retryBodies[0], retryBodies[1])

  const drift = { ...receipt, requestCommitment: b4a.alloc(32, 0x78), signature: b4a.alloc(64) }
  const driftBytes = signedValue(blindReceiptV1, drift,
    RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT, fixture.keys.secretKey)
  t.exception(() => verifyOperationResult({
    endpoint,
    request: created.request,
    requestCommitment: created.requestCommitment,
    resultBytes: driftBytes
  }), /requestCommitment/)
})

test('profile-2 result verification recomputes and verifies the independent commit witness', async t => {
  const witnessKeys = keyPair(0x42)
  const fixture = await qualifiedCellEndpoint(0x43, {
    durability: profile2Durability(witnessKeys.publicKey)
  })
  const context = verifiedEndpointContext(fixture.endpoint)
  const created = await createCellReplica({
    runtime,
    relayPublicKey: fixture.keys.publicKey,
    allocationEpoch: 101,
    sizeClass: 1,
    leaseClass: 1,
    structuredContent: b4a.from('opaque profile-2 result fixture'),
    admission: {
      profileId: 7,
      schemeId: 9,
      parameterHash: fixture.admission.hash,
      token: b4a.from([1])
    }
  })
  const relayBinding = {
    version: 1,
    relayPublicKey: fixture.keys.publicKey,
    storeId: context.storeId,
    descriptorSequence: context.descriptorSequence,
    descriptorHash: context.descriptorHash,
    durabilityProfileId: 2,
    durabilityContinuityHash: context.durabilityContinuityHash,
    durabilityProfileHash: context.durabilityProfileHash,
    restoreEvidenceHeadSequence: 0n,
    restoreEvidenceHeadHash: b4a.alloc(32),
    externalCommitWitness: null
  }
  const receipt = {
    version: 1,
    protocol: b4a.from('hiverelay-blind-cell-v1', 'ascii'),
    relayBinding,
    slotCommitment: blake2b256(created.request.storageSlot),
    cellBlobHash: created.request.declaredBlobHash,
    allocationCommitment: created.allocationCommitment,
    requestCommitment: created.requestCommitment,
    sizeClass: created.request.sizeClass,
    allocationEpoch: created.request.allocationEpoch,
    leaseClass: created.request.leaseClass,
    leaseEpoch: 105,
    stateRevision: 0n,
    receiptEpoch: 101,
    requestNonce: created.request.clientNonce,
    result: 1,
    signature: b4a.alloc(64)
  }
  const absent = encodeCanonical(blindReceiptV1, receipt)
  const resultCommitment = persistentResultCommitment(
    FAMILY.CELL,
    OPERATION.CELL.PUT,
    absent.subarray(0, absent.byteLength - 64)
  )
  const witness = signAuxiliaryValue(blindExternalCommitWitnessV1, {
    version: 1,
    relayPublicKey: fixture.keys.publicKey,
    storeId: context.storeId,
    externalJournalId: context.externalJournalId,
    durabilityContinuityHash: context.durabilityContinuityHash,
    durabilityProfileHash: context.durabilityProfileHash,
    restoreEvidenceHeadSequence: 0n,
    restoreEvidenceHeadHash: b4a.alloc(32),
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    requestCommitment: created.requestCommitment,
    resultCommitment,
    commitWalSequence: 10n,
    commitWalHash: b4a.alloc(32, 0xa4),
    coveringFloorRevision: 1n,
    coveringFloorHash: b4a.alloc(32, 0xa5),
    coveringFloorWalSequence: 11n,
    coveringFloorWalHash: b4a.alloc(32, 0xa6),
    writerEpoch: 1n,
    writerFenceTokenHash: b4a.alloc(32, 0xa7),
    externalLeaseRevision: 1n,
    witnessedUnixMillis: 1n,
    witnessPublicKey: witnessKeys.publicKey,
    signature: b4a.alloc(64)
  }, AUXILIARY_SIGNATURE_DOMAIN_ID.EXTERNAL_COMMIT_WITNESS, witnessKeys.secretKey)
  const resultBytes = signedValue(blindReceiptV1, {
    ...receipt,
    relayBinding: { ...relayBinding, externalCommitWitness: witness }
  }, RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT, fixture.keys.secretKey)
  const verified = verifyOperationResult({
    endpoint: fixture.endpoint,
    request: created.request,
    requestCommitment: created.requestCommitment,
    resultBytes,
    externalWitnessVerifier: ({ resultCommitment: observed }) => b4a.equals(observed, resultCommitment)
  })
  t.alike(verified.snapshotBytes(), resultBytes)

  const missingBytes = signedValue(blindReceiptV1, receipt,
    RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT, fixture.keys.secretKey)
  t.exception(() => verifyOperationResult({
    endpoint: fixture.endpoint,
    request: created.request,
    requestCommitment: created.requestCommitment,
    resultBytes: missingBytes,
    requireExternalWitness: false,
    externalWitnessVerifier: () => true
  }), /omitted its external commit witness/)

  const forgedWitness = { ...witness, signature: b4a.alloc(64, 0xa8) }
  const forgedBytes = signedValue(blindReceiptV1, {
    ...receipt,
    relayBinding: { ...relayBinding, externalCommitWitness: forgedWitness }
  }, RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT, fixture.keys.secretKey)
  t.exception(() => verifyOperationResult({
    endpoint: fixture.endpoint,
    request: created.request,
    requestCommitment: created.requestCommitment,
    resultBytes: forgedBytes,
    externalWitnessVerifier: () => true
  }), /external commit witness signature is invalid/)
})

test('rendezvous selection accepts one unregistered relay, deduplicates continuity and bounds repairs', async t => {
  const fixtures = await Promise.all([0x41, 0x51, 0x61, 0x71].map(qualifiedCellEndpoint))
  const pool = new RelayCandidatePool({
    selectionKey: b4a.alloc(32, 0x21),
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    privacyProfileBit: PRIVACY_PROFILE.DIRECT
  })
  for (const fixture of fixtures) pool.add(fixture.endpoint)
  pool.add(fixtures[0].endpoint)
  const logicalId = b4a.alloc(32, 0x22)
  const first = pool.select(logicalId)
  const second = pool.select(logicalId)
  t.is(first.length, 3)
  t.alike(first.map(value => value.relayPublicKey), second.map(value => value.relayPublicKey))

  const oneRelayPool = new RelayCandidatePool({
    selectionKey: b4a.alloc(32, 0x23),
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    privacyProfileBit: PRIVACY_PROFILE.DIRECT
  })
  oneRelayPool.add(fixtures[0].endpoint)
  t.is(oneRelayPool.select(logicalId).length, 1)

  const durability = new DurabilityTracker()
  const stored = durability.observe(logicalId, first[0], { acknowledged: true })
  t.is(stored.remoteStored, true)
  t.is(stored.label, 'remote-stored')
  t.is(durability.observe(logicalId, first[0]).remoteStored, true)
  const operatorGroupId = b4a.alloc(32, 0x24)
  t.is(durability.observe(logicalId, first[0], {
    readbackVerified: true,
    operatorGroupId
  }).label, 'remote-readback-verified')
  t.exception(() => durability.observe(logicalId, first[0], {
    operatorGroupId: b4a.alloc(32, 0x25)
  }), /operator-group evidence changed/)
  const repairs = durability.repairTargets(logicalId, pool)
  t.is(repairs.length, 2)
  t.absent(repairs.some(value => b4a.equals(value.relayPublicKey, first[0].relayPublicKey)))

  pool.recordFailure(first[1], 10)
  t.absent(pool.select(logicalId, { nowTick: 10 }).some(value =>
    b4a.equals(value.relayPublicKey, first[1].relayPublicKey)))
})
