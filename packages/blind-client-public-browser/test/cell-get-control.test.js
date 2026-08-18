import fs from 'node:fs'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import test from 'brittle'
import {
  ADVERTISED_OPERATION_BITS,
  AUXILIARY_SIGNATURE_DOMAIN_ID,
  FAMILY,
  FRAME_KIND,
  OPERATION,
  PRIVACY_PROFILE,
  PROTOCOL,
  RESULT_SIGNATURE_DOMAIN_ID,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT
} from '../../blind-protocol/registry.js'
import {
  auxiliarySignaturePayload,
  durabilityContinuityHash,
  durabilityProfileHash,
  resultSignaturePayload,
  serviceDescriptorHash
} from '../../blind-protocol/hashes.js'
import {
  blindDescribeGetV1,
  blindHealthChallengeV1,
  blindHealthResultV1,
  blindServiceDescriptorV1,
  durabilityProfileV1,
  getCellResultV1,
  relayIdentityTransitionV1
} from '../../blind-protocol/schemas.js'
import { durabilityContinuityBindingV1 } from '../../blind-protocol/durability-schemas.js'
import { decodeCanonical, encodeCanonical } from '../../blind-protocol/codec.js'
import { decodeOuterEnvelope, encodeOuterEnvelope } from '../../blind-protocol/outer-envelope.js'
import { encodeDispatchFrame } from '../../blind-protocol/dispatch.js'
import {
  DescriptorTrustStore,
  MemoryDescriptorTrustBackend,
  verifyDescriptorBytes
} from '../../blind-client/control.js'
import { createCellReplica } from '../../blind-client/requests.js'
import { createNodeCryptoRuntime } from '../../blind-client/runtime/node.js'
import { createBlindCellGetControl } from '../src/cell-get-control.js'

const runtime = createNodeCryptoRuntime()
const descriptorVector = fs.readFileSync(new URL(
  '../../blind-protocol/vectors/draft/describe/service-descriptor.bin', import.meta.url))
const admission = Object.freeze({
  profileId: 1,
  schemeId: 1,
  parameterHash: b4a.alloc(32, 0x72),
  token: b4a.from([0x73])
})

function keyPair (seedByte) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.alloc(32, seedByte))
  return { publicKey, secretKey }
}

function signResult (codec, value, domainId, secretKey) {
  value.signature = b4a.alloc(64)
  const complete = encodeCanonical(codec, value)
  const unsigned = complete.subarray(0, complete.byteLength - 64)
  sodium.crypto_sign_detached(value.signature, resultSignaturePayload(domainId, unsigned), secretKey)
  return encodeCanonical(codec, value)
}

function identityTransition (oldKeys, newKeys, oldIdentitySequence, validFromEpoch) {
  const value = {
    version: 1,
    oldRelayKey: b4a.from(oldKeys.publicKey),
    newRelayKey: b4a.from(newKeys.publicKey),
    oldIdentitySequence,
    newIdentitySequence: oldIdentitySequence + 1n,
    validFromEpoch,
    reasonCode: 1,
    transitionNonce: b4a.alloc(32, Number(oldIdentitySequence) + 0x90),
    oldSignature: b4a.alloc(64),
    newSignature: b4a.alloc(64)
  }
  const complete = encodeCanonical(relayIdentityTransitionV1, value)
  const unsigned = complete.subarray(0, complete.byteLength - 128)
  const payload = auxiliarySignaturePayload(
    AUXILIARY_SIGNATURE_DOMAIN_ID.IDENTITY_TRANSITION, unsigned)
  sodium.crypto_sign_detached(value.oldSignature, payload, oldKeys.secretKey)
  sodium.crypto_sign_detached(value.newSignature, payload, newKeys.secretKey)
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

function descriptor (keys, changes = {}) {
  const value = decodeCanonical(blindServiceDescriptorV1, descriptorVector, { copyBytes: true })
  value.relayPublicKey = b4a.from(keys.publicKey)
  value.storeId = b4a.alloc(32, 0x62)
  value.descriptorNonce = b4a.alloc(32, Number(changes.descriptorSequence || 0n) + 0x63)
  value.protocols.push({
    protocolId: FAMILY.CELL,
    major: 1,
    minor: 0,
    featureBits: 0n,
    profileHash: b4a.alloc(32, 0x64)
  })
  value.endpoints[0].envelopeClassBits = 0x007e
  value.enabledOperationBits &= ADVERTISED_OPERATION_BITS
  Object.assign(value, changes)
  value.durabilityProfileHash = durabilityProfileHash(
    encodeCanonical(durabilityProfileV1, value.durability))
  value.durabilityContinuityHash = durabilityContinuityHash(encodeCanonical(
    durabilityContinuityBindingV1, continuityBinding(value.durability)))
  const bytes = signResult(
    blindServiceDescriptorV1, value, RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, keys.secretKey)
  return { keys, value, bytes, hash: serviceDescriptorHash(bytes) }
}

function descriptorChain ({ length = 1, rotateAt = -1 } = {}) {
  const rootKeys = keyPair(0x31)
  const chain = []
  let keys = rootKeys
  let previous = null
  for (let index = 0; index < length; index++) {
    const nextKeys = index === rotateAt ? keyPair(0x41) : keys
    const changes = {
      descriptorSequence: BigInt(index),
      previousDescriptorHash: previous == null ? null : previous.hash,
      identitySequence: nextKeys === keys ? BigInt(index > rotateAt && rotateAt >= 0 ? 1 : 0) : 1n,
      previousRelayKey: nextKeys === keys ? null : b4a.from(keys.publicKey),
      identityTransition: nextKeys === keys
        ? null
        : identityTransition(keys, nextKeys, 0n, 100)
    }
    const current = descriptor(nextKeys, changes)
    chain.push(current)
    previous = current
    keys = nextKeys
  }
  return { rootKeys, chain, head: chain[chain.length - 1] }
}

function signedHealth (fixture, challenge) {
  return signResult(blindHealthResultV1, {
    version: 1,
    relayPublicKey: fixture.value.relayPublicKey,
    storeId: fixture.value.storeId,
    descriptorSequence: fixture.value.descriptorSequence,
    descriptorHash: fixture.hash,
    endpointId: challenge.endpointId,
    transportSupportBit: challenge.transportSupportBit,
    durabilityContinuityHash: fixture.value.durabilityContinuityHash,
    durabilityProfileHash: fixture.value.durabilityProfileHash,
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
    signature: b4a.alloc(64)
  }, RESULT_SIGNATURE_DOMAIN_ID.HEALTH_RESULT, fixture.keys.secretKey)
}

function responseFor (request, body, options = {}) {
  const response = encodeOuterEnvelope({
    outerClass: request.outerClass,
    innerDispatch: encodeDispatchFrame({
      frameKind: FRAME_KIND.RESPONSE,
      familyId: request.frame.familyId,
      operationId: request.frame.operationId,
      requestId: request.frame.requestId,
      body
    })
  })
  return new Response(response, {
    status: options.status || 200,
    headers: new Headers([
      ['content-type', options.contentType || PROTOCOL.mediaType],
      ['content-length', String(options.contentLength == null ? response.byteLength : options.contentLength)]
    ])
  })
}

async function harness (options = {}) {
  const chainFixture = options.chainFixture || descriptorChain({ length: 1 })
  const replica = await createCellReplica({
    runtime,
    relayPublicKey: chainFixture.head.value.relayPublicKey,
    allocationEpoch: 7,
    sizeClass: 1,
    leaseClass: 1,
    structuredContent: b4a.from('peerit recovery record'),
    admission
  })
  const byHash = new Map(chainFixture.chain.map(value => [b4a.toString(value.hash, 'hex'), value]))
  const trace = []
  const fetch = async (_url, init) => {
    const request = decodeOuterEnvelope(init.body, { copyBody: true })
    trace.push([request.frame.familyId, request.frame.operationId])
    if (request.frame.familyId === FAMILY.DESCRIBE &&
        request.frame.operationId === OPERATION.DESCRIBE.GET) {
      const get = decodeCanonical(blindDescribeGetV1, request.frame.body, { copyBytes: true })
      const requested = b4a.toString(get.descriptorHash, 'hex')
      const selected = options.descriptorResponse
        ? options.descriptorResponse(requested, byHash)
        : byHash.get(requested)
      if (!selected) return new Response('', { status: 404 })
      return responseFor(request, selected.bytes)
    }
    if (request.frame.familyId === FAMILY.DESCRIBE &&
        request.frame.operationId === OPERATION.DESCRIBE.CHALLENGE) {
      const challenge = decodeCanonical(
        blindHealthChallengeV1, request.frame.body, { copyBytes: true })
      return responseFor(request, signedHealth(chainFixture.head, challenge))
    }
    if (request.frame.familyId === FAMILY.CELL &&
        request.frame.operationId === OPERATION.CELL.GET) {
      return responseFor(request, encodeCanonical(getCellResultV1, {
        version: 1,
        sizeClass: replica.readCap.sizeClass,
        cellBlob: replica.request.cellBlob
      }))
    }
    throw new Error(`unexpected operation ${request.frame.familyId}/${request.frame.operationId}`)
  }
  const control = createBlindCellGetControl({
    runtime,
    fetch,
    nowEpoch: () => 101,
    monotonicMillis: () => 1,
    trustBackend: options.trustBackend,
    ...supportFor(chainFixture.head.value)
  })
  const candidate = {
    canonicalUrl: chainFixture.head.value.endpoints[0].canonicalUrl,
    expectedDescriptorHash: options.expectedDescriptorHash || chainFixture.head.hash,
    continuityRootRelayPublicKey: options.continuityRootRelayPublicKey ||
      chainFixture.rootKeys.publicKey
  }
  return { chainFixture, replica, trace, fetch, control, candidate }
}

async function qualify (fixture) {
  return fixture.control.qualifyCellGetCandidate(fixture.candidate, {
    endpointId: 1,
    requiredRoleBits: 1,
    privacyProfileBit: PRIVACY_PROFILE.DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
  })
}

test('CELL.GET control has an opaque closed returned-key surface', t => {
  const control = createBlindCellGetControl({
    runtime,
    fetch: async () => { throw new Error('unexpected transport') },
    nowEpoch: () => 1,
    monotonicMillis: () => 1,
    supportedProtocolProfiles: [{ profileId: 1, profileHash: b4a.alloc(32, 1) }],
    supportedTransportProfiles: [{ transportProfileId: 1, transportProfileHash: b4a.alloc(32, 2) }]
  })
  t.ok(Object.isFrozen(control))
  t.alike(Object.keys(control), [])
  t.alike(Object.getOwnPropertyNames(Object.getPrototypeOf(control)).sort(), [
    'constructor',
    'qualifyCellGetCandidate',
    'readCell'
  ])
})

test('sequence-zero qualification and read emit DESCRIBE internally and CELL.GET only', async t => {
  const fixture = await harness()
  const endpoint = await qualify(fixture)
  t.alike(await fixture.control.readCell({
    endpoint,
    readCap: fixture.replica.readCap,
    clientNonce: b4a.alloc(32, 0x91)
  }).then(value => value.structuredContent), b4a.from('peerit recovery record'))
  t.alike(fixture.trace, [
    [FAMILY.DESCRIBE, OPERATION.DESCRIBE.GET],
    [FAMILY.DESCRIBE, OPERATION.DESCRIBE.GET],
    [FAMILY.DESCRIBE, OPERATION.DESCRIBE.CHALLENGE],
    [FAMILY.CELL, OPERATION.CELL.GET]
  ])
})

test('sequence-positive rotated chain supports repeat and prepopulated persistent resume', async t => {
  const chainFixture = descriptorChain({ length: 3, rotateAt: 2 })
  const backend = new MemoryDescriptorTrustBackend()
  const fixture = await harness({ chainFixture, trustBackend: backend })
  await qualify(fixture)
  await qualify(fixture)
  t.is(backend.records.size, 1)

  const prepopulated = new MemoryDescriptorTrustBackend()
  const store = new DescriptorTrustStore(prepopulated)
  for (let index = 0; index < chainFixture.chain.length - 1; index++) {
    const item = chainFixture.chain[index]
    const verified = verifyDescriptorBytes(item.bytes, {
      nowEpoch: 101,
      history: index < chainFixture.chain.length - 1,
      ...supportFor(item.value)
    })
    await store.accept(verified, {
      ...(index === 0 ? { pinnedDescriptorHash: item.hash } : {}),
      continuityRootRelayPublicKey: chainFixture.rootKeys.publicKey
    })
  }
  const resumed = await harness({ chainFixture, trustBackend: prepopulated })
  await qualify(resumed)
  t.is(prepopulated.records.size, 1)
  const persisted = [...prepopulated.records.values()][0].value
  t.is(persisted.sequence, 2n)
  t.ok(b4a.equals(persisted.currentHash, chainFixture.head.hash))
})

test('per-control endpoint provenance rejects a cross-control endpoint', async t => {
  const first = await harness()
  const second = await harness({ chainFixture: first.chainFixture })
  const endpoint = await qualify(first)
  await t.exception(second.control.readCell({
    endpoint,
    readCap: first.replica.readCap
  }), /from this control/)
})

test('descriptor reconstruction rejects missing/wrong predecessor, gaps, roots and nullness', async t => {
  const chainFixture = descriptorChain({ length: 2 })
  const missing = await harness({
    chainFixture,
    descriptorResponse: (requested, byHash) => requested === b4a.toString(chainFixture.head.hash, 'hex')
      ? byHash.get(requested)
      : null
  })
  await t.exception(qualify(missing), /non-protocol status|transport/i)

  const wrong = await harness({
    chainFixture,
    descriptorResponse: (requested, byHash) => requested === b4a.toString(chainFixture.head.hash, 'hex')
      ? byHash.get(requested)
      : chainFixture.head
  })
  await t.exception(qualify(wrong), /requested history object|hash/i)

  const gapGenesis = descriptor(keyPair(0x31), { descriptorSequence: 0n })
  const gapHead = descriptor(keyPair(0x31), {
    descriptorSequence: 2n,
    previousDescriptorHash: gapGenesis.hash
  })
  const gap = await harness({
    chainFixture: { rootKeys: gapGenesis.keys, chain: [gapGenesis, gapHead], head: gapHead }
  })
  await t.exception(qualify(gap), /sequence is not contiguous/)

  const wrongRoot = await harness({
    continuityRootRelayPublicKey: b4a.alloc(32, 0xff)
  })
  await t.exception(qualify(wrongRoot), /continuity root/)

  const missingRoot = await harness()
  delete missingRoot.candidate.continuityRootRelayPublicKey
  await t.exception(qualify(missingRoot), /continuityRootRelayPublicKey/)

  const missingHead = await harness()
  delete missingHead.candidate.expectedDescriptorHash
  await t.exception(qualify(missingHead), /expectedDescriptorHash/)

  t.exception(() => descriptor(keyPair(0x31), {
    descriptorSequence: 1n,
    previousDescriptorHash: null
  }), /absent exactly for descriptor sequence zero/)
})

test('descriptor reconstruction rejects >4095, store drift and persisted tamper/quarantine', async t => {
  const oversized = descriptor(keyPair(0x31), {
    descriptorSequence: 4096n,
    previousDescriptorHash: b4a.alloc(32, 1)
  })
  const oversizedFixture = await harness({
    chainFixture: { rootKeys: oversized.keys, chain: [oversized], head: oversized }
  })
  await t.exception(qualify(oversizedFixture), /exceeds 4095/)

  const genesis = descriptor(keyPair(0x31), { descriptorSequence: 0n })
  const drift = descriptor(keyPair(0x31), {
    descriptorSequence: 1n,
    previousDescriptorHash: genesis.hash,
    storeId: b4a.alloc(32, 0xee)
  })
  const driftFixture = await harness({
    chainFixture: { rootKeys: genesis.keys, chain: [genesis, drift], head: drift }
  })
  await t.exception(qualify(driftFixture), /store identity/)

  const backend = new MemoryDescriptorTrustBackend()
  const persisted = await harness({ trustBackend: backend })
  await qualify(persisted)
  const record = [...backend.records.values()][0]
  record.value.quarantined = true
  await t.exception(qualify(persisted), /invalid sequence/)
  record.value.quarantined = false
  record.value.currentHash = b4a.alloc(32, 0xff)
  await t.exception(qualify(persisted), /does not match the authenticated chain/)
})

test('CELL.GET rejects operation selection and foreign endpoints before transport', async t => {
  const fixture = await harness()
  await t.exception(
    fixture.control.qualifyCellGetCandidate(fixture.candidate, { familyId: FAMILY.INBOX }),
    /cannot select/)
  await t.exception(fixture.control.readCell({ endpoint: Object.freeze({}) }), /from this control/)
})
