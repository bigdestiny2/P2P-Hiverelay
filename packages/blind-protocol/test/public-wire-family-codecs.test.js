import test from 'brittle'
import b4a from 'b4a'
import {
  ABI_STATUS,
  ADMISSION_MODE,
  CORE_ACK_RESULT,
  CORE_SESSION_CLASS,
  FAMILY,
  FORWARD_CIRCUIT_CLASS,
  FRAME_KIND,
  IMPLEMENTED_SCHEMAS,
  OPERATION,
  OPERATION_PROFILE_ROWS,
  OPERATION_PROFILE_STATUS,
  PUBLIC_FAMILY_SCHEMA_CODECS,
  SCHEMA_CATEGORY,
  STREAM_TRANSITION,
  STREAM_WIRE_CLASS,
  TRANSPORT_SUPPORT,
  admissionParametersV1,
  admissionProfileV1,
  blindCoreAckV1,
  blindDhtPointerV1,
  blindExternalJournalTopologyV1,
  blindForwardCloseV1,
  blindForwardDataV1,
  blindForwardOpenResultV1,
  blindForwardOpenV1,
  blindForwardWindowV1,
  blindHealthChallengeV1,
  blindHealthResultV1,
  blindOhttpKeyConfigV1,
  blindServiceDescriptorV1,
  blindStreamChunkPlainV1,
  coreMirrorRequestV1,
  coreMirrorRequestCommitment,
  coreServeChallengeV1,
  coreServeRequestCommitment,
  coreServeResultV1,
  decodeCanonical,
  draftSchemaId,
  encodeCanonical,
  forwardOpenRequestCommitment,
  operationProfileV1,
  relayIdentityTransitionV1,
  schemaCatalogEntryV1,
  wireAbiRegistryValue
} from '../index.js'
import { OPERATION_PROFILE_ROWS as FROZEN_OPERATION_PROFILE_ROWS } from '../wire-runtime-authority.js'

const KiB = 1024
const MiB = 1024 * KiB
const bytes = (length, value) => b4a.alloc(length, value)
const utf8 = value => b4a.from(value, 'utf8')

function relayBinding (seed, overrides = {}) {
  return {
    version: 1,
    relayPublicKey: bytes(32, seed),
    storeId: bytes(32, seed + 1),
    descriptorSequence: 1n,
    descriptorHash: bytes(32, seed + 2),
    durabilityProfileId: 1,
    durabilityContinuityHash: bytes(32, seed + 3),
    durabilityProfileHash: bytes(32, seed + 4),
    restoreEvidenceHeadSequence: 0n,
    restoreEvidenceHeadHash: bytes(32, 0),
    externalCommitWitness: null,
    ...overrides
  }
}

function admission () {
  return {
    profileId: 7,
    schemeId: 9,
    parameterHash: bytes(32, 0xa1),
    token: bytes(1, 0xa2)
  }
}

function admissionProfile () {
  return {
    profileId: 7,
    schemeId: 9,
    conformanceClass: 1,
    roleBits: 1,
    parameterUrl: utf8('https://evidence.example:443/admission.cenc'),
    parameterHash: bytes(32, 0x11)
  }
}

function admissionParameters () {
  return {
    version: 1,
    relayPublicKey: bytes(32, 0x12),
    profileId: 7,
    schemeId: 9,
    conformanceClass: 1,
    roleBits: 1,
    verifierKey: bytes(3, 0x13),
    resourceCosts: [
      { familyId: 2, operationId: 1, resourceClass: 1, leaseClass: 1, costUnits: 10n },
      { familyId: 4, operationId: 1, resourceClass: 1, leaseClass: 1, costUnits: 20n }
    ],
    tokenMaxBytes: 4096,
    issuanceUrl: utf8('https://issuer.example:443/token'),
    issuerRelayKey: bytes(32, 0x14),
    validFromEpoch: 100,
    expiresEpoch: 104,
    nonce: bytes(32, 0x15),
    signature: bytes(64, 0x16)
  }
}

function coreAck (result = CORE_ACK_RESULT.RECENTLY_SERVED) {
  return {
    version: 1,
    relayBinding: relayBinding(0x21),
    corePublicKey: bytes(32, 0x22),
    fork: 2n,
    length: 16n,
    signedHeadHash: bytes(32, 0x23),
    observedAtEpoch: 100,
    leaseEpoch: 104,
    result,
    requestNonce: bytes(32, 0x24),
    requestCommitment: bytes(32, 0x25),
    signature: bytes(64, 0x26)
  }
}

function nextHopAccept () {
  const limits = FORWARD_CIRCUIT_CLASS[1]
  return {
    version: 1,
    previousRelayKey: bytes(32, 0x31),
    previousDescriptorSequence: 9n,
    previousDescriptorHash: bytes(32, 0x32),
    nextRelayKey: bytes(32, 0x33),
    nextDescriptorSequence: 10n,
    nextDescriptorHash: bytes(32, 0x34),
    nextRelayBinding: relayBinding(0x33, {
      relayPublicKey: bytes(32, 0x33),
      descriptorSequence: 10n,
      descriptorHash: bytes(32, 0x34)
    }),
    routeId: bytes(16, 0x35),
    circuitNonce: bytes(32, 0x36),
    nextStreamId: 21n,
    grantedWireClass: 1,
    circuitClass: 1,
    grantedInitialWindow: limits.grantedInitialWindow,
    maxDataBytes: STREAM_WIRE_CLASS[1],
    maxCircuitBytes: BigInt(limits.maxCircuitBytes),
    idleMillis: limits.idleMillis,
    lifetimeMillis: limits.lifetimeMillis,
    openedAtEpoch: 100,
    hopOpenCommitment: bytes(32, 0x37),
    acceptedRouteScopeHash: bytes(32, 0x3a),
    acceptedRelayCount: 1,
    handshakeFlight2: bytes(96, 0x38),
    nextSignature: bytes(64, 0x39)
  }
}

function buildProfile () {
  return {
    specHash: bytes(32, 1),
    abiHash: bytes(32, 2),
    vectorSetHash: bytes(32, 3),
    evidenceFormatHash: bytes(32, 4),
    evidenceVectorSetHash: bytes(32, 5),
    storeFormatHash: bytes(32, 6),
    storeVectorSetHash: bytes(32, 7),
    privateIpcFormatHash: bytes(32, 10),
    privateIpcVectorSetHash: bytes(32, 11),
    buildArtifactHash: bytes(32, 8),
    buildArtifactUrl: utf8('https://evidence.example:443/artifact.cenc'),
    buildManifestUrl: utf8('https://evidence.example:443/build.cenc'),
    buildManifestHash: bytes(32, 9),
    releaseEvidenceBundleUrl: utf8('https://evidence.example:443/release.cenc'),
    releaseEvidenceBundleHash: bytes(32, 12),
    releaseSupportHorizonHash: bytes(32, 13),
    runtimeBoundaryEvidenceUrl: utf8('https://evidence.example:443/runtime-boundary.cenc'),
    runtimeBoundaryEvidenceHash: bytes(32, 14)
  }
}

function durabilityProfile () {
  return {
    profileId: 1,
    storeFormatMajor: 1,
    storeFormatMinor: 1,
    storeFormatHash: bytes(32, 0x41),
    externalJournalId: bytes(32, 0),
    externalWitnessPublicKey: bytes(32, 0),
    externalJournalReplicationClass: 0,
    externalJournalFailureGroupId: bytes(32, 0),
    externalCheckpointAgeBand: 0,
    externalJournalTopologyUrl: null,
    externalJournalTopologyHash: bytes(32, 0),
    restoreEvidenceFeedUrl: null,
    restoreEvidenceFeedId: bytes(32, 0),
    restoreEvidenceCheckpointSequence: 0n,
    restoreEvidenceCheckpointHash: bytes(32, 0),
    acknowledgedRpoBand: 0,
    targetRtoBand: 0,
    redundancyClass: 0,
    restoreDrillAgeBand: 0
  }
}

function descriptor () {
  return {
    version: 1,
    relayPublicKey: bytes(32, 0x51),
    storeId: bytes(32, 0x52),
    descriptorSequence: 0n,
    previousDescriptorHash: null,
    identitySequence: 0n,
    previousRelayKey: null,
    identityTransition: null,
    build: buildProfile(),
    protocols: [{ protocolId: 1, major: 1, minor: 0, featureBits: 0n, profileHash: bytes(32, 0x53) }],
    endpoints: [{
      endpointId: 1,
      transportId: 1,
      transportProfileHash: bytes(32, 0x54),
      roleBits: 1,
      privacyProfileBits: 1,
      canonicalUrl: utf8('https://relay.example:443/api/blind/v1/describe'),
      endpointKey: null,
      envelopeClassBits: 0x02,
      wireClassBits: 0,
      maxStreams: 0,
      auxiliaryUrl: null,
      auxiliaryHash: null
    }],
    cellSizeClassBits: 0x3e,
    leaseClassBits: 0x1e,
    maxBatchCount: 64,
    maxResponseBytes: 4 * MiB,
    maxSponsoredCoreLength: 1024n,
    enabledOperationBits: 0x003fffff,
    admissionProfiles: [admissionProfile()],
    durability: durabilityProfile(),
    durabilityContinuityHash: bytes(32, 0x55),
    durabilityProfileHash: bytes(32, 0x56),
    storeLifecycleState: 1,
    drainStartedEpoch: null,
    capacityBand: 5,
    issuedEpoch: 100,
    expiresEpoch: 104,
    descriptorNonce: bytes(32, 0x57),
    signature: bytes(64, 0x58)
  }
}

test('public WIRE closure has executable codecs and all 22 operation rows', t => {
  const names = Object.keys(PUBLIC_FAMILY_SCHEMA_CODECS).sort()
  t.alike(names, [
    'AdmissionParametersV1',
    'AdmissionProfileV1',
    'BlindCoreAckV1',
    'BlindDhtPointerV1',
    'BlindExternalJournalTopologyV1',
    'BlindForwardCloseV1',
    'BlindForwardDataV1',
    'BlindForwardOpenResultV1',
    'BlindForwardOpenV1',
    'BlindForwardWindowV1',
    'BlindHealthChallengeV1',
    'BlindHealthResultV1',
    'BlindOhttpKeyConfigV1',
    'BlindServiceDescriptorV1',
    'BlindStreamChunkPlainV1',
    'CoreMirrorRequestV1',
    'CoreServeChallengeV1',
    'CoreServeResultV1',
    'RelayIdentityTransitionV1',
    'SchemaCatalogEntryV1'
  ])
  for (const name of names) t.ok(IMPLEMENTED_SCHEMAS.some(schema => schema.name === name), `${name} has ABI metadata`)
  t.is(ABI_STATUS.wireMissingSchemaNames.length, 0)
  t.is(ABI_STATUS.missingSchemaNames.length, 0)
  t.is(OPERATION_PROFILE_ROWS.length, 22)
  t.is(OPERATION_PROFILE_STATUS.missingPairs.length, 0)
  t.is(ABI_STATUS.releaseReady, true)
  t.alike(ABI_STATUS.releaseBlockers, [])
  t.is(ABI_STATUS.wireAuthorityPublished, true)
  t.is(ABI_STATUS.operationCapStatus.complete, true)
  t.is(ABI_STATUS.errorTransportMappingStatus.complete, true)
  t.is(ABI_STATUS.categoryRegistryStatus.complete, true)
  t.is(ABI_STATUS.schemaInventorySource, 'stable-master-142-schema-category-catalog')
  t.absent(ABI_STATUS.releaseBlockers.find(blocker => blocker === 'MASTER_SCHEMA_CATALOG_RECONCILIATION_PENDING'))
})

test('final WIRE ABI serializes every public enum, cap and operation bit without build metadata', t => {
  const registry = wireAbiRegistryValue()
  t.is(registry.magic, 'hiverelay-blind-abi-v1')
  t.is(registry.mediaType, 'application/vnd.hiverelay.blind-v1')
  t.is(registry.cellReceiptResults.length, 4)
  t.is(registry.inboxManageOperations.length, 2)
  t.is(registry.inboxAppendAuthModes.length, 2)
  t.is(registry.inboxReceiptResults.length, 3)
  t.is(registry.inboxAppendResults.length, 1)
  t.is(registry.admissionConformanceClasses.length, 2)
  t.is(registry.coreAckResults.length, 2)
  t.is(registry.forwardCloseKinds.length, 2)
  t.is(registry.storeLifecycleStates.length, 3)
  t.is(registry.healthClockStates.length, 3)
  t.is(registry.healthIntegrityStates.length, 3)
  t.is(registry.healthRebalanceStates.length, 4)
  t.is(registry.ohttpDeliveryBoundaries.length, 3)
  t.is(registry.ohttpRetryActions.length, 3)
  t.is(registry.publicProfileLimits.length, 11)
  t.is(registry.operationBits.length, 22)
  for (let ordinal = 0; ordinal < registry.operationBits.length; ordinal++) {
    t.is(registry.operationBits[ordinal].ordinal, ordinal)
    t.is(registry.operationBits[ordinal].bit, 2 ** ordinal)
  }
  t.is(registry.implementedSchemas.length, 73)
  t.ok(registry.implementedSchemas.every(schema => schema.category === SCHEMA_CATEGORY.WIRE))
  t.absent(Object.hasOwn(registry, 'releaseReady'))
  t.absent(Object.hasOwn(registry, 'releaseBlockers'))
  t.absent(Object.hasOwn(registry, 'schemaInventorySource'))
})

test('DESCRIBE admission codecs enforce sorted costs, URL/key pairing and bounded validity', t => {
  const profile = admissionProfile()
  t.alike(decodeCanonical(admissionProfileV1, encodeCanonical(admissionProfileV1, profile)).parameterHash,
    profile.parameterHash)

  const parameters = admissionParameters()
  const encoded = encodeCanonical(admissionParametersV1, parameters)
  t.is(decodeCanonical(admissionParametersV1, encoded).resourceCosts[1].costUnits, 20n)
  t.exception(() => encodeCanonical(admissionParametersV1, {
    ...parameters,
    resourceCosts: [...parameters.resourceCosts].reverse()
  }), /strictly sorted/)
  t.exception(() => encodeCanonical(admissionParametersV1, { ...parameters, issuerRelayKey: null }), /present together/)
  t.exception(() => encodeCanonical(admissionParametersV1, { ...parameters, expiresEpoch: 100 }), /nonempty/)
  t.exception(() => encodeCanonical(admissionProfileV1, { ...profile, roleBits: 0x80 }), /known nonzero bits/)
})

test('DESCRIBE identity, pointer, health, OHTTP and schema catalog reject rollback-shaped ambiguity', t => {
  const transition = {
    version: 1,
    oldRelayKey: bytes(32, 0x61),
    newRelayKey: bytes(32, 0x62),
    oldIdentitySequence: 8n,
    newIdentitySequence: 9n,
    validFromEpoch: 100,
    reasonCode: 1,
    transitionNonce: bytes(32, 0x63),
    oldSignature: bytes(64, 0x64),
    newSignature: bytes(64, 0x65)
  }
  t.is(decodeCanonical(relayIdentityTransitionV1,
    encodeCanonical(relayIdentityTransitionV1, transition)).newIdentitySequence, 9n)
  t.exception(() => encodeCanonical(relayIdentityTransitionV1, {
    ...transition,
    newIdentitySequence: 10n
  }), /oldIdentitySequence \+ 1/)

  const pointer = {
    version: 1,
    relayPublicKey: bytes(32, 0x66),
    descriptorSequence: 1n,
    descriptorHash: bytes(32, 0x67),
    descriptorUrl: utf8('https://relay.example:443/descriptor.cenc'),
    transportBits: 2,
    issuedEpoch: 100,
    expiresEpoch: 104,
    nonce: bytes(32, 0x68),
    signature: bytes(64, 0x69)
  }
  t.ok(encodeCanonical(blindDhtPointerV1, pointer).byteLength <= 1000)
  t.exception(() => encodeCanonical(blindDhtPointerV1, { ...pointer, transportBits: 1 }), /known nonzero bits/)

  const challenge = {
    version: 1,
    descriptorSequence: 1n,
    descriptorHash: pointer.descriptorHash,
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    requestedRoleBits: 1,
    requestedOperationBits: 1,
    clientNonce: bytes(32, 0x6a)
  }
  t.is(decodeCanonical(blindHealthChallengeV1,
    encodeCanonical(blindHealthChallengeV1, challenge)).requestedOperationBits, 1)
  const currentChallengeBytes = encodeCanonical(blindHealthChallengeV1, challenge)
  const legacyChallengeBytes = b4a.concat([
    currentChallengeBytes.subarray(0, 41),
    currentChallengeBytes.subarray(44)
  ])
  t.exception(() => decodeCanonical(blindHealthChallengeV1, legacyChallengeBytes))
  t.exception(() => encodeCanonical(blindHealthChallengeV1, {
    ...challenge,
    requestedOperationBits: 0x80000000
  }), /reserved bit/)
  t.exception(() => encodeCanonical(blindHealthChallengeV1, {
    ...challenge,
    requestedRoleBits: 0
  }), /both be nonzero/)
  t.exception(() => encodeCanonical(blindHealthChallengeV1, {
    ...challenge,
    requestedOperationBits: 0
  }), /both be nonzero/)
  t.exception(() => encodeCanonical(blindHealthChallengeV1, {
    ...challenge,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP | TRANSPORT_SUPPORT.DIRECT_NATIVE
  }), /one frozen one-hot support bit/)
  t.exception(() => encodeCanonical(blindHealthChallengeV1, {
    ...challenge,
    endpointId: 0
  }), /outside 1\.\.255/)

  const result = {
    version: 1,
    relayPublicKey: pointer.relayPublicKey,
    storeId: bytes(32, 0x6b),
    descriptorSequence: 1n,
    descriptorHash: pointer.descriptorHash,
    endpointId: challenge.endpointId,
    transportSupportBit: challenge.transportSupportBit,
    durabilityContinuityHash: bytes(32, 0x6c),
    durabilityProfileHash: bytes(32, 0x6d),
    clientNonce: challenge.clientNonce,
    readyRoleBits: 1,
    readyOperationBits: 1,
    clockState: 1,
    effectiveEpochFloor: 100,
    integrityState: 1,
    checkpointAgeBand: 1,
    scrubAgeBand: 1,
    rebalanceState: 0,
    capacityBand: 4,
    challengeEpoch: 100,
    signature: bytes(64, 0x6e)
  }
  t.is(decodeCanonical(blindHealthResultV1,
    encodeCanonical(blindHealthResultV1, result)).clockState, 1)
  const currentResultBytes = encodeCanonical(blindHealthResultV1, result)
  const legacyResultBytes = b4a.concat([
    currentResultBytes.subarray(0, 105),
    currentResultBytes.subarray(108)
  ])
  t.exception(() => decodeCanonical(blindHealthResultV1, legacyResultBytes))
  t.exception(() => encodeCanonical(blindHealthResultV1, {
    ...result,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP | TRANSPORT_SUPPORT.DIRECT_NATIVE
  }), /one frozen one-hot support bit/)

  const keyConfig = {
    version: 1,
    gatewayRelayKey: bytes(32, 0x6f),
    gatewayDescriptorSequence: 1n,
    configId: 255,
    kemId: 0x20,
    kdfId: 1,
    aeadId: 1,
    encodedPublicKey: bytes(32, 0x70),
    notBeforeEpoch: 100,
    notAfterEpoch: 104,
    previousConfigHash: null,
    signature: bytes(64, 0x71)
  }
  t.is(decodeCanonical(blindOhttpKeyConfigV1,
    encodeCanonical(blindOhttpKeyConfigV1, keyConfig)).configId, 255)
  t.exception(() => encodeCanonical(blindOhttpKeyConfigV1, {
    ...keyConfig,
    notAfterEpoch: 221
  }), /1\.\.120 epochs/)

  const catalog = {
    category: SCHEMA_CATEGORY.WIRE,
    categoryLocalSchemaId: 1,
    schemaName: utf8('AdmissionCostRuleV1'),
    canonicalSchemaBytes: utf8('canonical-schema')
  }
  t.is(decodeCanonical(schemaCatalogEntryV1,
    encodeCanonical(schemaCatalogEntryV1, catalog)).categoryLocalSchemaId, 1)
  t.exception(() => encodeCanonical(schemaCatalogEntryV1, {
    ...catalog,
    categoryLocalSchemaId: 2
  }), /frozen category registry/)
})

test('DESCRIBE external journal topology requires a linked, sorted three-domain quorum', t => {
  const topology = {
    version: 1,
    relayPublicKey: bytes(32, 0x81),
    storeId: bytes(32, 0x82),
    externalJournalId: bytes(32, 0x83),
    durabilityContinuityHash: bytes(32, 0x84),
    topologySequence: 0n,
    previousTopologyHash: null,
    replicationClass: 1,
    commitQuorum: 2,
    sharedFailureGroupId: bytes(32, 0x85),
    liveStoreFailureGroupId: bytes(32, 0x86),
    backupFailureGroups: [],
    nodes: [
      { nodePublicKey: bytes(32, 1), operatorGroupId: bytes(32, 11), failureDomainId: bytes(32, 21), roleConflictBits: 0 },
      { nodePublicKey: bytes(32, 2), operatorGroupId: bytes(32, 12), failureDomainId: bytes(32, 22), roleConflictBits: 0 },
      { nodePublicKey: bytes(32, 3), operatorGroupId: bytes(32, 13), failureDomainId: bytes(32, 23), roleConflictBits: 0 }
    ],
    issuedEpoch: 100,
    expiresEpoch: 104,
    witnessPublicKey: bytes(32, 0x87),
    signature: bytes(64, 0x88)
  }
  t.is(decodeCanonical(blindExternalJournalTopologyV1,
    encodeCanonical(blindExternalJournalTopologyV1, topology)).nodes.length, 3)
  t.exception(() => encodeCanonical(blindExternalJournalTopologyV1, {
    ...topology,
    topologySequence: 1n
  }), /absent exactly/)
  t.exception(() => encodeCanonical(blindExternalJournalTopologyV1, {
    ...topology,
    nodes: [...topology.nodes].reverse()
  }), /strictly sorted/)
  t.exception(() => encodeCanonical(blindExternalJournalTopologyV1, {
    ...topology,
    nodes: topology.nodes.map((node, index) => ({
      ...node,
      operatorGroupId: index === 2 ? topology.nodes[1].operatorGroupId : node.operatorGroupId
    }))
  }), /duplicate/)
})

test('DESCRIBE service descriptor is capped, linked and lifecycle-fenced', t => {
  const value = descriptor()
  const encoded = encodeCanonical(blindServiceDescriptorV1, value)
  t.ok(encoded.byteLength < 16 * KiB)
  t.is(decodeCanonical(blindServiceDescriptorV1, encoded).descriptorSequence, 0n)
  t.exception(() => encodeCanonical(blindServiceDescriptorV1, {
    ...value,
    descriptorSequence: 1n
  }), /absent exactly/)
  t.exception(() => encodeCanonical(blindServiceDescriptorV1, {
    ...value,
    storeLifecycleState: 2,
    drainStartedEpoch: 100
  }), /wrong enabled operation bitmap/)
  t.exception(() => encodeCanonical(blindServiceDescriptorV1, {
    ...value,
    storeLifecycleState: 3,
    drainStartedEpoch: 100
  }), /disable all operations/)
  t.exception(() => encodeCanonical(blindServiceDescriptorV1, {
    ...value,
    protocols: [
      value.protocols[0],
      { ...value.protocols[0], profileHash: bytes(32, 0x59) }
    ]
  }), /strictly sorted/)
})

test('CORE mirror, serve and acknowledgement codecs freeze head and sample bounds', t => {
  const ack = coreAck()
  t.is(encodeCanonical(blindCoreAckV1, ack).byteLength, 429)
  const mirror = {
    version: 1,
    corePublicKey: ack.corePublicKey,
    fork: ack.fork,
    length: ack.length,
    signedHeadHash: ack.signedHeadHash,
    leaseClass: 2,
    clientNonce: bytes(32, 0x27),
    admission: admission()
  }
  t.is(decodeCanonical(coreMirrorRequestV1,
    encodeCanonical(coreMirrorRequestV1, mirror)).length, 16n)
  t.is(coreMirrorRequestCommitment({ relayPublicKey: ack.relayBinding.relayPublicKey, ...mirror }).byteLength, 32)
  t.exception(() => encodeCanonical(coreMirrorRequestV1, { ...mirror, length: 0n }), /must be nonzero/)
  t.exception(() => coreMirrorRequestCommitment({
    relayPublicKey: ack.relayBinding.relayPublicKey,
    ...mirror,
    length: 0n
  }), /must be nonzero/)

  const challenge = {
    version: 1,
    corePublicKey: ack.corePublicKey,
    fork: ack.fork,
    length: ack.length,
    signedHeadHash: ack.signedHeadHash,
    blockIndices: [0n, 7n, 15n],
    clientNonce: ack.requestNonce,
    admission: null
  }
  t.is(decodeCanonical(coreServeChallengeV1,
    encodeCanonical(coreServeChallengeV1, challenge)).blockIndices.length, 3)
  t.is(coreServeRequestCommitment({ relayPublicKey: ack.relayBinding.relayPublicKey, ...challenge }).byteLength, 32)
  t.exception(() => encodeCanonical(coreServeChallengeV1, {
    ...challenge,
    blockIndices: [7n, 7n]
  }), /strictly sorted/)
  t.exception(() => encodeCanonical(coreServeChallengeV1, {
    ...challenge,
    blockIndices: [16n]
  }), /below length/)
  t.exception(() => coreServeRequestCommitment({
    relayPublicKey: ack.relayBinding.relayPublicKey,
    ...challenge,
    blockIndices: [7n, 7n]
  }), /strictly sorted/)

  const result = { version: 1, acknowledgement: ack, proofsAndBlocks: bytes(8, 0x28) }
  t.alike(decodeCanonical(coreServeResultV1,
    encodeCanonical(coreServeResultV1, result)).proofsAndBlocks, result.proofsAndBlocks)
  t.exception(() => encodeCanonical(coreServeResultV1, {
    ...result,
    acknowledgement: coreAck(CORE_ACK_RESULT.MIRROR_ACCEPTED)
  }), /RECENTLY_SERVED/)
})

test('FORWARD open/result codecs bind the adjacent accept and frozen class tuple', t => {
  const next = nextHopAccept()
  const open = {
    version: 1,
    routeId: next.routeId,
    nextDescriptorSequence: next.nextDescriptorSequence,
    nextDescriptorHash: next.nextDescriptorHash,
    requestedWireClass: 1,
    circuitClass: 1,
    circuitNonce: next.circuitNonce,
    parentRouteScopeHash: bytes(32, 0),
    hopAdmission: admission(),
    innerHandshake: bytes(32, 0x3a)
  }
  t.is(decodeCanonical(blindForwardOpenV1,
    encodeCanonical(blindForwardOpenV1, open)).requestedWireClass, 1)
  t.is(forwardOpenRequestCommitment({
    previousRelayKey: next.previousRelayKey,
    ...open
  }).byteLength, 32)

  const result = {
    version: 1,
    relayBinding: relayBinding(0x31, {
      relayPublicKey: next.previousRelayKey,
      descriptorSequence: next.previousDescriptorSequence,
      descriptorHash: next.previousDescriptorHash
    }),
    routeId: next.routeId,
    nextDescriptorSequence: next.nextDescriptorSequence,
    nextDescriptorHash: next.nextDescriptorHash,
    circuitNonce: next.circuitNonce,
    grantedWireClass: next.grantedWireClass,
    circuitClass: next.circuitClass,
    streamId: 20n,
    grantedInitialWindow: next.grantedInitialWindow,
    maxDataBytes: next.maxDataBytes,
    maxCircuitBytes: next.maxCircuitBytes,
    idleMillis: next.idleMillis,
    lifetimeMillis: next.lifetimeMillis,
    openedAtEpoch: next.openedAtEpoch,
    requestCommitment: bytes(32, 0x3b),
    acceptedRouteScopeHash: next.acceptedRouteScopeHash,
    acceptedRelayCount: next.acceptedRelayCount,
    nextHopAccept: next,
    signature: bytes(64, 0x3c)
  }
  t.is(decodeCanonical(blindForwardOpenResultV1,
    encodeCanonical(blindForwardOpenResultV1, result)).streamId, 20n)
  t.exception(() => encodeCanonical(blindForwardOpenResultV1, {
    ...result,
    routeId: bytes(16, 0x3d)
  }), /does not match nextHopAccept/)
  t.exception(() => encodeCanonical(blindForwardOpenResultV1, {
    ...result,
    maxCircuitBytes: 64n * BigInt(MiB)
  }), /frozen class tuple/)
  t.exception(() => encodeCanonical(blindForwardOpenV1, {
    ...open,
    circuitNonce: bytes(32, 0)
  }), /must be nonzero/)
  t.exception(() => encodeCanonical(blindForwardOpenV1, {
    ...open,
    innerHandshake: bytes(31, 0x3a)
  }), /32/)
  t.exception(() => forwardOpenRequestCommitment({
    previousRelayKey: next.previousRelayKey,
    ...open,
    requestedWireClass: 4
  }), /outside 1\.\.3/)
})

test('FORWARD active bodies and fixed plaintext classes reject length and flag fingerprints', t => {
  const nonce = bytes(32, 0x91)
  const data = { version: 1, circuitNonce: nonce, offset: 0n, bytes: bytes(4, 0x92) }
  const window = { version: 1, circuitNonce: nonce, consumedThrough: 4n, creditIncrement: 4096 }
  const close = { version: 1, circuitNonce: nonce, closeKind: 1, finalSendOffset: 4n, reasonCode: 0 }
  t.is(decodeCanonical(blindForwardDataV1, encodeCanonical(blindForwardDataV1, data)).offset, 0n)
  t.is(decodeCanonical(blindForwardWindowV1,
    encodeCanonical(blindForwardWindowV1, window)).creditIncrement, 4096)
  t.is(decodeCanonical(blindForwardCloseV1,
    encodeCanonical(blindForwardCloseV1, close)).closeKind, 1)
  t.exception(() => encodeCanonical(blindForwardWindowV1, {
    ...window,
    creditIncrement: MiB + 1
  }), /outside 1\.\.1048576/)
  t.exception(() => encodeCanonical(blindForwardCloseV1, { ...close, closeKind: 3 }), /outside 1\.\.2/)

  for (const [wireClass, ciphertextLength] of Object.entries(STREAM_WIRE_CLASS)) {
    const content = bytes(3, Number(wireClass))
    const padding = bytes(ciphertextLength - 23 - content.byteLength, 0xa0 + Number(wireClass))
    const chunk = {
      version: 1,
      wireClass: Number(wireClass),
      flags: 0,
      contentLength: content.byteLength,
      content,
      randomPadding: padding
    }
    const encoded = encodeCanonical(blindStreamChunkPlainV1, chunk)
    t.is(encoded.byteLength, ciphertextLength - 16)
    t.alike(decodeCanonical(blindStreamChunkPlainV1, encoded).content, content)
  }
  const chunk = {
    version: 1,
    wireClass: 1,
    flags: 2,
    contentLength: 0,
    content: b4a.alloc(0),
    randomPadding: bytes(4073, 0)
  }
  t.exception(() => encodeCanonical(blindStreamChunkPlainV1, chunk), /reserved bit/)
  t.exception(() => encodeCanonical(blindStreamChunkPlainV1, {
    ...chunk,
    flags: 0,
    randomPadding: bytes(4072, 0)
  }), /exactly 4073/)
})

test('DESCRIBE, CORE and FORWARD operation metadata is complete and transition-specific', t => {
  const describe = OPERATION_PROFILE_ROWS.filter(row => row.familyId === FAMILY.DESCRIBE)
  const core = OPERATION_PROFILE_ROWS.filter(row => row.familyId === FAMILY.CORE)
  const forward = OPERATION_PROFILE_ROWS.filter(row => row.familyId === FAMILY.FORWARD)
  const frozenByPair = new Map(FROZEN_OPERATION_PROFILE_ROWS.map(row => [
    `${row.familyId}:${row.operationId}`,
    row
  ]))
  t.is(describe.length, 3)
  t.is(core.length, 3)
  t.is(forward.length, 4)
  for (const row of [...describe, ...core, ...forward]) {
    const frozenRow = frozenByPair.get(`${row.familyId}:${row.operationId}`)
    t.ok(frozenRow, 'operation exists in the frozen runtime authority')
    t.is(decodeCanonical(operationProfileV1,
      encodeCanonical(operationProfileV1, frozenRow)).operationId, row.operationId)
  }

  for (const row of describe) {
    t.is(row.admissionMode, ADMISSION_MODE.NONE)
    t.is(row.requestCommitmentDomainId, 0)
    t.is(row.transportSupportBits, 31)
  }
  const coreOpen = core.find(row => row.operationId === OPERATION.CORE.OPEN_REPLICATION)
  t.is(coreOpen.streamTransition, STREAM_TRANSITION.CORE_CHILD)
  t.is(coreOpen.transportSupportBits, TRANSPORT_SUPPORT.DIRECT_NATIVE | TRANSPORT_SUPPORT.TOR_NATIVE)
  t.is(CORE_SESSION_CLASS[2].maxSessionBytes, 64 * MiB)

  const forwardOpen = forward.find(row => row.operationId === OPERATION.FORWARD.OPEN)
  t.is(forwardOpen.streamTransition, STREAM_TRANSITION.FORWARD_OPEN)
  t.is(forwardOpen.maxRequestBodyBytes, 131072)
  for (const row of forward.filter(row => row.operationId !== OPERATION.FORWARD.OPEN)) {
    t.is(row.requestSchemaId > 0, true)
    t.is(row.resultSchemaId, 0)
    t.is(row.allowedRequestKindBits, 1 << (FRAME_KIND.STREAM - 1))
    t.is(row.streamTransition, STREAM_TRANSITION.FORWARD_ACTIVE)
  }
  t.is(draftSchemaId('BlindForwardOpenV1') > 0, true)
})
