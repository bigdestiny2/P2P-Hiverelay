import test from 'brittle'
import b4a from 'b4a'
import {
  ABI_STATUS,
  CONTROL_CHANNEL_ID_TYPE,
  DURABILITY_PROFILE_ID,
  IMPLEMENTED_SCHEMAS,
  OPERATION_PROFILE_STATUS,
  REQUIRED_SCHEMA_NAMES,
  SCHEMA_CATEGORY,
  SCHEMA_NAMES_BY_CATEGORY,
  TRANSPORT_EXPORTER_ID,
  TRANSPORT_ID,
  buildProfileV1,
  decodeCanonical,
  draftAbiRegistryValue,
  durabilityProfileV1,
  encodeCanonical,
  hashProtocolProfile,
  hashTransportProfile,
  protocolProfileArtifactV1,
  protocolProfileV1,
  schemaCategory,
  transportEndpointV1,
  transportProfileArtifactV1
} from '../index.js'

const bytes = (length, value) => b4a.alloc(length, value)
const utf8 = value => b4a.from(value, 'utf8')

function protocolArtifact () {
  return {
    version: 1,
    protocolId: 4,
    major: 1,
    minor: 0,
    featureBits: 0x0102030405060708n,
    wireSchemaSetHash: bytes(32, 0x11),
    dependencyManifestHash: bytes(32, 0x12),
    interoperabilityVectorSetHash: bytes(32, 0x13)
  }
}

function transportArtifact () {
  return {
    version: 1,
    transportId: TRANSPORT_ID.DIRECT_PROTOMUX_NOISE,
    profileName: utf8('hiverelay/protomux-noise/1'),
    major: 1,
    minor: 0,
    exporterId: TRANSPORT_EXPORTER_ID.NOISE_HANDSHAKE_HASH_BLAKE2B,
    controlChannelIdType: CONTROL_CHANNEL_ID_TYPE.NONZERO_U64BE,
    handshakeProfileHash: bytes(32, 0x21),
    dependencyManifestHash: bytes(32, 0x22),
    interoperabilityVectorSetHash: bytes(32, 0x23)
  }
}

function endpoint (overrides = {}) {
  return {
    endpointId: 1,
    transportId: TRANSPORT_ID.DIRECT_PROTOMUX_NOISE,
    transportProfileHash: bytes(32, 0x31),
    roleBits: 1,
    privacyProfileBits: 1,
    canonicalUrl: utf8('https://relay.example:443/api/blind/v1/describe'),
    endpointKey: bytes(32, 0x32),
    envelopeClassBits: 0,
    wireClassBits: 0x0e,
    maxStreams: 64,
    auxiliaryUrl: utf8('https://relay.example:443/routes'),
    auxiliaryHash: bytes(32, 0x33),
    ...overrides
  }
}

test('blind candidate schema catalog: category and operation gaps fail closed independently', t => {
  t.is(REQUIRED_SCHEMA_NAMES.length, 150)
  t.is(IMPLEMENTED_SCHEMAS.length, 143)
  t.is(ABI_STATUS.missingSchemaNames.length, 0)
  t.is(ABI_STATUS.wireRequiredSchemaNames.length, 73)
  t.is(ABI_STATUS.wireImplementedSchemaNames.length, 73)
  t.is(ABI_STATUS.wireMissingSchemaNames.length, 0)
  t.is(ABI_STATUS.schemaStatusByCategory[SCHEMA_CATEGORY.EVIDENCE].missingSchemaNames.length, 0)
  t.is(ABI_STATUS.schemaStatusByCategory[SCHEMA_CATEGORY.CLIENT_EXAMPLE].missingSchemaNames.length, 0)
  t.is(ABI_STATUS.schemaStatusByCategory[SCHEMA_CATEGORY.INTERNAL_STORE].missingSchemaNames.length, 0)
  t.is(ABI_STATUS.schemaStatusByCategory[SCHEMA_CATEGORY.PRIVATE_IPC].externallyOwnedSchemaNames.length, 7)
  t.is(ABI_STATUS.duplicateSchemaNames.length, 0)
  t.is(ABI_STATUS.unclassifiedImplementedSchemaNames.length, 0)
  for (const names of Object.values(SCHEMA_NAMES_BY_CATEGORY)) {
    t.alike(names, [...names].sort(), 'category-local schema IDs use raw-ASCII name order')
  }
  t.is(OPERATION_PROFILE_STATUS.requiredPairs.length, 22)
  t.is(OPERATION_PROFILE_STATUS.implementedPairs.length, 22)
  t.is(OPERATION_PROFILE_STATUS.missingPairs.length, 0)
  t.is(schemaCategory('ProtocolProfileArtifactV1'), SCHEMA_CATEGORY.EVIDENCE)
  t.is(schemaCategory('TransportEndpointV1'), SCHEMA_CATEGORY.WIRE)
  t.is(schemaCategory('BlindStoreManifestV1'), SCHEMA_CATEGORY.INTERNAL_STORE)
  t.is(schemaCategory('BlindLocalCheckpointV1'), SCHEMA_CATEGORY.INTERNAL_STORE)
  t.is(schemaCategory('BlindWalHeaderV2'), SCHEMA_CATEGORY.INTERNAL_STORE)
  t.is(schemaCategory('ReadCellCapV1'), SCHEMA_CATEGORY.CLIENT_EXAMPLE)
  for (const name of [
    'BlindExternalAckFloorV1',
    'OperationProfileV1',
    'ProtocolProfileArtifactV1',
    'SchemaCatalogEntryV1',
    'TransportProfileArtifactV1'
  ]) t.ok(REQUIRED_SCHEMA_NAMES.includes(name), `${name} is classified`)

  const registry = draftAbiRegistryValue()
  t.is(registry.requiredSchemaNames.length, 73)
  t.is(registry.implementedSchemas.length, 73)
  t.is(registry.missingSchemaNames.length, 0)
  t.absent(registry.implementedSchemas.find(schema => schema.name === 'ProtocolProfileArtifactV1'))
})

test('blind profile evidence: protocol artifact and descriptor pin are byte exact', t => {
  const artifact = protocolArtifact()
  const encodedArtifact = encodeCanonical(protocolProfileArtifactV1, artifact)
  t.is(encodedArtifact.byteLength, 111)
  t.is(b4a.toString(encodedArtifact.subarray(0, 15), 'hex'), '010004000100000102030405060708')
  t.is(decodeCanonical(protocolProfileArtifactV1, encodedArtifact).featureBits, artifact.featureBits)

  const profileHash = hashProtocolProfile(encodedArtifact)
  const profile = {
    protocolId: artifact.protocolId,
    major: artifact.major,
    minor: artifact.minor,
    featureBits: artifact.featureBits,
    profileHash
  }
  const encodedProfile = encodeCanonical(protocolProfileV1, profile)
  t.is(encodedProfile.byteLength, 46)
  t.alike(decodeCanonical(protocolProfileV1, encodedProfile).profileHash, profileHash)
  t.exception(() => encodeCanonical(protocolProfileArtifactV1, { ...artifact, protocolId: 0 }), /outside 1..5/)
  t.exception(() => encodeCanonical(protocolProfileV1, { ...profile, protocolId: 6 }), /outside 1..5/)
})

test('blind profile evidence: transport artifact freezes canonical ASCII and hashes', t => {
  const artifact = transportArtifact()
  const encoded = encodeCanonical(transportProfileArtifactV1, artifact)
  t.is(encoded.byteLength, 105 + artifact.profileName.byteLength)
  t.is(encoded[2], artifact.profileName.byteLength)
  t.alike(decodeCanonical(transportProfileArtifactV1, encoded).profileName, artifact.profileName)
  t.is(hashTransportProfile(encoded).byteLength, 32)
  t.exception(() => encodeCanonical(transportProfileArtifactV1, {
    ...artifact,
    profileName: b4a.from([0x61, 0x00, 0x62])
  }), /embedded NUL/)
  t.exception(() => encodeCanonical(transportProfileArtifactV1, {
    ...artifact,
    profileName: utf8('café')
  }), /printable ASCII/)
  t.exception(() => encodeCanonical(transportProfileArtifactV1, { ...artifact, exporterId: 2 }), /outside 0..1/)
  t.exception(() => encodeCanonical(transportProfileArtifactV1, { ...artifact, transportId: 10 }), /outside 1..9/)
})

test('blind descriptor endpoint: canonical URL, class and auxiliary invariants are closed', t => {
  const encoded = encodeCanonical(transportEndpointV1, endpoint())
  const decoded = decodeCanonical(transportEndpointV1, encoded)
  t.is(decoded.endpointId, 1)
  t.alike(decoded.canonicalUrl, endpoint().canonicalUrl)
  t.is(decoded.maxStreams, 64)

  t.exception(() => encodeCanonical(transportEndpointV1, endpoint({
    canonicalUrl: utf8('https://Relay.example:443/api/blind/v1/core')
  })), /host must be lowercase/)
  t.exception(() => encodeCanonical(transportEndpointV1, endpoint({
    canonicalUrl: utf8('https://relay.example/api/blind/v1/core')
  })), /explicit port/)
  t.exception(() => encodeCanonical(transportEndpointV1, endpoint({
    canonicalUrl: b4a.concat([utf8('https://relay.example:443/'), b4a.from([0xc0, 0xaf])])
  })), /strict UTF-8/)
  t.exception(() => encodeCanonical(transportEndpointV1, endpoint({
    canonicalUrl: utf8('https://relay.example:443/cafe\u0301')
  })), /already be NFC/)
  t.exception(() => encodeCanonical(transportEndpointV1, endpoint({
    canonicalUrl: utf8('https://relay.example:443/api/blind/v1/cell')
  })), /listener authority anchor/)
  t.exception(() => encodeCanonical(transportEndpointV1, endpoint({ roleBits: 0x80 })), /reserved bit/)
  t.exception(() => encodeCanonical(transportEndpointV1, endpoint({ wireClassBits: 0, maxStreams: 1 })), /both describe/)
  t.exception(() => encodeCanonical(transportEndpointV1, endpoint({ auxiliaryHash: null })), /present together/)

  const onionHost = `${'a'.repeat(56)}.onion`
  const onion = endpoint({
    transportId: TRANSPORT_ID.TOR_V3_ONION,
    canonicalUrl: utf8(`http://${onionHost}:80/api/blind/v1/describe`),
    endpointKey: null,
    envelopeClassBits: 0x02,
    wireClassBits: 0,
    maxStreams: 0,
    auxiliaryUrl: null,
    auxiliaryHash: null
  })
  t.is(decodeCanonical(transportEndpointV1, encodeCanonical(transportEndpointV1, onion)).transportId, 7)
  t.exception(() => encodeCanonical(transportEndpointV1, {
    ...onion,
    canonicalUrl: utf8('https://relay.example:443/blind')
  }), /v3 onion URL/)
})

test('blind descriptor evidence: durability and build profiles are fixed and bounded', t => {
  const durability = {
    profileId: DURABILITY_PROFILE_ID.CONTROL_RPO0_3_NODE_V1,
    storeFormatMajor: 1,
    storeFormatMinor: 1,
    storeFormatHash: bytes(32, 0x41),
    externalJournalId: bytes(32, 0x42),
    externalWitnessPublicKey: bytes(32, 0x43),
    externalJournalReplicationClass: 1,
    externalJournalFailureGroupId: bytes(32, 0x45),
    externalCheckpointAgeBand: 2,
    externalJournalTopologyUrl: utf8('https://evidence.example:443/journal-topology.cenc'),
    externalJournalTopologyHash: bytes(32, 0x44),
    restoreEvidenceFeedUrl: utf8('https://evidence.example:443/restore-feed.cenc'),
    restoreEvidenceFeedId: bytes(32, 0x46),
    restoreEvidenceCheckpointSequence: 1n,
    restoreEvidenceCheckpointHash: bytes(32, 0x47),
    acknowledgedRpoBand: 1,
    targetRtoBand: 2,
    redundancyClass: 2,
    restoreDrillAgeBand: 4
  }
  const encodedDurability = encodeCanonical(durabilityProfileV1, durability)
  t.ok(encodedDurability.byteLength > 250)
  t.is(decodeCanonical(durabilityProfileV1, encodedDurability).restoreDrillAgeBand, 4)
  t.exception(() => encodeCanonical(durabilityProfileV1, { ...durability, profileId: 3 }), /outside 1..2/)
  t.exception(() => encodeCanonical(durabilityProfileV1, { ...durability, externalJournalReplicationClass: 2 }), /outside 0..1/)
  t.exception(() => encodeCanonical(durabilityProfileV1, { ...durability, externalCheckpointAgeBand: 8 }), /outside 0..7/)
  t.exception(() => encodeCanonical(durabilityProfileV1, {
    ...durability,
    externalJournalTopologyUrl: utf8('http://evidence.example:80/journal-topology.cenc')
  }), /must use HTTPS/)
  t.exception(() => encodeCanonical(durabilityProfileV1, { ...durability, acknowledgedRpoBand: 4 }), /outside 0..3/)
  t.exception(() => encodeCanonical(durabilityProfileV1, { ...durability, restoreDrillAgeBand: 8 }), /outside 0..7/)
  t.exception(() => encodeCanonical(durabilityProfileV1, {
    ...durability,
    externalJournalId: bytes(32, 0)
  }), /requires its nonzero external journal topology tuple/)
  t.exception(() => encodeCanonical(durabilityProfileV1, {
    ...durability,
    externalWitnessPublicKey: bytes(32, 0)
  }), /requires its nonzero external journal topology tuple/)

  const build = {
    specHash: bytes(32, 0x51),
    abiHash: bytes(32, 0x52),
    vectorSetHash: bytes(32, 0x53),
    evidenceFormatHash: bytes(32, 0x54),
    evidenceVectorSetHash: bytes(32, 0x55),
    storeFormatHash: bytes(32, 0x56),
    storeVectorSetHash: bytes(32, 0x57),
    privateIpcFormatHash: bytes(32, 0x5a),
    privateIpcVectorSetHash: bytes(32, 0x5b),
    buildArtifactHash: bytes(32, 0x58),
    buildArtifactUrl: utf8('https://evidence.example:443/artifact.cenc'),
    buildManifestUrl: utf8('https://evidence.example:443/build.cenc'),
    buildManifestHash: bytes(32, 0x59),
    releaseEvidenceBundleUrl: utf8('https://evidence.example:443/release.cenc'),
    releaseEvidenceBundleHash: bytes(32, 0x5c),
    releaseSupportHorizonHash: bytes(32, 0x5d),
    runtimeBoundaryEvidenceUrl: utf8('https://evidence.example:443/runtime-boundary.cenc'),
    runtimeBoundaryEvidenceHash: bytes(32, 0x5e)
  }
  const encodedBuild = encodeCanonical(buildProfileV1, build)
  t.ok(encodedBuild.byteLength > 500)
  t.alike(decodeCanonical(buildProfileV1, encodedBuild).buildManifestUrl, build.buildManifestUrl)
  t.exception(() => encodeCanonical(buildProfileV1, { ...build, buildManifestUrl: null }), /must be bytes/)
  t.exception(() => encodeCanonical(buildProfileV1, {
    ...build,
    buildManifestUrl: utf8('http://evidence.example:80/build.cenc')
  }), /must use HTTPS/)
})
