import test from 'brittle'
import b4a from 'b4a'
import { decodeCanonical, encodeCanonical } from '../codec.js'
import {
  blindArtifactFileInventoryV1,
  blindExecutableEntrypointCatalogV1,
  blindLaunchTopologyV1,
  blindListenerCatalogV1,
  blindListenerEntryV1,
  blindProcessInspectionEvidenceV1,
  blindProductDistributionBundleV1,
  blindProductIsolationEvidenceV1,
  blindProductIsolationReportBundleV1,
  blindReleaseEvidenceBundleV1,
  blindReleaseSupportHorizonV1,
  blindRouteAbsenceEvidenceV1,
  blindRuntimeBoundaryEvidenceV1,
  blindRuntimeImportGraphV1,
  buildInputV1,
  buildManifestV1,
  buildReproductionAttestationV1,
  hiveRelayCompatibilityAuthorityTransitionV1,
  hiveRelayCompatibilityBuildManifestV1,
  hiveRelayCompatibilityRuntimeBoundaryEvidenceV1,
  hiveRelayCompatibilitySunsetGenesisV1,
  hiveRelayCompatibilitySunsetHeadV1,
  hiveRelayLegacyCompatibilitySunsetV1,
  reproductionEnvironmentV1,
  toolchainEntryV1,
  toolchainManifestV1
} from '../evidence-schemas.js'

const bytes = (length, fill) => b4a.alloc(length, fill)
const text = value => b4a.from(value, 'utf8')
const hash = fill => bytes(32, fill)
const signature = fill => bytes(64, fill)
const url = path => text(`https://evidence.example:443/${path}`)

function publicListener (componentId = 1) {
  return {
    componentId,
    listenerClass: 1,
    transportId: 1,
    endpointId: 1,
    addressOrSocket: text('0.0.0.0'),
    port: 443,
    ownerUid: componentId === 3 ? 2003 : 2001
  }
}

function buildInput () {
  return { path: text('src/main.js'), byteLength: 12n, contentHash: hash(0x10) }
}

function buildManifest () {
  const buildArtifactHash = hash(0x2f)
  return {
    version: 1,
    productMode: 1,
    implementationId: text('hiverelay-blind'),
    implementationVersion: text('1.0.0'),
    sourceRevision: text('0123456789abcdef'),
    sourceTreeHash: hash(0x20),
    implementationSpecHash: hash(0x21),
    specHash: hash(0x22),
    abiHash: hash(0x23),
    vectorSetHash: hash(0x24),
    evidenceFormatHash: hash(0x25),
    evidenceVectorSetHash: hash(0x26),
    storeFormatHash: hash(0x27),
    storeVectorSetHash: hash(0x28),
    privateIpcFormatHash: hash(0x29),
    privateIpcVectorSetHash: hash(0x2a),
    toolchainManifestHash: hash(0x2b),
    dependencyLockHash: hash(0x2c),
    sbomHash: null,
    artifactFormat: 1,
    inputs: [buildInput()],
    buildArtifactHash,
    launchTopologyHash: hash(0x30),
    releaseSupportHorizonHash: hash(0x31),
    productIsolationEvidenceHash: hash(0x32),
    reproductionPolicyId: 1,
    reproductions: [{
      builderPublicKey: hash(0x33),
      environmentHash: hash(0x34),
      reproducedArtifactHash: buildArtifactHash,
      signature: signature(0x35)
    }],
    releaseSignerPublicKey: hash(0x36),
    releaseSignature: signature(0x37)
  }
}

function launchTopology () {
  const daemonArtifact = hash(0x43)
  return {
    version: 1,
    buildArtifactHash: hash(0x40),
    privateIpcFormatHash: hash(0x41),
    privateIpcVectorSetHash: hash(0x42),
    components: [{
      componentId: 1,
      componentArtifactHash: hash(0x44),
      entrypointPath: text('bin/edge'),
      entrypointContentHash: hash(0x45),
      serviceUnitPath: text('units/edge.service'),
      serviceUnitContentHash: hash(0x46),
      uid: 2001,
      gid: 2001,
      readOnlyMounts: [text('/etc/edge')],
      writableMounts: [],
      publicListenerFamilyBits: 0x1f,
      allowedChildEntrypointHashes: []
    }, {
      componentId: 2,
      componentArtifactHash: daemonArtifact,
      entrypointPath: text('bin/daemon'),
      entrypointContentHash: hash(0x47),
      serviceUnitPath: text('units/daemon.service'),
      serviceUnitContentHash: hash(0x48),
      uid: 2002,
      gid: 2002,
      readOnlyMounts: [text('/etc/daemon')],
      writableMounts: [text('/run'), text('/data')],
      publicListenerFamilyBits: 0,
      allowedChildEntrypointHashes: [hash(0x49)]
    }],
    ipcUnarySocketPath: text('/run/blind/unary.sock'),
    ipcStreamSocketPath: text('/run/blind/stream.sock'),
    ipcOwnerUid: 2002,
    ipcPeerUid: 2001,
    ipcGroupGid: 2999,
    ipcMode: 0x01b0,
    launcherKind: 1,
    defaultCommand: [text('bin/launch')],
    initializers: [{
      initializerId: 1,
      componentArtifactHash: daemonArtifact,
      argv: [text('bin/init')],
      uid: 0,
      gid: 0,
      capabilityBits: 7n,
      networkDisabled: 1,
      rootFilesystemReadOnly: 1,
      noNewPrivileges: 1,
      maxPids: 32,
      writableMounts: [text('/run'), text('/data')],
      targets: [{ targetKind: 1, path: text('/run'), finalUid: 2002, finalGid: 2002, finalMode: 0x01e8 },
        { targetKind: 2, path: text('/data'), finalUid: 2002, finalGid: 2002, finalMode: 0x01c0 }],
      maxRuntimeMillis: 60000
    }],
    releaseSignerPublicKey: hash(0x4a),
    signature: signature(0x4b)
  }
}

function processInspection () {
  return {
    version: 1,
    buildArtifactHash: hash(0x60),
    launchTopologyHash: hash(0x61),
    observedFromUnixMillis: 1n,
    observedThroughUnixMillis: 4n,
    completedInitializers: [{
      initializerId: 1,
      componentArtifactHash: hash(0x62),
      argv: [text('bin/init')],
      uid: 0,
      gid: 0,
      startedUnixMillis: 2n,
      endedUnixMillis: 3n,
      exitCode: 0,
      observedCapabilityBits: 7n,
      networkDisabled: 1,
      rootFilesystemReadOnly: 1,
      noNewPrivileges: 1,
      pidsLimit: 32,
      observedPeakPids: 1,
      writableMounts: [text('/run'), text('/data')],
      targetsAfter: [{
        targetKind: 1,
        path: text('/run'),
        finalUid: 2002,
        finalGid: 2002,
        finalMode: 0x01e8,
        inodeKind: 1,
        symlinkFree: 1
      }, {
        targetKind: 2,
        path: text('/data'),
        finalUid: 2002,
        finalGid: 2002,
        finalMode: 0x01c0,
        inodeKind: 1,
        symlinkFree: 1
      }]
    }],
    processes: [{
      processOrdinal: 1,
      componentId: 1,
      parentProcessOrdinal: null,
      uid: 2001,
      gid: 2001,
      executablePath: text('bin/edge'),
      executableContentHash: hash(0x63),
      argv: [text('bin/edge')],
      environmentNames: [],
      mounts: []
    }, {
      processOrdinal: 2,
      componentId: 2,
      parentProcessOrdinal: null,
      uid: 2002,
      gid: 2002,
      executablePath: text('bin/daemon'),
      executableContentHash: hash(0x64),
      argv: [text('bin/daemon')],
      environmentNames: [],
      mounts: []
    }]
  }
}

function runtimeBoundary () {
  return {
    version: 1,
    buildArtifactHash: hash(0x70),
    buildManifestHash: hash(0x71),
    launchTopologyHash: hash(0x72),
    componentProcesses: [{
      componentId: 1,
      entrypointPath: text('bin/edge'),
      entrypointBytes: bytes(1, 1),
      serviceUnitPath: text('units/edge.service'),
      serviceUnitBytes: bytes(1, 2),
      uid: 2001,
      gid: 2001
    }, {
      componentId: 2,
      entrypointPath: text('bin/daemon'),
      entrypointBytes: bytes(1, 3),
      serviceUnitPath: text('units/daemon.service'),
      serviceUnitBytes: bytes(1, 4),
      uid: 2002,
      gid: 2002
    }],
    listeners: [publicListener()],
    descriptorProtocolId: text('hiverelay-blind/1'),
    descriptorSigningPublicKey: hash(0x73),
    discoveryTopic: hash(0x74),
    publicCredentials: [{ credentialClass: 1, canonicalPublicBytes: bytes(1, 5) }],
    storageRoots: [{ componentId: 2, path: text('/data'), rootClass: text('data'), encryptionPublicKey: null }],
    releaseChannelUrl: url('blind/releases'),
    releaseChannelPublicKey: hash(0x75),
    observability: [{ componentId: 1, logSinkId: text('logs'), logNamespace: text('edge'), metricSinkId: text('metrics'), metricNamespace: text('edge') },
      { componentId: 2, logSinkId: text('logs'), logNamespace: text('daemon'), metricSinkId: text('metrics'), metricNamespace: text('daemon') }],
    deploymentId: hash(0x76),
    observedFromUnixMillis: 1n,
    observedThroughUnixMillis: 2n,
    issuedUnixMillis: 3n,
    expiresUnixMillis: 4n,
    evidenceSignerPublicKey: hash(0x77),
    signature: signature(0x78)
  }
}

function supportHorizon () {
  return {
    version: 1,
    buildArtifactHash: hash(0x80),
    specHash: hash(0x81),
    abiHash: hash(0x82),
    vectorSetHash: hash(0x83),
    evidenceFormatHash: hash(0x84),
    evidenceVectorSetHash: hash(0x85),
    storeFormatHash: hash(0x86),
    storeVectorSetHash: hash(0x87),
    privateIpcFormatHash: hash(0x88),
    privateIpcVectorSetHash: hash(0x89),
    issuedUnixMillis: 1n,
    activationNotBeforeUnixMillis: 2n,
    fullSupportThroughUnixMillis: 3n,
    upgradeMode: 1,
    predecessors: [],
    releaseSignerPublicKey: hash(0x8a),
    signature: signature(0x8b)
  }
}

function compatibilityBoundary () {
  return {
    version: 1,
    compatibilityProductId: text('legacy-v1'),
    compatibilityArtifactHash: hash(0x90),
    compatibilityBuildManifestHash: hash(0x91),
    entrypointPath: text('bin/legacy'),
    entrypointBytes: bytes(1, 1),
    serviceUnitPath: text('units/legacy.service'),
    serviceUnitBytes: bytes(1, 2),
    processUid: 2003,
    processGid: 2003,
    processArgv: [text('bin/legacy')],
    listeners: [publicListener(3)],
    descriptorProtocolId: text('hiverelay-legacy/1'),
    descriptorSigningPublicKey: hash(0x92),
    discoveryTopic: hash(0x93),
    publicCredentials: [{ credentialClass: 1, canonicalPublicBytes: bytes(1, 3) }],
    storageRoots: [{ path: text('/legacy'), rootClass: text('data'), encryptionPublicKey: null }],
    releaseChannelUrl: url('legacy/releases'),
    releaseChannelPublicKey: hash(0x94),
    logSinkId: text('logs'),
    logNamespace: text('legacy'),
    metricSinkId: text('metrics'),
    metricNamespace: text('legacy'),
    deploymentId: hash(0x95),
    observedFromUnixMillis: 1n,
    observedThroughUnixMillis: 2n,
    successorBuildArtifactHash: hash(0x96),
    successorBuildManifestHash: hash(0x97),
    successorBuildManifestBytes: bytes(1, 4),
    successorBlindRuntimeBoundaryEvidenceBytes: bytes(1, 5),
    disjointBoundaryBits: 0x07ff,
    issuedUnixMillis: 3n,
    expiresUnixMillis: 4n,
    evidenceSignerPublicKey: hash(0x98),
    signature: signature(0x99)
  }
}

function catalogFixtures () {
  const graphNode1 = { nodeId: hash(1), componentId: 1, path: text('edge.js'), contentHash: hash(3), importedNodeIds: [] }
  const graphNode2 = { nodeId: hash(2), componentId: 2, path: text('daemon.js'), contentHash: hash(4), importedNodeIds: [] }
  const genesisHash = hash(0xa0)
  return [
    ['BuildInputV1', buildInputV1, buildInput()],
    ['ToolchainEntryV1', toolchainEntryV1, { name: text('bare'), version: text('1.0.0'), distributionHash: hash(0x11) }],
    ['ToolchainManifestV1', toolchainManifestV1, { version: 1, entries: [{ name: text('bare'), version: text('1.0.0'), distributionHash: hash(0x11) }] }],
    ['ReproductionEnvironmentV1', reproductionEnvironmentV1, {
      version: 1,
      os: text('linux'),
      architecture: text('x64'),
      containerOrVmHash: hash(0x12),
      sourceDateEpoch: 1n,
      locale: text('C'),
      timezone: text('UTC'),
      variables: [{ name: text('SOURCE_DATE_EPOCH'), valueHash: hash(0x13) }]
    }],
    ['BuildReproductionAttestationV1', buildReproductionAttestationV1, {
      version: 1,
      builderPublicKey: hash(0x14),
      environmentHash: hash(0x15),
      unsignedBuildCommitment: hash(0x16),
      reproducedArtifactHash: hash(0x17)
    }],
    ['BlindProductDistributionBundleV1', blindProductDistributionBundleV1, {
      version: 1,
      artifactFormat: 1,
      edgeComponentDistributionBytes: bytes(1, 1),
      daemonComponentDistributionBytes: bytes(1, 2),
      packagingFiles: [{ path: text('a'), mode: 0x01a4, fileBytes: bytes(1, 3) },
        { path: text('b'), mode: 0x01a4, fileBytes: bytes(1, 4) }]
    }],
    ['BuildManifestV1', buildManifestV1, buildManifest()],
    ['BlindLaunchTopologyV1', blindLaunchTopologyV1, launchTopology()],
    ['BlindArtifactFileInventoryV1', blindArtifactFileInventoryV1, {
      version: 1,
      buildArtifactHash: hash(0x50),
      files: [{ componentId: 1, path: text('bin/edge'), mode: 0x01ed, byteLength: 1n, contentHash: hash(0x51) }]
    }],
    ['BlindExecutableEntrypointCatalogV1', blindExecutableEntrypointCatalogV1, {
      version: 1,
      buildArtifactHash: hash(0x52),
      launchTopologyHash: hash(0x53),
      entries: [{ componentId: 1, componentArtifactHash: hash(0x54), entrypointPath: text('bin/edge'), entrypointContentHash: hash(0x55), argvPrefix: [text('bin/edge')] },
        { componentId: 2, componentArtifactHash: hash(0x56), entrypointPath: text('bin/daemon'), entrypointContentHash: hash(0x57), argvPrefix: [text('bin/daemon')] }]
    }],
    ['BlindRuntimeImportGraphV1', blindRuntimeImportGraphV1, { version: 1, buildArtifactHash: hash(0x58), entrypointNodeIds: [graphNode1.nodeId, graphNode2.nodeId], nodes: [graphNode1, graphNode2] }],
    ['BlindListenerEntryV1', blindListenerEntryV1, publicListener()],
    ['BlindListenerCatalogV1', blindListenerCatalogV1, {
      version: 1,
      buildArtifactHash: hash(0x59),
      launchTopologyHash: hash(0x5a),
      observedFromUnixMillis: 1n,
      observedThroughUnixMillis: 2n,
      listeners: [publicListener()]
    }],
    ['BlindRouteAbsenceEvidenceV1', blindRouteAbsenceEvidenceV1, {
      version: 1,
      buildArtifactHash: hash(0x5b),
      abiHash: hash(0x5c),
      evidenceVectorSetHash: hash(0x5d),
      allowedRoutes: [{ method: text('GET'), path: text('/blind/v1'), familyId: 1 }],
      negativeProbes: [{ method: text('GET'), path: text('/legacy/v0'), expectedStatus: 404, observedStatus: 404, responseBodyBytes: bytes(0, 0) }]
    }],
    ['BlindProcessInspectionEvidenceV1', blindProcessInspectionEvidenceV1, processInspection()],
    ['BlindProductIsolationReportBundleV1', blindProductIsolationReportBundleV1, {
      version: 1,
      artifactFileInventoryBytes: bytes(1, 1),
      executableEntrypointBytes: bytes(1, 2),
      runtimeImportGraphBytes: bytes(1, 3),
      listenerCatalogBytes: bytes(1, 4),
      routeAbsenceEvidenceBytes: bytes(1, 5),
      processInspectionBytes: bytes(1, 6)
    }],
    ['BlindProductIsolationEvidenceV1', blindProductIsolationEvidenceV1, {
      version: 1,
      productMode: 1,
      buildArtifactHash: hash(0x65),
      launchTopologyHash: hash(0x66),
      artifactFileInventoryHash: hash(0x67),
      executableEntryPointHash: hash(0x68),
      runtimeImportGraphHash: hash(0x69),
      listenerCatalogHash: hash(0x6a),
      forbiddenComponentPresenceBits: 0,
      routeAbsenceEvidenceHash: hash(0x6b),
      processInspectionEvidenceHash: hash(0x6c),
      isolationReportBundleHash: hash(0x6d),
      issuedUnixMillis: 1n,
      evidenceSignerPublicKey: hash(0x6e),
      signature: signature(0x6f)
    }],
    ['BlindRuntimeBoundaryEvidenceV1', blindRuntimeBoundaryEvidenceV1, runtimeBoundary()],
    ['BlindReleaseSupportHorizonV1', blindReleaseSupportHorizonV1, supportHorizon()],
    ['BlindReleaseEvidenceBundleV1', blindReleaseEvidenceBundleV1, {
      version: 1,
      buildManifestBytes: bytes(1, 1),
      launchTopologyBytes: bytes(1, 2),
      isolationEvidenceBytes: bytes(1, 3),
      isolationReportBundleBytes: bytes(1, 4),
      releaseSupportHorizonBytes: bytes(1, 5),
      privateIpcRegistryBytes: bytes(1, 6),
      privateIpcVectorManifestBytes: bytes(1, 7),
      releaseCompatibilityVectorManifestBytes: [],
      toolchainManifestBytes: bytes(1, 8),
      reproductionEnvironmentBytes: [bytes(1, 9)],
      dependencyLockBytes: bytes(1, 10),
      sbomBytes: null
    }],
    ['HiveRelayCompatibilityBuildManifestV1', hiveRelayCompatibilityBuildManifestV1, {
      version: 1,
      productMode: 2,
      compatibilityProductId: text('legacy-v1'),
      implementationVersion: text('1.0.0'),
      sourceRevision: text('0123456789abcdef'),
      sourceTreeHash: hash(0xa1),
      inputs: [buildInput()],
      toolchainManifestHash: hash(0xa2),
      dependencyLockHash: hash(0xa3),
      compatibilityArtifactFormat: 1,
      compatibilityArtifactUrl: url('legacy.bundle'),
      compatibilityArtifactHash: hash(0xa4),
      sunsetChainGenesisHash: genesisHash,
      sunsetGenesisUrl: url('sunset/genesis.cenc'),
      sunsetLatestUrl: url('sunset/head/latest.cenc'),
      releaseSignerPublicKey: hash(0xa5),
      releaseSignature: signature(0xa6)
    }],
    ['HiveRelayCompatibilitySunsetGenesisV1', hiveRelayCompatibilitySunsetGenesisV1, {
      version: 1,
      compatibilityProductId: text('legacy-v1'),
      sunsetChainId: hash(0xa7),
      sunsetSequence: 0n,
      successorSpecHash: hash(0xa8),
      successorAbiHash: hash(0xa9),
      successorVectorSetHash: hash(0xaa),
      genesisAuthoritySequence: 0n,
      genesisAuthorityPublicKey: hash(0xab),
      genesisAuthorityKeyId: hash(0xac),
      sunsetHistoryBaseUrl: url('sunset'),
      issuedUnixMillis: 1n,
      lastWriteUnixMillis: 2n,
      lastReadUnixMillis: 3n,
      releaseChannelPublicKey: hash(0xad),
      signature: signature(0xae)
    }],
    ['HiveRelayLegacyCompatibilitySunsetV1', hiveRelayLegacyCompatibilitySunsetV1, {
      version: 1,
      compatibilityProductId: text('legacy-v1'),
      sunsetChainGenesisHash: genesisHash,
      sunsetChainId: hash(0xaf),
      sunsetSequence: 1n,
      compatibilityArtifactUrl: url('legacy.bundle'),
      compatibilityArtifactHash: hash(0xb0),
      compatibilityBuildManifestUrl: url('legacy-manifest.cenc'),
      compatibilityBuildManifestHash: hash(0xb1),
      compatibilityRuntimeBoundaryEvidenceUrl: url('legacy-boundary.cenc'),
      compatibilityRuntimeBoundaryEvidenceHash: hash(0xb2),
      successorSpecHash: hash(0xb3),
      successorAbiHash: hash(0xb4),
      successorVectorSetHash: hash(0xb5),
      successorBuildArtifactHash: hash(0xb6),
      successorBuildManifestHash: hash(0xb7),
      successorLaunchTopologyHash: hash(0xb8),
      successorIsolationEvidenceHash: hash(0xb9),
      successorRuntimeBoundaryEvidenceHash: hash(0xba),
      issuedUnixMillis: 1n,
      lastWriteUnixMillis: 2n,
      lastReadUnixMillis: 3n,
      previousSunsetHash: genesisHash,
      releaseAuthoritySequence: 0n,
      releaseAuthorityPublicKey: hash(0xbb),
      releaseAuthorityKeyId: hash(0xbc),
      authorityTransitionHash: null,
      signature: signature(0xbd)
    }],
    ['HiveRelayCompatibilitySunsetHeadV1', hiveRelayCompatibilitySunsetHeadV1, {
      version: 1,
      compatibilityProductId: text('legacy-v1'),
      sunsetChainGenesisHash: genesisHash,
      sunsetChainId: hash(0xbe),
      sunsetSequence: 1n,
      sunsetHash: hash(0xbf),
      compatibilityBuildManifestHash: hash(0xc0),
      headLeaseSlot: 1n,
      issuedUnixMillis: 299000n,
      notBeforeUnixMillis: 300000n,
      expiresUnixMillis: 600000n,
      releaseAuthoritySequence: 0n,
      releaseAuthorityKeyId: hash(0xc1),
      signature: signature(0xc2)
    }],
    ['HiveRelayCompatibilityAuthorityTransitionV1', hiveRelayCompatibilityAuthorityTransitionV1, {
      version: 1,
      compatibilityProductId: text('legacy-v1'),
      sunsetChainGenesisHash: genesisHash,
      sunsetChainId: hash(0xc3),
      successorSpecHash: hash(0xc4),
      successorAbiHash: hash(0xc5),
      successorVectorSetHash: hash(0xc6),
      previousSunsetHash: hash(0xc7),
      previousSunsetSequence: 1n,
      nextSunsetSequence: 2n,
      previousAuthoritySequence: 0n,
      nextAuthoritySequence: 1n,
      previousPublicKey: hash(0xc8),
      nextPublicKey: hash(0xc9),
      previousKeyId: hash(0xca),
      nextKeyId: hash(0xcb),
      validFromSunsetSequence: 2n,
      previousKeySignature: signature(0xcc),
      nextKeySignature: signature(0xcd)
    }],
    ['HiveRelayCompatibilityRuntimeBoundaryEvidenceV1', hiveRelayCompatibilityRuntimeBoundaryEvidenceV1, compatibilityBoundary()]
  ]
}

test('evidence schema catalog: all 26 master declarations round-trip canonically', t => {
  const fixtures = catalogFixtures()
  t.is(fixtures.length, 26)
  for (const [name, encoding, value] of fixtures) {
    const encoded = encodeCanonical(encoding, value)
    const decoded = decodeCanonical(encoding, encoded, { copyBytes: true })
    t.alike(decoded, value, `${name} round-trips`)
    t.alike(encodeCanonical(encoding, decoded), encoded, `${name} re-encodes byte exactly`)
  }
})

test('evidence schema catalog: stable-master closed invariants fail at the codec boundary', t => {
  const horizon = supportHorizon()
  const decodedHorizon = decodeCanonical(blindReleaseSupportHorizonV1, encodeCanonical(blindReleaseSupportHorizonV1, horizon))
  t.alike(Object.keys(decodedHorizon), [
    'version',
    'buildArtifactHash',
    'specHash',
    'abiHash',
    'vectorSetHash',
    'evidenceFormatHash',
    'evidenceVectorSetHash',
    'storeFormatHash',
    'storeVectorSetHash',
    'privateIpcFormatHash',
    'privateIpcVectorSetHash',
    'issuedUnixMillis',
    'activationNotBeforeUnixMillis',
    'fullSupportThroughUnixMillis',
    'upgradeMode',
    'predecessors',
    'releaseSignerPublicKey',
    'signature'
  ], 'support horizon has the exact 18 master fields once each')

  t.ok(encodeCanonical(blindListenerEntryV1, publicListener(3)), 'shared listener entry admits compatibility component 3')
  t.exception(() => encodeCanonical(blindListenerCatalogV1, {
    version: 1,
    buildArtifactHash: hash(1),
    launchTopologyHash: hash(2),
    observedFromUnixMillis: 1n,
    observedThroughUnixMillis: 2n,
    listeners: [publicListener(3)]
  }), /cannot contain legacy compatibility/)

  t.exception(() => encodeCanonical(hiveRelayCompatibilityRuntimeBoundaryEvidenceV1, {
    ...compatibilityBoundary(),
    disjointBoundaryBits: 0x03ff
  }), /must be 2047/)

  t.exception(() => encodeCanonical(blindReleaseEvidenceBundleV1, {
    ...catalogFixtures().find(([name]) => name === 'BlindReleaseEvidenceBundleV1')[2],
    reproductionEnvironmentBytes: [bytes(2, 2), bytes(1, 1)]
  }), /strictly sorted/)

  const manifest = buildManifest()
  t.exception(() => encodeCanonical(buildManifestV1, {
    ...manifest,
    reproductions: [{ ...manifest.reproductions[0], reproducedArtifactHash: hash(0xff) }]
  }), /must equal buildArtifactHash/)

  const graph = catalogFixtures().find(([name]) => name === 'BlindRuntimeImportGraphV1')[2]
  t.exception(() => encodeCanonical(blindRuntimeImportGraphV1, {
    ...graph,
    nodes: [{ ...graph.nodes[0], importedNodeIds: [graph.nodes[1].nodeId] }, graph.nodes[1]]
  }), /crosses component boundaries/)

  t.exception(() => encodeCanonical(blindRuntimeBoundaryEvidenceV1, {
    ...runtimeBoundary(),
    observedThroughUnixMillis: 4n,
    issuedUnixMillis: 3n
  }), /times are invalid/)
})
