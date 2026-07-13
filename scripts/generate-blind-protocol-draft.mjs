import fs from 'fs'
import path from 'path'
import process from 'process'
import b4a from 'b4a'
import {
  ADMISSION_CONFORMANCE_CLASS,
  ADMISSION_COST_RULES,
  AUXILIARY_SIGNATURE_DOMAIN_ID,
  ABI_STATUS,
  CELL_RECEIPT_RESULT,
  CELL_SIZE_CLASS,
  CLOCK_UNSAFE_OPERATION_BITS,
  CORE_ACK_RESULT,
  CORE_SESSION_CLASS,
  DISPATCH_LIMITS,
  DOMAIN_PURPOSE,
  DOMAIN_RECIPE,
  DOMAIN_REGISTRY,
  ENDPOINT_LIMITS,
  ERROR_PROFILE_ID,
  ERROR_RETRY_AFTER_MODE,
  ERROR_PROFILE_ROWS,
  EXECUTABLE_SCHEMA_CODEC_STATUS,
  FAMILY,
  FAMILY_ROUTES,
  FORWARD_CIRCUIT_CLASS,
  FORWARD_CLOSE_KIND,
  FRAME_KIND,
  HEALTH_CLOCK_STATE,
  HEALTH_INTEGRITY_STATE,
  HEALTH_REBALANCE_STATE,
  INBOX_APPEND_AUTH_MODE,
  INBOX_APPEND_RESULT,
  INBOX_FRAME_CLASS,
  INBOX_MANAGE_OPERATION,
  INBOX_RECEIPT_RESULT,
  OPERATION,
  OUTER_CLASS,
  PROTOCOL,
  OPERATION_PROFILE_ROWS,
  PUBLIC_PROFILE_LIMITS,
  REQUEST_COMMITMENT_DOMAIN_ID,
  RESULT_SIGNATURE_DOMAIN_ID,
  SCHEMA_CATEGORY,
  SCHEMA_NAMES_BY_CATEGORY,
  STORE_LIFECYCLE_STATE,
  STREAM_TRANSITION,
  STORE_FORMAT_AUTHORITY_V1,
  STREAM_WIRE_CLASS,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  WIRE_EXECUTABLE_SCHEMA_CODEC_STATUS,
  assertMasterSchemaInventory,
  admissionParametersV1,
  admissionProfileV1,
  admissionCostRuleV1,
  batchGetEntriesCommitment,
  batchGetResultV1,
  batchGetSignaturePayloadV1,
  batchGetV1,
  blindCoreAckV1,
  blindBackupChunkManifestV1,
  blindBackupEncryptionProfileV1,
  blindBackupManifestV1,
  blindBackupRetentionTransitionV1,
  blindCleanRestoreEvidenceV1,
  blindControlStateSnapshotV1,
  blindDhtPointerV1,
  blindExternalJournalTopologyV1,
  blindExternalCommitWitnessV1,
  blindForwardCloseV1,
  blindForwardDataV1,
  blindForwardOpenResultV1,
  blindForwardOpenV1,
  blindForwardWindowV1,
  blindHealthChallengeV1,
  blindHealthResultV1,
  blindLocalCheckpointV1,
  blindOhttpKeyConfigV1,
  blindRestoreEvidenceBundleV1,
  blindRestoreEvidenceHeadV1,
  blindServiceDescriptorV1,
  blindStreamChunkPlainV1,
  blindWalHeaderV2,
  blake2b256,
  cellPutRequestCommitment,
  cellStorageSlot,
  coreMirrorRequestV1,
  coreMirrorRequestCommitment,
  coreServeChallengeV1,
  coreServeRequestCommitment,
  coreServeResultV1,
  compileMasterSchemaCatalog,
  compileMasterSchemaCatalogForCategory,
  controlSnapshotHash,
  domainRegistryEntryV1,
  durabilityContinuityBindingV1,
  encodeCanonical,
  encodeDispatchFrame,
  encodeWireAbiRegistry,
  encodeOuterEnvelope,
  encodeSchemaCatalog,
  encodeStoreFormatAuthorityV1,
  encodeVectorManifest,
  errorProfileEntryV1,
  forwardOpenRequestCommitment,
  getCellResultV1,
  hashAbi,
  hashEvidenceFormat,
  hashEvidenceVectorSet,
  hashSpec,
  hashStoreFormat,
  hashStoreVectorSet,
  hashVectorSet,
  inboxAppendV1,
  inboxPhysicalTopic,
  inboxReadEntriesCommitment,
  inboxReadRequestCommitment,
  inboxReadResultV1,
  inboxReadSignaturePayloadV1,
  operationProfileV1,
  persistentResultCommitment,
  putCellV1,
  relayResultBindingV1,
  relayIdentityTransitionV1,
  schemaCatalogEntryV1
} from '@hiverelay/blind-protocol'

const root = process.cwd()
const check = process.argv.includes('--check')
const wireOnly = process.argv.includes('--wire-only')
const forbidNonWireFixtures = process.argv.includes('--forbid-non-wire-fixtures')

function nonWireFixture (label, buildFixture) {
  if (forbidNonWireFixtures) throw new Error(`WIRE-only generation evaluated non-WIRE fixture: ${label}`)
  return buildFixture()
}

function canonicalTextBytes (relative) {
  const file = path.join(root, ...relative)
  const bytes = fs.readFileSync(file)
  if (bytes.length === 0 || bytes[bytes.length - 1] !== 0x0a || bytes.includes(0x0d) ||
      (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf)) {
    throw new Error('canonical protocol text is not UTF-8/LF/no-BOM/exact-final-LF form')
  }
  return bytes
}

const canonicalWireSpecBytes = canonicalTextBytes(['docs', 'protocol', 'HIVERELAY-BLIND-WIRE-V1.md'])
const canonicalMasterBytes = canonicalTextBytes([
  'docs', 'protocol', 'BLIND-APP-AGNOSTIC-HIVERELAY-MASTER-SPEC.md'
])
const canonicalMasterText = b4a.toString(canonicalMasterBytes, 'utf8')
const wireSchemaCatalog = compileMasterSchemaCatalogForCategory(canonicalMasterText, SCHEMA_CATEGORY.WIRE)
const masterInventoryAudit = wireOnly ? wireSchemaCatalog.inventoryAudit : assertMasterSchemaInventory(canonicalMasterText)
const masterSchemaCatalog = wireOnly ? null : compileMasterSchemaCatalog(canonicalMasterText)
if (!WIRE_EXECUTABLE_SCHEMA_CODEC_STATUS.complete ||
    WIRE_EXECUTABLE_SCHEMA_CODEC_STATUS.nonWireLeakNames.length !== 0 ||
    EXECUTABLE_SCHEMA_CODEC_STATUS.privateIpcLeakNames.length !== 0) {
  throw new Error('public WIRE catalog does not have exact executable codec coverage')
}
if (!wireOnly && !EXECUTABLE_SCHEMA_CODEC_STATUS.complete) {
  throw new Error('stable-master catalog does not have exact package-owned executable codec coverage')
}

function sameBytes (a, b) {
  return a.byteLength === b.byteLength && b4a.equals(b4a.from(a), b4a.from(b))
}

function emit (relative, bytes) {
  const file = path.join(root, relative)
  if (check) {
    if (!fs.existsSync(file)) throw new Error(`missing generated artifact: ${relative}`)
    const current = fs.readFileSync(file)
    if (!sameBytes(current, bytes)) throw new Error(`generated artifact drift: ${relative}`)
    return
  }
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, bytes)
}

function listedFiles (directory, prefix = '') {
  const output = []
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const relative = prefix === '' ? entry.name : `${prefix}/${entry.name}`
    if (entry.isDirectory()) output.push(...listedFiles(path.join(directory, entry.name), relative))
    else if (entry.isFile()) output.push(relative)
    else throw new Error(`generated vector tree contains a non-file entry: ${relative}`)
  }
  return output
}

const cellGet = encodeDispatchFrame({
  frameKind: FRAME_KIND.REQUEST,
  familyId: FAMILY.CELL,
  operationId: OPERATION.CELL.GET,
  requestId: b4a.from('00112233445566778899aabbccddeeff', 'hex'),
  body: b4a.from('01020304', 'hex')
})

const forwardData = encodeDispatchFrame({
  frameKind: FRAME_KIND.STREAM,
  familyId: FAMILY.FORWARD,
  operationId: OPERATION.FORWARD.DATA,
  requestId: b4a.alloc(16),
  streamId: 0x0102030405060708n,
  sequence: 9n,
  body: b4a.from('a0a1a2a3', 'hex')
})

const outerCellGet = encodeOuterEnvelope({ outerClass: 1, innerDispatch: cellGet }, {
  randomFill: padding => padding.fill(0xa5)
})

const invalidFlags = b4a.from(cellGet)
invalidFlags[8] = 1
const invalidOperation = b4a.from(cellGet)
invalidOperation[7] = 0xff

const bytes = (length, value) => b4a.alloc(length, value)
function relayBinding (seed, overrides = {}) {
  return {
    version: 1,
    relayPublicKey: bytes(32, seed),
    storeId: bytes(32, seed + 1),
    descriptorSequence: 9n,
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

const admission = {
  profileId: 7,
  schemeId: 9,
  parameterHash: bytes(32, 0xa1),
  token: bytes(3, 0xa2)
}
const allocationEpoch = 0x01020304
const createPublicKey = bytes(32, 0x11)
const cellBlob = bytes(4096, 0x51)
const storageSlot = cellStorageSlot({ allocationEpoch, createPublicKey })
const cellPutBody = encodeCanonical(putCellV1, {
  version: 1,
  storageSlot,
  allocationEpoch,
  sizeClass: 1,
  leaseClass: 2,
  clientNonce: bytes(32, 0x12),
  createPublicKey,
  renewPublicKey: bytes(32, 0x13),
  dropPublicKey: bytes(32, 0x14),
  declaredBlobHash: blake2b256(cellBlob),
  createSignature: bytes(64, 0x15),
  admission,
  cellBlob
})
const cellPutCommitment = cellPutRequestCommitment({
  allocationCommitment: bytes(32, 0x16),
  clientNonce: bytes(32, 0x12)
})

const batchSlots = [bytes(32, 0x21), bytes(32, 0x22)]
const batchRequestBody = encodeCanonical(batchGetV1, {
  version: 1,
  clientNonce: bytes(32, 0x23),
  slots: batchSlots,
  admission: null
})
const duplicateBatchSlots = b4a.from(batchRequestBody)
b4a.copy(duplicateBatchSlots.subarray(34, 66), duplicateBatchSlots, 66)
const batchEntries = [{ status: 0 }, { status: 1, sizeClass: 1, cellBlob }]
const batchResultBody = encodeCanonical(batchGetResultV1, {
  version: 1,
  relayBinding: relayBinding(0x24),
  requestNonce: bytes(32, 0x23),
  requestCommitment: bytes(32, 0x25),
  entries: batchEntries,
  entriesCommitment: batchGetEntriesCommitment(batchEntries),
  signature: bytes(64, 0x26)
})
const batchPersistentResultCommitment = persistentResultCommitment(
  FAMILY.CELL,
  OPERATION.CELL.BATCH_GET,
  batchResultBody.subarray(0, batchResultBody.byteLength - 64)
)
const invalidBatchTag = b4a.from(batchResultBody)
invalidBatchTag[277] = 2

const getResultBody = encodeCanonical(getCellResultV1, { version: 1, sizeClass: 1, cellBlob })
const invalidGetClass = b4a.from(getResultBody)
invalidGetClass[1] = 0

const inboxAllocationEpoch = 0x05060708
const inboxCreatePublicKey = bytes(32, 0x31)
const physicalTopic = inboxPhysicalTopic({
  allocationEpoch: inboxAllocationEpoch,
  createPublicKey: inboxCreatePublicKey
})
const inboxFrame = bytes(4096, 0x32)
const inboxAppendBody = encodeCanonical(inboxAppendV1, {
  version: 1,
  physicalTopic,
  frameClass: 1,
  frameHash: blake2b256(inboxFrame),
  clientNonce: bytes(32, 0x33),
  appendSignature: null,
  admission,
  frame: inboxFrame
})
const emptyInboxEntries = []
const inboxReadResultBody = encodeCanonical(inboxReadResultV1, {
  version: 1,
  relayBinding: relayBinding(0x34),
  requestNonce: bytes(32, 0x35),
  requestCommitment: bytes(32, 0x36),
  snapshotRevision: 0n,
  entries: emptyInboxEntries,
  entriesCommitment: inboxReadEntriesCommitment(emptyInboxEntries),
  nextCursor: null,
  signature: bytes(64, 0x37)
})
const inboxReadCommitment = inboxReadRequestCommitment({
  relayPublicKey: bytes(32, 0x34),
  physicalTopic,
  cursor: b4a.from('a0a1a2', 'hex'),
  limit: 64,
  clientNonce: bytes(32, 0x35)
})
const invalidInboxCursor = b4a.concat([
  b4a.from([1]),
  physicalTopic,
  b4a.from([129]),
  bytes(129, 0x38),
  b4a.from([0, 1]),
  bytes(32, 0x39),
  b4a.from([0])
])

const admissionProfile = {
  profileId: 7,
  schemeId: 9,
  conformanceClass: 1,
  roleBits: 1,
  parameterUrl: b4a.from('https://evidence.example:443/admission.cenc'),
  parameterHash: bytes(32, 0x40)
}
const admissionProfileBody = encodeCanonical(admissionProfileV1, admissionProfile)
const admissionParametersBody = encodeCanonical(admissionParametersV1, {
  version: 1,
  relayPublicKey: bytes(32, 0x41),
  profileId: 7,
  schemeId: 9,
  conformanceClass: 1,
  roleBits: 1,
  verifierKey: bytes(3, 0x42),
  resourceCosts: [
    { familyId: 2, operationId: 1, resourceClass: 1, leaseClass: 1, costUnits: 10n },
    { familyId: 4, operationId: 1, resourceClass: 1, leaseClass: 1, costUnits: 20n }
  ],
  tokenMaxBytes: 4096,
  issuanceUrl: b4a.from('https://issuer.example:443/token'),
  issuerRelayKey: bytes(32, 0x43),
  validFromEpoch: 100,
  expiresEpoch: 104,
  nonce: bytes(32, 0x44),
  signature: bytes(64, 0x45)
})

const identityTransitionBody = encodeCanonical(relayIdentityTransitionV1, {
  version: 1,
  oldRelayKey: bytes(32, 0x46),
  newRelayKey: bytes(32, 0x47),
  oldIdentitySequence: 5n,
  newIdentitySequence: 6n,
  validFromEpoch: 100,
  reasonCode: 1,
  transitionNonce: bytes(32, 0x48),
  oldSignature: bytes(64, 0x49),
  newSignature: bytes(64, 0x4a)
})

const dhtPointerBody = encodeCanonical(blindDhtPointerV1, {
  version: 1,
  relayPublicKey: bytes(32, 0x4b),
  descriptorSequence: 9n,
  descriptorHash: bytes(32, 0x4c),
  descriptorUrl: b4a.from('https://relay.example:443/descriptor.cenc'),
  transportBits: 0x0002,
  issuedEpoch: 100,
  expiresEpoch: 104,
  nonce: bytes(32, 0x4d),
  signature: bytes(64, 0x4e)
})

const healthChallengeBody = encodeCanonical(blindHealthChallengeV1, {
  version: 1,
  descriptorSequence: 9n,
  descriptorHash: bytes(32, 0x4f),
  endpointId: 1,
  transportSupportBit: 1,
  requestedRoleBits: 0x0003,
  requestedOperationBits: 0x00000007,
  clientNonce: bytes(32, 0x50)
})
const healthResultBody = encodeCanonical(blindHealthResultV1, {
  version: 1,
  relayPublicKey: bytes(32, 0x51),
  storeId: bytes(32, 0x52),
  descriptorSequence: 9n,
  descriptorHash: bytes(32, 0x4f),
  endpointId: 1,
  transportSupportBit: 1,
  durabilityContinuityHash: bytes(32, 0x53),
  durabilityProfileHash: bytes(32, 0x54),
  clientNonce: bytes(32, 0x50),
  readyRoleBits: 0x0003,
  readyOperationBits: 0x00000007,
  clockState: 1,
  effectiveEpochFloor: 100,
  integrityState: 1,
  checkpointAgeBand: 1,
  scrubAgeBand: 2,
  rebalanceState: 0,
  capacityBand: 5,
  challengeEpoch: 100,
  signature: bytes(64, 0x55)
})

const ohttpKeyConfigBody = encodeCanonical(blindOhttpKeyConfigV1, {
  version: 1,
  gatewayRelayKey: bytes(32, 0x56),
  gatewayDescriptorSequence: 9n,
  configId: 17,
  kemId: 0x0020,
  kdfId: 0x0001,
  aeadId: 0x0001,
  encodedPublicKey: bytes(32, 0x57),
  notBeforeEpoch: 100,
  notAfterEpoch: 104,
  previousConfigHash: null,
  signature: bytes(64, 0x58)
})

const externalTopologyBody = encodeCanonical(blindExternalJournalTopologyV1, {
  version: 1,
  relayPublicKey: bytes(32, 0x59),
  storeId: bytes(32, 0x5a),
  externalJournalId: bytes(32, 0x5b),
  durabilityContinuityHash: bytes(32, 0x5c),
  topologySequence: 0n,
  previousTopologyHash: null,
  replicationClass: 1,
  commitQuorum: 2,
  sharedFailureGroupId: bytes(32, 0x5d),
  liveStoreFailureGroupId: bytes(32, 0x5e),
  backupFailureGroups: [
    { backupFailureGroupId: bytes(32, 0x60), operatorGroupId: bytes(32, 0x61) }
  ],
  nodes: [
    { nodePublicKey: bytes(32, 0x62), operatorGroupId: bytes(32, 0x72), failureDomainId: bytes(32, 0x82), roleConflictBits: 0 },
    { nodePublicKey: bytes(32, 0x63), operatorGroupId: bytes(32, 0x73), failureDomainId: bytes(32, 0x83), roleConflictBits: 0 },
    { nodePublicKey: bytes(32, 0x64), operatorGroupId: bytes(32, 0x74), failureDomainId: bytes(32, 0x84), roleConflictBits: 0 }
  ],
  issuedEpoch: 100,
  expiresEpoch: 104,
  witnessPublicKey: bytes(32, 0x65),
  signature: bytes(64, 0x66)
})

const coreAck = {
  version: 1,
  relayBinding: relayBinding(0x67),
  corePublicKey: bytes(32, 0x68),
  fork: 2n,
  length: 16n,
  signedHeadHash: bytes(32, 0x69),
  observedAtEpoch: 100,
  leaseEpoch: 104,
  result: 2,
  requestNonce: bytes(32, 0x6a),
  requestCommitment: bytes(32, 0x6b),
  signature: bytes(64, 0x6c)
}
const coreAckBody = encodeCanonical(blindCoreAckV1, coreAck)
const coreMirror = {
  version: 1,
  corePublicKey: coreAck.corePublicKey,
  fork: 2n,
  length: 16n,
  signedHeadHash: coreAck.signedHeadHash,
  leaseClass: 2,
  clientNonce: bytes(32, 0x6d),
  admission
}
const coreMirrorBody = encodeCanonical(coreMirrorRequestV1, coreMirror)
const coreMirrorCommitment = coreMirrorRequestCommitment({
  relayPublicKey: coreAck.relayBinding.relayPublicKey,
  ...coreMirror
})
const coreServeChallenge = {
  version: 1,
  corePublicKey: coreAck.corePublicKey,
  fork: 2n,
  length: 16n,
  signedHeadHash: coreAck.signedHeadHash,
  blockIndices: [0n, 7n, 15n],
  clientNonce: coreAck.requestNonce,
  admission: null
}
const coreServeChallengeBody = encodeCanonical(coreServeChallengeV1, coreServeChallenge)
const coreServeCommitment = coreServeRequestCommitment({
  relayPublicKey: coreAck.relayBinding.relayPublicKey,
  ...coreServeChallenge
})
const coreServeResultBody = encodeCanonical(coreServeResultV1, {
  version: 1,
  acknowledgement: coreAck,
  proofsAndBlocks: b4a.from('0102030405', 'hex')
})

const forwardOpenBody = encodeCanonical(blindForwardOpenV1, {
  version: 1,
  routeId: bytes(16, 0x6e),
  nextDescriptorSequence: 10n,
  nextDescriptorHash: bytes(32, 0x6f),
  requestedWireClass: 1,
  circuitClass: 1,
  circuitNonce: bytes(32, 0x70),
  hopAdmission: admission,
  innerHandshake: bytes(32, 0x71)
})
const forwardOpenCommitment = forwardOpenRequestCommitment({
  previousRelayKey: bytes(32, 0x72),
  routeId: bytes(16, 0x6e),
  nextDescriptorSequence: 10n,
  nextDescriptorHash: bytes(32, 0x6f),
  requestedWireClass: 1,
  circuitClass: 1,
  circuitNonce: bytes(32, 0x70),
  innerHandshake: bytes(32, 0x71)
})
const nextHopAccept = {
  version: 1,
  previousRelayKey: bytes(32, 0x72),
  previousDescriptorSequence: 9n,
  previousDescriptorHash: bytes(32, 0x73),
  nextRelayKey: bytes(32, 0x74),
  nextDescriptorSequence: 10n,
  nextDescriptorHash: bytes(32, 0x6f),
  nextRelayBinding: relayBinding(0x74, {
    relayPublicKey: bytes(32, 0x74),
    descriptorSequence: 10n,
    descriptorHash: bytes(32, 0x6f)
  }),
  routeId: bytes(16, 0x6e),
  circuitNonce: bytes(32, 0x70),
  nextStreamId: 21n,
  grantedWireClass: 1,
  circuitClass: 1,
  grantedInitialWindow: 64 * 1024,
  maxDataBytes: 4096,
  maxCircuitBytes: 16n * 1024n * 1024n,
  idleMillis: 30000,
  lifetimeMillis: 600000,
  openedAtEpoch: 100,
  hopOpenCommitment: bytes(32, 0x75),
  handshakeFlight2: bytes(96, 0x76),
  nextSignature: bytes(64, 0x77)
}
const forwardOpenResultBody = encodeCanonical(blindForwardOpenResultV1, {
  version: 1,
  relayBinding: relayBinding(0x72, {
    relayPublicKey: nextHopAccept.previousRelayKey,
    descriptorSequence: nextHopAccept.previousDescriptorSequence,
    descriptorHash: nextHopAccept.previousDescriptorHash
  }),
  routeId: nextHopAccept.routeId,
  nextDescriptorSequence: nextHopAccept.nextDescriptorSequence,
  nextDescriptorHash: nextHopAccept.nextDescriptorHash,
  circuitNonce: nextHopAccept.circuitNonce,
  grantedWireClass: 1,
  circuitClass: 1,
  streamId: 20n,
  grantedInitialWindow: nextHopAccept.grantedInitialWindow,
  maxDataBytes: nextHopAccept.maxDataBytes,
  maxCircuitBytes: nextHopAccept.maxCircuitBytes,
  idleMillis: nextHopAccept.idleMillis,
  lifetimeMillis: nextHopAccept.lifetimeMillis,
  openedAtEpoch: nextHopAccept.openedAtEpoch,
  requestCommitment: bytes(32, 0x78),
  nextHopAccept,
  signature: bytes(64, 0x79)
})
const forwardDataBody = encodeCanonical(blindForwardDataV1, {
  version: 1,
  circuitNonce: nextHopAccept.circuitNonce,
  offset: 0n,
  bytes: b4a.from('deadbeef', 'hex')
})
const forwardWindowBody = encodeCanonical(blindForwardWindowV1, {
  version: 1,
  circuitNonce: nextHopAccept.circuitNonce,
  consumedThrough: 4n,
  creditIncrement: 4096
})
const forwardCloseBody = encodeCanonical(blindForwardCloseV1, {
  version: 1,
  circuitNonce: nextHopAccept.circuitNonce,
  closeKind: 1,
  finalSendOffset: 4n,
  reasonCode: 0
})
const streamContent = b4a.from('010203', 'hex')
const streamChunkBody = encodeCanonical(blindStreamChunkPlainV1, {
  version: 1,
  wireClass: 1,
  flags: 0,
  contentLength: streamContent.byteLength,
  content: streamContent,
  randomPadding: bytes(4070, 0x7a)
})
const invalidStreamClass = b4a.from(streamChunkBody)
invalidStreamClass[1] = 0

const serviceDescriptorBody = encodeCanonical(blindServiceDescriptorV1, {
  version: 1,
  relayPublicKey: bytes(32, 0x7b),
  storeId: bytes(32, 0x7c),
  descriptorSequence: 0n,
  previousDescriptorHash: null,
  identitySequence: 0n,
  previousRelayKey: null,
  identityTransition: null,
  build: {
    specHash: bytes(32, 0x01),
    abiHash: bytes(32, 0x02),
    vectorSetHash: bytes(32, 0x03),
    evidenceFormatHash: bytes(32, 0x04),
    evidenceVectorSetHash: bytes(32, 0x05),
    storeFormatHash: bytes(32, 0x06),
    storeVectorSetHash: bytes(32, 0x07),
    privateIpcFormatHash: bytes(32, 0x14),
    privateIpcVectorSetHash: bytes(32, 0x15),
    buildArtifactHash: bytes(32, 0x08),
    buildArtifactUrl: b4a.from('https://evidence.example:443/artifact.cenc'),
    buildManifestUrl: b4a.from('https://evidence.example:443/build.cenc'),
    buildManifestHash: bytes(32, 0x09),
    releaseEvidenceBundleUrl: b4a.from('https://evidence.example:443/release.cenc'),
    releaseEvidenceBundleHash: bytes(32, 0x16),
    releaseSupportHorizonHash: bytes(32, 0x17),
    runtimeBoundaryEvidenceUrl: b4a.from('https://evidence.example:443/runtime-boundary.cenc'),
    runtimeBoundaryEvidenceHash: bytes(32, 0x18)
  },
  protocols: [{ protocolId: 1, major: 1, minor: 0, featureBits: 0n, profileHash: bytes(32, 0x0a) }],
  endpoints: [{
    endpointId: 1,
    transportId: 1,
    transportProfileHash: bytes(32, 0x0b),
    roleBits: 1,
    privacyProfileBits: 1,
    canonicalUrl: b4a.from('https://relay.example:443/api/blind/v1/describe'),
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
  maxResponseBytes: 4 * 1024 * 1024,
  maxSponsoredCoreLength: 1024n,
  enabledOperationBits: 0x003fffff,
  admissionProfiles: [admissionProfile],
  durability: {
    profileId: 1,
    storeFormatMajor: 1,
    storeFormatMinor: 1,
    storeFormatHash: bytes(32, 0x0c),
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
  },
  durabilityContinuityHash: bytes(32, 0x10),
  durabilityProfileHash: bytes(32, 0x11),
  storeLifecycleState: 1,
  drainStartedEpoch: null,
  capacityBand: 5,
  issuedEpoch: 100,
  expiresEpoch: 104,
  descriptorNonce: bytes(32, 0x12),
  signature: bytes(64, 0x13)
})

const schemaCatalogBody = encodeCanonical(schemaCatalogEntryV1, wireSchemaCatalog.entries[0])

const externalCommitWitness = {
  version: 1,
  relayPublicKey: bytes(32, 0x81),
  storeId: bytes(32, 0x82),
  externalJournalId: bytes(32, 0x83),
  durabilityContinuityHash: bytes(32, 0x84),
  durabilityProfileHash: bytes(32, 0x85),
  restoreEvidenceHeadSequence: 1n,
  restoreEvidenceHeadHash: bytes(32, 0x86),
  familyId: FAMILY.CELL,
  operationId: OPERATION.CELL.PUT,
  requestCommitment: bytes(32, 0x87),
  resultCommitment: bytes(32, 0x88),
  commitWalSequence: 9n,
  commitWalHash: bytes(32, 0x89),
  coveringFloorRevision: 10n,
  coveringFloorHash: bytes(32, 0x8a),
  coveringFloorWalSequence: 9n,
  coveringFloorWalHash: bytes(32, 0x8b),
  writerEpoch: 11n,
  writerFenceTokenHash: bytes(32, 0x8c),
  externalLeaseRevision: 12n,
  witnessedUnixMillis: 13n,
  witnessPublicKey: bytes(32, 0x8d),
  signature: bytes(64, 0x8e)
}
const externalCommitWitnessBody = encodeCanonical(blindExternalCommitWitnessV1, externalCommitWitness)
const persistentRelayBinding = {
  version: 1,
  relayPublicKey: externalCommitWitness.relayPublicKey,
  storeId: externalCommitWitness.storeId,
  descriptorSequence: 14n,
  descriptorHash: bytes(32, 0x8f),
  durabilityProfileId: 2,
  durabilityContinuityHash: externalCommitWitness.durabilityContinuityHash,
  durabilityProfileHash: externalCommitWitness.durabilityProfileHash,
  restoreEvidenceHeadSequence: externalCommitWitness.restoreEvidenceHeadSequence,
  restoreEvidenceHeadHash: externalCommitWitness.restoreEvidenceHeadHash,
  externalCommitWitness
}
const persistentRelayBindingBody = encodeCanonical(relayResultBindingV1, persistentRelayBinding)
const batchSignaturePayloadBody = encodeCanonical(batchGetSignaturePayloadV1, {
  version: 1,
  relayBinding: persistentRelayBinding,
  requestNonce: bytes(32, 0x90),
  requestCommitment: bytes(32, 0x91),
  entriesCommitment: bytes(32, 0x92)
})
const inboxSignaturePayloadBody = encodeCanonical(inboxReadSignaturePayloadV1, {
  version: 1,
  relayBinding: persistentRelayBinding,
  requestNonce: bytes(32, 0x93),
  requestCommitment: bytes(32, 0x94),
  snapshotRevision: 15n,
  entriesCommitment: bytes(32, 0x95),
  nextCursor: null
})

const durabilityContinuityBody = encodeCanonical(durabilityContinuityBindingV1, {
  version: 1,
  profileId: 2,
  externalJournalId: bytes(32, 0xa1),
  externalWitnessPublicKey: bytes(32, 0xa2),
  externalJournalReplicationClass: 1,
  externalJournalFailureGroupId: bytes(32, 0xa3),
  restoreEvidenceFeedId: bytes(32, 0xa4)
})
const backupEncryptionProfile = {
  version: 1,
  algorithmId: 1,
  keyDerivationId: 1,
  recoveryKeyId: bytes(32, 0xa5),
  keyEpoch: 1
}
const backupEncryptionProfileBody = encodeCanonical(blindBackupEncryptionProfileV1, backupEncryptionProfile)
const backupChunkManifest = {
  version: 1,
  backupId: bytes(32, 0xa6),
  encryptionProfile: backupEncryptionProfile,
  encryptionManifestHash: bytes(32, 0xa7),
  entries: [{
    path: b4a.from('store/manifest', 'ascii'),
    fileOffset: 0n,
    plaintextByteLength: 1024,
    ciphertextByteLength: 1040,
    chunkObjectId: bytes(32, 0xa8),
    chunkSalt: bytes(32, 0xa9),
    nonce: bytes(24, 0xaa),
    ciphertextHash: bytes(32, 0xab)
  }],
  totalPlaintextByteLength: 1024n,
  totalCiphertextByteLength: 1040n
}
const backupChunkManifestBody = encodeCanonical(blindBackupChunkManifestV1, backupChunkManifest)
const backupManifest = {
  version: 1,
  relayPublicKey: bytes(32, 0xac),
  storeId: bytes(32, 0xad),
  externalJournalId: bytes(32, 0xae),
  durabilityContinuityHash: bytes(32, 0xaf),
  backupId: backupChunkManifest.backupId,
  backupFailureGroupId: bytes(32, 0xb0),
  storeManifestRevision: 1n,
  storeManifestHash: bytes(32, 0xb1),
  storeFormatHash: bytes(32, 0xb2),
  coverageCutoffExternalUnixMillis: 1n,
  coveredWalSequence: 2n,
  coveredWalHash: bytes(32, 0xb3),
  externalFloorRevision: 3n,
  externalFloorHash: bytes(32, 0xb4),
  externalCheckpointRevision: 4n,
  externalCheckpointHash: bytes(32, 0xb5),
  baseFloorRevision: 3n,
  baseFloorHash: bytes(32, 0xb6),
  controlSnapshotHash: bytes(32, 0xb7),
  backupEncryptionProfileHash: bytes(32, 0xb8),
  encryptionManifestHash: backupChunkManifest.encryptionManifestHash,
  chunkManifestByteLength: BigInt(backupChunkManifestBody.byteLength),
  chunkManifestHash: bytes(32, 0xb9),
  totalPlaintextByteLength: 1024n,
  totalCiphertextByteLength: 1040n,
  restoreVerifierPublicKey: bytes(32, 0xba),
  cleanRestoreEvidenceHash: bytes(32, 0xbb),
  createdExternalUnixMillis: 100n,
  restoreSupportExpiresUnixMillis: 200n,
  witnessPublicKey: bytes(32, 0xbc),
  signature: bytes(64, 0xbd)
}
const backupManifestBody = encodeCanonical(blindBackupManifestV1, backupManifest)
const cleanRestoreBody = encodeCanonical(blindCleanRestoreEvidenceV1, {
  version: 1,
  backupId: backupManifest.backupId,
  backupCandidateCommitment: bytes(32, 0xbe),
  restoredStoreManifestHash: bytes(32, 0xbf),
  verifiedWalSequence: 2n,
  verifiedWalHash: backupManifest.coveredWalHash,
  verifiedExternalFloorRevision: 3n,
  verifiedExternalFloorHash: backupManifest.externalFloorHash,
  verifiedCheckpointRevision: 4n,
  verifiedCheckpointHash: backupManifest.externalCheckpointHash,
  scrubbedObjectCount: 5n,
  scrubFailureCount: 0,
  startedExternalUnixMillis: 101n,
  completedExternalUnixMillis: 102n,
  verifierPublicKey: backupManifest.restoreVerifierPublicKey,
  signature: bytes(64, 0xc0)
})
const retentionTransitionBody = encodeCanonical(blindBackupRetentionTransitionV1, {
  version: 1,
  relayPublicKey: backupManifest.relayPublicKey,
  storeId: backupManifest.storeId,
  externalJournalId: backupManifest.externalJournalId,
  durabilityContinuityHash: backupManifest.durabilityContinuityHash,
  backupId: backupManifest.backupId,
  backupManifestHash: bytes(32, 0xc1),
  transitionRevision: 1n,
  previousTransitionHash: null,
  operation: 1,
  supportExpiresUnixMillis: 200n,
  replacementBackupId: null,
  effectiveExternalTimeFloorMillis: 103n,
  witnessPublicKey: backupManifest.witnessPublicKey,
  signature: bytes(64, 0xc2)
})
const restoreIssued = 21600000n * 10n
const restoreHead = {
  version: 1,
  relayPublicKey: bytes(32, 0xc3),
  storeId: bytes(32, 0xc4),
  externalJournalId: bytes(32, 0xc5),
  durabilityContinuityHash: bytes(32, 0xc6),
  restoreEvidenceFeedId: bytes(32, 0xc7),
  evidenceSequence: 1n,
  previousEvidenceHeadHash: null,
  currentBackupManifestHash: bytes(32, 0xc8),
  currentRetentionTransitionHash: bytes(32, 0xc9),
  currentCoveredWalSequence: 1n,
  currentExternalFloorRevision: 1n,
  currentChunkObjectCount: 1n,
  currentAvailabilityAuditHash: bytes(32, 0xca),
  currentSupportExpiresUnixMillis: restoreIssued + 1000n,
  drillBackupManifestHash: bytes(32, 0xcb),
  drillCleanRestoreEvidenceHash: bytes(32, 0xcc),
  drillRetentionTransitionHash: bytes(32, 0xcd),
  restoreDrillCompletedUnixMillis: restoreIssued - 1n,
  drillSupportExpiresUnixMillis: restoreIssued + 1000n,
  issuedExternalUnixMillis: restoreIssued,
  expiresExternalUnixMillis: restoreIssued + 2000n,
  issuedEpoch: 10,
  witnessPublicKey: bytes(32, 0xce),
  signature: bytes(64, 0xcf)
}
const restoreHeadBody = encodeCanonical(blindRestoreEvidenceHeadV1, restoreHead)
const restoreBundleBody = encodeCanonical(blindRestoreEvidenceBundleV1, {
  version: 1,
  heads: [restoreHead],
  currentBackupManifestBytes: bytes(1, 1),
  currentRetentionTransitionBytes: bytes(1, 2),
  drillBackupManifestBytes: bytes(1, 3),
  drillCleanRestoreEvidenceBytes: bytes(1, 4),
  drillRetentionTransitionBytes: bytes(1, 5)
})

const cellPutOperationRow = OPERATION_PROFILE_ROWS.find(row =>
  row.familyId === FAMILY.CELL && row.operationId === OPERATION.CELL.PUT)
const cellPutOperationProfile = encodeCanonical(operationProfileV1, cellPutOperationRow)
const invalidOperationDomain = b4a.from(cellPutOperationProfile)
invalidOperationDomain[20] = 0
invalidOperationDomain[21] = 104
const cellPutDomainEntry = encodeCanonical(domainRegistryEntryV1, {
  ...DOMAIN_REGISTRY[0],
  exactAsciiBytes: b4a.from(DOMAIN_REGISTRY[0].exactAsciiBytes, 'ascii')
})
const invalidDomainPurpose = b4a.from(cellPutDomainEntry)
invalidDomainPurpose[2] = 2
const renewNotDueErrorProfile = encodeCanonical(errorProfileEntryV1, ERROR_PROFILE_ROWS[17])
const invalidErrorProfileRetryable = b4a.from(renewNotDueErrorProfile)
invalidErrorProfileRetryable[6] = 0
const cellPutCostRule = encodeCanonical(admissionCostRuleV1, { costClassRuleId: 1, ruleKind: 1 })

const publicOperationProfileVectors = [
  ['describe-get', FAMILY.DESCRIBE, OPERATION.DESCRIBE.GET],
  ['describe-challenge', FAMILY.DESCRIBE, OPERATION.DESCRIBE.CHALLENGE],
  ['describe-admission-parameters', FAMILY.DESCRIBE, OPERATION.DESCRIBE.ADMISSION_PARAMETERS],
  ['core-mirror', FAMILY.CORE, OPERATION.CORE.MIRROR],
  ['core-prove', FAMILY.CORE, OPERATION.CORE.PROVE],
  ['core-open-replication', FAMILY.CORE, OPERATION.CORE.OPEN_REPLICATION],
  ['forward-open', FAMILY.FORWARD, OPERATION.FORWARD.OPEN],
  ['forward-data', FAMILY.FORWARD, OPERATION.FORWARD.DATA],
  ['forward-window', FAMILY.FORWARD, OPERATION.FORWARD.WINDOW],
  ['forward-close', FAMILY.FORWARD, OPERATION.FORWARD.CLOSE]
].map(([name, familyId, operationId]) => {
  const row = OPERATION_PROFILE_ROWS.find(row => row.familyId === familyId && row.operationId === operationId)
  if (!row) throw new Error(`missing operation profile vector row: ${name}`)
  return [`registry/${name}-operation-profile.bin`, encodeCanonical(operationProfileV1, row)]
})

function registryName (registry, id, label) {
  const match = Object.entries(registry).find(([, value]) => value === id)
  if (!match) throw new Error(`missing ${label} registry name for ${id}`)
  return match[0].toLowerCase().replaceAll('_', '-')
}

const completeOperationProfileVectors = OPERATION_PROFILE_ROWS.map(row => {
  const familyName = registryName(FAMILY, row.familyId, 'family')
  const familyRegistryName = Object.entries(FAMILY).find(([, id]) => id === row.familyId)[0]
  const operationName = registryName(OPERATION[familyRegistryName], row.operationId, 'operation')
  const prefix = `${String(row.familyId).padStart(2, '0')}-${String(row.operationId).padStart(2, '0')}`
  return [`registry/operations/${prefix}-${familyName}-${operationName}.bin`,
    encodeCanonical(operationProfileV1, row)]
})

const completeDomainVectors = DOMAIN_REGISTRY.map(row => [
  `registry/domains/${String(row.domainId).padStart(3, '0')}.bin`,
  encodeCanonical(domainRegistryEntryV1, {
    ...row,
    exactAsciiBytes: b4a.from(row.exactAsciiBytes, 'ascii')
  })
])

const completeErrorVectors = ERROR_PROFILE_ROWS.map(row => [
  `registry/errors/${String(row.code).padStart(2, '0')}.bin`,
  encodeCanonical(errorProfileEntryV1, row)
])

const completeCostRuleVectors = ADMISSION_COST_RULES.map(row => [
  `registry/admission-costs/${String(row.costClassRuleId).padStart(2, '0')}.bin`,
  encodeCanonical(admissionCostRuleV1, row)
])

const completeWireSchemaVectors = wireSchemaCatalog.entries
  .map(entry => {
    const name = b4a.toString(entry.schemaName, 'ascii')
    const prefix = String(entry.categoryLocalSchemaId).padStart(3, '0')
    return [`registry/schemas/${prefix}-${name}.bin`, encodeCanonical(schemaCatalogEntryV1, entry)]
  })

const wireSchemaCatalogVector = ['registry/wire-schema-catalog.bin',
  encodeSchemaCatalog(wireSchemaCatalog.entries)]
const nonWireSchemaCatalogVectors = wireOnly
  ? []
  : [
      ['registry/master-schema-catalog.bin', masterSchemaCatalog.entries],
      ['registry/evidence-schema-catalog.bin', masterSchemaCatalog.entries.filter(entry => entry.category === SCHEMA_CATEGORY.EVIDENCE)],
      ['registry/client-example-schema-catalog.bin', masterSchemaCatalog.entries.filter(entry => entry.category === SCHEMA_CATEGORY.CLIENT_EXAMPLE)],
      ['registry/internal-store-schema-catalog.bin', masterSchemaCatalog.entries.filter(entry => entry.category === SCHEMA_CATEGORY.INTERNAL_STORE)]
    ].map(([name, entries]) => [name, encodeSchemaCatalog(entries)])
const schemaCatalogVectors = [wireSchemaCatalogVector, ...nonWireSchemaCatalogVectors]

const walHeaderV2 = wireOnly
  ? null
  : nonWireFixture('BlindWalHeaderV2', () => encodeCanonical(blindWalHeaderV2, {
    magic: b4a.from('HRWL', 'ascii'),
    walVersion: 2,
    recordType: 9,
    totalLength: 224 + 17,
    walSequence: 1n,
    transactionId: bytes(32, 0xc1),
    virtualBucket: 0x1234,
    mapGeneration: 1n,
    writerFenceTokenHash: bytes(32, 0xc2),
    payloadLength: 17,
    previousWalHash: bytes(32, 0),
    durabilityContinuityHash: bytes(32, 0xc3),
    payloadHash: bytes(32, 0xc4)
  }))

const controlStateSnapshotV1 = wireOnly
  ? null
  : nonWireFixture('BlindControlStateSnapshotV1', () =>
    encodeCanonical(blindControlStateSnapshotV1, {
      version: 1,
      relayPublicKey: bytes(32, 0xd1),
      storeId: bytes(32, 0xd2),
      durabilityContinuityHash: bytes(32, 0xd3),
      walSequence: 9n,
      walHash: bytes(32, 0xda),
      entries: [
        {
          entryKind: 1,
          key: b4a.from('spend/0001', 'ascii'),
          value: b4a.from('committed', 'ascii')
        },
        {
          entryKind: 6,
          key: b4a.from('global/accounting', 'ascii'),
          value: bytes(8, 0xa6)
        },
        {
          entryKind: 8,
          key: b4a.from('retry/0001', 'ascii'),
          value: b4a.alloc(0)
        }
      ]
    }))

const localCheckpointV1 = wireOnly
  ? null
  : nonWireFixture('BlindLocalCheckpointV1', () =>
    encodeCanonical(blindLocalCheckpointV1, {
      magic: b4a.from('HRBCKP01', 'ascii'),
      checkpointVersion: 1,
      relayPublicKey: bytes(32, 0xd1),
      storeId: bytes(32, 0xd2),
      durabilityProfileId: 1,
      durabilityContinuityHash: bytes(32, 0xd3),
      durabilityProfileHash: bytes(32, 0xd4),
      formatMajor: 1,
      formatMinor: 1,
      storeFormatHash: bytes(32, 0xd5),
      specHash: bytes(32, 0xd6),
      abiHash: bytes(32, 0xd7),
      mapGeneration: 1n,
      bucketMapHash: bytes(32, 0xd8),
      writerEpoch: 1n,
      writerFenceTokenHash: bytes(32, 0xd9),
      checkpointRevision: 1n,
      previousCheckpointHash: null,
      coveredWalSequence: 9n,
      coveredWalHash: bytes(32, 0xda),
      epochFloor: 10,
      descriptorSequenceFloor: 2n,
      descriptorHashFloor: bytes(32, 0xdb),
      snapshotByteLength: BigInt(controlStateSnapshotV1.byteLength),
      snapshotHash: controlSnapshotHash(controlStateSnapshotV1)
    }))

const vectorFiles = [
  ['dispatch/cell-get-request.bin', cellGet],
  ['dispatch/forward-data.bin', forwardData],
  ['invalid/dispatch-nonzero-flags.bin', invalidFlags],
  ['invalid/dispatch-unknown-operation.bin', invalidOperation],
  ['outer/cell-get-class-1.bin', outerCellGet],
  ['cell/put-class-1.bin', cellPutBody],
  ['cell/batch-get-result.bin', batchResultBody],
  ['inbox/append-class-1.bin', inboxAppendBody],
  ['inbox/read-result-empty.bin', inboxReadResultBody],
  ['describe/admission-profile.bin', admissionProfileBody],
  ['describe/admission-parameters.bin', admissionParametersBody],
  ['describe/dht-pointer.bin', dhtPointerBody],
  ['describe/external-journal-topology.bin', externalTopologyBody],
  ['describe/health-challenge.bin', healthChallengeBody],
  ['describe/health-result.bin', healthResultBody],
  ['describe/identity-transition.bin', identityTransitionBody],
  ['describe/ohttp-key-config.bin', ohttpKeyConfigBody],
  ['describe/schema-catalog-entry.bin', schemaCatalogBody],
  ['describe/service-descriptor.bin', serviceDescriptorBody],
  ['durability/external-commit-witness.bin', externalCommitWitnessBody],
  ['durability/relay-result-binding.bin', persistentRelayBindingBody],
  ['durability/batch-signature-payload.bin', batchSignaturePayloadBody],
  ['durability/inbox-signature-payload.bin', inboxSignaturePayloadBody],
  ['durability/continuity-binding.bin', durabilityContinuityBody],
  ['durability/backup-encryption-profile.bin', backupEncryptionProfileBody],
  ['durability/backup-chunk-manifest.bin', backupChunkManifestBody],
  ['durability/backup-manifest.bin', backupManifestBody],
  ['durability/clean-restore.bin', cleanRestoreBody],
  ['durability/retention-transition.bin', retentionTransitionBody],
  ['durability/restore-head.bin', restoreHeadBody],
  ['durability/restore-bundle.bin', restoreBundleBody],
  ['core/ack.bin', coreAckBody],
  ['core/mirror-request.bin', coreMirrorBody],
  ['core/serve-challenge.bin', coreServeChallengeBody],
  ['core/serve-result.bin', coreServeResultBody],
  ['forward/open.bin', forwardOpenBody],
  ['forward/open-result.bin', forwardOpenResultBody],
  ['forward/data-body.bin', forwardDataBody],
  ['forward/window.bin', forwardWindowBody],
  ['forward/close.bin', forwardCloseBody],
  ['forward/stream-chunk-class-1.bin', streamChunkBody],
  ['commitment/cell-put.bin', cellPutCommitment],
  ['commitment/inbox-read.bin', inboxReadCommitment],
  ['commitment/core-mirror.bin', coreMirrorCommitment],
  ['commitment/core-serve.bin', coreServeCommitment],
  ['commitment/forward-open.bin', forwardOpenCommitment],
  ['commitment/persistent-batch-get.bin', batchPersistentResultCommitment],
  ['registry/cell-put-operation-profile.bin', cellPutOperationProfile],
  ['registry/cell-put-domain.bin', cellPutDomainEntry],
  ['registry/renew-not-due-error-profile.bin', renewNotDueErrorProfile],
  ['registry/cell-put-cost-rule.bin', cellPutCostRule],
  ['store/control-state-snapshot-v1.bin', controlStateSnapshotV1],
  ['store/local-checkpoint-v1.bin', localCheckpointV1],
  ['store/wal-header-v2.bin', walHeaderV2],
  ...publicOperationProfileVectors,
  ...completeOperationProfileVectors,
  ...completeDomainVectors,
  ...completeErrorVectors,
  ...completeCostRuleVectors,
  ...completeWireSchemaVectors,
  ...schemaCatalogVectors,
  ['invalid/cell-get-unknown-class.bin', invalidGetClass],
  ['invalid/batch-get-duplicate-slots.bin', duplicateBatchSlots],
  ['invalid/batch-get-unknown-entry-tag.bin', invalidBatchTag],
  ['invalid/inbox-read-cursor-129.bin', invalidInboxCursor],
  ['invalid/operation-profile-wrong-domain-purpose.bin', invalidOperationDomain],
  ['invalid/domain-entry-wrong-purpose.bin', invalidDomainPurpose],
  ['invalid/error-profile-wrong-retryable.bin', invalidErrorProfileRetryable],
  ['invalid/stream-chunk-unknown-class.bin', invalidStreamClass]
]

const nonWireVectorPaths = new Set([
  'registry/master-schema-catalog.bin',
  'registry/evidence-schema-catalog.bin',
  'registry/client-example-schema-catalog.bin',
  'registry/internal-store-schema-catalog.bin'
])
const wireVectorFiles = vectorFiles.filter(([vectorPath]) =>
  !vectorPath.startsWith('store/') && !nonWireVectorPaths.has(vectorPath))

for (const [name, bytes] of (wireOnly ? wireVectorFiles : vectorFiles)) {
  emit(path.join('packages', 'blind-protocol', 'vectors', 'draft', name), bytes)
}
for (const [name, bytes] of wireVectorFiles) {
  emit(path.join('packages', 'blind-protocol', 'vectors', name), bytes)
}
const vectorRoot = path.join(root, 'packages', 'blind-protocol', 'vectors')
const reservedNonWireRoots = new Set(['client-composition', 'draft', 'evidence', 'store'])
const actualWireVectorPaths = listedFiles(vectorRoot)
  .filter(relative => !reservedNonWireRoots.has(relative.split('/')[0]))
  .sort()
const expectedWireVectorPaths = wireVectorFiles.map(([vectorPath]) => vectorPath).sort()
if (actualWireVectorPaths.length !== expectedWireVectorPaths.length ||
    actualWireVectorPaths.some((value, index) => value !== expectedWireVectorPaths[index])) {
  throw new Error('final WIRE vector directory contains missing or unmanifested package files')
}

const abiBytes = encodeWireAbiRegistry(wireSchemaCatalog.entries)
const vectorManifestBytes = encodeVectorManifest(
  wireVectorFiles.map(([vectorPath, bytes]) => ({ path: vectorPath, bytes }))
)
const hashes = {
  profile: ABI_STATUS.profile,
  releaseReady: ABI_STATUS.releaseReady,
  missingSchemaCount: ABI_STATUS.wireMissingSchemaNames.length,
  specHash: b4a.toString(hashSpec(canonicalWireSpecBytes), 'hex'),
  abiHash: b4a.toString(hashAbi(abiBytes), 'hex'),
  vectorSetHash: b4a.toString(hashVectorSet(vectorManifestBytes), 'hex')
}
const wireAuthority = {
  profile: ABI_STATUS.profile,
  protocolFamily: 'hiverelay-blind',
  protocolMajor: 1,
  protocolMinor: 0,
  specArtifact: 'docs/protocol/HIVERELAY-BLIND-WIRE-V1.md',
  abiArtifact: 'packages/blind-protocol/hiverelay-blind-abi-v1.cenc',
  vectorManifestArtifact: 'packages/blind-protocol/vector-manifest-v1.cenc',
  specHash: hashes.specHash,
  abiHash: hashes.abiHash,
  vectorSetHash: hashes.vectorSetHash,
  wireSchemaCount: ABI_STATUS.wireRequiredSchemaNames.length,
  operationCount: ABI_STATUS.operationProfileStatus.requiredPairs.length,
  errorCount: ERROR_PROFILE_ROWS.length,
  domainCount: DOMAIN_REGISTRY.length,
  vectorCount: wireVectorFiles.length
}
const wireAuthorityBytes = b4a.from(JSON.stringify(wireAuthority, null, 2) + '\n')
const schemaCatalogNameHashesByCategory = Object.fromEntries(
  Object.entries(SCHEMA_NAMES_BY_CATEGORY).map(([category, names]) => [
    category,
    names.map(name => b4a.toString(blake2b256(b4a.from(name, 'ascii')), 'hex'))
  ])
)
const schemaCatalogRuntimeAuthorityBytes = b4a.from(`/* eslint-disable */
// Generated by scripts/generate-blind-protocol-draft.mjs. Do not edit.
// This import-free table commits SchemaCatalogEntryV1 category/id positions
// without exposing category names or package-internal schema vocabulary.
export const SCHEMA_CATALOG_NAME_HASHES_BY_CATEGORY = Object.freeze(
  Object.fromEntries(Object.entries(${JSON.stringify(schemaCatalogNameHashesByCategory, null, 2)})
    .map(([category, hashes]) => [category, Object.freeze(hashes)]))
)
`)
const wireRuntimeAuthorityBytes = b4a.from(`/* eslint-disable */
// Generated by scripts/generate-blind-protocol-draft.mjs. Do not edit.
function deepFreeze (value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const child of Object.values(value)) deepFreeze(child)
  return Object.freeze(value)
}

export const PROTOCOL = deepFreeze(${JSON.stringify(PROTOCOL, null, 2)})
export const FRAME_KIND = deepFreeze(${JSON.stringify(FRAME_KIND, null, 2)})
export const FAMILY = deepFreeze(${JSON.stringify(FAMILY, null, 2)})
export const FAMILY_ROUTES = deepFreeze(${JSON.stringify(FAMILY_ROUTES, null, 2)})
export const OPERATION = deepFreeze(${JSON.stringify(OPERATION, null, 2)})
export const TRANSPORT_ID = deepFreeze(${JSON.stringify(TRANSPORT_ID, null, 2)})
export const TRANSPORT_SUPPORT = deepFreeze(${JSON.stringify(TRANSPORT_SUPPORT, null, 2)})
export const ENDPOINT_LIMITS = deepFreeze(${JSON.stringify(ENDPOINT_LIMITS, null, 2)})
export const PUBLIC_PROFILE_LIMITS = deepFreeze(${JSON.stringify(PUBLIC_PROFILE_LIMITS, null, 2)})
export const ADMISSION_CONFORMANCE_CLASS = deepFreeze(${JSON.stringify(ADMISSION_CONFORMANCE_CLASS, null, 2)})
export const CELL_RECEIPT_RESULT = deepFreeze(${JSON.stringify(CELL_RECEIPT_RESULT, null, 2)})
export const INBOX_MANAGE_OPERATION = deepFreeze(${JSON.stringify(INBOX_MANAGE_OPERATION, null, 2)})
export const INBOX_APPEND_AUTH_MODE = deepFreeze(${JSON.stringify(INBOX_APPEND_AUTH_MODE, null, 2)})
export const INBOX_RECEIPT_RESULT = deepFreeze(${JSON.stringify(INBOX_RECEIPT_RESULT, null, 2)})
export const INBOX_APPEND_RESULT = deepFreeze(${JSON.stringify(INBOX_APPEND_RESULT, null, 2)})
export const CORE_ACK_RESULT = deepFreeze(${JSON.stringify(CORE_ACK_RESULT, null, 2)})
export const FORWARD_CLOSE_KIND = deepFreeze(${JSON.stringify(FORWARD_CLOSE_KIND, null, 2)})
export const STORE_LIFECYCLE_STATE = deepFreeze(${JSON.stringify(STORE_LIFECYCLE_STATE, null, 2)})
export const HEALTH_CLOCK_STATE = deepFreeze(${JSON.stringify(HEALTH_CLOCK_STATE, null, 2)})
export const HEALTH_INTEGRITY_STATE = deepFreeze(${JSON.stringify(HEALTH_INTEGRITY_STATE, null, 2)})
export const HEALTH_REBALANCE_STATE = deepFreeze(${JSON.stringify(HEALTH_REBALANCE_STATE, null, 2)})
export const STREAM_TRANSITION = deepFreeze(${JSON.stringify(STREAM_TRANSITION, null, 2)})
export const DOMAIN_PURPOSE = deepFreeze(${JSON.stringify(DOMAIN_PURPOSE, null, 2)})
export const DOMAIN_RECIPE = deepFreeze(${JSON.stringify(DOMAIN_RECIPE, null, 2)})
export const REQUEST_COMMITMENT_DOMAIN_ID = deepFreeze(${JSON.stringify(REQUEST_COMMITMENT_DOMAIN_ID, null, 2)})
export const RESULT_SIGNATURE_DOMAIN_ID = deepFreeze(${JSON.stringify(RESULT_SIGNATURE_DOMAIN_ID, null, 2)})
export const AUXILIARY_SIGNATURE_DOMAIN_ID = deepFreeze(${JSON.stringify(AUXILIARY_SIGNATURE_DOMAIN_ID, null, 2)})
export const ERROR_PROFILE_ID = deepFreeze(${JSON.stringify(ERROR_PROFILE_ID, null, 2)})
export const ERROR_RETRY_AFTER_MODE = deepFreeze(${JSON.stringify(ERROR_RETRY_AFTER_MODE, null, 2)})
export const DOMAIN_REGISTRY = deepFreeze(${JSON.stringify(DOMAIN_REGISTRY, null, 2)})
export const ADMISSION_COST_RULES = deepFreeze(${JSON.stringify(ADMISSION_COST_RULES, null, 2)})
export const ERROR_PROFILE_ROWS = deepFreeze(${JSON.stringify(ERROR_PROFILE_ROWS, null, 2)})
export const CELL_SIZE_CLASS = deepFreeze(${JSON.stringify(CELL_SIZE_CLASS, null, 2)})
export const INBOX_FRAME_CLASS = deepFreeze(${JSON.stringify(INBOX_FRAME_CLASS, null, 2)})
export const OUTER_CLASS = deepFreeze(${JSON.stringify(OUTER_CLASS, null, 2)})
export const STREAM_WIRE_CLASS = deepFreeze(${JSON.stringify(STREAM_WIRE_CLASS, null, 2)})
export const FORWARD_CIRCUIT_CLASS = deepFreeze(${JSON.stringify(FORWARD_CIRCUIT_CLASS, null, 2)})
export const CORE_SESSION_CLASS = deepFreeze(${JSON.stringify(CORE_SESSION_CLASS, null, 2)})
export const DISPATCH_LIMITS = deepFreeze(${JSON.stringify(DISPATCH_LIMITS, null, 2)})
export const OPERATION_PROFILE_ROWS = deepFreeze(${JSON.stringify(OPERATION_PROFILE_ROWS, null, 2)})
export const CLOCK_UNSAFE_OPERATION_BITS = ${JSON.stringify(CLOCK_UNSAFE_OPERATION_BITS)}

export function domainRegistryEntry (domainId) {
  return DOMAIN_REGISTRY.find(entry => entry.domainId === domainId) || null
}

export function admissionCostRule (costClassRuleId) {
  return ADMISSION_COST_RULES.find(entry => entry.costClassRuleId === costClassRuleId) || null
}

export function errorProfileEntry (errorProfileId, code) {
  return ERROR_PROFILE_ROWS.find(entry =>
    entry.errorProfileId === errorProfileId && entry.code === code) || null
}

export function operationOrdinal (familyId, operationId) {
  return OPERATION_PROFILE_ROWS.findIndex(row =>
    row.familyId === familyId && row.operationId === operationId)
}

export function operationBit (familyId, operationId) {
  const ordinal = operationOrdinal(familyId, operationId)
  return ordinal < 0 ? 0 : 1 << ordinal
}

export function operationProfile (familyId, operationId) {
  return OPERATION_PROFILE_ROWS.find(row =>
    row.familyId === familyId && row.operationId === operationId) || null
}

export function isKnownOperation (familyId, operationId) {
  return operationProfile(familyId, operationId) !== null
}

export function familyName (familyId) {
  return Object.entries(FAMILY).find(([, id]) => id === familyId)?.[0] || null
}

export function routeForFamily (familyId) {
  return FAMILY_ROUTES[familyId] || null
}

export const WIRE_RUNTIME_AUTHORITY = deepFreeze(${JSON.stringify(wireAuthority, null, 2)})
export const WIRE_RUNTIME_AUTHORITY_STATUS = deepFreeze({
  profile: WIRE_RUNTIME_AUTHORITY.profile,
  specHash: WIRE_RUNTIME_AUTHORITY.specHash,
  abiHash: WIRE_RUNTIME_AUTHORITY.abiHash,
  vectorSetHash: WIRE_RUNTIME_AUTHORITY.vectorSetHash,
  wireSchemaCount: WIRE_RUNTIME_AUTHORITY.wireSchemaCount,
  operationCount: WIRE_RUNTIME_AUTHORITY.operationCount,
  errorCount: WIRE_RUNTIME_AUTHORITY.errorCount,
  domainCount: WIRE_RUNTIME_AUTHORITY.domainCount,
  vectorCount: WIRE_RUNTIME_AUTHORITY.vectorCount,
  releaseBlockers: [],
  releaseReady: true
})

export function assertWireAuthorityReady () {
  if (WIRE_RUNTIME_AUTHORITY_STATUS.releaseReady &&
      WIRE_RUNTIME_AUTHORITY_STATUS.releaseBlockers.length === 0) {
    return WIRE_RUNTIME_AUTHORITY_STATUS
  }
  const error = new Error('blind public WIRE authority is incomplete')
  error.code = 'BLIND_WIRE_AUTHORITY_INCOMPLETE'
  error.releaseBlockers = [...WIRE_RUNTIME_AUTHORITY_STATUS.releaseBlockers]
  throw error
}

export const assertReleaseReady = assertWireAuthorityReady
`)

emit(path.join('packages', 'blind-protocol', 'hiverelay-blind-abi-v1.cenc'), abiBytes)
emit(path.join('packages', 'blind-protocol', 'hiverelay-blind-abi-v1.draft.cenc'), abiBytes)
emit(path.join('packages', 'blind-protocol', 'vector-manifest-v1.cenc'), vectorManifestBytes)
emit(path.join('packages', 'blind-protocol', 'hiverelay-blind-wire-authority-v1.json'), wireAuthorityBytes)
emit(path.join('packages', 'blind-protocol', 'schema-catalog-runtime-authority.js'),
  schemaCatalogRuntimeAuthorityBytes)
emit(path.join('packages', 'blind-protocol', 'wire-runtime-authority.js'), wireRuntimeAuthorityBytes)
emit(path.join('packages', 'blind-protocol', 'vectors', 'draft', 'vector-manifest-v1.draft.cenc'), vectorManifestBytes)

if (!wireOnly) {
  const evidenceRegistryBytes = schemaCatalogVectors[2][1]
  const clientExampleRegistryBytes = schemaCatalogVectors[3][1]
  const storeRegistryBytes = schemaCatalogVectors[4][1]
  const storeFormatAuthorityBytes = encodeStoreFormatAuthorityV1(
    storeRegistryBytes,
    STORE_FORMAT_AUTHORITY_V1
  )
  const evidenceVectorManifestBytes = encodeVectorManifest([
    { path: 'registry/evidence-schema-catalog.bin', bytes: evidenceRegistryBytes }
  ])
  const storeVectorManifestBytes = encodeVectorManifest([
    { path: 'registry/internal-store-schema-catalog.bin', bytes: storeRegistryBytes },
    ...vectorFiles.filter(([vectorPath]) => vectorPath.startsWith('store/'))
      .map(([vectorPath, bytes]) => ({ path: vectorPath, bytes }))
  ])
  const completeHashes = {
    ...hashes,
    evidenceFormatHash: b4a.toString(hashEvidenceFormat(evidenceRegistryBytes), 'hex'),
    evidenceVectorSetHash: b4a.toString(hashEvidenceVectorSet(evidenceVectorManifestBytes), 'hex'),
    storeFormatHash: b4a.toString(hashStoreFormat(storeFormatAuthorityBytes), 'hex'),
    storeVectorSetHash: b4a.toString(hashStoreVectorSet(storeVectorManifestBytes), 'hex')
  }
  const hashesBytes = b4a.from(JSON.stringify(completeHashes, null, 2) + '\n')
  emit(path.join('packages', 'blind-protocol', 'hiverelay-blind-schema-catalog-v1.draft.cenc'),
    encodeSchemaCatalog(masterSchemaCatalog.entries))
  emit(path.join('packages', 'blind-protocol', 'hiverelay-blind-evidence-v1.draft.cenc'), evidenceRegistryBytes)
  emit(path.join('packages', 'blind-protocol', 'hiverelay-blind-client-example-v1.draft.cenc'), clientExampleRegistryBytes)
  emit(path.join('packages', 'blind-protocol', 'hiverelay-blind-store-v1.draft.cenc'), storeRegistryBytes)
  emit(path.join('packages', 'blind-protocol', 'hiverelay-blind-store-format-authority-v1.draft.cenc'),
    storeFormatAuthorityBytes)
  emit(path.join('packages', 'blind-protocol', 'hiverelay-blind-evidence-schema-catalog-v1.draft.cenc'),
    evidenceRegistryBytes)
  emit(path.join('packages', 'blind-protocol', 'hiverelay-blind-client-example-schema-catalog-v1.draft.cenc'),
    clientExampleRegistryBytes)
  emit(path.join('packages', 'blind-protocol', 'hiverelay-blind-store-schema-catalog-v1.draft.cenc'),
    storeRegistryBytes)
  emit(path.join('packages', 'blind-protocol', 'vectors', 'evidence', 'vector-manifest-v1.draft.cenc'),
    evidenceVectorManifestBytes)
  emit(path.join('packages', 'blind-protocol', 'vectors', 'store', 'vector-manifest-v1.draft.cenc'),
    storeVectorManifestBytes)
  emit(path.join('packages', 'blind-protocol', 'vectors', 'draft', 'hashes.draft.json'), hashesBytes)
}

if (check) {
  process.stdout.write(`blind public WIRE authority verified (${wireVectorFiles.length} WIRE vectors; ${masterInventoryAudit.catalogSchemaCount} classified schemas; wireReleaseReady=${ABI_STATUS.releaseReady})\n`)
} else {
  process.stdout.write(`blind public WIRE authority generated (${wireVectorFiles.length} WIRE vectors; ${masterInventoryAudit.catalogSchemaCount} classified schemas; wireReleaseReady=${ABI_STATUS.releaseReady})\n`)
}
