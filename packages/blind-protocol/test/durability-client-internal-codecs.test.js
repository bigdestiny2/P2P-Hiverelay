import test from 'brittle'
import b4a from 'b4a'
import {
  CELL_BLOB_V1_BY_SIZE_CLASS,
  HASH_DOMAIN,
  batchGetSignaturePayloadV1,
  blindBackupChunkManifestV1,
  blindBackupEncryptionProfileV1,
  blindBackupManifestV1,
  blindBackupRetentionTransitionV1,
  blindCellAtomicCommittedPutSpendSnapshotV1,
  blindCleanRestoreEvidenceV1,
  blindControlStateSnapshotV1,
  blindCoreReadCapV1,
  blindExternalAckFloorV1,
  blindExternalCommitWitnessV1,
  blindExternalControlCheckpointV1,
  blindLocalCheckpointV1,
  blindPutAtomicCommittedStoreV1,
  blindRestoreEvidenceBundleV1,
  blindRestoreEvidenceHeadV1,
  blindStoreManifestV1,
  blindWalHeaderV2,
  cellRecordV1,
  chargedUnaryRetryV1,
  controlSnapshotHash,
  decodeCanonical,
  domainLengthHash,
  durabilityContinuityBindingV1,
  encodeCanonical,
  inboxReadSignaturePayloadV1,
  localCheckpointHash,
  opaqueChainCheckpointV1,
  opaqueChainFrameV1,
  readCellCapV1,
  relayResultBindingV1,
  writeCellCapV1
} from '../index.js'

const bytes = (length, value) => b4a.alloc(length, value)
const ascii = value => b4a.from(value, 'ascii')

test('version-2 WAL header freezes continuity-bound 192-byte recovery authority', t => {
  const header = {
    magic: ascii('HRWL'),
    walVersion: 2,
    recordType: 9,
    totalLength: 224 + 17,
    walSequence: 1n,
    transactionId: bytes(32, 0x31),
    virtualBucket: 0x1234,
    mapGeneration: 1n,
    writerFenceTokenHash: bytes(32, 0x32),
    payloadLength: 17,
    previousWalHash: bytes(32, 0),
    durabilityContinuityHash: bytes(32, 0x33),
    payloadHash: bytes(32, 0x34)
  }
  const canonical = encodeCanonical(blindWalHeaderV2, header)
  t.is(canonical.byteLength, 192)
  const decoded = decodeCanonical(blindWalHeaderV2, canonical)
  t.is(decoded.walVersion, 2)
  t.alike(decoded.durabilityContinuityHash, header.durabilityContinuityHash)
  t.exception(() => encodeCanonical(blindWalHeaderV2, {
    ...header,
    walSequence: 2n
  }), /predecessor hash zero state/)
  t.exception(() => encodeCanonical(blindWalHeaderV2, {
    ...header,
    totalLength: header.totalLength + 1
  }), /total and payload lengths disagree/)
})

test('atomic Cell PUT store and checkpoint codecs require result authority without reservation fields', t => {
  const committed = {
    version: 1,
    spendTag: bytes(32, 0x35),
    requestCommitment: bytes(32, 0x36),
    requestFingerprint: bytes(32, 0x37),
    storageSlot: bytes(32, 0x38),
    allocationEpoch: 1,
    sizeClass: 1,
    leaseClass: 1,
    declaredBlobHash: bytes(32, 0x39),
    createPublicKey: bytes(32, 0x3a),
    renewPublicKey: bytes(32, 0x3b),
    dropPublicKey: bytes(32, 0x3c),
    allocationCommitment: bytes(32, 0x3d),
    profileId: 1,
    preparedAdmissionBytes: bytes(1, 0x3e),
    resultBindingBytes: bytes(1, 0x3f),
    declaredBytes: 4096,
    blobObjectId: bytes(32, 0x40),
    leaseEpoch: 5,
    stateRevision: 0n,
    policyRevision: 0n,
    resultIdentity: bytes(32, 0x41),
    committedEpoch: 1
  }
  const encoded = encodeCanonical(blindPutAtomicCommittedStoreV1, committed)
  t.alike(decodeCanonical(blindPutAtomicCommittedStoreV1, encoded).resultIdentity,
    committed.resultIdentity)
  t.exception(() => encodeCanonical(blindPutAtomicCommittedStoreV1, {
    ...committed,
    resultBindingBytes: null
  }), /resultBindingBytes/)

  const checkpoint = decodeCanonical(blindCellAtomicCommittedPutSpendSnapshotV1,
    encodeCanonical(blindCellAtomicCommittedPutSpendSnapshotV1, {
      ...committed,
      transactionId: bytes(32, 0x42),
      resultCell: {
        storageSlot: committed.storageSlot,
        allocationEpoch: committed.allocationEpoch,
        sizeClass: committed.sizeClass,
        leaseClass: committed.leaseClass,
        leaseEpoch: committed.leaseEpoch,
        stateRevision: committed.stateRevision,
        policyRevision: committed.policyRevision,
        cellBlobHash: committed.declaredBlobHash,
        allocationCommitment: committed.allocationCommitment,
        objectState: 1,
        policyState: 1
      }
    }))
  t.absent(checkpoint.deadlineUnixMillis)
  t.absent(checkpoint.remainingAttempts)
  t.absent(checkpoint.reservedEpoch)
})

test('local checkpoint header binds one exact snapshot and covered WAL anchor', t => {
  const checkpoint = {
    magic: ascii('HRBCKP01'),
    checkpointVersion: 1,
    relayPublicKey: bytes(32, 0x41),
    storeId: bytes(32, 0x42),
    durabilityProfileId: 1,
    durabilityContinuityHash: bytes(32, 0x43),
    durabilityProfileHash: bytes(32, 0x44),
    formatMajor: 1,
    formatMinor: 1,
    storeFormatHash: bytes(32, 0x45),
    specHash: bytes(32, 0x46),
    abiHash: bytes(32, 0x47),
    mapGeneration: 1n,
    bucketMapHash: bytes(32, 0x48),
    writerEpoch: 1n,
    writerFenceTokenHash: bytes(32, 0x49),
    checkpointRevision: 1n,
    previousCheckpointHash: null,
    coveredWalSequence: 9n,
    coveredWalHash: bytes(32, 0x4a),
    epochFloor: 10,
    descriptorSequenceFloor: 2n,
    descriptorHashFloor: bytes(32, 0x4b),
    snapshotByteLength: 512n,
    snapshotHash: bytes(32, 0x4c)
  }
  const canonical = encodeCanonical(blindLocalCheckpointV1, checkpoint)
  t.alike(encodeCanonical(blindLocalCheckpointV1,
    decodeCanonical(blindLocalCheckpointV1, canonical)), canonical)
  t.is(localCheckpointHash(canonical).byteLength, 32)
  t.exception(() => encodeCanonical(blindLocalCheckpointV1, {
    ...checkpoint,
    checkpointRevision: 2n
  }), /predecessor presence/)
  t.exception(() => encodeCanonical(blindLocalCheckpointV1, {
    ...checkpoint,
    snapshotByteLength: 0n
  }), /must be nonzero/)
})

function externalWitness () {
  return {
    version: 1,
    relayPublicKey: bytes(32, 1),
    storeId: bytes(32, 2),
    externalJournalId: bytes(32, 3),
    durabilityContinuityHash: bytes(32, 4),
    durabilityProfileHash: bytes(32, 5),
    restoreEvidenceHeadSequence: 1n,
    restoreEvidenceHeadHash: bytes(32, 6),
    familyId: 2,
    operationId: 1,
    requestCommitment: bytes(32, 7),
    resultCommitment: bytes(32, 8),
    commitWalSequence: 9n,
    commitWalHash: bytes(32, 9),
    coveringFloorRevision: 10n,
    coveringFloorHash: bytes(32, 10),
    coveringFloorWalSequence: 9n,
    coveringFloorWalHash: bytes(32, 11),
    writerEpoch: 12n,
    writerFenceTokenHash: bytes(32, 12),
    externalLeaseRevision: 13n,
    witnessedUnixMillis: 14n,
    witnessPublicKey: bytes(32, 13),
    signature: bytes(64, 14)
  }
}

function resultBinding () {
  const witness = externalWitness()
  return {
    version: 1,
    relayPublicKey: witness.relayPublicKey,
    storeId: witness.storeId,
    descriptorSequence: 15n,
    descriptorHash: bytes(32, 15),
    durabilityProfileId: 2,
    durabilityContinuityHash: witness.durabilityContinuityHash,
    durabilityProfileHash: witness.durabilityProfileHash,
    restoreEvidenceHeadSequence: witness.restoreEvidenceHeadSequence,
    restoreEvidenceHeadHash: witness.restoreEvidenceHeadHash,
    externalCommitWitness: witness
  }
}

function restoreHead () {
  const issued = 21600000n * 10n
  return {
    version: 1,
    relayPublicKey: bytes(32, 21),
    storeId: bytes(32, 22),
    externalJournalId: bytes(32, 23),
    durabilityContinuityHash: bytes(32, 24),
    restoreEvidenceFeedId: bytes(32, 25),
    evidenceSequence: 1n,
    previousEvidenceHeadHash: null,
    currentBackupManifestHash: bytes(32, 26),
    currentRetentionTransitionHash: bytes(32, 27),
    currentCoveredWalSequence: 28n,
    currentExternalFloorRevision: 29n,
    currentChunkObjectCount: 30n,
    currentAvailabilityAuditHash: bytes(32, 31),
    currentSupportExpiresUnixMillis: issued + 100000n,
    drillBackupManifestHash: bytes(32, 32),
    drillCleanRestoreEvidenceHash: bytes(32, 33),
    drillRetentionTransitionHash: bytes(32, 34),
    restoreDrillCompletedUnixMillis: issued - 1000n,
    drillSupportExpiresUnixMillis: issued + 100000n,
    issuedExternalUnixMillis: issued,
    expiresExternalUnixMillis: issued + 200000n,
    issuedEpoch: 10,
    witnessPublicKey: bytes(32, 35),
    signature: bytes(64, 36)
  }
}

function readCap (seed = 41) {
  return {
    version: 1,
    relayPublicKey: bytes(32, seed),
    storageSlot: bytes(32, seed + 1),
    cellKey: bytes(32, seed + 2),
    sizeClass: 1,
    expectedCellBlobHash: bytes(32, seed + 3)
  }
}

test('result bindings carry external commit continuity and signature payloads', t => {
  const witness = externalWitness()
  t.is(decodeCanonical(blindExternalCommitWitnessV1,
    encodeCanonical(blindExternalCommitWitnessV1, witness)).commitWalSequence, 9n)
  const binding = resultBinding()
  t.is(decodeCanonical(relayResultBindingV1,
    encodeCanonical(relayResultBindingV1, binding)).durabilityProfileId, 2)
  t.exception(() => encodeCanonical(relayResultBindingV1, {
    ...binding,
    restoreEvidenceHeadHash: bytes(32, 99)
  }), /does not match relay binding/)
  const batch = {
    version: 1,
    relayBinding: binding,
    requestNonce: bytes(32, 51),
    requestCommitment: bytes(32, 52),
    entriesCommitment: bytes(32, 53)
  }
  t.alike(decodeCanonical(batchGetSignaturePayloadV1,
    encodeCanonical(batchGetSignaturePayloadV1, batch)).entriesCommitment, batch.entriesCommitment)
  const inbox = {
    version: 1,
    relayBinding: binding,
    requestNonce: bytes(32, 54),
    requestCommitment: bytes(32, 55),
    snapshotRevision: 56n,
    entriesCommitment: bytes(32, 57),
    nextCursor: bytes(8, 58)
  }
  const encodedInbox = encodeCanonical(inboxReadSignaturePayloadV1, inbox)
  const decodedInbox = decodeCanonical(inboxReadSignaturePayloadV1, encodedInbox)
  t.is(decodedInbox.snapshotRevision, 56n)
  t.alike(decodedInbox.relayBinding, binding)
  t.alike(decodedInbox.requestNonce, inbox.requestNonce)
  t.alike(decodedInbox.requestCommitment, inbox.requestCommitment)
  t.alike(decodedInbox.entriesCommitment, inbox.entriesCommitment)
  t.alike(decodedInbox.nextCursor, inbox.nextCursor)
  const nullCursor = encodeCanonical(inboxReadSignaturePayloadV1, { ...inbox, nextCursor: null })
  t.is(decodeCanonical(inboxReadSignaturePayloadV1, nullCursor).nextCursor, null)
  t.unlike(encodedInbox, nullCursor, 'cursor presence changes the normative signed bytes')
  t.unlike(encodedInbox, encodeCanonical(inboxReadSignaturePayloadV1, {
    ...inbox,
    entriesCommitment: bytes(32, 59)
  }), 'entries commitment changes the normative signed bytes')
})

test('public backup and restore codecs round trip their frozen continuity chain', t => {
  const continuity = {
    version: 1,
    profileId: 2,
    externalJournalId: bytes(32, 61),
    externalWitnessPublicKey: bytes(32, 62),
    externalJournalReplicationClass: 1,
    externalJournalFailureGroupId: bytes(32, 63),
    restoreEvidenceFeedId: bytes(32, 64)
  }
  t.is(decodeCanonical(durabilityContinuityBindingV1,
    encodeCanonical(durabilityContinuityBindingV1, continuity)).profileId, 2)
  const encryptionProfile = {
    version: 1,
    algorithmId: 1,
    keyDerivationId: 1,
    recoveryKeyId: bytes(32, 65),
    keyEpoch: 1
  }
  t.is(decodeCanonical(blindBackupEncryptionProfileV1,
    encodeCanonical(blindBackupEncryptionProfileV1, encryptionProfile)).keyEpoch, 1)
  const chunkManifest = {
    version: 1,
    backupId: bytes(32, 66),
    encryptionProfile,
    encryptionManifestHash: bytes(32, 67),
    entries: [{
      path: ascii('store/manifest'),
      fileOffset: 0n,
      plaintextByteLength: 1024,
      ciphertextByteLength: 1040,
      chunkObjectId: bytes(32, 68),
      chunkSalt: bytes(32, 69),
      nonce: bytes(24, 70),
      ciphertextHash: bytes(32, 71)
    }],
    totalPlaintextByteLength: 1024n,
    totalCiphertextByteLength: 1040n
  }
  t.is(decodeCanonical(blindBackupChunkManifestV1,
    encodeCanonical(blindBackupChunkManifestV1, chunkManifest)).entries.length, 1)
  t.exception(() => encodeCanonical(blindBackupChunkManifestV1, {
    ...chunkManifest,
    totalCiphertextByteLength: 1041n
  }), /do not equal/)
  const manifest = {
    version: 1,
    relayPublicKey: bytes(32, 72),
    storeId: bytes(32, 73),
    externalJournalId: bytes(32, 74),
    durabilityContinuityHash: bytes(32, 75),
    backupId: chunkManifest.backupId,
    backupFailureGroupId: bytes(32, 76),
    storeManifestRevision: 1n,
    storeManifestHash: bytes(32, 77),
    storeFormatHash: bytes(32, 78),
    coverageCutoffExternalUnixMillis: 100n,
    coveredWalSequence: 2n,
    coveredWalHash: bytes(32, 79),
    externalFloorRevision: 3n,
    externalFloorHash: bytes(32, 80),
    externalCheckpointRevision: 4n,
    externalCheckpointHash: bytes(32, 81),
    baseFloorRevision: 3n,
    baseFloorHash: bytes(32, 82),
    controlSnapshotHash: bytes(32, 83),
    backupEncryptionProfileHash: bytes(32, 84),
    encryptionManifestHash: chunkManifest.encryptionManifestHash,
    chunkManifestByteLength: 1000n,
    chunkManifestHash: bytes(32, 85),
    totalPlaintextByteLength: chunkManifest.totalPlaintextByteLength,
    totalCiphertextByteLength: chunkManifest.totalCiphertextByteLength,
    restoreVerifierPublicKey: bytes(32, 86),
    cleanRestoreEvidenceHash: bytes(32, 87),
    createdExternalUnixMillis: 200n,
    restoreSupportExpiresUnixMillis: 300n,
    witnessPublicKey: bytes(32, 88),
    signature: bytes(64, 89)
  }
  t.is(decodeCanonical(blindBackupManifestV1,
    encodeCanonical(blindBackupManifestV1, manifest)).backupFailureGroupId.byteLength, 32)
  const clean = {
    version: 1,
    backupId: manifest.backupId,
    backupCandidateCommitment: bytes(32, 90),
    restoredStoreManifestHash: bytes(32, 91),
    verifiedWalSequence: 2n,
    verifiedWalHash: manifest.coveredWalHash,
    verifiedExternalFloorRevision: 3n,
    verifiedExternalFloorHash: manifest.externalFloorHash,
    verifiedCheckpointRevision: 4n,
    verifiedCheckpointHash: manifest.externalCheckpointHash,
    scrubbedObjectCount: 5n,
    scrubFailureCount: 0,
    startedExternalUnixMillis: 201n,
    completedExternalUnixMillis: 202n,
    verifierPublicKey: manifest.restoreVerifierPublicKey,
    signature: bytes(64, 92)
  }
  t.is(decodeCanonical(blindCleanRestoreEvidenceV1,
    encodeCanonical(blindCleanRestoreEvidenceV1, clean)).scrubFailureCount, 0)
  const retention = {
    version: 1,
    relayPublicKey: manifest.relayPublicKey,
    storeId: manifest.storeId,
    externalJournalId: manifest.externalJournalId,
    durabilityContinuityHash: manifest.durabilityContinuityHash,
    backupId: manifest.backupId,
    backupManifestHash: bytes(32, 93),
    transitionRevision: 1n,
    previousTransitionHash: null,
    operation: 1,
    supportExpiresUnixMillis: 300n,
    replacementBackupId: null,
    effectiveExternalTimeFloorMillis: 203n,
    witnessPublicKey: manifest.witnessPublicKey,
    signature: bytes(64, 94)
  }
  t.is(decodeCanonical(blindBackupRetentionTransitionV1,
    encodeCanonical(blindBackupRetentionTransitionV1, retention)).operation, 1)
  const head = restoreHead()
  t.is(decodeCanonical(blindRestoreEvidenceHeadV1,
    encodeCanonical(blindRestoreEvidenceHeadV1, head)).evidenceSequence, 1n)
  const bundle = {
    version: 1,
    heads: [head],
    currentBackupManifestBytes: bytes(1, 1),
    currentRetentionTransitionBytes: bytes(1, 2),
    drillBackupManifestBytes: bytes(1, 3),
    drillCleanRestoreEvidenceBytes: bytes(1, 4),
    drillRetentionTransitionBytes: bytes(1, 5)
  }
  t.is(decodeCanonical(blindRestoreEvidenceBundleV1,
    encodeCanonical(blindRestoreEvidenceBundleV1, bundle)).heads.length, 1)
})

test('client example codecs remain contextual and never become relay wire imports', t => {
  const cap = readCap()
  t.is(decodeCanonical(readCellCapV1, encodeCanonical(readCellCapV1, cap)).sizeClass, 1)
  const write = {
    readCap: cap,
    allocationEpoch: 10,
    createPrivateKey: bytes(32, 45),
    renewPrivateKey: bytes(32, 46),
    dropPrivateKey: bytes(32, 47)
  }
  t.alike(decodeCanonical(writeCellCapV1,
    encodeCanonical(writeCellCapV1, write)).readCap.storageSlot, cap.storageSlot)
  const cellBlob = { formatVersion: 1, nonce: bytes(12, 48), sealed: bytes(4096 - 13, 49) }
  t.is(encodeCanonical(CELL_BLOB_V1_BY_SIZE_CLASS[1], cellBlob).byteLength, 4096)
  const checkpoint = {
    version: 1,
    coveredFrontier: [{ chainId: bytes(32, 50), sequence: 1n, frameHash: bytes(32, 51) }],
    opaqueStateCommitment: bytes(32, 52),
    snapshotPayloadHash: bytes(32, 53),
    snapshotReadCaps: [cap]
  }
  t.is(decodeCanonical(opaqueChainCheckpointV1,
    encodeCanonical(opaqueChainCheckpointV1, checkpoint)).coveredFrontier.length, 1)
  const frame = {
    version: 1,
    chainId: bytes(32, 54),
    sequence: 0n,
    previousFrameHash: null,
    transportVerifyKey: bytes(32, 55),
    opaquePayloads: [bytes(1, 56)],
    nextReadCellCaps: [cap],
    checkpoint,
    transportSignature: bytes(64, 57)
  }
  t.is(decodeCanonical(opaqueChainFrameV1,
    encodeCanonical(opaqueChainFrameV1, frame)).sequence, 0n)
  const coreCap = {
    version: 1,
    corePublicKey: bytes(32, 58),
    blockEncryptionKey: bytes(32, 59),
    witnessedFork: 0n,
    witnessedLength: 1n,
    witnessedSignedHead: bytes(1, 60)
  }
  t.is(decodeCanonical(blindCoreReadCapV1,
    encodeCanonical(blindCoreReadCapV1, coreCap)).witnessedLength, 1n)
})

test('internal store codecs bind migration, floors, checkpoints and retry caps', t => {
  const record = {
    version: 1,
    slot: bytes(32, 101),
    allocationEpoch: 1,
    sizeClass: 1,
    leaseClass: 1,
    leaseEpoch: 2,
    stateRevision: 3n,
    policyRevision: 4n,
    cellBlobHash: bytes(32, 102),
    cellBlob: bytes(4096, 103),
    createPublicKey: bytes(32, 104),
    renewPublicKey: bytes(32, 105),
    dropPublicKey: bytes(32, 106),
    allocationCommitment: bytes(32, 107)
  }
  t.is(decodeCanonical(cellRecordV1, encodeCanonical(cellRecordV1, record)).stateRevision, 3n)
  const retry = {
    version: 1,
    spendTag: bytes(32, 108),
    requestCommitment: bytes(32, 109),
    familyId: 2,
    operationId: 2,
    locatorCommitment: bytes(32, 110),
    sourceRevision: 3n,
    sourceCommitment: bytes(32, 111),
    resultCommitment: bytes(32, 112),
    reconstruction: bytes(4, 113),
    retryExpiresMinute: 10n,
    retryState: 1
  }
  t.ok(encodeCanonical(chargedUnaryRetryV1, retry).byteLength <= 256)
  const snapshot = {
    version: 1,
    relayPublicKey: bytes(32, 114),
    storeId: bytes(32, 115),
    durabilityContinuityHash: bytes(32, 116),
    walSequence: 1n,
    walHash: bytes(32, 117),
    entries: []
  }
  const snapshotBytes = encodeCanonical(blindControlStateSnapshotV1, snapshot)
  t.is(decodeCanonical(blindControlStateSnapshotV1, snapshotBytes).entries.length, 0)
  t.is(HASH_DOMAIN.CONTROL_SNAPSHOT, 'hiverelay.blind.control-snapshot.v1')
  t.alike(controlSnapshotHash(snapshotBytes),
    domainLengthHash('hiverelay.blind.control-snapshot.v1', snapshotBytes))
  const floor = {
    version: 1,
    relayPublicKey: snapshot.relayPublicKey,
    storeId: snapshot.storeId,
    externalJournalId: bytes(32, 118),
    durabilityContinuityHash: snapshot.durabilityContinuityHash,
    floorRevision: 1n,
    previousFloorHash: null,
    writerEpoch: 2n,
    writerFenceTokenHash: bytes(32, 119),
    externalLeaseRevision: 3n,
    walSequence: snapshot.walSequence,
    walHash: snapshot.walHash,
    descriptorSequence: 4n,
    descriptorHash: bytes(32, 120),
    witnessedUnixMillis: 5n,
    witnessPublicKey: bytes(32, 121),
    signature: bytes(64, 122)
  }
  t.is(decodeCanonical(blindExternalAckFloorV1,
    encodeCanonical(blindExternalAckFloorV1, floor)).floorRevision, 1n)
  const checkpoint = {
    version: 1,
    relayPublicKey: floor.relayPublicKey,
    storeId: floor.storeId,
    externalJournalId: floor.externalJournalId,
    durabilityContinuityHash: floor.durabilityContinuityHash,
    checkpointRevision: 1n,
    previousCheckpointHash: null,
    baseFloorRevision: floor.floorRevision,
    baseFloorHash: bytes(32, 123),
    writerEpoch: floor.writerEpoch,
    writerFenceTokenHash: floor.writerFenceTokenHash,
    externalLeaseRevision: floor.externalLeaseRevision,
    walSequence: floor.walSequence,
    walHash: floor.walHash,
    descriptorSequence: floor.descriptorSequence,
    descriptorHash: floor.descriptorHash,
    snapshotByteLength: 100n,
    snapshotHash: bytes(32, 124),
    oldestRetainedFloorRevision: 1n,
    createdUnixMillis: 6n,
    witnessPublicKey: floor.witnessPublicKey,
    signature: bytes(64, 125)
  }
  t.is(decodeCanonical(blindExternalControlCheckpointV1,
    encodeCanonical(blindExternalControlCheckpointV1, checkpoint)).checkpointRevision, 1n)
  const manifest = {
    magic: ascii('HRBLIND1'),
    manifestVersion: 1,
    storeId: snapshot.storeId,
    relayPublicKey: snapshot.relayPublicKey,
    durabilityProfileId: 1,
    durabilityContinuityHash: snapshot.durabilityContinuityHash,
    durabilityProfileHash: bytes(32, 126),
    formatMajor: 1,
    formatMinor: 1,
    storeFormatHash: bytes(32, 127),
    specHash: bytes(32, 128),
    abiHash: bytes(32, 129),
    mapGeneration: 1n,
    bucketMapHash: bytes(32, 130),
    checkpointWalSequence: 1n,
    checkpointHash: bytes(32, 131),
    epochFloor: 1,
    writerEpoch: 1n,
    writerFenceTokenHash: bytes(32, 132),
    externalLeaseRevision: 0n,
    externalJournalId: bytes(32, 0),
    externalWitnessPublicKey: bytes(32, 0),
    restoreEvidenceFeedId: bytes(32, 0),
    lastAckWalSequence: 0n,
    lastAckWalHash: bytes(32, 0),
    externalCheckpointRevision: 0n,
    externalCheckpointHash: bytes(32, 0),
    descriptorSequenceFloor: 1n,
    descriptorHashFloor: bytes(32, 133),
    migrationState: 0,
    sourceFormatMajor: 0,
    targetFormatMajor: 0,
    migrationCursorHash: bytes(32, 0),
    previousManifestHash: null,
    manifestRevision: 0n,
    mac: bytes(32, 134)
  }
  t.is(decodeCanonical(blindStoreManifestV1,
    encodeCanonical(blindStoreManifestV1, manifest)).migrationState, 0)
  t.exception(() => encodeCanonical(blindStoreManifestV1, {
    ...manifest,
    externalJournalId: bytes(32, 1)
  }), /zero external continuity state/)
})
