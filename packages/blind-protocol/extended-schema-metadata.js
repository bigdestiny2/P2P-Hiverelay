const bytes32 = 'fixed32'
const bytes64 = 'fixed64'

function schema (name, fields) {
  return { name, fields }
}

function masterDefined (name) {
  return schema(name, [['canonicalDefinition', 'schema-meta-v1(master-declaration)']])
}

export const SCHEMA_METADATA_OVERRIDES = Object.freeze([
  schema('BlindReceiptV1', [
    ['version', 'u8=1'], ['protocol', 'exact-ascii(hiverelay-blind-cell-v1)'],
    ['relayBinding', 'RelayResultBindingV1'], ['slotCommitment', bytes32],
    ['cellBlobHash', bytes32], ['allocationCommitment', bytes32], ['requestCommitment', bytes32],
    ['sizeClass', 'u8[1..5]'], ['allocationEpoch', 'u32be'], ['leaseClass', 'u8[0..4]'],
    ['leaseEpoch', 'u32be'], ['stateRevision', 'u64be'], ['receiptEpoch', 'u32be'],
    ['requestNonce', bytes32], ['result', 'u8[1..4]'], ['signature', bytes64]
  ]),
  schema('BatchGetResultV1', [
    ['version', 'u8=1'], ['relayBinding', 'RelayResultBindingV1'], ['requestNonce', bytes32],
    ['requestCommitment', bytes32], ['entries', 'array[1..64](BatchGetEntryV1)'],
    ['entriesCommitment', bytes32], ['signature', bytes64]
  ]),
  schema('InboxReceiptV1', [
    ['version', 'u8=1'], ['relayBinding', 'RelayResultBindingV1'], ['topicCommitment', bytes32],
    ['stateRevision', 'u64be'], ['leaseClass', 'u8[0..4]'], ['leaseEpoch', 'u32be'],
    ['requestNonce', bytes32], ['requestCommitment', bytes32], ['result', 'u8[1..3]'],
    ['signature', bytes64]
  ]),
  schema('InboxAppendAckV1', [
    ['version', 'u8=1'], ['relayBinding', 'RelayResultBindingV1'], ['topicCommitment', bytes32],
    ['frameHash', bytes32], ['appendRevision', 'u64be'], ['storedAtEpoch', 'u32be'],
    ['expiresAtEpoch', 'u32be'], ['requestNonce', bytes32], ['requestCommitment', bytes32],
    ['result', 'u8=1'], ['signature', bytes64]
  ]),
  schema('InboxReadResultV1', [
    ['version', 'u8=1'], ['relayBinding', 'RelayResultBindingV1'], ['requestNonce', bytes32],
    ['requestCommitment', bytes32], ['snapshotRevision', 'u64be'], ['entries', 'array[0..64](InboxReadEntryV1)'],
    ['entriesCommitment', bytes32], ['nextCursor', 'optional(compact-bytes[0..128])'], ['signature', bytes64]
  ]),
  schema('BlindCoreAckV1', [
    ['version', 'u8=1'], ['relayBinding', 'RelayResultBindingV1'], ['corePublicKey', bytes32],
    ['fork', 'u64be'], ['length', 'u64be'], ['signedHeadHash', bytes32], ['observedAtEpoch', 'u32be'],
    ['leaseEpoch', 'u32be'], ['result', 'u8[1..2]'], ['requestNonce', bytes32],
    ['requestCommitment', bytes32], ['signature', bytes64]
  ]),
  schema('CoreOpenReplicationResultV1', [
    ['version', 'u8=1'], ['relayBinding', 'RelayResultBindingV1'], ['wireProfileHash', bytes32],
    ['sessionClass', 'u8[1..3]'], ['controlChannelId', 'u64be-nonzero'], ['parentChannelBinding', bytes32],
    ['streamId', 'u64be-nonzero'], ['maxSessionBytes', 'u64be[class-tuple]'],
    ['idleMillis', 'u32be[class-tuple]'], ['lifetimeMillis', 'u32be[class-tuple]'],
    ['openedAtEpoch', 'u32be'], ['requestNonce', bytes32],
    ['requestCommitment', bytes32], ['signature', bytes64]
  ]),
  schema('BlindForwardOpenResultV1', [
    ['version', 'u8=1'], ['relayBinding', 'RelayResultBindingV1'], ['routeId', 'fixed16'],
    ['nextDescriptorSequence', 'u64be'], ['nextDescriptorHash', bytes32], ['circuitNonce', bytes32],
    ['grantedWireClass', 'u8[1..3]'], ['circuitClass', 'u8[1..3]'], ['streamId', 'u64be-nonzero'],
    ['grantedInitialWindow', 'u32be[class-tuple]'],
    ['maxDataBytes', 'u32be[wire-class]'], ['maxCircuitBytes', 'u64be[class-tuple]'],
    ['idleMillis', 'u32be[class-tuple]'], ['lifetimeMillis', 'u32be[class-tuple]'],
    ['openedAtEpoch', 'u32be'], ['requestCommitment', bytes32],
    ['nextHopAccept', 'BlindForwardHopAcceptV1'], ['signature', bytes64]
  ]),
  schema('BlindForwardHopAcceptV1', [
    ['version', 'u8=1'], ['previousRelayKey', bytes32], ['previousDescriptorSequence', 'u64be'],
    ['previousDescriptorHash', bytes32], ['nextRelayKey', bytes32], ['nextDescriptorSequence', 'u64be'],
    ['nextDescriptorHash', bytes32], ['nextRelayBinding', 'RelayResultBindingV1'], ['routeId', 'fixed16'],
    ['circuitNonce', bytes32], ['nextStreamId', 'u64be-nonzero'], ['grantedWireClass', 'u8[1..3]'],
    ['circuitClass', 'u8[1..3]'], ['grantedInitialWindow', 'u32be[class-tuple]'],
    ['maxDataBytes', 'u32be[wire-class]'], ['maxCircuitBytes', 'u64be[class-tuple]'],
    ['idleMillis', 'u32be[class-tuple]'], ['lifetimeMillis', 'u32be[class-tuple]'],
    ['openedAtEpoch', 'u32be'], ['hopOpenCommitment', bytes32], ['handshakeFlight2', 'fixed96'], ['nextSignature', bytes64]
  ]),
  schema('DurabilityProfileV1', [
    ['profileId', 'u8[1..2]'], ['storeFormatMajor', 'u16be'], ['storeFormatMinor', 'u16be'],
    ['storeFormatHash', bytes32], ['externalJournalId', bytes32], ['externalWitnessPublicKey', bytes32],
    ['externalJournalReplicationClass', 'u8[0..1]'], ['externalJournalFailureGroupId', bytes32],
    ['externalCheckpointAgeBand', 'u8[0..7]'], ['externalJournalTopologyUrl', 'optional(canonical-https-url[1..512])'],
    ['externalJournalTopologyHash', bytes32], ['restoreEvidenceFeedUrl', 'optional(canonical-https-url[1..512])'],
    ['restoreEvidenceFeedId', bytes32], ['restoreEvidenceCheckpointSequence', 'u64be'],
    ['restoreEvidenceCheckpointHash', bytes32], ['acknowledgedRpoBand', 'u8[0..3]'],
    ['targetRtoBand', 'u8[0..3]'], ['redundancyClass', 'u8[0..2]'], ['restoreDrillAgeBand', 'u8[0..7]']
  ]),
  schema('BuildProfileV1', [
    ['specHash', bytes32], ['abiHash', bytes32], ['vectorSetHash', bytes32], ['evidenceFormatHash', bytes32],
    ['evidenceVectorSetHash', bytes32], ['storeFormatHash', bytes32], ['storeVectorSetHash', bytes32],
    ['privateIpcFormatHash', bytes32], ['privateIpcVectorSetHash', bytes32], ['buildArtifactHash', bytes32],
    ['buildArtifactUrl', 'canonical-https-url[1..512]'], ['buildManifestUrl', 'canonical-https-url[1..512]'],
    ['buildManifestHash', bytes32], ['releaseEvidenceBundleUrl', 'canonical-https-url[1..512]'],
    ['releaseEvidenceBundleHash', bytes32], ['releaseSupportHorizonHash', bytes32],
    ['runtimeBoundaryEvidenceUrl', 'canonical-https-url[1..512]'], ['runtimeBoundaryEvidenceHash', bytes32]
  ])
])

export const EXTENDED_SCHEMA_METADATA = Object.freeze([
  schema('BatchGetSignaturePayloadV1', [
    ['version', 'u8=1'], ['relayBinding', 'RelayResultBindingV1'], ['requestNonce', bytes32],
    ['requestCommitment', bytes32], ['entriesCommitment', bytes32]
  ]),
  schema('BlindBackupChunkManifestV1', [
    ['version', 'u8=1'], ['backupId', bytes32], ['encryptionProfile', 'BlindBackupEncryptionProfileV1'],
    ['encryptionManifestHash', bytes32], ['entries', 'sorted-array[1..16777216](backup-chunk-entry-v1)'],
    ['totalPlaintextByteLength', 'u64be'], ['totalCiphertextByteLength', 'u64be']
  ]),
  schema('BlindBackupEncryptionProfileV1', [
    ['version', 'u8=1'], ['algorithmId', 'u16be=1'], ['keyDerivationId', 'u16be=1'],
    ['recoveryKeyId', bytes32], ['keyEpoch', 'u32be-nonzero']
  ]),
  schema('BlindBackupManifestV1', [['canonicalDefinition', 'schema-meta-v1(master-declaration)']]),
  schema('BlindBackupRetentionTransitionV1', [['canonicalDefinition', 'schema-meta-v1(master-declaration)']]),
  schema('BlindCellChargedReadPinEntrySnapshotV1', [
    ['storageSlot', bytes32], ['present', 'u8[0..1]'], ['sizeClass', 'u8[0..5]'],
    ['allocationEpoch', 'u32be'], ['leaseClass', 'u8[0..4]'], ['leaseEpoch', 'u32be'],
    ['stateRevision', 'u64be'], ['policyRevision', 'u64be'], ['cellBlobHash', bytes32],
    ['allocationCommitment', bytes32]
  ]),
  schema('BlindCellChargedReadRetrySnapshotV1', [
    ['version', 'u8=1'], ['lifecycleState', 'u8[1..3]'],
    ['operationId', 'u8{CELL.GET=2,CELL.PROVE=5,CELL.BATCH_GET=6}'],
    ['transactionId', bytes32], ['spendTag', bytes32], ['requestCommitment', bytes32],
    ['requestFingerprint', bytes32], ['preparedAdmissionBytes', 'optional(compact-bytes[1..17408])'],
    ['resultBindingBytes', 'optional(compact-bytes[1..1024])'], ['receiptEpoch', 'optional(u32be)'],
    ['retryExpiresUnixMillis', 'u64be-nonzero'],
    ['entries', 'optional(array[1..64](BlindCellChargedReadPinEntrySnapshotV1))'],
    ['resultCommitment', 'optional(bytes32)'], ['committedEpoch', 'u32be'],
    ['terminalEpoch', 'optional(u32be)']
  ]),
  schema('BlindCellCommittedPutSpendSnapshotV1', [
    ['version', 'u8=1'], ['transactionId', bytes32], ['spendTag', bytes32], ['requestCommitment', bytes32],
    ['requestFingerprint', bytes32], ['storageSlot', bytes32], ['allocationEpoch', 'u32be'],
    ['sizeClass', 'u8[1..5]'], ['leaseClass', 'u8[1..4]'], ['declaredBlobHash', bytes32],
    ['createPublicKey', bytes32], ['renewPublicKey', bytes32], ['dropPublicKey', bytes32],
    ['allocationCommitment', bytes32], ['profileId', 'u16be[1..65535]'],
    ['preparedAdmissionBytes', 'compact-bytes[1..17408]'],
    ['resultBindingBytes', 'optional(compact-bytes[1..1024])'], ['declaredBytes', 'u32be'],
    ['deadlineUnixMillis', 'u64be-nonzero'], ['remainingAttempts', 'u8[0..1]'], ['reservedEpoch', 'u32be'],
    ['resultIdentity', bytes32], ['committedEpoch', 'u32be'],
    ['resultCell', 'BlindCellHistoricalResultSnapshotV1']
  ]),
  schema('BlindCellCommittedRenewSpendSnapshotV1', [
    ['version', 'u8=1'], ['transactionId', bytes32], ['spendTag', bytes32], ['requestCommitment', bytes32],
    ['requestFingerprint', bytes32], ['storageSlot', bytes32], ['expectedStateRevision', 'u64be'],
    ['expectedLeaseEpoch', 'u32be'], ['requestedLeaseClass', 'u8[1..4]'],
    ['profileId', 'u16be[1..65535]'],
    ['preparedAdmissionBytes', 'compact-bytes[1..17408]'],
    ['resultBindingBytes', 'optional(compact-bytes[1..1024])'],
    ['resultIdentity', bytes32], ['committedEpoch', 'u32be'],
    ['resultCell', 'BlindCellHistoricalResultSnapshotV1']
  ]),
  schema('BlindCellControlGlobalSnapshotV1', [
    ['version', 'u8=1'], ['epochFloor', 'u32be'], ['clockUnsafe', 'u8[0..1]'], ['recoveryGap', 'u8[0..1]'],
    ['storedBytes', 'u64be'], ['stagingBytes', 'u64be'], ['controlBytes', 'u64be'],
    ['tombstoneBytes', 'u64be'], ['reservedCells', 'u64be'], ['cellCount', 'u64be'],
    ['spendCount', 'u64be'], ['commitmentCount', 'u64be'], ['requestResultCount', 'u64be'],
    ['chargedReadPinnedCount', 'u64be'], ['chargedReadFinalizedCount', 'u64be'],
    ['chargedReadExpiredCount', 'u64be'], ['chargedReadPinnedEntryCount', 'u64be'],
    ['profileStagingCount', 'u32be'], ['integrityEvidenceCount', 'u32be'],
    ['controlRecordAccountingBytes', 'u16be=512'], ['tombstoneRecordAccountingBytes', 'u16be=512']
  ]),
  schema('BlindCellHistoricalResultSnapshotV1', [
    ['storageSlot', bytes32], ['allocationEpoch', 'u32be'], ['sizeClass', 'u8[1..5]'],
    ['leaseClass', 'u8[1..4]'], ['leaseEpoch', 'u32be'], ['stateRevision', 'u64be'],
    ['policyRevision', 'u64be'], ['cellBlobHash', bytes32], ['allocationCommitment', bytes32],
    ['objectState', 'u8[1..2]'], ['policyState', 'u8[1..2]']
  ]),
  schema('BlindCellIntegrityEvidenceSnapshotV1', [
    ['version', 'u8=1'], ['reason', 'u8[1..3]'], ['detectedEpoch', 'u32be'], ['evidenceHash', bytes32]
  ]),
  schema('BlindCellProfileStagingSnapshotV1', [
    ['version', 'u8=1'], ['profileId', 'u16be[1..65535]'], ['stagingBytes', 'u64be-nonzero']
  ]),
  schema('BlindCellRecordSnapshotV1', [
    ['version', 'u8=1'], ['storageSlot', bytes32], ['allocationEpoch', 'u32be'],
    ['allocationLeaseClass', 'u8[1..4]'], ['sizeClass', 'u8[1..5]'],
    ['leaseClass', 'u8[1..4]'], ['leaseEpoch', 'u32be'], ['stateRevision', 'u64be'],
    ['policyRevision', 'u64be'], ['cellBlobHash', bytes32], ['blobVirtualBucket', 'u16be'],
    ['blobObjectId', bytes32], ['createPublicKey', bytes32], ['renewPublicKey', bytes32],
    ['dropPublicKey', bytes32], ['allocationCommitment', bytes32], ['objectState', 'u8[1..2]'],
    ['policyState', 'u8[1..2]'], ['tombstoneReason', 'optional(u8[1..2])'],
    ['terminalEpoch', 'optional(u32be)'], ['createSpendTag', bytes32],
    ['resultIdentity', bytes32], ['createdEpoch', 'u32be']
  ]),
  schema('BlindCellRequestResultSnapshotV1', [
    ['version', 'u8=1'], ['transactionId', bytes32], ['requestCommitment', bytes32],
    ['requestFingerprint', bytes32], ['storageSlot', bytes32],
    ['resultBindingBytes', 'optional(compact-bytes[1..1024])'], ['resultIdentity', bytes32],
    ['committedEpoch', 'u32be'], ['resultCell', 'BlindCellHistoricalResultSnapshotV1']
  ]),
  schema('BlindCellReservedSpendSnapshotV1', [
    ['version', 'u8=1'], ['transactionId', bytes32], ['spendTag', bytes32], ['requestCommitment', bytes32],
    ['requestFingerprint', bytes32], ['storageSlot', bytes32], ['allocationEpoch', 'u32be'],
    ['sizeClass', 'u8[1..5]'], ['leaseClass', 'u8[1..4]'], ['declaredBlobHash', bytes32],
    ['createPublicKey', bytes32], ['renewPublicKey', bytes32], ['dropPublicKey', bytes32],
    ['allocationCommitment', bytes32], ['profileId', 'u16be[1..65535]'],
    ['preparedAdmissionBytes', 'compact-bytes[1..17408]'],
    ['resultBindingBytes', 'optional(compact-bytes[1..1024])'], ['declaredBytes', 'u32be'],
    ['deadlineUnixMillis', 'u64be-nonzero'], ['remainingAttempts', 'u8[0..2]'], ['reservedEpoch', 'u32be']
  ]),
  schema('BlindCellTerminalSpendSnapshotV1', [
    ['version', 'u8=1'], ['transactionId', bytes32], ['spendTag', bytes32], ['requestCommitment', bytes32],
    ['requestFingerprint', bytes32], ['storageSlot', bytes32], ['allocationEpoch', 'u32be'],
    ['sizeClass', 'u8[1..5]'], ['leaseClass', 'u8[1..4]'], ['declaredBlobHash', bytes32],
    ['createPublicKey', bytes32], ['renewPublicKey', bytes32], ['dropPublicKey', bytes32],
    ['allocationCommitment', bytes32], ['profileId', 'u16be[1..65535]'],
    ['preparedAdmissionBytes', 'compact-bytes[1..17408]'],
    ['resultBindingBytes', 'optional(compact-bytes[1..1024])'], ['declaredBytes', 'u32be'],
    ['deadlineUnixMillis', 'u64be-nonzero'], ['remainingAttempts', 'u8[0..2]'], ['reservedEpoch', 'u32be'],
    ['terminalReason', 'u8[1..3]'], ['terminalEpoch', 'u32be']
  ]),
  schema('BlindCoreControlGlobalSnapshotV1', [
    ['version', 'u8=1'], ['epochFloor', 'u32be'], ['clockUnsafe', 'u8[0..1]'],
    ['recordCount', 'u64be'], ['reservedCount', 'u64be'], ['liveCount', 'u64be'],
    ['terminalCount', 'u64be'], ['spendIndexCount', 'u64be'], ['logicalIndexCount', 'u64be'],
    ['channelIndexCount', 'u64be'], ['resultCount', 'u64be'], ['snapshotRecordBytes', 'u64be']
  ]),
  schema('BlindCoreOpenReplicationRetrySnapshotV1', [
    ['version', 'u8=1'], ['lifecycleState', 'u8[1..3]'], ['logicalRetryKey', bytes32],
    ['spendTag', 'compact-bytes[1..128]'], ['requestCommitment', bytes32],
    ['wireProfileHash', bytes32], ['sessionClass', 'u8[1..3]'], ['clientNonce', bytes32],
    ['parentSessionId', 'compact-bytes[1..256]'], ['controlChannelId', 'u64be-nonzero'],
    ['parentChannelBinding', bytes32], ['streamId', 'u64be-nonzero'],
    ['maxSessionBytes', 'u64be[class-tuple]'], ['idleMillis', 'u32be[class-tuple]'],
    ['lifetimeMillis', 'u32be[class-tuple]'], ['openedAtEpoch', 'u32be'],
    ['recordVirtualBucket', 'u16be'], ['resultBytes', 'optional(compact-bytes[1..16384])'],
    ['terminalReason', 'optional(canonical-ascii[1..64])']
  ]),
  schema('BlindInboxCommittedSpendSnapshotV1', [
    ['version', 'u8=1'], ['transactionId', bytes32], ['spendTag', bytes32],
    ['requestCommitment', bytes32], ['requestFingerprint', bytes32], ['physicalTopic', bytes32],
    ['operation', 'u8{1,2,4,5,6}'], ['profileId', 'u16be[1..65535]'], ['frameClass', 'u8[0..3]'],
    ['frameHash', 'optional(fixed32)'], ['requestedLeaseClass', 'u8[0..4]'], ['declaredBytes', 'u32be'],
    ['deadlineUnixMillis', 'u64be-nonzero'], ['remainingAttempts', 'u8[0..1]'],
    ['reservedEpoch', 'u32be'], ['resultIdentity', bytes32], ['resultRevision', 'u64be'],
    ['committedEpoch', 'u32be'], ['resultLeaseClass', 'optional(u8[1..4])'],
    ['resultLeaseEpoch', 'optional(u32be)'], ['resultBindingBytes', 'compact-bytes[1..1024]'],
    ['clientNonce', bytes32], ['retentionClassAtAppend', 'optional(u8[1..4])'],
    ['appendLeaseEpoch', 'optional(u32be)'], ['expiresAtEpoch', 'optional(u32be)'],
    ['ackSignature', 'optional(fixed64)'], ['resultCommitment', 'optional(fixed32)'],
    ['retryState', 'u8[0..3]']
  ]),
  schema('BlindInboxControlGlobalSnapshotV1', [
    ['version', 'u8=1'], ['epochFloor', 'u32be'], ['clockUnsafe', 'u8[0..1]'],
    ['recoveryGap', 'u8[0..1]'], ['storedFrameBytes', 'u64be'], ['stagingFrameBytes', 'u64be'],
    ['controlBytes', 'u64be'], ['tombstoneBytes', 'u64be'], ['frameIndexBytes', 'u64be'],
    ['reservedFrames', 'u64be'], ['inboxCount', 'u64be'], ['frameCount', 'u64be'],
    ['spendCount', 'u64be'], ['commitmentCount', 'u64be'], ['requestResultCount', 'u64be'],
    ['retryRecordCount', 'u64be'], ['retryFramePinCount', 'u64be'], ['profileStagingCount', 'u32be'],
    ['integrityEvidenceCount', 'u32be'], ['controlRecordAccountingBytes', 'u16be=512'],
    ['tombstoneRecordAccountingBytes', 'u16be=512'], ['frameIndexAccountingBytes', 'u16be=256'],
    ['retryRecordAccountingBytes', 'u16be=256']
  ]),
  schema('BlindInboxExpiredAppendSpendSnapshotV1', [
    ['version', 'u8=1'], ['transactionId', bytes32], ['spendTag', bytes32],
    ['requestCommitment', bytes32], ['requestFingerprint', bytes32], ['physicalTopic', bytes32],
    ['profileId', 'u16be[1..65535]'], ['frameClass', 'u8[1..3]'], ['frameHash', bytes32],
    ['declaredBytes', 'u32be'], ['deadlineUnixMillis', 'u64be-nonzero'],
    ['remainingAttempts', 'u8[0..1]'], ['reservedEpoch', 'u32be'], ['resultIdentity', bytes32],
    ['appendRevision', 'u64be-nonzero'], ['storedAtEpoch', 'u32be'],
    ['retentionClassAtAppend', 'u8[1..4]'], ['appendLeaseEpoch', 'u32be'],
    ['expiresAtEpoch', 'u32be'], ['expiredEpoch', 'u32be'], ['clientNonce', bytes32],
    ['resultBindingBytes', 'compact-bytes[1..1024]'], ['ackSignature', 'fixed64'],
    ['resultCommitment', bytes32]
  ]),
  schema('BlindInboxFrameSnapshotV1', [
    ['version', 'u8=1'], ['physicalTopic', bytes32], ['appendRevision', 'u64be-nonzero'],
    ['frameHash', bytes32], ['frameClass', 'u8[1..3]'], ['frameVirtualBucket', 'u16be'],
    ['frameObjectId', bytes32], ['appendLeaseEpoch', 'u32be'], ['storedAtEpoch', 'u32be'],
    ['expiresAtEpoch', 'u32be'], ['spendTag', bytes32], ['requestCommitment', bytes32],
    ['resultIdentity', bytes32]
  ]),
  schema('BlindInboxIntegrityEvidenceSnapshotV1', [
    ['version', 'u8=1'], ['reason', 'u8[1..3]'], ['detectedEpoch', 'u32be'], ['evidenceHash', bytes32]
  ]),
  schema('BlindInboxProfileStagingSnapshotV1', [
    ['version', 'u8=1'], ['profileId', 'u16be[1..65535]'], ['stagingFrameBytes', 'u64be-nonzero']
  ]),
  schema('BlindInboxRecordSnapshotV1', [
    ['version', 'u8=1'], ['physicalTopic', bytes32], ['metadataVirtualBucket', 'u16be'],
    ['allocationEpoch', 'u32be'], ['allocationLeaseClass', 'u8[1..4]'], ['frameClassBits', 'u8[1..7]'],
    ['appendAuthMode', 'u8[0..1]'], ['appendPublicKey', 'optional(fixed32)'], ['createPublicKey', bytes32],
    ['renewPublicKey', bytes32], ['closePublicKey', bytes32], ['retentionClass', 'u8[1..4]'],
    ['leaseClass', 'u8[1..4]'], ['leaseEpoch', 'u32be'], ['stateRevision', 'u64be'],
    ['policyRevision', 'u64be'], ['appendRevision', 'u64be'], ['createCommitment', bytes32],
    ['objectState', 'u8[1..2]'], ['policyState', 'u8[1..2]'],
    ['tombstoneReason', 'optional(u8[1..2])'], ['terminalEpoch', 'optional(u32be)'],
    ['createSpendTag', bytes32], ['createRequestCommitment', bytes32],
    ['resultIdentity', bytes32], ['createdEpoch', 'u32be']
  ]),
  schema('BlindInboxRequestResultSnapshotV1', [
    ['version', 'u8=1'], ['transactionId', bytes32], ['requestCommitment', bytes32],
    ['physicalTopic', bytes32], ['resultIdentity', bytes32], ['resultRevision', 'u64be-nonzero'],
    ['committedEpoch', 'u32be'], ['resultBindingBytes', 'compact-bytes[1..1024]'],
    ['clientNonce', bytes32], ['resultLeaseClass', 'u8=0'], ['resultLeaseEpoch', 'u32be']
  ]),
  schema('BlindInboxReservedSpendSnapshotV1', [
    ['version', 'u8=1'], ['transactionId', bytes32], ['spendTag', bytes32],
    ['requestCommitment', bytes32], ['requestFingerprint', bytes32], ['physicalTopic', bytes32],
    ['operation', 'u8{1,2,4,5,6}'], ['profileId', 'u16be[1..65535]'], ['frameClass', 'u8[0..3]'],
    ['frameHash', 'optional(fixed32)'], ['requestedLeaseClass', 'u8[0..4]'], ['declaredBytes', 'u32be'],
    ['deadlineUnixMillis', 'u64be-nonzero'], ['remainingAttempts', 'u8[0..2]'], ['reservedEpoch', 'u32be']
  ]),
  schema('BlindInboxRetryFramePinSnapshotV1', [
    ['version', 'u8=1'], ['spendTag', bytes32], ['physicalTopic', bytes32],
    ['appendRevision', 'u64be-nonzero'], ['frameHash', bytes32]
  ]),
  schema('BlindInboxRetryMaterialSnapshotV1', [
    ['version', 'u8=1'], ['spendTag', bytes32], ['entriesCommitment', bytes32],
    ['nextCursor', 'optional(compact-bytes[1..128])']
  ]),
  schema('BlindInboxRetryReconstructionV1', [
    ['version', 'u8=1'], ['firstAppendRevision', 'u64be'], ['lastAppendRevision', 'u64be'],
    ['entryCount', 'u8[0..64]'], ['nextCursorHash', bytes32]
  ]),
  schema('BlindInboxTerminalSpendSnapshotV1', [
    ['version', 'u8=1'], ['transactionId', bytes32], ['spendTag', bytes32],
    ['requestCommitment', bytes32], ['requestFingerprint', bytes32], ['physicalTopic', bytes32],
    ['operation', 'u8{1,2,4,5,6}'], ['profileId', 'u16be[1..65535]'], ['frameClass', 'u8[0..3]'],
    ['frameHash', 'optional(fixed32)'], ['requestedLeaseClass', 'u8[0..4]'], ['declaredBytes', 'u32be'],
    ['deadlineUnixMillis', 'u64be-nonzero'], ['remainingAttempts', 'u8[0..2]'],
    ['reservedEpoch', 'u32be'], ['terminalReason', 'u8[1..3]'], ['terminalEpoch', 'u32be']
  ]),
  schema('BlindCleanRestoreEvidenceV1', [['canonicalDefinition', 'schema-meta-v1(master-declaration)']]),
  schema('BlindExternalCommitWitnessV1', [['canonicalDefinition', 'schema-meta-v1(master-declaration)']]),
  schema('BlindRestoreEvidenceBundleV1', [['canonicalDefinition', 'schema-meta-v1(master-declaration)']]),
  schema('BlindRestoreEvidenceHeadV1', [['canonicalDefinition', 'schema-meta-v1(master-declaration)']]),
  schema('BlindLocalCheckpointV1', [
    ['magic', 'fixed8=ASCII(HRBCKP01)'], ['checkpointVersion', 'u16be=1'],
    ['relayPublicKey', bytes32], ['storeId', bytes32], ['durabilityProfileId', 'u8[1..2]'],
    ['durabilityContinuityHash', bytes32], ['durabilityProfileHash', bytes32], ['formatMajor', 'u16be'],
    ['formatMinor', 'u16be'], ['storeFormatHash', bytes32], ['specHash', bytes32], ['abiHash', bytes32],
    ['mapGeneration', 'u64be-nonzero'], ['bucketMapHash', bytes32], ['writerEpoch', 'u64be-nonzero'],
    ['writerFenceTokenHash', bytes32], ['checkpointRevision', 'u64be-nonzero'],
    ['previousCheckpointHash', 'optional(fixed32)'], ['coveredWalSequence', 'u64be-nonzero'],
    ['coveredWalHash', bytes32], ['epochFloor', 'u32be'], ['descriptorSequenceFloor', 'u64be'],
    ['descriptorHashFloor', bytes32], ['snapshotByteLength', 'u64be-nonzero'], ['snapshotHash', bytes32]
  ]),
  schema('BlindPreparedAdmissionStoreV1', [
    ['version', 'u8=1'], ['spendTag', bytes32], ['requestCommitment', bytes32],
    ['profileId', 'u16be[1..65535]'], ['schemeId', 'u16be[1..65535]'],
    ['parameterHash', bytes32], ['resourceClass', 'u16be'], ['leaseClass', 'u8'],
    ['costUnits', 'u64be'], ['walCommitRecord', 'compact-bytes[1..16384]']
  ]),
  schema('BlindWalHeaderV2', [
    ['magic', 'fixed4=ASCII(HRWL)'], ['walVersion', 'u8=2'], ['recordType', 'u8[1..255]'],
    ['totalLength', 'u32be=224+payloadLength'], ['walSequence', 'u64be-nonzero'],
    ['transactionId', bytes32], ['virtualBucket', 'u16be'], ['mapGeneration', 'u64be-nonzero'],
    ['writerFenceTokenHash', bytes32], ['payloadLength', 'u32be'], ['previousWalHash', bytes32],
    ['durabilityContinuityHash', bytes32], ['payloadHash', bytes32]
  ]),
  schema('DurabilityContinuityBindingV1', [
    ['version', 'u8=1'], ['profileId', 'u8[1..2]'], ['externalJournalId', bytes32],
    ['externalWitnessPublicKey', bytes32], ['externalJournalReplicationClass', 'u8[0..1]'],
    ['externalJournalFailureGroupId', bytes32], ['restoreEvidenceFeedId', bytes32]
  ]),
  schema('InboxReadSignaturePayloadV1', [
    ['version', 'u8=1'], ['relayBinding', 'RelayResultBindingV1'], ['requestNonce', bytes32],
    ['requestCommitment', bytes32], ['snapshotRevision', 'u64be'], ['entriesCommitment', bytes32],
    ['nextCursor', 'optional(compact-bytes[0..128])']
  ]),
  schema('RelayResultBindingV1', [
    ['version', 'u8=1'], ['relayPublicKey', bytes32], ['storeId', bytes32], ['descriptorSequence', 'u64be'],
    ['descriptorHash', bytes32], ['durabilityProfileId', 'u8[1..2]'], ['durabilityContinuityHash', bytes32],
    ['durabilityProfileHash', bytes32], ['restoreEvidenceHeadSequence', 'u64be'],
    ['restoreEvidenceHeadHash', bytes32], ['externalCommitWitness', 'optional(BlindExternalCommitWitnessV1)']
  ]),
  ...[
    'BlindArtifactFileInventoryV1', 'BlindExecutableEntrypointCatalogV1', 'BlindLaunchTopologyV1',
    'BlindListenerCatalogV1', 'BlindListenerEntryV1', 'BlindProcessInspectionEvidenceV1',
    'BlindProductDistributionBundleV1', 'BlindProductIsolationEvidenceV1',
    'BlindProductIsolationReportBundleV1', 'BlindReleaseEvidenceBundleV1', 'BlindReleaseSupportHorizonV1',
    'BlindRouteAbsenceEvidenceV1', 'BlindRuntimeBoundaryEvidenceV1', 'BlindRuntimeImportGraphV1',
    'BuildInputV1', 'BuildManifestV1', 'BuildReproductionAttestationV1',
    'HiveRelayCompatibilityAuthorityTransitionV1', 'HiveRelayCompatibilityBuildManifestV1',
    'HiveRelayCompatibilityRuntimeBoundaryEvidenceV1', 'HiveRelayCompatibilitySunsetGenesisV1',
    'HiveRelayCompatibilitySunsetHeadV1', 'HiveRelayLegacyCompatibilitySunsetV1',
    'ReproductionEnvironmentV1', 'ToolchainEntryV1', 'ToolchainManifestV1',
    'BlindCoreReadCapV1', 'CellBlobV1', 'OpaqueChainCheckpointV1', 'OpaqueChainFrameV1',
    'ReadCellCapV1', 'WriteCellCapV1', 'BlindControlStateSnapshotV1', 'BlindExternalAckFloorV1',
    'BlindExternalControlCheckpointV1', 'BlindStoreManifestV1', 'CellRecordV1',
    'ChargedUnaryRetryV1'
  ].map(masterDefined)
])
